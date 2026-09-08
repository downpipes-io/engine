// The REAL DeployDriver for the safe-apply update pipeline (src/admin/update-apply.ts): the
// Cloudflare "Worker Versions + Deployments" surface, driven FROM THE CONSOLE so an owner
// applies a vendor-signed engine update without ever leaving the product (no CLI). The pipeline
// in update-apply.ts is pure orchestration over this driver; this file is the only part that
// actually talks to Cloudflare, and it is UNTESTED AGAINST A LIVE ACCOUNT BY DESIGN:
//
//   * The upstream pipeline gates EVERYTHING before this driver can act: a release is only ever
//     uploaded/promoted after its bytes verify SHA-384 against the signature-verified channel,
//     a rollback target is recorded first, and the promotion is canary-gated with an automatic
//     rollback if the canary does not pass (the "non-singing" health outcome defined in
//     update-apply.ts). So the worst a bad call here can do is a brief
//     availability blip on the engine WORKER, which Cloudflare lets us roll back; the DATA
//     (immutable, append-only, in the customer's own bucket) and RECOVERY (self-describing,
//     signed archive + standalone reader) are independent of the running engine and unharmed.
//   * This module is therefore made CORRECT-BY-THE-DOCS and DEFENSIVE rather than proven against
//     a real account: the validator (test/validate-cf-deploy.ts) drives every method with a
//     stub fetch and asserts the request shapes, the binding/secret preservation, and that every
//     opaque Cloudflare failure becomes a precise, actionable thrown message.
//
// TOKEN: the deploy token needs "Workers Scripts: Edit" on the engine's account (the dashboard
// "Edit Cloudflare Workers" template grants it). It is used for these calls only and is never
// stored or logged. The same scope reads the engine's settings, uploads a version, and deploys.
//
// Cloudflare API shapes used (api.cloudflare.com/client/v4), confirm against the live docs:
//   GET    /accounts/{a}/workers/scripts/{name}/deployments        -> list deployments (newest first)
//   GET    /accounts/{a}/workers/scripts/{name}/settings           -> result.bindings (+ compat fields)
//   POST   /accounts/{a}/workers/scripts/{name}/versions           -> multipart: metadata + module(s)
//   POST   /accounts/{a}/workers/scripts/{name}/deployments        -> {strategy, versions:[{version_id,percentage}]}

import type { ArtefactMeta, DeployDriver, LiveVersionShare } from "./update-apply.ts";

const CF_API = "https://api.cloudflare.com/client/v4";

// REDACTED_TYPES carry a value Cloudflare does not return on read, so they cannot be re-sent on
// the upload's metadata; keep_bindings preserves them (and their values) in place instead. Kept
// in lockstep with attach.ts's REDACTED_TYPES, these are the engine's SECRETS.
const REDACTED_TYPES = new Set(["secret_text", "secret_key"]);

// RESENDABLE_TYPES are binding types whose settings-read returns EVERY field needed to re-send them
// verbatim on the new version's metadata (references and plain values, never a withheld secret). The
// union of these + REDACTED_TYPES (preserved via keep_bindings) is the set the driver KNOWS how to carry
// forward without dropping anything. A binding of any OTHER type is refused before upload (see the guard
// in uploadVersion): a clean refusal, "use the manual deploy path", is always safer than silently
// uploading a version that drops a binding and bricks the engine. Extend this list as new types are
// confirmed re-sendable. (secrets_store_secret is a REFERENCE, store_id + secret_name, not the value, 
// so it is re-sendable, exactly as attach.ts treats it.)
const RESENDABLE_TYPES = new Set([
  "durable_object_namespace",
  "kv_namespace",
  "r2_bucket",
  "d1",
  "secrets_store_secret",
  "plain_text",
  "json",
  "service",
  "send_email",
  "analytics_engine",
  "queue",
  "wasm_module",
  "data_blob",
  "text_blob",
  "browser",
  "ai",
  "vectorize",
  "hyperdrive",
  "mtls_certificate",
  "version_metadata",
  "assets",
  "tail_consumer",
  "dispatch_namespace",
  "ratelimit",
]);

// A live binding as the script-settings read returns it. The non-secret ones are re-sent VERBATIM
// in the new version's metadata so the uploaded version keeps every binding it had; only name and
// type are inspected here. Exported for cf-assets-deploy.ts (the console driver preserves the console
// script's bindings with the same discipline).
export type LiveBinding = Record<string, unknown> & { name?: string; type?: string };

// cfErr extracts a redaction-safe reason + codes from a Cloudflare API error body (copied from
// attach.ts so opaque failures turn into precise, actionable messages, never a bare HTTP status).
// Exported for cf-assets-deploy.ts so both deploy drivers phrase Cloudflare failures identically.
export function cfErr(body: { errors?: Array<{ code?: number; message?: string }> } | null, status: number): { why: string; codes: number[] } {
  const codes = body?.errors?.map((e) => e.code).filter((c): c is number => typeof c === "number") ?? [];
  const why = body?.errors?.map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${status}`;
  return { why, codes };
}

// readSettings reads the engine's CURRENT settings from the SAME endpoint attach.ts uses (GET
// script settings). We need result.bindings (to PRESERVE the engine's bindings on the new version)
// and any compatibility_date / compatibility_flags (so the new version keeps the same runtime
// contract). Throws on any anomaly so the caller refuses rather than uploading a version that
// would lose the engine's configuration. Mirrors attach.ts's readDeployedBindings discipline.
async function readSettings(
  token: string,
  accountId: string,
  scriptName: string,
  fetchImpl: typeof fetch,
): Promise<{ bindings: LiveBinding[]; compatibilityDate?: string; compatibilityFlags?: string[] }> {
  const auth = { authorization: `Bearer ${token}` };
  const url = `${CF_API}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`;

  const resp = await fetchImpl(url, { method: "GET", headers: auth });
  const body = (await resp.json().catch(() => null)) as {
    success?: boolean;
    result?: { bindings?: unknown; compatibility_date?: unknown; compatibility_flags?: unknown };
    errors?: Array<{ code?: number; message?: string }>;
  } | null;
  if (!resp.ok || body?.success !== true) {
    const { why } = cfErr(body, resp.status);
    throw new Error(`could not read the engine's current settings to preserve its bindings before uploading the new version (Cloudflare: ${why}). The token must have Workers Scripts: Edit on account ${accountId} (the "Edit Cloudflare Workers" template). Nothing was uploaded.`);
  }
  const bindings = body.result?.bindings;
  if (!Array.isArray(bindings)) {
    throw new Error(`Cloudflare returned settings without a readable bindings list for "${scriptName}"; refusing to upload a new version blind (it would risk dropping the engine's bindings/secrets). Nothing was uploaded.`);
  }
  const compatibilityDate = typeof body.result?.compatibility_date === "string" ? body.result.compatibility_date : undefined;
  const compatibilityFlags = Array.isArray(body.result?.compatibility_flags)
    ? (body.result!.compatibility_flags as unknown[]).filter((f): f is string => typeof f === "string")
    : undefined;
  return {
    bindings: bindings as LiveBinding[],
    ...(compatibilityDate !== undefined ? { compatibilityDate } : {}),
    ...(compatibilityFlags !== undefined ? { compatibilityFlags } : {}),
  };
}

// classifyBindings splits the engine's live bindings into the set re-sent verbatim (non-secret), the secret
// types preserved via keep_bindings, and the UNKNOWN types the safe-apply pipeline cannot guarantee to carry
// forward. Cloudflare REPLACES the binding set on each version, so an unrecognised type we neither re-send
// nor keep would be silently dropped, bricking the engine; the caller refuses on a non-empty unknownTypes.
// Exported for cf-assets-deploy.ts so the console driver classifies with the SAME type sets (one place to
// extend when a new binding type is confirmed re-sendable).
export function classifyBindings(bindings: LiveBinding[]): { nonSecretBindings: LiveBinding[]; keepBindings: string[]; unknownTypes: string[] } {
  const unknownTypes = [
    ...new Set(
      bindings
        .map((b) => (typeof b.type === "string" ? b.type : ""))
        .filter((t) => t !== "" && !RESENDABLE_TYPES.has(t) && !REDACTED_TYPES.has(t)),
    ),
  ];
  const nonSecretBindings = bindings.filter((b) => typeof b.type === "string" && !REDACTED_TYPES.has(b.type));
  const keepBindings = [
    ...new Set(
      bindings
        .map((b) => b.type)
        .filter((t): t is string => typeof t === "string" && REDACTED_TYPES.has(t)),
    ),
  ];
  return { nonSecretBindings, keepBindings, unknownTypes };
}

// buildVersionMetadata builds the version metadata that carries the engine's whole config forward so the new
// version keeps working: preserved bindings + keep_bindings (secrets), the runtime compatibility fields, and
// the entry module. Only the CODE (the module body) is new.
function buildVersionMetadata(
  nonSecretBindings: LiveBinding[],
  keepBindings: string[],
  mainModule: string,
  compat: { compatibilityDate?: string; compatibilityFlags?: string[] },
): Record<string, unknown> {
  return {
    main_module: mainModule,
    bindings: nonSecretBindings,
    keep_bindings: keepBindings,
    ...(compat.compatibilityDate !== undefined ? { compatibility_date: compat.compatibilityDate } : {}),
    ...(compat.compatibilityFlags !== undefined ? { compatibility_flags: compat.compatibilityFlags } : {}),
  };
}

// makeCfDeployDriver builds the live DeployDriver for one engine worker. fetchImpl is injectable so
// the validator drives the EXACT shipped code with a stub (no network, no account, no cost).
export function makeCfDeployDriver(opts: {
  token: string;
  accountId: string;
  scriptName: string;
  fetchImpl?: typeof fetch;
}): DeployDriver {
  const { token, accountId, scriptName } = opts;
  const fetchImpl: typeof fetch = opts.fetchImpl ?? fetch;
  const auth = { authorization: `Bearer ${token}` };
  const A = encodeURIComponent(accountId);
  const S = encodeURIComponent(scriptName);

  // readLiveSlices reads the ACTIVE deployment's version slices (versionId + percentage) from the deployments
  // endpoint, shared by currentLiveVersionId (dominant slice) and currentLiveVersions (full set). The active
  // deployment is the most recent (first) one Cloudflare returns; each slice carries a version_id and (for a
  // ramp) a percentage. A missing percentage defaults to 100 (the single-version shape). Throws clearly on any
  // anomaly so the caller refuses rather than acting on an unreadable deployment.
  async function readLiveSlices(): Promise<LiveVersionShare[]> {
    const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/deployments`;
    const resp = await fetchImpl(url, { method: "GET", headers: auth });
    const body = (await resp.json().catch(() => null)) as {
      success?: boolean;
      result?: { deployments?: Array<{ id?: unknown; versions?: Array<{ version_id?: unknown; percentage?: unknown }> }> };
      errors?: Array<{ code?: number; message?: string }>;
    } | null;
    if (!resp.ok || body?.success !== true) {
      const { why } = cfErr(body, resp.status);
      throw new Error(`could not read the engine's current deployment to record a rollback target (Cloudflare: ${why}). The token needs Workers Scripts: Edit on account ${accountId}. Nothing was changed.`);
    }
    const deployments = body.result?.deployments;
    if (!Array.isArray(deployments) || deployments.length === 0) {
      throw new Error(`Cloudflare returned no deployments for "${scriptName}", so there is no current live version to roll back to; refusing to proceed. Nothing was changed.`);
    }
    const active = deployments[0];
    const versions = Array.isArray(active?.versions) ? active.versions : [];
    const slices: LiveVersionShare[] = [];
    for (const v of versions) {
      const versionId = v?.version_id;
      if (typeof versionId !== "string" || versionId === "") continue;
      const percentage = typeof v?.percentage === "number" ? v.percentage : 100; // single-version shape => 100
      slices.push({ versionId, percentage });
    }
    if (slices.length === 0) {
      throw new Error(`Cloudflare's current deployment for "${scriptName}" did not include a version id; cannot record a rollback target. Nothing was changed.`);
    }
    return slices;
  }

  return {
    // currentLiveVersionId reads the engine's CURRENT live version so the pipeline can record it as the
    // rollback target BEFORE any change. Cloudflare returns deployments newest-first; the ACTIVE deployment is
    // the most recent one. It usually serves a SINGLE version at 100%, but with the opt-in gradual ramp it can
    // be a real TWO-version split. We therefore return the DOMINANT slice (the version serving the most
    // traffic) rather than blindly versions[0], versions[] ordering is not a documented "live version"
    // contract, and on a split versions[0] could be the smaller (suspect) slice. Callers that must reason
    // about a split read currentLiveVersions (below) and never short-circuit on a multi-version shape.
    async currentLiveVersionId(): Promise<string> {
      const slices = await readLiveSlices();
      // The dominant slice (max percentage). On the common single-version deployment this is just that
      // version; on a split it is the larger share, the right thing to record as the rollback target.
      let best: LiveVersionShare | null = null;
      for (const s of slices) if (best === null || s.percentage > best.percentage) best = s;
      if (best === null) {
        throw new Error(`Cloudflare's current deployment for "${scriptName}" did not include a version id; cannot record a rollback target. Nothing was changed.`);
      }
      return best.versionId;
    },

    // currentLiveVersions returns EVERY live slice of the ACTIVE deployment (versionId + percentage), so the
    // orchestration can tell a single-version deployment from a split and never short-circuit on a split. It
    // reads the SAME deployments endpoint as currentLiveVersionId.
    async currentLiveVersions(): Promise<LiveVersionShare[]> {
      return readLiveSlices();
    },

    // uploadVersion creates a NEW, NOT-YET-LIVE version of the engine worker and returns its id.
    //
    // *** THIS IS THE BRICK-RISK OPERATION. *** A version replaces the engine's deployed bundle.
    // The new version MUST keep every binding and secret the engine had, or the engine, once this
    // version is promoted, would come up without its R2 archive, its Durable Objects, or its
    // signing secret, i.e. bricked. Cloudflare REPLACES (does not merge) the binding set on each
    // upload, so we must re-send the engine's existing configuration explicitly:
    //   * read the current settings (bindings + compat fields) from the settings endpoint;
    //   * re-send every NON-secret binding VERBATIM in the metadata (same shape the read returns);
    //   * list the secret types in keep_bindings so Cloudflare preserves the SECRETS and their
    //     VALUES (their values are never returned on read, so they cannot be re-sent, keep_bindings
    //     is the only safe way to carry them forward);
    //   * carry over compatibility_date / compatibility_flags so the runtime contract is unchanged;
    //   * set main_module to the artefact's entry module (meta.mainModule || "index.js").
    // The upload is a NOT-LIVE version, so even a wrong upload changes nothing until deployVersion
    // promotes it, and the pipeline only promotes after this returns and then canary-gates it.
    async uploadVersion(artefact: Uint8Array, meta: ArtefactMeta): Promise<string> {
      // 1. Read the engine's current configuration so the new version preserves it. A failure here
      //    refuses BEFORE any upload (nothing is changed).
      const { bindings, compatibilityDate, compatibilityFlags } = await readSettings(token, accountId, scriptName, fetchImpl);

      // 2. Classify the bindings (re-sendable vs secrets-to-keep vs unknown). BRICK-SAFETY GUARD: refuse if
      //    the engine has ANY binding type the driver cannot guarantee to carry forward. A clean refusal
      //    (use the manual deploy path) converts the "unknown future binding type" risk into a refusal,
      //    never a brick.
      const { nonSecretBindings, keepBindings, unknownTypes } = classifyBindings(bindings);
      if (unknownTypes.length > 0) {
        throw new Error(`refusing to upload a new version: the engine has binding type(s) the safe-apply pipeline cannot guarantee to preserve (${unknownTypes.join(", ")}); a self-deploy could drop them and brick the engine. Use the wrangler deploy path for this update. Nothing was uploaded.`);
      }

      // 3. The entry module name (defaults to index.js when the channel does not declare one).
      const mainModule = meta.mainModule || "index.js";

      // 4. Build the version metadata carrying the engine's whole config forward.
      const metadata = buildVersionMetadata(nonSecretBindings, keepBindings, mainModule, {
        ...(compatibilityDate !== undefined ? { compatibilityDate } : {}),
        ...(compatibilityFlags !== undefined ? { compatibilityFlags } : {}),
      });

      // 5. Multipart body: a `metadata` JSON part + the module file part. The module part's
      //    FILENAME must equal main_module (that is how Cloudflare matches the entry module), with
      //    content-type application/javascript+module and the artefact bytes as its body.
      const form = new FormData();
      form.append("metadata", JSON.stringify(metadata));
      // Copy into a fresh ArrayBuffer-backed view so the Blob body is exactly the artefact bytes,
      // independent of the input's underlying buffer offset/length.
      const moduleBlob = new Blob([new Uint8Array(artefact)], { type: "application/javascript+module" });
      form.append(mainModule, moduleBlob, mainModule);

      const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/versions`;
      const resp = await fetchImpl(url, { method: "POST", headers: auth, body: form });
      const body = (await resp.json().catch(() => null)) as {
        success?: boolean;
        result?: { id?: unknown };
        errors?: Array<{ code?: number; message?: string }>;
      } | null;
      if (!resp.ok || body?.success !== true) {
        const { why } = cfErr(body, resp.status);
        throw new Error(`the new engine version could not be uploaded (Cloudflare: ${why}); your engine is unchanged (an uploaded version is not live until it is deployed, and nothing was deployed). The token needs Workers Scripts: Edit on account ${accountId}.`);
      }
      const id = body.result?.id;
      if (typeof id !== "string" || id === "") {
        throw new Error(`Cloudflare accepted the upload but did not return a version id, so the new version cannot be promoted; your engine is unchanged. Try again, or use the wrangler deploy path.`);
      }
      return id;
    },

    // fetchVersionModule fetches the just-UPLOADED version's main module bytes back
    // from Cloudflare's own API, so the apply can prove the platform holds exactly the signed bytes
    // BEFORE promotion. The response shape for version content has more than one historical spelling,
    // so the parser is deliberately tolerant (modules[].content_base64, modules[].content, or
    // resources.script.content) and THROWS a redaction-safe "unrecognised shape" error otherwise --
    // which the gate reports as an honest "unavailable" verdict, recorded as a fixture before enforce mode is ever enabled. Read-only: the
    // same token the upload just used necessarily reads what it wrote.
    async fetchVersionModule(versionId: string, mainModule: string): Promise<Uint8Array> {
      const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/versions/${versionId}?include=modules`;
      const resp = await fetchImpl(url, { headers: auth });
      const body = (await resp.json().catch(() => null)) as {
        success?: boolean;
        result?: Record<string, unknown>;
        errors?: Array<{ code?: number; message?: string }>;
      } | null;
      if (!resp.ok || body?.success !== true) {
        const { why } = cfErr(body, resp.status);
        throw new Error(`the uploaded version could not be read back (Cloudflare: ${why})`);
      }
      const result = body.result ?? {};
      const resources = result.resources as { script?: { content?: unknown; modules?: unknown } } | undefined;
      const rawModules = (result.modules ?? resources?.script?.modules) as unknown;
      if (Array.isArray(rawModules)) {
        const modules = rawModules as Array<{ name?: unknown; content_base64?: unknown; content?: unknown }>;
        const m = modules.find((x) => x?.name === mainModule) ?? (modules.length === 1 ? modules[0] : undefined);
        if (m !== undefined) {
          if (typeof m.content_base64 === "string") {
            return Uint8Array.from(atob(m.content_base64), (c) => c.charCodeAt(0));
          }
          if (typeof m.content === "string") {
            return new TextEncoder().encode(m.content);
          }
        }
      }
      const content = resources?.script?.content;
      if (typeof content === "string") {
        return new TextEncoder().encode(content);
      }
      throw new Error("the version read-back response shape was not recognised (keep the raw response as the sandbox-experiment fixture); read-back is unavailable for this apply");
    },

    // deployVersion makes a version THE LIVE DEPLOYMENT at 100%. It is used for BOTH directions: to PROMOTE
    // the just-uploaded new version, and to ROLL BACK (deploy the recorded prior version id) when the canary
    // does not sing. A 100%-of-one-version deployment is the atomic "this is now live" operation, and it also
    // COLLAPSES any prior gradual split back to a single version (deploying at 100% supersedes a ramp).
    // Cloudflare deploys are atomic, so a failed deploy leaves the prior deployment live (a clean no-op the
    // pipeline reports as such). The opt-in gradual rollout uses rampVersion below; the default apply uses this.
    async deployVersion(versionId: string): Promise<void> {
      const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/deployments`;
      const resp = await fetchImpl(url, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({
          strategy: "percentage",
          versions: [{ version_id: versionId, percentage: 100 }],
        }),
      });
      const body = (await resp.json().catch(() => null)) as {
        success?: boolean;
        errors?: Array<{ code?: number; message?: string }>;
      } | null;
      if (!resp.ok || body?.success !== true) {
        const { why } = cfErr(body, resp.status);
        throw new Error(`could not make version ${versionId} the live deployment (Cloudflare: ${why}); the previously-live version is still serving (Cloudflare deploys are atomic, so nothing was half-applied). The token needs Workers Scripts: Edit on account ${accountId}.`);
      }
    },

    // rampVersion (OPT-IN gradual rollout) serves `percentage`% of LIVE traffic to newVersionId and the
    // remainder to priorVersionId, a real two-version traffic split via the SAME deployments-create endpoint
    // deployVersion uses, just with two versions whose percentages sum to 100. It is the honest, feasible
    // substitute for an isolated preview (isolated preview URLs need *.workers.dev, which downpipes bans): a
    // ramp serves the new version to a FRACTION OF REAL TRAFFIC. The orchestration only calls this on the
    // explicit opt-in ramp path; the default apply uses deployVersion (atomic 100%). Promoting the ramp to
    // 100% afterwards, and rolling it back, both use deployVersion. Cloudflare deploys are atomic, so a failed
    // ramp leaves the prior version at 100% (a clean no-op). The percentage is bounded by the caller
    // (rampPercentageValid: 1..99); this is defence in depth.
    async rampVersion(newVersionId: string, priorVersionId: string, percentage: number): Promise<void> {
      if (!Number.isInteger(percentage) || percentage < 1 || percentage > 99) {
        throw new Error(`a gradual ramp needs an integer percentage between 1 and 99 (got ${percentage}); nothing was changed.`);
      }
      const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/deployments`;
      const resp = await fetchImpl(url, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({
          strategy: "percentage",
          versions: [
            { version_id: newVersionId, percentage },
            { version_id: priorVersionId, percentage: 100 - percentage },
          ],
        }),
      });
      const body = (await resp.json().catch(() => null)) as {
        success?: boolean;
        errors?: Array<{ code?: number; message?: string }>;
      } | null;
      if (!resp.ok || body?.success !== true) {
        const { why } = cfErr(body, resp.status);
        throw new Error(`could not start the gradual ramp to ${newVersionId} at ${percentage}% (Cloudflare: ${why}); the previously-live version is still serving 100% (Cloudflare deploys are atomic, so nothing was half-applied). The token needs Workers Scripts: Edit on account ${accountId}.`);
      }
    },
  };
}
