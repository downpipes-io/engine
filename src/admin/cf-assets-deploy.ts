// The STATIC-ASSETS DeployDriver for the multi-component update pipeline: cf-deploy.ts's twin for the
// CONSOLE script. The console is a different SHAPE of deploy from the engine's single-module upload: a
// Workers Static Assets manifest (upload session -> deduplicated bucket uploads -> completion token) plus
// a small shell worker, promoted with the SAME atomic deployments endpoint the engine uses. Like
// cf-deploy.ts, this file is the only part of the console path that talks to Cloudflare, and it is
// UNTESTED AGAINST A LIVE ACCOUNT BY DESIGN:
//
//   * The upstream pipeline gates EVERYTHING before this driver can act: the console bundle's bytes
//     verify SHA-384 against the signature-verified channel, every per-asset SHA-256 inside the bundle is
//     re-verified against the decoded bytes (parseConsoleBundle below), and a rollback target is recorded
//     before any change. The worst a bad call here can do is a brief availability blip on the console
//     WORKER, which the recorded prior version reverts; the engine, the DATA and RECOVERY are untouched
//     (the console is a stateless shell + assets in front of the engine's API).
//   * This module is therefore CORRECT-BY-THE-REFERENCE-IMPLEMENTATION and defensive: the request shapes
//     below are derived from wrangler's own assets uploader (wrangler 4.103.0, the reference client for
//     this API), and the validator (test/validate-assets-deploy.ts) drives every method with a stub fetch
//     asserting those recorded shapes, the binding preservation, and that every opaque Cloudflare failure
//     becomes a precise, actionable thrown message.
//
// TOKEN: the same one-shot deploy token as the engine path ("Workers Scripts: Edit" on the account); it
// is used for these calls only and is never stored or logged. A Cloudflare token cannot be scoped to a
// script NAME, so the deploy-target guarantee is this driver's scriptName (env.CONSOLE_WORKER_NAME,
// default "downpipe-console") -- the console twin of the engine's WORKER_NAME guard.
//
// Cloudflare API shapes used (api.cloudflare.com/client/v4), matched to wrangler 4.103.0's uploader:
//   GET  /accounts/{a}/workers/scripts/{name}/deployments            -> list deployments (newest first)
//   GET  /accounts/{a}/workers/scripts/{name}/settings               -> result.bindings (+ compat fields)
//   POST /accounts/{a}/workers/scripts/{name}/assets-upload-session  -> { manifest } -> result { jwt, buckets }
//   POST /accounts/{a}/workers/assets/upload?base64=true             -> FormData of base64 file parts
//                                                                       (Bearer = session jwt) -> result { jwt? }
//   POST /accounts/{a}/workers/scripts/{name}/versions               -> multipart: metadata (+ assets.jwt) + module
//   POST /accounts/{a}/workers/scripts/{name}/deployments            -> {strategy, versions:[{version_id,percentage}]}
//
// MANIFEST HASH (load-bearing; verified against wrangler's source in node_modules): each manifest entry is
//   { "/path": { hash, size } } where size is the RAW byte length and hash is
//   blake3( base64(fileBytes) + fileExtensionWithoutDot ) -> hex -> first 32 characters.
// It is BLAKE3 (not SHA-256), over the base64 TEXT of the contents concatenated with the extension --
// wrangler's hashFile() exactly. The validator cross-checks this recipe against wrangler's own blake3
// dependency so a drift in either place fails the gate.

import { blake3 } from "@noble/hashes/blake3.js";
import { base64Encode, hexEncode, sha256Hex, utf8 } from "../crypto/bytes.ts";
import { cfErr, classifyBindings, type LiveBinding } from "./cf-deploy.ts";
import type { LiveVersionShare } from "./update-types.ts";

const CF_API = "https://api.cloudflare.com/client/v4";

// CONSOLE_BUNDLE_FORMAT is the exact self-describing format string a console artefact must declare
// (design MULTI-COMPONENT-UPDATES s4). The parse is strict: any other value is refused loudly, so a
// future format revision can never be half-read by an engine that predates it.
export const CONSOLE_BUNDLE_FORMAT = "downpipe-console-bundle/1";

// CONSOLE_ASSET_COUNT_MAX / CONSOLE_ASSET_BYTES_MAX bound a parsed bundle: the real console is a few
// dozen files totalling 3-4 MB, so these caps (a thousand files, 25 MiB decoded per asset -- Workers
// Assets' own per-file ceiling) only reject a malformed or hostile bundle, never a legitimate release.
const CONSOLE_ASSET_COUNT_MAX = 1000;
const CONSOLE_ASSET_BYTES_MAX = 25 * 1024 * 1024;

// ConsoleBundleAsset is one verified file of the parsed console bundle: the serve path, the content type
// the asset server should answer with, the DECODED bytes (sha256-verified against the bundle's own
// declaration), and the canonical base64 of those bytes (re-encoded here, so the upload payload and the
// manifest hash never depend on the artefact's own base64 formatting).
export interface ConsoleBundleAsset {
  path: string;
  contentType: string;
  sha256: string;
  bytes: Uint8Array;
  b64: string;
}

// ConsoleBundle is the parsed, per-asset-verified console artefact. config carries the version-controlled
// static facts of the release (what the console's wrangler.toml would set); bindings deliberately do NOT
// ride in the artefact -- the driver preserves the LIVE console script's bindings (the ENGINE service
// binding, vars, the assets binding) by reading settings first, exactly as the engine deploy does.
export interface ConsoleBundle {
  version: string;
  worker: { mainModule: string; source: Uint8Array };
  config: { compatibilityDate?: string; runWorkerFirst?: boolean; cpuMs?: number };
  assets: ConsoleBundleAsset[];
}

// base64DecodeStrict decodes STANDARD RFC 4648 base64 (the alphabet base64Encode in crypto/bytes.ts
// emits: A-Z a-z 0-9 + /, with `=` padding). Strict in the b64urlDecode mould: out-of-alphabet
// characters, whitespace, a bad length, misplaced padding and non-canonical trailing bits are all
// rejected, so a sloppy or hostile encoding can never decode to bytes whose hash "happens" to pass.
function base64DecodeStrict(s: string): Uint8Array {
  if (s.length % 4 !== 0) throw new Error(`invalid base64 length ${s.length}: must be a multiple of 4`);
  let end = s.length;
  let pad = 0;
  while (pad < 2 && end > 0 && s[end - 1] === "=") {
    end--;
    pad++;
  }
  if (pad === 1 && end % 4 !== 3) throw new Error("invalid base64 padding");
  if (pad === 2 && end % 4 !== 2) throw new Error("invalid base64 padding");
  const out = new Uint8Array(Math.floor((end * 6) / 8));
  let n = 0;
  let bits = 0;
  let acc = 0;
  for (let i = 0; i < end; i++) {
    const ch = s[i]!;
    const code = ch.charCodeAt(0);
    let v = -1;
    if (code >= 65 && code <= 90) v = code - 65; // A-Z
    else if (code >= 97 && code <= 122) v = code - 97 + 26; // a-z
    else if (code >= 48 && code <= 57) v = code - 48 + 52; // 0-9
    else if (ch === "+") v = 62;
    else if (ch === "/") v = 63;
    if (v < 0) throw new Error(`invalid base64 character: ${JSON.stringify(ch)}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Error("invalid base64: non-canonical trailing bits");
  return out;
}

// assetManifestHash computes the Workers Assets manifest hash for one file, matching wrangler's
// hashFile() EXACTLY: blake3 over the UTF-8 of (standard base64 of the raw bytes) + (the file extension
// WITHOUT its dot, "" when the basename has none), hex-encoded, truncated to 32 characters. The
// extension rule mirrors node's path.extname (a leading-dot basename like "/.well-known" has no
// extension). Exported for the validator's cross-check against wrangler's own blake3.
export function assetManifestHash(bytes: Uint8Array, path: string): string {
  const basename = path.slice(path.lastIndexOf("/") + 1);
  const dot = basename.lastIndexOf(".");
  const ext = dot > 0 ? basename.slice(dot + 1) : "";
  return hexEncode(blake3(utf8(base64Encode(bytes) + ext))).slice(0, 32);
}

// parseConsoleBundle parses + verifies a downloaded console artefact (whose WHOLE-FILE sha384 the caller
// has already verified against the signed channel, the same order as the engine artefact flow). It is
// STRICT: the exact format string, a non-empty version, a decodable shell worker module, well-typed
// static config, and a bounded, non-empty asset list whose every entry decodes and matches its own
// declared SHA-256. Any deviation throws with the offending path named -- a console bundle is code that
// will run in the operator's browser, so nothing partially-verified is ever returned. Pure + async
// (WebCrypto SHA-256); no network.
export async function parseConsoleBundle(raw: Uint8Array): Promise<ConsoleBundle> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw new Error("the console bundle is not valid JSON; refusing it (nothing was changed)");
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("the console bundle is not a JSON object; refusing it (nothing was changed)");
  const b = parsed as Record<string, unknown>;
  if (b.format !== CONSOLE_BUNDLE_FORMAT) {
    throw new Error(`the console bundle declares format ${JSON.stringify(b.format)} but this engine reads only "${CONSOLE_BUNDLE_FORMAT}"; refusing it (nothing was changed)`);
  }
  if (typeof b.version !== "string" || b.version === "") throw new Error("the console bundle declares no version; refusing it (nothing was changed)");

  // The shell worker module (the CSP/security-header worker served in front of the assets).
  const worker = b.worker as Record<string, unknown> | undefined;
  if (typeof worker !== "object" || worker === null) throw new Error("the console bundle has no worker module; refusing it (nothing was changed)");
  if (typeof worker.mainModule !== "string" || worker.mainModule === "") throw new Error("the console bundle's worker declares no mainModule; refusing it (nothing was changed)");
  if (typeof worker.sourceB64 !== "string" || worker.sourceB64 === "") throw new Error("the console bundle's worker has no source; refusing it (nothing was changed)");
  let workerSource: Uint8Array;
  try {
    workerSource = base64DecodeStrict(worker.sourceB64);
  } catch (e) {
    throw new Error(`the console bundle's worker source does not decode (${e instanceof Error ? e.message : String(e)}); refusing it (nothing was changed)`);
  }

  // Static config: version-controlled release facts only (never bindings; those are preserved live).
  const rawConfig = (typeof b.config === "object" && b.config !== null ? b.config : {}) as Record<string, unknown>;
  const rawLimits = (typeof rawConfig.limits === "object" && rawConfig.limits !== null ? rawConfig.limits : {}) as Record<string, unknown>;
  const config: ConsoleBundle["config"] = {
    ...(typeof rawConfig.compatibilityDate === "string" && rawConfig.compatibilityDate !== "" ? { compatibilityDate: rawConfig.compatibilityDate } : {}),
    ...(typeof rawConfig.runWorkerFirst === "boolean" ? { runWorkerFirst: rawConfig.runWorkerFirst } : {}),
    ...(typeof rawLimits.cpu_ms === "number" && Number.isFinite(rawLimits.cpu_ms) && rawLimits.cpu_ms > 0 ? { cpuMs: rawLimits.cpu_ms } : {}),
  };

  // Assets: every entry strictly typed, decoded and sha256-verified against its own declaration.
  if (!Array.isArray(b.assets) || b.assets.length === 0) throw new Error("the console bundle lists no assets; refusing it (nothing was changed)");
  if (b.assets.length > CONSOLE_ASSET_COUNT_MAX) throw new Error(`the console bundle lists ${b.assets.length} assets, over the ${CONSOLE_ASSET_COUNT_MAX} bound; refusing it (nothing was changed)`);
  const assets: ConsoleBundleAsset[] = [];
  const seenPaths = new Set<string>();
  for (const entry of b.assets) {
    const a = entry as Record<string, unknown>;
    const path = typeof a.path === "string" ? a.path : "";
    if (path === "" || !path.startsWith("/") || path.includes("..") || path.includes("\\")) {
      throw new Error(`the console bundle carries an asset with a malformed path ${JSON.stringify(a.path)}; refusing it (nothing was changed)`);
    }
    if (seenPaths.has(path)) throw new Error(`the console bundle lists the asset path ${path} twice; refusing it (nothing was changed)`);
    seenPaths.add(path);
    if (typeof a.contentType !== "string" || a.contentType === "") throw new Error(`the console bundle's asset ${path} declares no contentType; refusing it (nothing was changed)`);
    if (typeof a.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(a.sha256)) throw new Error(`the console bundle's asset ${path} declares no usable sha256; refusing it (nothing was changed)`);
    if (typeof a.b64 !== "string" || a.b64 === "") throw new Error(`the console bundle's asset ${path} has no content; refusing it (nothing was changed)`);
    let bytes: Uint8Array;
    try {
      bytes = base64DecodeStrict(a.b64);
    } catch (e) {
      throw new Error(`the console bundle's asset ${path} does not decode (${e instanceof Error ? e.message : String(e)}); refusing it (nothing was changed)`);
    }
    if (bytes.length > CONSOLE_ASSET_BYTES_MAX) throw new Error(`the console bundle's asset ${path} is over the per-file bound; refusing it (nothing was changed)`);
    // Verify-before-anything: the decoded bytes must match the entry's own declared SHA-256. The whole
    // file already verified sha384 against the signed channel; this inner check pins each asset to what
    // the publisher hashed, so a corrupted entry is named precisely rather than surfacing as a bad page.
    const actual = await sha256Hex(bytes);
    if (actual !== a.sha256) {
      throw new Error(`the console bundle's asset ${path} does not match its declared sha256 (possible corruption); refusing it (nothing was changed)`);
    }
    // Canonical re-encode: the upload payload and the manifest hash use base64Encode(bytes), never the
    // artefact's own base64 text, so encoding quirks cannot skew the wrangler-recipe manifest hash.
    assets.push({ path, contentType: a.contentType, sha256: a.sha256, bytes, b64: base64Encode(bytes) });
  }

  return { version: b.version, worker: { mainModule: worker.mainModule, source: workerSource }, config, assets };
}

// CfEnvelope is the standard Cloudflare v4 response envelope the calls below parse defensively.
interface CfEnvelope<T> {
  success?: boolean;
  result?: T;
  errors?: Array<{ code?: number; message?: string }>;
}

// AssetsDeployDriver is the console-shaped driver surface. currentLiveVersionId/currentLiveVersions/
// deployVersion match DeployDriver (so verifyAndGuard and the rollback orchestration reuse them);
// uploadVersion takes the PARSED console bundle rather than raw module bytes (the console upload is a
// manifest + buckets + shell worker, not a single module body). There is deliberately NO rampVersion:
// a static-assets swap is atomic at promote and has no traffic-percentage concept.
export interface AssetsDeployDriver {
  currentLiveVersionId(): Promise<string>;
  currentLiveVersions(): Promise<LiveVersionShare[]>;
  uploadVersion(bundle: ConsoleBundle): Promise<string>;
  deployVersion(versionId: string): Promise<void>;
}

// makeCfAssetsDeployDriver builds the live assets driver for one console worker. fetchImpl is injectable
// so the validator drives the EXACT shipped code with a stub (no network, no account, no cost).
export function makeCfAssetsDeployDriver(opts: {
  token: string;
  accountId: string;
  scriptName: string;
  // engineScriptName is THIS engine's own script name (env.WORKER_NAME). Every mutating call proves the
  // target console is bound to it before touching anything -- see assertBoundToThisEngine below.
  engineScriptName: string;
  fetchImpl?: typeof fetch;
}): AssetsDeployDriver {
  const { token, accountId, scriptName, engineScriptName } = opts;
  const fetchImpl: typeof fetch = opts.fetchImpl ?? fetch;
  const auth = { authorization: `Bearer ${token}` };
  const A = encodeURIComponent(accountId);
  const S = encodeURIComponent(scriptName);

  // readLiveSlices mirrors cf-deploy.ts's deployments read, pointed at the CONSOLE script: the ACTIVE
  // (most recent) deployment's version slices, defaulting a missing percentage to 100. Throws clearly on
  // any anomaly so the caller refuses rather than acting on an unreadable deployment.
  async function readLiveSlices(): Promise<LiveVersionShare[]> {
    const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/deployments`;
    const resp = await fetchImpl(url, { method: "GET", headers: auth });
    const body = (await resp.json().catch(() => null)) as CfEnvelope<{ deployments?: Array<{ versions?: Array<{ version_id?: unknown; percentage?: unknown }> }> }> | null;
    if (!resp.ok || body?.success !== true) {
      const { why } = cfErr(body, resp.status);
      throw new Error(`could not read the console's current deployment to record a rollback target (Cloudflare: ${why}). The token needs Workers Scripts: Edit on account ${accountId}. Nothing was changed.`);
    }
    const deployments = body.result?.deployments;
    if (!Array.isArray(deployments) || deployments.length === 0) {
      throw new Error(`Cloudflare returned no deployments for "${scriptName}", so there is no current live console version to roll back to; refusing to proceed. Nothing was changed.`);
    }
    const versions = Array.isArray(deployments[0]?.versions) ? deployments[0]!.versions! : [];
    const slices: LiveVersionShare[] = [];
    for (const v of versions) {
      const versionId = v?.version_id;
      if (typeof versionId !== "string" || versionId === "") continue;
      slices.push({ versionId, percentage: typeof v?.percentage === "number" ? v.percentage : 100 });
    }
    if (slices.length === 0) {
      throw new Error(`Cloudflare's current deployment for "${scriptName}" did not include a version id; cannot record a rollback target. Nothing was changed.`);
    }
    return slices;
  }

  // readConsoleSettings reads the console script's CURRENT settings (bindings + compat fields) so the new
  // version preserves them: the ENGINE service binding, vars, and the assets binding identity all ride in
  // result.bindings. Throws on any anomaly so the caller refuses BEFORE any upload -- exactly
  // cf-deploy.ts's readSettings discipline, worded for the console.
  async function readConsoleSettings(): Promise<{ bindings: LiveBinding[]; compatibilityDate?: string; compatibilityFlags?: string[] }> {
    const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/settings`;
    const resp = await fetchImpl(url, { method: "GET", headers: auth });
    const body = (await resp.json().catch(() => null)) as CfEnvelope<{ bindings?: unknown; compatibility_date?: unknown; compatibility_flags?: unknown }> | null;
    if (!resp.ok || body?.success !== true) {
      const { why } = cfErr(body, resp.status);
      throw new Error(`could not read the console's current settings to preserve its bindings before uploading the new version (Cloudflare: ${why}). The token must have Workers Scripts: Edit on account ${accountId} (the "Edit Cloudflare Workers" template). Nothing was uploaded.`);
    }
    const bindings = body.result?.bindings;
    if (!Array.isArray(bindings)) {
      throw new Error(`Cloudflare returned settings without a readable bindings list for "${scriptName}"; refusing to upload a new console version blind (it would risk dropping the console's engine binding). Nothing was uploaded.`);
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

  // assertBoundToThisEngine is the OWNERSHIP PROOF (deploy-target guard): the script this driver is
  // about to mutate must be THE console bound to THIS engine -- its live bindings must include a
  // service binding whose service is the engine's own script name. A script NAME alone is never
  // trusted: a defaulted CONSOLE_WORKER_NAME on an engine whose live vars predate the feature (a
  // channel-upgraded install, a -demo engine) could otherwise target another install's console. The
  // binding is the proof; without it every mutating call refuses before touching anything.
  function assertBoundToThisEngine(bindings: LiveBinding[]): void {
    const bound = bindings.some((b) => b.type === "service" && (b as { service?: unknown }).service === engineScriptName);
    if (!bound) {
      throw new Error(`refusing to touch the console script "${scriptName}": it has no service binding pointing at this engine ("${engineScriptName}"), so it cannot be proven to be this install's console. Set CONSOLE_WORKER_NAME to the correct console script name. Nothing was changed.`);
    }
  }

  // uploadAssets runs the manifest -> session -> buckets flow and returns the COMPLETION token the new
  // version's metadata must carry. Unchanged files are deduplicated by Cloudflare: the session's buckets
  // list only the hashes it wants uploaded, and an all-deduplicated release returns NO buckets, in which
  // case the session token doubles as the completion token (wrangler's exact handling).
  async function uploadAssets(assets: ConsoleBundleAsset[]): Promise<string> {
    const manifest: Record<string, { hash: string; size: number }> = {};
    const byHash = new Map<string, ConsoleBundleAsset>();
    for (const a of assets) {
      const hash = assetManifestHash(a.bytes, a.path);
      manifest[a.path] = { hash, size: a.bytes.length };
      byHash.set(hash, a);
    }
    const sessionUrl = `${CF_API}/accounts/${A}/workers/scripts/${S}/assets-upload-session`;
    const sessionResp = await fetchImpl(sessionUrl, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ manifest }),
    });
    const sessionBody = (await sessionResp.json().catch(() => null)) as CfEnvelope<{ jwt?: unknown; buckets?: unknown }> | null;
    if (!sessionResp.ok || sessionBody?.success !== true) {
      const { why } = cfErr(sessionBody, sessionResp.status);
      throw new Error(`the console asset manifest was not accepted (Cloudflare: ${why}); your console is unchanged (no version was created and nothing was deployed). The token needs Workers Scripts: Edit on account ${accountId}.`);
    }
    const sessionJwt = typeof sessionBody.result?.jwt === "string" ? sessionBody.result.jwt : "";
    if (sessionJwt === "") {
      throw new Error("Cloudflare's asset-upload session returned no token, so the assets cannot be uploaded; your console is unchanged.");
    }
    const buckets = Array.isArray(sessionBody.result?.buckets) ? (sessionBody.result!.buckets as unknown[]) : [];
    const wanted = buckets.filter((b): b is string[] => Array.isArray(b)).filter((b) => b.length > 0);
    if (wanted.length === 0) {
      // Every file already known to Cloudflare (deduplicated): the session token IS the completion token.
      return sessionJwt;
    }
    let completionJwt = "";
    for (const bucket of wanted) {
      const payload = new FormData();
      for (const hash of bucket) {
        const asset = byHash.get(typeof hash === "string" ? hash : "");
        if (asset === undefined) {
          throw new Error("Cloudflare requested an asset hash that is not in the verified console bundle; refusing the upload (your console is unchanged).");
        }
        // The part is the BASE64 TEXT of the file (the ?base64=true contract), field name AND filename
        // both the manifest hash, content type the asset's own (how the API learns what to serve).
        payload.append(hash as string, new File([asset.b64], hash as string, { type: asset.contentType }), hash as string);
      }
      const upResp = await fetchImpl(`${CF_API}/accounts/${A}/workers/assets/upload?base64=true`, {
        method: "POST",
        headers: { authorization: `Bearer ${sessionJwt}` },
        body: payload,
      });
      const upBody = (await upResp.json().catch(() => null)) as CfEnvelope<{ jwt?: unknown }> | null;
      if (!upResp.ok || upBody?.success !== true) {
        const { why } = cfErr(upBody, upResp.status);
        throw new Error(`a console asset bucket failed to upload (Cloudflare: ${why}); your console is unchanged (staged assets do not serve until a version referencing them is deployed, and none was).`);
      }
      // The FINAL bucket's response carries the completion token (earlier ones return none).
      if (typeof upBody.result?.jwt === "string" && upBody.result.jwt !== "") completionJwt = upBody.result.jwt;
    }
    if (completionJwt === "") {
      throw new Error("Cloudflare did not return an asset-upload completion token after the final bucket, so no version can reference the assets; your console is unchanged.");
    }
    return completionJwt;
  }

  return {
    // currentLiveVersionId returns the console's DOMINANT live version (max percentage), the rollback
    // target recorded before any change -- the same rule as the engine driver.
    async currentLiveVersionId(): Promise<string> {
      const slices = await readLiveSlices();
      let best: LiveVersionShare | null = null;
      for (const s of slices) if (best === null || s.percentage > best.percentage) best = s;
      if (best === null) {
        throw new Error(`Cloudflare's current deployment for "${scriptName}" did not include a version id; cannot record a rollback target. Nothing was changed.`);
      }
      return best.versionId;
    },

    // currentLiveVersions returns every live slice so orchestration can tell a single-version deployment
    // from a split (the console never ramps, but an out-of-band split must still be collapsed safely).
    async currentLiveVersions(): Promise<LiveVersionShare[]> {
      return readLiveSlices();
    },

    // uploadVersion creates a NEW, NOT-YET-LIVE console version and returns its id. Order is the safety:
    //   1. read the LIVE settings FIRST (fail early; preserve every binding: the ENGINE service binding,
    //      vars, and the assets binding identity -- Cloudflare REPLACES the binding set on each version);
    //   2. refuse on any binding type the pipeline cannot guarantee to carry forward (never drop blind);
    //   3. run the manifest -> session -> bucket-upload flow (deduplicated; nothing live yet);
    //   4. POST the new version: main module = the bundle's shell worker, bindings = the preserved live
    //      set, assets wired to the completion token, compat date + run_worker_first + cpu limit from the
    //      artefact's static config (release facts), compat flags carried from the live script.
    // Nothing here changes what serves: a version is inert until deployVersion promotes it.
    async uploadVersion(bundle: ConsoleBundle): Promise<string> {
      const { bindings, compatibilityDate, compatibilityFlags } = await readConsoleSettings();
      assertBoundToThisEngine(bindings);
      const { nonSecretBindings, keepBindings, unknownTypes } = classifyBindings(bindings);
      if (unknownTypes.length > 0) {
        throw new Error(`refusing to upload a new console version: the console has binding type(s) the update pipeline cannot guarantee to preserve (${unknownTypes.join(", ")}); a self-deploy could drop them and break the console. Use the wrangler deploy path for this update. Nothing was uploaded.`);
      }

      const completionJwt = await uploadAssets(bundle.assets);

      // The version metadata: preserved bindings + the assets completion token + the release's static
      // config. compatibility_date prefers the artefact's declared date (a version-controlled release
      // fact); the live script's date is the fallback so a config-less bundle cannot regress the runtime
      // contract. run_worker_first rides INSIDE assets.config (wrangler's shape).
      const metadata: Record<string, unknown> = {
        main_module: bundle.worker.mainModule,
        bindings: nonSecretBindings,
        keep_bindings: keepBindings,
        ...(bundle.config.compatibilityDate !== undefined || compatibilityDate !== undefined
          ? { compatibility_date: bundle.config.compatibilityDate ?? compatibilityDate }
          : {}),
        ...(compatibilityFlags !== undefined ? { compatibility_flags: compatibilityFlags } : {}),
        ...(bundle.config.cpuMs !== undefined ? { limits: { cpu_ms: bundle.config.cpuMs } } : {}),
        assets: {
          jwt: completionJwt,
          config: {
            ...(bundle.config.runWorkerFirst !== undefined ? { run_worker_first: bundle.config.runWorkerFirst } : {}),
          },
        },
      };

      const form = new FormData();
      form.append("metadata", JSON.stringify(metadata));
      const moduleBlob = new Blob([new Uint8Array(bundle.worker.source)], { type: "application/javascript+module" });
      form.append(bundle.worker.mainModule, moduleBlob, bundle.worker.mainModule);

      const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/versions`;
      const resp = await fetchImpl(url, { method: "POST", headers: auth, body: form });
      const body = (await resp.json().catch(() => null)) as CfEnvelope<{ id?: unknown }> | null;
      if (!resp.ok || body?.success !== true) {
        const { why } = cfErr(body, resp.status);
        throw new Error(`the new console version could not be uploaded (Cloudflare: ${why}); your console is unchanged (an uploaded version is not live until it is deployed, and nothing was deployed). The token needs Workers Scripts: Edit on account ${accountId}.`);
      }
      const id = body.result?.id;
      if (typeof id !== "string" || id === "") {
        throw new Error("Cloudflare accepted the console upload but did not return a version id, so the new version cannot be promoted; your console is unchanged. Try again, or use the wrangler deploy path.");
      }
      return id;
    },

    // deployVersion makes a console version THE LIVE DEPLOYMENT at 100%: the atomic promote, and the
    // SAME call performs a console rollback (deploy the recorded prior version id). Cloudflare deploys
    // are atomic, so a failed deploy leaves the previously-live console version serving. The ownership
    // proof runs here too (a rollback-only flow has no earlier settings read of its own).
    async deployVersion(versionId: string): Promise<void> {
      assertBoundToThisEngine((await readConsoleSettings()).bindings);
      const url = `${CF_API}/accounts/${A}/workers/scripts/${S}/deployments`;
      const resp = await fetchImpl(url, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({ strategy: "percentage", versions: [{ version_id: versionId, percentage: 100 }] }),
      });
      const body = (await resp.json().catch(() => null)) as CfEnvelope<unknown> | null;
      if (!resp.ok || body?.success !== true) {
        const { why } = cfErr(body, resp.status);
        throw new Error(`could not make console version ${versionId} the live deployment (Cloudflare: ${why}); the previously-live console version is still serving (Cloudflare deploys are atomic, so nothing was half-applied). The token needs Workers Scripts: Edit on account ${accountId}.`);
      }
    },
  };
}
