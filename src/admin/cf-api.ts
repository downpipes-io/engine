// The Cloudflare API plumbing half of the in-product attach + key install (see attach.ts for the
// full narrative). These are the network helpers that read the engine's deployed bindings, diagnose
// an opaque read failure into a precise cause, probe a token's capabilities, and put/delete a worker
// secret. attach.ts re-exports nothing from here (these are internal), so no importer changes.
//
// The deploy token is used for these calls only and is never stored or logged; every error message is
// redaction-safe (it names sizes/shapes/binding names, never a value).

import type { AttachSource, LiveBinding } from "./attach-plan.ts";
import type { AttachRefusalCause } from "./discovery-health.ts";

const CF_API = "https://api.cloudflare.com/client/v4";

// cfErr extracts a redaction-safe reason + codes from a Cloudflare API error body.
function cfErr(body: { errors?: Array<{ code?: number; message?: string }> } | null, status: number): { why: string; codes: number[] } {
  const codes = body?.errors?.map((e) => e.code).filter((c): c is number => typeof c === "number") ?? [];
  const why = body?.errors?.map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${status}`;
  return { why, codes };
}

// ---- The Cloudflare API fault, as CLOSED, RECORDABLE evidence --------------------------------------
//
// THE GAP: cfErr already extracts Cloudflare's NUMERIC error codes and then DROPS them on the floor -- every
// caller keeps only `why`, the joined human MESSAGE, which is then interpolated into a thrown Error that becomes
// an HTTP response and is recorded nowhere. So an attach or a key install that fails with "Cloudflare: HTTP 502"
// during a CF incident is indistinguishable, remotely, from one that failed on a token scope: support cannot
// tell an EDGE OUTAGE (wait) from a TOKEN PROBLEM (recreate the token). And `.json().catch(() => null)` masks a
// non-JSON body (an HTML edge error page -- itself the signature of an incident) as a bare status.
//
// THE FIX: the numeric codes ARE Cloudflare's own fixed vocabulary and carry no customer data, so they are safe
// to carry. CfApiFault TAGS the throw at the site that knows, with a bounded, closed shape; the caller records
// the tag (never the message). The thrown MESSAGE is unchanged, so every existing operator-facing string, test
// and HTTP response is byte-identical.
//
// REDACTION: the raw body (which can embed account names, script names and Cloudflare prose) NEVER rides. Only:
// a clamped HTTP status, its coarse class, up to 8 integer error codes, and a closed body class.
export const CF_BODY_CLASSES = ["json-api-error", "json-no-errors", "non-json"] as const;
export type CfBodyClass = (typeof CF_BODY_CLASSES)[number];
export const CF_STATUS_CLASSES = ["2xx", "4xx", "429", "5xx", "other"] as const;
export type CfStatusClass = (typeof CF_STATUS_CLASSES)[number];
// A real Cloudflare error body carries one or two codes. The cap bounds a pathological body.
const CF_CODES_MAX = 8;

/** The bounded, redaction-safe shape of ONE Cloudflare API failure. Closed enums + clamped ints only. */
export interface CfApiFaultInfo {
  readonly httpStatus: number; // clamped 0..599
  readonly statusClass: CfStatusClass;
  readonly cfCodes: number[]; // Cloudflare's OWN numeric error codes, capped at 8 (a fixed vendor vocabulary)
  readonly bodyClass: CfBodyClass;
}

/**
 * cfStatusClass coarsens an HTTP status into the closed class the bot branches on. 429 gets its own class (it is
 * a throttle, not a fault: the remediation is to slow down, not to re-scope a token).
 *
 * @param status - the HTTP status.
 * @returns the closed class.
 */
export function cfStatusClass(status: number): CfStatusClass {
  if (status === 429) return "429";
  if (status >= 200 && status < 300) return "2xx";
  if (status >= 400 && status < 500) return "4xx";
  if (status >= 500 && status < 600) return "5xx";
  return "other";
}

/**
 * cfFaultInfo builds the bounded fault record from a Cloudflare response's status and its already-parsed body.
 * PURE, and the single redaction chokepoint for this evidence: it takes the codes (integers) and the SHAPE of
 * the body, never the body itself. A null body (the `.json().catch(() => null)` mask) is reported as "non-json"
 * -- which is the diagnostic point: an HTML edge error page IS the signature of a Cloudflare incident, and it
 * used to be flattened into a bare status.
 *
 * @param body - the parsed JSON body, or null when it would not parse.
 * @param status - the HTTP status.
 * @returns the bounded fault record.
 */
export function cfFaultInfo(body: { errors?: Array<{ code?: number; message?: string }> } | null, status: number): CfApiFaultInfo {
  const httpStatus = Number.isFinite(status) ? Math.max(0, Math.min(599, Math.trunc(status))) : 0;
  const rawCodes = body?.errors?.map((e) => e.code).filter((c): c is number => typeof c === "number" && Number.isInteger(c)) ?? [];
  const cfCodes = rawCodes.slice(0, CF_CODES_MAX);
  const bodyClass: CfBodyClass = body === null ? "non-json" : rawCodes.length > 0 ? "json-api-error" : "json-no-errors";
  return { httpStatus, statusClass: cfStatusClass(httpStatus), cfCodes, bodyClass };
}

/**
 * CfApiFault is a plain Error carrying the bounded fault record alongside its UNCHANGED operator-facing message.
 * Callers that want the evidence read the tag with cfFaultOf; callers that only want to surface the message are
 * completely unaffected (it is still an Error with the same .message).
 */
export class CfApiFault extends Error {
  readonly cfFault: CfApiFaultInfo;
  constructor(message: string, fault: CfApiFaultInfo) {
    super(message);
    this.name = "CfApiFault";
    this.cfFault = fault;
  }
}

/**
 * cfFaultOf reads the bounded fault record off a thrown value, or null when it carries none. It NEVER inspects an
 * untagged error's message: an untagged throw is one no site classified, and guessing from its text is exactly
 * the free-text leak the tag exists to prevent (the sealErrorClassOf idiom). Every field is re-validated here, so
 * even a forged tag cannot widen what is recorded.
 *
 * @param e - the thrown value.
 * @returns the bounded fault, or null.
 */
export function cfFaultOf(e: unknown): CfApiFaultInfo | null {
  const f = (e as { cfFault?: unknown } | null)?.cfFault as Partial<CfApiFaultInfo> | undefined;
  if (f === undefined || f === null || typeof f !== "object") return null;
  const status = typeof f.httpStatus === "number" && Number.isFinite(f.httpStatus) ? Math.max(0, Math.min(599, Math.trunc(f.httpStatus))) : 0;
  const codes = Array.isArray(f.cfCodes) ? f.cfCodes.filter((c): c is number => typeof c === "number" && Number.isInteger(c)).slice(0, CF_CODES_MAX) : [];
  const bodyClass = (CF_BODY_CLASSES as readonly string[]).includes(String(f.bodyClass)) ? (f.bodyClass as CfBodyClass) : "non-json";
  return { httpStatus: status, statusClass: cfStatusClass(status), cfCodes: codes, bodyClass };
}

// diagnoseRead turns an opaque versions-read failure into a precise cause by making the
// canonical "does this token work + what is here" call: list the account's Workers. If
// THAT also fails, the token genuinely cannot read Workers in this account (wrong account,
// or scoped to a zone not the account). If it succeeds, the token works and the failure is
// the SCRIPT NAME, so the message lists the workers that ARE in the account so the operator
// can see which name to set WORKER_NAME to; malformed rows (a non-string id) are dropped.
// Returns the message to throw.
async function diagnoseRead(token: string, accountId: string, scriptName: string, readWhy: string, fetchImpl: typeof fetch): Promise<string> {
  const auth = { authorization: `Bearer ${token}` };
  try {
    const resp = await fetchImpl(`${CF_API}/accounts/${accountId}/workers/scripts`, { method: "GET", headers: auth });
    const body = (await resp.json().catch(() => null)) as { success?: boolean; result?: Array<{ id?: unknown }>; errors?: Array<{ code?: number; message?: string }> } | null;
    if (resp.ok && body?.success === true && Array.isArray(body.result)) {
      const names = body.result.map((s) => (typeof s.id === "string" ? s.id : "")).filter((n) => n !== "");
      if (!names.includes(scriptName)) {
        if (names.length === 0) {
          // The token reads this account fine, but it has NO workers, so the engine is
          // deployed in a DIFFERENT account than this one (this id came from the R2
          // destination, which can live in another account). The token must be scoped to,
          // and the attach must target, the account the engine worker is actually in.
          return `the token works, but account ${accountId} has no workers in it at all, so the engine is deployed in a different Cloudflare account than this one (this id comes from the R2 destination, which can be a separate account). Find the account that holds the engine worker (Workers & Pages in the dashboard), and use a token scoped to THAT account. Or use the wrangler deploy path, which needs no token.`;
        }
        const list = names.join(", ");
        return `the token works, but there is no worker named "${scriptName}" in account ${accountId}. The workers in this account are: ${list}. The engine's deployed name is one of those, set the WORKER_NAME var to it and redeploy the engine, then try again. Or use the wrangler deploy path, which needs no token.`;
      }
      // The name exists and the token can read the account, but the versions read failed:
      // a versions-specific scope the template did not grant.
      return `the token can list this account's workers but not "${scriptName}"'s settings (Cloudflare: ${readWhy}). Recreate the token from the "Edit Cloudflare Workers" template (it grants Workers Scripts edit, which the binding read and write both need), or use the deploy path.`;
    }
    const { why } = cfErr(body, resp.status);
    return `the token cannot read Workers in account ${accountId} (Cloudflare: ${why}). Two things to check on the token: it must be created from the "Edit Cloudflare Workers" template, and under Account Resources it must be scoped to THIS account (${accountId}), not a zone, and not a different account in your organisation. Or use the wrangler deploy path, which needs no token.`;
  } catch {
    return `could not read this engine on account ${accountId} (Cloudflare: ${readWhy}). Use the wrangler deploy path, which needs no token.`;
  }
}

// readDeployedBindings reads the engine's CURRENT binding set from the SAME endpoint the
// write uses, GET of the script settings (result.bindings), so any token that can perform
// the attach's write (PATCH settings) can, by construction, perform this read: read and
// write are one Cloudflare permission with no asymmetric-scope gap. (The versions API is a
// separate subresource the "Edit Cloudflare Workers" template need not grant; reading from
// the settings endpoint also guarantees the read shape equals the write shape, so re-sending
// existing bindings verbatim is exact.) Throws on any anomaly so the caller refuses rather
// than acting on a bad read. Used for both the pre-read and the post-verify. quiet skips the
// extra diagnostic round-trip on the post-verify read (where a failure tells a different story).
export async function readDeployedBindings(token: string, accountId: string, scriptName: string, fetchImpl: typeof fetch, quiet = false): Promise<LiveBinding[]> {
  const auth = { authorization: `Bearer ${token}` };
  const url = `${CF_API}/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`;

  const resp = await fetchImpl(url, { method: "GET", headers: auth });
  const body = (await resp.json().catch(() => null)) as { success?: boolean; result?: { bindings?: unknown }; errors?: Array<{ code?: number; message?: string }> } | null;
  if (!resp.ok || body?.success !== true) {
    const { why } = cfErr(body, resp.status);
    // G026: TAG both arms with the bounded fault, so the attach-refusal record can name a CF edge outage (5xx +
    // non-json body) apart from a token scope problem (4xx + code 10000). The messages are unchanged.
    const fault = cfFaultInfo(body, resp.status);
    if (quiet) throw new CfApiFault(`could not re-read the engine's settings for the post-write check (Cloudflare: ${why}).`, fault);
    // Turn the opaque failure into a precise cause (token vs account vs script name).
    throw new CfApiFault(await diagnoseRead(token, accountId, scriptName, why, fetchImpl), fault);
  }
  const bindings = body.result?.bindings;
  if (!Array.isArray(bindings)) {
    throw new Error(`Cloudflare returned settings without a readable bindings list for "${scriptName}"; refusing to modify the engine blind. Use the wrangler deploy path.`);
  }
  return bindings as LiveBinding[];
}

// checkTokenWindow asks Cloudflare whether the token is usable RIGHT NOW. A token whose Start
// Date is in the future, or which has expired, authenticates as a plain "Authentication error"
// on every endpoint, which is indistinguishable from a scope problem unless you ask the token
// verify endpoint directly. /accounts/{id}/tokens/verify reports the not_before / expires_on
// window and status for an account-owned token. Returns a precise message if the token is
// unusable for a time-window reason, or null (proceed) when it is active or the check does not
// apply (e.g. a user-owned token, which this endpoint will not confirm, the capability probes
// then speak). Never throws.
//
// `cause` is the CLOSED verdict beside the (byte-identical) operator message. The message is prose that
// interpolates the token's not_before / expires_on and Cloudflare's own wording; it can never be recorded. The
// cause can, and it is the whole diagnosis: a FUTURE Start Date, an EXPIRED token and a token Cloudflare would
// not confirm at all are three different sentences to the customer, and all three used to reach support as one
// undifferentiated "attach failed".
export async function checkTokenWindow(token: string, accountId: string, fetchImpl: typeof fetch): Promise<{ problem: string | null; cause?: AttachRefusalCause; tokenId?: string; expiresOn?: string }> {
  try {
    const r = await fetchImpl(`${CF_API}/accounts/${encodeURIComponent(accountId)}/tokens/verify`, { method: "GET", headers: { authorization: `Bearer ${token}` } });
    const b = (await r.json().catch(() => null)) as { success?: boolean; result?: { id?: string; status?: string; not_before?: string; expires_on?: string }; messages?: Array<{ code?: number; message?: string }>; errors?: Array<{ code?: number; message?: string }> } | null;
    if (b == null) return { problem: null };
    // Capture the redaction-safe window facts for the credential lifecycle registry from the SAME verify
    // call (no second request): the PUBLIC token id and its expires_on. Present only for an ACCOUNT-OWNED
    // token (a user-owned token returns nothing usable here); the token VALUE is NEVER captured.
    const facts: { tokenId?: string; expiresOn?: string } = {};
    if (typeof b.result?.id === "string") facts.tokenId = b.result.id;
    if (typeof b.result?.expires_on === "string") facts.expiresOn = b.result.expires_on;
    const notes = [...(b.messages ?? []), ...(b.errors ?? [])];
    // Not yet active: a Start Date in the future (Cloudflare message code 10002).
    if (notes.some((m) => m.code === 10002 || /can ?not be used before|not yet valid/i.test(m.message ?? ""))) {
      const when = b.result?.not_before ? ` It does not become valid until ${b.result.not_before} (UTC).` : "";
      return { problem: `the token is not active yet: its Start Date is in the future, so Cloudflare rejects every call from it as an "Authentication error".${when} Recreate the token (or edit it) with the Start Date set to today or left blank, and an Expiry far enough out, then paste it again.`, cause: "token-not-yet-active", ...facts };
    }
    // Expired or otherwise not active.
    const status = b.result?.status;
    if (b.success === true && status !== undefined && status !== "active") {
      const exp = b.result?.expires_on ? ` (expires ${b.result.expires_on} UTC)` : "";
      return { problem: `the token's status is "${status}", not active${exp}. Create a fresh token from the "Edit Cloudflare Workers" template, scoped to this account, with no Start Date and a sensible Expiry.`, cause: "token-status-inactive", ...facts };
    }
    if (notes.some((m) => /expired/i.test(m.message ?? ""))) {
      return { problem: `the token has expired. Create a fresh token from the "Edit Cloudflare Workers" template, scoped to this account, with no Start Date and a sensible Expiry.`, cause: "token-expired", ...facts };
    }
    return { problem: null, ...facts };
  } catch {
    // The verify call itself could not complete (a Cloudflare blip, an egress fault). The attach proceeds --
    // the capability probes refuse safely on a bad token, so this is the right availability choice -- but it
    // proceeds BLIND to the token's window, so a later generic "Authentication error" may in fact be a Start
    // Date nobody was able to check. G244: say so, rather than presenting the unchecked window as a good one.
    return { problem: null, cause: "window-unreadable" };
  }
}

// A token capability the attach needs on the engine's account, with the cheap account-scoped
// READ that the gating permission allows (so we can probe what the token can actually do) and
// the dashboard permission name to add if it cannot.
export interface Capability { key: string; label: string; needs: string; path: string; }

// neededCapabilities returns exactly the capabilities THIS change requires: always Workers
// Scripts (to read AND write the engine's own settings), plus read access to each SOURCE
// resource type being attached, Cloudflare will not let the engine bind a namespace, bucket,
// database or secret the token cannot itself see (which is WHY the "Edit Cloudflare Workers"
// template bundles KV and R2; it predates D1 and Secrets Store, so those sources need their
// permission added). A pure detach (no additions) needs only Workers Scripts.
export function neededCapabilities(accountId: string, add: AttachSource[]): Capability[] {
  const A = encodeURIComponent(accountId);
  const all: Record<string, Capability> = {
    workers: { key: "workers", label: "Workers Scripts", needs: "Workers Scripts (edit)", path: `/accounts/${A}/workers/scripts` },
    kv: { key: "kv", label: "Workers KV", needs: "Workers KV Storage (edit)", path: `/accounts/${A}/storage/kv/namespaces?per_page=1` },
    r2: { key: "r2", label: "R2", needs: "Workers R2 Storage (edit)", path: `/accounts/${A}/r2/buckets?per_page=1` },
    d1: { key: "d1", label: "D1", needs: "D1 (edit)", path: `/accounts/${A}/d1/database?per_page=1` },
    secrets: { key: "secrets", label: "Secrets Store", needs: "Secrets Store (edit)", path: `/accounts/${A}/secrets_store/stores?per_page=1` },
  };
  const keys = new Set<string>(["workers"]);
  for (const s of add) if (s.type in all) keys.add(s.type);
  return [...keys].map((k) => all[k]).filter((c): c is Capability => c !== undefined);
}

// CAP_PROBE_OUTCOMES is what ONE capability probe ESTABLISHED, as a closed tag rather than a boolean.
//
// The probe used to report `ok: r.ok && b?.success === true`, with `catch { ok: false }`. That is a boolean over
// four different worlds: a Cloudflare 403 (the token genuinely lacks the capability), a Cloudflare 500 (the token
// was never assessed), a 429 (the token was never assessed) and a socket reset (the token was never assessed).
// All four came out false, and the caller then refused the change as "token-scope" -- a class whose MEANING is
// "the engine PROVED the token cannot do this". Support read that and re-minted a perfectly good deploy token
// while the customer's Cloudflare 5xx and 429s sat in their own logs. Only `refused` establishes a fact about the
// token; the rest establish a fact about Cloudflare, and the caller must say so.
export const CAP_PROBE_OUTCOMES = [
  "allowed", // Cloudflare answered the capability's read with success: the token CAN use it
  "refused", // Cloudflare answered 401/403: it refused this capability to this token. It proves the token lacks THIS CAPABILITY
  "token-invalid", // Cloudflare answered that the TOKEN ITSELF is bad (its own error code 1000 "Invalid API Token", or 9109 / 6003 on the same family). This is NOT a capability refusal and NOT a Cloudflare fault: the pasted token is wrong, expired or revoked, and re-minting it IS the remedy
  "rate-limited", // Cloudflare answered 429: throttled, and the token was never assessed
  "unavailable", // Cloudflare answered 5xx: its own fault, and the token was never assessed
  "inconclusive", // Cloudflare answered, but with neither success nor a refusal nor a token verdict nor a transient status: the token was never assessed. This member tells the operator NOT to re-mint, so nothing that Cloudflare has actually blamed the token for may land here
  "transport", // the probe never reached Cloudflare (it threw before a status was seen): the token was never assessed
] as const;

// Cloudflare's OWN error codes for "the API token you sent is not usable". They arrive on an HTTP 400, not a 401,
// which is why a status-only classifier put them in `inconclusive` and told the operator the token was fine.
// That is the exact inversion this vocabulary exists to prevent: the one state where the token IS the fault was
// the one state where the engine said to leave the token alone. Numbers only; no Cloudflare prose is read.
const CF_TOKEN_INVALID_CODES: ReadonlySet<number> = new Set([1000, 6003, 9109]);
export type CapProbeOutcome = (typeof CAP_PROBE_OUTCOMES)[number];

// auditToken probes each needed capability with its read and reports what Cloudflare ANSWERED for each, so a
// missing permission becomes a precise checklist rather than a generic "Authentication error", and a Cloudflare
// outage is never mistaken for one. Probes run concurrently and never throw. A probe that did not get a
// success is still "do not proceed" (the caller refuses either way, and nothing is written); the difference is
// what the caller is entitled to SAY about it.
export async function auditToken(token: string, caps: Capability[], fetchImpl: typeof fetch): Promise<{ cap: Capability; outcome: CapProbeOutcome }[]> {
  const auth = { authorization: `Bearer ${token}` };
  return Promise.all(caps.map(async (cap) => {
    try {
      const r = await fetchImpl(`${CF_API}${cap.path}`, { method: "GET", headers: auth });
      const b = (await r.json().catch(() => null)) as { success?: boolean; errors?: Array<{ code?: number; message?: string }> } | null;
      if (r.ok && b?.success === true) return { cap, outcome: "allowed" as CapProbeOutcome };
      if (r.status === 401 || r.status === 403) return { cap, outcome: "refused" as CapProbeOutcome };
      // Cloudflare's verdict on the TOKEN, which arrives on a 400 and not a 401. Checked BEFORE the residual
      // below, because the residual's meaning is "we established nothing, do not re-mint the token", and a token
      // Cloudflare has explicitly rejected is the one case where re-minting is exactly the remedy. Only the
      // numeric codes are read; the message is never touched.
      const codes = b?.errors?.map((e) => e.code).filter((c): c is number => typeof c === "number") ?? [];
      if (codes.some((c) => CF_TOKEN_INVALID_CODES.has(c))) return { cap, outcome: "token-invalid" as CapProbeOutcome };
      if (r.status === 429) return { cap, outcome: "rate-limited" as CapProbeOutcome };
      if (r.status >= 500 && r.status <= 599) return { cap, outcome: "unavailable" as CapProbeOutcome };
      return { cap, outcome: "inconclusive" as CapProbeOutcome };
    } catch {
      return { cap, outcome: "transport" as CapProbeOutcome };
    }
  }));
}

// SECRET_TEXT is Cloudflare's wire `type` for a plaintext secret on the dedicated secrets endpoint.
const SECRET_TEXT = "secret_text";

// putSecret sets ONE worker secret by name via PUT .../secrets, mirroring the CF_API /
// account / script-name / Bearer / error conventions. On a failed PUT it throws a loud, named
// error that points at the required "Edit Cloudflare Workers" scope (exactly as the attach harness
// does), and the caller does NOT continue setting the rest, so a scope failure can never leave a
// partial-but-unannounced key set. The secret VALUE never enters the thrown message or any log.
export async function putSecret(token: string, accountId: string, scriptName: string, name: string, value: string, fetchImpl: typeof fetch): Promise<void> {
  const url = `${CF_API}/accounts/${encodeURIComponent(accountId)}/workers/scripts/${encodeURIComponent(scriptName)}/secrets`;
  const resp = await fetchImpl(url, {
    method: "PUT",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ name, text: value, type: SECRET_TEXT }),
  });
  const body = (await resp.json().catch(() => null)) as { success?: boolean; errors?: Array<{ code?: number; message?: string }> } | null;
  if (!resp.ok || body?.success !== true) {
    const { why } = cfErr(body, resp.status);
    // TAG the throw with the bounded fault (status class + Cloudflare's own numeric codes + the body
    // class) so the key-ceremony route can AUDIT a half-applied install by cause instead of by an unrecorded
    // message. The message itself is unchanged, so the operator-facing 400 is byte-identical.
    throw new CfApiFault(
      `could not set the engine secret ${name} (Cloudflare: ${why}). The token must be created from the dashboard "Edit Cloudflare Workers" template and scoped to the engine's OWN account (it grants Workers Scripts edit, which writing a Worker secret needs). Nothing further was set. Or use the wrangler deploy path, which needs no token.`,
      cfFaultInfo(body, resp.status),
    );
  }
}

// deleteSecret removes ONE worker secret by name via DELETE .../secrets/{name} (the per-secret ITEM
// endpoint, distinct from putSecret's collection endpoint), mirroring the CF_API / account / script /
// Bearer / error conventions. Cloudflare treats a delete the same as a put for propagation: it deploys
// a new worker version with the binding absent, available to the running worker without a manual
// redeploy. A missing secret (already absent) is treated as success so the operation is idempotent.
// The secret name appears in the thrown message (it is a fixed env-var name, never a value).
export async function deleteSecret(token: string, accountId: string, scriptName: string, name: string, fetchImpl: typeof fetch): Promise<void> {
  const url = `${CF_API}/accounts/${encodeURIComponent(accountId)}/workers/scripts/${encodeURIComponent(scriptName)}/secrets/${encodeURIComponent(name)}`;
  const resp = await fetchImpl(url, {
    method: "DELETE",
    headers: { authorization: `Bearer ${token}` },
  });
  // 404 means the secret is already gone, which is the desired end state: treat it as success.
  if (resp.status === 404) return;
  const body = (await resp.json().catch(() => null)) as { success?: boolean; errors?: Array<{ code?: number; message?: string }> } | null;
  if (!resp.ok || body?.success !== true) {
    const { why } = cfErr(body, resp.status);
    // G026 / G027: same bounded tag on the REMOVAL path. A break-glass-only switch that dies after deleting
    // OPERATIONAL_PRIVATE but before OPERATIONAL_PUBLIC leaves the engine half-posture with (until now) no record.
    throw new CfApiFault(
      `could not remove the engine secret ${name} (Cloudflare: ${why}). The token must be created from the dashboard "Edit Cloudflare Workers" template and scoped to the engine's OWN account. Nothing further was changed.`,
      cfFaultInfo(body, resp.status),
    );
  }
}
