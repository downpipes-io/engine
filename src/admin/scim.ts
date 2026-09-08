// Minimal SCIM 2.0 deprovision facade (RFC 7644, the /Users subset only). An identity provider's
// SCIM connector calls this to OFFBOARD a leaver: a DELETE /scim/v2/Users/{id} or a
// PATCH /scim/v2/Users/{id} with `active:false` removes the member, driving the SAME existing,
// audited offboarding the console's POST /admin/roles/delete drives (role removal + per-email session
// epoch bump + per-subject not-before, terminating live sessions, idempotent).
//
// SCOPE (deliberately a thin facade, NOT full SCIM CRUD): this surface PROVISIONS nothing and READS
// no user records. {id} is the URL-encoded member email (the SCIM connector is configured with email
// as the externalId / userName). DELETE and PATCH(active:false) deprovision; PATCH(active:true),
// POST, PUT and GET on a user are out of scope (provisioning happens through the console's role grant
// + IdP login, not here). ServiceProviderConfig advertises this honestly. The deferral is stated in
// the ServiceProviderConfig response so a connector author sees exactly what is and is not supported.
//
// AUTH: a DEDICATED bearer (env.SCIM_BEARER_TOKEN), separate from the owner break-glass ADMIN_TOKEN,
// so the connector holds only a leaver credential. Unset -> the whole surface is 503 (fail closed, no
// functionality without an explicit secret). Set -> the presented bearer is compared in CONSTANT TIME
// over the SHA-384 of each side (fixed 48-byte digests, so constantTimeEqual never short-circuits on
// length and there is no length oracle). A per-IP rate limit (the same fail-closed brute-force gate the
// unauthenticated /admin/auth ceremony uses) fronts the bearer check.

import { constantTimeEqual, utf8 } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { CALLER_HEADER, type Caller, encodeCaller, SCIM_OFFBOARD_EMAIL, SCIM_OFFBOARD_SUBJECT } from "./identity.ts";
import { OWNER_FLOOR_REFUSAL_CODE } from "./owner-floor.ts";
import { authRateLimited } from "./router-core.ts";
import { doURL, schedulerStub } from "./router-helpers.ts";
import { routeAuthChangeAlert } from "./router-notify.ts";

// SCIM_OFFBOARD_CALLER is the internal owner-authority the SCIM facade forwards to the DO's
// /roles/delete, the SAME method:"token" owner break-glass the engine's own cron uses for its internal
// authority (cron/restore-test-pass.ts ENGINE_DRILL_CALLER). The caller header is router-internal (built
// only here from the verified SCIM bearer, never copied from a client header; see callerHeaders /
// CALLER_HEADER), so this forged owner header cannot reach the DO from a client request.
//
// email/subject are a STABLE SYNTHETIC identity, NOT null (ASVS V7.4.1/V7.4.2), imported from identity.ts
// rather than inlined here because the DO's routing layer ALSO needs the exact same literal: it recognises
// this one caller (isScimOffboardCaller) to route an automated, IdP-driven offboarding straight to the
// validated apply path INSTEAD OF the human dual-control approval queue, regardless of whether "Require
// approval for config changes" is on (a queued approval cannot work for this caller, since no login flow
// can ever bind this synthetic subject for the queue's approve-time replay to re-resolve authority from).
// email/subject grant no authority themselves --
// roleForCaller's method==="token" branch resolves authority from `method` ALONE, before ever consulting
// them -- they exist so the audit trail names the actor as the automated SCIM connector rather than a
// blank. The DO still records the OFFBOARDED member (not this caller) as the audit target, so the trail
// names who was removed.
const SCIM_OFFBOARD_CALLER: Caller = {
  method: "token",
  email: SCIM_OFFBOARD_EMAIL,
  subject: SCIM_OFFBOARD_SUBJECT,
  role: "owner",
  groups: [],
};

// SCIM_URN is the standard SCIM 2.0 schema/message URN namespace.
const SCIM_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

// scimError builds an RFC 7644 SCIM error response. `scimType` is the optional fine-grained code SCIM
// defines (e.g. "mutability"); `detail` is the human reason. The body carries the SCIM Error schema so a
// conformant connector parses it, and the content-type is application/scim+json.
function scimError(status: number, detail: string, scimType?: string): Response {
  return new Response(JSON.stringify({ schemas: [SCIM_ERROR], status: String(status), detail, ...(scimType !== undefined ? { scimType } : {}) }), {
    status,
    headers: { "content-type": "application/scim+json" },
  });
}

// scimBearerOk compares the presented `Authorization: Bearer <token>` against env.SCIM_BEARER_TOKEN in
// constant time over the SHA-384 of each side (no length leak). Returns false when the header is absent or
// malformed. The UNSET-secret case is handled by the caller (a 503), not here: this only answers "does the
// presented bearer match the configured one".
async function scimBearerOk(req: Request, configured: string): Promise<boolean> {
  const header = req.headers.get("authorization");
  if (header === null) return false;
  const presented = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  // Hash both sides so the comparison is over fixed 48-byte digests (constantTimeEqual returns early only on
  // a length mismatch, which can never happen between two SHA-384 outputs), removing any token-length oracle.
  const a = await sha384(utf8(presented));
  const b = await sha384(utf8(configured));
  return constantTimeEqual(a, b);
}

// recordScimSignal is the BEST-EFFORT (fire-and-forget) recorder for a SCIM auth/deprovision defensive-branch
// event into the DO's bounded auth-signal aggregate (P2), so a "my SCIM connector can't deprovision" ticket is
// diagnosable from the support pack: a bearer rejection (401, rotated/wrong bearer), a request while unconfigured
// (503, no deprovision path), a last-Owner-guard refusal, or (residual) any other offboard refusal - dual
// control ("Require Config Approval") is NOT one of these causes; it never blocks SCIM offboarding at all
// (HI-07, see isScimOffboardCaller in identity.ts). It never blocks or fails the SCIM response, and the DO
// drops any out-of-vocabulary name; only the closed event name crosses the wire (never the bearer / email).
//
// The write is CHECKED rather than a bare fire-and-forget: a scheduler DO that is unavailable (or answering
// non-2xx) has a dropped write counted in the droppedWrites aggregate (recordDiagWrite), so an INCOMPLETE
// pack says so instead of reading as clean. It still never throws, never blocks and never alters the SCIM
// response.
// waitUntil: scim.ts sits OUTSIDE the admin router tree (it is its own
// facade dispatched directly from index.ts), so it carries the raw ExecutionContext.waitUntil capability
// rather than an AdminRuntime -- same shape, same fireInBackground discipline as the rest of this triage,
// just without AdminRuntime's other admin-only fields to drag in. Optional throughout so a direct call with
// no fetch context (a unit test) still typechecks and falls back to the pre-existing bare-void behaviour.
function recordScimSignal(env: Env, name: string, waitUntil?: (task: Promise<unknown>) => void): void {
  try {
    const scheduler = schedulerStub(env); // throws synchronously on an unbound SCHEDULER env: contained here
    const write = recordDiagWrite(scheduler, "auth-signal", () =>
      scheduler.fetch(doURL("/auth-signal"), { method: "POST", body: JSON.stringify({ name }), headers: { "content-type": "application/json" } }),
    );
    if (waitUntil) waitUntil(write);
    else void write;
  } catch {
    /* best-effort: a diagnostic write must never affect the SCIM response */
  }
}

// offboard drives the EXISTING audited offboarding for an email through the DO's /roles/delete (the same
// path POST /admin/roles/delete drives). The DO's routing layer recognises SCIM_OFFBOARD_CALLER
// (isScimOffboardCaller, identity.ts) and applies the removal DIRECTLY, bypassing the human dual-control
// approval queue entirely regardless of the "Require Config Approval" setting (HI-07) - so a 202 (queued)
// is never a legitimate response for this caller. Returns true when a member was actually removed, false
// for an idempotent no-op (an already-absent member) - either way the member is now gone, a plain 204. Any
// non-200 (the last-Owner guard, which 400s; or, defensively, anything else including an unexpected 202)
// throws so the SCIM dispatcher reports a refusal rather than answering a false 204.

// ScimOffboardError carries the offboarding DO's refusal as STRUCTURE rather than prose (G003): the HTTP status
// (an int) and whether the last-Owner guard fired (a boolean), so the dispatcher can record a closed signal class
// without string-matching the DO's error text. The `message` still carries the DO's text for the SCIM error body
// the connector sees, but that text NEVER reaches the bounded aggregate: only status/lastOwner are read there.
// Explicit field declarations (no TS parameter properties): the engine's modules must stay Node strip-types
// compatible, and a parameter property is not strip-only syntax.
class ScimOffboardError extends Error {
  status: number;
  lastOwner: boolean;
  constructor(message: string, status: number, lastOwner: boolean) {
    super(message);
    this.name = "ScimOffboardError";
    this.status = status;
    this.lastOwner = lastOwner;
  }
}

// scimOffboardSignal maps a caught offboarding failure to its CLOSED signal name (G003). The last-Owner guard keeps
// its own bucket; anything else is bucketed by HTTP STATUS CLASS (4xx = a facade/DO contract drift, 5xx = a DO-side
// fault where the leaver was NOT removed and the connector will keep retrying). A non-HTTP failure (a fetch throw,
// so no status at all) falls to the pre-existing residual bucket. No error text is ever read here.
function scimOffboardSignal(e: unknown): string {
  if (!(e instanceof ScimOffboardError)) return "scim-offboard-refused";
  if (e.lastOwner) return "scim-last-owner-refused";
  if (e.status >= 500) return "scim-offboard-do-error-5xx";
  if (e.status >= 400) return "scim-offboard-do-error-4xx";
  return "scim-offboard-refused";
}

// isOwnerFloorRefusal decides, from the DO's refusal body, whether the Owner-floor guard fired. It reads a
// STRUCTURED FIELD (a closed refusal code) rather than matching the operator-facing sentence: the guard has
// two distinct refusal sentences (the last-Owner floor and the dual-control floor), and a copy change to
// either must never silently break this signal.
//
// A body that does not parse, or carries no code, answers FALSE, which files the refusal in the generic
// bucket. That is the honest direction: the alternative is asserting an Owner-floor refusal on no evidence,
// and the generic bucket is already the one that means "a facade/DO contract drift", which is exactly what an
// unreadable refusal body is.
function isOwnerFloorRefusal(text: string): boolean {
  try {
    return (JSON.parse(text) as { refusal?: unknown }).refusal === OWNER_FLOOR_REFUSAL_CODE;
  } catch {
    return false;
  }
}

// revokeSignInFactorsFirst issues the offboarding REVOKE ahead of the role delete, which is the ordering the
// SCIM-REVOKE plan settles on and the review confirmed at source.
//
// WHY REVOKE FIRST, and it is not a preference. `revokeSignInFactors` runs its whole veto (the Owner floor,
// the anti-escalation guard, the self-revocation refusal) BEFORE any of its three deletes, so issuing it first
// yields two properties at once: nothing irreversible happens for a request the engine was going to refuse,
// and the bearer secrets die before the authority does. The opposite order does not merely weaken that, it
// DISARMS it: delete the role row first and the revoke resolves its target from an absent roster entry, which
// `effectiveRole` reports as viewer, so the Owner floor never runs at all.
//
// WHY A FAILURE HERE DOES NOT ABORT THE OFFBOARD. The role delete is the half that removes AUTHORITY, and
// leaving a departed member's authority in place because a secondary store would not answer is the exposure a
// prompt deprovision exists to close. So a non-200 is recorded as its own signal and the offboard continues.
// The two are deliberately distinguishable: `scim-offboard-revoke-failed` means the revoke leg was issued and
// did not succeed, which is a different fact from the role delete failing.
async function revokeSignInFactorsFirst(env: Env, scheduler: ReturnType<typeof schedulerStub>, email: string, waitUntil?: (task: Promise<unknown>) => void): Promise<void> {
  let resp: Response;
  try {
    resp = await scheduler.fetch(doURL("/signin-factors/revoke"), {
      method: "POST",
      body: JSON.stringify({ email }),
      headers: { [CALLER_HEADER]: encodeCaller(SCIM_OFFBOARD_CALLER), "content-type": "application/json" },
    });
  } catch {
    recordScimSignal(env, "scim-offboard-revoke-failed", waitUntil);
    return;
  }
  const text = await resp.text();
  if (resp.status !== 200) {
    recordScimSignal(env, "scim-offboard-revoke-failed", waitUntil);
    return;
  }
  // THE REVOKE'S OWN AUDIT ROW IS CONDITIONAL: it is written only when a way in was actually closed
  // (`revocationClosedAWayIn`), so a revoke that ran correctly and found nothing live writes nothing at all.
  // On this unattended route that would be indistinguishable from a revoke that was never issued, and the
  // audit is the only witness there is. So the SCIM side records what it saw from the RETURN VALUE, which
  // exists either way.
  try {
    const body = JSON.parse(text) as { declined?: unknown; revoked?: { passkeyCredentials?: number; recovery?: boolean; invitesLive?: number } };
    if (body.declined === "unattended-owner") {
      recordScimSignal(env, "scim-offboard-revoke-declined-owner", waitUntil);
      return;
    }
    const r = body.revoked ?? {};
    const closed = (r.passkeyCredentials ?? 0) > 0 || r.recovery === true || (r.invitesLive ?? 0) > 0;
    recordScimSignal(env, closed ? "scim-offboard-revoked" : "scim-offboard-revoke-nothing-live", waitUntil);
  } catch {
    // A 200 whose body does not parse is a facade/DO contract drift, filed as such rather than guessed at.
    recordScimSignal(env, "scim-response-unparseable", waitUntil);
  }
}

async function offboard(env: Env, email: string, waitUntil?: (task: Promise<unknown>) => void): Promise<boolean> {
  const scheduler = schedulerStub(env);
  await revokeSignInFactorsFirst(env, scheduler, email, waitUntil);
  const resp = await scheduler.fetch(doURL("/roles/delete"), {
    method: "POST",
    body: JSON.stringify({ email }),
    headers: { [CALLER_HEADER]: encodeCaller(SCIM_OFFBOARD_CALLER), "content-type": "application/json" },
  });
  const text = await resp.text();
  if (resp.status !== 200) {
    // The DO refused outright (e.g. the last-Owner guard -> 400). Surface it as a throw so the dispatcher
    // maps it to a SCIM error rather than a false 204. G003: the throw now carries the DO's HTTP STATUS and a
    // structured last-Owner flag, so the dispatcher buckets the refusal on the status CLASS instead of
    // re-matching the DO's prose (a brittle string test that would silently misfile every refusal the day that
    // wording changed). The status is an int and the flag a boolean; the DO's text never reaches the aggregate.
    throw new ScimOffboardError(`offboarding refused: ${text}`, resp.status, isOwnerFloorRefusal(text));
  }
  let removed = false;
  try {
    removed = (JSON.parse(text) as { deleted?: boolean }).deleted === true;
  } catch {
    // The DO answered 200 but its body did not parse, so we do NOT know whether a member was removed. Record
    // the contract fault and continue CONSERVATIVELY (removed=true): a spurious "member removed" alert is far
    // safer than a missed real one.
    recordScimSignal(env, "scim-response-unparseable", waitUntil);
    removed = true;
  }
  // V6.3.7 parity with POST /admin/roles/delete: notify on an ACTUAL offboarding (a takeover/insider
  // signal). Fail-open, redaction-safe (names the removed email + the SCIM origin, never a secret).
  if (removed) {
    const alert = routeAuthChangeAlert(env, scheduler, "role-change", "offboard", `Member removed (offboarded) via SCIM: ${email}.`);
    if (waitUntil) waitUntil(alert);
    else void alert;
  }
  return removed;
}

// serviceProviderConfig is the honest capability advertisement (RFC 7643 §5): this provider supports
// PATCH (the active:false deprovision), does NOT support bulk/filter/sort/changePassword/ETag/password
// resets, and authenticates with a bearer (oauthbearertoken). The `documentationUri` records, in plain
// words, that the only supported operation is leaver DEPROVISION (DELETE or PATCH active:false).
function serviceProviderConfig(): Response {
  const body = {
    schemas: [SCIM_SPC],
    documentationUri: "deprovision-only: DELETE /scim/v2/Users/{id} or PATCH /scim/v2/Users/{id} with active:false offboards a member by email; provisioning, reads and reactivation are not supported",
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: false, maxResults: 0 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: "oauthbearertoken",
        name: "OAuth Bearer Token",
        description: "Authentication via the dedicated SCIM bearer token (SCIM_BEARER_TOKEN).",
        primary: true,
      },
    ],
  };
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/scim+json" } });
}

// patchDeactivates returns true when a SCIM PatchOp body sets `active` to false, false when it sets it to
// true, and undefined when the body is not a recognised active-toggle PatchOp. SCIM PatchOp paths are
// case-insensitive ("active"); a replace (or the default op) of active:false is the deprovision. We accept
// both the path-scoped form ({op:"replace",path:"active",value:false}) and the value-object form
// ({op:"replace",value:{active:false}}), which different IdP connectors emit.
function patchDeactivates(body: unknown): boolean | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const ops = (body as { Operations?: unknown }).Operations;
  if (!Array.isArray(ops)) return undefined;
  let sawActive = false;
  let active: boolean | undefined;
  for (const raw of ops) {
    if (typeof raw !== "object" || raw === null) continue;
    const op = raw as { op?: unknown; path?: unknown; value?: unknown };
    const verb = typeof op.op === "string" ? op.op.toLowerCase() : "";
    if (verb !== "replace" && verb !== "add" && verb !== "") continue;
    const path = typeof op.path === "string" ? op.path.toLowerCase() : "";
    if (path === "active") {
      if (typeof op.value === "boolean") {
        sawActive = true;
        active = op.value;
      }
    } else if (path === "" && typeof op.value === "object" && op.value !== null && "active" in (op.value as object)) {
      const v = (op.value as { active?: unknown }).active;
      if (typeof v === "boolean") {
        sawActive = true;
        active = v;
      }
    }
  }
  if (!sawActive) return undefined;
  return active === false;
}

// handleScim dispatches the /scim/v2 surface. It is reached from the Worker entry (index.ts) for any path
// under /scim/v2, BEFORE the /admin branch, so SCIM has its own auth (the dedicated bearer) and never
// touches the console auth model. The path is matched against the literal SCIM routes; an unrecognised one
// is a 404 SCIM error. The response is always application/scim+json (or 204 No Content with no body).
export async function handleScim(req: Request, env: Env, waitUntil?: (task: Promise<unknown>) => void): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // FAIL CLOSED when the surface is not configured: with no dedicated bearer, /scim/v2 has no
  // functionality at all and every request is 503, so a deployment that has not opted in has no SCIM
  // attack surface. (Contrast the always-on ServiceProviderConfig of a full provider: here even the
  // capability read requires the surface to be enabled, since there is nothing to integrate without it.)
  const configured = env.SCIM_BEARER_TOKEN;
  if (configured === undefined || configured.length === 0) {
    // P2: a SCIM connector is hitting an unconfigured surface -> no deprovision path is wired (leavers are not
    // being removed). Record the bounded signal (scim-unconfigured-no-deprovision).
    recordScimSignal(env, "scim-unconfigured", waitUntil);
    return new Response(JSON.stringify({ schemas: [SCIM_ERROR], status: "503", detail: "SCIM is not enabled on this deployment (no SCIM_BEARER_TOKEN configured)" }), {
      status: 503,
      headers: { "content-type": "application/scim+json" },
    });
  }

  // PER-IP brute-force gate on the bearer check (the same fail-closed limiter the unauthenticated
  // /admin/auth ceremony uses), so a stolen-endpoint guess is throttled and a limiter outage denies rather
  // than opens. It runs BEFORE the bearer comparison so a flood cannot exhaust CPU on the hash.
  const limited = await authRateLimited(schedulerStub(env), req, { waitUntil });
  if (limited !== null) return limited;

  // CONSTANT-TIME bearer check (fail closed): anything but a positive match is 401.
  if (!(await scimBearerOk(req, configured))) {
    // P2: a rejected SCIM bearer is the "bearer rotated / wrong -> deprovision now 401s" signal (scim-bearer-rotated-401).
    recordScimSignal(env, "scim-unauthorised", waitUntil);
    return scimError(401, "invalid or missing SCIM bearer token");
  }

  // GET /scim/v2/ServiceProviderConfig: the honest, deprovision-only capability advertisement.
  if (req.method === "GET" && path === "/scim/v2/ServiceProviderConfig") {
    return serviceProviderConfig();
  }

  // The /Users/{id} routes. {id} is the URL-encoded member email.
  const usersPrefix = "/scim/v2/Users/";
  if (path.startsWith(usersPrefix)) {
    const idRaw = path.slice(usersPrefix.length);
    // Each id-shape rejection records its OWN closed class, so a connector that 400s/404s forever (the leaver
    // is never removed) is distinguishable from a healthy-but-idle one. The offending id NEVER rides - only
    // the class.
    if (idRaw.length === 0 || idRaw.includes("/")) {
      recordScimSignal(env, "scim-id-rejected-empty", waitUntil);
      return scimError(404, "user id (email) required in the path");
    }
    let email: string;
    try {
      email = decodeURIComponent(idRaw);
    } catch {
      recordScimSignal(env, "scim-id-rejected-encoding", waitUntil);
      return scimError(400, "user id is not a valid URL-encoded value");
    }
    // Defence in depth at the facade (ASVS V5.1.3): reject an obviously malformed email before it
    // reaches the DO, including an embedded newline that could disturb downstream body parsing.
    if (!email.includes("@") || email.length > 320 || /[\r\n]/.test(email)) {
      // The single highest-value SCIM signal: an IdP sending the immutable objectId / externalId instead of the
      // email userName can never match a member, so EVERY deprovision fails silently until the mapping is fixed.
      recordScimSignal(env, "scim-id-rejected-email-shape", waitUntil);
      return scimError(400, "user id is not a valid email address");
    }

    if (req.method === "DELETE") return handleScimDelete(env, email, waitUntil);
    if (req.method === "PATCH") return handleScimPatch(req, env, email, waitUntil);

    // G003: a connector deactivating via an unsupported method (e.g. PUT with active:false) 405s forever.
    recordScimSignal(env, "scim-method-unsupported", waitUntil);
    return scimError(405, `${req.method} is not supported on /scim/v2/Users/{id}`);
  }

  // GET /scim/v2/Users (a bare list) is the one other route a connector probes; we honestly return an
  // EMPTY ListResponse (this facade does not enumerate users), which is a valid SCIM response and keeps a
  // connector from treating the surface as broken while disclosing no member data.
  if (req.method === "GET" && (path === "/scim/v2/Users" || path === "/scim/v2/Users/")) {
    return new Response(JSON.stringify({ schemas: [SCIM_LIST_RESPONSE], totalResults: 0, startIndex: 1, itemsPerPage: 0, Resources: [] }), {
      headers: { "content-type": "application/scim+json" },
    });
  }

  // G003: the connector is calling a SCIM route this facade does not implement (it expects a fuller provider).
  recordScimSignal(env, "scim-endpoint-unknown", waitUntil);
  return scimError(404, "unknown SCIM endpoint (this is a minimal deprovision-only /Users facade)");
}


// handleScimDelete handles DELETE /scim/v2/Users/{id}: offboard. 204 on success OR an already-absent member
// (idempotent deprovision, per SCIM); the DO's /roles/delete is itself idempotent ({deleted:false} for an
// absent member), so this is a 204 either way, REGARDLESS of dual control ("Require Config Approval"):
// offboard() bypasses that gate entirely for this caller (HI-07 - queuing it instead produced a WORSE,
// unapprovable stuck state, see identity.ts's isScimOffboardCaller). The one remaining thrown case in
// ordinary operation is the last-Owner guard (a 400 from the DO), reported as a SCIM error with a coarse
// log that carries no member email or secret.
async function handleScimDelete(env: Env, email: string, waitUntil?: (task: Promise<unknown>) => void): Promise<Response> {
  try {
    await offboard(env, email, waitUntil);
    return new Response(null, { status: 204 });
  } catch (e) {
    log("error", "SCIM deprovision (DELETE) refused");
    const message = (e as Error).message;
    // P2 + G003: the last-Owner guard (a leaver cannot be removed because they are the sole Owner) keeps its own
    // bucket; every other refusal is now bucketed by the DO's HTTP STATUS CLASS (4xx contract drift vs 5xx DO
    // fault) rather than by re-matching the DO's prose. See scimOffboardSignal.
    recordScimSignal(env, scimOffboardSignal(e), waitUntil);
    return scimError(400, message);
  }
}


// handleScimPatch handles PATCH /scim/v2/Users/{id}: the only supported PatchOp is a replace of active to
// false, which offboards exactly like DELETE. An active:true (re)activation is rejected 400 rather than
// silently accepted (a no-op the IdP would read as a successful activation that never happened); a body that
// is not a SCIM PatchOp, or that targets anything other than active:false, is a 400 SCIM error.
async function handleScimPatch(req: Request, env: Env, email: string, waitUntil?: (task: Promise<unknown>) => void): Promise<Response> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    recordScimSignal(env, "scim-patch-body-invalid", waitUntil);
    return scimError(400, "PATCH body is not valid JSON");
  }
  // The body must be a SCIM PatchOp.
  // The two shape rejections below cover a connector whose every deprovision 400s (an unrecognised PatchOp
  // shape). Only the rejected-shape CLASS is recorded; the PatchOp body (which carries the member's id /
  // attributes) never leaves this frame.
  const schemas = (body as { schemas?: unknown }).schemas;
  if (!Array.isArray(schemas) || !schemas.includes(SCIM_PATCH_OP)) {
    recordScimSignal(env, "scim-patch-shape-rejected", waitUntil);
    return scimError(400, `PATCH must be a SCIM PatchOp (schemas must include ${SCIM_PATCH_OP})`, "invalidSyntax");
  }
  const deactivate = patchDeactivates(body);
  if (deactivate === undefined) {
    recordScimSignal(env, "scim-patch-shape-rejected", waitUntil);
    return scimError(400, "the only supported PATCH is a replace of active to false (deprovision)", "invalidValue");
  }
  if (deactivate === false) {
    recordScimSignal(env, "scim-patch-reactivation-refused", waitUntil);
    return scimError(400, "reactivation (active:true) is not supported; this SCIM surface is deprovision-only", "mutability");
  }
  // active:false -> the same offboarding as DELETE.
  try {
    await offboard(env, email, waitUntil);
    return new Response(null, { status: 204 });
  } catch (e) {
    log("error", "SCIM deprovision (PATCH active:false) refused");
    const message = (e as Error).message;
    // P2 + G003: as in the DELETE path, the last-Owner guard keeps its own bucket and everything else is
    // bucketed by the DO's HTTP status class. See scimOffboardSignal.
    recordScimSignal(env, scimOffboardSignal(e), waitUntil);
    return scimError(400, message);
  }
}
