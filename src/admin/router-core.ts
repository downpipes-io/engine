// router-core.ts -- cross-cutting primitives every admin route shares: the JSON response/refusal helpers,
// the V16.3.1 auth-signal log lines, the per-route capability gate, the per-caller + per-IP rate limiters,
// the step-up re-auth gate, and the router-executed owner-action dual-control gate. The caller-header
// builder and the first-class audit appenders (incl. the self-redeploy-retry variants) live in
// router-audit.ts and are re-exported from here so importers that reference them by name are unchanged.

import { log } from "../log.ts";
import { ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW, AUTH_RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS } from "../sched/scheduler-do.ts";
import type { RecoveryRefusalClass } from "./diag-records.ts";
import {
  type AuthMethod,
  type Caller,
  type Capability,
  callerCan,
  type Forbidden,
  type Role,
} from "./identity.ts";
import { callerHeaders } from "./router-audit.ts";
import { type AdminRuntime, doURL, recordAuthSignalEdge } from "./router-helpers.ts";
import { readSessionCookie } from "./session.ts";
import type { RiskClass } from "./updates.ts";



// fireInBackground: see router-identity.ts's identical helper. The
// three gates below record their edge signals as the LAST action before returning a refusal, with no awaited
// work left to give the detached promise a scheduling window, so under real workerd the write is abandoned
// with the request context. `runtime` is optional and threaded from the call site: a direct call with no
// fetch runtime (a unit test) falls back to the old bare void unchanged.
//
// The parameter is the KEEP-ALIVE CAPABILITY, not the whole AdminRuntime, because scim.ts reaches the same
// gate holding the raw ExecutionContext rather than a router runtime, and an AdminRuntime satisfies this
// shape structurally.
type KeepAlive = { waitUntil?: AdminRuntime["waitUntil"] };

function fireInBackground(runtime: KeepAlive | undefined, task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}


// jsonResponse is the 200 JSON helper used by the routes the router answers itself.
export function jsonResponse(v: unknown): Response {
  return new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
}


// jsonError is the refusal helper for the routes that answer a plain, honest reason (the
// discovery-token and destination validation paths): a JSON {error} body with the given status.
export function jsonError(error: string, status: number): Response {
  return new Response(JSON.stringify({ error }), { status, headers: { "content-type": "application/json" } });
}

// jsonRefusal is jsonError PLUS a CLOSED refusal class the console can act on (G196).
//
// WHY IT EXISTS. The disaster-recovery routes answer 400 for a bad signature, a failed shape check, a no-custody
// refusal and a plane that was not empty alike, and the only thing separating them was this engine's PROSE. The
// console cannot classify that prose: it can name a bucket or a key, and a classifier over a sentence the console
// does not own mislabels the moment this engine rewords itself. So the class the engine ALREADY KNOWS (it has just
// written it to its own recovery-refusal latch) rides in the body as a frozen member, and the console admits it by
// SET MEMBERSHIP against its own mirror of the list. The customer reads a distinct code out; the pack carries a
// distinct row.
//
// `refusalClass` is a compile-time constant chosen by the call site, never derived from a request value, so the
// body it rides in gains no new custody surface. The prose in `error` is unchanged and stays exactly as honest as
// it was.
export function jsonRefusal(error: string, status: number, refusalClass: RecoveryRefusalClass): Response {
  return new Response(JSON.stringify({ error, refusalClass }), { status, headers: { "content-type": "application/json" } });
}

// parseJsonBody reads and parses a request body, returning a typed result rather than letting a
// malformed (non-JSON, empty, form-encoded) body throw a SyntaxError that bubbles to the last-resort
// 500 contract. Callers map ok:false to a clean 400, matching the update-route body-parse pattern.
export async function parseJsonBody<T>(req: Request): Promise<{ ok: true; body: T } | { ok: false }> {
  try {
    return { ok: true, body: (await req.json()) as T };
  } catch {
    return { ok: false };
  }
}


// DEPLOY_TOKEN_RE is the single shape check every route that accepts a one-shot Cloudflare deploy
// token (or the discovery API token) applies before the token leaves the request: the printable
// token-character set, bounded 20..300. validateDeployToken wraps it so the shape boundary lives in
// one place; if the accepted token shape ever changes, only this constant moves.
const DEPLOY_TOKEN_RE = /^[A-Za-z0-9_.-]{20,300}$/;

// validateDeployToken returns true when the token is a non-empty string of the accepted SHAPE.
//
// HONEST SCOPE (R10): this is a SHAPE check ONLY (character set + length). It does NOT, and CANNOT from inside
// the Worker, verify the token's Cloudflare PERMISSIONS/scope; that the token is least-privilege ("Workers
// Scripts: Edit" on exactly the engine's account) is the OPERATOR's responsibility when they mint it from the
// dashboard "Edit Cloudflare Workers" template, and the engine never claims to enforce it. The properties the
// engine itself guarantees are that the token is one-shot (never persisted or logged) and that an
// over/under-scoped token surfaces as an actionable Cloudflare error at call time (see cf-deploy.ts), never a
// silent mis-use. So no caller should read a true result here as proof the token is correctly scoped.
export function validateDeployToken(token: string): boolean {
  return token !== "" && DEPLOY_TOKEN_RE.test(token);
}


// AUTH_LOG_PREFIX tags every authentication-boundary log line so an operator (or a Logpush sink)
// can grep authn outcomes out of the engine's console stream as one stable family. The lines are
// the V16.3.1 authn-success / authn-failure signal; they are coarse and carry NO token, NO Access
// assertion and NO email, only the attempted method, the outcome and (on success) the verified role.
export const AUTH_LOG_PREFIX = "authn";


// attemptedMethod derives which credential the caller PRESENTED, for the failure log only. authorise()
// returns a bare { ok: false } that does not say which path it rejected, so the attempted method is
// read from the request shape exactly as auth.ts decides which credential to check: a present
// cf-access-jwt-assertion header means the Access path was attempted, otherwise the bare-token path.
// It reads only the PRESENCE of the header, never its value, so no assertion bytes are touched.
export function attemptedMethod(req: Request): AuthMethod {
  return req.headers.get("cf-access-jwt-assertion") ? "access" : "token";
}


// logAuthFailure records an authentication FAILURE (a 401 path) as a coarse console.error line, so a
// review and any log-shipping pipeline can see refused sign-ins (V16.3.1). It logs the attempted
// method and a short, fixed reason only: never the presented token or assertion, and never an email
// (an unverified assertion's email is untrustworthy PII and a missing email is the very thing being
// rejected). It emits through the structured section 11 logger so the line lands in Workers Logs with
// the JSON shape, and it does not alter the 401 plaintext response.
export function logAuthFailure(method: AuthMethod, reason: string): void {
  log("error", `${AUTH_LOG_PREFIX} failure method=${method} reason=${reason}`);
}


// logAuthSuccess records an authentication SUCCESS as a coarse structured line once the caller is
// resolved (V16.3.1). The closed AuditAction/AuditTarget union has no natural authn action or target,
// so this is observability rather than a first-class audit event. It logs the auth method and the
// VERIFIED role (the access-control fact a reviewer cares about) and deliberately omits the email to
// keep the line free of avoidable PII and omits any token/session value. It emits through the
// structured section 11 logger so the line lands in Workers Logs with the JSON shape, and it does not
// alter any response.
export function logAuthSuccess(method: AuthMethod, role: Role): void {
  log("info", `${AUTH_LOG_PREFIX} success method=${method} role=${role}`);
}


// gate is the per-route CAPABILITY check (contract section 1 + section 8). It returns a 403 JSON
// Forbidden response when the caller does not hold the required capability, or null when the caller
// may proceed. The check is callerCan(caller, cap): for a built-in-role caller this is the
// can(caller.role, cap) lookup over ROLE_CAPABILITIES (unchanged); for a custom-role caller it is the
// resolved capability SET's has(), so a custom role is gated by exactly the capabilities it bundles.
// The 403 body is JSON (distinct from the plaintext 401), with required = the capability the route
// needs and have = the caller's role (the viewer floor for a custom-role caller; the body is for
// console messaging only, the authority decision is callerCan). Client gates mirror this control.
export function gate(caller: Caller, required: Capability): Response | null {
  if (callerCan(caller, required)) return null;
  const body: Forbidden = { error: "forbidden", required, have: caller.role };
  return new Response(JSON.stringify(body), { status: 403, headers: { "content-type": "application/json" } });
}


// rateLimitKey derives the per-caller bucket key the rate limiter counts against. Every ATTRIBUTABLE
// caller gets their own bucket, keyed on the STABLE SUBJECT. The bare-token break-glass has no stable
// identity at all, so it shares one "token" bucket: it is the all-or-nothing operator credential, and
// giving it a single bucket caps an automated misuse of the shared token without ever letting a per-IP
// signal leak in. Keying on the verified caller (never the source IP) is the design point: a per-IP
// limiter would fail closed across a shared NAT/egress and harm legitimate customers (the cost/rate-limit
// audit calls this out).
// IT KEYS ON SUBJECT, NOT EMAIL, so every ATTRIBUTABLE AuthMethod (access | passkey | oidc | saml |
// recovery) gets its own bucket rather than falling into the SAME bucket as the bare token. On any estate
// not fronted by Cloudflare Access, which is every estate using this engine's own passkey or native-IdP
// front door, sharing one bucket across methods would make the 120-per-60s cap a SHARED budget: one
// operator's console automation could 429 every other operator's mutating routes and the break-glass
// fallback with them, which is precisely the shared-fate harm the per-IP argument above exists to avoid,
// moved onto the identity axis. Caller.subject is null ONLY for the bare-token break-glass (see its
// declaration), so it is the exact discriminator, and it is the same subject-over-email axis the rest of
// this engine authorises on.
export function rateLimitKey(caller: Caller): string {
  return caller.subject ? `sub:${caller.subject}` : "token";
}


// rateLimited is the router-side per-caller pre-check for the mutating routes. It asks the scheduler
// DO (the single counter authority) whether THIS caller is within the per-window cap, and returns a
// 429 Response (with a Retry-After header in whole seconds and a small JSON { error: "rate limited" }
// body, mirroring the JSON discipline of the 403 capability gate) when the caller is over the cap, or
// null to let the request proceed.
//
// FAIL-OPEN (deliberate): if the /rate-check call itself throws or the DO is unavailable, the request
// is ADMITTED (return null) and a coarse structured log("error") line is emitted. This is an internal authenticated
// admin API on the recovery path, so availability beats strict limiting: a limiter that failed closed
// when its own backing store hiccuped would block legitimate recovery actions, which is exactly the
// fail-closed harm the cost/rate-limit audit warns against. The limiter narrows abuse on the happy
// path; it must never become a new way to deny a verified operator their own admin surface.
// RATE_LIMIT_WINDOW_SECONDS is the per-caller window in whole seconds, derived once from the DO's
// authoritative window so the IETF RateLimit-Policy header carries the real window.
export const RATE_LIMIT_WINDOW_SECONDS = Math.round(RATE_LIMIT_WINDOW_MS / 1000);


// rateLimitHeaders builds the IETF draft RateLimit + RateLimit-Policy headers (draft-ietf-httpapi-
// ratelimit-headers). `limit` is the window ceiling, `remaining` the count left (0 at a 429), `reset`
// the whole seconds until the window rolls over (we reuse Retry-After's value, which is the same span).
// RateLimit-Policy advertises the static policy "<limit>;w=<window-seconds>". These are advisory, additive
// headers; they never change the status or the existing Retry-After.
export function rateLimitHeaders(limit: number, remaining: number, resetSeconds: number): Record<string, string> {
  return {
    ratelimit: `limit=${limit}, remaining=${remaining}, reset=${resetSeconds}`,
    "ratelimit-policy": `${limit};w=${RATE_LIMIT_WINDOW_SECONDS}`,
  };
}


// RATE_LIMITED_ERROR / RATE_LIMIT_UNAVAILABLE_ERROR are the two `error` values a 429 body carries. They
// are the WIRE CONTRACT, not prose: the docs tell an integrator to match on `error === "rate limited"`
// (reference/error-and-status-codes) and the validators assert the same string, so they are named
// constants rather than four hand-typed literals that can drift a character apart.
export const RATE_LIMITED_ERROR = "rate limited";
export const RATE_LIMIT_UNAVAILABLE_ERROR = "rate limit unavailable";

// rateLimitedResponse is the ONE producer of a 429 on this engine. Every 429 body is RFC 9457
// problem+json ({ type, title, status, error }) served as application/problem+json, with a whole-second
// Retry-After and the advisory IETF RateLimit + RateLimit-Policy headers beside it.
//
// It exists because the shape DID drift. The bare-token throttle's 429 was added by hand as a plaintext
// body with no content-type and a hard-coded retry-after, so the engine answered two different 429s: one
// an integrator could parse per the published contract, and one that threw on the first JSON.parse. The
// four call sites now share this builder, so a future 429 cannot be almost-right. `limit` is the cap of
// the bucket that actually refused (each limiter has its own), so the RateLimit header describes the
// ceiling the caller met rather than a generic one.
export function rateLimitedResponse(error: typeof RATE_LIMITED_ERROR | typeof RATE_LIMIT_UNAVAILABLE_ERROR, retryAfterSeconds: number, limit: number): Response {
  const unavailable = error === RATE_LIMIT_UNAVAILABLE_ERROR;
  const body = {
    type: unavailable ? "urn:downpipe:error:rate-limit-unavailable" : "urn:downpipe:error:rate-limited",
    title: unavailable ? "Rate limit unavailable" : "Rate limited",
    status: 429,
    error,
  };
  return new Response(JSON.stringify(body), {
    status: 429,
    headers: { "content-type": "application/problem+json", "retry-after": String(retryAfterSeconds), ...rateLimitHeaders(limit, 0, retryAfterSeconds) },
  });
}


// adminTokenThrottledResponse is the 429 for the PER-IP bare-token anti-brute-force throttle
// (adminTokenRateLimitedViaDO, consulted inside authorise()). It is built here, beside its three sibling
// 429s, so the bare-token refusal cannot drift away from the shape the other limiters answer with.
//
// The Retry-After is the FULL window, not the remaining span: the throttle resolver answers a boolean, so
// the remainder is not carried back and the full window is the only value that is certainly not too short.
// Advertising the ceiling means a caller never retries early into a still-saturated window, and it is
// derived from RATE_LIMIT_WINDOW_SECONDS rather than written as a literal, so retuning the window cannot
// leave a stale number on the wire.
export function adminTokenThrottledResponse(): Response {
  return rateLimitedResponse(RATE_LIMITED_ERROR, RATE_LIMIT_WINDOW_SECONDS, ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW);
}


export async function rateLimited(scheduler: DurableObjectStub, caller: Caller): Promise<Response | null> {
  const key = rateLimitKey(caller);
  try {
    const resp = await scheduler.fetch(doURL("/rate-check"), {
      method: "POST",
      body: JSON.stringify({ key }),
      headers: { "content-type": "application/json" },
    });
    const verdict = (await resp.json()) as { allowed?: boolean; retryAfterMs?: number };
    // FAIL OPEN on anything other than an explicit refusal: only a verdict that positively says
    // allowed === false refuses the request. A missing/garbled verdict (allowed not strictly false)
    // is treated as "admit", so a DO that answered with an unexpected shape (or a future field
    // rename) degrades to availability rather than silently denying a verified operator.
    //
    // G201: that fail-open is DELIBERATE and was INVISIBLE. A DO answering a shape with no boolean verdict
    // admits every request, so the limiter is silently not limiting -- and the request looks, to every
    // observer, exactly like a request the limiter allowed. NOISE DISCIPLINE: this fires ONLY on a MALFORMED
    // verdict (no boolean at all), never on a healthy limiter's ordinary allowed:true, which is the common case.
    if (typeof verdict.allowed !== "boolean") {
      void recordAuthSignalEdge(scheduler, "limiter-verdict-malformed");
      return null;
    }
    if (verdict.allowed !== false) return null;
    // Retry-After is expressed in whole seconds (the HTTP header's unit), rounded UP so a caller never
    // retries a hair early into the still-saturated window; at least 1 second so the header is useful.
    const retryAfterMs = typeof verdict.retryAfterMs === "number" && verdict.retryAfterMs > 0 ? verdict.retryAfterMs : 0;
    const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
    // RFC 9457 problem+json body keeping the legacy `error` field (validators assert body.error === "rate
    // limited"); plus the advisory IETF RateLimit headers alongside the existing Retry-After.
    return rateLimitedResponse(RATE_LIMITED_ERROR, retryAfterSeconds, RATE_LIMIT_MAX_PER_WINDOW);
  } catch (e) {
    // FAIL OPEN: the limiter's own backing store is unavailable. Admit the request and log coarsely
    // (the caller identity is NOT logged here to keep the line free of avoidable PII; the failure mode
    // and a short reason are what an operator needs to see).
    log("error", `rate-check unavailable, failing open (request admitted): ${(e as Error).message}`);
    // G201: the log line dies with the Workers-Logs retention window; the pack carried nothing. The same
    // malformed-verdict name covers the THROWN limiter too: in both cases the limiter produced no usable
    // verdict and the request was admitted anyway, which is the one fact a diagnosis needs.
    void recordAuthSignalEdge(scheduler, "limiter-verdict-malformed");
    return null;
  }
}


// STEPUP_HEADER carries the single-use step-up token the console obtains from a fresh passkey assertion and
// presents on the retry of a sensitive action. STEPUP_SUBS is the set of main-switch sensitive routes the
// step-up gate covers: restore approval, key install/rotate/add-operational, the break-glass-only posture switch
// (it permanently deletes BOTH operational worker secrets, so THAT KEY MATERIAL is unrecoverable and archives
// sealed to it never regain an operational recipient; the POSTURE itself is not one-way, because
// /keys/add-operational -- three entries earlier in this same list -- installs a fresh pair and clears the
// OPERATIONAL_RETIRED marker), and posture accept/
// unaccept, PLUS the high-blast-radius data/identity ops - repointing or removing a destination (a data-theft
// path: a stolen ambient session could redirect every backup or delete an archive copy), setting/replacing/
// clearing the SIEM push destination (the same data-theft class: a stolen session could redirect the
// identity-bearing audit egress to an attacker-controlled endpoint, or run an arbitrary test-send),
// setting/replacing the OTLP metrics push destination (mon-otlp; the same class -- a stolen session could
// redirect the operational backup-health telemetry egress to an attacker-controlled collector), and
// changing the IdP trust roots (wiring/removing/enabling an authentication source), PLUS the identity / auth-lifecycle
// mutations a stale ambient cookie can otherwise reach: granting a role (the built-in /roles, the
// group-claim->role mapping /group-roles, and the custom-role definition /custom-roles each can mint a brand
// new OWNER = a persistent backdoor), retiring the break-glass bearer token (/policy/retire-break-glass-token,
// an IRREVERSIBLE one-way latch that disables the operator fallback = a lockout/availability hit), and
// deleting a passkey credential (/passkey/credentials/delete, an auth-credential-lifecycle mutation). The
// RBAC REVOKE/DELETE siblings are gated for the SAME reason as their GRANT siblings: removing a member
// (/roles/delete) offboards them and terminates their live sessions (the DO's deleteRole bumps the session
// epoch), and removing a group->role mapping (/group-roles/delete) or a custom-role definition
// (/custom-roles/delete) is an equally high-consequence identity mutation, so a stale ambient cookie must
// not reach them without a fresh re-auth either. PLUS (STEPUP-SESSION-TERMINATION-GAP) evicting
// ANOTHER operator's sessions (/sessions/terminate-user) or every operator's sessions (/sessions/terminate-
// all, owner-only) and emailing a custody share to a recipient outside the engine (/custody/send-share).
// /sessions/terminate-others stays exempt: it only bumps the CALLER's own epoch, never another operator's.
// PLUS (STEPUP-NOTIFY-CONFIG-UNGATED) the DETECTION CONFIG: the notify rules and channels that
// decide whether anything the rest of this list guards is ever noticed. See the block on those entries.
// Each string here MUST match a real POST dispatch case the
// router dispatches (the gate runs once before the switch, keyed on `sub`); a string with no matching case
// would be a silent no-op, so validate-session.ts drives each one THROUGH the dispatch (not just set
// membership) AND, STRUCTURALLY, derives the router's actual dispatched POST set from the spoke source and
// asserts that every identity/auth-lifecycle/keys/posture/destination/restore MUTATION case is present here
// (so a future sensitive route added without a step-up entry FAILS that test rather than slipping through).
//
// HI-04 / the ONE necessary exception to "each string here MUST match a real POST dispatch case": the two
// dual-control APPROVE routes (POST /config/changes/<id>/approve, POST /owner-actions/<id>/approve) carry a
// per-request ULID path segment, so their `sub` can never equal a literal STEPUP_SUBS member (no string could
// ever be added to cover it - Set membership needs exact equality, not a pattern match). router.ts instead
// gates their PARSED "approve" action with a direct requireStepUp() call, right where matchConfigChangeAction /
// matchOwnerActionAction are matched, before the DO forward; reject is exempt on both (it only discards a
// pending record, the same "only gate the dangerous direction" convention this set already follows elsewhere).
// These two routes are therefore step-up-gated but are deliberately ABSENT from the Set below and from
// dispatchedPostSubs()'s literal `case "POST ..."` parse; validate-session.ts's HI-04 structural check reads
// router.ts's source directly to assert the requireStepUp call is still present on each matcher's approve
// leg, so a future dynamic route cannot silently reintroduce this exact blind spot.
//
// A SECOND exception, same shape: POST /restore (router-restore.ts) is ONE static `sub` that multiplexes
// TWO actions on a body field, never a path segment -- a read-only dry-run plan (confirm omitted/false,
// writes nothing) and the actual data-overwriting APPLY (confirm:true). Restore-apply is the single most
// consequential mutation this engine performs (it writes customer data back), and its sibling in the
// identical request -> approve -> apply dual-control shape, /retention-prune/apply, already sits in this
// Set; POST /restore itself did not, which is the STEPUP-SESSION-TERMINATION-GAP sweep's third
// finding. Adding the bare "/restore" string here would also gate the harmless, high-volume dry-run path
// (a body-blind Set membership check cannot see `confirm`), so router-restore.ts instead calls
// requireStepUp() directly inside the `body.confirm === true` branch, before the dual-control gate reserves
// the approval and before any byte is written -- mirroring the HI-04 pattern above exactly, one static sub
// instead of one dynamic id. validate-session.ts's structural check reads router-restore.ts's source
// directly to assert the requireStepUp call is still present on that branch.
export const STEPUP_HEADER = "x-downpipes-stepup";

export const STEPUP_SUBS: ReadonlySet<string> = new Set([
  "/restore/approve",
  "/keys/install",
  "/keys/rotate",
  "/keys/add-operational",
  "/keys/break-glass-only",
  "/posture/accept",
  "/posture/unaccept",
  "/destination",
  "/destinations",
  "/destinations/remove",
  "/destinations/default",
  "/push",
  "/push/delete",
  "/push/test",
  "/otlp-push",
  "/otlp-push/delete",
  "/idp/connections",
  "/idp/connections/delete",
  "/idp/connections/enabled",
  "/idp/connections/cert",
  "/roles",
  "/roles/delete",
  "/group-roles",
  "/group-roles/delete",
  "/custom-roles",
  "/custom-roles/delete",
  "/policy/retire-break-glass-token",
  "/passkey/credentials/delete",
  // THE STRICTLY LARGER SIBLING OF THE LINE ABOVE, WHICH WAS NOT GATED. /passkey/credentials/delete removes
  // ONE credential and has been step-up gated since the route existed. /signin-factors/revoke removes EVERY
  // credential for an address plus the recovery record plus every pending invite, in one call, and it was
  // absent from this Set, so a stale ambient cookie could reach the larger act while the smaller one demanded
  // a fresh assertion. It is the one route in this engine that destroys recovery codes, which cannot be
  // re-derived, so the act it performs is irreversible in a way no other member here is.
  //
  // The membership test is exact string equality on `sub`, which is why this had to be enumerated rather than
  // inferred: nothing about the route's shape or its capability would have pulled it in. Access and bare-token
  // callers stay exempt inside requireStepUp exactly as they are for every other member, so this changes the
  // cookie-borne path only.
  "/signin-factors/revoke",
  // DETECTION CONFIG (STEPUP-NOTIFY-CONFIG-UNGATED): the alert rules and the channels they
  // deliver to. The confidentiality argument that gates /push and /otlp-push does NOT read across here (a
  // notify emission is redaction-safe by construction, so repointing a channel steals nothing), but that
  // settles the wrong property. These routes govern the AVAILABILITY OF EVIDENCE: routeRecoveryAlert emits
  // recovery-code-abuse at CRITICAL severity precisely so a brute-force of the recovery route is loud, and
  // deleting the rule that carries that signal is the move an attacker makes BEFORE the attempt, not after.
  // Silencing an account is a stale-ambient-cookie action with no visible effect and no undo, which is the
  // exact profile the step-up gate exists for. BOTH DIRECTIONS are gated, for the same reason /push is gated
  // on set as well as delete: suppression by REPLACEMENT needs no delete at all -- repoint a channel at a
  // sink nobody reads, or narrow a rule until it matches nothing, and the account goes quiet with every
  // record still present.
  "/notify/rules",
  "/notify/rules/delete",
  // THE SIGN-IN NOTIFY TOGGLE, and it belongs with the two lines above rather than with the config family
  // (STEPUP-SIGNIN-CONTEXT-NOTIFY-TOGGLE-UNGATED). POST /config/signin-context-policy turns the
  // unusual-location sign-in notification off. That is the same act as deleting a notify rule, reached
  // through a different route: it silences a signal about ACCESS ITSELF, it has no undo prompt and no
  // visible effect, and turning it off is the move made BEFORE an attempt rather than after.
  //
  // Its siblings under /config/ are deliberately NOT here, and the reasoning is per-route rather than
  // per-prefix. /config/approval-policy was proposed as the stronger candidate and is refuted: the DO
  // enforces an asymmetric off switch, so arming is immediate while an attributable owner's DISARM queues
  // for a second owner at 202, a real-time disarm alert fires on any immediate disarm, and the only caller
  // who can disarm outright is the bare-token break-glass owner, who is exempt from step-up anyway. Adding
  // it would cost a ceremony and close nothing.
  //
  // The console half landed FIRST. That order is load-bearing: the step-up ceremony
  // lives in Transport.gatedFetch, so a caller on the plain transport meeting this gate shows the operator
  // an authentication error instead of a passkey prompt. Do not add a route here whose console caller is
  // still on engineFetch.
  "/config/signin-context-policy",
  "/notify/channels",
  "/notify/channels/delete",
  // attended verification: STARTING a session issues the live-possession challenge that lets the browser
  // enable per-run masters, so a stale ambient session must not open one without a fresh re-auth. Only the
  // create is gated; the later session routes (prove/capsules/verify/abort) are owner-bound (caller.subject
  // === createdBy) and lower-consequence, so they follow the "only gate the dangerous direction" convention.
  "/attest/session/create",
  // retention-prune apply is a DELETING route (it can supersede runs and delete their run-trees +
  // orphaned segments), gated on restore.apply so it can never sit below the attend session's drill.run
  // floor (every restore.apply holder also holds drill.run; identity-rbac.ts). A destructive, irreversible
  // action reachable by a stale ambient cookie is exactly the STEPUP_SUBS threat model, so it gets the same
  // fresh re-auth as the other high-blast-radius destination/identity mutations above. The read-only
  // candidate route (which only serves non-secret capsules, like /restore/capsule) is deliberately absent.
  "/retention-prune/apply",
  // Dual control (post-adversarial-review): approving a prune request is the dangerous
  // direction of the request/approve/reject trio (it is what makes the plan applicable), mirroring
  // /restore/approve exactly; request and reject stay exempt (the "only gate the dangerous direction"
  // convention this set already follows for restore).
  "/retention-prune/approve",
  // STEPUP-SUPPORT-CREDENTIAL-MINT (the fifth gap of the STEPUP-SESSION-TERMINATION-GAP sweep, which
  // cleared this route on the ground that a second owner's approval covered it). It does not, by default:
  // support-credential-mint is absent from HIGH_BLAST_ALWAYS_GATED (owner-action.ts) and requireConfigApproval
  // defaults false (scheduler-do-org-policy.ts), so ownerActionGate answers "off" and the mint ran inline on
  // nothing but a caller.role === "owner" test. The route's own comment calls the mint "the same custody weight
  // as granting a role", and /roles is in this Set, so this is the gate that matches the weight the route
  // already claims for itself: it opens a read-only, scoped, expiring PULL surface over the sealed support
  // bundle and hands back a bearer, which a stale ambient owner cookie must not be able to do. The mint is the
  // dangerous direction; /support/credentials/delete only REVOKES a credential (it closes the surface, and
  // requiring a fresh re-auth to shut off a credential you suspect is stolen would be the wrong friction), so
  // it follows the "only gate the dangerous direction" convention this Set already uses for restore and prune.
  // Dual control is NOT the fix here for the same reason it is not the fix for /roles: it is opt-in, it needs a
  // second owner to exist, and a single-owner self-hosted account would get no protection at all from it.
  "/support/credentials",
  // STEPUP-SESSION-TERMINATION-GAP: evicting ANOTHER operator's live sessions or every operator's
  // sessions is a takeover-adjacent action (a stale ambient session that survives a suspected compromise
  // could silence the legitimate operator's other tabs so they never notice the attacker acting), so it
  // needs the same fresh re-auth as the identity-lifecycle mutations above. /sessions/terminate-others is
  // DELIBERATELY absent: it only bumps the CALLER's own epoch (self-scoped housekeeping, never another
  // operator's session), matching the "only gate the dangerous direction" convention this set already
  // follows for restore/retention-prune. terminate-user (one named operator) and terminate-all (every
  // operator, owner-only) both touch a session that is not the caller's own, so both are gated.
  "/sessions/terminate-user",
  "/sessions/terminate-all",
  // STEPUP-SESSION-TERMINATION-GAP: emailing a custody share transits the engine on its way to a
  // custodian's inbox (router-custody.ts). A stale ambient session sending a share is exactly the step-up
  // threat model: the share alone cannot open identity.key (S1 ciphertext separation), but a captured session
  // could still exfiltrate enough shares, across enough calls, to matter, and the action is owner-gated and
  // irreversible once mailed (there is no un-send). Fresh re-auth before it leaves the engine.
  "/custody/send-share",
]);


// requireStepUp gates a SENSITIVE action (ASVS V7.5.1 / V7.5.3) behind a fresh re-authentication, so a STALE
// ambient session cannot perform it. The bare-token break-glass (all-or-nothing) and Cloudflare Access (its
// own session/MFA management) are EXEMPT. For a cookie method it asks the DO (which holds the signing key)
// whether the session was recently authenticated OR a valid single-use step-up token is presented (the DO
// consumes it). Returns null when satisfied (proceed), or a 401 { stepUpRequired:true } the console catches to
// run the re-auth ceremony and retry. FAILS CLOSED: if the DO check is unavailable, the action is denied.
export async function requireStepUp(req: Request, scheduler: DurableObjectStub, method: AuthMethod, runtime?: KeepAlive): Promise<Response | null> {
  if (method === "token" || method === "access") return null;
  const token = readSessionCookie(req);
  const stepUpToken = req.headers.get(STEPUP_HEADER);
  try {
    const resp = await scheduler.fetch(doURL("/stepup/check"), {
      method: "POST",
      body: JSON.stringify({ token, stepUpToken }),
      headers: { "content-type": "application/json" },
    });
    const out = (await resp.json()) as { satisfied?: unknown };
    if (out.satisfied === true) return null;
    // G201: THE ANSWERED OUTAGE, the "every sensitive action keeps demanding a passkey and never accepts it"
    // ticket. stepUpCheck's contract is total: it returns { satisfied: boolean } on EVERY path it takes. But
    // scheduler.fetch() does not throw on an HTTP error status, so an up-but-broken DO (a storage fault, a
    // TypeError, route drift) answers through its own JSON 500 envelope -- the body parses, `satisfied` is
    // simply absent -- and lands here, never in the catch. The fail-closed 401 it then gets is byte-identical
    // to the 401 the step-up ceremony OPENS with, so the outage was invisible in the response AND in the pack.
    //
    // NOISE DISCIPLINE: an explicit `satisfied: false` is the ceremony working exactly as designed (the console
    // catches that 401 and runs the re-auth), so it records NOTHING. Only a non-boolean verdict -- a DO that
    // did not run this function -- is a fault.
    if (typeof out.satisfied !== "boolean") fireInBackground(runtime, recordAuthSignalEdge(scheduler, "stepup-check-verdict-malformed"));
  } catch (e) {
    log("error", `step-up check unavailable, failing closed (sensitive action denied): ${(e as Error).message}`);
    // G201: fail-closed on a DO outage returns the SAME 401 "step-up required" as a caller who simply has not
    // stepped up. So "every sensitive action keeps demanding a passkey and never accepts it" -- an OUTAGE --
    // is indistinguishable from the ordinary, healthy prompt, and the pack showed nothing either way.
    //
    // NOISE DISCIPLINE: this fires ONLY here, in the catch. The honest `satisfied:false` path below is the
    // ceremony working exactly as designed (the step-up flow OPENS with this 401), and recording it as a fault
    // would put a phantom auth fault on every SUCCESSFUL step-up -- a signal that cries wolf on the happy path
    // is worse than no signal, because it devalues the true ones.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "stepup-check-unavailable"));
  }
  return new Response(JSON.stringify({ error: "step-up required", stepUpRequired: true }), { status: 401, headers: { "content-type": "application/json" } });
}


// authRateLimited is the PER-IP pre-check for the UNAUTHENTICATED /admin/auth/* ceremony routes (V2.4.1).
// Those routes have no verified caller (they are the sign-in flow) and each finish runs heavy crypto, so
// an unthrottled flood is a CPU-DoS + enumeration vector. Unlike the per-caller limiter above, this bucket
// is keyed on the source IP (CF-Connecting-IP) in a SEPARATE `ip:` namespace, with the tighter
// AUTH_RATE_LIMIT_MAX_PER_WINDOW cap. UNLIKE rateLimited (which fails OPEN for a verified operator's
// recovery actions), this unauthenticated brute-force surface FAILS CLOSED: a non-admit verdict OR a
// backing-store outage returns 429, and only a verdict that positively says allowed === true proceeds.
// The single ADMIT-on-failure case is a MISSING source IP, which at the custom-domain-only edge cannot
// occur (the edge always injects CF-Connecting-IP); its absence means a non-edge/local context, so it is
// admitted rather than bucketing every header-less caller into one shared key (see the no-IP note below).
// A request over the cap gets a 429 with a Retry-After (whole seconds) and a small JSON body, mirroring
// the 429 the per-caller limiter returns.
//
// AUTH_RATE_LIMIT_FALLBACK_RETRY_AFTER_S is the Retry-After (whole seconds) advertised on the
// fail-closed 429 emitted when the limiter's backing store is unavailable. It is a fixed fallback
// window rather than the real per-window span (which is only known from the DO verdict we did not get).
const AUTH_RATE_LIMIT_FALLBACK_RETRY_AFTER_S = 60;

export async function authRateLimited(scheduler: DurableObjectStub, req: Request, runtime?: KeepAlive): Promise<Response | null> {
  const ip = req.headers.get("CF-Connecting-IP");
  // No source IP: ADMIT. On the custom-domain-only deployment the Cloudflare edge ALWAYS injects
  // CF-Connecting-IP (overwriting any client-supplied value), and the engine rejects workers.dev, so a real
  // edge request can never lack it - its absence means a non-edge/local context (a validator), not an
  // attacker who stripped it. Failing closed here would buy ZERO production security (the case cannot occur
  // at the edge) while bucketing every header-less local caller into one shared "ip:" key. The deliberate,
  // edge-guaranteed accept follows the V2.4.1 / V8.1.4 anti-automation design.
  if (ip === null || ip.length === 0) return null;
  try {
    const resp = await scheduler.fetch(doURL("/rate-check"), {
      method: "POST",
      body: JSON.stringify({ key: `ip:${ip}`, max: AUTH_RATE_LIMIT_MAX_PER_WINDOW }),
      headers: { "content-type": "application/json" },
    });
    const verdict = (await resp.json()) as { allowed?: boolean; retryAfterMs?: number };
    // FAIL CLOSED on anything but an explicit admit (V2.4.1). This is the UNAUTHENTICATED sign-in surface
    // (the brute-force / credential-stuffing target); unlike the per-caller rateLimited there is no verified
    // operator whose availability we trade for, so only a verdict that positively says allowed === true is
    // admitted - a refusal OR a missing/garbled verdict returns 429 rather than silently opening the gate.
    if (verdict.allowed === true) return null;
    // G201: THE ANSWERED OUTAGE. scheduler.fetch() does NOT throw on an HTTP error status -- the DO's outer
    // catch returns a JSON 500 -- so an up-but-broken limiter DO (a storage fault, a TypeError, route drift)
    // ARRIVES HERE, not in the catch below: the body parses, `allowed` is simply absent, the fail-closed rule
    // above returns the same 429 the genuine over-cap returns, and NOTHING was recorded. The pack during
    // "nobody in the company can sign in" was byte-identical to a healthy quiet day.
    //
    // Three states, three rows now: a genuine over-cap records auth-ratelimited (the DO's own auto-signal on
    // `ip:` keys), an UNREACHABLE limiter records auth-limiter-unavailable (the catch), and an ANSWERED-BUT-
    // BROKEN limiter records this. NOISE DISCIPLINE: a healthy allowed:true never reaches here, and an honest
    // allowed:false is a working limiter doing its job (already counted as auth-ratelimited, not as a fault).
    if (typeof verdict.allowed !== "boolean") {
      log("error", "auth rate-check answered without a boolean verdict, failing closed (request denied)");
      fireInBackground(runtime, recordAuthSignalEdge(scheduler, "auth-limiter-verdict-malformed"));
    }
    const retryAfterMs = typeof verdict.retryAfterMs === "number" && verdict.retryAfterMs > 0 ? verdict.retryAfterMs : 0;
    const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
    return rateLimitedResponse(RATE_LIMITED_ERROR, retryAfterSeconds, AUTH_RATE_LIMIT_MAX_PER_WINDOW);
  } catch (e) {
    // FAIL CLOSED: the limiter's backing store is unavailable. On the unauthenticated brute-force surface a
    // limiter outage must NOT open the floodgates. The heavy WebAuthn ceremony behind this gate depends on
    // the same scheduler DO, so a real outage blocks completion anyway - failing closed here costs no extra
    // availability while denying an attacker the limiter-down brute-force window. (Contrast rateLimited,
    // which fails OPEN for a VERIFIED operator's recovery actions, a deliberate availability choice.)
    log("error", `auth rate-check unavailable, failing closed (request denied): ${(e as Error).message}`);
    // P3 (auth-ratelimiter-outage-loginblock): record that the unauthenticated auth limiter FAILED CLOSED on a
    // backing-DO outage, so a "nobody can sign in" incident (login BLOCKED, not throttled) is diagnosable from the
    // pack, distinct from a genuine over-cap 429. Fire-and-forget; never delays the fail-closed response.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "auth-limiter-unavailable"));
    return rateLimitedResponse(RATE_LIMIT_UNAVAILABLE_ERROR, AUTH_RATE_LIMIT_FALLBACK_RETRY_AFTER_S, AUTH_RATE_LIMIT_MAX_PER_WINDOW);
  }
}


// ---- OPT-IN dual control for the ROUTER-EXECUTED owner ops (the one-shot-token / mint flow) -------------
// update/apply, update/settle, sources/attach and support-credential mint do the privileged work IN THE
// ROUTER (a one-shot deploy token runs the deploy; the mint generates a one-time secret), NOT in the DO. So
// they cannot dispatch through the DO's gatedOwnerAction (which runs DO methods). Instead the router asks the
// DO to gate them: ownerActionGate is the FIRST-call decision (off / pending / armed) and consumeOwnerAction
// is the single-use consume on the re-submit. This keeps ALL the gate logic in the DO (the router cannot
// bypass it) and ensures the one-shot token / the mint runs ONLY on the approved execution.

// OwnerActionGateResult tells the route what to do:
//  - "proceed": run the privileged op now (gate OFF, OR an armed approval was just consumed for this exact
//    action). The op may use the one-shot token / mint exactly once here.
//  - "queued": dual control is ON and no armed approval exists; a pending approval was just recorded. The
//    route must answer 202 + the pending id WITHOUT consuming the token / running the op.
//  - "error": the DO refused (e.g. a non-owner, a bare-token maker, a re-submit whose params no longer match
//    the approved action); the route returns the DO's error verbatim.
export type OwnerActionGateResult =
  | { kind: "proceed" }
  | { kind: "queued"; id: string; actionHash: string }
  | { kind: "error"; response: Response };


// ownerActionGate runs the FIRST-call gate-check for a router-executed owner op, and, when the DO reports an
// existing ARMED approval (the re-submit), atomically CONSUMES it, so the route proceeds with the one-shot
// token ONLY because an approved owner-action record existed. `params` are the action's DECISION-RELEVANT,
// NON-SECRET fields (NEVER the deploy token): the DO binds the approval to a hash over them + the proposer
// identity, so the consume on the re-submit pins to the EXACT approved action and proposer. `summary` is the
// redaction-safe inbox line. On any DO refusal it surfaces the DO's status+body verbatim (a 400/403), so a
// non-owner / bare-token maker / mismatched re-submit is reported faithfully and the op never runs.
export async function ownerActionGate(
  scheduler: DurableObjectStub,
  caller: Caller,
  kind: string,
  params: unknown,
  summary: string,
): Promise<OwnerActionGateResult> {
  const checkResp = await scheduler.fetch(doURL("/owner-actions/gate-check"), {
    method: "POST",
    body: JSON.stringify({ kind, params, summary }),
    headers: callerHeaders(caller),
  });
  if (!checkResp.ok) return { kind: "error", response: checkResp };
  const verdict = (await checkResp.json()) as { gate: "off" | "pending" | "armed"; id?: string; actionHash?: string };
  if (verdict.gate === "off") return { kind: "proceed" };
  if (verdict.gate === "pending") return { kind: "queued", id: verdict.id ?? "", actionHash: verdict.actionHash ?? "" };
  // armed: this is the re-submit. CONSUME the armed approval (single-use, atomic in the DO) for THIS exact
  // action hash before proceeding; if the consume fails (already used, expired, mismatched), surface it.
  const consumeResp = await scheduler.fetch(doURL("/owner-actions/consume"), {
    method: "POST",
    body: JSON.stringify({ id: verdict.id ?? "", expectedActionHash: verdict.actionHash ?? "" }),
    headers: callerHeaders(caller),
  });
  if (!consumeResp.ok) return { kind: "error", response: consumeResp };
  return { kind: "proceed" };
}


// ownerActionQueuedResponse is the 202 a router-executed op returns when ownerActionGate recorded a pending
// approval: { ownerActionQueued:true, id, status:"pending" } so the console routes the owner to "awaiting a
// second owner's approval". Mirrors the 202 the DO returns for the DO-executed gated ops, so the console
// treats both the same way.
export function ownerActionQueuedResponse(id: string): Response {
  return new Response(JSON.stringify({ ownerActionQueued: true, id, status: "pending" }), {
    status: 202,
    headers: { "content-type": "application/json" },
  });
}


// updateNeedsDualControl is the W5 risk-class rule for the update-apply / update-settle / update-ramp dual
// control: a release is gated by the second-owner approval (when dual control is ON) ONLY when its signed
// manifest flags it "migration" or "breaking", the consequential releases. A "routine" release applies
// without a second approver even when dual control is ON (the common patch case), per the "only gate
// dangerous activities" principle (O-3). The riskClass passed in is the NORMALISED one
// (normaliseRiskClass), so an absent/unknown class is already the safe default (migration -> gated) and a
// requiresMigration release is at least migration-class. Pure; the actual gate-on/off check + the maker !=
// checker enforcement stay in the DO (ownerActionGate). This only decides WHETHER to consult that gate.
export function updateNeedsDualControl(riskClass: RiskClass): boolean {
  return riskClass === "migration" || riskClass === "breaking";
}


// resolveRollbackTarget resolves the KNOWN-GOOD version a standalone rollback should put back live, from the
// persisted update lifecycle, in an OUTCOME-AWARE way (NOT a blind last.fromVersion). The hazard it closes: a
// rollback's record stores the abandoned BAD version in toVersion and the reverted-to known-good in
// fromVersion; reading last.fromVersion blindly would, after a rollback, still be the known-good (fine), but
// reading the WRONG field, or treating a superseded/expired record's stale versions as a target, would
// deploy a bad/abandoned build FORWARD and report it as a "rollback". The rule (and its rationale) is spelled
// out at the call site. Returns "" when there is no reliable known-good (the caller maps that to no-target).
// Pure (no I/O); the validator drives every branch.
export function resolveRollbackTarget(rec: { pending: null | { fromVersion?: string }; last: null | { outcome?: string; fromVersion?: string } }): string {
  // A verification in flight: the known-good is the version it promoted away from.
  if (rec.pending && typeof rec.pending.fromVersion === "string" && rec.pending.fromVersion !== "") return rec.pending.fromVersion;
  const last = rec.last;
  if (!last) return "";
  // applied: roll back to the prior known-good. rolled-back: fromVersion is the version we reverted TO (the
  // current known-good); we are already on it, so a redundant rollback no-ops against it (never the BAD
  // version, which is recorded in toVersion). Both use fromVersion.
  //
  // G219: the three HONEST outcomes carry the SAME fromVersion convention (the known-good), and each is a
  // state in which a manual rollback is MORE urgent, not less:
  //   rollback-failed             the auto-rollback did not land; the engine is STILL on the bad version and
  //                               fromVersion is the known-good it failed to reach. Retrying the rollback
  //                               against exactly that target is the whole remedy.
  //   rollback-failed-still-split a live traffic split is still routing to the suspect version.
  //   applied-unconfirmed         the promote was accepted and never confirmed; fromVersion is still the prior.
  // Omitting them would fall through to the no-target refusal below and REFUSE the operator a rollback in
  // precisely the states that need one -- which is why widening the outcome vocabulary had to widen this too.
  if (last.outcome === "applied" || last.outcome === "rolled-back" || last.outcome === "rollback-failed" || last.outcome === "rollback-failed-still-split" || last.outcome === "applied-unconfirmed") {
    return typeof last.fromVersion === "string" ? last.fromVersion : "";
  }
  // superseded / expired / anything else: the pending was cleared WITHOUT a deploy, so the stored versions are
  // not a reliable known-good. Refuse (no-target) rather than deploy a stale/abandoned version.
  return "";
}


// The actor-attribution + first-class audit-appender primitives (callerHeaders, recordAudit,
// recordAuditAfterSelfDeploy, observeAttachAfterSelfDeploy, stampRestoreProven) MOVED VERBATIM to the
// sibling router-audit.ts; they are re-exported below so importers that reference them by name on
// router-core are unchanged. ownerActionGate above imports callerHeaders from that spoke.
// recordBookkeepingAfterSelfDeploy (asvs-HI-19) is NEW, not moved: the update-lifecycle bookkeeping writes
// needed the same self-redeploy retry the audit append already had.
export {
  callerHeaders,
  observeAttachAfterSelfDeploy,
  recordAudit,
  recordAuditAfterSelfDeploy,
  recordAuditCheckedAfterSelfDeploy,
  recordBookkeepingAfterSelfDeploy,
  recordVerifiedEngineAccountAfterSelfDeploy,
  stampAttendedVerification,
  stampRestoreProven,
  stampRestoreTested,
} from "./router-audit.ts";
