// router-session.ts -- the session/identity RESOLVERS the admin gate depends on: the WebAuthn origin/rpId
// resolver, the DO-backed passkey-session verifier and the break-glass-retired resolver (both injected into
// authorise()), and resolveCaller/doWhoami that turn a positive verdict into the caller (role + custom-role
// + isOnlyOwner).
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW } from "../sched/scheduler-do.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import {
  type AuthMethod,
  type Caller,
  type Capability,
  type CustomRole,
  canonicalEmail,
  type Role,
  type RoleSource,
} from "./identity.ts";
import { type AdminRuntime, doURL, recordAuthSignalEdge } from "./router-helpers.ts";



// resolveCaller turns a positive auth verdict into the caller (role included) and whether the
// caller is the sole Owner, in ONE DO lookup. The token fallback resolves to owner without a DO
// round trip (no email to key on, and it is the all-or-nothing break-glass); an Access OR passkey
// caller's role + bootstrap + isOnlyOwner come from the DO whoami keyed by their verified email.
// sourceIp is the edge address the router read off CF-Connecting-IP. G346: it is threaded in because this
// resolution WRITES on a fresh engine (the first Access/passkey caller bootstraps as Owner, and that append is
// an attributed human audit row). Without it the bootstrap row landed with a null address on an engine whose
// capture path was working perfectly, and the pack's capture-fault counter cried wolf on it. It is
// SERVER-supplied (the edge header, never a client-controlled value) and is used for the audit row only; no
// gate reads it and no role is derived from it.
// fireInBackground: see router-identity.ts's identical helper. The
// bare-token limiter below records its edge signals as the LAST action before returning the verdict that
// denies the caller, and handleAdmin then answers the 429 with no awaited work left, so under real workerd
// the write can be abandoned with the request context. `runtime` is threaded from router.ts, where the
// resolver closure is built; a direct call with no fetch runtime falls back to the old bare void unchanged.
function fireInBackground(runtime: AdminRuntime | undefined, task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}


export async function resolveCaller(
  scheduler: DurableObjectStub,
  verdict: { ok: true; method: AuthMethod; email: string | null; subject?: string; groups?: string[]; identityProvider?: string; connId?: string },
  sourceIp: string | null = null,
): Promise<{ caller: Caller; isOnlyOwner: boolean; roleSource: RoleSource; customRole?: CustomRole }> {
  // Canonicalise the verified identity ONCE here, at the trust boundary, so EVERY downstream
  // consumer sees the same canonical email: the DO role lookup, the x-downpipe-caller header, the
  // audit actorEmail, and the dual-control maker != checker comparison. Without this single
  // normalisation, the role table (keyed by the lowercased email) and the maker != checker check
  // (which compares caller.email verbatim) would disagree on case, and "Alice@Example.com" could
  // approve a request raised by "alice@example.com" (the same person) as if a distinct checker.
  const email = canonicalEmail(verdict.email);
  // SECURITY (ENG-B1): ONLY the bare-token method gets the all-or-nothing Owner break-glass. An
  // emailless Access OR passkey caller must NEVER fold into this branch (that was the privilege-escalation
  // bug); the token break-glass carries no IdP identity, so no groups and no identity provider, and its
  // basis is owner-token. A passkey caller is email-bearing and is resolved below exactly like Access.
  if (verdict.method === "token") {
    return { caller: { method: "token", email: null, subject: null, role: "owner", groups: [] }, isOnlyOwner: false, roleSource: "owner-token" };
  }
  // The email-bearing method (Access or passkey) carried on the verdict; preserved on the caller so the
  // forwarded header attributes the correct method and the CSRF guard can recognise a passkey caller. Both
  // resolve their role from the per-email role table identically; only the method LABEL and the IdP-groups
  // axis (passkey carries none) differ.
  const method: AuthMethod = verdict.method;
  // The STABLE subject the role table keys on (iss+"|"+sub for Access, passkeySubject(email) for passkey).
  // authorise() guarantees an Access/passkey verdict carries one; a passkey verdict's subject is derived
  // from its bound email. It is threaded into the DO whoami so the DO keys the role lookup on the subject.
  const subject = verdict.subject ?? null;
  // An Access/passkey caller must resolve to a verified email AND a stable subject (authorise + handleAdmin
  // enforce both upstream); if either is somehow absent here, fail closed to a least-privilege viewer,
  // never the break-glass.
  if (!email || !subject) {
    // G201: the SILENT DOWNGRADE. An Access/passkey caller that reached here without a usable email or subject
    // is failed closed to a least-privilege viewer -- which is precisely what an owner whose role was REVOKED
    // also looks like. "I am an owner but I am treated as a viewer" had no evidence on either side of it.
    // The e-mail and subject themselves are of course never recorded: only that the downgrade happened.
    void recordAuthSignalEdge(scheduler, "caller-verdict-degraded");
    return { caller: { method, email: email ?? null, subject, role: "viewer", groups: [] }, isOnlyOwner: false, roleSource: "default" };
  }
  // The OPTIONAL verified groups (from the RS256-verified Access payload) are threaded into the DO role
  // lookup so the DO resolves roleFor(subject, email, groups); a passkey caller carries no groups ([]), so
  // its resolution is the subject-keyed path exactly. The DO is the role authority; the role + source it
  // returns are used verbatim (and it binds-on-first-auth a pending email invite to this subject).
  const groups = verdict.groups ?? [];
  const who = await doWhoami(scheduler, method, email, subject, groups, sourceIp);
  // caller.email is the canonical email from here on; the header builder, recordAudit, and the DO
  // approval logic all read this one value, so the whole request compares canonical-to-canonical.
  // caller.groups carries the verified groups so a forwarded mutating call lets the DO RE-RESOLVE the
  // role from email + groups (it never trusts the asserted role for the group-roles routes). buildCaller
  // assembles the caller (including any custom-role envelope) from the verdict + the whoami result.
  return buildCaller(method, email, subject, groups, verdict, who);
}


// buildCaller assembles the resolved Caller (and the isOnlyOwner / roleSource / customRole envelope) from
// the verified method/email/subject/groups and the DO whoami result. It is the spread-heavy construction
// extracted from resolveCaller so that function stays under the §6 50-line ceiling. CUSTOM ROLE: when the
// DO resolved a custom role it returned the role record + the resolved capability ARRAY; the role NAME is
// carried on the caller (forwarded to the DO so it re-resolves the SAME set, never a forwarded set) and the
// capability SET locally so callerCan() gates this request by exactly those capabilities. role stays the
// built-in floor (viewer) the DO returned, so any non-capability read of caller.role is least-privilege and
// the owner-escalation guard treats a custom-role caller as a non-owner. For a built-in caller both absent.
function buildCaller(
  method: AuthMethod,
  email: string,
  subject: string,
  groups: string[],
  verdict: { identityProvider?: string; connId?: string },
  who: { role: Role; roleSource: RoleSource; isOnlyOwner: boolean; customRole?: CustomRole; capabilities?: Capability[] },
): { caller: Caller; isOnlyOwner: boolean; roleSource: RoleSource; customRole?: CustomRole } {
  const customRoleName = who.customRole?.name;
  const capabilities = who.capabilities !== undefined ? new Set<Capability>(who.capabilities) : undefined;
  return {
    caller: {
      method,
      email,
      subject,
      role: who.role,
      groups,
      ...(verdict.identityProvider !== undefined ? { identityProvider: verdict.identityProvider } : {}),
      ...(verdict.connId !== undefined ? { connId: verdict.connId } : {}),
      ...(customRoleName !== undefined ? { customRole: customRoleName } : {}),
      ...(capabilities !== undefined ? { capabilities } : {}),
    },
    isOnlyOwner: who.isOnlyOwner,
    roleSource: who.roleSource,
    ...(who.customRole !== undefined ? { customRole: who.customRole } : {}),
  };
}


// doWhoami asks the DO for the role + roleSource + isOnlyOwner for the CANONICAL verified email and the
// verified groups (and bootstraps the first email-bearing caller as Owner). Both the Access and the passkey
// path reach here (the token fallback is resolved without a DO round trip); the method is forwarded so the
// DO's whoami treats it correctly (only "token" is the break-glass; "access" and "passkey" both take the
// email-keyed path, so passkey resolves its role exactly like Access). The email is already canonicalised
// by resolveCaller, so the role-table key the DO computes and the caller.email the rest of the request uses
// are the same canonical string. groups are passed as a JSON array query param (a passkey caller passes an
// empty list, the per-email path). The DO additionally returns the custom-role record + the resolved
// capability ARRAY when the caller resolved to a custom role (roleSource "custom"); both are absent for a
// built-in-role caller.
export async function doWhoami(
  scheduler: DurableObjectStub,
  method: AuthMethod,
  email: string,
  subject: string,
  groups: string[],
  sourceIp: string | null = null,
): Promise<{ role: Role; roleSource: RoleSource; subject?: string; isOnlyOwner: boolean; customRole?: CustomRole; capabilities?: Capability[] }> {
  const params = new URLSearchParams();
  params.set("method", method);
  params.set("email", email);
  // The stable subject the DO keys the role lookup on (and bootstraps/binds by). Forwarded as a query
  // param like email + groups; the DO bounds it itself (normaliseSubject) before using it as a key.
  params.set("subject", subject);
  if (groups.length > 0) params.set("groups", JSON.stringify(groups));
  // G346: the ONE write this read-shaped route can perform is the first-Owner bootstrap, and it appends an
  // attributed human audit row. Forward the edge address alongside email/subject/method/groups so that row
  // carries the same provenance every other human row does, instead of the honest-but-wrong "not recorded"
  // that the pack then counted as a capture fault. This is the router's own read of CF-Connecting-IP (never a
  // client-supplied value), it travels on the internal DO fetch only, and it reaches nothing but the audit
  // draft: the role is resolved without it, exactly as before.
  if (sourceIp !== null && sourceIp !== "") params.set("sourceIp", sourceIp);
  const resp = await scheduler.fetch(doURL(`/whoami?${params.toString()}`), { method: "GET" });
  // G051: a NON-2xx here is not an error -- the body is parsed anyway, and a body without a `role` resolves the
  // caller to the viewer default. So a DO blip can tell a genuine Owner that their own console is read-only
  // ("every security-centre and credentials control is greyed out, owner only"), and nothing anywhere recorded
  // that the identity report was ABSENT rather than LOW. The behaviour is unchanged; the degradation is counted.
  if (!resp.ok) void bumpAdminCounter(scheduler, "degraded-read-whoami");
  // G257: the same degradation, in the aggregate the CONSOLE'S OWN symptoms are read against. degraded-read-whoami
  // is an admin counter (a total); this is the authSignals entry, which carries firstAt, lastAt and a 14-day
  // per-day ring, so "every control has been greyed out since Tuesday" can be answered with a date rather than a
  // number. The console's honest degradation to viewer is what the customer is looking at; this is the only thing
  // that says the engine, not their role, is why.
  if (!resp.ok) void recordAuthSignalEdge(scheduler, "whoami-server-error");
  return (await resp.json()) as { role: Role; roleSource: RoleSource; subject?: string; isOnlyOwner: boolean; customRole?: CustomRole; capabilities?: Capability[] };
}


// passkeyOriginAndRpId resolves the WebAuthn origin (CONSOLE_ORIGIN, the exact origin the browser
// ceremony runs in) and the rp.id the credential is scoped to. The origin is CONSOLE_ORIGIN verbatim.
// The rp.id is PASSKEY_RP_ID when set, else the HOST of CONSOLE_ORIGIN: WebAuthn requires the rp.id to
// be a registrable-domain suffix of the ceremony origin, which is the CONSOLE, so the console host is
// the correct default (an engine-host rp.id would fail in the browser since the ceremony does not run on
// the engine origin). Returns null when CONSOLE_ORIGIN is unset or unparseable, so the passkey routes
// fail closed (501) rather than running a ceremony with no origin to bind and check against.
export function passkeyOriginAndRpId(env: Env): { origin: string; rpId: string } | null {
  const origin = typeof env.CONSOLE_ORIGIN === "string" ? env.CONSOLE_ORIGIN.trim() : "";
  if (origin.length === 0) return null;
  let host: string;
  try {
    host = new URL(origin).hostname;
  } catch {
    return null;
  }
  if (host.length === 0) return null;
  const configured = typeof env.PASSKEY_RP_ID === "string" ? env.PASSKEY_RP_ID.trim() : "";
  const rpId = configured.length > 0 ? configured : host;
  return { origin, rpId };
}


// verifyPasskeySessionViaDO is the PasskeySessionVerifier the router injects into authorise(): it forwards
// the presented session cookie token to the DO's POST /passkey/session/verify, where the constant-time MAC,
// the exp check and the epoch-revocation gate run over the signing key that never leaves the DO, and returns
// the verified identity (email + the SIGNED stable subject + the cookie-borne method + the optional connId)
// or null. A DO hiccup or any non-ok/inconsistent shape resolves to null (fail closed): authorise() then
// treats the request as having no valid session, which (because a cookie WAS present) denies it rather than
// silently downgrading to the token path. It NEVER throws (the DO fetch is guarded), so the auth path cannot
// 500 on a session check.
export async function verifyPasskeySessionViaDO(scheduler: DurableObjectStub, token: string, onSlide?: (token: string) => void): Promise<{ email: string; subject: string; method: AuthMethod; connId: string | null; groups: string[] } | null> {
  try {
    const resp = await scheduler.fetch(doURL("/passkey/session/verify"), {
      method: "POST",
      body: JSON.stringify({ token }),
      headers: { "content-type": "application/json" },
    });
    const res = (await resp.json()) as { verdict?: unknown; email?: string | null; subject?: unknown; method?: unknown; connId?: unknown; groups?: unknown; slidToken?: unknown };
    // G201: TELL AN OUTAGE FROM A LOGGED-OUT USER. Every branch below fails the request CLOSED to a null
    // caller, which is byte-identical to an expired or forged cookie. So a DO that is UP AND BROKEN (a drifted
    // build, a half-written record, a storage fault) signs the whole team out and reads, in every artefact, as
    // "their sessions expired". The three states are separated on the DO's REAL contract, its closed `verdict`
    // token, not on the shape of the payload:
    //
    //   verdict "rejected"  -> the DO answered and REFUSED (no token, a bad MAC, an expired token, a revoked
    //                          epoch). A LEGITIMATE state, taken on every stale page load and by every session
    //                          on the estate after a terminate-all or a factor change. RECORDS NOTHING.
    //   verdict "verified"  -> the DO answered and ACCEPTED. Its payload must then satisfy the contract; if it
    //                          does not, the DO is broken (session-shape-invalid).
    //   no verdict at all   -> the DO never ran this function. scheduler.fetch() does not throw on an HTTP
    //                          error status, so an up-but-broken DO arrives HERE, through its own JSON 500
    //                          envelope, and NOT in the catch below: the body parses and the verdict is simply
    //                          absent. This is the "whole team got logged out for an hour" outage, and it is
    //                          the ONLY branch here that is a fault with a healthy-looking cookie.
    //
    // NOISE DISCIPLINE (the defect this replaces): the previous guard inferred "the DO answered" from
    // `res.email !== undefined`. The DO returns `{ email: null }` on all six of its ordinary rejection paths,
    // and `null !== undefined` is TRUE, so an EXPIRED COOKIE fired session-shape-invalid -- an exact-count
    // signal, so also a storage write per rejected request on the hottest path in the product -- while the real
    // outage recorded nothing at all. A signal that fires on a legitimate state devalues every true one.
    if (res.verdict === "rejected") return null;
    if (res.verdict !== "verified") {
      void recordAuthSignalEdge(scheduler, "session-verify-verdict-malformed");
      return null;
    }
    const shapeOk = typeof res.email === "string" && res.email.length > 0 && typeof res.subject === "string" && res.subject.length > 0 && (res.method === "passkey" || res.method === "oidc" || res.method === "saml");
    if (!shapeOk) void recordAuthSignalEdge(scheduler, "session-shape-invalid");
    if (typeof res.email !== "string" || res.email.length === 0) return null;
    if (typeof res.subject !== "string" || res.subject.length === 0) return null;
    const method = res.method;
    if (method !== "passkey" && method !== "oidc" && method !== "saml") return null;
    const connId = typeof res.connId === "string" && res.connId.length > 0 ? res.connId : null;
    // The DO returns the live per-subject GROUP snapshot for an oidc/saml session ([] for passkey). Bound it
    // defensively (keep only strings) so a malformed DO response cannot inject a non-string into role resolution.
    const groups = Array.isArray(res.groups) ? res.groups.filter((g): g is string => typeof g === "string") : [];
    // V7.3.1 idle-slide: when the DO re-minted the session (lastSeen was stale), hand the fresh token to the
    // optional onSlide sink so the caller can set it as a refreshed cookie. Verification itself is unaffected.
    if (typeof res.slidToken === "string" && res.slidToken.length > 0 && onSlide !== undefined) onSlide(res.slidToken);
    return { email: res.email, subject: res.subject, method, connId, groups };
  } catch (e) {
    log("error", `session cookie verify unavailable, failing closed (request denied): ${(e as Error).message}`);
    // G201: the fail-closed DENIAL is identical to an expired session, so "the whole team got logged out for an
    // hour" arrived with an authSignals aggregate that was EMPTY -- during exactly the outage it exists to
    // explain. Fire-and-forget; never delays the denial. (If the DO is down this write is dropped too, and
    // recordAuthSignalEdge's own droppedWrites tally is what says the pack is under-recording.)
    void recordAuthSignalEdge(scheduler, "session-verify-unavailable");
    return null;
  }
}


// breakGlassRetiredViaDO is the BreakGlassRetiredResolver the router injects into authorise(): it forwards a
// GET to the DO's /policy/break-glass-retired and returns the durable breakGlassTokenRetired latch, so a
// retired token is refused at the gate exactly as ADMIN_TOKEN_DISABLED refuses it. It FAILS CLOSED (returns
// true = retired/deny) on a DO hiccup or any non-boolean shape: the DO is the authority for everything the
// token could do anyway, and a leaked token must never win a fail-open bypass by knocking the DO over. It
// NEVER throws (the DO fetch is guarded), so the auth path cannot 500 on the retire check. authorise()
// invokes it ONLY on the bare-token path (after Access + passkey, once a token is configured and presented),
// so it adds no DO read to the Access/passkey/no-credential paths.
export async function breakGlassRetiredViaDO(scheduler: DurableObjectStub): Promise<boolean> {
  try {
    const resp = await scheduler.fetch(doURL("/policy/break-glass-retired"), { method: "GET" });
    const res = (await resp.json()) as { breakGlassTokenRetired?: unknown };
    // Fail closed on anything other than an explicit false: only a verdict that positively says
    // breakGlassTokenRetired === false admits the token; a missing/garbled shape denies it.
    //
    // G201: THE ANSWERED OUTAGE, and it is the whole "my break-glass token stopped working" ticket. There are
    // three ways the token gets denied here and, until now, only one of them left a trace:
    //
    //   an INTENTIONAL retire       breakGlassTokenRetired === true. Records nothing (it is not a fault: the
    //                               Owner asked for exactly this). Correct, and it stays that way.
    //   an UNREACHABLE DO           the fetch throws -> break-glass-check-unavailable (the catch below).
    //   an ANSWERED-BUT-BROKEN DO   a JSON 500 / a drifted route / a half-written record: the body parses and
    //                               carries no boolean, the token is denied fail-closed, and the operator's
    //                               experience is IDENTICAL to a retire they never performed. scheduler.fetch
    //                               does not throw on an HTTP error status, so this never reached the catch.
    //
    // The third one now has its own row, so the pack can say "your retire check is broken" rather than leaving
    // the support engineer to guess between a rotten DO answer and a deliberate retire that records nothing.
    if (typeof res.breakGlassTokenRetired !== "boolean") {
      log("error", "break-glass-retired check answered without a boolean verdict, failing closed (token denied)");
      void recordAuthSignalEdge(scheduler, "break-glass-check-shape-invalid");
    }
    return res.breakGlassTokenRetired !== false;
  } catch (e) {
    log("error", `break-glass-retired check unavailable, failing closed (token denied): ${(e as Error).message}`);
    // P3 (break-glass-retired-resolver-failclosed): record that the bare-token fallback was DENIED because the
    // retire-latch check could not reach the DO, so a "my break-glass token stopped working" ticket is
    // diagnosable as a DO-availability event rather than an intentional retire. Fire-and-forget; never blocks.
    void recordAuthSignalEdge(scheduler, "break-glass-check-unavailable");
    return true;
  }
}


// adminTokenRateLimitedViaDO is the TokenRateLimiter the router injects into authorise() (ASVS V6.3.1):
// the bare-token break-glass compare has no ceremony of its own to throttle it (unlike Access or the
// passkey session, which authRateLimited already guards), so this mirrors authRateLimited's per-IP
// fail-closed design over the SAME generic DO /rate-check route, but in its OWN key namespace
// (`admin-token-ip:`, never `ip:`) so it neither shares the auth-ceremony bucket nor trips the DO's
// generic `key.startsWith("ip:")` auto-signal (scheduler-do.ts rateCheck) - this resolver records its own
// distinct signal below instead. Same missing-IP carve-out as authRateLimited (edge-guaranteed at the
// custom-domain-only deployment; see its comment for the full reasoning). FAILS CLOSED like
// authRateLimited, not rateLimited's fail-open (this guards an unauthenticated guessing surface, not a
// verified operator's recovery action): a non-admit verdict OR a thrown round trip returns true
// (blocked), and either way records admin-token-ratelimited (fire-and-forget) so a guessing campaign - or
// a limiter outage denying a legitimate operator - is visible in the support pack, closing the gap the
// finding identified (previously nothing but an ephemeral log line).
export async function adminTokenRateLimitedViaDO(scheduler: DurableObjectStub, req: Request, runtime?: AdminRuntime): Promise<boolean> {
  const ip = req.headers.get("CF-Connecting-IP");
  if (ip === null || ip.length === 0) return false; // no source IP: admit (edge-impossible; see authRateLimited)
  try {
    const resp = await scheduler.fetch(doURL("/rate-check"), {
      method: "POST",
      body: JSON.stringify({ key: `admin-token-ip:${ip}`, max: ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW }),
      headers: { "content-type": "application/json" },
    });
    const verdict = (await resp.json()) as { allowed?: boolean };
    if (verdict.allowed === true) return false;
    // G201: the OVER-CAP arm, and it is now gated STRICTLY on an explicit allowed === false. The first build
    // fired -overcap on ANY non-admit answer, which re-created inside the fix the exact anti-goal the gap
    // names: scheduler.fetch does not throw on an HTTP error status, so an up-but-broken limiter DO (its own
    // JSON 500, a drifted route) answered without a verdict, was filed as "the limiter is WORKING and someone
    // is guessing your break-glass token", and sent the ticket hunting an attacker who did not exist.
    //
    //   allowed === false   the limiter WORKED and said no: a real guessing campaign, or one operator retrying
    //                       hard. This is the ONLY state that is throttling.
    //   no boolean          the limiter ANSWERED and is broken: the denial is an OUTAGE wearing a throttle's
    //                       clothes. Its own row (-malformed), distinct from the unreachable-DO row below.
    //
    // The legacy admin-token-ratelimited name rides on both so the aggregate stays continuous across the split.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "admin-token-ratelimited"));
    if (verdict.allowed === false) {
      fireInBackground(runtime, recordAuthSignalEdge(scheduler, "admin-token-ratelimited-overcap"));
    } else {
      log("error", "admin-token rate-check answered without a boolean verdict, failing closed (token denied)");
      fireInBackground(runtime, recordAuthSignalEdge(scheduler, "admin-token-ratelimited-malformed"));
    }
    return true;
  } catch (e) {
    log("error", `admin-token rate-check unavailable, failing closed (token denied): ${(e as Error).message}`);
    // G201: the OUTAGE arm, which used to be filed under the SAME name as the over-cap one. The two are
    // opposite diagnoses: over-cap says "someone is guessing your break-glass token", unavailable says "your
    // scheduler is down and it denied a legitimate operator's break-glass because it fails closed". Labelling
    // an outage as throttling sent every "my break-glass token stopped working" ticket looking for an attacker.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "admin-token-ratelimited"));
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "admin-token-ratelimited-unavailable"));
    return true;
  }
}
