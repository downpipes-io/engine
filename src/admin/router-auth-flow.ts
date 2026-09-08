// router-auth-flow.ts -- the PRE-AUTH /admin/auth/* sign-in FLOW: the WebAuthn front door (register/login
// begin+finish, logout), the session-mint-on-finish helper, the recovery-code sign-in + self-service
// regeneration, and the first-Owner bootstrap-link email. These run BEFORE the main authorise() gate (they
// ARE the sign-in flow).

import { isCustomDomainAddress } from "../email.ts";
import { renderEngineEmailHtml } from "../email-theme.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { authorise, type BreakGlassRetiredResolver, type PasskeySessionVerifier } from "./auth.ts";
import { bootstrapEmailSignalName } from "./auth-signals.ts";
import { canonicalEmail, isCookieBorneMethod } from "./identity.ts";
import { type PasskeyCeremony, passkeySignalName } from "./passkey-types.ts";
import { attemptedMethod, authRateLimited, logAuthFailure, requireStepUp } from "./router-core.ts";
import { type AdminRuntime, doURL, recordAuthSignalEdge, schedulerStub } from "./router-helpers.ts";
import { routeAuthChangeAlert, routeRecoveryAlert, routeSignInContextAlert } from "./router-notify.ts";
import { breakGlassRetiredViaDO, passkeyOriginAndRpId, verifyPasskeySessionViaDO } from "./router-session.ts";
import { originFailClass, readSessionCookie, sessionClearCookie, sessionSetCookie } from "./session.ts";



// handleRecovery serves POST /admin/auth/recovery { email, code }: the recovery-code sign-in. It is the
// ongoing admin break-glass for a user who lost their passkey. It forwards the email + code + source IP to
// the DO (the authority that holds the per-email hashes, the in-DO signing key, the hard rate limit and the
// session mint). On a verified, unconsumed code the DO marks it consumed and mints a NORMAL signed session;
// the router sets the same hardened __Host- cookie a passkey login sets and returns a body telling the
// console to prompt a fresh-passkey enrolment. On ANY failure (wrong code, unknown email, exhausted set,
// rate-limited) the DO returns a generic { ok:false }, which the router maps to a single 401 "unauthorised"
// (the same plaintext sign-in signal the main gate returns), so there is NO oracle on which part failed and
// no "email not found" distinction. The DO audits every attempt and returns an alert SIGNAL (used/abuse)
// the router routes through the notify channels (fire-and-forget) so a successful break-glass sign-in AND
// repeated failures are loud. The whole route NEVER reads or returns a code hash and never logs the code.
export async function handleRecovery(req: Request, env: Env, runtime?: AdminRuntime): Promise<Response> {
  // fireInBackground: both auth-signal writes below fire as the LAST
  // action on their branch before an immediate return, with no await in between to give the detached promise
  // a scheduling window -- the same shape already confirmed to lose a write live. runtime is
  // undefined only for a direct call with no fetch runtime (a unit test), which falls back to the old bare-void.
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  const scheduler = schedulerStub(env);
  // PER-IP pre-throttle (same fail-open per-IP ceremony limiter as the passkey routes), BEFORE the body
  // read, so a flood is shed early. The DO then applies the HARD per-email + per-IP recovery limit (fail
  // closed) on top; this outer one is the cheap first line, the DO's is the authoritative one.
  const authLimited = await authRateLimited(scheduler, req, runtime);
  if (authLimited) return authLimited;
  // CSRF is not applicable here: recovery is an UNAUTHENTICATED sign-in that carries no ambient credential a
  // foreign page could ride (there is no session cookie yet); like login/finish it is not Origin-gated.
  const body = (await req.json()) as { email?: unknown; code?: unknown };
  const ip = req.headers.get("CF-Connecting-IP");
  const resp = await scheduler.fetch(doURL("/recovery/recover"), {
    method: "POST",
    body: JSON.stringify({ email: body.email, code: body.code, ...(ip !== null ? { ip } : {}) }),
    headers: { "content-type": "application/json" },
  });
  const result = (await resp.json()) as
    | { ok: true; email: string; token: string; role: string; remaining: number; enrolPasskey?: unknown }
    | { ok: false; alert: "recovery-code-used" | "recovery-code-abuse" | null };
  if (result.ok !== true) {
    // GENERIC failure: a single 401 plaintext, identical to the main gate's sign-in failure, so the console
    // shows "sign-in failed" with no detail. Route the abuse alert (repeated/failed attempts) fire-and-forget.
    logAuthFailure("token", "recovery-code sign-in rejected");
    // OBSERVE (G083 / G124): "every recovery code we try is rejected". Until now this left NOTHING in the pack -
    // the log line above goes to Workers Logs, which remote support structurally cannot read. Count the rejection
    // class only; the presented code, the email and the IP never ride, and the 401 the caller sees stays generic.
    fireInBackground(recordAuthSignalEdge(scheduler, "recovery-code-invalid"));
    if (result.alert !== null) {
      fireInBackground(
        routeRecoveryAlert(env, scheduler, result.alert, null).catch((e: unknown) => {
          log("error", `recovery-code alert routing skipped (non-critical): ${(e as Error).message}`);
        }),
      );
    }
    return new Response("unauthorised", { status: 401 });
  }
  // SUCCESS: set the hardened session cookie (the same __Host- cookie a passkey login issues) and return a
  // body the console reads: ok + the resolved role + enrolPasskey (prompt the user to enrol a fresh passkey)
  // + the remaining count. The token is in the cookie, never the body. Route the used alert so a successful
  // break-glass sign-in is loud.
  //
  // enrolPasskey IS FORWARDED FROM THE DO AND WAS A HARDCODED `true` HERE. That was harmless only while the
  // DO's field was typed as the literal true, and it is the shape of coupling this campaign has been closing:
  // the authority computes an answer and the layer in front republishes a constant, so the day the authority
  // learns to say no, the wire keeps saying yes. It is read DEFENSIVELY (an absent or non-boolean field
  // yields false rather than true), because the only cost of a false negative here is that the console asks
  // the user to enrol from the Keys screen instead of prompting them, and the cost of a false positive is
  // offering a button the registration route will refuse.
  const enrolPasskey = result.enrolPasskey === true;
  fireInBackground(
    routeRecoveryAlert(env, scheduler, "recovery-code-used", result.email).catch((e: unknown) => {
      log("error", `recovery-code alert routing skipped (non-critical): ${(e as Error).message}`);
    }),
  );
  return new Response(
    JSON.stringify({ ok: true, role: result.role, enrolPasskey, recoveryCodesRemaining: result.remaining }),
    { status: 200, headers: { "content-type": "application/json", "set-cookie": sessionSetCookie(result.token) } },
  );
}


// handleRegenerate serves POST /admin/auth/recovery-codes/regenerate: the self-service "mint a fresh set"
// route. It is dispatched under /admin/auth/ (before the main gate) but is AUTHENTICATED inside: it runs the
// SAME authorise() the main gate uses (with the passkey-session + break-glass-retired wiring) to identify
// the caller, then scopes the regeneration to the caller's OWN verified email, so a user can only regenerate
// their own codes. The bare-token break-glass has no email (it is not a per-email identity), so it cannot
// regenerate a set (there is no email to scope to) and is refused; recovery codes are a per-user credential,
// and the token is the thing being disposed of, not a recovery-code holder. The DO mints a fresh set,
// invalidates all prior codes for that email, and returns the plaintext ONCE; the router returns it verbatim
// for one-time display (it is never stored or returned again). CSRF: a regenerate is a MUTATING request that
// can be cookie-borne (a passkey-session caller), so it is strict-Origin gated for that method, exactly like
// the mutating admin routes.
export async function handleRegenerate(req: Request, env: Env, runtime?: AdminRuntime): Promise<Response> {
  // fireInBackground: see handleRecovery's identical helper above.
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  const scheduler = schedulerStub(env);
  const authLimited = await authRateLimited(scheduler, req, runtime);
  if (authLimited) return authLimited;
  const verifyPasskeySession: PasskeySessionVerifier = (token) => verifyPasskeySessionViaDO(scheduler, token);
  const breakGlassRetired: BreakGlassRetiredResolver = () => breakGlassRetiredViaDO(scheduler);
  const verdict = await authorise(req, env, verifyPasskeySession, breakGlassRetired);
  if (!verdict.ok) {
    logAuthFailure(attemptedMethod(req), "regenerate recovery codes: not authenticated");
    return new Response("unauthorised", { status: 401 });
  }
  // The caller MUST carry a verified email to own a recovery set. An Access/passkey caller does; the bare
  // token does not (it is the email-less break-glass), so it cannot regenerate a per-user set.
  const email = canonicalEmail(verdict.email);
  if (!email) {
    logAuthFailure(verdict.method, "regenerate recovery codes: caller has no per-user email (token break-glass cannot hold recovery codes)");
    return new Response(JSON.stringify({ error: "recovery codes are per-user; sign in as a user (passkey or Access) to regenerate" }), { status: 403, headers: { "content-type": "application/json" } });
  }
  // CSRF for the cookie (passkey-session) method on this mutating request: require a strict-Origin match,
  // exactly like every other mutating cookie-borne route. Access/token carry an explicit header and are not
  // ambient-credential CSRF vectors, so they are exempt (mirroring handleAdmin's conditional check).
  // G118: record WHICH branch refused (unset CONSOLE_ORIGIN vs a foreign Origin vs no Origin at all). This route
  // was one of the two CSRF callers that recorded NOTHING, so "regenerate recovery codes always 403s" -- on the
  // last-way-back-in path -- left no trace in the pack whatsoever. The 403 and its body are unchanged.
  const originFault = isCookieBorneMethod(verdict.method) ? originFailClass(req, env.CONSOLE_ORIGIN) : null;
  if (originFault !== null) {
    logAuthFailure(verdict.method, "regenerate recovery codes: cross-origin request rejected by the CSRF Origin check");
    fireInBackground(recordAuthSignalEdge(scheduler, originFault));
    return new Response(JSON.stringify({ error: "csrf origin check failed" }), { status: 403, headers: { "content-type": "application/json" } });
  }
  // Step-up (ASVS V7.5.1): regenerating recovery codes is a sensitive action, so require a FRESH re-auth proof
  // (or a recent authentication). The bare-token + Access methods are exempt inside requireStepUp; a recovery
  // sign-in is itself recent-enough (freshness) so a break-glass operator is never locked out of this.
  const stepUp = await requireStepUp(req, scheduler, verdict.method, runtime);
  if (stepUp) return stepUp;
  // The source IP for the recovery-codes-generated audit event, forwarded in the body (the recovery-recover
  // pattern): the DO method takes only the email, so the IP rides the body. Server-read, never a client field.
  const ip = req.headers.get("CF-Connecting-IP");
  const resp = await scheduler.fetch(doURL("/recovery/regenerate"), {
    method: "POST",
    body: JSON.stringify({ email, method: verdict.method, ...(ip !== null ? { ip } : {}) }),
    headers: { "content-type": "application/json" },
  });
  const result = (await resp.json()) as { ok?: boolean; codes?: string[]; reason?: string };
  // ROSTER-BOUND REGENERATION (see recoveryRegenerate). This is a POLICY answer, not a fault, and it must not
  // wear the 500 below: the operator reading "could not regenerate recovery codes" would retry for ever, and
  // the pack would carry a server fault where a deliberate refusal happened. The message says what is true and
  // what is still available, because the person reading it has just signed in with a break-glass code and the
  // one thing they must not conclude is that they are locked out.
  if (result.reason === "off-roster") {
    logAuthFailure(verdict.method, "regenerate recovery codes: the address is no longer on the account's roster");
    return new Response(
      JSON.stringify({ error: "this address is no longer on the account's roster, so a fresh set of recovery codes cannot be minted for it; the codes you already hold still sign you in, and an Owner can restore the grant" }),
      { status: 403, headers: { "content-type": "application/json" } },
    );
  }
  if (result.ok !== true || !Array.isArray(result.codes)) {
    // OBSERVE (G083): the regenerate failed engine-side. The console keeps nagging the operator to regenerate and
    // the regenerate keeps failing, with the DO's reason discarded into a bare 500 - recorded nowhere until now.
    fireInBackground(recordAuthSignalEdge(scheduler, "recovery-regenerate-failed"));
    return new Response(JSON.stringify({ error: "could not regenerate recovery codes" }), { status: 500, headers: { "content-type": "application/json" } });
  }
  // V6.3.7: notify that recovery codes were regenerated (a "your sign-in details changed" signal - if it was
  // not you, a takeover indicator). The codes themselves are NEVER in the notify body (redaction-safe).
  fireInBackground(routeAuthChangeAlert(env, scheduler, "auth-credential-change", "recovery-regenerate", `Recovery codes were regenerated${email ? ` for ${email}` : ""}.`));
  // Return the fresh plaintext set ONCE for display. This is the only time the codes leave the engine; they
  // are never stored as plaintext and never returned again (a later read sees only the count).
  return new Response(JSON.stringify({ ok: true, recoveryCodes: result.codes }), { status: 200, headers: { "content-type": "application/json" } });
}


// handleConfirmStaged serves POST /admin/auth/recovery-codes/confirm (STAGED-RECOVERY-CODES-CONFIRM-GATE):
//  the console fires this the moment the operator ticks "I have saved my recovery codes" and
// presses Continue on the save-confirm panel, for an enrolment whose register/finish answered
// recoveryCodesPending:true (a self-add that ran while a live record already existed -- the forced
// re-enrolment after a recovery-code sign-in is the common case, but any self-add reaches it). It promotes
// the STAGED set generateRecoveryStaged minted to live, which is the actual invalidation of whatever was
// live before it; until this call the operator's old codes keep working, so an abandoned enrolment (the tab
// closed before Continue was pressed) costs nothing.
//
// AUTHENTICATED, exactly like handleRegenerate: it runs the SAME authorise() the main gate uses and scopes
// the confirm to the caller's OWN verified email, so a caller can only promote their own staged set. IT IS
// NOT A SENSITIVE MUTATION IN THE WAY REGENERATE IS: it does not mint anything and does not decide to
// invalidate a working set on the operator's say-so alone -- the operator already completed a step-up-gated
// enrolment ceremony (or the freshness of their recovery sign-in) to reach this point, and confirm only
// finalises what that ceremony already produced. No additional step-up is required. CSRF: still a MUTATING
// cookie-borne request, so the same strict-Origin check applies. A confirm for an email with nothing staged
// (already confirmed, none was ever staged, or a later staged mint superseded it) is a harmless 200
// promoted:false, never a fault: the caller is already signed in and their live set is already correct
// either way.
export async function handleConfirmStaged(req: Request, env: Env, runtime?: AdminRuntime): Promise<Response> {
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  const scheduler = schedulerStub(env);
  const authLimited = await authRateLimited(scheduler, req, runtime);
  if (authLimited) return authLimited;
  const verifyPasskeySession: PasskeySessionVerifier = (token) => verifyPasskeySessionViaDO(scheduler, token);
  const breakGlassRetired: BreakGlassRetiredResolver = () => breakGlassRetiredViaDO(scheduler);
  const verdict = await authorise(req, env, verifyPasskeySession, breakGlassRetired);
  if (!verdict.ok) {
    logAuthFailure(attemptedMethod(req), "confirm staged recovery codes: not authenticated");
    return new Response("unauthorised", { status: 401 });
  }
  const email = canonicalEmail(verdict.email);
  if (!email) {
    logAuthFailure(verdict.method, "confirm staged recovery codes: caller has no per-user email");
    return new Response(JSON.stringify({ error: "recovery codes are per-user; sign in as a user (passkey or Access) to confirm" }), { status: 403, headers: { "content-type": "application/json" } });
  }
  const originFault = isCookieBorneMethod(verdict.method) ? originFailClass(req, env.CONSOLE_ORIGIN) : null;
  if (originFault !== null) {
    logAuthFailure(verdict.method, "confirm staged recovery codes: cross-origin request rejected by the CSRF Origin check");
    fireInBackground(recordAuthSignalEdge(scheduler, originFault));
    return new Response(JSON.stringify({ error: "csrf origin check failed" }), { status: 403, headers: { "content-type": "application/json" } });
  }
  const ip = req.headers.get("CF-Connecting-IP");
  const resp = await scheduler.fetch(doURL("/recovery/confirm-staged"), {
    method: "POST",
    body: JSON.stringify({ email, method: verdict.method, ...(ip !== null ? { ip } : {}) }),
    headers: { "content-type": "application/json" },
  });
  const result = (await resp.json()) as { ok?: boolean; promoted?: boolean };
  if (result.ok !== true) {
    fireInBackground(recordAuthSignalEdge(scheduler, "recovery-regenerate-failed"));
    return new Response(JSON.stringify({ error: "could not confirm recovery codes" }), { status: 500, headers: { "content-type": "application/json" } });
  }
  if (result.promoted === true) {
    // V6.3.7: the same "your sign-in details changed" signal regenerate fires, now that the staged set has
    // actually gone live and the old one is dead.
    fireInBackground(routeAuthChangeAlert(env, scheduler, "auth-credential-change", "recovery-regenerate", `Recovery codes were regenerated${email ? ` for ${email}` : ""}.`));
  }
  return new Response(JSON.stringify({ ok: true, promoted: result.promoted === true }), { status: 200, headers: { "content-type": "application/json" } });
}


// handleLogout serves POST /admin/auth/logout: clear the session cookie and return ok. CSRF: logout is a
// MUTATING (state-changing) request on the ambient session cookie, so a foreign page could otherwise
// force-log-out a signed-in user. Apply the SAME strict-Origin check as every other mutating cookie-borne
// route: refuse a cross-origin logout 403. originAllowed fails closed on a missing Origin or an unset
// CONSOLE_ORIGIN; the console always sends Origin on a fetch, so a legitimate logout is never blocked. (A
// clear-only op is low-impact, but matching the Origin discipline closes the cross-origin forced-logout
// vector.) V7.4.1 / V7.4.2: TERMINATE the session SERVER-SIDE, not merely clear the browser cookie. A
// clear-only logout left a captured/exfiltrated COPY of the bearer token valid for up to the 12h TTL. The
// stateless token carries no per-session row, so the kill is the coarse revocation axis: the DO bumps this
// identity's per-email epoch + per-subject not-before instant, so the just-logged-out token AND any copy
// fail closed on their next request. This signs the account out of all its sessions - the correct posture
// for a logout on an admin console with a 12h TTL. BEST-EFFORT: a missing token, a no-SCHEDULER env, or a
// DO hiccup must never block the logout itself; the cookie is always cleared and a 200 always returned.
async function handleLogout(req: Request, env: Env, runtime?: AdminRuntime): Promise<Response> {
  // fireInBackground: see handleRecovery's identical helper above.
  // Load-bearing here in particular -- see the G314 comment below.
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  // G118: the logout path was the second CSRF caller that recorded nothing. A csrf-origin-unset here is
  // especially misleading in the field ("I click sign out and nothing happens"), so name the branch. The signal
  // is best-effort and must never block the logout: schedulerStub can THROW synchronously on an unbound env, so
  // the resolve is contained here exactly as the router's own onAuthDeny sink contains it.
  const originFault = originFailClass(req, env.CONSOLE_ORIGIN);
  if (originFault !== null) {
    logAuthFailure("passkey", "cross-origin logout rejected by the Origin check");
    try {
      fireInBackground(recordAuthSignalEdge(schedulerStub(env), originFault));
    } catch {
      /* no DO binding: the 403 still happens, just without its signal */
    }
    return new Response(JSON.stringify({ error: "csrf origin check failed" }), { status: 403, headers: { "content-type": "application/json" } });
  }
  const token = readSessionCookie(req);
  if (token !== null) {
    try {
      const resp = await schedulerStub(env).fetch(doURL("/passkey/session/logout"), {
        method: "POST",
        body: JSON.stringify({ token, sourceIp: req.headers.get("CF-Connecting-IP") }),
        headers: { "content-type": "application/json" },
      });
      // G314: THE ONE THAT MATTERS MOST ON THIS LIST. The cookie is cleared unconditionally (correctly: a
      // logout must always LOOK like it worked), so a revocation that did not land leaves the user believing
      // they are signed out while any STOLEN COPY of that session keeps working until its 12h TTL. The DO
      // answering non-2xx is the same silent failure as the fetch throwing, and neither was recorded anywhere.
      // "Was the stolen session actually revoked at logout?" now has an answer in the pack.
      if (!resp.ok) {
        try {
          fireInBackground(recordAuthSignalEdge(schedulerStub(env), "logout-revoke-failed"));
        } catch {
          /* no DO binding: the logout still happens */
        }
        log("error", `logout session-termination refused (cookie still cleared): status ${resp.status}`);
      }
    } catch (e) {
      try {
        fireInBackground(recordAuthSignalEdge(schedulerStub(env), "logout-revoke-failed"));
      } catch {
        /* no DO binding: the logout still happens */
      }
      log("error", `logout session-termination skipped (cookie still cleared): ${(e as Error).message}`);
    }
  }
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "content-type": "application/json", "set-cookie": sessionClearCookie() },
  });
}


// resolveRegisterAuth runs the REGISTRATION AUTHORISATION (account-takeover fix) for a register/begin or
// register/finish: a register must be authorised by one of three PROVEN paths, never by the client-supplied
// email alone (WebAuthn proves key possession, NOT email ownership). It resolves the proven facts here and
// returns them as authExtras for the DO to forward; the DO decides which path applies and derives the BOUND
// email from the proof, not the client field:
//   1. BOOTSTRAP: a valid ADMIN_TOKEN bearer claims the FIRST Owner (only when the role table is empty,
//      checked atomically in the DO). authorise() returns method:"token" ONLY for a valid ADMIN_TOKEN
//      (its precedence + constant-time compare), so a resolved token verdict IS the operator's proof.
//   2. INVITE: a single-use, email-bound invite token (in the client body as inviteToken) the DO minted
//      when an Owner granted a role to a not-yet-enrolled email; the bound email comes from the invite.
//   3. SELF-ADD: an already-authenticated caller (Access/passkey session/token) adding a credential to
//      THEIR OWN email; the DO refuses unless the proven email equals the registration email.
// We run the SAME authorise() the main gate uses (with the same passkey-session verifier wiring), so the
// proof here cannot diverge from the gate; only its method + verified email are forwarded (never trusted
// as a role). The login ceremonies need none of this and forward nothing extra. A non-null stepUp Response
// short-circuits the caller (the self-add re-auth challenge).
async function resolveRegisterAuth(
  req: Request,
  env: Env,
  scheduler: DurableObjectStub,
  sub: string,
  runtime?: AdminRuntime,
): Promise<{ authExtras: Record<string, unknown>; stepUp: Response | null }> {
  let authExtras: Record<string, unknown> = {};
  const verifyPasskeySession: PasskeySessionVerifier = (token) => verifyPasskeySessionViaDO(scheduler, token);
  // Wire the break-glass-retired resolver here too, so a RETIRED token is no longer a valid bootstrap
  // proof: authorise() returns method:"token" only for a live (non-retired) ADMIN_TOKEN, so a retired
  // token can never re-claim the first Owner via passkey registration (bootstrapConsumed already closes
  // that once a first Owner exists; this also shuts it before any first Owner if the token was retired).
  const breakGlassRetired: BreakGlassRetiredResolver = () => breakGlassRetiredViaDO(scheduler);
  const verdict = await authorise(req, env, verifyPasskeySession, breakGlassRetired);
  // sourceIp is the coarse provenance for the audit events a register ceremony fires (bootstrap-consumed and,
  // on EVERY completed enrolment, recovery-codes-generated). It is read from the edge CF-Connecting-IP header,
  // which is server-supplied: handlePasskey STRIPS any inbound client sourceIp off the body before merging
  // authExtras over it, so a client cannot forge the IP that lands in the trail.
  //
  // IT IS READ OUTSIDE THE verdict.ok FENCE: the INVITE registration path is UNAUTHENTICATED BY DESIGN (an
  // invitee has no session yet: that is the whole point of an invite), so a version that only forwarded the IP
  // when verdict.ok would leave sourceIp null for every completed invite enrolment, an attributed audit entry
  // with a human actor method and NO SOURCE IP, indistinguishable from a proxy stripping the header. Threading
  // the edge IP on every register path makes the audit-source-ip-gap counter mean what its name says: it moves
  // only when the engine had an actor and genuinely could not capture an address.
  const sourceIp = req.headers.get("CF-Connecting-IP");
  if (verdict.ok) {
    // authMethod is the PROVEN method (access | passkey | token); authEmail is the verified email
    // (null for the bare-token break-glass). The DO trusts these FROM THE ROUTER ONLY (built here from
    // the verified verdict, never copied from an inbound client field), the same trust model as the
    // x-downpipe-caller header. bootstrapAuthorised is true only for a valid ADMIN_TOKEN bearer.
    authExtras = {
      authMethod: verdict.method,
      ...(typeof verdict.email === "string" && verdict.email.length > 0 ? { authEmail: canonicalEmail(verdict.email) } : {}),
      bootstrapAuthorised: verdict.method === "token",
    };
  }
  // The IP rides on the authorised AND the unauthenticated (invite) register paths alike. Null (no edge header)
  // is omitted rather than forwarded: an absent address must stay absent, because an engine that genuinely
  // cannot capture one is the fault this evidence is for.
  if (sourceIp !== null && sourceIp.length > 0) authExtras.sourceIp = sourceIp;
  // Step-up (ASVS V7.5.1): SELF-ADD of a passkey (an AUTHENTICATED cookie session adding a NEW credential)
  // requires a FRESH re-auth, so a stale ambient session cannot enrol an attacker-controlled key (account
  // takeover). Bootstrap (token) and invite (unauthenticated, no cookie session) are NOT gated here, and
  // register/begin adds nothing so it is not gated; a recent login (freshness) satisfies it without a prompt.
  if (sub === "register/finish" && verdict.ok && isCookieBorneMethod(verdict.method)) {
    const stepUp = await requireStepUp(req, scheduler, verdict.method, runtime);
    if (stepUp) return { authExtras, stepUp };
  }
  return { authExtras, stepUp: null };
}


// handlePasskey is the engine's OWN passkey (WebAuthn) sign-in front door, reached at /admin/auth/* and
// dispatched BEFORE the authorise() gate (it IS the sign-in flow, so it cannot require a prior
// credential). It is a thin, UNAUTHENTICATED forwarder onto the scheduler DO (the storage + verification
// authority): it resolves the origin (CONSOLE_ORIGIN) and rp.id, forwards the client body plus those two
// server-controlled values to the matching DO route, and returns the DO's JSON. It never trusts a
// client-supplied origin/rp.id (it supplies them itself from env). The sub-paths mirror the WebAuthn
// ceremonies: register/begin, register/finish, login/begin, login/finish, plus the session lifecycle
// endpoint logout. An unknown sub-path is a 404; an unconfigured origin is a 501 (the engine refuses to
// run a ceremony with no origin to bind and check against).
//
// SESSION: on a SUCCESSFUL login/finish OR register/finish (both are completed WebAuthn ceremonies that
// PROVE the credential's bound email), the engine mints a signed, short-TTL session in the DO (which holds
// the signing key) and attaches it as the hardened Set-Cookie (HttpOnly, Secure, SameSite=Strict). The
// subsequent /admin calls present that cookie and authorise as the passkey method. register/finish mints a
// session too so a fresh registrant (including the bootstrap Owner) is signed in without a redundant
// immediate login. logout clears the cookie. These endpoints are NOT subject to the passkey CSRF Origin
// guard (no session exists yet on a finish, and the WebAuthn challenge-binding + clientData origin check is
// their own CSRF protection); logout is a clear-only operation, safe to honour from any origin.
export async function handlePasskey(req: Request, env: Env, sub: string, runtime?: AdminRuntime): Promise<Response> {
  // fireInBackground keeps a diagnostic write alive past the response, the same way ctx.waitUntil
  // already does for every other background write in this codebase (index.ts's sealNow/canaryNow). Every
  // call below fires as the LAST action before its enclosing branch returns, with no further await to give
  // it a scheduling window, so a bare `void` here is not merely theoretically racy on this path. runtime is
  // undefined only for a direct handleAdmin call with no fetch runtime (a unit test), which falls back to the
  // old bare-void behaviour unchanged.
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  if (req.method !== "POST") return new Response("not found", { status: 404 });
  // logout: clear the session cookie and return ok. See handleLogout for the CSRF + server-side termination
  // discipline (MOVED VERBATIM, this is the same code, just named).
  if (sub === "logout") {
    return handleLogout(req, env, runtime);
  }
  // RECOVERY-CODE SIGN-IN (the ongoing admin break-glass), dispatched HERE under /admin/auth/ (BEFORE the
  // main authorise gate, like the passkey ceremonies): a user who lost their passkey presents a recovery
  // code at the sign-in screen and gets a normal signed session. It is UNAUTHENTICATED by necessity (it IS a
  // sign-in path) and HARD rate-limited in the DO (per IP + per email, fail closed) + generic on failure, so
  // an oracle/brute-force gains nothing. See handleRecovery.
  if (sub === "recovery") {
    return handleRecovery(req, env, runtime);
  }
  // REGENERATE recovery codes (self-service), also under /admin/auth/ but AUTHENTICATED inside: it runs the
  // SAME authorise() the main gate uses to identify the caller, then scopes the regeneration to the caller's
  // OWN verified email (a user can only regenerate their own codes, never another's). See handleRegenerate.
  if (sub === "recovery-codes/regenerate") {
    return handleRegenerate(req, env, runtime);
  }
  // CONFIRM a staged recovery-code set (STAGED-RECOVERY-CODES-CONFIRM-GATE), also AUTHENTICATED
  // and scoped to the caller's own email. See handleConfirmStaged.
  if (sub === "recovery-codes/confirm") {
    return handleConfirmStaged(req, env, runtime);
  }
  // The ceremony sub-paths and the DO route each maps to. An unknown sub-path is a 404 BEFORE any body read
  // or DO call, so a probe at an unrelated /admin/auth/* path is a plain 404.
  const routeFor: Record<string, string> = {
    "register/begin": "/passkey/register/begin",
    "register/finish": "/passkey/register/finish",
    "login/begin": "/passkey/login/begin",
    "login/finish": "/passkey/login/finish",
  };
  // bootstrap/send is the one auth sub-path that is NOT a WebAuthn ceremony: it asks the engine to email
  // the FIRST-OWNER set-up link to the deploy-time-pinned owner address (env, never the client body). It
  // keeps the shared per-IP auth rate limit (it can trigger an outbound email, the costliest thing on
  // this surface) and answers the SAME generic 200 for every outcome, so the route is no oracle for the
  // engine's bootstrap state. A non-POST falls through to the ceremony map and stays a plain 404.
  if (sub === "bootstrap/send" && req.method === "POST") {
    const scheduler = schedulerStub(env);
    const limited = await authRateLimited(scheduler, req, runtime);
    if (limited) return limited;
    return sendBootstrapLink(env, scheduler, req, runtime);
  }
  const doPath = routeFor[sub];
  if (doPath === undefined) return new Response("not found", { status: 404 });
  const scheduler = schedulerStub(env);
  // PER-IP RATE LIMIT (V2.4.1, DoS + enumeration): the /admin/auth/* ceremony routes are UNAUTHENTICATED by
  // necessity (they ARE the sign-in flow) and each finish runs heavy crypto (CBOR/COSE parse, signature
  // verify), so an unthrottled flood is a CPU-DoS and an account-enumeration vector. Unlike the per-CALLER
  // limiter on the mutating admin routes (which has a verified identity to key on), here there IS no caller
  // yet, so this one bucket is keyed on the source IP (CF-Connecting-IP). It FAILS OPEN exactly like the
  // per-caller limiter (an unavailable limiter must never lock everyone out of sign-in). It sits AFTER the
  // 404 (so a probe at an unknown sub-path stays a plain 404) and BEFORE the body read + DO ceremony.
  const authLimited = await authRateLimited(scheduler, req, runtime);
  if (authLimited) return authLimited;
  // Resolve the server-controlled origin + rp.id. Fail closed (501) when CONSOLE_ORIGIN is not set, so a
  // ceremony never runs without a known origin to bind the credential to and check the clientData origin
  // against. The reason is coarse and carries no secret.
  const oc = passkeyOriginAndRpId(env);
  if (oc === null) {
    // OBSERVE (G115): CONSOLE_ORIGIN is unset or unparseable, so EVERY passkey ceremony 501s and nobody can enrol
    // or sign in. This is a deploy-configuration fault that reads to the user as "sign-in is broken", and until
    // now the pack carried no trace of it at all.
    fireInBackground(recordAuthSignalEdge(scheduler, "passkey-not-configured"));
    return new Response(JSON.stringify({ ok: false, reason: "passkey_not_configured" }), { status: 501, headers: { "content-type": "application/json" } });
  }
  // Read the client body (the {email}/{credential} the SPA sent). A malformed JSON body throws here and
  // is caught by the index.ts last-resort handler as a 500, matching every other route's req.json()
  // discipline; the passkey-specific faults (bad challenge/origin/signature) are returned by the DO as a
  // coarse { ok:false, reason } 200-bodied result, distinct from a transport/parse 500.
  const body = (await req.json()) as Record<string, unknown>;
  // REGISTRATION AUTHORISATION (account-takeover fix): a register/begin or register/finish must be
  // authorised by one of three PROVEN paths (bootstrap / invite / self-add), never by the client-supplied
  // email alone (WebAuthn proves key possession, NOT email ownership). resolveRegisterAuth runs the SAME
  // authorise() the main gate uses and returns the proven auth facts (forwarded below) plus any self-add
  // step-up challenge; the login ceremonies need none of this and forward nothing extra.
  const isRegister = sub === "register/begin" || sub === "register/finish";
  let authExtras: Record<string, unknown> = {};
  if (isRegister) {
    // Resolve the proven registration auth facts (authExtras for the DO) and any step-up challenge. MOVED
    // VERBATIM into resolveRegisterAuth; a returned stepUp short-circuits exactly as the inline block did.
    const resolved = await resolveRegisterAuth(req, env, scheduler, sub, runtime);
    if (resolved.stepUp) return resolved.stepUp;
    authExtras = resolved.authExtras;
  }
  // Forward the client fields PLUS the server-supplied rp.id and origin and the proven auth facts. The DO
  // never trusts a client-supplied rpId/origin/authMethod/authEmail/bootstrapAuthorised: we STRIP any such
  // keys off the inbound body first (so a forged authMethod:"token"/bootstrapAuthorised:true can never
  // reach the DO), overwrite rp.id/origin from env, and SET the auth facts ONLY from the verified verdict.
  // inviteToken is a legitimate client field (the one-shot capability the DO re-validates), so it is kept.
  const { rpId: _ci, origin: _co, authMethod: _cm, authEmail: _ce, bootstrapAuthorised: _cb, sourceIp: _cs, ...clientBody } = body;
  void _ci; void _co; void _cm; void _ce; void _cb; void _cs;
  const forward = { ...clientBody, rpId: oc.rpId, origin: oc.origin, ...authExtras };
  const resp = await scheduler.fetch(doURL(doPath), {
    method: "POST",
    body: JSON.stringify(forward),
    headers: { "content-type": "application/json" },
  });
  // The DO returns a JSON result. For the two FINISH ceremonies, read the body and, on a verified success
  // ({ ok:true } carrying the proven email), mint a session and attach the Set-Cookie. The body is then
  // returned verbatim with the same status, so the client still sees the ceremony outcome (email + bootstrap
  // facts) AND receives the session cookie. A begin route, or a finish that did NOT verify ({ ok:false }),
  // sets no cookie: only a proven WebAuthn ceremony issues a session.
  const isFinish = sub === "login/finish" || sub === "register/finish";
  const ceremony: PasskeyCeremony = isRegister ? "register" : "login";
  if (isFinish) {
    const text = await resp.text();
    const setCookie = await sessionCookieForFinish(env, scheduler, text);
    // OBSERVE (G115 / G124): count the ceremony OUTCOME in the bounded auth-signal aggregate, so a lockout is
    // visible in the pack instead of only in Workers Logs. recordPasskeyOutcome allowlists the DO's coarse reason
    // against the closed PasskeyReason set, so no free text can ever become a stored key, and it distinguishes the
    // cruellest failure of all: a ceremony that VERIFIED but whose session could not be minted (the user proved
    // possession of their key and still cannot get in). The client response is unchanged.
    fireInBackground(recordPasskeyOutcome(scheduler, ceremony, text, setCookie !== null));
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (setCookie !== null) headers["set-cookie"] = setCookie;
    // R6 (V6.3.5): a PROVEN passkey login (a session was just minted) runs the opt-in coarse-context
    // check, the passkey twin of the OIDC/SAML in-DO checks. FIRE-AND-FORGET after the response is
    // fully determined, so the check and the notify can never delay or fail a sign-in. The proven email
    // is parsed from the DO's own finish body (never the client's), the source IP is the edge header the
    // DO uses only in-memory for the coarse prefix, and the alert itself carries no identity or location.
    if (sub === "login/finish" && setCookie !== null) {
      fireInBackground(
        fireSignInContextCheck(env, scheduler, text, req.headers.get("CF-Connecting-IP")).catch((e: unknown) => {
          log("error", `sign-in-context check skipped (sign-in unaffected): ${(e as Error).message}`);
        }),
      );
    }
    return new Response(text, { status: resp.status, headers });
  }
  // A begin route (or any non-finish): forward the DO body verbatim. A DO-side { ok:false, reason, errorId }
  // is a coarse client reason plus an opaque correlation id; a { ok:true, ... } carries the creation/request
  // options. The status stays the DO's (200 for a verification verdict). OBSERVE (G124): a BEGIN that refuses is
  // its own lockout class (a spent/absent invite, a forbidden enrolment, a challenge store that cannot write), so
  // the body is read here and counted before being forwarded verbatim - the client sees byte-identical JSON.
  const beginText = await resp.text();
  fireInBackground(recordPasskeyOutcome(scheduler, ceremony, beginText, false));
  return new Response(beginText, { status: resp.status, headers: { "content-type": "application/json" } });
}

// recordPasskeyOutcome counts a passkey ceremony outcome as a CLOSED auth-signal (G115 / G124). It parses the DO's
// own ceremony body (never the client's) and records nothing at all on success - except the one case that MUST be
// recorded on an otherwise-successful ceremony: `ok:true` with NO session cookie minted, i.e. the WebAuthn
// ceremony verified and the user still cannot get in (passkey-session-mint-failed).
//
// Redaction: the DO's `reason` is allowlisted through passkeySignalName against the closed PasskeyReason set, so a
// non-member (or any free text a future DO might return) can only ever land in the residual per-ceremony bucket -
// an email, credential id, origin or rpId can never be interpolated into a storage key. An unparseable body is
// simply not counted (it is not evidence of a ceremony failure). Best-effort: never throws, never delays the
// response, and the ceremony result the caller sees is untouched.
async function recordPasskeyOutcome(scheduler: DurableObjectStub, ceremony: PasskeyCeremony, body: string, sessionMinted: boolean): Promise<void> {
  let parsed: { ok?: unknown; reason?: unknown };
  try {
    parsed = JSON.parse(body) as { ok?: unknown; reason?: unknown };
  } catch {
    return; // not a ceremony verdict we can classify; record nothing rather than guess
  }
  if (parsed.ok === true) {
    // A verified ceremony that produced no session is an ENGINE-side fault, not a user error. Only meaningful on
    // a finish (a begin never mints a session), which is why the caller passes sessionMinted=false for a begin
    // and we gate on the presence of a proven email in the body.
    if (!sessionMinted && typeof (parsed as { email?: unknown }).email === "string") {
      await recordAuthSignalEdge(scheduler, "passkey-session-mint-failed");
    }
    return;
  }
  if (parsed.ok === false) await recordAuthSignalEdge(scheduler, passkeySignalName(ceremony, parsed.reason));
}


// sessionCookieForFinish mints the session Set-Cookie header value for a SUCCESSFUL finish ceremony, or
// null when the ceremony did not verify (so no session is issued). It parses the DO's finish body; only a
// { ok:true } carrying a non-empty string email triggers a mint. The email is the one the WebAuthn assertion
// (login) or attestation (register) just PROVED and the DO already normalised; it is handed to the DO's
// session issuer (which holds the signing key and re-normalises it), and the returned token is wrapped in
// the hardened cookie. Any shape surprise, a non-ok body, or a mint failure yields null (the finish still
// returns its body; the user simply did not get a session and would retry login). It NEVER throws (a
// JSON.parse or DO hiccup is caught), so the finish response is always returned.
export async function sessionCookieForFinish(_env: Env, scheduler: DurableObjectStub, finishBodyText: string): Promise<string | null> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(finishBodyText);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const o = parsed as Record<string, unknown>;
  if (o.ok !== true) return null; // a failed/!verified ceremony issues no session
  const email = o.email;
  if (typeof email !== "string" || email.length === 0) return null;
  try {
    const resp = await scheduler.fetch(doURL("/passkey/session/issue"), {
      method: "POST",
      body: JSON.stringify({ email }),
      headers: { "content-type": "application/json" },
    });
    const issued = (await resp.json()) as { ok?: boolean; token?: string };
    if (issued.ok !== true || typeof issued.token !== "string" || issued.token.length === 0) return null;
    return sessionSetCookie(issued.token);
  } catch (e) {
    log("error", `passkey session mint skipped (non-critical, login still returned): ${(e as Error).message}`);
    return null;
  }
}


// fireSignInContextCheck runs the R6 coarse-context check for a PROVEN passkey login: parse the proven
// email off the DO's finish body, ask the DO to record the context (POST /signin-context; a policy-gated
// no-op by default that never stores the raw IP), and fire the redaction-safe notify when the DO says the
// context is materially new. Best-effort end to end (the caller fire-and-forgets); a parse or DO hiccup
// simply skips the check.
export async function fireSignInContextCheck(env: Env, scheduler: DurableObjectStub, finishBodyText: string, sourceIp: string | null): Promise<void> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(finishBodyText);
  } catch {
    return;
  }
  if (parsed === null || typeof parsed !== "object") return;
  const email = (parsed as Record<string, unknown>).email;
  if (typeof email !== "string" || email.length === 0) return;
  const resp = await scheduler.fetch(doURL("/signin-context"), {
    method: "POST",
    body: JSON.stringify({ email, ...(sourceIp !== null ? { sourceIp } : {}) }),
    headers: { "content-type": "application/json" },
  });
  const verdict = (await resp.json()) as { newContext?: boolean };
  if (verdict.newContext === true) await routeSignInContextAlert(env, scheduler);
}

// BOOTSTRAP_SUBJECT is fixed, content-free copy (who/where rides only in the body and its link).
export const BOOTSTRAP_SUBJECT = "Set up the first Owner of your Downpipes engine";


// sendBootstrapLink handles POST /admin/auth/bootstrap/send: best-effort email the FIRST-OWNER set-up
// link to the deploy-time-pinned BOOTSTRAP_OWNER_EMAIL. NO ORACLE (sacred): every outcome (unconfigured,
// already bootstrapped, cross-origin, mint refused, send failed) answers the SAME generic 200 { ok:true },
// so an anonymous caller cannot learn the engine's bootstrap state, its configuration, or the pinned
// address by probing this route. The real outcome is observable only by the inbox owner (the email
// arrives) and the operator (a coarse console.error reason in the tail; NEVER the token, link or address).
//
// Pressing the button is NOT a grant. The capability is the emailed link, and it goes ONLY to the
// env-pinned address (the client body is ignored entirely), so the trust chain is: control of the
// Cloudflare account (set the var at deploy) -> control of that inbox -> first Owner. Cross-site browser
// abuse is bounded by the shared per-IP auth limiter and refused outright when an Origin header is present
// and differs from CONSOLE_ORIGIN (tooling without an Origin header passes); abuse therefore degrades to,
// at most, re-mailing the rightful owner their own link (which also REPLACES the previous one, never
// multiplying live links).
export async function sendBootstrapLink(env: Env, scheduler: DurableObjectStub, req: Request, runtime?: AdminRuntime): Promise<Response> {
  // fireInBackground: see handleRecovery's identical helper above.
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  const generic = (): Response =>
    new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  const skip = (reason: string): Response => {
    // Coarse, operator-facing reason only (wrangler tail debuggability); no token, link, or address.
    log("error", `bootstrap-link send skipped (no-oracle 200 returned): ${reason}`);
    // G117: "the first-Owner set-up email never arrives" is the most common bootstrap ticket, and this route
    // answers a NO-ORACLE 200 on every skip reason BY DESIGN (an anonymous presser must not learn whether an
    // Owner exists). That is kept exactly as it is -- the response below is unchanged -- but the reason is now
    // also RECORDED as a closed signal, so support can finally tell "no EMAIL binding" from "the bootstrap path
    // is closed because an Owner already exists" from "the DO mint faulted". Best-effort; never the address or
    // the link. Previously this reason existed only in a Workers Logs line the vendor structurally cannot read.
    fireInBackground(recordAuthSignalEdge(scheduler, bootstrapEmailSignalName(reason)));
    return generic();
  };
  // CSRF shaping: a browser fetch always carries Origin; when present it must match the console origin.
  const consoleOrigin = env.CONSOLE_ORIGIN?.trim() || "";
  if (consoleOrigin === "") return skip("console-origin-unset");
  const reqOrigin = req.headers.get("origin");
  if (reqOrigin !== null && reqOrigin !== consoleOrigin) return skip("origin-mismatch");
  const ownerV = isCustomDomainAddress(env.BOOTSTRAP_OWNER_EMAIL);
  if (!ownerV.ok) return skip("owner-email-not-configured");
  const binding = env.EMAIL;
  if (!binding || typeof binding.send !== "function") return skip("email-not-configured");
  // Sender: the dedicated invite sender when configured, else the general notification sender. The
  // bootstrap email IS an invite (the first one), so the invite sender is the natural fit, but requiring
  // a third sender var would only add first-run friction, which is the thing this route removes.
  const fromRaw = typeof env.INVITE_EMAIL_FROM === "string" && env.INVITE_EMAIL_FROM.trim().length > 0 ? env.INVITE_EMAIL_FROM : env.EMAIL_FROM;
  const fromV = isCustomDomainAddress(fromRaw);
  if (!fromV.ok) return skip("from-not-configured");
  // Mint (or REPLACE) the single first-Owner invite. The DO enforces the empty-table + unconsumed-latch
  // preconditions atomically; a null token means the path is closed (an Owner exists or once existed).
  let token: string | null = null;
  try {
    const resp = await scheduler.fetch(doURL("/passkey/bootstrap/mint"), {
      method: "POST",
      body: JSON.stringify({ email: ownerV.address }),
      headers: { "content-type": "application/json" },
    });
    const j = (await resp.json()) as { token?: unknown };
    token = typeof j.token === "string" && j.token.length > 0 ? j.token : null;
  } catch {
    return skip("mint-failed");
  }
  if (token === null) return skip("not-available");
  // The token rides in the FRAGMENT (the same discipline as the role-invite link) so it stays out of
  // server access logs; the SPA reads it client-side and threads it to register/begin + register/finish.
  const link = `${consoleOrigin}/#/register?invite=${encodeURIComponent(token)}`;
  const text = [
    `This Downpipes engine has no Owner yet. The link below sets up its FIRST Owner, bound to this address (${ownerV.address}):`,
    "",
    link,
    "",
    "Opening it asks this device for a passkey; completing that makes you the Owner and issues your recovery codes. The link works once, only for this address, and only while the engine still has no Owner; it expires in 24 hours, and requesting a new link replaces it.",
    "If you did not expect this email, you can ignore it. The link is only ever sent to the owner address pinned at deploy time, and pressing the button that sent it grants nothing to the presser.",
  ].join("\n");
  // The branded HTML twin carries the same sentences and the set-up link as a button; the raw link stays
  // in the text part above. ownerV.address is escaped by the renderer. No vendor sign-off (engine mail).
  const html = renderEngineEmailHtml({
    subject: BOOTSTRAP_SUBJECT,
    heading: "Set up the first Owner",
    paragraphs: [
      `This Downpipes engine has no Owner yet. The link below sets up its first Owner, bound to this address (${ownerV.address}).`,
      "Opening it asks this device for a passkey; completing that makes you the Owner and issues your recovery codes. The link works once, only for this address, and only while the engine still has no Owner; it expires in 24 hours, and requesting a new link replaces it.",
      "If you did not expect this email, you can ignore it. The link is only ever sent to the owner address pinned at deploy time, and pressing the button that sent it grants nothing to the presser.",
    ],
    cta: { label: "Set up the first Owner", url: link },
  });
  try {
    // Only the validated sender, the single pinned recipient, and this fixed-template body (the text and
    // its branded HTML twin) cross to the binding; there is no header, attachment or raw field besides.
    await binding.send({ to: ownerV.address, from: fromV.address, subject: BOOTSTRAP_SUBJECT, text, html });
  } catch (e) {
    // Fail-open + no oracle: a rejected send (e.g. sender domain not onboarded, or the recipient not a
    // verified destination during the Email Sending beta) logs a coarse reason only, never the link.
    log("error", `bootstrap-link send failed (no-oracle 200 returned): ${(e as Error).message}`);
    // G117: the PROVIDER rejected a correctly-configured send. This is the diagnosis that most often ends the
    // ticket ("your sender domain is not onboarded"), and it was the one branch that reached neither the pack
    // nor the operator. The provider's message is READ only by the log line above and is never recorded.
    fireInBackground(recordAuthSignalEdge(scheduler, bootstrapEmailSignalName("send-rejected")));
    return generic();
  }
  return generic();
}
