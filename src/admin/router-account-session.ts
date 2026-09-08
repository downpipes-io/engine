// router-account-session.ts -- the authenticated account self-service routes: passkey-credential
// listing/revocation, session termination (others / a user / all), and the step-up re-auth begin/finish
// ceremony. The hub already ran authorise(); per-route checks stay inline.


import { type Caller, isCookieBorneMethod } from "./identity.ts";
import { callerHeaders, rateLimited } from "./router-core.ts";
import { type AdminRuntime, doURL, type RouterCtx, recordAuthSignalEdge, recordAuthzRefusalEdge } from "./router-helpers.ts";
import { routeAuthChangeAlert } from "./router-notify.ts";
import { passkeyOriginAndRpId } from "./router-session.ts";
import { csrfDoubleSubmitFailClass, readSessionCookie, sessionSetCookie } from "./session.ts";

// csrfBlock is the SERVER-SIDE double-submit CSRF gate for the session-termination routes (ML-02). It is
// DEFENCE IN DEPTH on top of the strict-Origin guard the hub already enforces for every cookie-borne
// mutating request (§2.3a), never a replacement: a cookie-borne caller (passkey/oidc/saml) whose request
// lacks a matching x-downpipes-csrf header + __Host-downpipes_csrf cookie pair is refused 403 BEFORE any
// rate-limit or DO work. The token/access methods present an explicit header a foreign page cannot set
// cross-origin, so they carry no ambient-cookie CSRF exposure and are exempt (exactly as the Origin guard
// exempts them). Returns the 403 Response to short-circuit, or null to proceed.
//
// G118: the refusal is RECORDED as its closed sub-class (header missing / cookie missing / value mismatch).
// Those are three different tickets -- a console that never read whoami, a browser that blocked or partitioned
// the cookie, and a genuine cross-site attempt -- and the pack previously carried none of them at all, so
// "terminate-sessions always 403s" had no evidence anywhere. Best-effort and fire-and-forget: the 403 is already
// decided and is returned unchanged, and neither the header nor the cookie VALUE ever rides.
function csrfBlock(caller: Caller, req: Request, scheduler: DurableObjectStub, runtime?: AdminRuntime): Response | null {
  if (!isCookieBorneMethod(caller.method)) return null;
  const fault = csrfDoubleSubmitFailClass(req);
  if (fault === null) return null;
  // Both signals below fired as the last action before this function's
  // caller immediately returns the 403, with no intervening await -- the same shape proven lost for the
  // passkey ceremony signal. runtime.waitUntil is available whenever a real RouterCtx called in (every live
  // request); falls back to bare fire-and-forget only for a direct csrfBlock call with none (a unit test).
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  fireInBackground(recordAuthSignalEdge(scheduler, fault));
  // G314: the sub-class above says HOW the double-submit check failed; this says WHICH SURFACE was hit. The
  // SESSION-LIFECYCLE routes (logout, terminate-all) are the ones an attacker wants to reach cross-site, and
  // a post-incident review asks about them specifically. Without a surface-scoped name, a stale console tab
  // failing its token check on a settings save and a cross-site attempt against terminate-all are the same
  // three counters. Both are recorded: they answer different questions.
  fireInBackground(recordAuthSignalEdge(scheduler, "csrf-session-route"));
  return new Response(JSON.stringify({ error: "csrf token check failed" }), { status: 403, headers: { "content-type": "application/json" } });
}

// handleAccountSession dispatches the passkey/session/step-up group. Returns the route's Response, or null
// when no case here matched (the hub falls to the next spoke).
export async function handleAccountSession(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, url, scheduler, caller, sub, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- passkey credential management + session termination (authenticated) -------------
    case "GET /passkey/credentials": {
      // List enrolled passkeys: own (any authenticated role) or another member's (gated to roles.write
      // INSIDE the DO, which re-resolves authority). The caller is forwarded; the redacted view never
      // carries key material.
      const email = url.searchParams.get("email");
      return scheduler.fetch(doURL(`/passkey/credentials${email ? `?email=${encodeURIComponent(email)}` : ""}`), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /passkey/credentials/all": {
      // ACCOUNT-WIDE enumeration (roles.write, re-resolved INSIDE the DO). The route above takes an email and
      // falls back to the caller's own, so no read in this engine could establish that an account holds no
      // leftover credentials: you had to know which email to ask about, and a credential whose member was
      // deleted is precisely the one nobody thinks to ask about. deleteRole does not touch `passkeyCred:`
      // records, so that residue can accumulate over time.
      //
      // It reports and does not delete, and the per-row fact is `hasRoleEntry`, not `orphaned`. An email can
      // hold a role through an IdP GROUP CLAIM with no row in the role table at all (groupRoleFor), so a
      // legitimate operator reads false here. Naming the field for what was measured rather than for the
      // conclusion someone wants to draw is the whole point: a teardown script may sweep on it, a human may
      // judge it, and nothing is destroyed on an inference.
      return scheduler.fetch(doURL("/passkey/credentials/all"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /signin-factors": {
      // THE UNION READ. The credential route above answers "which credentials exist", and a credential is the
      // HARDEST of the three ways into this account, because it needs the physical authenticator. The other
      // two are bearer secrets and neither is reachable from an offboard: `recovery:<email>` is untouched by
      // deleteRole, and `passkeyInvite:<token>` is keyed by TOKEN, so an email-keyed delete cannot reach it
      // even in principle. Both mint a session and both lead to enrolling a FRESH credential. So an account
      // could read "no credentials" while holding two live ways in for the same person.
      //
      // `?email=` scopes to one member (self needs only authentication, anyone else needs roles.write);
      // omitting it reads the WHOLE ACCOUNT under roles.write, with no fallback to the caller's own email. The
      // absent fallback is the point: that fallback is what made the credential route answer `200 []` to every
      // bearer-token sweep. An `?email=` that is present and unusable is refused with a 400 rather than
      // widened or narrowed, and a NAMED email always comes back as a row, so "no rows" never has to stand in
      // for "this person has nothing".
      const email = url.searchParams.get("email");
      return scheduler.fetch(doURL(`/signin-factors${email === null ? "" : `?email=${encodeURIComponent(email)}`}`), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /passkey/credentials/delete": {
      // Revoke a WebAuthn credential (theft/loss, V6.5.6). Self-revoke needs only an authenticated
      // caller; revoking another's is gated to roles.write (an Owner's only by an Owner) in the DO. The
      // DO bumps the member's session epoch so sessions predating the revoke die.
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { credentialId?: string };
      const revResp = await scheduler.fetch(doURL("/passkey/credentials/delete"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      const revText = await revResp.text();
      // V6.3.7: a passkey credential revocation is a TAKEOVER signal (a sign-in factor was removed). Notify on
      // a successful removal ({ deleted:true }); the DO audits it too. Redaction-safe (no credential value).
      if (revResp.status === 200) {
        let removed = false;
        try {
          removed = (JSON.parse(revText) as { deleted?: boolean }).deleted === true;
        } catch {
          removed = false;
        }
        if (removed) {
          // Fires as the last action before the immediate return below, no intervening
          // await. runtime.waitUntil is available here via RouterCtx.
          const w = routeAuthChangeAlert(env, scheduler, "auth-credential-change", "credential-change", `A passkey credential was revoked${caller.email ? ` by ${caller.email}` : ""}.`);
          if (runtime?.waitUntil) runtime.waitUntil(w);
          else void w;
        }
      }
      return new Response(revText, { status: revResp.status, headers: { "content-type": "application/json" } });
    }
    case "POST /signin-factors/revoke": {
      // THE OFFBOARDING WRITE. The route above removes ONE credential; this removes every way the named person
      // can authenticate, across all three stores at once. It exists because two of those stores had no delete
      // anywhere in the engine, so a role row could be deleted while a live invite and banked recovery codes
      // both survived and both led straight back to a fresh credential.
      //
      // CSRF-GATED like the session-lifecycle routes, not like the credential route. It is defence in depth on
      // top of the hub's strict-Origin guard, and it belongs here on the same reasoning that put it on
      // terminate-all: this route destroys authentication factors AND signs the target out, so it is exactly
      // the shape an attacker would want to reach from a foreign page with an admin's ambient cookie.
      const csrf = csrfBlock(caller, req, scheduler, runtime);
      if (csrf) return csrf;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { email?: unknown };
      const revokeResp = await scheduler.fetch(doURL("/signin-factors/revoke"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      const revokeText = await revokeResp.text();
      // V6.3.7 takeover signal, on the SAME condition the DO audits and bumps the epoch on: a way in was really
      // closed. A revoke that found nothing, or swept only expired residue, is not a credential change and must
      // not raise one. Redaction-safe: the notification names the actor, never the target's secrets.
      if (revokeResp.status === 200) {
        let closed = false;
        try {
          const parsed = JSON.parse(revokeText) as { sessionsTerminated?: boolean };
          closed = parsed.sessionsTerminated === true;
        } catch {
          closed = false;
        }
        if (closed) {
          const w = routeAuthChangeAlert(env, scheduler, "auth-credential-change", "credential-change", `Every sign-in factor was revoked for a member${caller.email ? ` by ${caller.email}` : ""}.`);
          if (runtime?.waitUntil) runtime.waitUntil(w);
          else void w;
        }
      }
      return new Response(revokeText, { status: revokeResp.status, headers: { "content-type": "application/json" } });
    }
    case "POST /sessions/terminate-others": {
      // Self-service "terminate my OTHER sessions" (V7.5.2): the DO bumps the caller's epoch (killing
      // every other session for their email) and returns a fresh token; the router re-issues the cookie
      // so THIS session stays alive. A caller with no first-party email (bare token) is refused by the DO.
      // The raw cookie is forwarded (the SAME one authorise() already verified for this request) so the DO
      // can recover its ORIGINAL iat/exp and re-mint as a SLIDE, not a fresh login: this is a housekeeping
      // action, never an authentication event, and must not reset the step-up freshness clock or the
      // absolute 12h cap (ASVS V7.3 / V7.5.1).
      const csrf = csrfBlock(caller, req, scheduler, runtime);
      if (csrf) return csrf;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const resp = await scheduler.fetch(doURL("/passkey/session/terminate-others"), { method: "POST", body: JSON.stringify({ token: readSessionCookie(req) }), headers: callerHeaders(caller) });
      const out = (await resp.json()) as { ok?: boolean; token?: string };
      if (!out.ok || !out.token) {
        // G175: THE THIRD GUARD, AND THE ONE THE DO CAN NEVER SEE. This 400 is decided HERE, in the router, so it
        // never enters the DO's AuthError funnel and no ledger row for it could previously exist on either side.
        // On the console it landed as {admin-write, access-security, terminate-other-sessions, refused-validation},
        // byte-identical to a shape refusal.
        //
        // NOISE DISCIPLINE IS THE WHOLE DESIGN OF THIS ARM, and it is why the gate is not recorded unconditionally.
        // For a BARE-TOKEN or Access caller this refusal is a LEGITIMATE STATE, not a fault: that caller holds no
        // first-party session, the screen says so in as many words, and the engine is correct to refuse. Recording
        // it would fabricate a guaranteed phantom refusal on every token-auth console -- a signal that cries wolf.
        //
        // It is a GENUINE FAULT only for a COOKIE-BORNE caller (passkey / OIDC / SAML): that caller demonstrably
        // HAS a first-party session -- authorise() just verified the cookie on this very request -- and the engine
        // still found none to manage. That is broken session or epoch state, and it is the state an operator hits
        // when "sign out my other sessions" silently does nothing during a suspected compromise.
        if (isCookieBorneMethod(caller.method)) {
          // Fires as the last action before the immediate return below, no intervening
          // await -- and this is the "sign out my other sessions silently did nothing during a suspected
          // compromise" signal per the comment above.
          const w = recordAuthzRefusalEdge(scheduler, "first-party-session-required");
          if (runtime?.waitUntil) runtime.waitUntil(w);
          else void w;
        }
        return new Response(JSON.stringify({ error: "no first-party session to manage on this auth method" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // Re-issue the caller's cookie carrying the new epoch so they are not signed out of the current tab.
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "set-cookie": sessionSetCookie(out.token) } });
    }
    case "POST /sessions/terminate-user": {
      // Admin "terminate THIS user's sessions" (V7.4.5): gated to roles.write (the DO re-resolves and
      // owner-guards). Forward the target email + the caller.
      const csrf = csrfBlock(caller, req, scheduler, runtime);
      if (csrf) return csrf;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { email?: string };
      return scheduler.fetch(doURL("/passkey/session/terminate-user"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
    }
    // STEP-UP re-auth (ASVS V7.5.1/V7.5.3). begin issues a fresh WebAuthn assertion challenge for the caller's
    // OWN passkeys; finish verifies it and mints a single-use step-up token the console presents on the retry
    // of a sensitive action. Any authenticated caller may step up their own session (no capability gate); the
    // rpId/origin are server-resolved from CONSOLE_ORIGIN (the DO holds no env). A caller with no passkey gets
    // ok:false and re-authenticates instead (the freshness path).
    case "POST /stepup/begin": {
      const oc = passkeyOriginAndRpId(env);
      if (oc === null) {
        // Fired as the LAST action before return, same shape proven lost for the passkey ceremony
        // signal. runtime.waitUntil is available here (RouterCtx carries it); fall back to bare fire-and-
        // forget only when it is not (a direct handleAccountSession call with no fetch runtime, a test).
        const w = recordAuthSignalEdge(scheduler, "passkey-not-configured"); // G115: no CONSOLE_ORIGIN -> every step-up 501s
        if (runtime?.waitUntil) runtime.waitUntil(w);
        else void w;
        return new Response(JSON.stringify({ error: "passkey_not_configured" }), { status: 501, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/stepup/begin"), { method: "POST", body: JSON.stringify({ rpId: oc.rpId }), headers: callerHeaders(caller) });
    }
    case "POST /stepup/finish": {
      const oc = passkeyOriginAndRpId(env);
      if (oc === null) {
        // Same shape as stepup/begin above.
        const w = recordAuthSignalEdge(scheduler, "passkey-not-configured");
        if (runtime?.waitUntil) runtime.waitUntil(w);
        else void w;
        return new Response(JSON.stringify({ error: "passkey_not_configured" }), { status: 501, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const fb = (await req.json()) as { challengeId?: unknown; credential?: unknown };
      const sresp = await scheduler.fetch(doURL("/stepup/finish"), { method: "POST", body: JSON.stringify({ challengeId: fb.challengeId, credential: fb.credential, rpId: oc.rpId, origin: oc.origin }), headers: callerHeaders(caller) });
      // OBSERVE (G014 / G115): "the console keeps refusing my sensitive action". A failed step-up left no trace
      // anywhere, so support could not tell a broken step-up from a user who never attempted one. The DO body is
      // read and counted as ONE closed class (the finer WebAuthn reason is already counted on the login ceremony
      // that shares the same verify path), then forwarded VERBATIM with its original status - the caller sees
      // byte-identical JSON. Best-effort; a parse fault records nothing.
      const stext = await sresp.text();
      try {
        if ((JSON.parse(stext) as { ok?: unknown }).ok === false) {
          // Fires as the last action before the immediate return below, no intervening await.
          const w = recordAuthSignalEdge(scheduler, "stepup-failed");
          if (runtime?.waitUntil) runtime.waitUntil(w);
          else void w;
        }
      } catch {
        /* not a classifiable verdict: record nothing rather than guess */
      }
      return new Response(stext, { status: sresp.status, headers: { "content-type": "application/json" } });
    }
    case "POST /sessions/terminate-all": {
      // Owner-only "terminate ALL sessions" (V7.4.5, all-users): the DO rotates the session signing key.
      const csrf = csrfBlock(caller, req, scheduler, runtime);
      if (csrf) return csrf;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/passkey/session/terminate-all"), { method: "POST", headers: callerHeaders(caller) });
    }
    default:
      return null;
  }
}
