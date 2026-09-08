// The IDENTITY-and-AUTH half of the SchedulerDO's RPC dispatch (the route() dispatcher, sub-mixin 4 of
// 4). This sub-mixin owns the per-subsystem sub-dispatch methods for the engine's own WebAuthn/passkey
// IdP (register/login, bootstrap mint, the signed session lifecycle and credential/session
// management), the step-up re-auth ceremony, the native external IdP (OIDC + SAML) connection custody
// and sign-in flows, and the recovery-code break-glass. Each method is a switch over the SAME
// `${method} ${pathname}` key that returns the handler Response for a key it owns or null ("not my
// route"); route() (in scheduler-do-routing.ts) chains these among the other sub-dispatches. This
// sub-mixin's `this` is SchedulerDOSurface (like every sibling mixin), so each sub-dispatch calls the
// owning handler (this.passkeyRegisterBegin / this.idpOidcCallback / this.recoveryRecover / ...) with
// the SAME dispatch and `this` binding.

import { AUTH_SIGNAL_NAME_SET } from "../admin/auth-signals.ts";
import { CALLER_HEADER, decodeCaller, passkeySubject, type AuthMethod } from "../admin/identity.ts";
import { recordCeremonyFault, recordContractFault } from "./sched-fault-ledger.ts";
import type { SchedulerDOCtor } from "./scheduler-do-base.ts";

export function RoutingIdentityMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // WebAuthn / passkey: the engine's own IdP (register/login), bootstrap mint, sessions, and credential mgmt.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routePasskey(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /passkey/register/begin":
        return this.json(await this.passkeyRegisterBegin((await req.json()) as { email?: unknown; displayName?: unknown; rpId?: unknown; inviteToken?: unknown; authMethod?: unknown; authEmail?: unknown; bootstrapAuthorised?: unknown }));
      case "POST /passkey/register/finish":
        return this.json(await this.passkeyRegisterFinish((await req.json()) as { email?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown; displayName?: unknown; inviteToken?: unknown; authMethod?: unknown; authEmail?: unknown; bootstrapAuthorised?: unknown; sourceIp?: unknown }));
      // FIRST-OWNER bootstrap-link mint (INTERNAL: reached only by the router's own scheduler.fetch, like
      // /passkey/session/issue). The router supplies the deploy-time-pinned owner email FROM ENV (never a
      // client field); the DO enforces the empty-table + unconsumed-latch preconditions atomically and
      // returns { token } or { token: null } when the path is closed. The router emails the link; the DO
      // never sees an address it did not bind.
      case "POST /passkey/bootstrap/mint": {
        const b = (await req.json()) as { email?: unknown };
        return this.json({ token: await this.mintBootstrapInvite(b.email, Date.now()) });
      }
      case "POST /signin-context": {
        // R6 (V6.3.5): the PASSKEY sign-in's coarse-context check. The router calls this AFTER a proven
        // login/finish minted a session (the OIDC/SAML paths run the same check inside their own DO success
        // blocks, where the subject is already in hand). The body carries the PROVEN email (never trusted
        // for auth here; it only keys the seen-set via the same passkeySubject the session mint uses) and
        // the edge-read source IP, used in-memory only to derive the coarse prefix (never stored). Returns
        // { newContext } so the router can fire the redaction-safe sign-in-new-context notify. INTERNAL
        // (reached only by the router's own scheduler.fetch, like every route here).
        const scBody = (await req.json()) as { email?: unknown; sourceIp?: unknown };
        const scEmail = this.normaliseEmail(scBody.email);
        if (!scEmail) return this.json({ newContext: false });
        const scIp = typeof scBody.sourceIp === "string" ? scBody.sourceIp : null;
        return this.json({ newContext: await this.recordSignInContext(passkeySubject(scEmail), scIp) });
      }
      case "POST /passkey/login/begin":
        return this.json(await this.passkeyLoginBegin((await req.json()) as { email?: unknown; rpId?: unknown }));
      case "POST /passkey/login/finish": {
        const finRes = await this.passkeyLoginFinish((await req.json()) as { challengeId?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown });
        // V16.3.1: a FAILED passkey login otherwise leaves NO record at all (it returns a 200 {ok:false}).
        // Append a tamper-evident authn-failure event so a brute-force / credential-stuffing sweep is visible to
        // a reviewer reading the chain. No identity is verified on a failure, so the actor fields are null; the
        // bounded auth rate limit (authRateLimited, now fail-closed) caps how fast these can accrue. BEST-EFFORT:
        // an audit-write hiccup must never turn the {ok:false} into a 500 on this unauthenticated path.
        if (!finRes.ok) {
          try {
            await this.appendAudit({ actorSubject: null, actorEmail: null, actorMethod: "passkey", sourceIp: null, action: "authn-failure", outcome: "failed", target: { kind: "access-policy" } });
          } catch {
            /* best-effort: a failed-login audit must not break the login response */
            // G014: ...but the DROP is itself evidence. This append is the ONLY tamper-evident record that a
            // brute-force / credential-stuffing sweep happened, and it is deliberately excluded from the pack's
            // audit excerpt, so a swallowed failure left the pack showing a quiet weekend. Count the drop.
            await recordCeremonyFault(this.state.storage, "authn-failure-audit-append-failed");
          }
        }
        return this.json(finRes);
      }
      // STEP-UP RE-AUTH (ASVS V7.5.1/V7.5.3): begin/finish are the fresh-assertion ceremony (the caller asserts
      // one of their OWN passkeys, scoped under stepup:) that mints a single-use step-up token; check is the
      // router-internal "is a step-up satisfied for this session" decision (recent auth OR a consumed token).
      case "POST /passkey/session/issue":
        return this.json(await this.passkeySessionIssue((await req.json()) as { email?: unknown }));
      case "POST /passkey/session/verify":
        return this.json(await this.passkeySessionVerify((await req.json()) as { token?: unknown }));
      // Passkey CREDENTIAL management (authenticated; the caller is forwarded for the DO's own authority
      // re-check). List a member's enrolled keys (own = any role; another's = roles.write), revoke one
      // (the theft/loss path, ASVS V6.5.6; self or access-admin/owner, last-Owner-passkey guarded).
      case "GET /passkey/credentials":
        return this.json(await this.listPasskeyCredentials(url.searchParams.get("email"), decodeCaller(req.headers.get(CALLER_HEADER))));
      // ACCOUNT-WIDE credential enumeration (roles.write). The per-email route above cannot establish that an
      // account is CLEAN, because it needs the email first and a credential whose member was deleted is
      // exactly the one whose email nobody thinks to ask about. See listAllPasskeyCredentialsForAccount for
      // why this reports rather than having deleteRole revoke.
      case "GET /passkey/credentials/all":
        return this.json(await this.listAllPasskeyCredentialsForAccount(decodeCaller(req.headers.get(CALLER_HEADER))));
      // THE SIGN-IN FACTOR UNION over `passkeyCred:`, `recovery:` and `passkeyInvite:`. The credential route
      // above enumerates the hardest of the three factors and says nothing about the two bearer secrets that
      // survive an offboard. See listSignInFactors for the scope rules and src/admin/signin-factors.ts for why
      // the verdict is tri-state rather than a boolean.
      case "GET /signin-factors":
        return this.json(await this.listSignInFactors(url.searchParams.get("email"), decodeCaller(req.headers.get(CALLER_HEADER))));
      // THE OFFBOARDING WRITE, the union read's twin over the same three stores. It exists because two of them
      // (`recovery:` and `passkeyInvite:`) had NO delete anywhere in the engine, so the ordered offboarding the
      // product documents could not be carried out at all. roles.write with no self arm, sole-Owner and
      // dual-control guarded, and it bumps the session epoch ONLY when a way in was really closed. See
      // revokeSignInFactors for why this is not folded into deleteRole.
      case "POST /signin-factors/revoke":
        return this.json(await this.revokeSignInFactors((await req.json()) as { email?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /passkey/credentials/delete":
        return this.json(await this.revokePasskeyCredential((await req.json()) as { credentialId?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // SESSION termination (ASVS V7.4.5 / V7.5.2). terminate-others bumps the CALLER's own epoch and
      // returns a fresh token (kills other sessions, keeps this one); terminate-user is the admin
      // per-member kill (roles.write, owner-guarded); terminate-all rotates the session signing key so
      // EVERY session across all members dies at once (owner-only break-glass).
      case "POST /passkey/session/terminate-others":
        // The router forwards the caller's raw cookie in the body (token) alongside the CALLER_HEADER, so
        // the re-mint can preserve its ORIGINAL iat/exp (a slide, not a fresh login) - see
        // terminateOwnOtherSessions in scheduler-do-session.ts.
        return this.json(await this.terminateOwnOtherSessions(decodeCaller(req.headers.get(CALLER_HEADER)), (await req.json()) as { token?: unknown }));
      case "POST /passkey/session/terminate-user":
        return this.json(await this.terminateUserSessions((await req.json()) as { email?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /passkey/session/terminate-all":
        return this.json(await this.terminateAllSessions(decodeCaller(req.headers.get(CALLER_HEADER))));
      // LOGOUT (ASVS V7.4.1): the unauthenticated-edge logout forwards the presented cookie token here; the DO
      // verifies it and bumps this identity's revocation axes so the token (and any exfiltrated copy) dies
      // SERVER-SIDE, not merely in the browser. Reached only via the router's own scheduler.fetch on /logout.
      case "POST /passkey/session/logout":
        return this.json(await this.passkeySessionLogout((await req.json()) as { token?: unknown; sourceIp?: unknown }));
      // NATIVE EXTERNAL-IdP (OIDC). Connection custody + the sign-in flow + the v3 mint live here; the router
      // owns the web edge (the /admin/oidc/* + /admin/idp/* dispatch, the txn cookie, the relative-only returnTo,
      // the Origin + Referrer-Policy headers) and forwards. The DO is authoritative: each CRUD route re-resolves
      // the caller's capability from its OWN tables (keys.ceremony, owner-exclusive), never the forwarded role.
      //  - providers: the PRE-AUTH display DTO for the sign-in buttons (enabled connections, no internal fields).
      //  - conn create/list/delete/enabled: keys.ceremony-gated; disable/delete bump the per-connection idpEpoch.
      //  - oidc start/callback: the PRE-AUTH login flow (no caller; reached only via the router's pre-authorise
      //    dispatch); callback runs the guarded exchange + verify in the DO and mints the v3 oidc session.
        default:
          return null;
      }
    }

    // Step-up re-auth (ASVS V7.5.1/V7.5.3): the fresh-assertion ceremony + the router-internal satisfied check.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeStepUp(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /stepup/begin":
        return this.json(await this.stepUpBegin((await req.json()) as { rpId?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /stepup/finish":
        return this.json(await this.stepUpFinish((await req.json()) as { challengeId?: unknown; credential?: unknown; rpId?: unknown; origin?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /stepup/check":
        return this.json(await this.stepUpCheck((await req.json()) as { token?: unknown; stepUpToken?: unknown }));
      // Passkey SESSION (the signed browser session a successful login yields). The signing key
      // (passkeySessionKey) is generated ONCE by the DO and persisted here, never hardcoded and never
      // leaving the DO, so the HMAC sign + the constant-time verify both run INSIDE the DO over the stored
      // key (session.ts is the pure core the DO drives, exactly like passkey.ts). POST /passkey/session/
      // issue mints a token for an ALREADY-VERIFIED email (the router calls it only after login/finish
      // returned ok, so issuance is gated by a proven login, not by this route trusting its input);
      // POST /passkey/session/verify re-checks a presented cookie token and returns the verified email or
      // null. Both are INTERNAL (reached only by the router's own scheduler.fetch, like /whoami).
        default:
          return null;
      }
    }

    // Native external IdP: the OIDC + SAML connection custody and sign-in flows.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeIdp(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /idp/providers":
        return this.json(await this.idpProviders());
      case "GET /idp/presets":
        return this.json(await this.idpPresets(decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /idp/conn/create": {
        // GATED owner op (idp-conn-create): wiring an external IdP connection decides WHO can sign in, so it
        // takes a second owner's approval (account-takeover surface). The client secret, when supplied, is in
        // the replay params (like the webhook url / dest secret), never the summary or the audit; the summary
        // names the preset/id only. idpConnCreate's own keys.ceremony re-check runs on inline + replay paths.
        const icCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const icBody = (await req.json()) as Record<string, unknown>;
        const icHint = typeof icBody.id === "string" && icBody.id !== "" ? icBody.id : typeof icBody.presetId === "string" ? icBody.presetId : "connection";
        return this.ownerActionJson(
          await this.gatedOwnerAction("idp-conn-create", icBody, `Add an external IdP connection (${icHint}), changes who can sign in`, icCaller, (auth) => this.idpConnCreate(icBody, auth)),
        );
      }
      case "GET /idp/conn/list":
        return this.json(await this.idpConnList(decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /idp/conn/delete": {
        // GATED owner op (idp-conn-delete): removing a connection changes who can sign in.
        const idCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const idBody = (await req.json()) as { connId?: unknown };
        const idConn = typeof idBody.connId === "string" ? idBody.connId : "";
        return this.ownerActionJson(
          await this.gatedOwnerAction("idp-conn-delete", idBody, `Delete the external IdP connection ${idConn || "(unspecified)"}, changes who can sign in`, idCaller, (auth) => this.idpConnDelete(idBody, auth)),
        );
      }
      case "POST /idp/conn/enabled": {
        // GATED owner op (idp-conn-enabled): enabling/disabling a connection changes who can sign in.
        const ieCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const ieBody = (await req.json()) as { connId?: unknown; enabled?: unknown };
        const ieConn = typeof ieBody.connId === "string" ? ieBody.connId : "";
        const ieVerb = ieBody.enabled === true ? "Enable" : "Disable";
        return this.ownerActionJson(
          await this.gatedOwnerAction("idp-conn-enabled", ieBody, `${ieVerb} the external IdP connection ${ieConn || "(unspecified)"}, changes who can sign in`, ieCaller, (auth) => this.idpConnSetEnabled(ieBody, auth)),
        );
      }
      case "POST /idp/conn/removal-preflight": {
        // G5 lockout guard (READ-only, not gated): the DO-side facts the router combines with CF Access + the
        // token-disabled/retired state to decide whether deleting/disabling this connection would strand the
        // tenant with no way back in.
        const rpBody = (await req.json()) as { connId?: unknown };
        return this.json(await this.connectionRemovalPreflight(typeof rpBody.connId === "string" ? rpBody.connId : ""));
      }
      case "POST /idp/conn/cert": {
        // GATED owner op (idp-conn-cert): a ZERO-DOWNTIME SAML signing-cert rollover (IDP-1). A signing cert is
        // the SAML trust root, so appending/replacing one is the same account-takeover class as create/enable and
        // takes a second owner's approval - but a SINGLE rollover, not the two approvals delete+recreate needed.
        // It does NOT kill live sessions (no idpEpoch bump): refreshing the trust anchor for the same IdP must not
        // log everyone out. idpConnSamlCertUpdate's own keys.ceremony re-check runs on the inline + replay paths.
        const icCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const icBody = (await req.json()) as { connId?: unknown; addCerts?: unknown; certs?: unknown };
        const icConn = typeof icBody.connId === "string" ? icBody.connId : "";
        const icVerb = icBody.certs !== undefined ? "Replace" : "Append";
        return this.ownerActionJson(
          await this.gatedOwnerAction("idp-conn-cert", icBody, `${icVerb} the SAML signing cert(s) on the external IdP connection ${icConn || "(unspecified)"} (zero-downtime rollover)`, icCaller, (auth) => this.idpConnSamlCertUpdate(icBody, auth)),
        );
      }
      case "POST /idp/oidc/start":
        return this.json(await this.idpOidcStart((await req.json()) as { connId?: unknown; redirectUri?: unknown; returnTo?: unknown }));
      case "POST /idp/oidc/callback":
        return this.json(await this.idpOidcCallback((await req.json()) as { connId?: unknown; code?: unknown; state?: unknown; txnId?: unknown; iss?: unknown; sourceIp?: unknown }));
      // NATIVE EXTERNAL-IdP (SAML SP). The XML pipeline (parser -> pinned-cert dsig -> consume) runs in the
      // modules; the DO does state custody (the SP-initiated RelayState record) + the v3 mint. SP-initiated only
      // in v1: a missing RelayState record at the ACS rejects replay / IdP-initiated / forged. metadata is the
      // public SP descriptor (no secret). All PRE-AUTH (the router's pre-authorise dispatch forwards them).
      case "POST /idp/saml/metadata":
        return this.json(await this.idpSamlMetadata((await req.json()) as { connId?: unknown; acsUrl?: unknown }));
      case "POST /idp/saml/start":
        return this.json(await this.idpSamlStart((await req.json()) as { connId?: unknown; returnTo?: unknown; acsUrl?: unknown }));
      case "POST /idp/saml/acs":
        return this.json(await this.idpSamlAcs((await req.json()) as { connId?: unknown; samlResponse?: unknown; relayState?: unknown; acsUrl?: unknown; browserBind?: unknown; sourceIp?: unknown }));
      // SSO sign-in FAILURE aggregate (support diagnosis, D2): the bounded per-code counter the OIDC/SAML callback
      // wrappers maintain. An INTERNAL read (reached only by the Worker's scheduler.fetch, like the other support
      // reads) and redaction-safe by construction (closed code keys + int counts + timestamps).
      case "GET /sso-failures":
        return this.json(await this.readSsoFailures());
      // P1: the per-connection-KIND breakdown of the same aggregate (which PROTOCOL is failing). Same INTERNAL read,
      // same redaction-safe-by-construction shape (closed connKind -> closed code -> {count,lastAt}).
      case "GET /sso-failures-by-kind":
        return this.json(await this.readSsoFailuresByKind());
      // G140: the per-CONNECTION breakdown of the same aggregate (which of your two SAML connections is
      // failing). Keyed by the OPAQUE stable ordinal this DO minted, NEVER the operator-chosen connId, so the
      // connId-exclusion the pack has always held is preserved exactly.
      case "GET /sso-failures-by-conn":
        return this.json(await this.readSsoFailuresByConn());
      // P2: the bounded auth/RBAC defensive-branch signal aggregate. GET is the INTERNAL read the support pack
      // projects; POST records ONE closed-vocabulary event name, the recording path for the Worker-EDGE sites that
      // run outside the DO (a CSRF-origin refusal, a SCIM 401/503/last-owner-guard refusal) which self-fetch this
      // route best-effort. recordAuthSignal drops an out-of-vocabulary name, so a bad body can never add a key.
      case "GET /auth-signals":
        return this.json(await this.readAuthSignals());
      case "POST /auth-signal": {
        const b = (await req.json()) as { name?: unknown };
        const name = typeof b.name === "string" ? b.name : "";
        // G221: recordAuthSignal DROPS an out-of-vocabulary name (the redaction boundary, unchanged) while the
        // edge is answered ok - so after a partial deploy the Worker can post a name this DO does not know and
        // the counter simply STOPS INCREMENTING, with the pack showing a quiet period rather than a skew. Count
        // the rejection itself (route class + fault kind only, never the rejected string).
        if (!AUTH_SIGNAL_NAME_SET.has(name)) await recordContractFault(this.state.storage, "auth-signal", "enum-drift");
        await this.recordAuthSignal(name);
        return this.json({ ok: true });
      }
      // P4: auth posture probes for the pack - the session signing-key presence + age (a young key + a verify
      // spike = the "everyone logged out" session-signing-key-lost signal) and the count of confidential IdP
      // connections whose do-plaintext secret is absent. Presence/count only, never the key or a secret.
      // G140: doPlaintextSecretsMissingConns names WHICH connections are secretless by their OPAQUE ORDINAL
      // (never the connId), so "sign-in fails after we recreated the connection" points at the one that lost
      // its secret instead of leaving the operator to guess between two.
      case "GET /auth-posture": {
        const secretlessConns = await this.doPlaintextSecretsMissingConns();
        return this.json({
          sessionSigningKey: await this.sessionSigningKeyHealth(),
          doPlaintextSecretsMissing: secretlessConns.length,
          doPlaintextSecretsMissingConns: secretlessConns,
          adminCredentialPaths: await this.adminCredentialPaths(),
          // G253: WHICH credential path the estate actually RAN on, and when. adminCredentialPaths above is a
          // CAPABILITY count (how many alternative sign-in paths EXIST); this is USAGE OVER TIME (a closed method
          // enum x a 14-day UTC ring x a count, plus firstAt/lastAt). It is what bounds "how long did it run on
          // the shared break-glass token" and what dates "was this estate behind Access when the change landed".
          methodUsage: await this.readAuthMethodUsage(),
        });
      }
      // G253: the router posts ONE authenticated admin request's credential path here (throttled edge-side to at
      // most one write per method per minute per isolate, carrying the count it stands for). INTERNAL: reached
      // only by the router's own scheduler.fetch, like /auth-signal. The method is re-gated against the closed
      // AuthMethod set inside the recorder (the redaction boundary), so no caller string can become a key.
      case "POST /auth-method-use": {
        const b = (await req.json()) as { method?: unknown; n?: unknown };
        await this.recordAuthMethodUse(typeof b.method === "string" ? b.method : "", typeof b.n === "number" ? b.n : 1);
        return this.json({ ok: true });
      }
      // RECOVERY CODES (the ongoing admin-sign-in break-glass; recovery.ts owns the crypto, this DO owns the
      // per-email record + the rate limit + the session mint). All four routes are INTERNAL (reached only by
      // the router's own scheduler.fetch); the two PUBLIC-facing flows (recover, regenerate) are dispatched
      // by the router BEFORE its authorise gate and forward here.
      //  - POST /recovery/regenerate {email}: mint a fresh set, INVALIDATE all prior codes for that email,
      //    return the plaintext ONCE. The router gates this to the caller's OWN email (self-service).
      //  - POST /recovery/recover {email, code, ip}: constant-time verify against the unconsumed hashes, mark
      //    the matched code consumed, mint a NORMAL signed session for that email's resolved role. HARD
      //    rate-limited per IP AND per email (fail closed), generic on mismatch (no oracle), audited + the
      //    abuse/used alert signals returned for the router to route.
      //  - GET  /recovery/remaining?email=: the caller's OWN unconsumed count (the router passes the verified
      //    email). Never another user's count.
      //  - POST /recovery/confirm-staged {email, method, ip}: promote a STAGED set (generateRecoveryStaged,
      //    fired by a self-add enrolment that ran while a live record already existed) to live, invalidating
      //    whatever was live before it. The router dispatches this only for an authenticated caller confirming
      // their OWN email (see STAGED-RECOVERY-CODES-CONFIRM-GATE). A no-op (promoted:false) when
      //    nothing is staged.
        default:
          return null;
      }
    }

    // Recovery codes (the ongoing admin-sign-in break-glass): regenerate/recover/remaining/confirm-staged.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeRecovery(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /recovery/regenerate":
        return this.json(await this.recoveryRegenerate((await req.json()) as { email?: unknown; ip?: unknown; method?: unknown }));
      case "POST /recovery/recover":
        return this.json(await this.recoveryRecover((await req.json()) as { email?: unknown; code?: unknown; ip?: unknown }));
      case "GET /recovery/remaining":
        return this.json(await this.recoveryRemaining(url.searchParams.get("email")));
      case "POST /recovery/confirm-staged": {
        const b = (await req.json()) as { email?: unknown; method?: unknown; ip?: unknown };
        const email = this.normaliseEmail(b.email);
        if (!email) return this.json({ ok: true, promoted: false });
        const allowed: readonly AuthMethod[] = ["access", "passkey", "oidc", "saml", "token"];
        const method = (typeof b.method === "string" && (allowed as readonly string[]).includes(b.method) ? b.method : "passkey") as AuthMethod;
        const ip = typeof b.ip === "string" && b.ip.length > 0 ? b.ip : null;
        return this.json(await this.confirmRecoveryStaged(email, method, ip));
      }
        default:
          return null;
      }
    }
  };
}
