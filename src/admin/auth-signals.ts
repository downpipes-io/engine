// The CLOSED vocabulary of auth / RBAC "defensive-branch" events the engine records for the support pack.
//
// WHY (the audit's #1 idp-auth gap): almost every auth / IdP / RBAC FAILURE the engine takes today leaves NO
// durable trace at all - a fail-closed rate-limit, a SCIM bearer rejection, a dropped group claim, a verified-
// but-emailless assertion. So a "my users are locked out / can't be deprovisioned / silently lost their role"
// ticket is undiagnosable from the bundle. This module names those branches as a fixed set of event codes; the
// scheduler DO keeps ONE bounded aggregate keyed by these names -> { count, lastAt }, and the support pack
// projects it. The design mirrors the SSO-failure aggregate (sso-failure-class.ts): a CLOSED vocabulary read
// here and shared by BOTH the recorder (sched mixin) and the projector (admin/support.ts), so no operator text,
// email, ip, connId, subject or secret is ever stored - only the closed event name + an int count + a timestamp.
//
// DoS / no-custody floor (identical to the SSO aggregate): the key space is bounded by THIS set, so a flood of
// failed sign-ins / SCIM probes just re-bumps a counter - it never adds a storage row or an audit-chain entry,
// and the count is capped. An unknown name is DROPPED at both the record and the project boundary (defence in
// depth), so a caller can never inject an out-of-vocabulary key.

import { IDP_TEST_FAIL_CLASSES, IDP_VALIDATION_CLASSES, idpTestSignalName, idpValidationSignalName } from "./idp-diag.ts";
import { SAML_ATTACK_SHAPES, SAML_DEGRADE_SIGNALS, SAML_START_SIGNALS } from "./saml-signals.ts";
import { IDP_ERROR_CODES, idpErrorSignalName, SSO_EDGE_CODES, SSO_SUB_CODES, ssoEdgeSignalName, ssoSubSignalName } from "./sso-failure-class.ts";

export const AUTH_SIGNAL_NAMES = [
  // --- verified-principal refusals (native OIDC / SAML session mint) ---
  "emailless-assertion", // a VERIFIED IdP principal was refused for asserting no usable email (a subject-only token)
  "subject-unusable", // a verified principal was refused for a pathological / empty / control-char subject
  "email-verified-bind-blocked", // a pending-invite bind was SKIPPED because the IdP did not assert email_verified
  // --- rate-limit / lockout availability ---
  "auth-ratelimited", // an interactive auth attempt hit the per-IP rate-limit cap (shared-NAT / brute-force lockout)
  "recovery-ratelimited", // a recovery-code sign-in was refused by the hard per-IP / per-email fail-closed limiter
  "auth-limiter-unavailable", // the unauthenticated per-IP auth limiter FAILED CLOSED because its backing DO was unavailable (login blocked, not throttled)
  "admin-token-ratelimited", // the bare ADMIN_TOKEN break-glass compare was throttled: either its per-IP cap tripped (a guessing campaign) or the limiter's backing DO was unavailable (fails closed, so a legitimate operator's break-glass was denied too). RETAINED for the vocabulary's stability; the two causes now ALSO fire their own split names below, which is the whole point of the split below
  // --- THE AUTH-PLANE OUTAGE branches, which produced responses IDENTICAL to genuine auth verdicts ---
  //
  // WHY. Every branch below is a place where the auth plane's own BACKING STORE failed and the engine
  // substituted a VERDICT for it -- fail-open on the per-caller limiter, fail-closed on step-up, a
  // least-privilege viewer when a session shape came back wrong. The substituted verdict is byte-identical to
  // the genuine one: a locked-out fleet ("every sensitive action keeps demanding a passkey and never accepts
  // it") looks exactly like a fleet with no passkeys, and an owner degraded to viewer by a garbled DO answer
  // looks exactly like an owner whose role was revoked. The diagnostic signal fired ONLY from thrown paths,
  // never from the garbled-shape or silent-downgrade branches, so the pack's authSignals aggregate was
  // EMPTIEST during exactly the incident it exists to explain.
  //
  // NOISE DISCIPLINE (binding): none of these fires on a LEGITIMATE state. The step-up ceremony opens with a
  // 401 by design, and a caller who simply has not stepped up yet is not a fault -- so stepup-check-unavailable
  // fires ONLY from the catch (the DO could not be reached), never from an honest `satisfied:false`. Likewise
  // the per-caller limiter's ordinary "allowed:false" refusal is a working limiter doing its job and is not
  // recorded here at all.
  "session-verify-unavailable", // the session-cookie verify round trip THREW: the DO could not be reached, so the request was denied. The whole team is signed out for the duration, and this is the ONLY thing that says the cookies were fine
  "session-verify-verdict-malformed", // the session-verify DO ANSWERED and its answer carried NO verdict token at all: it never ran passkeySessionVerify (its own 500 envelope, a route drift, a drifted build). This is the up-but-broken DO that signs the whole team out while every cookie on the estate is perfectly good, and it is the one branch here that scheduler.fetch cannot throw for. An ordinary expired or revoked cookie comes back with the verdict "rejected" and is recorded NOWHERE
  "session-shape-invalid", // the session-verify DO answered "verified" and then failed its OWN contract (no email, no subject, an unknown method), so the caller was failed closed anyway. A rotten accept, distinct from the rotten envelope above and from a genuinely dead cookie
  "stepup-check-unavailable", // the step-up (passkey re-auth) check THREW: fail-closed, so EVERY sensitive action is refused with "step-up required" -- the "it keeps demanding a passkey and never accepts it" ticket, which is not a passkey fault at all
  "stepup-check-verdict-malformed", // the step-up check ANSWERED and its answer carried no BOOLEAN satisfied (the DO's 500 envelope, a route drift). stepUpCheck's contract is total, so this is a DO that is up and broken: every sensitive action is refused with the same 401 the ceremony legitimately opens with. An honest satisfied:false is the ceremony working and records nothing
  "limiter-verdict-malformed", // the per-caller rate limiter ANSWERED with a shape that carried no boolean verdict, and the request was ADMITTED (fail-open). The limiter is silently not limiting: an availability choice made deliberately, and previously invisible
  "caller-verdict-degraded", // an Access/passkey caller reached the resolver WITHOUT a usable email or subject and was failed closed to a least-privilege VIEWER. "I am an owner but I am treated as a viewer" -- and nothing anywhere recorded the downgrade
  "admin-token-ratelimited-overcap", // the break-glass per-IP CAP tripped: a real guessing campaign (or one operator retrying hard). The limiter is WORKING. Fires ONLY on an explicit allowed:false, never on a garbled answer
  "admin-token-ratelimited-unavailable", // the break-glass limiter's backing DO was UNAVAILABLE and it failed closed: the operator's break-glass was denied by an OUTAGE, not by a throttle. Labelling this as throttling sent every such ticket down the wrong path ("who is attacking us?") when the answer was "your scheduler is down"
  "admin-token-ratelimited-malformed", // the break-glass limiter ANSWERED and its verdict carried no boolean: the DO is UP and BROKEN (a route drift, a storage fault, the DO's own 500 envelope), and the fail-closed denial is identical to a throttle. scheduler.fetch does NOT throw on an HTTP error status, so this state never reached the catch above and was filed as a guessing campaign
  // --- THE ANSWERED-BUT-BROKEN limiter/gate branches ---
  //
  // THE MECHANISM THE FIRST BUILD MISSED. scheduler.fetch() does not throw on an HTTP error status: the DO's
  // own outer catch returns a JSON 500 {"error":"internal error"}. So an UP-BUT-BROKEN DO (a storage fault, a
  // TypeError, deploy/route drift) is an ANSWERED outage -- resp.json() parses, the verdict field is simply
  // absent -- and every catch-only signal above stays SILENT for it. The fail-closed gates then substitute a
  // denial that is byte-identical to the genuine verdict, which is the whole gap.
  "auth-limiter-verdict-malformed", // the UNAUTHENTICATED sign-in limiter ANSWERED with no boolean verdict and the sign-in was DENIED (it fails closed). This is the "all sign-ins 429" ticket in its third form: not an over-cap (auth-ratelimited) and not an unreachable DO (auth-limiter-unavailable), but a limiter DO that is up and answering rubbish
  "break-glass-check-shape-invalid", // the break-glass RETIRE check ANSWERED and its verdict carried no boolean, so the token was denied fail-closed. Previously indistinguishable from an INTENTIONAL retire (which records nothing at all), which is why "my break-glass token stopped working" could not be answered
  // --- recovery-code lockout / regenerate ---
  // WHY: recovery codes are the LAST way back in when a passkey is lost. Today a rejected code and a broken
  // regenerate both vanish into a generic 401/500, so "every recovery code we try is rejected" and "regenerate
  // silently fails" are equally undiagnosable. Counts only; never the code, salt, hash, email or IP, and the
  // client-facing responses stay generic (the no-oracle property is unchanged).
  "recovery-code-invalid", // a recovery-code sign-in was REJECTED (the code did not match any unconsumed slot). Distinct from recovery-ratelimited, which is a throttle rather than a rejection
  "recovery-regenerate-failed", // a signed-in caller's "regenerate my recovery codes" failed engine-side (a 500), so the operator is nagged to regenerate forever and never can
  // --- WHICH SIDE OF THE INVALIDATION LINE THE FAILED REGENERATE DIED ON ---------------------------
  //
  // The gap's stated worst case is "I regenerated my recovery codes, it errored, and now NEITHER old nor new
  // codes work", and it asks for the one fact that answers it: were the old codes ALREADY INVALIDATED engine-side?
  // `recovery-regenerate-failed` above cannot say. It is fired by the ROUTER, which sees one opaque non-2xx from
  // the DO and has no view of how far inside the DO the write got.
  //
  // The invalidation is a single, exact boundary: recoveryRegenerate mints a fresh record and PUTS it over the
  // email's existing one (scheduler-do-recovery.ts generateRecoveryFor). Before that put the old set still
  // verifies; after it the old set is dead forever. The two failures either side of that put have OPPOSITE
  // remedies, and until now they were the same 500 and the same row:
  //
  //   mint-failed       the mint threw BEFORE the put (the classic cause is an unusable in-DO signing key, which
  //                     is separately flagged by recovery-signing-key-invalid). Nothing was overwritten: the
  //                     operator's EXISTING codes still work. Tell them to keep the set they have.
  //   old-codes-lost    the put LANDED and the flow then failed (the audit append, the epoch bump, an ack write).
  //                     The old set is invalidated and the new plaintext was NEVER returned, because the caller
  //                     got a 500 instead of the codes. The operator holds NEITHER set, and no amount of retrying
  //                     a recovery code will help: they need another Owner, the break-glass token, or a passkey.
  //                     This is the gap's worst case and it is the one that must never again be silent.
  //
  // Counts only, fired inside the DO, which is the only party that can see the boundary. Never a code, a hash, a
  // salt, an email or the thrown message.
  "recovery-regenerate-mint-failed", // the regenerate failed BEFORE the new record was stored: the operator's EXISTING recovery codes are intact and still work
  "recovery-regenerate-old-codes-lost", // the regenerate STORED the new record (the old codes are invalidated) and then failed, so the fresh plaintext never reached the caller: the operator holds NEITHER set
  // The CORRUPTION half of the recovery-code gap: the two states in which recovery codes are broken for reasons the OPERATOR
  // cannot fix by typing more carefully. Both were invisible: a corrupt record and a mistyped code produce the
  // SAME generic no-oracle 401, so "the owner lost their passkey and every recovery code is rejected" arrived
  // with nothing anywhere saying the persisted record (or the key that hashes it) is the problem. Counts only:
  // never a code, a salt, a hash, a key or the caller's email, and the client response stays generic.
  "recovery-record-corrupt", // one or more of the STORED recovery-code slots has an undecodable salt/hash: those codes can NEVER match, whatever the operator types (a DO record corruption, not user error)
  "recovery-signing-key-invalid", // the in-DO session signing key that HMACs the recovery codes is too short to import, so EVERY recovery operation (generate and verify) fails: the last way back into a locked-out account is broken engine-side
  // --- roster-bound consumption (the recovery-code residue) ---
  // A recovery code has no expiry, deliberately: a break-glass credential that expires on a clock fails during
  // the emergency it exists for. Its validity is bound to the ROSTER at the moment it is spent instead, and
  // that binding FAILS OPEN. These two count the fail-open arm firing, because a gate that has quietly stood
  // down is indistinguishable from a gate that is passing everything legitimately.
  "roster-read-unavailable", // the role-table read threw while deciding whether a spent bearer secret may still enrol a fresh passkey, so the roster gate stood down and ADMITTED (fail open, never a lockout)
  "roster-read-empty", // the roster read succeeded and returned NOTHING at all: not a departure, a new or broken account, so the gate stood down. On a populated estate this should never fire
  "roster-enrolment-refused", // an enrolment was refused because a populated roster does not account for the address. Both arms report it: a proven passkey sign-in self-adding a second credential, and a still-valid registration invite redeemed after the grant it was minted for was removed. The existing credentials of that address are untouched
  // --- CSRF / origin ---
  "csrf-origin-mismatch", // a cookie-borne console mutation was refused for an Origin != CONSOLE_ORIGIN (CSRF block)
  // --- SCIM deprovision path ---
  "scim-unauthorised", // a SCIM request presented a missing / invalid bearer (401) - the bearer was rotated / is wrong
  "scim-unconfigured", // a SCIM request arrived while SCIM is unconfigured (503) - no deprovision path is wired
  "scim-last-owner-refused", // a SCIM deprovision was refused by the last-Owner guard (would remove the last Owner)
  "scim-offboard-refused", // a SCIM deprovision was refused for a reason OTHER than the last-Owner guard (e.g. an unexpected DO-side error); dual control ("Require Config Approval") is NEVER this cause - SCIM offboarding bypasses that gate entirely (see isScimOffboardCaller in admin/identity.ts)
  // --- SCIM lifecycle REJECTIONS: "SCIM shows connected but leavers are never removed" ---
  // WHY: every branch below 400s/404s/405s the connector FOREVER while the pack shows a healthy-looking SCIM
  // surface, so a departed user keeps access and support cannot see why. Each names the REJECTED SHAPE, never the
  // offending user id, email, connector IP or user-agent.
  "scim-id-rejected-empty", // the /Users/{id} path carried no id, or an id with an embedded slash (a connector addressing the collection, not a member)
  "scim-id-rejected-encoding", // the /Users/{id} id was not valid percent-encoding (a connector that did not URL-encode the address)
  "scim-id-rejected-email-shape", // the /Users/{id} id decoded but is not an email address: the classic Entra failure of sending the immutable objectId / externalId instead of userName, which can NEVER match a member
  "scim-patch-body-invalid", // a PATCH body was not valid JSON at all
  "scim-patch-shape-rejected", // a PATCH body was valid JSON but not a recognised deprovision PatchOp (schemas missing the PatchOp urn, or an Operations shape this facade does not recognise) - the Entra "unrecognised PatchOp" failure
  "scim-patch-reactivation-refused", // a PATCH asked to REACTIVATE (active:true); this surface is deprovision-only and refuses rather than silently no-op'ing a change the IdP would read as applied
  "scim-method-unsupported", // a /Users/{id} request used a method this facade does not support (405) - e.g. a connector that deactivates via PUT rather than PATCH/DELETE
  "scim-endpoint-unknown", // a request hit a path outside this minimal deprovision-only /Users facade (404) - the connector expects a fuller SCIM provider
  "scim-response-unparseable", // the DO answered the offboarding 200 but its body did not parse, so the engine could not confirm WHETHER a member was removed (the offboarding alert is now fired conservatively rather than silently suppressed)
  "scim-offboard-do-error-4xx", // the offboarding DO refused with a 4xx that is NOT the last-Owner guard (a contract/validation drift between the facade and the DO)
  "scim-offboard-do-error-5xx", // the offboarding DO failed with a 5xx (a DO-side fault): the leaver was NOT removed and the connector will keep retrying
  // --- the offboarding REVOKE leg (SCIM-REVOKE), which runs BEFORE the role delete ---
  // Four names rather than one, because the four states have four different remedies and collapsing them is
  // the defect this vocabulary exists to prevent. In particular a revoke that RAN and found nothing live must
  // not read the same as one that was never issued: the revoke's own audit row is written only when a way in
  // was really closed, so on this unattended route these signals are the only witness that the leg ran at all.
  "scim-offboard-revoked", // the revoke leg closed a real way in (a credential, a recovery record or a live invite)
  "scim-offboard-revoke-nothing-live", // the revoke leg ran and found nothing live to close: the leaver held no credential, no recovery record and no unexpired invite
  "scim-offboard-revoke-declined-owner", // the target is an Owner and the caller is the unattended SCIM identity, so the DESTRUCTIVE half was deliberately skipped; the role delete still ran, so authority was removed and only the irreversible part waits for a human
  "scim-offboard-revoke-failed", // the revoke leg was issued and did not succeed; the offboard CONTINUED to the role delete, so authority was still removed and this names the half that did not
  // --- group -> role resolution ---
  "group-name-dropped", // an asserted group name was dropped (empty / over-long / an ASCII control character)
  "zero-role-groups", // a login asserted groups but NONE matched a configured group -> role mapping (silent role loss)
  "subject-rekey-role-loss", // a verified login had NO role for its subject while the SAME email holds a role under a DIFFERENT subject (an IdP subject rekey orphaned the role binding)
  // --- SAML SP-initiated enforcement ---
  "saml-relaystate-missing", // an ACS assertion carried no server-minted RelayState record (IdP-initiated, replayed, or expired) - refused as SP-initiated-only
  // --- native OIDC issuer / tenant ---
  "oidc-tenant-not-accepted", // an Entra multitenant id_token carried a tid that is NOT in the connection's acceptedTenantIds allowlist (a /common misconfiguration, distinct from a plain wrong-issuer)
  "oidc-hd-not-accepted", // a Google id_token's hd (hosted-domain) claim did NOT match the connection's required Workspace domain (a personal/other-domain Google account attempted sign-in)
  // --- IdP connection configuration refusals (owner-facing) ---
  "private-key-jwt-unsupported", // a connection create/update was refused because private_key_jwt client auth is not wired in this build
  // --- Cloudflare Access front-door denials (the reason a verified-looking assertion was refused) ---
  "cf-access-aud-mismatch", // a signed Access JWT was refused because its aud did not include the configured CF_ACCESS_AUD (wrong Access application tag)
  "cf-access-issuer-mismatch", // a signed Access JWT was refused because its iss did not equal the configured team-domain issuer (a CF_ACCESS_TEAM_DOMAIN typo / wrong team)
  "cf-access-key-unknown", // an Access JWT referenced a signing kid not present in the fetched JWKS (a stale in-isolate JWKS cache across an Access key rotation, or a non-RSA key)
  "cf-access-verify-failed", // an Access JWT was refused for any other reason (bad signature, expired, malformed, wrong alg/typ) - the residual Access-denial bucket
  // --- SSO START-path failures: "the SSO button just errors" while ssoFailures shows nothing ---
  // WHY: the SSO-failure aggregate is written only by the DO's CALLBACK wrapper, so a sign-in that dies at /start
  // never reaches ANY recorder - the pack shows zero SSO failures during an outage the customer swears was full of
  // them. These are recorded at the Worker edge (router-idp-web.ts) via classifySsoStartFailure, which reduces the
  // reason (it interpolates discovery errors, connIds and endpoint hosts) to one of these closed names and discards it.
  "sso-start-discovery-unreachable", // the IdP's discovery host could not be REACHED (an IdP-side outage or a DNS/egress fault): wait / check the IdP, not the connection
  "sso-start-discovery-refused", // the IdP SERVED discovery but it was unusable: a non-200 (an auth/tenant error page) or a non-JSON body (typically a proxy/captive-portal interstitial)
  "sso-start-endpoint-refused", // WE refused an advertised endpoint (or the connection's issuer): a bad URL, or a host that does not match the issuer host (the SSRF / IdP-mix-up safety check)
  "sso-start-connection-refused", // the connection cannot start a sign-in at all: disabled, deleted, unknown connId, a kind with no interactive flow, or an unresolvable client secret
  "sso-start-refused", // residual: a start refusal outside the named classes above
  "sso-start-do-unreachable", // the START route could not reach the scheduler DO at all (the sign-in never even got as far as minting state) - an engine-side availability fault, not a connection fault
  // --- passkey / WebAuthn ceremony failures ---
  // WHY: every passkey failure funnelled into an errId'd console.error in Workers Logs, which remote support
  // structurally cannot read, so a TOTAL lockout after a CONSOLE_ORIGIN / custom-domain change looked exactly like
  // a quiet weekend in the pack. Recorded at the Worker edge from the DO's COARSE ceremony reason, allowlisted
  // through passkeySignalName (passkey-types.ts). The client-facing response is unchanged and stays coarse, so
  // none of these classes is ever oracled back to a caller (the anti-enumeration property is preserved).
  "passkey-not-configured", // a ceremony was refused 501 because CONSOLE_ORIGIN is unset/unparseable: the engine has no origin to bind a credential to (a deploy-config fault, not a user fault)
  "passkey-origin-mismatch", // clientData origin != CONSOLE_ORIGIN - the classic "every sign-in broke after we moved the console to a custom domain"
  "passkey-rpid-mismatch", // authData rpIdHash != SHA-256(rp.id) - PASSKEY_RP_ID is no longer a registrable-domain suffix of the console origin
  "passkey-uv-unmet", // the authenticator did not set user-verified: a UV-incapable security key against a front door that requires UV (a whole fleet can be locked out this way)
  "passkey-up-unmet", // the authenticator did not set user-present
  "passkey-challenge-failed", // the challenge was missing, expired (the TTL ceiling) or did not match - includes a challenge evicted from the bounded store under a begin flood
  "passkey-signature-failed", // the assertion signature did not verify
  "passkey-clone-detected", // signCount did not advance: a POSSIBLE CLONED AUTHENTICATOR (a posture signal, not a config fault)
  "passkey-unknown-credential", // an unregistered credential id was asserted (someone probing, or a credential store that lost the record)
  "passkey-already-registered", // a registration replayed a credential id that is already enrolled
  "passkey-bad-request", // the ceremony was structurally malformed (the coarse bucket the CBOR/COSE/authData parse faults land in)
  "passkey-login-rejected", // residual: a login ceremony refused for a cause outside the classes above (e.g. an internal fault)
  "passkey-register-rejected", // residual: a registration refused for a cause outside the classes above (a forbidden enrolment, a spent/absent invite)
  "passkey-session-mint-failed", // the WebAuthn ceremony VERIFIED but the session cookie could not be minted: the user proved possession and STILL cannot get in (an engine-side fault that reads to the user as "sign-in failed")
  "stepup-failed", // a step-up re-auth ceremony failed: "the console keeps refusing my sensitive action"
  // --- router-internal caller header ---
  "caller-header-undecodable", // a PRESENT router-set caller header failed to decode (a fail-closed 403; a router/internal encode fault or tampering, distinct from an absent header)
  // --- session revocation enforcement (forced re-auth) ---
  "session-revoked-email-epoch", // a session was refused because its epoch is below the email's current session epoch (a terminate-all / factor-change / version-invalidation forced re-auth)
  "session-revoked-idp-epoch", // an oidc/saml session was refused because it predates its connection's idpEpoch (the connection was disabled / deleted / its secret rotated - everyone on it re-auths)
  // --- break-glass availability ---
  "break-glass-check-unavailable", // the break-glass-retired resolver FAILED CLOSED because its backing DO was unavailable (the bare-token fallback was denied on a DO hiccup)
  // --- cookie-borne session refusals ---
  // WHY: a present-but-invalid session cookie fails CLOSED with a generic 401 and records nothing, so "our users
  // keep getting logged out mid-shift" is byte-identical to "nobody tried to sign in". The verifier returns a bare
  // null (it deliberately tells the edge nothing about WHY, an anti-oracle property we keep), so the recorded class
  // is the branch we can honestly name: the cookie did not verify at all, vs it verified but carried no email.
  "session-verify-failed", // a PRESENT session cookie failed verification (expired, bad MAC, tampered or malformed) - refused, never downgraded to the token path
  "session-email-missing", // a session cookie VERIFIED but carried no usable email (a corrupt / pre-v3 session record) - refused
  // --- bare-token (ADMIN_TOKEN break-glass) deny classes ---
  // WHY: every bearer deny is one generic 401 today, so an operator's stale token, a never-configured engine and an
  // operator-disabled fallback are indistinguishable in the pack. These name the branch, NEVER the presented token.
  "admin-token-denied-disabled", // a caller reached the token fallback but the operator has disabled it (ADMIN_TOKEN_DISABLED); no Access assertion and no session cookie were presented
  "admin-token-denied-unconfigured", // a caller reached the token fallback but no ADMIN_TOKEN is configured on the engine at all (nothing to compare against)
  "admin-token-denied-empty-bearer", // a caller reached the token fallback with an absent / non-Bearer / empty Authorization header (automation that never attached its credential)
  "admin-token-denied-retired", // the bare token was refused because the Owner has RETIRED it in-app (the durable break-glass latch), distinct from the env flag and from a DO outage
  "admin-token-denied-mismatch", // a bearer was presented and compared but did NOT equal the configured ADMIN_TOKEN (a stale / rotated / wrong token, or a guessing campaign)
  // --- Cloudflare Access JWKS availability: "all Access sign-ins 500 during a cloudflareaccess.com blip" ---
  // WHY: the JWKS fetch/import path THROWS out of verifyAccessJWT rather than returning a reason, so it never
  // reached accessDenySignal at all: an Access-side outage, a malformed JWKS entry or a bad CF_ACCESS_TEAM_DOMAIN
  // produced a 500 with NOTHING in the pack, byte-identical to "nobody tried to sign in". verifyAccessJWT now
  // CATCHES the throw and classifies it to one of these closed causes (classifyJwksThrow, access.ts), which reads
  // the message ONLY to select a member and discards it. Never the certs URL, the team domain or the response body.
  "cf-access-jwks-host-refused", // the resolved certs endpoint was NOT an https *.cloudflareaccess.com host: the SSRF pin refused the fetch (a CF_ACCESS_TEAM_DOMAIN typo / a hostile env value), so no Access sign-in can verify
  "cf-access-jwks-fetch-failed", // the JWKS fetch did not complete at all (a network / DNS / egress fault reaching cloudflareaccess.com): an Access-side or connectivity outage, not a configuration fault
  "cf-access-jwks-non-2xx", // the JWKS endpoint ANSWERED but with a non-2xx: the Access surface is up but is refusing us (typically an unknown team domain)
  "cf-access-jwks-no-keys", // the JWKS body parsed but carried no `keys` array: a shape change or a captive-portal / proxy interstitial standing in for the real document
  "cf-access-jwks-import-failed", // a JWKS entry was selected but crypto.subtle.importKey REFUSED its bytes (a malformed / non-RSA-shaped key): every token signed under that kid is unverifiable
  // --- Cloudflare Access verify sub-causes: the ~7 causes that collapsed into cf-access-verify-failed ---
  // WHY: "intermittent console 401s" is a clock skew, an IdP emitting a wrong typ, an alg downgrade attempt and a
  // corrupt token all at once in one undifferentiated counter, so support cannot pick a cause remotely. Each name
  // below is selected by an ANCHORED prefix rule (accessDenySignal) so an attacker-chosen alg/typ tail cannot
  // steer its own classification. The residual cf-access-verify-failed above stays as the catch-all.
  "cf-access-verify-failed-malformed-jwt", // the assertion was not three base64url segments, or the header/payload would not decode as JSON, or it carried no kid (a corrupt / truncated / non-JWT credential)
  "cf-access-verify-failed-alg", // the JWT header alg was not RS256 (an alg-confusion / downgrade attempt, or an IdP signing with the wrong algorithm)
  "cf-access-verify-failed-typ", // the JWT header carried a typ that is present but is not "JWT" (a type-confusion attempt, or an IdP emitting the wrong token type)
  "cf-access-verify-failed-expired", // the assertion's exp had already passed: with a live Access session this is CLOCK SKEW between the engine and Cloudflare, the classic intermittent-401 cause
  "cf-access-verify-failed-nbf", // the assertion's nbf is in the future: clock skew in the other direction
  "cf-access-verify-failed-signature", // the RS256 signature did not verify under the selected key (a genuine forgery, or a JWKS entry that no longer matches the signing key)
  // --- CSRF sub-classes: "every console save 403s" -- misconfiguration or attack? ---
  // WHY: csrf-origin-mismatch alone cannot say whether CONSOLE_ORIGIN is UNSET (a deploy dropped the var: fix the
  // config) or a FOREIGN Origin is being presented (an actual cross-site attempt). Those are opposite diagnoses and
  // opposite remediations. The raw Origin value NEVER rides; only which of the three branches fired.
  "csrf-origin-unset", // CONSOLE_ORIGIN is missing/empty on the engine, so originAllowed fails CLOSED and EVERY cookie-borne mutation 403s: a deploy-config fault, not an attack (the single highest-value split here)
  "csrf-origin-header-absent", // the mutating request carried NO Origin header at all (a non-browser client, or a stripping proxy in front of the console)
  // The double-submit second factor (terminate-sessions routes), split into its three branches: a console that
  // never received the token, a cookie the browser did not return, and a genuine value mismatch.
  "csrf-double-submit-header-missing", // the request carried no CSRF header (a console that never read whoami, or a client that does not implement the second factor)
  "csrf-double-submit-cookie-missing", // the CSRF header was present but the paired cookie was absent (a cookie blocked/expired/partitioned by the browser)
  "csrf-double-submit-mismatch", // both were present but did not match: a stale token pair, or a genuine cross-site attempt
  // --- session-cookie fault classes: "users keep getting logged out" ---
  // WHY: verifySession deliberately returns a bare null (an anti-oracle property we KEEP: the caller is told
  // nothing about WHY). But that null was also all the PACK ever saw, so a logout STORM, an idle-timeout
  // misconfiguration, a forced re-auth after a token-format upgrade, and a MAC mismatch (a forgery attempt, a
  // security signal) were one undifferentiated silence. These name the branch that fired, engine-side only: the
  // client-facing 401 is byte-identical in every case. Never a token, a MAC, an email or session content.
  "session-fault-malformed", // the cookie was not a well-formed <body>.<mac> token, or its body would not decode/parse (a truncated or corrupted cookie)
  "session-fault-mac-mismatch", // the body did not authenticate under the session signing key: a TAMPERED or FORGED cookie, or a session minted under a signing key this engine no longer holds. A posture signal, not a config fault
  "session-fault-expired", // the session's absolute exp had passed (the ordinary "you were signed in too long" re-auth)
  "session-fault-idle", // the session was idle past SESSION_IDLE_MS (the ASVS V7.3.1 idle timeout): the "logged out mid-shift" ticket when the idle window is tuned too tight
  "session-fault-upgrade-reauth", // the cookie was a valid but PRE-UPGRADE token shape (an unknown/legacy version, or a v3 field the older mint never wrote): a ONE-TIME forced re-auth across a deploy, which is EXPECTED and is exactly what support needs to be able to say
  "session-fault-shape-invalid", // the token authenticated but its claims were internally inconsistent (an oidc/saml session with no connId, a passkey session carrying one, an unusable subject): a corrupt session record
  // --- SAML sign-in START failures: "the SAML sign-in button dead-ends with a 500" ---
  // WHY: recordSsoFail is written only by the ACS (callback) wrapper, so a sign-in that dies while BUILDING the
  // AuthnRequest never reaches ANY recorder: the pack shows ZERO SSO failures and support rules SSO out on a clean
  // aggregate while no user can even reach the IdP. These join the existing sso-start-* family.
  "sso-start-compression-failed", // the AuthnRequest could not be DEFLATE-compressed for the HTTP-Redirect binding (a runtime CompressionStream fault): no redirect URL can be built at all
  // --- outbound BOOTSTRAP / INVITE email send failures ---
  // WHY: "the first-Owner set-up email never arrives" is the single most common bootstrap ticket, and the route
  // answers a NO-ORACLE 200 on every one of its skip reasons (deliberately: the button must not tell an anonymous
  // presser whether an Owner exists). So the operator sees success, the inbox stays empty, and the pack carried
  // NOTHING -- support could not even confirm a send was ATTEMPTED. Role invites are swallowed by design too. Each
  // name below is the CLOSED skip/failure class already computed at the send site and previously thrown away.
  // The no-oracle 200 and the fail-open grant path are both UNCHANGED: this only records, engine-side.
  // Never the recipient address, the link, the invite token or the provider's rejection text.
  "bootstrap-email-console-origin-unset", // CONSOLE_ORIGIN is unset, so no register link can be built and the button silently no-ops
  "bootstrap-email-origin-mismatch", // the request carried a foreign Origin (the route's CSRF shaping refused it)
  "bootstrap-email-owner-unconfigured", // BOOTSTRAP_OWNER_EMAIL is unset or is not a custom-domain address: there is NO pinned inbox to send the first-Owner link to
  "bootstrap-email-binding-unconfigured", // no EMAIL binding is bound on the engine at all: the engine cannot send anything
  "bootstrap-email-from-invalid", // neither INVITE_EMAIL_FROM nor EMAIL_FROM is a usable custom-domain sender
  "bootstrap-email-mint-failed", // the first-Owner invite token could not be minted (the DO round-trip faulted): an availability fault, not a configuration one
  "bootstrap-email-not-available", // the bootstrap path is CLOSED (an Owner exists, or once existed), so no link was minted. The honest answer to "I press the button and nothing arrives"
  "bootstrap-email-send-rejected", // the EMAIL binding REJECTED the send (an un-onboarded sender domain, or a recipient that is not a verified destination): the config is right and the provider refused
  "role-invite-email-binding-unconfigured", // a role was granted but no EMAIL binding is bound: the new admin is never told
  "role-invite-email-from-unconfigured", // INVITE_EMAIL_FROM is unset: invites are off (the honest "not configured" state)
  "role-invite-email-from-invalid", // INVITE_EMAIL_FROM is set but is not a usable custom-domain sender
  "role-invite-email-recipient-invalid", // the GRANTEE's address is not a custom-domain address, so the invite was a no-op: the grant committed and the person was never emailed
  "role-invite-email-send-rejected", // the EMAIL binding REJECTED the invite send; the role grant has already committed, so the person HAS access but was never told how to enrol
  // --- SSO failure SUB-CAUSES: the remediation-bearing half of "SSO broke overnight" ---
  // WHY: the 10 coarse SSO_FAIL_CODES name the STAGE that refused (issuer / key / signature / replay); they do
  // not name the CAUSE, and the cause is what the operator must fix. An EXPIRED Entra client secret answered
  // `invalid_client` at the token endpoint and the engine threw that answer away; a kid-not-found after a JWKS
  // rotation and a duplicate-kid document that refuses the WHOLE JWKS are one "key" code. And two SAML classes
  // were actively MISCLASSIFIED: an IdP-initiated POST at an SP-initiated-only connection filed under `replay`
  // (it is a config toggle, not an attack), and the IdP's own non-Success StatusCode -- the field that says the
  // IdP DECLINED THE USER -- was never read at all and fell into `other`. Each `sso-sub-*` name is selected by
  // classifySsoSubCode from a reason read TRANSIENTLY at the Worker edge and then discarded; only the closed name
  // is ever stored. Spread from the ONE vocabulary in sso-failure-class.ts (a leaf that imports nothing) so the
  // recorder, this closed set and the pack projection (which gates on THIS array) cannot drift apart. Disjoint
  // from every family above by the `sso-sub-` prefix.
  ...SSO_SUB_CODES.map(ssoSubSignalName),
  // --- ROUTER-LOCAL SSO failures + the IdP's OWN error code ---
  // WHY: the SSO-failure aggregate is written by the DURABLE OBJECT, so only failures that REACHED the DO were
  // ever counted. A mangled cross-origin ACS POST, a DO transport fault on the callback, an SP-metadata render
  // that 503s (so the customer's IdP cannot even import the connection) and -- the single most diagnostic
  // artefact in the whole flow -- the IdP's own `?error=` code, which says WHY the IdP declined and was read,
  // used and then discarded, all left ZERO server-side evidence. Spread from the ONE vocabulary in
  // sso-failure-class.ts so the recorder and the projector cannot drift. `error_description` (free prose, the
  // field IdPs put tenant names and addresses in) is never read at all; the error CODE is mapped through a
  // closed registry set, so an attacker-controlled query string can never inject a key here.
  ...SSO_EDGE_CODES.map(ssoEdgeSignalName),
  ...IDP_ERROR_CODES.map((c) => idpErrorSignalName(c)),
  // --- IdP SETUP-TIME evidence: "we tried to add Okta SSO and it never saves" ---
  // WHY: everything the operator learns while WIRING a connection died with the browser tab. The "test
  // connection" probe persisted nothing, and the pure validators refuse a proposal BEFORE any write, so a dozen
  // distinct refusals left no trace at all: remotely, a customer who has been fighting a captive-portal
  // interstitial for two days is indistinguishable from one who never tried. `idp-test-*` counts the probe's
  // closed fail class (idp-diag.ts classifies the probe's detail text, which interpolates the submitted URL and
  // issuer, TRANSIENTLY, and discards it); `idp-validation-refused-*` counts the pre-write refusal class the same
  // way. internal-error is deliberately its OWN class, so a defect in the probe stops reading as a customer
  // misconfiguration.
  ...IDP_TEST_FAIL_CLASSES.map(idpTestSignalName),
  ...IDP_VALIDATION_CLASSES.map(idpValidationSignalName),
  // --- FIRST-OWNER BOOTSTRAP + INVITE ENROLMENT refusals ---
  // WHY: six distinct enrolment refusals collapse to one "forbidden". An EXPIRED invite is deleted-then-refused,
  // so nothing proves it ever existed; a bootstrap enrolment DEMOTED by the consumed latch stores the credential
  // and never records the refused Owner mint ("I ran the bootstrap and I am only a viewer"); an owner-invite bind
  // refused for weak email verification leaves the invite looking unclaimed forever. Each name below is the
  // CLOSED cause the engine already computed and threw away. The client-facing responses are UNCHANGED and stay
  // deliberately coarse, so no class is ever oracled back to a caller (the anti-enumeration property holds).
  // Never the invite token, the target email, or any expiry token material.
  "invite-mint-refused-bad-email", // an invite could not be minted: the target address is not usable
  "invite-mint-refused-role-exists", // an invite was refused because the address already holds a role (it does not need one)
  "invite-mint-refused-latch-consumed", // a FIRST-OWNER bootstrap invite was refused because the one-shot bootstrap latch is already consumed: the documented "email the owner a link" button silently does nothing forever
  "invite-redeem-refused-malformed", // the presented invite token was not well-formed
  "invite-redeem-refused-absent", // no invite record exists for the presented token (never minted, or already burned)
  "invite-redeem-refused-expired", // the invite EXISTED and had lapsed. Recorded BEFORE the delete, so the proof it existed survives the burn
  "invite-redeem-refused-token-mismatch", // an invite record was found and the presented secret did not match it (the bootstrap slot: a re-send OVERWROTE the link the owner is clicking)
  "invite-redeem-refused-already-enrolled", // the invitee already holds an enrolled credential, so the invite path refuses at the write point
  // REMOVED: `invite-redeem-refused-email-mismatch` and
  // `invite-redeem-refused-race-recheck`. Neither had, or could have, a producer.
  //   email-mismatch: the redeeming identity never ASSERTS an address to mismatch. The bound email is taken
  //     FROM the invite record and never from the client field (resolveRegistrationAuthorisation: that is the
  //     account-takeover fix -- WebAuthn proves key possession, not email ownership), so there are not two
  //     addresses to compare and there is no site at which a mismatch could be observed.
  //   race-recheck: register/FINISH re-runs resolveRegistrationAuthorisation, which re-PEEKS the invite. An
  //     invite redeemed or revoked between begin and finish is therefore already reported, precisely, as
  //     `invite-redeem-refused-absent` (plus the ceremony fault passkey-invite-invalid). There is no second,
  //     commit-time invite check that could report anything a distinct class would add.
  "bootstrap-claim-demoted", // a bootstrap enrolment was SILENTLY DEMOTED to viewer because the consumed latch closed the window between begin and finish: the credential is stored and the Owner mint was refused with no trace
  "owner-bind-refused-weak-email-verification", // an owner-invite bind was refused because the IdP did not prove the address (trust-idp off): the invite reads unclaimed forever
  // REMOVED: `owner-bind-refused-native-idp-disallowed` and
  // `owner-bind-refused-emailless-caller`. Neither fault exists in this codebase.
  //   native-idp-disallowed: there is no per-connection "may not bind invites" policy. The native-IdP mint has
  //     exactly two bind gates, and BOTH already have their own producer: `email-verified-bind-blocked` (the
  //     IdP did not assert email_verified, so nothing binds) and `owner-bind-refused-weak-email-verification`
  //     (the connection verifies by policy, not by flag, so an OWNER invite specifically will not bind).
  //   emailless-caller: pending grants are keyed BY EMAIL, so a caller that asserts no address gives the engine
  //     nothing to look one up with. resolveBoundEntry returns before any lookup, and the emailless refusal at
  //     the mint is already recorded as `emailless-assertion`. The engine structurally cannot know whether an
  //     owner invite was waiting, so it could never truthfully say an OWNER bind was the thing refused.
  // --- RBAC AUTHORITY-RESOLUTION degradation + grant-store corruption ---
  // WHY: every one of these SILENTLY COERCES a broken record to a safe default and reports success, so "a member
  // disappeared from the people screen", "three engineers lost console access on Tuesday" (a deleted custom role,
  // holders dropped to viewer), "a JIT elevation never lapsed" (an unparseable expiresAt FAILS OPEN) and "our AD
  // group users all lost their roles" arrive with a clean-looking pack. Counts only: never a grant subject, an
  // email, a group name or a role's capability list.
  "rbac-malformed-role-row-dropped", // a stored role row did not parse and was silently filtered out of the authority resolution: that member VANISHES from the people screen and loses access
  "rbac-malformed-pending-row-dropped", // a stored PENDING (invited) row did not parse and was filtered: the invitee can never bind
  "rbac-provenance-fabricated", // a role row carried no usable provenance and a default was substituted: the audit answer to "who granted this?" is now an engine guess
  "rbac-dangling-custom-role-ref", // a role row names a CUSTOM ROLE that no longer exists: its holders silently drop to viewer. THE "three engineers lost access on Tuesday" signal
  "rbac-expiry-unparseable-fail-open", // a JIT elevation's expiresAt did not parse and the grant FAILED OPEN (it never lapses): a temporary elevation is now permanent
  "rbac-lazy-expiry-demotion", // a grant lapsed and was demoted at READ time (the lazy expiry): the demotion is real and had no record
  "rbac-owner-clamp-fired", // the tamper-clamp on an owner mapping FIRED: a stored mapping claimed an authority the engine refused to honour
  "rbac-groups-param-unparseable", // the caller's groups parameter was corrupt and was coerced to []: every group->role mapping silently stops resolving
  "rbac-group-list-truncated", // the asserted group list was longer than the cap and was truncated: a role-bearing group past the cap is silently invisible
  "rbac-empty-table-with-latch", // the role table is EMPTY while the bootstrap latch is consumed: nobody has authority and nobody can bootstrap (the deadlock), indistinguishable until now from "an account full of viewers"
  "rbac-custom-role-delete-blast-radius", // a custom role was DELETED while it still had holders: bumped once per deletion so the blast radius is a fact rather than a reconstruction
  // --- SESSION LIFECYCLE asymmetry ---
  // WHY: "every user was logged out at once with no terminate-all in the audit chain" is a corrupt session
  // signing key SILENTLY REGENERATING, and the only tell was a suspiciously young key age. The verify-failure
  // spike the diagnosis pairs with that age was never counted; two of the four revocation axes had no counter;
  // a CORRUPT epoch record FAILS OPEN (revoked tokens verify again, a revocation bypass); and an opted-in
  // sign-in-location alert can go inert with nothing saying so. Counts only (4.18's standing rule): never an
  // email, a subject, a connection id or token material.
  "session-signing-key-regenerated", // the in-DO session signing key was REGENERATED (it was absent or unusable): EVERY live session is now invalid. This turns the mass-logout inference into a recorded fact
  "session-revoked-subject-epoch", // a session was refused because it predates its SUBJECT's epoch (the uninstrumented revocation axis)
  "session-conn-liveness-refused", // a session was refused because its IdP connection is no longer live (the other uninstrumented axis: "the whole team on one IdP got signed out")
  // The SPEND-TIME sibling of the line above, and it needs its own count because the operator's remedy is
  // different. A stored governance record (an armed approval, a queued owner action, a queued config change)
  // re-resolves its recorded principal's LIVE authority with no request of theirs in hand; when that principal
  // signed in through a native IdP connection that has since been deleted or disabled, the re-resolution now
  // confers nothing, exactly as their own next request would be refused. Without this counter the approver
  // reads "authority lapsed", which points them at the role table, when the role grant may be perfectly intact
  // and the actual answer is that the connection they authenticate through is gone.
  "replay-conn-liveness-refused",
  "session-epoch-record-corrupt", // an epoch record read back malformed and was coerced to "revoke nothing": a REVOCATION BYPASS -- a session that should have been killed keeps working
  "session-logout-noop", // a logout returned ok having revoked NOTHING (no matching record): the user believes they signed out and their token is still live
  "signin-context-skipped", // an opted-in new-sign-in-location check was SKIPPED (the context could not be read): the alert the owner switched on goes inert
  // The TEMPORAL sibling of the line above, and it needs its own count because it explains an alert rather than
  // an absence. Every row of an operator's coarse seen-context baseline aged past the 90-day TTL, so the check
  // had NOTHING recent to compare this sign-in against. That state is reached by DOING NOTHING AT ALL -- a
  // dormant break-glass Owner is the likeliest operator to reach it and the one whose compromise matters most --
  // and it used to be indistinguishable from a genuine first-ever sign-in, which made the check silently adopt
  // an unrecognised network as the new baseline and then alert on the operator's OWN next sign-in. It is now an
  // alert AND this count, so the pack can answer "why did I get a new-location warning from my own office?"
  "signin-context-baseline-lapsed",
  "group-snapshot-missing", // an SSO session's group snapshot could not be read mid-session, so its group-derived roles silently evaporated for that request
  // --- THE CONSOLE-ORIGIN allowlist ---
  // A request arrived carrying an Origin that does NOT match CONSOLE_ORIGIN, so corsHeaders returned {} and the
  // browser refused the response before the console ever saw it. Move the console to a new hostname (or
  // misdeploy CONSOLE_ORIGIN) and the ENTIRE console goes dead -- while the pack shows a perfectly healthy
  // engine with no admin traffic and NO hint that the origin allowlist is rejecting every preflight. The
  // failure lives only as a browser-side CORS error, and section 6 is explicit that no browser-side state is
  // ever collected. A non-zero count here beside zero admin traffic is that ticket, answered in one line.
  // The Origin header VALUE and the configured CONSOLE_ORIGIN never ride: a count and a timestamp only.
  "cors-origin-rejected",
  // --- The SAML pipeline's own signals (admin/saml-signals.ts) ---
  // The whole SAML pipeline is PURE (no env, no DO stub, no network -- deliberately: it is the security core),
  // so it could never record anything, and three families of evidence died at the call site. Spread from the ONE
  // vocabulary in saml-signals.ts (a leaf that imports nothing) so the sites that NOTE these names, this closed
  // set, the DO's redaction gate and the pack projection cannot drift apart.
  //
  // saml-shape-*: the ATTACK shapes. XSW wrapping (a second root, a second Assertion, a duplicate ID, a
  // second Signature), DTD/XXE probes, attribute pollution, void-canon and a signature that verified over the
  // WRONG NODE all landed in the same `malformed` / `signature` counters as a pretty-printer glitch or a cert
  // rotation -- so the SOC's question ("was that spike an attack?") had no answer. Each is recorded AT the
  // refusal site, which KNOWS the shape, so no classifier ordering rule can misroute it (parser.ts's second-root
  // reason literally names signature-wrapping and was being filed under `malformed`) and no attacker-chosen
  // element name can steer its own classification. The hostile document is never stored.
  ...SAML_ATTACK_SHAPES,
  // sso-*: the SILENT degradations of a sign-in that SUCCEEDED -- which is exactly why no failure record
  // existed for them. A misspelt verified-flag attribute drops a good email (the email-bound role never applies);
  // an unparseable SessionNotOnOrAfter is read as "no bound", so the session OUTLIVES the IdP session.
  ...SAML_DEGRADE_SIGNALS,
  // The START path. A sign-in that dies while BUILDING the AuthnRequest never reaches the ACS, so it never
  // reaches recordSsoFail: "the sign-in button dead-ends with a 500" while ssoFailures reads zero.
  ...SAML_START_SIGNALS,
  // --- THE SECURITY-RELEVANT REFUSALS that were recorded NOWHERE, not even in Workers Logs -----------
  //
  // WHY. Each name below is a refusal the engine ALREADY makes correctly, and then forgets. The refusal itself
  // is the control working; the SILENCE is the gap, and it bites in exactly one place: the post-incident
  // review. "Did anyone replay the retired break-glass token? Did anyone aim the destination probe at
  // 169.254.169.254? Was the stolen session actually revoked at logout?" Those questions have an answer -- the
  // engine refused, or it did not -- and until now the pack could not produce it either way. An unanswerable
  // security question defaults, in practice, to "assume the worst", which is the wrong outcome for a customer
  // whose engine did the right thing.
  //
  // NOISE. None of these fires on a legitimate state. They fire only where the engine REFUSED, or where a
  // guard that should have held demonstrably did not.
  //
  // NO-CUSTODY. Counts and closed names, as with every other member here. Never the attempted endpoint value,
  // the IP, the binding name, the token, the email or the plan.
  "csrf-session-route", // a session-lifecycle route (logout / terminate-all) was refused by the CSRF guard. The double-submit sub-classes name HOW; this names the SURFACE, so "somebody is hammering the session routes cross-site" is legible on its own
  "ssrf-endpoint-refused", // a destination/probe endpoint was refused for resolving to an internal / private / loopback / link-local host (incl. the 169.254.169.254 cloud-metadata address). The SSRF guard HELD; nothing anywhere said it had to
  "reserved-binding-refused", // a restore named one of the engine's OWN reserved bindings as a write target (the confused-deputy attempt). Refused at the sink chokepoint, and previously invisible
  "break-glass-token-refused", // a bare ADMIN_TOKEN was presented to a break-glass-gated route and refused because it is DISABLED or RETIRED. This is the "did anyone try to replay the retired token?" signal, and it is distinct from the admin-token-denied-* family (which covers authorise()'s own precedence path, not these separately-gated routes)
  "lockout-guard-failopen", // the guard that stops an account locking ITSELF out (the last-owner / connection-removal preflight) could not read its inputs and answered fail-SAFE. It was running blind, and the operation it was meant to protect went ahead
  // TWO of the ten names the gap proposed are deliberately NOT here, and the reasons are worth recording:
  //
  //   custody-assert-tripped -- ALREADY CARRIED. The no-custody assertion (an import/export artefact holding a
  //   PLAINTEXT SECRET) is refused and recorded today, as recoveryRefusals {surface, cls:"no-custody"} from
  //   router-identity.ts. A second name for the same event would be duplicate evidence, and two counters that
  //   must be kept in step is how vocabularies drift.
  //
  //   restore-cues-mismatch -- NO SUCH CHECK EXISTS. The blast-radius cues an approver reviews (plannedWrites,
  //   bytes, isLatest, redirectBinding) are supplied on the REQUEST body and are never recomputed at apply
  //   time, so the engine cannot currently detect a doctored cue. Adding the SIGNAL without the CHECK would
  //   ship a counter that can only ever read zero -- dead evidence, which is precisely the failure this
  //   campaign exists to remove. The check itself is a CONTROL change (recompute the cues server-side at
  //   request time, or re-verify them at consume), not a logging change, and belongs in its own piece of work.
  "binding-claim-conflict", // two downpipes claim the SAME binding name as DIFFERENT Cloudflare resources, so the re-attach heal refuses to guess. The affected sources stay unprotected while the heal reports success
  "logout-revoke-failed", // a logout CLEARED the cookie (so the user believes they are signed out) and the session-epoch revocation did NOT land. The stolen copy of that session still works. The single most consequential silent failure on this list
  // A THIRD name the gap proposed is deliberately NOT here, and it was briefly shipped before being removed:
  //
  //   authn-401 -- A TAUTOLOGY THAT CRIED WOLF. It was added as a "sweep detector" on the premise that a
  //   caller presenting no credential matched no deny class. It does: authorise() records
  //   admin-token-denied-empty-bearer for precisely that caller, and has all along. Fired unconditionally on
  //   every refused verdict, authn-401 was the arithmetic SUM of the discriminating rows beside it (retired
  //   token, expired cookie, emailless assertion, rate-limited), so it separated no pair of states. And it
  //   fired on legitimate ones: every expired passkey session and every signed-out browser bumped it, leaving
  //   it permanently non-zero on a healthy tenant, where a probe and a dozen session timeouts read identically.
  //   A duplicate counter that must be kept in step with the rows it duplicates is how vocabularies drift, and
  //   a signal that is loudest when nothing is wrong is worse than an honest silence.
  // --- WHOAMI HEALTH. The identity echo the console builds its ENTIRE view of the operator from ------
  //
  // WHY. /whoami is the one route every screen leans on: the session card, the role chip, the Access
  // enforcement verifier, and every client-side capability gate in the console. When it is unwell the console
  // degrades HONESTLY (it says "not reported", it falls back to the least-privileged viewer, it declines to
  // claim a green "verified"), and that honest degradation is INDISTINGUISHABLE, on this side, from an engine
  // that predates the route. engine.version rules out the pre-whoami build; nothing at all said the route was
  // erroring, or that it was answering with a payload that contradicts itself.
  //
  // NOISE DISCIPLINE: none of these fires on a legitimate state. The bare-token break-glass caller HAS no email
  // by design and is excluded from whoami-caller-unresolvable; a healthy payload cannot trip
  // role-basis-inconsistent, because a role resolved FROM a group must have had a group to resolve from.
  "whoami-server-error", // the identity echo could not be built: the DO whoami round trip answered non-2xx or threw, so the caller was resolved from a body this engine could not trust. Every capability gate in the console then falls to viewer, and a real Owner reports "every control is greyed out, and I own this account"
  "whoami-caller-unresolvable", // the route RAN, the session was authenticated, and no identity came out of it: an email-bearing caller (Access or passkey, never the token break-glass) reached the echo with no email to report. The console's session card reads "not reported" everywhere and the enforcement verifier can never show verified
  "role-basis-inconsistent", // the echo was built with a roleSource that CONTRADICTS the payload beside it: basis `email` with no email, or basis `group` with no groups. The console tells the operator their role comes from their identity-provider groups and then names no group, which is the "my role says it comes from my IdP groups but no group is ever named" ticket
] as const;

// ---- THE TEMPORAL SHAPE (burst vs trickle) and the SATURATION FLAG -------------------------------
//
// The aggregate was deliberately coarse: a closed name -> {count, lastAt}. That is the right redaction posture
// (no identity, no IP, no email is representable), and it is ALSO a diagnosis that cannot be made. "One user
// cannot sign in" arrives, the aggregate shows session-revoked-email-epoch fired 40 times, and a TEN-THOUSAND-
// failure burst an hour ago is byte-identical to a month-long trickle of one a day apart from lastAt -- which
// tells you WHEN it last happened and nothing about WHETHER IT IS STILL HAPPENING. Those are opposite tickets:
// a burst is an incident that is over (an IdP rotation, a deploy), a trickle is a fault that is live right now.
//
// And the count SATURATES. At AUTH_SIGNAL_COUNT_CAP the counter stops moving, so a fleet under a sustained
// attack reads as a fleet that stopped having the problem -- silently, with no marker.
//
// The fix is still COUNTS ONLY, so the redaction contract is unchanged: a 14-slot ring of per-DAY counts, a
// firstAt, and a capSaturated boolean. No identity, no IP, no email, no attribution of any kind is added; the
// buckets are integers. Time-bucketed counts carry no identity.
export const AUTH_SIGNAL_DAY_SLOTS = 14;
export const MS_PER_DAY = 86_400_000;

// The per-name count cap: a flood of a single event re-bumps this ceiling but can never grow storage
// unboundedly. Reaching it latches capSaturated (below), so the pack SAYS the number stopped moving instead of
// quietly presenting a ceiling as a measurement.
export const AUTH_SIGNAL_COUNT_CAP = 1_000_000;

/** ONE signal's bounded aggregate entry. days[0] is TODAY; days[13] is thirteen days ago. */
export interface AuthSignalEntry {
  count: number; // the all-time count (capped)
  lastAt: string;
  firstAt?: string; // when this signal was FIRST seen: "since when?" is half of every one of these tickets
  capSaturated?: boolean; // the count hit AUTH_SIGNAL_COUNT_CAP and is no longer moving: every reading below it is a LOWER BOUND
  dayEpoch?: number; // the day index (floor(ms / 86_400_000)) that days[0] refers to
  days?: number[]; // per-day counts, newest first, AUTH_SIGNAL_DAY_SLOTS long
}

// The bounded aggregate value shape (shared by the recorder and the projector).
export type AuthSignalAgg = Record<string, AuthSignalEntry>;

/**
 * bumpAuthSignalEntry is the PURE day-ring bump (unit-testable with no DO). It ages the ring forward to
 * `now`'s day (dropping anything that has fallen off the 14-day window), adds `n` to today's slot, advances the
 * all-time count against its cap, and latches capSaturated the moment the cap is reached.
 *
 * A gap of 14 days or more zeroes the whole ring, which is correct: nothing in the window happened.
 *
 * `n` EXISTS BECAUSE THE HOT-PATH RECORDER COUNTED WINDOWS, NOT EVENTS. recordAuthSignalThrottled
 * writes a name at most once per minute per isolate, and this function added exactly one per surviving write --
 * so a fleet-wide lockout of 600 rejected session verifies inside one minute recorded `today: 1`, the SAME row
 * as one stale browser tab, and TEN TIMES SMALLER than a harmless ten-per-hour trickle. The tighter the burst,
 * the smaller the pack said it was. The throttle now ACCUMULATES the events it defers and flushes them with a
 * count, so the storage-write rate is unchanged (the DoS property the throttle exists for) while the numbers
 * become event counts. A non-finite or non-positive n is coerced to 1 (a bump is a bump).
 *
 * @param prev - the stored entry, if any (an entry from before this shape existed simply has no ring; it grows one).
 * @param nowMs - the DO clock in epoch millis.
 * @param nowIso - the same instant as an ISO string (injected so the recorder stamps one clock).
 * @param n - how many EVENTS this write carries (default 1; more when a throttled window is being flushed).
 * @returns the new entry.
 */
export function bumpAuthSignalEntry(prev: AuthSignalEntry | undefined, nowMs: number, nowIso: string, n = 1): AuthSignalEntry {
  const today = Math.floor(nowMs / MS_PER_DAY);
  const days = ageAuthSignalRing(prev, nowMs);
  const add = Number.isFinite(n) && n > 1 ? Math.min(AUTH_SIGNAL_COUNT_CAP, Math.floor(n)) : 1;
  days[0] = Math.min(AUTH_SIGNAL_COUNT_CAP, (days[0] ?? 0) + add);
  const count = Math.min(AUTH_SIGNAL_COUNT_CAP, (prev?.count ?? 0) + add);
  return {
    count,
    lastAt: nowIso,
    firstAt: typeof prev?.firstAt === "string" && prev.firstAt !== "" ? prev.firstAt : nowIso,
    ...(count >= AUTH_SIGNAL_COUNT_CAP ? { capSaturated: true } : {}),
    dayEpoch: today,
    days,
  };
}

/**
 * ageAuthSignalRing SHIFTS a stored day-ring forward to `nowMs`'s day and returns it. Pure and total.
 *
 * THE RING WAS AGED ONLY ON WRITE, WHICH IS THE ONE MOMENT IT DOES NOT NEED IT. The shift used to live
 * inside bumpAuthSignalEntry alone, so a ring only ever moved when the signal FIRED AGAIN -- and "it stopped
 * firing" is the entire question the ring exists to answer. A 10,000-failure burst that ended thirty days ago
 * stayed frozen at days[0]=10000 for ever, and the projector, assuming days[0] was today, derived
 * last24h=10000. The pack did not merely fail to discriminate the dead burst from the live one: it AFFIRMED,
 * in the direction that pages someone, that ten thousand failures had happened in the last day, when the true
 * count was zero.
 *
 * Ageing must therefore happen on the READ path too, against the clock the PACK IS BUILT WITH. A signal that
 * has been silent for thirty days then projects days=[0,...,0], today=0, last7dToDate=0 -- while count and
 * lastAt still say "10,000 of these, last seen thirty days ago". That is the row that discriminates, and it is
 * the honest one.
 *
 * THIS IS A UTC CALENDAR-DAY RING, and the projector's field names now say so (support-sections-auth.ts). days[0]
 * is the current day TO DATE, not a rolling 24 hours, and calling it "last24h" was a second false assertion: at
 * 00:30 UTC a burst ninety minutes old sits in days[1] and the pack reported zero in the last day.
 *
 * A gap of AUTH_SIGNAL_DAY_SLOTS days or more zeroes the whole ring, which is correct: nothing in the window
 * happened. An entry stored before the ring existed simply has no ring, and grows one.
 *
 * @param prev - the stored entry, if any.
 * @param nowMs - the clock to age TO (the recorder's DO clock on write, the bundle-build clock on read).
 * @returns a fresh AUTH_SIGNAL_DAY_SLOTS-long ring, newest first, clamped.
 */
export function ageAuthSignalRing(prev: AuthSignalEntry | undefined, nowMs: number): number[] {
  const today = Math.floor(nowMs / MS_PER_DAY);
  const priorDays = Array.isArray(prev?.days) ? prev.days : [];
  const priorEpoch = typeof prev?.dayEpoch === "number" && Number.isFinite(prev.dayEpoch) ? prev.dayEpoch : today;
  // A negative shift (a stored epoch in the FUTURE: clock skew, a restored backup) ages nothing rather than
  // shifting backwards, so a skewed record can never resurrect counts into slots they did not occur in.
  const shift = Math.max(0, Math.min(AUTH_SIGNAL_DAY_SLOTS, today - priorEpoch));
  const days: number[] = [];
  for (let i = 0; i < AUTH_SIGNAL_DAY_SLOTS; i++) {
    const src = i - shift;
    const v = src >= 0 && src < priorDays.length ? priorDays[src] : 0;
    days.push(typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.min(AUTH_SIGNAL_COUNT_CAP, Math.floor(v)) : 0);
  }
  return days;
}

// The single DO storage key holding the whole bounded aggregate.
export const AUTH_SIGNALS_KEY = "authsignals:agg";

export const AUTH_SIGNAL_NAME_SET: ReadonlySet<string> = new Set(AUTH_SIGNAL_NAMES);

// ---- The outbound-email skip/failure mappers ------------------------------------------------------
//
// Both send sites ALREADY compute a closed reason at a single chokepoint (sendBootstrapLink's skip(), and
// sendRoleInvite's { sent:false, reason }); they simply threw it away. These are the total functions that map
// that reason onto the closed auth-signal name, so the recorder never invents a name and an unrecognised reason
// (an upstream wording change) coarsens to a residual rather than silently vanishing OR leaking the string.
//
// PURE and TOTAL: the input is one of the engine's OWN fixed literals, the output is always a member of
// AUTH_SIGNAL_NAMES. No address, link, token or provider text can pass through.

const BOOTSTRAP_EMAIL_SIGNALS: Readonly<Record<string, string>> = {
  "console-origin-unset": "bootstrap-email-console-origin-unset",
  "origin-mismatch": "bootstrap-email-origin-mismatch",
  "owner-email-not-configured": "bootstrap-email-owner-unconfigured",
  "email-not-configured": "bootstrap-email-binding-unconfigured",
  "from-not-configured": "bootstrap-email-from-invalid",
  "mint-failed": "bootstrap-email-mint-failed",
  "not-available": "bootstrap-email-not-available",
  "send-rejected": "bootstrap-email-send-rejected",
};

/**
 * Maps sendBootstrapLink's closed skip reason to its closed auth-signal name.
 *
 * @param reason - the engine's own fixed skip literal.
 * @returns the closed signal name; an unrecognised reason coarsens to the mint-failed residual (an engine-side
 *          fault we could not name) rather than being recorded as text.
 */
export function bootstrapEmailSignalName(reason: string): string {
  return BOOTSTRAP_EMAIL_SIGNALS[reason] ?? "bootstrap-email-mint-failed";
}

const ROLE_INVITE_EMAIL_SIGNALS: Readonly<Record<string, string>> = {
  "invite-not-configured": "role-invite-email-binding-unconfigured",
  "invite-from-not-configured": "role-invite-email-from-unconfigured",
  "invite-from-invalid": "role-invite-email-from-invalid",
  "invite-recipient-invalid": "role-invite-email-recipient-invalid",
  "invite-send-failed": "role-invite-email-send-rejected",
};

/**
 * Maps sendRoleInvite's closed { sent:false, reason } to its closed auth-signal name.
 *
 * @param reason - the engine's own fixed invite-skip literal.
 * @returns the closed signal name; an unrecognised reason coarsens to the send-rejected residual.
 */
export function roleInviteEmailSignalName(reason: string): string {
  return ROLE_INVITE_EMAIL_SIGNALS[reason] ?? "role-invite-email-send-rejected";
}
