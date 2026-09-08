import type { Env } from "../env.d.ts";
import { noteAdminAuthMethod } from "./auth-method-usage.ts";
import { adminRefusalReasonForStatus, noteAdminWriteRefusal, recordAdminRefusal } from "./diag-admin.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import type { AdminCounterName } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { type AdminRuntime, doURL, type RouterCtx, schedulerStub } from "./router-helpers.ts";

// AdminRuntime moved to the leaf router-helpers.ts (so the post-auth route spokes can share its shape
// without importing router.ts); re-exported here so importers that reference it by name from router.ts
// (the Worker fetch entry) are unchanged.
export type { AdminRuntime } from "./router-helpers.ts";
export { doURL, schedulerStub } from "./router-helpers.ts";

// B8-2 god-module split (MOVE-ONLY): handleAdmin (the central method+path dispatch) stays here; the
// route-group HELPERS it calls were moved verbatim into these sibling spokes. router.ts imports them
// and calls them exactly as before; the spokes never import router.ts (the de-cycled boundary that
// router-helpers.ts established is preserved). resolveRollbackTarget is re-exported so the validators
// that import it by name from router.ts keep working unchanged (interface-stable surface).
import {
  adminTokenThrottledResponse,
  attemptedMethod,
  callerHeaders,
  gate,
  jsonError,
  logAuthFailure,
  logAuthSuccess,
  rateLimited,
  requireStepUp,
  STEPUP_SUBS,
} from "./router-core.ts";

export { resolveRollbackTarget } from "./router-core.ts";

import { type AuthDenySink, authorise, type BreakGlassRetiredResolver, type ClaimDropSink, envFlagEnabled, type PasskeySessionVerifier, type TokenRateLimiter } from "./auth.ts";
import { CHANGE_HEADER, CHANGE_NUMBER_TOO_LONG, type ChangeHeaderFault, decodeChangeHeaderWithFault } from "./change-ref.ts";

// CHANGE_REF_FAULT_REASON maps the header fault class onto the closed governance-refusal reason recorded for
// it (sched-fault-ledger.ts GOVERNANCE_REFUSAL_REASONS). It is a total map over the non-null faults rather
// than a ternary, so adding a fourth fault is a TYPE ERROR here instead of silently landing in whichever
// branch the ternary happened to fall through to.
const CHANGE_REF_FAULT_REASON: Record<Exclude<ChangeHeaderFault, null>, string> = {
  garbled: "change-ref-garbled",
  truncated: "change-ref-truncated",
  "over-length": "change-ref-over-length",
};
import {
  canonicalEmail,
  isCookieBorneMethod,
} from "./identity.ts";
import { handleAccountSession } from "./router-account-session.ts";
import { handleAttest } from "./router-attest.ts";
import { handlePasskey } from "./router-auth-flow.ts";
import { handleConfigVersion } from "./router-config-version.ts";
import { handleCustody } from "./router-custody.ts";
import { handleDestinations } from "./router-destinations.ts";
import { handleDiscovery } from "./router-discovery.ts";
// The post-auth route spokes (the dispatch-split): handleAdmin authorises ONCE, resolves the caller, runs
// the CSRF + step-up + dynamic-route gates exactly as before, then dispatches the body of each route group
// to one of these. Each takes the RouterCtx the hub builds and returns the route's Response, or null when
// no case in that spoke matched (the hub then tries the next spoke, as the original single switch fell to
// its next case; the route keys are unique, so the chain order is behaviour-irrelevant but kept textual).
import { handleControlPlaneRecoveryAck } from "./router-control-plane-recovery-ack.ts";
import { handleControlPlaneStatus } from "./router-control-plane-status.ts";
import { handleIdentity } from "./router-identity.ts";
import { handleOidc, handleSaml } from "./router-idp-web.ts";
import { handleKeys } from "./router-keys.ts";
import { routeDualControlDisarmAlert } from "./router-notify.ts";
import { handleOps } from "./router-ops.ts";
import { handleOtlpPush } from "./router-otlp-push.ts";
import { handlePipelines } from "./router-pipelines.ts";
import { handleReport } from "./router-posture.ts";
import { handlePush } from "./router-push.ts";
import { handleRbac } from "./router-rbac.ts";
import { handleRestore } from "./router-restore.ts";
import { handleRetentionPrune } from "./router-retention-prune.ts";
import { adminTokenRateLimitedViaDO, breakGlassRetiredViaDO, resolveCaller, verifyPasskeySessionViaDO } from "./router-session.ts";
import {
  handleEstateSize,
  matchConfigChangeAction,
  matchOwnerActionAction,
} from "./router-sources.ts";
import { handleStatus } from "./router-status.ts";
import { handleUpdates } from "./router-updates.ts";
import { originFailClass, sessionSetCookie } from "./session.ts";

// The admin API the in-account console calls. Every route forwards to the scheduler
// Durable Object, which is the single authority for schedules, the run lock and the
// runlogIndex. There is no inbound path from the vendor; this surface is reached only by
// the customer's own console within their account.
//
// OWN-SURFACE DEVIATIONS (§12, B6-2): the /admin surface deliberately does NOT carry a `/v0/`
// URL version prefix and does NOT implement Idempotency-Key. Both are owner-recorded deviations,
// not gaps: /admin is a PRIVATE, console-proxied RPC surface (no public hostname, no third-party
// consumer), and the console proxies these exact paths verbatim, so introducing /v0/ would break the
// console-to-engine wiring for zero external benefit. Idempotency-Key is likewise omitted because the
// only mutating callers are the single in-account console and the cron driver, which already de-dupe
// via the run lock and the runlogIndex. The low-risk §12 improvements (CORS max-age, GET /ready,
// RFC 9457 problem+json bodies, RateLimit/RateLimit-Policy headers) ARE applied.
//
// Routes (all under /admin). THIS LIST IS A CURATED SUBSET, NOT THE DISPATCH'S OWN SET, and saying so is
// the point: it is chosen for a reader arriving at the surface cold. The authority on what exists is the
// `case "<METHOD> <path>"` labels in the router-*.ts spokes, and nothing derives from this block. AN ABSENCE
// HERE IS NOT EVIDENCE A ROUTE DOES NOT EXIST. That is not a caveat for tidiness: POST /admin/keys/add-
// operational was missing from this list while the removal route below sat in it labelled "irreversible",
// and five separate statements across this repo and the docs site inherited that false premise from the gap
// rather than from a wrong sentence.
//
// COVERAGE, MEASURED RATHER THAN CHARACTERISED: 51 CATALOGUED OF 160 DISPATCHED. Both numbers are asserted
// against a scan of the spoke source by test/validate-admin-route-manifest.ts, so adding a route without
// touching this block turns that validator red instead of quietly widening the gap the disclaimer above
// describes. "Roughly a third" is what this line used to say, and a prose fraction is the one form of this
// claim that can never be wrong and never be checked. A further 5 lines below carry routes that are real but
// are NOT `case` labels (the pre-switch surfaces: the health probe, the two /auth/* recovery routes, and the
// dynamic-id config-change approve/reject pair); those are declared in that validator, so a catalogue line
// naming a route the dispatch does not have is red too.

//   GET  /admin/downpipes        list configured downpipes + their state, the stored records verbatim (every SourceSpec, destination id and retention policy) (downpipe.read)
//   POST /admin/downpipes        add or update a downpipe {id,name,cadenceSeconds,enabled}
//   POST /admin/downpipes/bulk   {downpipes:[...]} create/upsert MANY in one call (each item runs the same gated single-upsert path; continue-on-error; per-item results; capped per request, the cap echoed as maxBatch on an oversized batch) (downpipe.write)
//   POST /admin/trigger          {id} run a downpipe now (allocates a run id + index)
//   POST /admin/restore          {runId,confirm?,target?,include?,exclude?,maxRecords?,recordName?} dry-run restore plan; confirm to write data back (an apply needs Approver/Owner AND a dual-control approval, maker != checker). recordName = GRANULAR single-record restore (exact name; plans + applies EXACTLY one record)
//   POST /admin/restore/verify   {runId,include?,exclude?,maxRecords?} BLIND restore test: decrypt every in-scope record to a discard sink, verify each hash, return counts + restoreDigest, NEVER any plaintext (restore.verify). ok is false whenever the run itself holds zero records (a genuinely empty source) as well as on a genuine per-record or freshness failure -- "zero records is not a pass" -- but the FORMER case also carries nothingToVerify:true + reason (WIRE-28), so a caller must read that pair before treating a bare ok:false as a broken archive: a fresh seal against a not-yet-seeded source answers {ok:false,nothingToVerify:true,reason:"the run holds no records..."}, never a bare {ok:false}

//   POST /admin/restore/attest   {runId} KEYLESS Tier 0 attestation: signature + completeness + anti-rollback, no key and no data (restore.verify)
//   POST /admin/attest/session/create  {scope?,sampleRate?} ATTENDED verification (key-posture attend): pin the LATEST completed run per selected downpipe (omit scope = all enabled), issue the live-possession challenge bound to the break-glass public, and open a session (drill.run + STEP-UP; one active session/account; the break-glass token cannot own one)
//   POST /admin/attest/session/prove   {sessionId,proofB64} prove live possession of the break-glass private (the challenge round-trip); flips the session proven (owner-bound: caller subject == creator) (drill.run)
//   POST /admin/attest/session/capsules {sessionId,runIds} serve the run capsules the browser needs to recover each PINNED run's master locally (never a capsule for a non-pinned run) (drill.run; owner-bound; session proven)
//   POST /admin/attest/session/verify  {sessionId,batch:[{runId,masterB64}]} sample-decrypt each PINNED run from the browser-supplied master to a discard sink; stamp the result; the masters are used only in-request and NEVER stored (drill.run; owner-bound; session proven; batch capped)
//   GET  /admin/attest/session/status  ?id=<sessionId> the session (proof hash stripped) (drill.run; owner-bound)
//   POST /admin/attest/session/abort   {sessionId} end the session (frees the one-active slot) (drill.run; owner-bound)
//   POST /admin/retention-prune/candidate  {downpipeId} serve the retained+superseded candidate runs' non-secret master capsules for a downpipe's CURRENT prune split, so the browser can recover each run's master locally before a request/apply (restore.verify)
//   POST /admin/retention-prune/request    {downpipeId,reason} raise a dual-control prune request bound to a KEYLESS planHash over the downpipe's current split (restore.request)
//   POST /admin/retention-prune/approve    {planHash} approve another's prune request (restore.approve, maker != checker; STEP-UP)
//   POST /admin/retention-prune/reject     {planHash,rejectReason?} reject a pending prune request (restore.approve)
//   GET  /admin/retention-prune/approvals  the pending prune-approval inbox (Approver/Owner see all; a requester sees their own)
//   POST /admin/retention-prune/apply      {downpipeId,batch:[{runId,masterB64}],previewOnly?} plan (and, only when this downpipe's OWN stored retention.enforce is true, previewOnly is not set, AND a usable dual-control approval for this exact plan exists, apply) a prune from browser-recovered per-run masters -- the break-glass-only posture's no-CLI replacement for `downpipe prune` (restore.apply; STEP-UP; batch capped; mandatory 100% candidate-coverage precheck before any delete)
//   POST /admin/restore/request  {runId,target?,include?,exclude?,maxRecords?,reason} raise a restore request bound to the plan hash (Operator+)
//   POST /admin/restore/approve  {planHash} approve another's restore request (Approver/Owner, maker != checker)
//   POST /admin/restore/reject   {planHash} reject a restore request (Approver/Owner)
//   GET  /admin/restore/approvals the pending-approval inbox (Approver/Owner see all; a requester sees their own)
//   GET  /admin/history          per-downpipe recent-run ring (?id=<downpipeId>), or all rings when id is absent (downpipe.read)
//   GET  /admin/runs/at          POINT-IN-TIME resolution (?downpipe=&at=<rfc3339>) -> the latest SUCCESSFUL run completed at-or-before T (runId+completedAt) from the retained ring, or an honest miss with the retained-window bounds (downpipe.read)
//   GET  /admin/rto              the RTO estimate (?id=<downpipeId> optional) -> per-downpipe + fleet recovery-time estimate derived from observed restore-test throughput, with a "based on N drills" caveat and an honest "unknown" when there is no drill history (reports.read)
//   GET  /admin/replication      per-destination replication state (?id=<downpipeId>, or all): N-of-M copies + which destination is down (downpipe.read)
//   GET  /admin/licence          the effective assurance tier (fail-open: a licence problem yields tier 'community')
//   GET  /admin/status           config-presence booleans for onboarding (NEVER a secret value)
//   POST /admin/keys/install     install the in-browser key ceremony's output as the engine's OWN worker secrets via a one-shot deploy token the operator scopes to "Edit Cloudflare Workers" (the engine shape-checks it, never verifies its Cloudflare scope; no customer CLI; Owner; keys.ceremony; token+private values never stored/logged, audited by name)
//   GET  /admin/keys/vintages    KEYLESS key-vintage inventory (G-P0-098 + G-P0-099 surfacing): which archive vintages each key opens, which runs are stranded to a key NOT currently installed, and the signer-continuity rollup for the re-key surface, each verdict derived from the run's SIGNATURE-VERIFIED root manifest read back keylessly (no recorded index); PUBLIC dpr1:/edmldsa1: fingerprints + closed roles + counts only, never a key (downpipe.read)
//   POST /admin/keys/add-operational  install ONLY a fresh OPERATIONAL_PUBLIC/OPERATIONAL_PRIVATE pair on a break-glass-only engine, through the same one-shot scoped token (Owner; keys.ceremony; STEP-UP). SIGNER_PRIVATE and BREAK_GLASS_PUBLIC are never read or written, so every existing run stays signed by the same signer; REFUSES when an operational key is already present (replacing one is the full re-key ceremony's job). This is the RETURN ROUTE from the break-glass-only posture below
//   POST /admin/keys/break-glass-only  remove BOTH operational worker secrets (Owner; keys.ceremony). The deleted KEY MATERIAL is unrecoverable and archives sealed to it never regain an operational recipient (the recipient set is baked in at seal time and is never rewrapped), but the POSTURE is reversible: POST /admin/keys/add-operational above installs a fresh pair and clears the OPERATIONAL_RETIRED marker. GUARDED (G-P0-098): refuses with 409 {discardGuard} when removing the operational key would strand an archive it alone opens (or when the impact cannot be fully determined), unless confirmDiscardStranded is set (the deliberate, warned path)
//   GET  /admin/health           liveness
//   POST /admin/drill-all        {downpipeIds?} start an ON-DEMAND bulk restore-test campaign over the whole fleet (or a subset); the cron drains it capped-per-tick under the shared budget (drill.run)
//   GET  /admin/drill-all        the fleet-drill progress (active campaign or the last finished one)
//   POST /admin/drill-evidence   record a drill or offline-rehearsal evidence entry (Operator+)
//   GET  /admin/drill-evidence   list all drill-evidence entries newest-first (any role)
//   POST /admin/policy/require-access  surface the Access-only (ADMIN_TOKEN_DISABLED) posture for the console (access.policy; P9/console-access-1)
//   POST /admin/policy/retire-break-glass-token  retire the ADMIN_TOKEN bearer in-app (engine stops honouring it immediately, no redeploy) (Owner; keys.ceremony; REFUSED unless a way back in exists: recovery codes for an Owner OR a 2nd Owner)
//   POST /admin/auth/recovery    recovery-code sign-in {email, code}: a NORMAL signed session for that email's role (UNAUTHENTICATED, BEFORE the gate; hard rate-limited per IP+email, fail closed; generic on failure)
//   POST /admin/auth/recovery-codes/regenerate  mint a fresh recovery-code set for the CALLER'S OWN email, invalidating prior codes; returns the plaintext ONCE (authenticated inside; self-service)
//   POST /admin/auth/recovery-codes/confirm  promote a STAGED recovery-code set (minted on a self-add enrolment over an existing live set) to live, the actual invalidation of the old set; a no-op when nothing is staged (authenticated inside; self-service; STAGED-RECOVERY-CODES-CONFIRM-GATE)
//   GET  /admin/group-roles      the OPTIONAL identity-provider group->role mapping (any role, enforced as roles.read like GET /admin/roles)
//   POST /admin/group-roles      map an IdP group to a role {group, role = any role except owner} (Owner; a group can never map to owner)
//   POST /admin/group-roles/delete  remove a group->role mapping {group} (Owner)
//   POST /admin/coverage/inventory  store the reference resource inventory {kv,r2,d1,secrets} (access.policy; reference data only, never grants data access)
//   GET  /admin/coverage         the gap view: per-resource protected/unprotected/untested + rollup, honest-unknown when no inventory (posture.read)
//   POST /admin/config/snapshot  capture the current config posture as a new signed history version now (access.policy; de-dupes against the head)
//   GET  /admin/config/history   the config version history newest-first (id, at, author, parentHash, summary) + chain head + verify verdict (downpipe.read)
//   GET  /admin/config/version   one full config version (header + snapshot) by ?id=N (downpipe.read)
//   GET  /admin/config/diff      the plain-English (Australian) change list between two versions ?from=&to= (downpipe.read)
//   GET  /admin/config/approval-policy  the OPT-IN dual-control change-control gate flag (downpipe.read)
//   POST /admin/config/approval-policy  toggle the gate {requireConfigApproval} (Owner-only; applies immediately)
//   GET  /admin/config/changes   the PENDING config-change inbox (each with its plain-English diff) (downpipe.read)
//   POST /admin/config/changes/<id>/approve  approve a pending change (maker != checker, same write cap as the original mutation; the DO enforces both, plus no stale/superseded apply)
//   POST /admin/config/changes/<id>/reject   reject (discard) a pending change (same write cap as the original mutation)
export async function handleAdmin(req: Request, env: Env, runtime?: AdminRuntime, slide?: { cookie: string | null }): Promise<Response> {
  // fireInBackground: the same keep-alive helper handlePasskey
  // introduced, defined here too since onAuthDeny/onClaimDrop/the CSRF-fail branch/the change-ref fault
  // branch all fire diagnostic writes before this function's OWN return, several with no further await on
  // the reachable path (the CSRF-fail branch answers its 403 immediately after firing). runtime is
  // undefined only for a direct handleAdmin call with no fetch runtime (a unit test), which falls back to
  // the pre-existing bare-void behaviour unchanged.
  const fireInBackground = (task: Promise<unknown>): void => {
    if (runtime?.waitUntil) runtime.waitUntil(task);
    else void task;
  };
  const url = new URL(req.url);
  if (url.pathname === "/admin/health") {
    return new Response(JSON.stringify({ ok: true, service: "downpipe-engine" }), { headers: { "content-type": "application/json" } });
  }
  // The engine's OWN passkey sign-in front door (WebAuthn), independent of Cloudflare Access (which is
  // not free over 50 users). These four routes are the multi-user authentication FLOW itself, so they
  // are handled BEFORE the authorise() gate below: requiring a prior credential to obtain one would be
  // circular. They are unauthenticated by necessity but NOT unprotected: registration and login both
  // bind to a server-issued, single-use, short-TTL challenge, verify the origin against CONSOLE_ORIGIN
  // and the rpIdHash against the rp.id, and (login) verify the assertion signature with the stored COSE
  // key and run clone detection, all in the scheduler DO (the storage + verification authority). The
  // first registrant bootstraps to Owner exactly like the Access bootstrap. See handlePasskey.
  if (url.pathname.startsWith("/admin/auth/")) {
    // G177: THE HUB'S REFUSAL RECORDER, HOISTED OVER THE PRE-AUTH EDGE. The frozen route table holds
    // "POST /auth/recovery-codes/regenerate" -- the gap's own stated worst case -- and that key was DEAD: the
    // table is looked up in the dispatch loop at the bottom of this function, and this early return leaves 214
    // lines before `sub` is even computed, so the regenerate's answer never passed the recorder. The surface was
    // real, the reason map was real, and no request on earth could reach either.
    //
    // The recorder is the same one, called with the same /admin-relative path shape the table is keyed on, so
    // the route templates stay in ONE place. Every other /admin/auth/* route (the WebAuthn ceremonies, the
    // recovery sign-in, the bootstrap send) is absent from the table and therefore records nothing, which is the
    // right answer: a fumbled passkey ceremony is not a refused admin write, and a row for it would be noise on
    // the sign-in path. A throw is recorded as the 500 the outer catch will answer with, then rethrown unchanged.
    const authSub = url.pathname.replace(/^\/admin/, "");
    // schedulerStub resolves the DO id SYNCHRONOUSLY and throws on an unbound env, so the note is contained:
    // an engine whose DO binding is missing must still answer the sign-in route exactly as it did before, and a
    // recorder must never become the thing that breaks the front door.
    const noteAuth = async (status: number): Promise<void> => {
      try {
        await noteAdminWriteRefusal(schedulerStub(env), req.method, authSub, status);
      } catch {
        /* best-effort: the evidence is never worth the route */
      }
    };
    let authResp: Response;
    try {
      // runtime carries waitUntil: handlePasskey fires diagnostic auth-signal writes as its LAST
      // action before returning, with no await left to give them a scheduling window, so they need the same
      // ctx.waitUntil keep-alive sealNow/canaryNow already get. runtime is undefined only for a direct
      // handleAdmin call with no fetch runtime (a unit test), which handlePasskey falls back from unchanged.
      authResp = await handlePasskey(req, env, url.pathname.slice("/admin/auth/".length), runtime);
    } catch (e) {
      await noteAuth(500);
      throw e;
    }
    await noteAuth(authResp.status);
    return authResp;
  }
  // The native external-IdP (OIDC) sign-in FLOW, the analogue of the passkey front door: reached at
  // /admin/oidc/* BEFORE the authorise() gate (obtaining a session cannot require a prior session). It is
  // under /admin/* so the console proxies it VERBATIM (an /auth/oidc/* path would 404 -> the SPA and leak the
  // authorization code into JS). The flow itself is unauthenticated by necessity but bound by the single-use
  // state record + the __Host- txn cookie + the per-connId callback path; the DO is the verification authority.
  if (url.pathname.startsWith("/admin/oidc/")) {
    return handleOidc(req, env, url.pathname.slice("/admin/oidc/".length), runtime);
  }
  // The native SAML 2.0 SP flow (metadata / SP-initiated start / the cross-origin ACS POST), reached at
  // /admin/saml/* BEFORE the authorise() gate (same reason as the OIDC flow). The ACS is an IdP-driven
  // cross-origin POST that carries no SameSite cookie, so it is NOT subject to the cookie-CSRF Origin guard
  // below (it never reaches it); its anti-CSRF/replay defence is the single-use RelayState + the InResponseTo
  // binding enforced in the DO. Under /admin/* so the console proxies it verbatim.
  if (url.pathname.startsWith("/admin/saml/")) {
    return handleSaml(req, env, url.pathname.slice("/admin/saml/".length), runtime);
  }
  // DEMO-ONLY reset surface (POST /admin/demo/reset): it EXISTS only when DEMO_MODE is configured (the
  // throwaway demo engine). In PRODUCTION (no DEMO_MODE) it 404s HERE, before any auth or DO round-trip,
  // so production has no reset surface to find or invoke. When DEMO_MODE IS set, the request falls through
  // to authorise() and the switch case below, which requires the ADMIN_TOKEN break-glass bearer.
  if (url.pathname === "/admin/demo/reset" && !envFlagEnabled(env.DEMO_MODE)) {
    return new Response("not found", { status: 404 });
  }
  // Authorise ONCE and carry the identity (D1), instead of collapsing to a boolean. Precedence is
  // Access > passkey session > ADMIN_TOKEN; a present-but-invalid Access assertion OR a present-but-invalid
  // passkey session is denied here and never downgraded to a weaker method (auth.ts preserves that); the
  // 401 stays plaintext "unauthorised" so the console can distinguish a sign-in failure from a capability
  // gate (the 403 below is JSON). The passkey verifier performs the DO round-trip that validates the
  // session cookie against the signing key the DO holds (the key never leaves the DO); it is wired here so
  // authorise() stays the pure precedence logic. The scheduler stub is resolved LAZILY inside the verifier
  // closure (schedulerStub(env)) so a request with NO session cookie never resolves the DO id at all:
  // authorise() invokes the verifier only when it actually reads a cookie, so a non-passkey request (and a
  // caller whose env binds no SCHEDULER, e.g. a unit test of the unauthenticated 401 path) never touches the
  // DO here. The authenticated path below builds its own scheduler stub once, after the auth gate.
  // The onSlide sink lets the DO refresh the session cookie (ASVS V7.3.1 idle-slide) without changing the
  // authorise() verifier contract: when the DO re-mints a stale-lastSeen session, we stash the hardened
  // Set-Cookie on the shared `slide` holder, and the index.ts wrapper appends it to the rebuilt response.
  const verifyPasskeySession: PasskeySessionVerifier = (token) =>
    verifyPasskeySessionViaDO(schedulerStub(env), token, (slid) => {
      if (slide !== undefined) slide.cookie = sessionSetCookie(slid);
    });
  // The break-glass-retired resolver is wired the same way: authorise() consults it ONLY on the bare-token
  // path (after Access + passkey), and the scheduler stub is resolved LAZILY inside the closure so an
  // Access/passkey/no-credential request never resolves the DO id for this check. A retired token is then
  // refused at the gate exactly as ADMIN_TOKEN_DISABLED refuses it (the effective predicate is the env flag
  // OR the durable retire latch); the resolver fails closed (deny) on a DO hiccup. See breakGlassRetiredViaDO.
  const breakGlassRetired: BreakGlassRetiredResolver = () => breakGlassRetiredViaDO(schedulerStub(env));
  // ANTI-BRUTE-FORCE (ASVS V6.3.1): wired the same lazy way as breakGlassRetired just above, so an
  // Access/passkey/no-credential request never resolves the DO id for this check either; authorise()
  // consults it only once a bare token is actually configured and presented. See adminTokenRateLimitedViaDO.
  const tokenRateLimited: TokenRateLimiter = (r) => adminTokenRateLimitedViaDO(schedulerStub(env), r, runtime);
  // P3 + G001: record WHY authorise() denied, as a closed signal in the DO's bounded auth-signal aggregate, so the
  // whole family of byte-identical generic 401s becomes diagnosable from the pack: a failed Access assertion (wrong
  // AUD, team-domain typo, stale-JWKS key rotation), a VERIFIED-but-unusable Access assertion (a service token with
  // no email, an IdP asserting no sub), a present-but-invalid session cookie ("logged out mid-shift"), and each
  // bare-token deny class (fallback disabled, no token configured, empty bearer, retired, mismatch). Best-effort and
  // fire-and-forget; the DO drops an out-of-vocabulary name and the diagnostic write never delays or alters the deny.
  // The 401 the caller sees is unchanged and stays generic, so no deny class is ever oracled back to an attacker.
  // The try/catch is load-bearing, not belt-and-braces: schedulerStub(env) resolves the DO id SYNCHRONOUSLY and
  // THROWS when the SCHEDULER binding is absent (an unbound/partial env), so a bare `.catch()` on the fetch
  // promise would not contain it -- the throw would escape the sink, unwind through authorise(), and turn a
  // clean generic 401 into a 500. That is an availability regression AND an oracle (a 500-vs-401 split tells an
  // attacker which deny class they hit). The diagnostic write is best-effort by contract: it must never delay,
  // alter or fail the deny.
  //
  // G331: the write is CHECKED. It was a bare .catch(() => {}), so during a DO outage every auth-deny signal
  // was dropped SILENTLY and the pack showed a QUIET authSignals aggregate for the exact window the customer
  // reports as a total lockout -- absence of evidence reading as absence of problems, the audit's meta-finding.
  // recordDiagWrite counts the loss in droppedWrites, so an incomplete pack SAYS it is incomplete. The deny
  // itself, and the generic 401 the caller sees, are unchanged.
  const onAuthDeny: AuthDenySink = (name) => {
    try {
      const scheduler = schedulerStub(env); // throws SYNCHRONOUSLY on an unbound env: contained here, not by a .catch
      fireInBackground(
        recordDiagWrite(scheduler, "auth-signal", () =>
          scheduler.fetch(doURL("/auth-signal"), { method: "POST", body: JSON.stringify({ name }), headers: { "content-type": "application/json" } }),
        ),
      );
    } catch {
      // No DO binding (or the stub would not resolve): the deny still happens, just without its signal.
    }
  };
  // G271: the twin of onAuthDeny for the ADMITTED path. A verified Access assertion whose group claim was
  // bounded away signs the user IN -- with the wrong role -- and used to record nothing at all, so
  // "present but dropped" was indistinguishable from "the IdP sent nothing". The sink bumps a CLOSED
  // admin counter naming the boundary and the drop kind; the group name never crosses the wire, and the
  // caller's verdict is untouched. Fire-and-forget, and contained the same way (schedulerStub can throw).
  const onClaimDrop: ClaimDropSink = (name) => {
    try {
      fireInBackground(bumpAdminCounter(schedulerStub(env), name as AdminCounterName));
    } catch {
      // No DO binding: the sign-in still happens, just without its drop counter.
    }
  };
  const verdict = await authorise(req, env, verifyPasskeySession, breakGlassRetired, onAuthDeny, tokenRateLimited, onClaimDrop);
  // THE THROTTLE ANSWERS 429, NOT 401. Every other deny below stays a byte-identical generic 401 on purpose,
  // so no deny class is oracled back to an attacker. This one is different in kind: the anti-brute-force
  // limiter fires BEFORE tokenEqual (auth.ts), so it refuses a correct and an incorrect token identically and
  // leaks nothing about either. Answering 401 for it was actively harmful, because a rate limit and a session
  // loss then look the same to every caller: the console's isUnauthorised() signs the operator out, so a
  // throttled approvals lookup could end an operator's session in the middle of a restore. Retry-After makes
  // the difference actionable rather than merely visible.
  //
  // It answers through the SHARED builder (adminTokenThrottledResponse), not a hand-built Response. Changing
  // the status was only half the contract: this 429 first shipped as a plaintext body with no content-type
  // and a hard-coded retry-after, while the engine's other three 429s are RFC 9457 problem+json carrying
  // `error: "rate limited"`, which is the field the published contract tells an integrator to match on. A
  // caller doing what the docs say got a JSON parse failure on this one and nothing to match. One producer
  // now serves all four, so the shape cannot go almost-right again.
  if (!verdict.ok && verdict.throttled === true) {
    logAuthFailure(attemptedMethod(req), "bare-token rate limit; refused before any credential compare");
    return adminTokenThrottledResponse();
  }
  if (!verdict.ok) {
    // V16.3.1: log the authentication FAILURE at the auth boundary. authorise() returns a bare
    // { ok: false } with no method, so the attempted method is derived from the request shape
    // (an Access assertion was presented vs the bare-token path), exactly as auth.ts decides which
    // credential to check. The line is coarse and carries NO token, NO assertion and NO email (an
    // unverified assertion's "email" is untrustworthy and would be unwanted PII), only the attempted
    // method and a short reason. The 401 plaintext shape is unchanged.
    logAuthFailure(attemptedMethod(req), "authorise rejected the presented credential");
    // G314: there is DELIBERATELY no counter here, and its removal is the fix.
    //
    // An "authn-401" signal was added on the premise that a caller presenting NO credential matched no deny
    // class and so left no durable trace. That premise is false: authorise() records
    // admin-token-denied-empty-bearer for exactly that caller (auth.ts), and it has been a pack-visible member
    // of this vocabulary all along. Every other refusal -- a retired token replayed, an expired cookie, a stale
    // automation bearer, an emailless assertion, a rate-limited sweep -- ALREADY has its own discriminating
    // row. Firing unconditionally on every !verdict.ok made this counter the arithmetic SUM of those rows: it
    // separated no pair of states, which is the one job it was added to do.
    //
    // Worse, it fired on LEGITIMATE states. Every 12-hour passkey session that expires, every signed-out
    // browser that touches an admin route, every unconfigured automation trips it, so on a healthy tenant it
    // is permanently and monotonically non-zero. A reviewer asking "were we probed last Tuesday?" could not
    // tell a probe from a dozen sessions timing out: same count, same day-ring shape. A false signal on a hot
    // path is worse than no signal, because it costs a support engineer the time an honest silence would not.
    return new Response("unauthorised", { status: 401 });
  }
  // SECURITY (ENG-B1), defence in depth: an authenticated EMAIL-BEARING caller (Access OR passkey) must
  // carry a usable verified email. authorise already fails closed on an emailless Access assertion, passkey
  // session or native oidc/saml session; reject here too so NO email-bearing method can ever reach the Owner
  // break-glass resolution (reserved exclusively for the bare-token path). Only the token method is exempt:
  // it is the email-less break-glass by design (hence `!== "token"` covers access | passkey | oidc | saml).
  if (verdict.method !== "token" && !canonicalEmail(verdict.email)) {
    // V16.3.1: the second 401 path is the emailless-(Access|passkey) rejection. The method is known, and
    // the reason is the missing verified email; no token/assertion/email value is logged (the email is
    // precisely what is absent or unusable here). The 401 plaintext shape is unchanged.
    logAuthFailure(verdict.method, "session verified but carried no usable email (ENG-B1)");
    return new Response("unauthorised", { status: 401 });
  }
  // The caller is now authenticated, so the scheduler DO (the role + state authority every route below
  // forwards to) is resolved here, AFTER the auth gate. Building it earlier would resolve the DO id on a
  // no-credential request that should simply 401 (and on a test env that binds no SCHEDULER); the passkey
  // session verifier above builds its own lazily, only when a cookie is actually presented.
  const scheduler = schedulerStub(env);
  // Resolve the caller's role ONCE (D3). The token fallback is the documented break-glass and
  // resolves to owner (it cannot be attributed, so it is all-or-nothing); an Access OR passkey caller's
  // role comes from the DO role table keyed by the verified email (with the first such caller
  // bootstrapped as Owner). Everything below gates on caller.role server-side; the console
  // mirrors these gates but never replaces them. isOnlyOwner is resolved in the same DO lookup
  // so whoami needs no second round trip.
  // The source IP for the audit trail, read once from the edge header Cloudflare injects, BEFORE the role
  // resolution rather than after it. G346: the role resolution is not a pure read. On a fresh Access-fenced
  // engine the console's very first GET /admin/whoami IS the first-owner bootstrap, and it writes an audit
  // row (bootstrap-consumed) attributed to that human. Reading the header afterwards meant the engine HELD the
  // address and dropped it on the floor for exactly that row, so a healthy, freshly onboarded estate booked a
  // permanent +1 on the missing-source-IP capture-fault counter and read, in the pack, as a capture path
  // failing right now. It is threaded into resolveCaller for that one write and re-used by every router-
  // recorded draft below.
  const sourceIp = req.headers.get("CF-Connecting-IP");
  const { caller, isOnlyOwner, roleSource, customRole } = await resolveCaller(scheduler, verdict, sourceIp);

  // G253: RECORD WHICH CREDENTIAL PATH THIS REQUEST AUTHENTICATED ON. The engine has always classified it
  // (caller.method is the closed access | passkey | oidc | saml | token set) and has always thrown it away, so
  // "was this estate behind Access when the change was made, and how long did it run on the shared break-glass
  // token?" was unanswerable from the pack: the only disclosure was an amber console chip that dies with the
  // browser tab, and the audit excerpt carries no authn events at all.
  //
  // Recorded HERE, before the CSRF gate and before any route, so it counts the method that AUTHENTICATED the
  // request whatever a later gate does with it -- a break-glass caller refused downstream still ran on the token.
  // Fire-and-forget, throttled edge-side to at most one DO write per method per minute per isolate (a status
  // poll must not become a storage write), and it can never fail or delay the request. Counts and stamps only:
  // never the session, the email, the subject or the IP.
  fireInBackground(noteAdminAuthMethod(scheduler, caller.method));

  // CSRF (defence in depth on top of the cookie's SameSite=Strict): a passkey session is carried in an
  // AMBIENT cookie a foreign page could ride on a state-changing request, so every MUTATING (non-GET,
  // non-OPTIONS) request authenticated via the passkey session MUST also carry an Origin that EXACTLY
  // matches CONSOLE_ORIGIN. The Access and token methods present an EXPLICIT header (the Access assertion
  // header or the Authorization bearer) that a cross-site page cannot set on a credentialed cross-origin
  // request, so they are not ambient-credential CSRF vectors and are not subject to this check. A GET is a
  // read and is exempt (it is not state-changing). This sits BEFORE any route body read or DO forward, so a
  // forged cross-origin write is refused 403 before it can touch state. originAllowed fails closed on a
  // missing Origin or an unset CONSOLE_ORIGIN; the console (a real browser fetch) always sends Origin on a
  // state-changing request, so a legitimate console write is never blocked.
  if (isCookieBorneMethod(caller.method) && req.method !== "GET" && req.method !== "OPTIONS") {
    // G118: classify WHICH of the three branches refused, not merely THAT one did. originFailClass returns
    // null when the check passes, so the gate below is byte-identical to the old `!originAllowed(...)`.
    const originFault = originFailClass(req, env.CONSOLE_ORIGIN);
    if (originFault !== null) {
      logAuthFailure(caller.method, "cross-origin state-changing request rejected by the cookie-session CSRF Origin check");
      // P2: record the bounded auth-signal so a "console mutations are being 403'd" is diagnosable from the pack.
      // Fire-and-forget: a diagnostic write must never delay or fail the 403; the DO drops any out-of-vocabulary
      // name. G331: CHECKED, so a dropped signal is counted in droppedWrites rather than leaving the pack looking
      // like nobody's console mutations were being 403'd at all.
      //
      // G118: the name is now the CLOSED SUB-CLASS, because "every console save 403s" has two opposite fixes.
      // csrf-origin-unset says CONSOLE_ORIGIN is missing on the engine (a deploy dropped the var: EVERY user's
      // every cookie-borne mutation 403s, and the fix is to set it); csrf-origin-mismatch says a foreign Origin
      // was actually presented (a security event); csrf-origin-header-absent says no Origin arrived at all (a
      // stripping proxy / a non-browser client). The Origin VALUE never rides -- only which branch fired.
      fireInBackground(
        recordDiagWrite(scheduler, "auth-signal", () =>
          scheduler.fetch(doURL("/auth-signal"), { method: "POST", body: JSON.stringify({ name: originFault }), headers: { "content-type": "application/json" } }),
        ),
      );
      return new Response(JSON.stringify({ error: "csrf origin check failed" }), { status: 403, headers: { "content-type": "application/json" } });
    }
  }

  // V16.3.1: emit the authentication-SUCCESS signal once the caller is resolved. The closed
  // AuditAction/AuditTarget union (audit.ts) has no authn action and no authn-shaped target, so a
  // successful authentication is not a first-class audit event; it is recorded as a coarse,
  // non-sensitive console line (the auth method and the verified role) so the success side of
  // V16.3.1 is captured alongside the failure side above. No token, no email and no session value
  // is logged: the role is the access-control fact that matters, and the email is already redacted
  // out to keep this line free of avoidable PII. This is observability only; it changes no response.
  logAuthSuccess(caller.method, caller.role);

  // Carry the SAME IP on the resolved caller so callerHeaders(caller) forwards it to the DO on every
  // mutating call: the DO then stamps it on the SUCCESS it records at the commit point, matching the IP
  // the router already stamps on a DENIAL recorded here. This is what closes the "a denied role-change
  // shows an IP but the matching successful role-change does not" gap. SECURITY: this is the edge header
  // the router just read (never a client-supplied caller-header value; encodeCaller re-emits it and
  // decodeCaller re-reads it only from the router-internal header), so the inbound-overwrite property is
  // preserved, a client cannot inject a forged source IP into the trail. The token break-glass caller is
  // resolved without a DO round trip but is the same mutable object, so it carries the IP too.
  caller.sourceIp = sourceIp;

  // Carry the OPTIONAL change reference the operator attached (OWNER-OPT-IN requireChangeNumber policy),
  // read ONCE from the console's X-Downpipes-Change header (base64url(JSON)) onto the caller, exactly as the
  // source IP is read onto it above. callerHeaders(caller) then forwards it to the DO, where the
  // change-control chokepoint validates it and records the change-recorded event. SECURITY: unlike the source
  // IP this is a CLIENT-supplied value, but it is NON-AUTHORITY metadata (no gate reads it, the role is never
  // derived from it) and is recorded as the operator's own attestation, the same class as the restore reason,
  // so reading it from the inbound request confers nothing; a missing/garbled header is simply "no reference"
  // (the policy then refuses a change-controlled action if one was required for it). decodeChangeHeader bounds
  // it (control-chars stripped, length-capped), so an oversized/forged value cannot pass an unbounded blob on.
  // G182: the header's own FAULT, classified at the only place it can be. A change reference that arrives
  // garbled (the header did not decode) or truncated (it decoded and its text normalised away to nothing)
  // both become a plain `null` here -- which is byte-identical to a request that carried no reference at all.
  // So "the console demands a change number I already entered" had, server-side, no evidence that any number
  // was ever sent. The refusal downstream is UNCHANGED (a reference the engine cannot read is still no
  // reference); this only records WHY there is none.
  //
  // NOISE DISCIPLINE: an absent header reports no fault, so the default posture (the policy is OFF and no
  // console request carries a CR) writes nothing at all. Only a header that was SENT and could not be used
  // records, and the console is the only thing that ever sets it, so that is always a genuine defect.
  const changeHeader = decodeChangeHeaderWithFault(req.headers.get(CHANGE_HEADER));
  caller.change = changeHeader.ref;
  if (changeHeader.fault !== null) {
    fireInBackground(
      schedulerStub(env)
        .fetch(doURL("/diag/governance-refusal"), {
          method: "POST",
          body: JSON.stringify({ stage: "change-ref", reason: CHANGE_REF_FAULT_REASON[changeHeader.fault] }),
          headers: { "content-type": "application/json" },
        })
        .catch(() => {}),
    );
  }
  // AN OVER-LENGTH CHANGE NUMBER IS REFUSED HERE, and it is the ONLY change-header fault that refuses.
  //
  // A change number is a reference to a record in the CUSTOMER'S change-management system, and the entire
  // point of storing it is that somebody can later match the two. Truncating it to the cap produced a value
  // that still looks like a change number, went into the immutable CR ledger without complaint, and matched
  // nothing: the one job the field has, failed silently, in the audit trail that exists to be trusted. So
  // the engine refuses it at the wire and names the bound, and the operator fixes it while they are looking
  // at the field. The JUSTIFICATION is deliberately NOT refused: it is prose, its tail costs detail rather
  // than identity, and the cut is visible to whoever reads the record, so it keeps degrading gracefully.
  //
  // This is checked at the WIRE rather than left to the console's own field validator, because the console
  // is ONE caller and this is an interface: anything holding an operator session or the break-glass token
  // can set the header, and a record the engine writes into an immutable trail has to be honest about who
  // wrote the request. The bound is far above every real CAB identifier, so nothing legitimate is refused;
  // a reference of exactly CHANGE_NUMBER_MAX characters still passes, and so does a legal one padded with
  // whitespace or carrying a stray CR from a paste (changeNumberExceedsMax measures the CLEANED text).
  if (changeHeader.fault === "over-length") return jsonError(CHANGE_NUMBER_TOO_LONG, 400);

  // Per-caller anti-automation rate limiting (OWASP ASVS V2.4.1). The MUTATING routes (every admin
  // write is a POST; the GET reads are exempt) each call rateLimited() AFTER the caller is resolved
  // and BEFORE they reach the scheduler DO, so the bucket is keyed on the verified identity rather
  // than the source IP. It is gated per-route (not once before the switch) on purpose: a malformed
  // JSON body must still throw at the route's own `await req.json()` BEFORE any DO forward (the
  // last-resort 500 contract), so the limiter's DO call must sit AFTER the body is consumed by the
  // route, not ahead of it. The check is a THIN pre-check that never alters a route's behaviour; it
  // only adds the possibility of a 429 for a caller already past the per-window cap, and it FAILS
  // OPEN (see rateLimited) so an unavailable limiter never blocks a verified operator's recovery action.
  const sub = url.pathname.replace(/^\/admin/, "");
  // STEP-UP GATE (ASVS V7.5.1 / V7.5.3): the sensitive owner/operator actions require a FRESH re-authentication
  // so a stale ambient session cannot perform them. Checked once here for the main-switch sensitive routes
  // (recovery regeneration + self-add passkey re-run authorise and check inline). requireStepUp exempts the
  // bare-token + Access methods; a caller lacking the route's capability still hits its own 403 on retry.
  if (req.method === "POST" && STEPUP_SUBS.has(sub)) {
    const stepUp = await requireStepUp(req, scheduler, caller.method, runtime);
    if (stepUp) return stepUp;
  }
  // Reporting (contract section 6) is matched BEFORE the switch because the route carries a dynamic
  // :kind path segment (GET /admin/reports/<kind>[?format=pdf]) that a literal switch case cannot
  // express. It gates on reports.read (any authenticated role) and is a read (no rate-limit pre-check;
  // the GET reads are exempt, like the other reads). The handler gathers the per-kind data, assembles +
  // signs the Report, and returns JSON or, with ?format=pdf, a rendered PDF. See handleReport.
  if (req.method === "GET" && (sub === "/reports" || sub.startsWith("/reports/"))) {
    const denied = gate(caller, "reports.read");
    if (denied) return denied;
    return handleReport(env, scheduler, caller, sub.slice("/reports/".length), url.searchParams);
  }
  // Cost: the ANALYTICS-FIRST onboarding size estimate (GET /admin/cost/estate-size). Read-only
  // (downpipe.read, any authenticated config-viewer) and a GET (no rate-limit pre-check, like the other
  // reads). Best-effort: it sizes the configured sources from Cloudflare storage analytics so the cost
  // screen shows a real figure before the first backup runs; see handleEstateSize.
  if (req.method === "GET" && sub === "/cost/estate-size") {
    const denied = gate(caller, "downpipe.read");
    if (denied) return denied;
    return handleEstateSize(env, scheduler);
  }
  // OPT-IN dual-control change control: approve/reject a PENDING config change. Matched BEFORE the switch
  // because the route carries a dynamic <id> path segment (POST /admin/config/changes/<id>/approve|reject)
  // a literal switch case cannot express, mirroring the reports handler above. The id is extracted from the
  // path and forwarded to the DO in the body (the DO is the change-control authority). Each is a MUTATING
  // POST, so it is rate-limited per caller after the gate. GATING: the router gates these on downpipe.read
  // (the config read cap, so the caller is at least an authenticated config-viewer); the SPECIFIC write
  // capability the change requires (e.g. roles.write for a queued role change) plus maker != checker and
  // the no-stale/superseded base check are RE-RESOLVED and enforced by the DO against its own tables, since
  // the required capability depends on the change's kind (which only the DO knows by reading the record).
  // This is the same router-gates-coarse / DO-enforces-specific split as the restore approve path.
  {
    const changeAction = matchConfigChangeAction(req.method, sub);
    if (changeAction !== null) {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      // STEP-UP (HI-04 / ASVS V7.5.1): the <id> here is a per-request ULID path segment, so this route can
      // never be enumerated into STEPUP_SUBS (a Set<string> keyed on exact `sub` equality) - the dynamic
      // segment is structurally incompatible with Set membership, unlike every other STEPUP_SUBS entry. Gate
      // the PARSED action directly instead: approving actually applies the change (the dangerous direction,
      // the same one the direct-route mutation it approves is already gated on), so it needs the same fresh
      // re-auth; reject only discards a pending record and stays exempt, matching this codebase's existing
      // "only gate the dangerous direction" convention (e.g. restore/reject vs restore/approve).
      if (changeAction.action === "approve") {
        const stepUp = await requireStepUp(req, scheduler, caller.method, runtime);
        if (stepUp) return stepUp;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the id (from the path) to the DO route in the body + the caller header so the DO
      // re-resolves the approver's authority and records both actors. The inbound body is ignored (the id
      // is the only input, and it comes from the trusted path segment, not a client field).
      return scheduler.fetch(doURL(`/config/changes/${changeAction.action}`), {
        method: "POST",
        body: JSON.stringify({ id: changeAction.id }),
        headers: callerHeaders(caller),
      });
    }
  }
  // OPT-IN dual control for the HIGH-BLAST-RADIUS OWNER OPERATIONS: approve/reject a PENDING owner action.
  // Matched BEFORE the switch (dynamic <id> path segment, like the config-change + reports handlers). GATING:
  // every gated owner op is OWNER-class, so approving/rejecting one is gated on keys.ceremony (the owner-
  // exclusive capability, the same gate the gated ops themselves use); the DO RE-RESOLVES owner + the maker
  // != checker / no-stale / single-use rules against its own tables, so the router gate is coarse and the DO
  // enforces the specific dual-control logic. A mutating POST, so it is rate-limited per caller after the gate.
  {
    const ownerAction = matchOwnerActionAction(req.method, sub);
    if (ownerAction !== null) {
      // G245: the OWNER GATE. This block RETURNS BEFORE the dispatch loop below (its path carries a dynamic
      // <id>, so it can never be a key in the hub's frozen route table), which is exactly why every refusal on
      // the owner-action queue -- the second Owner's approve, the reject, the re-arm -- was invisible to the
      // hub recorder that catches every other admin write. "Our second owner approved and nothing happened" is
      // the ticket. Recorded here with the same discipline the hub uses and nothing else: a 2xx records
      // nothing; a 401 records nothing (it is the OPENING move of the step-up ceremony that then succeeds, not
      // a denial); the reason is a total map from the integer status; the body, the id and the record are never
      // read. noteOwnerGate is awaited before each return so the row cannot be lost to Worker shutdown.
      const noteOwnerGate = async (status: number): Promise<void> => {
        if (status < 400 || status === 401) return;
        await recordAdminRefusal(scheduler, "owner-gate", adminRefusalReasonForStatus(status));
      };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        await noteOwnerGate(denied.status);
        return denied;
      }
      // STEP-UP (HI-04 / ASVS V7.5.1): same structural reasoning as the config-change block above - the <id>
      // is a per-request ULID, so this route can never be a STEPUP_SUBS member. Approving a DO-executed kind
      // (e.g. dest-remove) runs the real mutation ATOMICALLY inside the DO call below, so a stale ambient
      // second-owner session must not be able to trigger it without a fresh re-auth; reject only discards the
      // pending record and stays exempt (the same "only gate the dangerous direction" convention).
      if (ownerAction.action === "approve") {
        const stepUp = await requireStepUp(req, scheduler, caller.method, runtime);
        if (stepUp) return stepUp;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) {
        await noteOwnerGate(limited.status);
        return limited;
      }
      // Forward the id (from the trusted path segment) + the caller header so the DO re-resolves the
      // approver's authority and records both actors. The inbound body is ignored.
      const resp = await scheduler.fetch(doURL(`/owner-actions/${ownerAction.action}`), {
        method: "POST",
        body: JSON.stringify({ id: ownerAction.id }),
        headers: callerHeaders(caller),
      });
      await noteOwnerGate(resp.status);
      // DISARM ALERT (the approved path): a dual-control-disable action is DO-executed on APPROVE, so an
      // approve that returns an executed dual-control-disable record IS a true->false transition, fire the
      // real-time disarm alert (fail-open). Read the body to inspect, then return a faithful copy so the
      // caller still sees the DO's exact status + record. Only an approve (not a reject) can execute it.
      if (ownerAction.action === "approve" && resp.status === 200) {
        const text = await resp.text();
        try {
          const rec = JSON.parse(text) as { kind?: unknown; status?: unknown };
          if (rec.kind === "dual-control-disable" && rec.status === "executed") {
            await routeDualControlDisarmAlert(env, scheduler, caller.email ?? null, "an approved second-owner disarm");
          }
        } catch {
          // A non-JSON 200 should not happen; fall through to return the body verbatim.
        }
        // Preserve the DO's own content-type so a non-JSON 200 is never misrepresented as JSON.
        return new Response(text, { status: 200, headers: { "content-type": resp.headers.get("content-type") ?? "application/json" } });
      }
      return resp;
    }
  }
  // POST-AUTH DISPATCH (the god-module split, engine-src-016-01 / engine-sys-arch-02 / engine-sys-asvs-04):
  // the central method+path switch was MOVED, body-for-body, into the route-group spokes imported above; the
  // gate()/capability check that guarded each route moved WITH its handler, unmoved relative to it, so every
  // capability check still runs for exactly the same path. The pre-auth edge (health, /auth, /oidc, /saml,
  // the demo-404), the single authorise() gate, resolveCaller, the cookie-CSRF guard, the step-up gate and
  // the dynamic-route matchers above are UNCHANGED and still run, in order, before any spoke. ctx carries the
  // exact locals the moved case bodies read (the same values the inline cases saw). Each spoke runs a sub-
  // switch on `${req.method} ${sub}` and returns the route's Response, or null when none of ITS cases matched;
  // we try them in the original textual order and the FIRST non-null answer wins. The route keys are unique
  // across the spokes (no key appears in two), so this chain is byte-for-byte equivalent to the one switch:
  // the same key reaches the same body, and an unmatched key falls through every spoke to the same 404 below.
  const ctx: RouterCtx = { req, env, url, scheduler, caller, sub, sourceIp, runtime, verdict, isOnlyOwner, roleSource, customRole };
  const dispatch = [
    handleIdentity,
    // CP-RECOVERY-LATCH-NO-CLEAR-PATH-AFTER-ORGANIC-RESUME: a one-route spoke (see its own file
    // header for why it was not grown into handleIdentity above, which sits at the line-budget ceiling).
    handleControlPlaneRecoveryAck,
    // G-P0-096: another one-route spoke, same reason (see its own file header) -- GET /control-plane/status
    // moved out of handleIdentity to make room for the harness-only fault-hook seam without busting the budget.
    handleControlPlaneStatus,
    handleUpdates,
    handleStatus,
    handleAccountSession,
    handlePipelines,
    handleRestore,
    handleAttest,
    handleRetentionPrune,
    handleRbac,
    handleOps,
    handleDiscovery,
    handleKeys,
    handleCustody,
    handleDestinations,
    handlePush,
    handleOtlpPush,
    handleConfigVersion,
  ];
  for (const handle of dispatch) {
    const resp = await handle(ctx);
    if (resp !== null) {
      // G177: THE ONE SEAM EVERY ADMIN WRITE'S ANSWER PASSES THROUGH. Recorded here, at the hub, rather than at
      // the nineteen refusal sites the gap lists, for the same reason blockError records the console's transport
      // faults at its one render seam: a recorder a call site must remember to call is a recorder that a new
      // route silently omits. Every one of these routes returns THROUGH this loop, so none can forget.
      //
      // It reads the STATUS and nothing else. Not the body, not the headers, not the engine's refusal prose --
      // which on these routes can name a channel URL, a role name or an operator's own change reference. The
      // surface is a compile-time constant looked up from a frozen route table, the reason is a total map from an
      // integer, and neither can be derived from a request value.
      await noteAdminWriteRefusal(scheduler, req.method, sub, resp.status);
      return resp;
    }
  }
  // No spoke matched the method+path: the same fall-through the original switch's `default` produced.
  return new Response("not found", { status: 404 });
}
