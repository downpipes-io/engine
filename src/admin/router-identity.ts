// router-identity.ts -- the post-auth identity + IdP-connection-management routes: the DEMO_MODE reset,
// the whoami identity echo, the role-table read, the control-plane recovery (export/import/reconcile/
// apply-staged) routes, and the native-IdP (OIDC/OAuth2/SAML) CONNECTION MANAGEMENT surface (NOT the
// pre-auth login flow, which is router-idp-web). The per-route capability gate runs inline per route.

import { b64urlDecode, hexEncode } from "../crypto/bytes.ts";
import { LABEL_SIGNER_PUBLIC, parseKeyFile, parseVerifier } from "../crypto/keys.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { HybridVerifier, HybridVerifyVerdict } from "../crypto/sign.ts";
import { buildDestination } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { envFlagEnabled, tokenEqual } from "./auth.ts";
import { assertNoPlaintextSecretInExport, type ControlPlaneExport, isControlPlaneExport, serialiseControlPlaneExport, type StagedControlPlane, sameControlPlaneAccount, signControlPlaneExport, verifyControlPlaneSignatureDetailed } from "./control-plane.ts";
import { isSealedControlPlaneExport, type SealedControlPlaneExport, verifySealedControlPlaneSignatureDetailed } from "./control-plane-seal.ts";
import { manualReconcileTail, nothingToConfirmMessage } from "./control-plane-latch-exit.ts";
import { noteTestOutcome, recordRecoveryRefusal } from "./diag-counters.ts";
import type { RecoveryRefusalClass } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { type Caller, isCookieBorneMethod, type WhoAmI } from "./identity.ts";
import { classifyIdpTestFailure, classifyIdpValidationRefusal, idpTestSignalName, idpValidationSignalName } from "./idp-diag.ts";
import { runIdpConnectionTest } from "./idp-test.ts";
import { callerHeaders, gate, jsonError, jsonRefusal, jsonResponse, parseJsonBody, rateLimited, recordAudit } from "./router-core.ts";
import { type AdminRuntime, doURL, type RouterCtx, recordAuthSignalEdge } from "./router-helpers.ts";
import { doDeletedNothing, doRefusedTheChange, routeAuthChangeAlert } from "./router-notify.ts";
import { breakGlassRetiredViaDO } from "./router-session.ts";
import { csrfSetCookie, mintCsrfToken, readCsrfCookie } from "./session.ts";

// fireInBackground: the module-scope twin of handlePasskey's fireInBackground closure,
// needed standalone since several writes below sit in top-level functions, not closures over handleIdentity's
// own runtime. Falls back to bare-void only when no fetch runtime is supplied (a unit test).
function fireInBackground(runtime: AdminRuntime | undefined, task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// G202: the CRYPTO VERDICT -> REFUSAL CLASS map, and the operator sentence that goes with each.
//
// The three manual recovery routes used to derive this from a pure length check on the SIGNATURE STRING, which
// has no access to the KEY at all. So a recovery-kit signer.pub that is the correct length and CORRUPT (bit
// rot, a partially restored file, the wrong same-size key) passed the length check, failed inside the total
// verify, and was reported as `signature` -- byte-identical to a genuinely ALTERED export. The pack told the
// support engineer "your recovery artefact was tampered with" when the truth was "your kit file is damaged,
// take another copy". That is the precise inversion the gap's ticket names.
//
// hybridVerifyDetailed computes the real verdict; these routes keep it. The five non-ok members are five
// different incidents with five different remedies, and they no longer coalesce. The one that matters most is
// classical-half-damaged: the post-quantum half verified the exact export bytes, so the export is PROVABLY
// intact and what is damaged is the customer's own kit (the Ed25519 half of the signer.pub, or of the .sig). It
// is the state a corrupt, partially-restored or half-written kit file actually takes, and it was scored as
// tamper, because the verify short-circuited on the classical half and threw the proof away.
const RECOVERY_CLASS_BY_VERDICT: Record<Exclude<HybridVerifyVerdict, "ok">, RecoveryRefusalClass> = {
  "sig-decode": "verify-threw", // the .sig blob is truncated / half-written: the signature FILE is damaged
  "verifier-invalid": "verifier-invalid", // the KEY would not import: the kit's signer.pub (or SIGNER_PRIVATE) is corrupt
  "ed25519-mismatch": "signature", // NEITHER half verified: the wrong key, or the export was ALTERED. Tamper lives here
  "ed25519-only-mismatch": "classical-half-damaged", // the post-quantum half VERIFIED these exact export bytes: the export is provably intact, and the Ed25519 half of the KEY or of the .sig is damaged. Never tamper
  "mldsa-mismatch": "signature-pq", // only the post-quantum half failed: a partial/mixed signer rotation. Never tamper
};

// recoveryVerifySentence is the operator prose for each verdict. It names the artefact to re-copy, so the
// customer is not sent hunting for an attacker when their key file has rotted. The prose is never persisted
// (the pack carries the closed class above); it is only ever returned on this response.
function recoveryVerifySentence(verdict: Exclude<HybridVerifyVerdict, "ok">, keyLabel: string): string {
  switch (verdict) {
    case "sig-decode":
      return "the export's detached signature could not be READ (it is not a well-formed signature blob), so the export was never checked at all. This is a damaged signature FILE, not evidence of tampering: take a fresh copy of the export and its .sig and try again.";
    case "verifier-invalid":
      return `the export could not be checked because ${keyLabel} would not import. The KEY is damaged, not the export: this is not evidence of tampering. Take a fresh copy of the key and try again.`;
    case "mldsa-mismatch":
      return `the export's classical signature half verified and its post-quantum half did not. The export itself is INTACT (a modified export fails BOTH halves, because both cover the same bytes), so this is not tampering: what is wrong is confined to the post-quantum half of the key. Either this export was signed by a different or partially rotated signer, or the ML-DSA half of ${keyLabel} is damaged. Check which signer signed this export, and take a fresh copy of the key.`;
    case "ed25519-only-mismatch":
      return `the export's post-quantum signature half verified and its classical (Ed25519) half did not verify. The post-quantum half checked THESE EXACT export bytes under this key, so the export itself is INTACT and this is not tampering: what is damaged is confined to the Ed25519 half of ${keyLabel} or of the detached signature (bit rot, a partially restored or half-written file), or the export was signed by a partially rotated signer. Take a fresh copy of the key and the signature, and try again.`;
    case "ed25519-mismatch":
      return "the export signature did not verify (the wrong key, or the export was modified).";
  }
}

// recordIdpSetupSignal (G010) counts ONE closed IdP setup-time outcome in the bounded auth-signal aggregate: a
// failed "test connection" probe, or a connection proposal REFUSED by the pre-write validators. Both used to
// vanish (the probe persists nothing and a validator refusal 400s before any storage write), which is why "we
// tried to add Okta SSO and it never saves" arrived with a pack that shows no IdP at all -- indistinguishable
// from an operator who never tried. The classifiers in idp-diag.ts are the redaction chokepoint: they read the
// probe's `detail` / the validator's reason (both of which interpolate the SUBMITTED URL, issuer, cert or preset
// id) ONLY to select a closed class, and discard the text. It rides the CHECKED diag-writer, so a signal dropped
// during a DO outage is itself counted. Fire-and-forget: the operator's response is unchanged and never delayed.
function recordIdpSetupSignal(scheduler: DurableObjectStub, name: string, runtime?: AdminRuntime): void {
  const write = recordDiagWrite(scheduler, "auth-signal", () =>
    scheduler.fetch(doURL("/auth-signal"), { method: "POST", body: JSON.stringify({ name }), headers: { "content-type": "application/json" } }),
  );
  fireInBackground(runtime, write);
}

// recordIdpTestOutcome classifies a probe result and, when there is something worth recording (a failed check,
// or the cert-expiring advance warning), counts its closed fail class. A clean pass records nothing.
function recordIdpTestOutcome(scheduler: DurableObjectStub, result: unknown, runtime?: AdminRuntime): void {
  const cls = classifyIdpTestFailure(result);
  if (cls !== null) recordIdpSetupSignal(scheduler, idpTestSignalName(cls.failClass), runtime);
  // G246: "the SSO test failed with some cert error." The signal above is a COUNTER (how often an IdP test has
  // failed on this class), which cannot say WHEN, or whether the very next press passed. The ring says both, in
  // sequence, which is what makes a customer's "it failed yesterday and works now" checkable rather than a
  // matter of trust. The probe's own closed fail class is the reason; the submitted URL never rides.
  const ok = (result as { ok?: unknown } | null)?.ok === true;
  fireInBackground(runtime, noteTestOutcome(scheduler, "idp", { ok, ...(cls !== null ? { reason: cls.failClass } : {}) }));
}

// The account-wide signed RUNLOG and its detached signature live at these fixed keys in EVERY destination
// (SPEC 9/10). The seal layer owns the values; the demo-reset route only needs the paths to clear them.
const RUNLOG_KEY = "_RECOVERY/RUNLOG";
const RUNLOG_SIG_KEY = "_RECOVERY/RUNLOG.sig";

// clearDestinationRunlog drops the signed RUNLOG (+ its .sig) from the engine's DEFAULT destination, so a
// demo-reset that wipes the SchedulerDO's runlogCounter to 0 cannot leave a SURVIVING RUNLOG in the bucket
// that post-reset runs reuse indices against (RUNLOG-1: the deterministic demo-reset chain fork -- two
// `idx 1` entries appended to the same _RECOVERY/RUNLOG → the offline CLI rc=5 on an otherwise-intact
// archive). Deleting the RUNLOG is sufficient: a reused index appended to an ABSENT log starts a clean
// single-entry chain. It is BEST-EFFORT (fail-open): the primary reset is the DO wipe, which has already
// succeeded by the time this runs, and a demo without a configured default destination (no DEST_R2/DEST_*)
// simply has nothing to clear. Returns true when both keys were deleted, false when the destination could
// not be built or the delete failed. RESIDUAL: only the env-DEFAULT destination is cleared here; a demo
// configured with extra per-downpipe destinations (3-2-1) would keep their RUNLOGs -- those configs live in
// the DO that the reset just wiped, so enumerating them would have to happen before the wipe (not done; the
// demo uses the single default destination, which is the live-reproduced case).
async function clearDestinationRunlog(env: Env): Promise<boolean> {
  try {
    const dest = await buildDestination(env);
    await dest.delete(RUNLOG_KEY);
    await dest.delete(RUNLOG_SIG_KEY);
    return true;
  } catch {
    return false; // no default destination configured, or a transient delete failure; the DO wipe stands
  }
}

// requireLiveBreakGlassToken is the SHARED gate for the three routes below that authenticate on the raw
// ADMIN_TOKEN bearer directly (constant-time) instead of through authorise()'s precedence: after a wipe or
// during a demo reset, a passkey/Access caller resolves to recovery-required viewer and cannot authorise these,
// so only the operator presenting the break-glass token may. That directness previously meant these three
// routes checked ONLY tokenEqual, silently skipping the SAME disablement predicate authorise() enforces on its
// own token path (envFlagEnabled(ADMIN_TOKEN_DISABLED) and the DO's break-glass-retired latch) -- so a token
// the Owner had disabled or retired, believing the shared secret fully neutralised, kept authenticating here
// forever, letting anyone who ever held it (plus any historically-valid signed export) permanently re-escalate
// to Owner. Defined ONCE and called from all three cases so a future 4th break-glass route cannot repeat the
// same incomplete raw-tokenEqual copy that let this happen. Returns the 401 Response to short-circuit with,
// or null when the bearer is live, byte-correct, and neither disabled nor retired.
async function requireLiveBreakGlassToken(req: Request, env: Env, scheduler: DurableObjectStub, runtime?: AdminRuntime): Promise<Response | null> {
  const bearer = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (typeof env.ADMIN_TOKEN !== "string" || env.ADMIN_TOKEN.length === 0 || !(await tokenEqual(bearer, env.ADMIN_TOKEN))) {
    return new Response("unauthorised", { status: 401 });
  }
  if (envFlagEnabled(env.ADMIN_TOKEN_DISABLED) || (await breakGlassRetiredViaDO(scheduler))) {
    // G314: the bearer was BYTE-CORRECT and the fallback is disabled or RETIRED, so this is a presentation of
    // a token that should no longer exist anywhere -- a replay of a retired break-glass credential, or an
    // operator using a copy nobody revoked from their laptop. Either way it is the question a post-incident
    // review asks first, and the 401 answered it to one caller and to nobody else. The bearer never rides.
    // Distinct from the admin-token-denied-* family, which covers authorise()'s precedence path, not these
    // separately-gated break-glass routes (which is exactly how this got missed).
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "break-glass-token-refused")); // 0-await to the return below
    return new Response("unauthorised", { status: 401 });
  }
  return null;
}

// lockoutRefusalIfLastSignInPath (G5, lockout guard) refuses deleting or disabling the LAST enabled IdP
// connection when doing so would leave the tenant with NO way back in. It mirrors POST /policy/require-access:
// the DO reports the connection-count + owner-passkey + recovery facts (connectionRemovalPreflight) and the
// ROUTER adds the env facts it alone sees -- Cloudflare Access (a configured team domain + AUD) and the
// break-glass token's disabled/retired state -- because a DO-only refuse would FALSE-POSITIVE for an Access
// tenant the DO cannot see. It refuses ONLY when EVERY way in is absent: this is the sole enabled connection,
// Access is not configured, no Owner holds a passkey, no recovery codes exist, AND the break-glass token is
// gone. In every other case it returns null (the removal proceeds through its normal gates). Fail-open: a
// preflight fetch error returns null so a transient hiccup never blocks a legitimate removal.
async function lockoutRefusalIfLastSignInPath(env: Env, scheduler: DurableObjectStub, connId: string, runtime?: AdminRuntime): Promise<Response | null> {
  if (connId.length === 0) return null;
  let pf: { lastEnabledConnection?: boolean; passkeyOwnerEnrolled?: boolean; recoveryReady?: boolean };
  try {
    const resp = await scheduler.fetch(doURL("/idp/conn/removal-preflight"), { method: "POST", body: JSON.stringify({ connId }), headers: { "content-type": "application/json" } });
    pf = (await resp.json()) as typeof pf;
  } catch {
    // G314: THE GUARD THAT PREVENTS AN ACCOUNT LOCKING ITSELF OUT WAS RUNNING BLIND. It fails OPEN by design
    // (a preflight hiccup must never block a legitimate removal), so the removal proceeds -- and if that
    // connection really was the last way in, the tenant is now locked out and the guard that exists to stop
    // exactly that never got to run. "We deleted an IdP connection and now nobody can sign in" reads, in the
    // pack, exactly like a tenant that had other ways in. This is the difference. Best-effort; still fail-open.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "lockout-guard-failopen")); // 0-await to the return below
    return null; // fail-open: never block a legitimate removal on a preflight hiccup
  }
  if (pf.lastEnabledConnection !== true) return null; // another enabled connection remains -> safe
  const accessConfigured = Boolean(env.CF_ACCESS_TEAM_DOMAIN && env.CF_ACCESS_AUD);
  if (accessConfigured || pf.passkeyOwnerEnrolled === true || pf.recoveryReady === true) return null; // another way in exists
  const tokenGone = envFlagEnabled(env.ADMIN_TOKEN_DISABLED) || (await breakGlassRetiredViaDO(scheduler));
  if (!tokenGone) return null; // the break-glass token is still a way in
  return jsonError(
    "Refusing to remove the only enabled sign-in path: there would be no way back in. Cloudflare Access is not configured, no Owner holds a passkey, no recovery codes are set, and the break-glass token is retired or disabled. Set up another way in first (enable Cloudflare Access, have an Owner register a passkey, generate recovery codes, or keep the break-glass token), then remove or disable this connection.",
    409,
  );
}

// handleIdentity dispatches the identity + IdP-connection-management group. Returns the route's Response,
// or null when no case here matched (the hub falls through to the next spoke, as the original switch fell
// to its next case). The auth gate already ran in the hub; the per-route capability gates stay inline below.
export async function handleIdentity(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, sourceIp, verdict, isOnlyOwner, roleSource, customRole, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- DEMO-ONLY reset (hard-gated; impossible in production) --------------------------
    case "POST /demo/reset": {
      // Reaching here means DEMO_MODE is on (the early guard 404s it otherwise). Gate on the ADMIN_TOKEN
      // break-glass bearer DIRECTLY (constant-time), NOT via the auth precedence: the demo is reached
      // behind Cloudflare Access + a passkey session, so authorise() above resolves the caller as
      // passkey/access, we want the reset authorised SPECIFICALLY by the operator presenting the
      // ADMIN_TOKEN here (the console button prompts for it; the CLI script sends it), decoupled from the
      // wipeable identity so it works repeatedly (and before/after bootstrap). It wipes the scheduler DO
      // to first-run. DESTRUCTIVE by design; there is no reset surface in production (no DEMO_MODE).
      // SECURITY (ASVS V6): also refuse a disabled or retired token (requireLiveBreakGlassToken) -- this
      // route's own bearer compare must not outlive the Owner's disable/retire decision.
      const denied = await requireLiveBreakGlassToken(req, env, scheduler, runtime);
      if (denied) return denied;
      // engine-src-037-M1: reaching here is itself a DEMO_MODE-gated path (the early guard 404s the route
      // otherwise), so persist the in-DO demo marker before forwarding the reset. This keeps the legitimate
      // demo flow working even if /setup-state has not been loaded yet, while the DO's marker guard still
      // fails closed for a reset that reaches the DO WITHOUT a DEMO_MODE-gated router path (misrouted/forged).
      try { await scheduler.fetch(doURL("/demo/mark"), { method: "POST" }); } catch { /* fail-open: the DO guard fails closed if this did not land */ }
      const resetResp = await scheduler.fetch(doURL("/demo/reset"), { method: "POST" });
      if (resetResp.status === 403) return jsonError("demo reset refused: this instance is not marked as a demo", 403);
      if (!resetResp.ok) return jsonError("demo reset failed; nothing may have been wiped", 500);
      const out = (await resetResp.json()) as { cleared?: number };
      // RUNLOG-1: the DO wipe resets runlogCounter to 0, but the destination bucket SURVIVES. Without also
      // clearing the surviving signed RUNLOG, post-reset runs reuse RUNLOG indices and append a forked chain
      // to it (two `idx 1` entries), which the strict offline CLI rejects (rc=5) on an otherwise-intact
      // archive. Drop the default destination's RUNLOG so the next run starts a clean chain. Best-effort.
      const runlogCleared = await clearDestinationRunlog(env);
      const note = runlogCleared
        ? "scheduler DO wiped to first-run and the destination RUNLOG cleared; reload the console and re-bootstrap with ADMIN_TOKEN then a passkey"
        : "scheduler DO wiped to first-run; the destination RUNLOG could NOT be auto-cleared (no default destination configured, or a transient error) -- empty the destination bucket before the first post-reset run to avoid a forked freshness chain; reload the console and re-bootstrap with ADMIN_TOKEN then a passkey";
      return jsonResponse({ ok: true, reset: true, cleared: out.cleared ?? null, runlogCleared, note });
    }
    // ---- INFRA-1 control-plane recovery -------------------------------------------------
    // GET /control-plane/status moved to its own one-route spoke, router-control-plane-status.ts (this file
    // sits at the line-budget ceiling; see that file's header for why, and CP-RECOVERY-LATCH-NO-CLEAR-PATH-
    // AFTER-ORGANIC-RESUME below for the precedent).
    // The DOWNLOAD: build the CURRENT control-plane export on demand and return it SIGNED, so the operator can
    // keep a fresh copy (JSON + detached signature) alongside their recovery kit -- the same no-custody
    // artefact the cron writes to the destination buckets, built now against live state, so the kit's config
    // inventory does not depend on later bucket access. Gated on access.policy (owner / access-admin): the
    // export carries the whole config posture, the operator roster and the destination topology (never a
    // plaintext secret -- those ride wrapped or reestablish), so it sits behind the same gate as the config
    // snapshot and the coverage inventory. The DO BUILDS it (it holds the records); the Worker SIGNS it
    // (SIGNER_PRIVATE lives here, never in the DO), exactly like the cron export pass, and re-asserts the
    // no-custody invariant before returning so a plaintext secret can never leave even on this read path.
    case "GET /control-plane/export-download": {
      const denied = gate(caller, "access.policy");
      if (denied) return denied;
      // G202: this is the operator trying to OBTAIN a fresh recovery artefact, and every failure below was a
      // bare HTTP error with no durable trace. "The recovery-kit download 502s" therefore arrived at support
      // with nothing in the pack -- on the one path where the pack may be the only artefact that survives.
      if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "export-download", cls: "no-signer" });
        return jsonError("cannot sign the control-plane export: SIGNER_PRIVATE is not configured", 500);
      }
      const built = await scheduler.fetch(doURL("/control-plane/export"), { method: "GET" });
      if (!built.ok) {
        await recordRecoveryRefusal(scheduler, { surface: "export-download", cls: "build-failed" });
        return jsonError("could not build the control-plane export from the scheduler", 502);
      }
      const exp = (await built.json()) as ControlPlaneExport;
      if (!isControlPlaneExport(exp)) {
        await recordRecoveryRefusal(scheduler, { surface: "export-download", cls: "shape" });
        return jsonError("the built control-plane export is malformed", 500);
      }
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "export-download", cls: "no-custody" });
        return jsonError(`refused: ${(e as Error).message}`, 500);
      }
      const signer = await loadSigner(env.SIGNER_PRIVATE);
      const signature = await signControlPlaneExport(signer, exp);
      return jsonResponse({ export: exp, signature });
    }
    // The CROSS-ENVIRONMENT estate import (recovery keystone): a bootstrapped Owner on a FRESH engine rebuilds
    // the DEFINITION of a lost estate from a signed export they pulled out-of-band. Unlike /restore (same
    // account, break-glass token, restores authority), this is gated on access.policy (the operator is a real
    // Owner) and grants NO authority -- the DO's importControlPlaneDefinition applies only downpipes /
    // destinations / discovery. The export is verified against the OPERATOR-SUPPLIED signer.pub from their
    // offline recovery kit: that is TAMPER EVIDENCE (the export is intact + internally consistent), NOT an
    // authority root -- a public key proves no authenticity, which is EXACTLY why no authority is imported.
    // crossAccount is computed from this engine's account vs the export's, so a different-account import lands
    // its downpipes disabled for rebind. This never touches a live estate: the DO refuses a non-fresh plane.
    case "POST /control-plane/import": {
      const denied = gate(caller, "access.policy");
      if (denied) return denied;
      const parsed = await parseJsonBody<{ export?: unknown; signature?: unknown; signerPublic?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const exp = parsed.body.export;
      const signature = parsed.body.signature;
      const signerPublic = parsed.body.signerPublic;
      if (!isControlPlaneExport(exp)) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: "shape" });
        return jsonRefusal("export is not a control-plane export artefact", 400, "shape");
      }
      if (typeof signature !== "string" || signature.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: "malformed" });
        return jsonRefusal("a detached signature is required", 400, "malformed");
      }
      if (typeof signerPublic !== "string" || signerPublic.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: "malformed" });
        return jsonRefusal("your recovery kit's signer.pub is required to verify the export", 400, "malformed");
      }
      // No-custody re-assertion (defence in depth): never import an artefact that carries a plaintext secret.
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: "no-custody" });
        return jsonRefusal(`refused: ${(e as Error).message}`, 400, "no-custody");
      }
      // Verify the export against the OPERATOR-SUPPLIED kit signer.pub -- TAMPER EVIDENCE, never an authority
      // root. Accept the labelled kit-file form (`downpipe-signer-public-v1 <b64url>`) or a raw b64url payload.
      let verifier: HybridVerifier;
      try {
        const trimmed = signerPublic.trim();
        const bytes = /\s/.test(trimmed) ? parseKeyFile(trimmed, LABEL_SIGNER_PUBLIC) : b64urlDecode(trimmed);
        verifier = parseVerifier(bytes);
      } catch (e) {
        // G202: THE KIT KEY is damaged, not the export. A signer.pub that will not even PARSE (the wrong
        // length, a mangled kit file) is a broken recovery-kit FILE; the customer needs another copy of the
        // kit. Recorded as verifier-invalid, the same class the CORRUPT-BUT-RIGHT-LENGTH key below lands on,
        // because both are the one fact that matters: the key is bad and the export is innocent.
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: "verifier-invalid" });
        return jsonRefusal(`the supplied signer.pub is not a valid downpipe signer public key: ${(e as Error).message}`, 400, "verifier-invalid");
      }
      // G202: THE SHARPEST EDGE IN THIS GAP, and the one the first build got wrong. The old code proxied the
      // crypto verdict with a LENGTH CHECK ON THE SIGNATURE STRING, which cannot see the key at all -- so an
      // operator-supplied signer.pub that is the correct 2624 bytes and CORRUPT sailed through it, failed
      // inside the total verify, and was recorded as `signature`: byte-identical to a genuinely ALTERED
      // export. "Estate import says signature invalid but the kit is correct" is exactly that ticket, and the
      // pack answered it with the OPPOSITE of the truth ("your recovery artefact was tampered with").
      //
      // hybridVerifyDetailed now computes the honest verdict and this route keeps it. FIVE worlds, five rows: a
      // damaged .sig, a KEY that would not import, a KEY whose Ed25519 half is damaged (the post-quantum half
      // still verifies the export, so the export is provably intact), a partial signer rotation, and an altered
      // export. Only the last of those is tamper, and it is now the only one that can reach `signature`.
      const verdict = await verifyControlPlaneSignatureDetailed(exp as ControlPlaneExport, signature, verifier);
      if (verdict !== "ok") {
        // G196: the SAME closed class that goes into this engine's own refusal latch rides in the 400 body, so the
        // console can stamp a distinct code on it. Until now every 400 on this route was DP-R12 in the console's
        // hands, so a tampered export, a wrong kit and a damaged .sig were one code and one coalesced pack row.
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: RECOVERY_CLASS_BY_VERDICT[verdict] });
        return jsonRefusal(recoveryVerifySentence(verdict, "your recovery kit's signer.pub"), 400, RECOVERY_CLASS_BY_VERDICT[verdict]);
      }
      // Cross-account: disable the imported downpipes when the export's account differs from this engine's.
      // G218: accountIdAbsent is the state in which a PRE-ACCOUNT-DISCOVERY export (built before the engine
      // ever knew its own account id) silently imports EVERYTHING DISABLED -- sameControlPlaneAccount fails
      // safe on a null on either side, so the import "succeeds" and not one downpipe runs. The customer's
      // estate is back on the screen and no backup is happening, and nothing said why.
      const exportAccountId = (exp as ControlPlaneExport).engineAccountId;
      const engineAccountId = typeof env.CF_ACCOUNT_ID === "string" ? env.CF_ACCOUNT_ID : null;
      const accountIdAbsent = !exportAccountId || !engineAccountId;
      const crossAccount = !sameControlPlaneAccount(exportAccountId, engineAccountId);
      const resp = await scheduler.fetch(doURL("/control-plane/import"), {
        method: "POST",
        body: JSON.stringify({ export: exp, crossAccount, accountIdAbsent }),
        headers: callerHeaders(caller),
      });
      if (!resp.ok) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import", cls: "reconcile-refused" });
        const detail = await resp.text();
        // The 400 leg carries the closed class (G196); the 403 leg does not need one (the console already has
        // its own code for "not an Owner", which is what a 403 on this route means and the only thing it means).
        if (resp.status === 403) return jsonError(`estate import refused: ${detail.slice(0, 300)}`, 403);
        return jsonRefusal(`estate import refused: ${detail.slice(0, 300)}`, 400, "reconcile-refused");
      }
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json" } });
    }
    // The browser-unseal counterpart of POST /control-plane/import, for the DEFAULT artefact -- a
    // .sealed.json, whenever a break-glass recipient is configured (control-plane-pass.ts:189) -- which the
    // plaintext route above structurally cannot accept. The unseal (identity.key decap + the two AEAD opens)
    // runs ENTIRELY in the operator's browser (keydecap.ts), never here: that private key is never a field on
    // this request. This route is handed the ORIGINAL sealed artefact (still encrypted; this engine holds no
    // key that opens it -- a fresh estate's CONFIG_RECIPIENT_PRIVATE was never a recipient of the old export)
    // plus its own detached signature and the recovery-kit signer.pub, and separately the PLAINTEXT the
    // browser already recovered. It cannot re-derive that plaintext (no key), so it instead verifies the
    // sealed signature (public-key only, exactly the plaintext route's own pattern) and cross-checks the
    // candidate plaintext's hash against `bodyHash`, the SIGNED commitment control-plane-seal.ts pins for
    // exactly this purpose. Only once BOTH hold does it fall through to the SAME DO import call the plaintext
    // route makes, with the SAME no-authority, cross-account semantics.
    case "POST /control-plane/import-sealed": {
      const denied = gate(caller, "access.policy");
      if (denied) return denied;
      const parsed = await parseJsonBody<{ sealed?: unknown; sealedSignature?: unknown; signerPublic?: unknown; export?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const sealed = parsed.body.sealed;
      const sealedSignature = parsed.body.sealedSignature;
      const signerPublic = parsed.body.signerPublic;
      const exp = parsed.body.export;
      if (!isSealedControlPlaneExport(sealed)) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "shape" });
        return jsonRefusal("sealed is not a sealed control-plane export artefact", 400, "shape");
      }
      if (typeof sealedSignature !== "string" || sealedSignature.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "malformed" });
        return jsonRefusal("a detached signature for the sealed artefact is required", 400, "malformed");
      }
      if (typeof signerPublic !== "string" || signerPublic.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "malformed" });
        return jsonRefusal("your recovery kit's signer.pub is required to verify the sealed artefact", 400, "malformed");
      }
      if (!isControlPlaneExport(exp)) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "shape" });
        return jsonRefusal("export is not a control-plane export artefact", 400, "shape");
      }
      // No-custody re-assertion (defence in depth), on the RECOVERED plaintext -- identical to the plaintext
      // import route, and load-bearing here too: a browser bug that leaked a plaintext secret into the
      // recovered export must not be waved through just because the sealed wrapper around it verified.
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "no-custody" });
        return jsonRefusal(`refused: ${(e as Error).message}`, 400, "no-custody");
      }
      let verifier: HybridVerifier;
      try {
        const trimmed = signerPublic.trim();
        const bytes = /\s/.test(trimmed) ? parseKeyFile(trimmed, LABEL_SIGNER_PUBLIC) : b64urlDecode(trimmed);
        verifier = parseVerifier(bytes);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "verifier-invalid" });
        return jsonRefusal(`the supplied signer.pub is not a valid downpipe signer public key: ${(e as Error).message}`, 400, "verifier-invalid");
      }
      // Verify the SEALED wrapper's own signature (the artefact the operator actually pulled from the bucket),
      // not a signature of the plaintext -- none was ever written for it (S5 writes ONE artefact + ONE
      // signature per generation; a sealed generation's plaintext .json/.json.sig siblings are purged). Same
      // five-world verdict as the plaintext route, so the same honest DP-R code split applies on the console.
      const verdict = await verifySealedControlPlaneSignatureDetailed(sealed as SealedControlPlaneExport, sealedSignature, verifier);
      if (verdict !== "ok") {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: RECOVERY_CLASS_BY_VERDICT[verdict] });
        return jsonRefusal(recoveryVerifySentence(verdict, "your recovery kit's signer.pub"), 400, RECOVERY_CLASS_BY_VERDICT[verdict]);
      }
      // The link this route exists to check: the sealed signature proves the SEALED object (header + capsule +
      // bodyHash + the body ciphertext) is authentic and untampered; it says nothing on its own about whether
      // THIS candidate plaintext is what that ciphertext decrypts to (this engine holds no key that opens it).
      // bodyHash is the bridge -- itself covered by the signature just verified -- so re-hashing the candidate
      // and comparing closes the gap without this engine ever touching a private key or the ciphertext. It is
      // a hash commitment in a PLAINTEXT header, so it is also a confirmation oracle for a bucket reader who
      // can guess the exact byte-for-byte plaintext; accepted, not closed -- see SealedControlPlaneExport.bodyHash's own comment (control-plane-seal.ts) for the full trade-off.
      const bodyHash = (sealed as SealedControlPlaneExport).bodyHash;
      if (typeof bodyHash !== "string" || bodyHash.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "sealed-unhashed" });
        return jsonRefusal(
          "this sealed artefact was written before body-hash pinning, so it cannot be verified against the plaintext your browser recovered. Wait for the next scheduled export (or trigger one with a config change) and pull a fresh copy, or use the offline downpipe unseal-export command on an air-gapped machine in the meantime.",
          400,
          "sealed-unhashed",
        );
      }
      const candidateHash = `sha384:${hexEncode(await sha384(serialiseControlPlaneExport(exp as ControlPlaneExport)))}`;
      if (candidateHash !== bodyHash) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "sealed-body-mismatch" });
        return jsonRefusal(
          "the sealed artefact's signature verified, but the plaintext handed to this route does not match what it was signed over. This is not the export the sealed artefact committed to: re-run the unseal in your browser and try again without editing the recovered JSON.",
          400,
          "sealed-body-mismatch",
        );
      }
      const exportAccountId = (exp as ControlPlaneExport).engineAccountId;
      const engineAccountId = typeof env.CF_ACCOUNT_ID === "string" ? env.CF_ACCOUNT_ID : null;
      const accountIdAbsent = !exportAccountId || !engineAccountId;
      const crossAccount = !sameControlPlaneAccount(exportAccountId, engineAccountId);
      const resp = await scheduler.fetch(doURL("/control-plane/import"), {
        method: "POST",
        body: JSON.stringify({ export: exp, crossAccount, accountIdAbsent }),
        headers: callerHeaders(caller),
      });
      if (!resp.ok) {
        await recordRecoveryRefusal(scheduler, { surface: "estate-import-sealed", cls: "reconcile-refused" });
        const detail = await resp.text();
        if (resp.status === 403) return jsonError(`estate import refused: ${detail.slice(0, 300)}`, 403);
        return jsonRefusal(`estate import refused: ${detail.slice(0, 300)}`, 400, "reconcile-refused");
      }
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json" } });
    }
    // The break-glass-gated RECONCILE: rebuild the wiped control plane from a signed export the operator
    // pulled out-of-band from the destination bucket. Gated DIRECTLY on the ADMIN_TOKEN break-glass bearer
    // (constant-time), exactly like demo-reset and for the same reason: after a wipe the role table is empty,
    // so a passkey/Access caller resolves to recovery-required viewer and CANNOT authorise this; only the
    // operator presenting the break-glass token may. The signature is verified HERE against the engine's
    // pinned verifier (the same hybrid signer that signs archives) before the DO is touched, and the
    // no-custody invariant is re-asserted (refuse to import an artefact carrying any plaintext secret).
    case "POST /control-plane/restore": {
      // SECURITY (ASVS V6): also refuse a disabled or retired token (requireLiveBreakGlassToken) -- a bare
      // tokenEqual compare alone would let a token the Owner believes fully neutralised keep reconciling in
      // ANY historically-valid signed export (including a self-favouring one an ex-Owner retained),
      // permanently un-doing the retire.
      const denied = await requireLiveBreakGlassToken(req, env, scheduler, runtime);
      if (denied) return denied;
      const parsed = await parseJsonBody<{ export?: unknown; signature?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const exp = parsed.body.export;
      const signature = parsed.body.signature;
      if (!isControlPlaneExport(exp)) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile", cls: "shape" });
        return jsonRefusal("export is not a control-plane export artefact", 400, "shape");
      }
      if (typeof signature !== "string" || signature.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile", cls: "malformed" });
        return jsonRefusal("a detached signature is required", 400, "malformed");
      }
      // NO-CUSTODY re-assertion: never import an artefact that carries a plaintext secret (defence in depth
      // over the builder's redaction-by-construction). A violation throws; surface it as a 400.
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile", cls: "no-custody" });
        return jsonRefusal(`refused: ${(e as Error).message}`, 400, "no-custody");
      }
      // Verify the detached signature against the engine's PINNED verifier (the signer's public halves), so
      // a tampered or forged export (no SIGNER_PRIVATE => no valid signature) is rejected before any rebuild.
      if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile", cls: "no-signer" });
        return jsonError("cannot verify the export: SIGNER_PRIVATE is not configured", 500);
      }
      // G202: the same key-damaged vs export-tampered split as the estate import above. On THIS path the
      // key-side fault is a corrupt SIGNER_PRIVATE (the engine's OWN key will not load), which is a completely
      // different incident from a forged export -- and both produced "the export signature did not verify".
      // loadSigner is the only throw site left; the verify itself is total and returns the closed verdict.
      let reconcileVerdict: HybridVerifyVerdict;
      try {
        const signer = await loadSigner(env.SIGNER_PRIVATE);
        reconcileVerdict = await verifyControlPlaneSignatureDetailed(exp as ControlPlaneExport, signature, verifierFrom(signer));
      } catch (e) {
        log("error", `control-plane export signature verify failed: ${(e as Error).message}`);
        reconcileVerdict = "verifier-invalid"; // SIGNER_PRIVATE would not load: this engine's key is broken, the export is innocent
      }
      if (reconcileVerdict !== "ok") {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile", cls: RECOVERY_CLASS_BY_VERDICT[reconcileVerdict] });
        return jsonRefusal(recoveryVerifySentence(reconcileVerdict, "this engine's own signer key (SIGNER_PRIVATE)"), 400, RECOVERY_CLASS_BY_VERDICT[reconcileVerdict]);
      }
      // Forward to the DO under a synthesised break-glass TOKEN caller (the DO reconcile re-asserts
      // caller.method === "token"). The token caller carries no identity; the bridge audit attributes it
      // to the break-glass, exactly as the bootstrap path does.
      const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [], sourceIp };
      const resp = await scheduler.fetch(doURL("/control-plane/reconcile"), {
        method: "POST",
        body: JSON.stringify({ export: exp }),
        headers: callerHeaders(tokenCaller),
      });
      if (!resp.ok) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile", cls: "reconcile-refused" });
        const detail = await resp.text();
        return jsonError(`control-plane reconcile refused: ${detail.slice(0, 300)}`, resp.status === 403 ? 403 : 400);
      }
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json" } });
    }
    // The break-glass-gated SEALED reconcile -- the same-account counterpart of import-sealed above,
    // for the estate whose default export is sealed (control-plane-pass.ts:189, on by default whenever a
    // break-glass recipient is configured) and whose engine holds no CONFIG_RECIPIENT_PRIVATE, so the cron
    // auto-heal itself cannot open it either (refuses "sealed-no-op-key"). /control-plane/restore above
    // cannot take its place: that route verifies a signature over the PLAINTEXT export's own canonical
    // bytes, and buildControlPlaneArtefactToWrite (control-plane-seal.ts) writes ONE artefact per generation,
    // sealed OR plaintext, never both -- once sealing is on, no plaintext-verifiable signature is EVER
    // produced for a sealed generation, so no client-only trick derives one.
    //
    // The operator's OWN break-glass identity.key is a SECOND, independent recipient of the same sealed
    // capsule (control-plane-seal.ts seals to break-glass + config, always), so it opens what
    // CONFIG_RECIPIENT_PRIVATE would have. That unseal (identity.key decap + the two AEAD opens) runs
    // ENTIRELY in the operator's browser (keydecap.ts / sealed-export-unseal.ts), never here -- this route
    // never receives identity.key or any other private key, exactly the no-custody posture import-sealed
    // already established. It is handed the ORIGINAL sealed artefact (still encrypted; this engine holds no
    // key that opens it) plus its own detached signature, and separately the PLAINTEXT the browser already
    // recovered.
    //
    // Unlike import-sealed, this is SAME-ACCOUNT (the same engine that sealed the export also reconciles
    // it), so the sealed wrapper's signature is verified against THIS ENGINE'S OWN pinned signer
    // (env.SIGNER_PRIVATE), exactly as the plaintext /control-plane/restore above does -- never an
    // operator-supplied kit signer.pub, which is estate-import-sealed's cross-environment trust model, not
    // this route's. The bridge from "the sealed wrapper verified" to "this plaintext is what it committed
    // to" is the SAME bodyHash cross-check import-sealed uses (control-plane-seal.ts's
    // SealedControlPlaneExport.bodyHash): re-hash the candidate plaintext, compare to the signed commitment,
    // done, without this engine ever holding a recipient private key.
    //
    // Once both hold, this forwards to the SAME DO /control-plane/reconcile route the plaintext restore uses
    // (reconcileControlPlane): full AUTHORITY restore (RBAC + downpipes + destinations + discovery), gated
    // (DO-side, defence in depth) on the bare-token break-glass caller, and refusing unless the plane AND the
    // role table are both empty (never overwrites a live estate). Zero new DO code: this route only proves,
    // through a different verification path, the same thing the plaintext route already proves before
    // calling the identical reconcile.
    case "POST /control-plane/restore-sealed": {
      const denied = await requireLiveBreakGlassToken(req, env, scheduler, runtime);
      if (denied) return denied;
      const parsed = await parseJsonBody<{ sealed?: unknown; sealedSignature?: unknown; export?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const sealed = parsed.body.sealed;
      const sealedSignature = parsed.body.sealedSignature;
      const exp = parsed.body.export;
      if (!isSealedControlPlaneExport(sealed)) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "shape" });
        return jsonRefusal("sealed is not a sealed control-plane export artefact", 400, "shape");
      }
      if (typeof sealedSignature !== "string" || sealedSignature.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "malformed" });
        return jsonRefusal("a detached signature for the sealed artefact is required", 400, "malformed");
      }
      if (!isControlPlaneExport(exp)) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "shape" });
        return jsonRefusal("export is not a control-plane export artefact", 400, "shape");
      }
      // NO-CUSTODY re-assertion on the RECOVERED plaintext (defence in depth): a browser bug that leaked a
      // plaintext secret into the recovered export must not be waved through because the sealed wrapper
      // around it verified.
      try {
        assertNoPlaintextSecretInExport(exp);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "no-custody" });
        return jsonRefusal(`refused: ${(e as Error).message}`, 400, "no-custody");
      }
      if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "no-signer" });
        return jsonError("cannot verify the sealed export: SIGNER_PRIVATE is not configured", 500);
      }
      // Verify the SEALED wrapper's own signature against THIS ENGINE'S pinned signer (same-account: the
      // engine that sealed it is the one reconciling it) -- never the plaintext's; none was ever written for
      // a sealed generation (buildControlPlaneArtefactToWrite writes one artefact per generation).
      let sealedVerdict: HybridVerifyVerdict;
      try {
        const signer = await loadSigner(env.SIGNER_PRIVATE);
        sealedVerdict = await verifySealedControlPlaneSignatureDetailed(sealed as SealedControlPlaneExport, sealedSignature, verifierFrom(signer));
      } catch (e) {
        log("error", `sealed control-plane export signature verify failed: ${(e as Error).message}`);
        sealedVerdict = "verifier-invalid"; // SIGNER_PRIVATE would not load: this engine's key is broken, the artefact is innocent
      }
      if (sealedVerdict !== "ok") {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: RECOVERY_CLASS_BY_VERDICT[sealedVerdict] });
        return jsonRefusal(recoveryVerifySentence(sealedVerdict, "this engine's own signer key (SIGNER_PRIVATE)"), 400, RECOVERY_CLASS_BY_VERDICT[sealedVerdict]);
      }
      // THE BRIDGE (identical to import-sealed): the sealed signature proves the SEALED object (header +
      // capsule + bodyHash + the body ciphertext) is authentic; it says nothing on its own about whether THIS
      // candidate plaintext is what that ciphertext decrypts to (this engine holds no key that opens it, by
      // design -- CONFIG_RECIPIENT_PRIVATE is absent, which is why this route exists at all). bodyHash is the
      // signed commitment that closes the gap without this engine ever touching a private key or the
      // ciphertext.
      const bodyHash = (sealed as SealedControlPlaneExport).bodyHash;
      if (typeof bodyHash !== "string" || bodyHash.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "sealed-unhashed" });
        return jsonRefusal(
          "this sealed artefact was written before body-hash pinning, so it cannot be verified against the plaintext your browser recovered. Wait for the next scheduled export (or trigger one with a config change) and pull a fresh copy, or use the offline downpipe unseal-export command and reconcile by hand in the meantime.",
          400,
          "sealed-unhashed",
        );
      }
      const candidateHash = `sha384:${hexEncode(await sha384(serialiseControlPlaneExport(exp as ControlPlaneExport)))}`;
      if (candidateHash !== bodyHash) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "sealed-body-mismatch" });
        return jsonRefusal(
          "the sealed artefact's signature verified, but the plaintext handed to this route does not match what it was signed over. This is not the export the sealed artefact committed to: re-run the unseal in your browser and try again without editing the recovered JSON.",
          400,
          "sealed-body-mismatch",
        );
      }
      // Forward to the SAME DO reconcile the plaintext route uses, under the SAME synthesised break-glass
      // TOKEN caller (the DO re-asserts caller.method === "token"; it also re-asserts the plane AND the role
      // table are both empty, so this can never clobber a live estate).
      const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [], sourceIp };
      const resp = await scheduler.fetch(doURL("/control-plane/reconcile"), {
        method: "POST",
        body: JSON.stringify({ export: exp }),
        headers: callerHeaders(tokenCaller),
      });
      if (!resp.ok) {
        await recordRecoveryRefusal(scheduler, { surface: "reconcile-sealed", cls: "reconcile-refused" });
        const detail = await resp.text();
        return jsonError(`control-plane reconcile refused: ${detail.slice(0, 300)}`, resp.status === 403 ? 403 : 400);
      }
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json" } });
    }
    // The AUTO-HEAL break-glass CONFIRM: apply the staged export's AUTHORITY slice (restore RBAC, clear the
    // silence-killer latch, re-arm the first-Owner bootstrap, write the bridge audit). The cron auto-heal has
    // already verified + staged the export and resumed backups (the no-authority slice); this is the human
    // checkpoint that restores operator access. Gated DIRECTLY on the ADMIN_TOKEN break-glass bearer
    // (constant-time), exactly like demo-reset/restore and for the same reason: after a wipe the role table is
    // empty, so a passkey/Access caller resolves to recovery-required viewer and CANNOT authorise this. The
    // signature of the STAGED export is RE-VERIFIED HERE against the engine's pinned signer (defence in depth:
    // the SIGNER lives in the Worker, not the DO) and no-custody is re-asserted, so authority is never restored
    // from an unverifiable artefact even if the DO-staged record were somehow corrupted.
    case "POST /control-plane/apply-staged": {
      // SECURITY (ASVS V6): also refuse a disabled or retired token (requireLiveBreakGlassToken), same
      // reason as restore above: this route's own bearer compare must not outlive the Owner's decision.
      const denied = await requireLiveBreakGlassToken(req, env, scheduler, runtime);
      if (denied) return denied;
      const staged = (await (await scheduler.fetch(doURL("/control-plane/staged-export"), { method: "GET" })).json()) as StagedControlPlane | null; // the cron auto-heal parked it; absent means nothing to confirm
      if (staged === null) return jsonError(await nothingToConfirmMessage(scheduler), 409);
      if (!isControlPlaneExport(staged.export) || typeof staged.signature !== "string" || staged.signature.length === 0) {
        // G202: "apply-staged keeps 409ing on a corrupt staged artefact". This is the WEDGE: the auto-heal
        // parked an export the confirm can NEVER accept, so the operator presses the button, gets a 409, and
        // presses it again forever. It is a STANDING condition (not a transient refusal), so it latches its
        // own flag on the record -- the pack must be able to say "your staged artefact is broken; it will
        // never apply until the auto-heal re-stages", which no number of retries will change.
        await recordRecoveryRefusal(scheduler, { surface: "apply-staged", cls: "staged-malformed" });
        return jsonError(`the staged recovery export is malformed. ${await manualReconcileTail(scheduler)}`, 409);
      }
      // NO-CUSTODY re-assertion + signature RE-VERIFY before any authority is restored.
      try {
        assertNoPlaintextSecretInExport(staged.export);
      } catch (e) {
        await recordRecoveryRefusal(scheduler, { surface: "apply-staged", cls: "no-custody" });
        return jsonError(`refused: ${(e as Error).message}`, 400);
      }
      if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) {
        await recordRecoveryRefusal(scheduler, { surface: "apply-staged", cls: "no-signer" });
        return jsonError("cannot verify the staged export: SIGNER_PRIVATE is not configured", 500);
      }
      let stagedVerdict: HybridVerifyVerdict;
      try {
        const signer = await loadSigner(env.SIGNER_PRIVATE);
        stagedVerdict = await verifyControlPlaneSignatureDetailed(staged.export as ControlPlaneExport, staged.signature, verifierFrom(signer));
      } catch (e) {
        log("error", `staged control-plane export signature verify failed: ${(e as Error).message}`);
        stagedVerdict = "verifier-invalid"; // SIGNER_PRIVATE would not load: re-staging cannot fix that, and neither can retrying
      }
      if (stagedVerdict !== "ok") {
        // G202: the STAGED artefact's signature blob not decoding is the permanent WEDGE (the auto-heal parked
        // something this confirm can never accept), so it keeps the latching staged-malformed class rather than
        // the generic damaged-signature one: no number of retries will clear it until the auto-heal re-stages.
        // Every other verdict keeps its own row, so a corrupt SIGNER_PRIVATE is never reported as a tamper.
        const cls: RecoveryRefusalClass = stagedVerdict === "sig-decode" ? "staged-malformed" : RECOVERY_CLASS_BY_VERDICT[stagedVerdict];
        await recordRecoveryRefusal(scheduler, { surface: "apply-staged", cls });
        return jsonError(
          stagedVerdict === "sig-decode"
            ? "the staged recovery export's signature could not be READ, so the staged artefact is corrupt and this confirm can never succeed. Run the manual control-plane reconcile with a fresh copy of the export instead of retrying."
            : recoveryVerifySentence(stagedVerdict, "this engine's own signer key (SIGNER_PRIVATE)"),
          400,
        );
      }
      // Forward to the DO under a synthesised break-glass TOKEN caller (the DO re-asserts caller.method ===
      // "token"). The DO applies the AUTHORITY slice from ITS OWN staged record (re-read inside the DO).
      const tokenCaller: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [], sourceIp };
      const resp = await scheduler.fetch(doURL("/control-plane/apply-staged"), { method: "POST", headers: callerHeaders(tokenCaller) });
      if (!resp.ok) {
        await recordRecoveryRefusal(scheduler, { surface: "apply-staged", cls: "reconcile-refused" });
        const detail = await resp.text();
        return jsonError(`control-plane recovery confirm refused: ${detail.slice(0, 300)}`, resp.status === 403 ? 403 : 400);
      }
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json" } });
    }
    // ---- reads: any authenticated role (engine-auth) -------------------------------------
    case "GET /whoami": {
      // G257: WHOAMI PAYLOAD CONSISTENCY, checked at the one place the echo is built.
      //
      // The console builds its entire view of the operator from this body, and it degrades honestly when the
      // body is thin: the session card reads "not reported", the enforcement verifier declines to claim
      // "verified", and the role chip names no group. All of that is right, and all of it is indistinguishable
      // on this side from an engine that predates the route. These two counters are the difference.
      //
      // (a) UNRESOLVABLE CALLER: an email-bearing method (Access or passkey) reached the echo with no email. The
      //     bare-token break-glass is EXCLUDED: it has no email by design, it is the legitimate state, and a
      //     counter that fired on it would cry wolf on every break-glass session.
      if (caller.method !== "token" && (caller.email === null || caller.email === "")) {
        fireInBackground(runtime, recordAuthSignalEdge(scheduler, "whoami-caller-unresolvable"));
      }
      // (b) INCONSISTENT ROLE BASIS: the echo is about to tell the operator WHERE their authority comes from,
      //     and the payload beside it contradicts it. A role resolved from an email with no email to resolve
      //     from, or from an IdP group with no group in the list, is not a thin payload: it is a wrong one, and
      //     the console faithfully renders the contradiction ("your role comes from your identity-provider
      //     groups", and then no group is ever named). Neither is a legitimate state, so neither cries wolf.
      if (
        (roleSource === "email" && (caller.email === null || caller.email === ""))
        || (roleSource === "group" && caller.groups.length === 0)
      ) {
        fireInBackground(runtime, recordAuthSignalEdge(scheduler, "role-basis-inconsistent"));
      }
      // D1: combine the verified verdict (method/email/exp) with the DO-resolved role +
      // isOnlyOwner. The console renders the honest session chip and the real Access verdict
      // from this; it never fakes a green "verified" state it cannot back.
      const body: WhoAmI = {
        method: caller.method,
        email: caller.email,
        // subject is the stable identity key (absent for the bare-token break-glass). The console
        // displays the email as the human label and uses subject only as the internal mirror key.
        ...(caller.subject !== null ? { subject: caller.subject } : {}),
        role: caller.role,
        // roleSource is the honest BASIS of the role (owner-token / email / group / custom / default) so
        // the console can explain it; groups is the verified IdP group list that applied (the customer's
        // own data, fine to return to their own console). identityProvider is present only when the
        // verified token actually carried it. customRole + capabilities are present only when the caller
        // resolved to a NAMED custom role (roleSource "custom"), so the console can pick the skin, open
        // the landing screen and mirror the gates by the same capability set the engine enforces.
        roleSource,
        groups: caller.groups,
        ...(caller.identityProvider !== undefined ? { identityProvider: caller.identityProvider } : {}),
        ...(caller.connId !== undefined ? { connId: caller.connId } : {}),
        ...(verdict.exp !== undefined ? { sessionExpiresAt: verdict.exp } : {}),
        isOnlyOwner,
        ...(customRole !== undefined ? { customRole } : {}),
        ...(caller.capabilities !== undefined ? { capabilities: [...caller.capabilities] } : {}),
      };
      // R2 (ML-02): for a COOKIE-BORNE session, issue/refresh the double-submit CSRF token the console echoes
      // on the session-termination routes (defence in depth ON TOP of the strict-Origin guard, never a
      // replacement). Reuse the token already on the request when present (it is stable across the session and
      // a session slide does not rotate it) so the console's cached value keeps matching; otherwise mint a
      // fresh one. It is returned in the body AND set as the readable __Host- cookie in the same response, so
      // the console reads one and the browser holds the other. The token/access methods carry no ambient
      // cookie a foreign page could ride, so they get neither (mirroring the Origin guard's exemption).
      if (isCookieBorneMethod(caller.method)) {
        const existing = readCsrfCookie(req);
        const csrf = existing !== null && existing.length > 0 ? existing : mintCsrfToken();
        body.csrfToken = csrf;
        return new Response(JSON.stringify(body), { headers: { "content-type": "application/json", "set-cookie": csrfSetCookie(csrf) } });
      }
      return jsonResponse(body);
    }
    case "GET /roles": {
      // The member + role table. Gated on roles.read. B9: this capability was declared in the
      // contract and shown in the console's roles-builder (a creator could tick or untick it) but no
      // gate()/can() call anywhere ever checked it; the gate below closes that hole, making roles.read
      // a real, live authorisation check rather than a phantom one (proven directly against a
      // hand-built caller lacking it in validate-custom-roles.ts). PRECISE CLAIM: every built-in role
      // holds roles.read from the viewer floor up, and identity-rbac.ts's read floor is additionally
      // folded, unconditionally, into every custom role's resolved capability set (resolveAuthority,
      // scheduler-do-rbac.ts:530-533, "custom roles are additive"), so no custom role composable
      // through the product today can actually be excluded from it -- this gate is correct and
      // future-proofing, not a live boundary against any caller reachable now. The console escapes
      // the emails on render.
      const denied = gate(caller, "roles.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/roles"), { method: "GET", headers: callerHeaders(caller) });
    }
    // ---- Native external-IdP (OIDC) connection MANAGEMENT (keys.ceremony, owner-exclusive) ----------------
    // The management surface (the PRE-AUTH login flow is handleOidc, above the authorise gate). Gated on
    // keys.ceremony HERE and re-enforced in the DO (defence in depth): keys.ceremony is owner-reserved, so a
    // group-conferred access-admin can NOT add a hostile connection and self-escalate (a group can confer
    // access.policy, never keys.ceremony). The client secret, when supplied on create, is write-only: it goes
    // to the DO's idpsecret:<id> and is never read back (the redacted record carries only a {mode, ref?}).
    case "GET /idp/presets": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      return scheduler.fetch(doURL("/idp/presets"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /idp/connections": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      return scheduler.fetch(doURL("/idp/conn/list"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /idp/connections": {
      const parsed = await parseJsonBody<{ proposal?: unknown; secret?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const body = parsed.body;
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        // Record the refused connection-add (a caller without keys.ceremony attempting to wire an IdP). The
        // connId hint comes from the proposal id when it is a well-formed slug, else "unknown"; no secret is
        // read or recorded (the target type cannot hold one).
        const pid = body.proposal && typeof body.proposal === "object" && typeof (body.proposal as { id?: unknown }).id === "string" ? (body.proposal as { id: string }).id : "";
        const connId = /^[a-z0-9-]{1,64}$/.test(pid) ? pid : "unknown";
        await recordAudit(scheduler, caller, sourceIp, "idp-connection-change", "denied", { kind: "idpconnection", connId, connKind: "oidc", op: "create" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const created = await scheduler.fetch(doURL("/idp/conn/create"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      // G010: a proposal REFUSED by the pure pre-write validators returns {ok:false, reason} and writes NOTHING
      // anywhere -- so a dozen distinct refusals ("the issuer is not https", "no signing certificate",
      // "private_key_jwt is not wired") were the pack's only silent half of the "it never saves" ticket. Peek the
      // body on a CLONE (the caller's Response is returned untouched and unread), classify the reason to a closed
      // class and DISCARD it: the reason interpolates the operator's own submitted values, so only the class is
      // recorded. Best-effort throughout; the refusal the console renders is byte-identical.
      try {
        const peek = (await created.clone().json()) as { ok?: unknown; reason?: unknown };
        if (peek.ok === false) recordIdpSetupSignal(scheduler, idpValidationSignalName(classifyIdpValidationRefusal(peek.reason)), runtime);
      } catch {
        /* a non-JSON / already-consumed body records nothing: the refusal itself still reaches the console */
      }
      // G7: real-time alert on the sign-in trust surface. Fire-and-forget + fail-open (never affects the op).
      if (created.ok && !(await doRefusedTheChange(created))) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "auth-credential-change", "idp-change", `An IdP connection add was requested (changes who can sign in)${caller.email ? ` by ${caller.email}` : ""}.`));
      return created;
    }
    case "POST /idp/connections/delete": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const parsed = await parseJsonBody<{ connId?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      // G5: refuse if this delete would remove the last sign-in path with no other way back in.
      const delLock = await lockoutRefusalIfLastSignInPath(env, scheduler, typeof parsed.body.connId === "string" ? parsed.body.connId : "", runtime);
      if (delLock) return delLock;
      const deleted = await scheduler.fetch(doURL("/idp/conn/delete"), { method: "POST", body: JSON.stringify(parsed.body), headers: callerHeaders(caller) });
      if (deleted.ok && !(await doRefusedTheChange(deleted)) && !(await doDeletedNothing(deleted))) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "auth-credential-change", "idp-change", `An IdP connection removal was requested (changes who can sign in)${caller.email ? ` by ${caller.email}` : ""}.`));
      return deleted;
    }
    case "POST /idp/connections/enabled": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const parsed = await parseJsonBody<{ connId?: unknown; enabled?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      // G5: refuse if DISABLING this connection would remove the last sign-in path with no other way back in.
      if (parsed.body.enabled !== true) {
        const disLock = await lockoutRefusalIfLastSignInPath(env, scheduler, typeof parsed.body.connId === "string" ? parsed.body.connId : "", runtime);
        if (disLock) return disLock;
      }
      const enabledResp = await scheduler.fetch(doURL("/idp/conn/enabled"), { method: "POST", body: JSON.stringify(parsed.body), headers: callerHeaders(caller) });
      if (enabledResp.ok && !(await doRefusedTheChange(enabledResp))) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "auth-credential-change", "idp-change", `An IdP connection enable/disable was requested (changes who can sign in)${caller.email ? ` by ${caller.email}` : ""}.`));
      return enabledResp;
    }
    // POST /idp/connections/cert is the ZERO-DOWNTIME SAML signing-cert ROLLOVER edit (IDP-1): {connId, addCerts?,
    // certs?}. Before this, a cert rollover meant delete+recreate (which killed every live session and, under dual
    // control, queued twice with a broken-login window). The verifier already iterates the overlapping cert array,
    // so this appends (addCerts) or replaces (certs) the pinned set in place. Gated on the owner-exclusive
    // keys.ceremony like the rest of connection management (a signing cert is the SAML trust root); the DO re-runs
    // the gate AND routes it through the idp-conn-cert dual-control owner action (one approval, not two).
    case "POST /idp/connections/cert": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const parsed = await parseJsonBody<{ connId?: unknown; addCerts?: unknown; certs?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const certResp = await scheduler.fetch(doURL("/idp/conn/cert"), { method: "POST", body: JSON.stringify(parsed.body), headers: callerHeaders(caller) });
      if (certResp.ok && !(await doRefusedTheChange(certResp))) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "auth-credential-change", "idp-change", `A SAML signing-certificate rollover was requested (an IdP trust-root change)${caller.email ? ` by ${caller.email}` : ""}.`));
      return certResp;
    }
    // POST /idp/test runs a READ-ONLY pre-save "test connection" probe over an IdP connection config (OIDC,
    // OAuth2 or SAML), so a misconfiguration is caught BEFORE it is enabled rather than at the first sign-in
    // (assessment finding C1). It is the same governance class as the other IdP-management routes - the gate
    // is the owner-exclusive keys.ceremony (a connection is an authentication trust root), and a non-owner
    // attempt records a DENIED audit event with NO outbound fetch (the gate returns before runIdpConnectionTest
    // is ever reached). The probe does NOT touch the DO or storage (it operates on a possibly-UNSAVED config),
    // so unlike the create/delete/enable routes it runs IN THE ROUTER over the global fetch (injected into the
    // pure idp-test core). It is SSRF-disciplined (https-only + the engine's internal-host classifier +
    // redirect:"manual" with a 3xx refused + a byte cap + a per-fetch timeout) and TOLERANT (any fault is a failed CHECK, never a
    // 500). The result is the structured { ok, checks:[{name,status,detail}] } the console renders. The body
    // carries a `proposal` of the same shape idpconn stores; no secret is read or required (the probe needs
    // only the issuer/endpoints for OIDC and the public certs/metadata for SAML).
    case "POST /idp/test": {
      const parsed = await parseJsonBody<{ proposal?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const body = parsed.body;
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        // Record the refused test (a caller without keys.ceremony probing an IdP). The connId hint comes from
        // the proposal id when it is a well-formed slug, else "unknown"; no secret is read (the probe holds none).
        const proposal = body.proposal && typeof body.proposal === "object" ? (body.proposal as Record<string, unknown>) : {};
        const pid = typeof proposal.id === "string" ? proposal.id : "";
        const connId = /^[a-z0-9-]{1,64}$/.test(pid) ? pid : "unknown";
        const connKind = proposal.kind === "saml" || proposal.kind === "oauth2" ? proposal.kind : "oidc";
        await recordAudit(scheduler, caller, sourceIp, "idp-connection-change", "denied", { kind: "idpconnection", connId, connKind, op: "test" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const proposal = body.proposal && typeof body.proposal === "object" && !Array.isArray(body.proposal) ? (body.proposal as Record<string, unknown>) : {};
      // The probe is tolerant and never throws; it always returns a structured result, so this is always a 200
      // carrying { ok, checks }. The console reads ok + the per-check lines (it does not branch on HTTP status).
      const result = await runIdpConnectionTest(proposal, fetch);
      recordIdpTestOutcome(scheduler, result, runtime); // G010: the probe's closed fail class (never the submitted URL)
      return jsonResponse(result);
    }
    // POST /idp/test-saved runs the SAME read-only probe over a connection that is ALREADY STORED, so an
    // operator can re-verify a connection after an IdP-side change (a metadata move, a cert rollover)
    // without retyping it. The stored record is loaded REDACTED from the DO (a secretRef never carries a
    // value) and the probe needs no secret (issuer/endpoints for OIDC, public certs/metadata for SAML),
    // so nothing sensitive is read or sent. Same governance class as /idp/test: keys.ceremony gate with
    // a denied audit, rate limit, and a tolerant structured { ok, checks } result (an unknown id is a
    // failed CHECK, never a 500, so the console renders every outcome through one surface).
    case "POST /idp/test-saved": {
      const parsed = await parseJsonBody<{ connId?: unknown }>(req);
      if (!parsed.ok) return jsonError("request body must be valid JSON", 400);
      const rawId = typeof parsed.body.connId === "string" ? parsed.body.connId : "";
      const connId = /^[a-z0-9-]{1,64}$/.test(rawId) ? rawId : "unknown";
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        // Record the refused test (a caller without keys.ceremony probing a stored IdP connection). The
        // stored kind is unread at this point (the gate comes first), so the hint defaults like /idp/test.
        await recordAudit(scheduler, caller, sourceIp, "idp-connection-change", "denied", { kind: "idpconnection", connId, connKind: "oidc", op: "test" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      if (connId === "unknown") return jsonError("connId must be 1 to 64 chars of lowercase letters, digits and hyphen", 400);
      const listResp = await scheduler.fetch(doURL("/idp/conn/list"), { method: "GET", headers: callerHeaders(caller) });
      if (!listResp.ok) return jsonError("could not read the stored connections", 502);
      const { connections } = (await listResp.json()) as { connections?: Array<Record<string, unknown>> };
      const conn = (connections ?? []).find((c) => c.id === connId);
      if (conn === undefined) {
        const absent = { ok: false, checks: [{ name: "connection exists", status: "fail", detail: `no stored connection with id "${connId}"` }] };
        recordIdpTestOutcome(scheduler, absent, runtime);
        return jsonResponse(absent);
      }
      const result = await runIdpConnectionTest(conn, fetch);
      recordIdpTestOutcome(scheduler, result, runtime); // G010: same closed fail class on the re-verify path
      return jsonResponse(result);
    }
    default:
      return null;
  }
}
