// router-keys.ts -- the in-product key-ceremony routes: the no-CLI key install, the break-glass-public
// rotation, the targeted operational-key add (the minimal break-glass-only upgrade path, and the route that
// makes the posture switch below reversible), the break-glass-only posture switch, and the guided-setup
// acknowledge. The install/rotate/break-glass-only/
// acknowledge case bodies were MOVED VERBATIM from handleAdmin's switch in router.ts (the dispatch-split);
// add-operational is a NEW case added alongside them, in the same shape. The only change from the original
// inline bodies is reading the shared locals off the RouterCtx the hub builds once, so the owner-exclusive
// keys.ceremony gate on each route runs here exactly as it did inline. Imports shared primitives + the
// attach/secret-install helpers; never imports router.ts.


import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { addOperationalSecrets, installEngineSecrets, KeyCeremonyFault, keyCeremonyFaultOf, removeOperationalSecrets, rotateBreakGlassPublic } from "./attach.ts";
import type { AuditAction, AuditOutcome, AuditTarget } from "./audit-types.ts";
import { envFlagEnabled } from "./auth.ts";
import { cfFaultOf } from "./cf-api.ts";
import { flushDroppedWrites, noteDroppedWrite } from "./diag-writer.ts";
import type { Caller } from "./identity.ts";
import { computeKeyVintages, type KeyVintageInventory } from "./key-vintages.ts";
import {
  type PostureAckChannel,
  type PostureAckPrincipalType,
  type PostureChoice,
  postureAckStatementHash,
  resolvePostureAckStatement,
} from "./posture-ack-statements.ts";
import { gate, jsonError, jsonResponse, rateLimited, recordAudit, recordAuditCheckedAfterSelfDeploy } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { type DiscoveryConfigView, resolveEngineAccountId } from "./router-sources.ts";
import { buildStatus } from "./status.ts";

// postureAckPrincipalType resolves the evidentiary weight of the acknowledging caller from its auth
// method, so a bootstrap-token acknowledgement (unattributable to a person) is recorded as low weight
// and never reads as a named one: the bare ADMIN_TOKEN break-glass is "bootstrap-admin-token", a passkey
// caller (the engine's own strongest credential) is "owner-passkey", and a federated Access/OIDC/SAML
// identity is "named-operator".
function postureAckPrincipalType(caller: Caller): PostureAckPrincipalType {
  if (caller.method === "token") return "bootstrap-admin-token";
  if (caller.method === "passkey") return "owner-passkey";
  return "named-operator";
}

// DEFAULT_ENGINE_SCRIPT_NAME is the worker name a key ceremony names itself by when WORKER_NAME is unset.
const DEFAULT_ENGINE_SCRIPT_NAME = "downpipe-engine";

// recordKeyCeremonyFailure (G027) AUDITS a failed key ceremony. The trail carried keys-installed /
// break-glass-rotated / operational-removed on SUCCESS only, so an install that died at PUT #2 -- leaving the
// engine HALF-KEYED, signer set, break-glass not -- recorded nothing anywhere, and neither did a key-paste that
// would not parse. Remotely, "we installed the keys and backups still do not run" and "we never got past the key
// screen" were the same empty trail.
//
// What rides: the closed STEP (a fixed env-var NAME: signer / break-glass / operational-public /
// operational-private / preflight), the closed CAUSE (parse / missing / cf-put / cf-delete / other), and, when
// Cloudflare refused, the bounded CF evidence the API layer tagged (a status class plus Cloudflare's OWN numeric
// error codes, capped at 8). What NEVER rides: the pasted key, its length, the deploy token, the Cloudflare
// response body or the thrown message. An UNTAGGED throw is honestly recorded as cause "other" rather than being
// guessed at from its text. Best-effort: a dropped audit row never turns a failed ceremony into a different
// answer for the operator, whose 400 is byte-identical.
//
// afterSecretWrite is the Env, passed by the callers whose ceremony had ALREADY reached Cloudflare when
// it died. A ceremony that fails at PUT #2 has already rolled a worker version for PUT #1, so this append races
// the same Durable Object reset a successful one does, and this is the row the operator can least do without:
// it is the only durable evidence a HALF-KEYED engine ever leaves. The preflight refusals (an already-installed
// signer, an already-present operational key) pass nothing, because they return before any network call and so
// there is no version rollout to race.
async function recordKeyCeremonyFailure(
  scheduler: DurableObjectStub,
  caller: Caller,
  sourceIp: string | null,
  action: "key-install-failed" | "key-removal-failed",
  e: unknown,
  afterSecretWrite?: Env,
): Promise<void> {
  const tag = keyCeremonyFaultOf(e);
  const cf = cfFaultOf((e as { cause?: unknown } | null)?.cause ?? e);
  try {
    await auditChecked(
      scheduler,
      caller,
      sourceIp,
      action,
      "failed",
      {
        kind: "key-ceremony",
        step: tag?.step ?? "preflight",
        cause: tag?.cause ?? "other",
        ...(cf !== null ? { cfStatusClass: cf.statusClass, cfCodes: cf.cfCodes } : {}),
      },
      afterSecretWrite,
    );
  } catch (err) {
    log("warn", `${action} audit append failed: ${(err as Error).message.slice(0, 140)}`);
          // G100: the append is best-effort, but its LOSS is not silent: a key ceremony that leaves no
          // audit event makes the pack's configEvents read as though no ceremony ever happened.
          noteDroppedWrite("key-ceremony-audit");
          await flushDroppedWrites(scheduler);
  }
}

// resolveEngineAccountAndScript resolves the engine's OWN account id + script name the way every key
// ceremony needs them: the marked engineAccountId (else CF_ACCOUNT_ID) via resolveEngineAccountId, and
// WORKER_NAME (else the default). It fetches the discovery-config the resolver reads. Without an account
// the engine cannot name itself for the secret PUTs, so it returns the honest 400 Response the caller
// returns verbatim; otherwise it returns { accountId, scriptName }. failMsg lets each route phrase the
// "account not set" guidance in its own words (install vs rotate vs posture-change).
async function resolveEngineAccountAndScript(ctx: RouterCtx, failMsg: string): Promise<{ accountId: string; scriptName: string } | Response> {
  const { env, scheduler } = ctx;
  const cfgResp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
  const cfg = ((await cfgResp.json()) as { config?: DiscoveryConfigView | null }).config ?? null;
  const accountId = await resolveEngineAccountId(env, cfg);
  if (accountId === null) return jsonError(failMsg, 400);
  const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : DEFAULT_ENGINE_SCRIPT_NAME;
  return { accountId, scriptName };
}

// KeyInstallBody is the untrusted /keys/install body (every field unknown; only the string halves are read).
type KeyInstallBody = { token?: unknown; signerPrivate?: unknown; breakGlassPublic?: unknown; operationalPublic?: unknown; operationalPrivate?: unknown };

// installSecretsAndAudit runs the landed-install sequence: installEngineSecrets (which VALIDATES every
// key with the engine's own loaders BEFORE any network call), the name-only success audit (best-effort:
// a dropped row never turns a landed install into a failure), and the demo first-run marker clear
// (best-effort, harmless off-demo). It returns the 200 the route returns; installEngineSecrets throws a
// coarse value-free reason on a bad key or a CF scope failure, which the caller maps to a 400.
//
// Cloudflare rolls a NEW WORKER VERSION per secret PUT, and a new version resets this Worker's Durable
// Objects. The append below is therefore a post-self-deploy append and takes the same reset ladder the
// source-attach appends take, through auditChecked's afterSecretWrite argument.
async function installSecretsAndAudit(ctx: RouterCtx, accountId: string, scriptName: string, body: KeyInstallBody): Promise<Response> {
  const { env, scheduler, caller, sourceIp } = ctx;
  const result = await installEngineSecrets(accountId, scriptName, {
    token: typeof body.token === "string" ? body.token : "",
    signerPrivate: typeof body.signerPrivate === "string" ? body.signerPrivate : "",
    breakGlassPublic: typeof body.breakGlassPublic === "string" ? body.breakGlassPublic : "",
    ...(typeof body.operationalPublic === "string" ? { operationalPublic: body.operationalPublic } : {}),
    ...(typeof body.operationalPrivate === "string" ? { operationalPrivate: body.operationalPrivate } : {}),
  });
  // Audit by NAME only: the structured engine log names the secrets set; the closed key-ceremony target
  // records who + when. No private value, no token.
  const names = ["SIGNER_PRIVATE", "BREAK_GLASS_PUBLIC", ...(result.configured.operational ? ["OPERATIONAL_PUBLIC", "OPERATIONAL_PRIVATE"] : [])];
  const markerNote = result.configured.operational ? "; the OPERATIONAL_RETIRED marker (B7) is cleared best-effort" : "";
  log("info", `keys-installed: set engine secrets ${names.join(", ")} (values never logged)${markerNote}`);
  try {
    // CHECKED, not merely attempted. recordAudit does NOT throw on a non-2xx from the audit DO: it counts
    // the loss as an "audit-write" drop and then RETURNS NORMALLY, parsing the DO's error body as an
    // AuditEvent (router-audit.ts, and its own comment says a non-2xx "still surfaces to the caller exactly
    // as before", which means it does not surface as an error at all). So the catch below, which exists
    // precisely to notice a lost KEY-CEREMONY audit, could never fire for the commonest form of the loss:
    // this handler believed it had audited.
    //
    // A real append always carries a numeric seq (AuditEvent.seq), so that is what is checked.
    //
    // Checked HERE rather than in recordAudit itself: there are many call sites, most of them a bare
    // inline await, so making it throw would turn a dropped audit into a 500 across the engine. The key
    // ceremony is the one operation where a missing trail is worst, so it is the one that checks.
    //
    // env is passed, so this append also carries the DO-reset ladder. The seq check alone could never have
    // caught this loss, because the four secret PUTs above roll four worker versions and the append can
    // THROW on the reset before there is any response to check the seq of.
    await auditChecked(scheduler, caller, sourceIp, "keys-installed", "success", { kind: "key-ceremony" }, env);
  } catch (e) {
    log("warn", `keys-installed audit append failed: ${(e as Error).message.slice(0, 140)}`);
          // G100: the append is best-effort, but its LOSS is not silent: a key ceremony that leaves no
          // audit event makes the pack's configEvents read as though no ceremony ever happened.
          noteDroppedWrite("key-ceremony-audit");
          await flushDroppedWrites(scheduler);
  }
  // Clear the demo fresh-first-run marker (a demo reset set it to force the wizard back to the ceremony;
  // the operator has now re-run it). Best-effort + harmless on a non-demo engine (the marker is never set there).
  //
  // CHECKED, not merely attempted, exactly like the audit append above it. This was a bare `catch {}` with no
  // drop tracking, so a lost clear was invisible, and the loss is not cosmetic: the marker MASKS the key
  // booleans, so an estate whose clear failed reports KEYLESS while physically holding keys. Worse,
  // installRekeyDecision reads that same masked view, so the already-provisioned guard is blind and every
  // subsequent "first install" silently RE-KEYS the estate for real, which is the one thing that guard exists
  // to prevent.
  //
  // A lost clear can leave the estate reporting signer=false breakGlass=false ready=false even though the
  // install landed, masking the already-provisioned guard and risking a silent re-key on the next "first
  // install".
  //
  // Still FAIL-OPEN: a lost clear must never turn a landed install into a failure for the operator. It is the
  // SILENCE that is fixed here, not the tolerance.
  try {
    const cleared = await scheduler.fetch(doURL("/demo/first-run/clear"), { method: "POST" });
    if (!cleared.ok) {
      log("warn", `demo first-run marker clear answered ${cleared.status}: the estate may report keyless while holding keys`);
      noteDroppedWrite("demo-first-run-clear");
      await flushDroppedWrites(scheduler);
    }
  } catch (e) {
    log("warn", `demo first-run marker clear failed: ${(e as Error).message.slice(0, 140)}`);
    noteDroppedWrite("demo-first-run-clear");
    await flushDroppedWrites(scheduler).catch(() => {});
  }
  return jsonResponse({ ok: true, signerPublic: result.signerPublic, configured: result.configured });
}

// installRekeyDecision reads the demo-masked signer presence (the SAME signerConfigured GET /admin/status
// reports, so engine and console agree) and decides what a POST /keys/install should do about an ALREADY-
// PRESENT signer. This is the custody guard: a second install would OVERWRITE SIGNER_PRIVATE, mint a fresh
// signer, and break signature verification of EVERY prior run receipt, so a re-key must never happen silently.
//   - no signer present -> { proceed: true, rekey: false }: a normal FIRST install. This covers a genuinely
//     fresh engine AND a demo reset (the fresh-first-run marker masks the persisted secret exactly as it does
//     for the onboarding wizard, so the legitimate demo re-run installs without a flag and is not refused).
//   - signer present, caller confirmed -> { proceed: true, rekey: true }: the DELIBERATE, warned re-key (the
//     console sets confirmRekey only from the state-aware re-key card, AFTER showing the signer-continuity
//     warning). This is the "explicit, warned route" the full re-key keeps.
//   - signer present, NOT confirmed -> { proceed: false }: the case body refuses + audits, so a SILENT re-key
//     is impossible. Mirrors the add-operational already-configured refusal.
// The demo marker is read ONLY on a demo engine (no per-request DO round-trip in production); a failed read is
// presence-safe (it leaves the marker unread, so the guard errs towards the production reading).
async function installRekeyDecision(ctx: RouterCtx, confirmed: boolean): Promise<{ proceed: boolean; rekey: boolean }> {
  const { env, scheduler } = ctx;
  let demoFreshFirstRun: boolean | undefined;
  if (envFlagEnabled(env.DEMO_MODE)) {
    try {
      const frResp = await scheduler.fetch(doURL("/demo/first-run"), { method: "GET" });
      const { forceFirstRun } = (await frResp.json()) as { forceFirstRun?: boolean };
      if (forceFirstRun === true) demoFreshFirstRun = true;
    } catch { /* presence-safe: an unread marker never fails the install on a demo read */ }
  }
  const signerPresent = buildStatus(env, 0, demoFreshFirstRun !== undefined ? { demoFreshFirstRun } : {}).signerConfigured;
  if (!signerPresent) return { proceed: true, rekey: false };
  return { proceed: confirmed, rekey: true };
}

// handleKeys dispatches the key-ceremony + setup-acknowledge group. Returns the route's Response, or null
// when no case here matched (the hub falls to the next spoke).

/**
 * Appends an audit event and COUNTS the loss when it does not land.
 *
 * WHY THIS EXISTS. recordAudit does NOT throw when the audit DO answers a non-2xx: it counts an
 * "audit-write" drop and then returns normally, parsing the DO's error body as an AuditEvent
 * (router-audit.ts, whose comment says a non-2xx "still surfaces to the caller exactly as before", meaning
 * it does not surface as an error at all). A bare try/catch around recordAudit cannot see that case at all,
 * so a call site can believe it has audited when it has not.
 *
 * A real append always carries a numeric seq (AuditEvent.seq), so that is the check. Checked HERE rather
 * than by making recordAudit throw: there are many call sites across the engine, essentially all a bare
 * inline await, so throwing would turn a dropped audit into a 500. The key-ceremony family is where a
 * missing trail is worst, so it is the family that checks -- including the two POST
 * /keys/posture-acknowledgement appends, since that route is the customer's LIABILITY RECORD: its whole
 * purpose is that an entry exists saying which posture was accepted, in which words, by whom.
 *
 * afterSecretWrite is the Env, and it is supplied by exactly the appends that run AFTER this router has
 * mutated the engine's own worker secrets. Every Cloudflare secret PUT or DELETE rolls a NEW WORKER VERSION,
 * and a new version RESETS this Worker's Durable Objects, so those appends race the rollout and can throw
 * "Durable Object reset because its code was updated" on the stub the isolate already holds. Checking the
 * seq cannot see that at all: the call throws before there is anything to check. When the Env is supplied
 * the append runs through recordAuditCheckedAfterSelfDeploy, which keeps this seq check and adds the reset
 * ladder over a FRESH stub, the same remedy the source-attach appends use.
 *
 * The denial and preflight-failure appends deliberately do NOT pass it: they return before any secret is
 * written, so there is no version rollout to race and a retry ladder there would only be noise.
 */
async function auditChecked(
  scheduler: DurableObjectStub,
  caller: Caller,
  sourceIp: string | null,
  action: AuditAction,
  outcome: AuditOutcome,
  target: AuditTarget,
  afterSecretWrite?: Env,
): Promise<void> {
  if (afterSecretWrite !== undefined) {
    await recordAuditCheckedAfterSelfDeploy(afterSecretWrite, caller, sourceIp, action, outcome, target, "key-ceremony-audit");
    return;
  }
  const appended = await recordAudit(scheduler, caller, sourceIp, action, outcome, target);
  if (typeof appended?.seq !== "number") {
    log("warn", `${action} audit append returned no event (seq absent): the append did not land`);
    noteDroppedWrite("key-ceremony-audit");
    await flushDroppedWrites(scheduler);
  }
}

export async function handleKeys(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, sourceIp } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- key-vintage INVENTORY (keyless, manifest-authoritative; G-P0-098 + G-P0-099 surfacing) -----
    // GET /keys/vintages returns which archive vintages each key opens, which runs are stranded to a key that
    // is NOT currently installed, and the signer-continuity rollup the re-key surface needs. It is a READ,
    // gated on downpipe.read (the same cap as GET /history and GET /runs/at, the sibling run-history reads;
    // GATE-GAP: /history named no capability at all until this sentence was checked against it,
    // so for as long as the two siblings disagreed the claim was true of the intent and false of the code),
    // and it discloses ONLY public dpr1:/edmldsa1: fingerprints, the closed role enum and run counts -- never a
    // key. The stranded verdict is derived from each run's SIGNATURE-VERIFIED root manifest read back keylessly
    // (admin/key-vintages.ts), so no recorded index can fabricate a false "safe". A GET, so no rate-limit
    // pre-check (the reads are exempt), exactly like the other run-history reads.
    case "GET /keys/vintages": {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      const inventory: KeyVintageInventory = await computeKeyVintages(env, scheduler);
      return jsonResponse({ inventory });
    }

    // ---- in-product KEY INSTALL (the no-customer-CLI ceremony) --------------------------------------
    // POST /keys/install: the engine installs the in-browser key-ceremony output as its OWN worker
    // secrets via the Cloudflare dedicated secrets endpoint, using the scoped "Edit Cloudflare Workers"
    // token in the request body for the writes only. This is the no-customer-CLI replacement for
    // `wrangler secret put SIGNER_PRIVATE` etc. (the hard rule: after the first deploy, every action
    // is done IN the console). It REUSES the source-attach trust model: the token is NEVER persisted
    // (no DO write, no env write) and never logged; the install is AUDITED BY NAME only (the secret
    // names set), never a value. Owner-exclusive (keys.ceremony) + rate-limited. The keys are VALIDATED
    // with the engine's own loaders BEFORE any network call (installEngineSecrets), so a malformed paste
    // sets nothing and makes zero API calls. Secrets set this way are available WITHOUT a redeploy; the
    // console polls GET /admin/status until they read present.
    case "POST /keys/install": {
      // Read the body BEFORE the gate so a REFUSED attempt records what was tried (the same discipline as
      // the IdP connection-add), but NEVER record the token or any private value (only that an install
      // was attempted; the closed key-ceremony target carries who + when, no value). A malformed body
      // degrades to {} so the gate still applies (a non-owner is still refused; an owner falls through to
      // installEngineSecrets, which 400s on the missing keys) rather than throwing past the gate.
      const body = (await req.json().catch(() => ({}))) as { token?: unknown; signerPrivate?: unknown; breakGlassPublic?: unknown; operationalPublic?: unknown; operationalPrivate?: unknown; confirmRekey?: unknown };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        // Record the refused install (a caller without keys.ceremony attempting to write the engine's
        // signing/recipient secrets). Field-less key-ceremony target: who + when + the denied outcome.
        await auditChecked(scheduler, caller, sourceIp, "keys-installed", "denied", { kind: "key-ceremony" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // ALREADY-PROVISIONED GUARD (custody-critical): a signer already present means this install would
      // OVERWRITE SIGNER_PRIVATE, mint a fresh signer, and break signature verification of EVERY prior run
      // receipt. Refuse unless the caller carried an explicit confirmRekey flag (the deliberate, warned
      // re-key), so a SILENT re-key is impossible while a genuine FIRST install and a demo re-run still work.
      const rekeyDecision = await installRekeyDecision(ctx, body.confirmRekey === true);
      if (!rekeyDecision.proceed) {
        // Refuse a silent re-key, exactly as add-operational refuses a re-add, and AUDIT it (key-install-
        // failed, cause already-configured) so a blocked re-key leaves a trace rather than an unaudited 400.
        const fault = new KeyCeremonyFault(
          "preflight",
          "already-configured",
          new Error(
            'a signer is already installed; installing a new key set here would REPLACE it, and every run signed by the current signer would stop verifying through this console. This route only performs the first install. To re-key deliberately, use the Keys > Posture re-key flow, which warns first and confirms the replacement; to add in-account restore proof WITHOUT touching your signer, use "Add an operational key" instead.',
          ),
        );
        await recordKeyCeremonyFailure(scheduler, caller, sourceIp, "key-install-failed", fault);
        return jsonError(fault.message, 400);
      }
      if (rekeyDecision.rekey) {
        // A CONFIRMED, deliberate re-key (a prior signer was present AND the console set confirmRekey after
        // showing the signer-continuity warning). Log it distinctly so a re-key is legible in the engine log,
        // not just a second keys-installed row; the name-only success audit still rides inside
        // installSecretsAndAudit below. Values are never logged.
        log("info", "keys-installed: DELIBERATE RE-KEY confirmed (a prior signer is being REPLACED; runs signed by the OLD signer stop verifying through this console; values never logged)");
      }
      // Resolve the engine's OWN account + script name exactly as the source-attach route does. Without
      // an account the engine cannot name itself, so it refuses (the console marks the account under Sources).
      const resolved = await resolveEngineAccountAndScript(ctx, "the engine's own account is not set; add a read-only discovery token or pick the account under Sources before installing keys (no command line needed)");
      if (resolved instanceof Response) return resolved;
      const { accountId, scriptName } = resolved;
      try {
        return await installSecretsAndAudit(ctx, accountId, scriptName, body);
      } catch (e) {
        // installEngineSecrets throws a coarse, value-free reason (a bad key, or a CF scope failure on a
        // PUT). Surface it as a 400; nothing (or only the secrets named before the failure) was set.
        // G027: record WHICH step died and WHY first -- this is the only durable evidence a half-keyed engine
        // (or a struggling paste) ever leaves. Closed step + closed cause + the bounded Cloudflare evidence.
        await recordKeyCeremonyFailure(scheduler, caller, sourceIp, "key-install-failed", e, env);
        return jsonError((e as Error).message.slice(0, 300), 400);
      }
    }

    // ---- break-glass key rotation (no-customer-CLI; owner-exclusive) -------------------------------
    // POST /keys/rotate writes ONLY a new BREAK_GLASS_PUBLIC via a one-shot scoped token, exactly the
    // way /keys/install writes its secrets (the new public is observed on the next seal, no redeploy).
    // The signer and operational secrets are untouched: this is a rotation, not a re-key, so archives
    // sealed before it still need the OLD identity.key (the console states this loudly). Owner-gated,
    // rate-limited, name-only audit; the new break-glass private never leaves the browser, so no private
    // value and no token ever reaches the engine beyond the single PUT body Cloudflare requires.
    case "POST /keys/rotate": {
      const body = (await req.json().catch(() => ({}))) as { token?: unknown; breakGlassPublic?: unknown };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        await auditChecked(scheduler, caller, sourceIp, "break-glass-rotated", "denied", { kind: "key-ceremony" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const cfgResp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
      const cfg = ((await cfgResp.json()) as { config?: DiscoveryConfigView | null }).config ?? null;
      const accountId = cfg?.engineAccountId ?? (typeof env.CF_ACCOUNT_ID === "string" && env.CF_ACCOUNT_ID.trim() !== "" ? env.CF_ACCOUNT_ID.trim() : null);
      if (accountId === null) {
        return jsonError("the engine's own account is not marked yet; choose it under Sources before rotating keys", 400);
      }
      const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
      try {
        await rotateBreakGlassPublic(accountId, scriptName, typeof body.token === "string" ? body.token : "", typeof body.breakGlassPublic === "string" ? body.breakGlassPublic : "");
        log("info", "break-glass-rotated: set engine secret BREAK_GLASS_PUBLIC (value never logged)");
        try {
          // env is passed. rotateBreakGlassPublic PUT a worker secret, which rolls a new worker
          // version and resets this Worker's Durable Objects, so this append can throw on the reset.
          await auditChecked(scheduler, caller, sourceIp, "break-glass-rotated", "success", { kind: "key-ceremony" }, env);
        } catch (e) {
          log("warn", `break-glass-rotated audit append failed: ${(e as Error).message.slice(0, 140)}`);
          // G100: the append is best-effort, but its LOSS is not silent: a key ceremony that leaves no
          // audit event makes the pack's configEvents read as though no ceremony ever happened.
          noteDroppedWrite("key-ceremony-audit");
          await flushDroppedWrites(scheduler);
        }
        return jsonResponse({ ok: true });
      } catch (e) {
        // G027: a FAILED rotation is a first-class key-ceremony fault (a bad paste, or Cloudflare refusing the
        // PUT), and left no trace before this. Same closed step + cause + bounded CF evidence.
        await recordKeyCeremonyFailure(scheduler, caller, sourceIp, "key-install-failed", e, env);
        return jsonError((e as Error).message.slice(0, 300), 400);
      }
    }

    // ---- targeted operational-key ADD (no-customer-CLI; owner-exclusive; refuses if already present) --
    // POST /keys/add-operational is the minimal upgrade path for a break-glass-only engine: the true
    // targeted add the ceremony never had. It installs ONLY OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE via
    // a one-shot scoped token, the same one-shot-token path /keys/install and /keys/rotate use.
    // SIGNER_PRIVATE and BREAK_GLASS_PUBLIC are never read or written here, so this can never rotate the
    // signer or the break-glass recipient as a side effect: every existing run stays signed by the same
    // signer and console-verifiable exactly as before (contrast /keys/install, which always mints a fresh
    // signer and break-glass pair too). Archives sealed before this call stay break-glass-only recoverable,
    // permanently; only new runs, sealed after, gain the operational recipient (the recipient set is baked
    // into each archive at seal time and is never rewrapped later). REFUSES, rather than silently
    // reissuing, when an operational key is already present: this route only ever ADDS to a break-glass-
    // only engine, never replaces an existing pair (replacing one is the full "Generate keys" re-key
    // ceremony's job, or remove-then-add via the Posture tab's break-glass-only switch). Owner-gated,
    // rate-limited, name-only audit; the operational private is validated with the engine's own loader
    // before any network call and is never logged or returned.
    case "POST /keys/add-operational": {
      const body = (await req.json().catch(() => ({}))) as { token?: unknown; operationalPublic?: unknown; operationalPrivate?: unknown };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        await auditChecked(scheduler, caller, sourceIp, "operational-added", "denied", { kind: "key-ceremony" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // REFUSE, not silently rotate: an operational key already present means this is not a break-glass-
      // only engine any more, so the targeted add is the wrong tool. Nothing is read or written past here.
      // Routed through the same KeyCeremonyFault + recordKeyCeremonyFailure path as every other ceremony
      // refusal, so an add-operational attempt against an already-configured engine leaves an audited
      // key-install-failed row (cause "already-configured") rather than an unaudited 400.
      if (env.OPERATIONAL_PUBLIC || env.OPERATIONAL_PRIVATE) {
        const fault = new KeyCeremonyFault(
          "preflight",
          "already-configured",
          new Error(
            'an operational key is already installed; this route only adds a NEW operational key to a break-glass-only engine, it never replaces one. To replace it, run the full "Generate keys" ceremony (Posture tab), or remove the operational key first (Posture tab: switch to break-glass-only) and add a fresh one.',
          ),
        );
        await recordKeyCeremonyFailure(scheduler, caller, sourceIp, "key-install-failed", fault);
        return jsonError(fault.message, 400);
      }
      const resolved = await resolveEngineAccountAndScript(ctx, "the engine's own account is not set; add a read-only discovery token or pick the account under Sources before adding an operational key");
      if (resolved instanceof Response) return resolved;
      const { accountId, scriptName } = resolved;
      try {
        await addOperationalSecrets(
          accountId,
          scriptName,
          typeof body.token === "string" ? body.token : "",
          typeof body.operationalPublic === "string" ? body.operationalPublic : "",
          typeof body.operationalPrivate === "string" ? body.operationalPrivate : "",
        );
        log("info", "operational-added: set engine secrets OPERATIONAL_PUBLIC, OPERATIONAL_PRIVATE (values never logged; SIGNER_PRIVATE and BREAK_GLASS_PUBLIC untouched); the OPERATIONAL_RETIRED marker (B7) is cleared best-effort");
        try {
          // env is passed. addOperationalSecrets PUT two worker secrets (and cleared a marker), so
          // this append runs in the version-rollout window that resets this Worker's Durable Objects.
          await auditChecked(scheduler, caller, sourceIp, "operational-added", "success", { kind: "key-ceremony" }, env);
        } catch (e) {
          log("warn", `operational-added audit append failed: ${(e as Error).message.slice(0, 140)}`);
          // G100: the append is best-effort, but its LOSS is not silent: a key ceremony that leaves no
          // audit event makes the pack's configEvents read as though no ceremony ever happened.
          noteDroppedWrite("key-ceremony-audit");
          await flushDroppedWrites(scheduler);
        }
        return jsonResponse({ ok: true });
      } catch (e) {
        // G027: record WHICH step died and WHY, the same discipline as install/rotate. A half-applied add
        // (operational-public set, operational-private not) is auditable, not invisible.
        await recordKeyCeremonyFailure(scheduler, caller, sourceIp, "key-install-failed", e, env);
        return jsonError((e as Error).message.slice(0, 300), 400);
      }
    }

    // ---- strict break-glass-only posture (no-customer-CLI; owner-exclusive) ------------------------
    // POST /keys/break-glass-only removes BOTH operational worker secrets via a one-shot scoped token,
    // so the engine holds no key that can read an archive. SAFE for recovery: every archive is wrapped
    // to the break-glass recipient too, so the offline identity.key still recovers everything (including
    // archives sealed while operational was present); only the engine's self-test-restore ability is
    // removed. WHAT IS IRREVERSIBLE HERE IS THE KEY MATERIAL, NOT THE POSTURE, and the two are worth
    // keeping apart because reading the second into the first is a mistake this repo has now made in
    // several places. The deleted pair is gone, and archives sealed to it never regain an operational
    // recipient (the recipient set is baked into each archive at seal time and is never rewrapped later),
    // so a self-test-restore of those runs never comes back. The POSTURE reverses: POST
    // /keys/add-operational above installs a FRESH operational pair on this engine and clears the
    // OPERATIONAL_RETIRED marker, and runs sealed after that call carry the new operational recipient.
    // Owner-gated, rate-limited; a name-only audit row is the durable evidence of the change.
    case "POST /keys/break-glass-only": {
      const body = (await req.json().catch(() => ({}))) as { token?: unknown; confirmDiscardStranded?: unknown };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        await auditChecked(scheduler, caller, sourceIp, "operational-removed", "denied", { kind: "key-ceremony" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // DISCARD-GUARD (custody-critical, G-P0-098): removing the operational key strands any archive wrapped to
      // operational whose break-glass vintage is NO LONGER the current one -- operational is then the LAST
      // currently-installed recipient that opens it, so discarding it is silent, permanent, old-vintage data
      // loss. Read the manifest-authoritative, keyless, ok-only vintage inventory and REFUSE the switch when it
      // would strand such a run, or when the impact could not be fully determined, UNLESS the owner explicitly
      // confirmed (confirmDiscardStranded). The console shows the count first; the bare confirm is the deliberate,
      // warned path, exactly as the deliberate re-key is confirmed. It NEVER blocks the ordinary case: with every
      // archive still wrapped to the CURRENT break-glass (no rotation) nothing is sole-access-openable by
      // operational, so the switch proceeds unchanged. Fails CLOSED toward caution: an inventory that cannot be
      // computed is treated as "not fully determined" (refuse-unless-confirmed), never silently allowed.
      if (body.confirmDiscardStranded !== true) {
        let inv: KeyVintageInventory | null = null;
        try {
          inv = await computeKeyVintages(env, scheduler);
        } catch (e) {
          log("warn", `break-glass-only discard-guard: inventory unavailable (${(e as Error).message.slice(0, 120)}); refusing unless confirmed`);
        }
        const sole = inv?.operationalSoleAccessRunCount ?? 0;
        const unknown = inv?.stranded.unknownCount ?? 0;
        const truncated = inv?.truncated ?? true; // an unavailable inventory reads as "not fully determined"
        // historyIncomplete: the inventory could not enumerate the runs to inspect (a /history fault, or no
        // inventory at all). Without the run list the impact cannot be determined, so a zero count is "not read",
        // NOT "nothing at stake" -- the fail-open the refuter landed, where a transient /history 5xx read as
        // zero-to-strand and let the last recipient be discarded silently.
        const historyIncomplete = inv === null || inv.historyReadOk === false;
        // Refuse when removing operational is KNOWN to strand a run (sole > 0), or when the inventory could not
        // fully rule that out (an unreadable/prior-signer manifest, a truncated scan, a /history fault, or no
        // inventory at all): custody-safety never asserts "safe" from an incomplete read.
        if (sole > 0 || unknown > 0 || truncated || historyIncomplete) {
          const parts: string[] = [];
          if (sole > 0) parts.push(`${sole} archive${sole === 1 ? "" : "s"} can be opened only by the operational key you are removing (${sole === 1 ? "it is" : "they are"} sealed to a break-glass key that is not your current one)`);
          if (unknown > 0) parts.push(`${unknown} run${unknown === 1 ? "'s" : "s'"} recipient vintage could not be read back to confirm it is safe`);
          if (inv === null) parts.push("the key-vintage inventory could not be computed, so the impact could not be checked");
          else {
            if (inv.historyReadOk === false) parts.push("the run history could not be read in full, so the impact could not be checked");
            if (truncated) parts.push("more archives exist than one inventory pass reads, so older ones were not checked");
          }
          // Correction 6: the scope caveat reaches the GUARD copy, so a low count is never read as "little at stake".
          const reason = `switching to break-glass-only is refused to prevent silent data loss: ${parts.join("; ")}. Older archives beyond retained run history may also need this key. If you have retained the offline identity.key for every prior vintage, retry with confirmation; otherwise those archives would become unrecoverable.`;
          await auditChecked(scheduler, caller, sourceIp, "operational-removed", "denied", { kind: "key-ceremony" });
          return new Response(
            JSON.stringify({ error: reason, discardGuard: true, strandedRunCount: sole, unknownRunCount: unknown, truncated: inv?.truncated ?? true, historyReadOk: inv?.historyReadOk ?? false }),
            { status: 409, headers: { "content-type": "application/json" } },
          );
        }
      } else {
        // A CONFIRMED, deliberate discard: the owner acknowledged (after the console showed the stranded count)
        // that they have retained the offline identity.key for any vintage that would otherwise be stranded. Log
        // it distinctly so a confirmed stranding is legible in the engine log, not just a second operational-
        // removed row; the name-only success audit still rides below. Values are never logged.
        log("info", "operational-removed: DISCARD CONFIRMED (owner confirmed retaining the offline identity.key for any vintage that would otherwise be stranded; values never logged)");
      }
      const cfgResp = await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" });
      const cfg = ((await cfgResp.json()) as { config?: DiscoveryConfigView | null }).config ?? null;
      const accountId = cfg?.engineAccountId ?? (typeof env.CF_ACCOUNT_ID === "string" && env.CF_ACCOUNT_ID.trim() !== "" ? env.CF_ACCOUNT_ID.trim() : null);
      if (accountId === null) {
        return jsonError("the engine's own account is not marked yet; choose it under Sources before changing posture", 400);
      }
      const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
      try {
        await removeOperationalSecrets(accountId, scriptName, typeof body.token === "string" ? body.token : "");
        log("info", "operational-removed: set the durable OPERATIONAL_RETIRED marker (B7), then deleted engine secrets OPERATIONAL_PRIVATE, OPERATIONAL_PUBLIC (break-glass-only posture)");
        try {
          // env is passed. removeOperationalSecrets set a marker and DELETED two worker secrets; a
          // delete rolls a version exactly as a put does, so this append is in the same reset window.
          await auditChecked(scheduler, caller, sourceIp, "operational-removed", "success", { kind: "key-ceremony" }, env);
        } catch (e) {
          log("warn", `operational-removed audit append failed: ${(e as Error).message.slice(0, 140)}`);
          // G100: the append is best-effort, but its LOSS is not silent: a key ceremony that leaves no
          // audit event makes the pack's configEvents read as though no ceremony ever happened.
          noteDroppedWrite("key-ceremony-audit");
          await flushDroppedWrites(scheduler);
        }
        return jsonResponse({ ok: true });
      } catch (e) {
        // G027: the posture switch deletes TWO secrets in sequence, so a failure on the second leaves the engine
        // HALF-APPLIED (no operational private, but the public still bound). key-removal-failed names the step.
        await recordKeyCeremonyFailure(scheduler, caller, sourceIp, "key-removal-failed", e, env);
        return jsonError((e as Error).message.slice(0, 300), 400);
      }
    }

    // ---- key-posture acknowledgement (the liability record) ----------------------------------------
    // POST /keys/posture-acknowledgement records that a customer confirmed a versioned acceptance
    // statement that RESTATES the specific residual of the posture they chose. The verbatim words are a
    // frozen repo constant (posture-ack-statements.ts); the tamper-evident audit chain carries only the
    // posture, the statement VERSION and the SHA-384 of the exact words, plus the capture channel
    // (onboarding vs a later Keys re-key) and the resolved principal type, so the record proves WHICH
    // words were shown, to WHOM, WHEN, without ever storing free-form text. The engine recomputes the
    // hash over its OWN canonical text (never a client-supplied hash) and refuses a posted text that does
    // not match the current statement (a drifted console), so the "what the customer read is what the
    // engine recorded" binding cannot be forged from the client side. Owner-gated (keys.ceremony),
    // rate-limited. It is advisory evidence, not an access gate: it never blocks a ceremony (a bootstrap
    // operator must still be able to operate); its adversary is a disputing customer, not a malicious
    // engine (a malicious engine owns its own DO state and could forge any record).
    case "POST /keys/posture-acknowledgement": {
      const body = (await req.json().catch(() => ({}))) as {
        posture?: unknown;
        statementVersion?: unknown;
        acknowledgedText?: unknown;
        channel?: unknown;
      };
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        // Record the refused acknowledgement attempt with the posture it was for (or a placeholder hash),
        // so even a denied attempt is attributable. The statement hash is not recomputed on a denial (no
        // canonical lookup for a possibly-bad posture); a fixed marker keeps the closed target well-formed.
        const posture: PostureChoice = body.posture === "break-glass-only" ? "break-glass-only" : "operational";
        await auditChecked(scheduler, caller, sourceIp, "posture-acknowledged", "denied", {
          kind: "posture-ack",
          posture,
          statementVersion: typeof body.statementVersion === "string" ? body.statementVersion.slice(0, 64) : "unknown",
          statementSha384: "sha384:denied",
          channel: body.channel === "keys-rekey" ? "keys-rekey" : "onboarding",
          principalType: postureAckPrincipalType(caller),
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const posture = body.posture;
      if (posture !== "operational" && posture !== "break-glass-only") {
        return jsonError("posture must be 'operational' or 'break-glass-only'", 400);
      }
      // ABSENT means "onboarding". A PRESENT channel outside the enum is REFUSED rather than filed as
      // onboarding: this record is the compliance
      // acknowledgement of a key-posture statement, and filing it against a ceremony that did not happen is
      // a false entry in exactly the register somebody will later read as evidence. `posture` two lines above
      // already refuses out-of-enum; this is the same rule on the field beside it.
      if (body.channel !== undefined && body.channel !== null && body.channel !== "keys-rekey" && body.channel !== "onboarding") {
        return jsonError("channel must be 'onboarding' or 'keys-rekey'", 400);
      }
      const channel: PostureAckChannel = body.channel === "keys-rekey" ? "keys-rekey" : "onboarding";
      const statementVersion = typeof body.statementVersion === "string" ? body.statementVersion : "";
      const statement = resolvePostureAckStatement(posture, statementVersion);
      if (statement === null) {
        return jsonError("unknown or stale acceptance statement version; reload the page and try again", 400);
      }
      // Drift guard: when the console posts the exact words it displayed, they MUST equal the engine's
      // canonical text for this version, else the "what was shown is what was recorded" binding is broken
      // (the console rendered different words than the engine will hash). Reject the mismatch rather than
      // silently record the engine's words against a screen that showed something else.
      if (typeof body.acknowledgedText === "string" && body.acknowledgedText !== statement.text) {
        return jsonError("the acknowledged text does not match the current statement; reload the page and try again", 400);
      }
      const statementSha384 = await postureAckStatementHash(statement.text);
      await auditChecked(scheduler, caller, sourceIp, "posture-acknowledged", "success", {
        kind: "posture-ack",
        posture,
        statementVersion: statement.version,
        statementSha384,
        channel,
        principalType: postureAckPrincipalType(caller),
      });
      log("info", `posture-acknowledged: ${posture} (${statement.version}) via ${channel} (statement text never logged)`);
      return jsonResponse({ ok: true, statementVersion: statement.version, statementSha384 });
    }

    // ---- setup acknowledge (clears the demo first-run marker; harmless off-demo) -------------------
    // POST /setup/acknowledge lets the console mark the guided first run done when the operator finished
    // the wizard with keys ALREADY present (a demo reset leaves the signer/break-glass worker secrets in
    // place but wipes the DO, setting a marker that forces keysReady:false; "continue with existing keys"
    // skips /keys/install, which is the only other place that clears it, so without this the wizard could
    // never read done on the demo). The clear is SERVER-ENFORCED: it only fires when the engine actually
    // observes the signer + break-glass present, so a premature call cannot fabricate a "done" state.
    // Off-demo the marker is never set, so this is a no-op. Owner-gated; changes no secret, so no audit.
    case "POST /setup/acknowledge": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const status = buildStatus(env, 0);
      if (!(status.signerConfigured && status.breakGlassConfigured)) {
        // No keys present: nothing to acknowledge. Honest, not an error.
        return jsonResponse({ ok: false, reason: "keys-not-present" });
      }
      // CHECKED for the same reason the install path's clear is, and found by the guard written for that one:
      // this is the SECOND place the marker is cleared, and it had the identical bare `catch {}`. The caller is
      // told ok:true either way, so a lost clear here is silent to the operator AND leaves the estate reporting
      // keyless while holding keys, which is the state that blinds installRekeyDecision's already-provisioned
      // guard. Still fail-open: the acknowledgement itself succeeded, and a lost marker clear must not turn
      // that into an error.
      try {
        const cleared = await scheduler.fetch(doURL("/demo/first-run/clear"), { method: "POST" });
        if (!cleared.ok) {
          log("warn", `setup-acknowledge marker clear answered ${cleared.status}: the estate may report keyless while holding keys`);
          noteDroppedWrite("demo-first-run-clear");
          await flushDroppedWrites(scheduler);
        }
      } catch (e) {
        log("warn", `setup-acknowledge marker clear failed: ${(e as Error).message.slice(0, 140)}`);
        noteDroppedWrite("demo-first-run-clear");
        await flushDroppedWrites(scheduler).catch(() => {});
      }
      return jsonResponse({ ok: true });
    }
    default:
      return null;
  }
}
