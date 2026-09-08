// router-updates.ts -- the licence-activation + safe-apply engine-update routes plus the small read
// forwarders that sit beside them: GET /downpipes|updates|history|runs/at|rto|replication|licence and the
// two-phase update apply/settle/status/rollback/ramp/ramp-settle lifecycle (asvs-HI-13: the gradual ramp is
// ALSO two-phase now -- POST /update/ramp never flies the canary, POST /update/ramp/settle, a genuinely
// separate request, does). asvs-HI-14: POST /update/apply and POST /update/ramp both refuse (409,
// pendingUpdateRefusal) while a PRIOR apply/ramp's verification is still open, so the documented "finish the
// ramp via apply" step can never reach the deploy machinery mid-split. The per-route capability gate runs
// inline per route.

import type { CanaryLiveness } from "../canary/types.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { log } from "../log.ts";
import { makeCfDeployDriver } from "./cf-deploy.ts";
import { recordUpdateFault } from "./diag-admin.ts";
import { recordAdminRouteError } from "./diag-counters.ts";
import { type AdminRouteStage, channelFaultStep, classifyUpdateFailStep } from "./diag-records.ts";

import { recordDiagWrite } from "./diag-writer.ts";
import { computeEstateRollup } from "./estate.ts";
import { effectiveSignerPin, readLicence, verifyLicenceToken } from "./licence.ts";
import { callerHeaders, gate, jsonError, jsonResponse, ownerActionGate, ownerActionQueuedResponse, rateLimited, recordAudit, recordAuditAfterSelfDeploy, recordBookkeepingAfterSelfDeploy, recordVerifiedEngineAccountAfterSelfDeploy, updateNeedsDualControl, validateDeployToken } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { enumerateBoundSources, fetchArtefactBytesDetailed, resolveEngineAccount } from "./router-sources.ts";
import { executeConsoleApply, handleComponentApply, type QueuedConsole, recordConsoleQueueResolution, resolveConsoleComponent } from "./router-updates-components.ts";
import { handleRampSettle, handleRampStart } from "./router-updates-ramp.ts";
import { handleStandaloneRollback } from "./router-updates-rollback.ts";
import { freshnessRefusal, noteUpdateAttempt, noteUpdateDegradations, noteUpdateGuardRefusal, pendingUpdateRefusal, readUpdateFloor } from "./router-updates-shared.ts";
import { decideKeep, type HealthGate, liveSingleVersion, planAndPromote, type SafeApplyInput, settleAfterPromote } from "./update-apply.ts";
import { DESTINATION_GATE_REASON, destinationConfigured, makeHealthGate, probeSettleVerdict } from "./update-gate.ts";
import { parseComponentsRequest } from "./update-orchestrate.ts";
import { normaliseReadbackMode } from "./update-types.ts";
import { checkUpdates, loadVerifiedChannel, normaliseRiskClass, RISK_CLASSES } from "./updates.ts";

// SETTLE_TTL_MS bounds the pending-update verification window: a promote whose verification has not
// settled within an hour is treated as expired (and cleared when the live version is healthy, or
// rolled back when it is not). Named at module scope so the window is visible to tests and adjustable
// in one place rather than buried in the handler body.
const SETTLE_TTL_MS = 60 * 60 * 1000;

// resolveTrustedRampTarget (asvs-HI-14-r2) supplies verifyAndGuard's record-rollback-target step with the
// ONE split shape it may safely trust instead of refusing forever: a still-live, already-settled ramp
// awaiting its documented promote-to-100% (a plain POST /update/apply). Called ONLY after
// pendingUpdateRefusal has already passed (pending is null, so this is not the mid-verification race the
// PRIMARY guard closes) -- reads the SAME /update-status shape and returns the last transition's recorded
// fromVersion/toVersion ONLY when it settled "applied" (never invented, never a live-shape guess). Any other
// last outcome (or none) returns nothing, so verifyAndGuard's existing unrecognised-split refusal is
// unchanged. Without this, a ramp that settled "applied" (still serving its configured percentage, per
// settleAfterRamp's own wording: "promote it to 100% when you are comfortable") could never actually reach
// 100% again through the app: the split it left live is real and does not collapse itself, and nothing else
// in this codebase ever collapses it besides this same apply path.
async function resolveTrustedRampTarget(scheduler: DurableObjectStub): Promise<{ knownRollbackTarget?: string; knownToVersion?: string }> {
  const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
  const rec = (await recResp.json()) as { last: null | { outcome?: unknown; fromVersion?: unknown; toVersion?: unknown } };
  const last = rec.last;
  if (last && last.outcome === "applied" && typeof last.fromVersion === "string" && last.fromVersion !== "" && typeof last.toVersion === "string" && last.toVersion !== "") {
    return { knownRollbackTarget: last.fromVersion, knownToVersion: last.toVersion };
  }
  return {};
}

// handleUpdates dispatches the licence + engine-update group. Returns the route's Response, or null when
// no case here matched (the hub falls to the next spoke). The hub already ran authorise(); the per-route
// capability gates stay inline below, unmoved relative to the handler they guard. The shared route guards
// (readUpdateFloor, freshnessRefusal, pendingUpdateRefusal, recordUpdateRefusal) live in
// router-updates-shared.ts, and the opt-in gradual-ramp halves live in router-updates-ramp.ts, both split
// out for the module size budget (the router-updates-components.ts precedent).
export async function handleUpdates(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, url, scheduler, caller, sub, sourceIp } = ctx;
  switch (`${req.method} ${sub}`) {
    // GATE-GAP, first of three in this spoke. GET /downpipes returns listDownpipes VERBATIM
    // (scheduler-do.ts hands back the stored dp:<id> records with no projection and no redaction), so the
    // response carries every downpipe's whole SourceSpec -- binding, namespaceId, bucketName, databaseId,
    // zoneId, accountId, the include/exclude patterns, the configured destinationIds and the retention
    // policy. That is the downpipe CONFIGURATION, which is precisely what downpipe.read names, and this
    // route named no capability at all while /runs/at and /rto beside it each named one.
    //
    // SAY WHAT THIS DOES AND DOES NOT FIX, because the honest version is the smaller one. It changes NO
    // caller's answer today, and that is provable rather than hoped for: every one of the six built-in
    // roles holds downpipe.read (identity-rbac.ts ROLE_CAPABILITIES), the resting role for any
    // authenticated caller with no grant is viewer (scheduler-do-rbac.ts resolveBuiltin), and custom-role
    // resolution is strictly ADDITIVE -- it seeds the set from ROLE_CAPABILITIES[builtin.role] and unions
    // the custom bundle on top, so a custom role cannot SUBTRACT downpipe.read either. There is therefore
    // no reachable principal in this engine that this gate refuses, and the documented "any authenticated
    // role" floor for this route stays true after it. What was wrong was not the effective access, it was
    // that the effective access rested on a property of the role table rather than on anything this route
    // said. The day a capability floor below viewer exists, or the day viewer stops holding downpipe.read,
    // every sibling read moves with the table and these three would silently have stayed open.
    case "GET /downpipes": {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/downpipes"), { method: "GET" });
    }
    case "GET /updates":
      return new Response(JSON.stringify(await checkUpdates(env)), { headers: { "content-type": "application/json" } });
    case "GET /history": {
      // Thin authenticated forwarder: pass ?id=... straight through to the DO, which is the
      // history authority (it reads searchParams.get("id")). The doURL host is ignored by
      // the DO, so forwarding url.search is correct.
      //
      // GATE-GAP, second of three, and the one with a written floor it did not hold.
      // router-keys.ts gates GET /keys/vintages on downpipe.read and says it is "the same cap as GET
      // /history and GET /runs/at, the sibling run-history reads". Of the two siblings that sentence
      // names, /runs/at did gate on downpipe.read and /history gated on nothing, so the sentence was true
      // of the intent and false of the code. This route also strictly dominates /runs/at, which resolves
      // ONE runId out of the retained ring behind downpipe.read while this returns EVERY ring in the fleet.
      // As above, no caller's answer changes today; the check is here so the claim is checkable.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL(`/history${url.search}`), { method: "GET" });
    }
    case "GET /runs/at": {
      // POINT-IN-TIME run resolution (E4/C1): GET /admin/runs/at?downpipe=&at=<rfc3339> -> the resolved
      // runId + completedAt of the latest SUCCESSFUL run completed at-or-before T from the retained ring,
      // or an honest miss (found:false) with the retained-window bounds when T precedes all retained runs.
      // The console uses it to turn a recovery-timeline pick into a runId that then flows through the
      // existing POST /admin/restore path. Gated on downpipe.read (reading the run timeline, viewer+); a
      // thin authenticated forwarder, the DO is the history authority. A missing downpipe / unparseable at
      // comes back as a 400 from the DO's honest error shape.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      // G183: this route is the recovery TIMELINE's resolver -- an operator picking the moment to restore
      // from. It was a bare forward with NO catch, so a DO fault escaped to the Worker's last-resort handler
      // and the console showed a generic failure with nothing anywhere naming the point-in-time lookup as the
      // thing that broke. It is read-only, so its stage can only ever be do-read (nothing is changed here,
      // and unlike its siblings that claim is unconditionally true).
      let resp: Response;
      let body: { error?: string };
      try {
        resp = await scheduler.fetch(doURL(`/runs/at${url.search}`), { method: "GET" });
        body = (await resp.json()) as { error?: string };
      } catch {
        await recordAdminRouteError(scheduler, { route: "runs-at", stage: "do-read" });
        return jsonError("could not resolve a run at that moment right now; the scheduler could not be read. Nothing was changed; retry.", 502);
      }
      // The DO returns the resolution with an `error` hint on a malformed request; map that to a 400 so
      // the console distinguishes "you asked wrong" (fix the query) from an honest "no run at or before T"
      // (found:false, a valid answer). A well-formed query is always 200, found true or false.
      const status = typeof body.error === "string" ? 400 : 200;
      return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    }
    case "GET /rto": {
      // RTO ESTIMATE (E4/C1): GET /admin/rto[?id=<downpipeId>] -> the per-downpipe + fleet recovery-time
      // estimate, the recovery-time companion to the RPO/freshness signal. Each estimate is an HONEST
      // projection derived from observed restore-test throughput (never a fabricated number; "unknown" with
      // no drill history), carrying a "based on N drills" sample count and a confidence. Gated on
      // reports.read (the same read tier as the SLA/posture surfaces it sits beside, viewer+); a thin
      // authenticated forwarder, the DO derives it from its own recovery samples + run history.
      const denied = gate(caller, "reports.read");
      if (denied) return denied;
      return scheduler.fetch(doURL(`/rto${url.search}`), { method: "GET" });
    }
    case "GET /replication": {
      // Per-destination replication state (?id=<downpipeId>, or all when absent): the honest source
      // for "N of M copies" and the per-destination "down" indicator. Same thin authenticated forwarder
      // as /history (read-only, redaction-safe: opaque destination ids + run ids, no credential).
      //
      // GATE-GAP, third of three. Redaction-safe is a claim about the BODY, not about the
      // caller, and only the first was ever argued here. This is per-downpipe state keyed on the downpipe
      // id, so it takes the same downpipe.read floor as the sibling forwarder it names above; the wording
      // "same thin authenticated forwarder as /history" is now true of the gate as well as of the shape.
      // No caller's answer changes today, for the reason set out on GET /downpipes.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL(`/replication${url.search}`), { method: "GET" });
    }
    case "GET /licence": {
      // Fail-open: readLicence never throws and never returns a non-2xx; a bad/absent/expired
      // licence yields HTTP 200 with tier 'community'. The licence gates only assurance
      // features, never the data or recovery path. The scheduler stub lets it resolve the
      // console-activated (DO-stored) token over the deploy-time env token, with who/when.
      const status = await readLicence(env, scheduler);
      // estate (volume-based self-serve licensing): the usage rollup alongside the entitlement, so the
      // console can show what is actually protected next to what the licence grants. computeEstateRollup
      // is independently fail-safe (a DO or aggregation fault resolves to null, never a throw); the .catch
      // here is belt-and-braces so an estate problem can never turn a healthy licence read into a failure.
      const estate = await computeEstateRollup(scheduler).catch(() => null);
      return new Response(JSON.stringify({ ...status, estate }), { headers: { "content-type": "application/json" } });
    }
    // POST /licence ACTIVATES (token) or CLEARS (token:null) the assurance licence FROM THE CONSOLE, no
    // CLI, honouring the no-customer-CLI rule. The submitted token is VERIFIED LIVE against the pinned
    // vendor signer here (verify-before-store, the destination/discovery discipline): only a token that
    // yields a VALID licence is handed to the DO to store. A token that does not verify (typo, wrong
    // signer, expired, or the vendor key is unpinned) is refused with the honest reason and never stored.
    // The licence is fail-open and gates nothing, so this never touches the data or recovery path.
    // Owner-exclusive (keys.ceremony): pinning the assurance entitlement is the same governance class as
    // the destination and the discovery token. Returns the now-effective LicenceStatus on success.
    case "POST /licence": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Fail-open even on this WRITE path: a malformed body or a DO outage is a clean 400 (nothing
      // changed), never a 500. The licence gates nothing regardless, so an activation hiccup can never
      // touch the data or recovery path. The verify-before-store refusals below are normal returns
      // (their honest reason still surfaces); only an actual throw lands in the catch.
      // G183: `stage` is the LAST CHECKPOINT PASSED, advanced as the route makes progress. The outer catch
      // below records it, which turns "could not activate the licence right now; nothing was changed" from an
      // unfalsifiable sentence into a checkable claim: a fault at `persist` means the DO write was in flight,
      // and the licence may well be stored.
      let stage: AdminRouteStage = "do-read";
      try {
        const body = (await req.json()) as { token?: unknown; allowSupersede?: unknown };
        if (body.token === null) {
          // Clear: remove the console token; the engine falls back to the env token, else community.
          const clearResp = await scheduler.fetch(doURL("/licence-token"), { method: "POST", body: JSON.stringify({ token: null }), headers: callerHeaders(caller) });
          if (!clearResp.ok) return clearResp; // the DO's plain { error } + status (e.g. owner re-resolution)
          const cleared = await readLicence(env, scheduler);
          // Credential lifecycle registry: refresh/drop the observed `licence` expiry row from the now-
          // effective notAfter (best-effort, fail-open, never affects the licence response).
          await recordDiagWrite(scheduler, "licence-refusal", () => scheduler.fetch(doURL("/expiry/observe-licence"), { method: "POST", body: JSON.stringify({ notAfter: cleared.notAfter ?? null }) })); // G331: a dropped expiry observe means the licence-expiry warning never fires and nothing says why
          return jsonResponse(cleared);
        }
        const token = typeof body.token === "string" ? body.token.trim() : "";
        // Length bound BEFORE the regex (and before any verify/DO work): cheap, and never runs the
        // pattern over an oversized paste.
        if (token === "" || token.length > 20000 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
          // Record the refused activation (failed-activation-no-trace) so a customer insisting "I pasted my
          // licence" is diagnosable. A pre-verify SHAPE reject has no verify reasonCode -> the closed
          // "malformed-token" code. Best-effort + fail-open (the licence gates nothing; a persist hiccup must
          // never affect activation), so the DO POST is swallowed and never changes the refusal response.
          await recordDiagWrite(scheduler, "licence-refusal", () => scheduler.fetch(doURL("/licence-activation-refusal"), { method: "POST", body: JSON.stringify({ reasonCode: "malformed-token" }), headers: { "content-type": "application/json" } })); // G331: a dropped refusal record leaves "it just says community" with no recorded reason
          return jsonError("that does not look like a licence token. Paste the licence token value from your activation email (the long dot-joined string).", 400);
        }
        // Verify-before-store against the PINNED vendor key (env override else the compile-time baked
        // vendor pin; effectiveSignerPin). Only a VALID licence is stored. Using the baked pin here means
        // a stock engine can verify+activate a console-pasted token without the customer setting an env
        // pin; when neither is configured this still returns the unchanged "pinned vendor key not
        // configured" refusal below.
        stage = "gate";
        // env.CF_ACCOUNT_ID was NOT passed here and is passed at every OTHER call site (licence.ts:279 for the
        // deploy token, licence.ts:327 for the stored console token). Without it checkExpiry leaves
        // accountClaimMatchesEngine unset, so the ONE verify that runs before anything is stored was the one
        // verify that never computed the account verdict. It changes no allow/deny (the field does not feed
        // `valid`) and the status this route RETURNS is a fresh readLicence that does pass the tag, which is
        // exactly why nobody noticed: the answer was right and the check behind it was not the same check.
        const verified = await verifyLicenceToken(token, effectiveSignerPin(env), "console", env.CF_ACCOUNT_ID);
        if (!verified.valid) {
          const why = verified.reason ?? "the licence did not verify";
          const hint =
            verified.reason === "pinned vendor key not configured"
              ? " (the vendor has not pinned its signing key on this engine yet, contact the vendor; this is not something you can fix here)"
              : verified.reason === "licence expired"
                ? " (request a renewed token; fail-open means nothing is interrupted in the meantime)"
                : "";
          // Record the refused activation (failed-activation-no-trace) with the CLOSED verify reasonCode, so
          // the support pack can tell WHY every activation attempt bounced (expired vs wrong-signer vs future-
          // tier vs tamper) rather than the customer's "it just says community". Best-effort + fail-open.
          await recordDiagWrite(scheduler, "licence-refusal", () => scheduler.fetch(doURL("/licence-activation-refusal"), { method: "POST", body: JSON.stringify({ reasonCode: verified.reasonCode ?? "body-malformed" }), headers: { "content-type": "application/json" } })); // G331: as above -- the refusal reason is the whole diagnostic value
          // THE ENGINE ALREADY KNEW THE REASON AND THEN DROPPED IT FROM THE ANSWER. The closed reasonCode was
          // written to the engine's own counter on the line above and the caller got prose only, so the one
          // party who can act on "expired" versus "wrong signer" versus "tamper" -- the person holding the
          // token -- was the only party not told which it was, and the console could only re-print a sentence
          // it must never parse. It rides in the body now, as a frozen closed member, which is the
          // jsonRefusal pattern (router-core.ts) applied to this route's own vocabulary rather than to
          // RecoveryRefusalClass. Additive: `error` is unchanged and stays exactly as honest as it was.
          return new Response(JSON.stringify({ error: `this licence could not be activated: ${why}${hint}.`, reasonCode: verified.reasonCode ?? "body-malformed" }), { status: 400, headers: { "content-type": "application/json" } });
        }
        // THE SUPERSEDED-TOKEN OVERWRITE. setLicenceToken puts the record unconditionally, so a token that
        // verifies is stored whatever it replaces, and the route then reports success. Re-pasting the SAME
        // token is fine and must stay fine (it is idempotent, and refusing it would build a dead end), but an
        // OLDER TERM'S token is a different act: it verifies, because it is genuinely signed and has not yet
        // expired, and it silently shortens the customer's term to the earlier end date. On renewal that is
        // the likeliest paste of all, the two tokens overlap by design, and the console cannot refuse it at
        // any price -- it never sees the pasted token's claims, so it has no basis on which to compare terms.
        // The engine has both: the verified claims of what was pasted, and the currently effective status.
        //
        // NOT A DEAD END, WHICH IS WHY IT IS AN OPT-IN AND NOT A BAN. There are real reasons to move to an
        // earlier-ending licence (a downgrade, a corrected issue, a term reissued shorter), so this is shaped
        // exactly like `allowDowngrade` on POST /update/apply below: default false, so it can never happen by
        // accident, and one explicit flag away when it is meant. The refusal names both dates, because "your
        // licence would end sooner" is only actionable if you can see by how much.
        const currentBeforeStore = await readLicence(env, scheduler);
        const currentEnds = typeof currentBeforeStore.notAfter === "string" ? Date.parse(currentBeforeStore.notAfter) : Number.NaN;
        const incomingEnds = typeof verified.notAfter === "string" ? Date.parse(verified.notAfter) : Number.NaN;
        // Every arm here fails OPEN to the store, deliberately: an unparseable or absent date on either side
        // is not evidence of a regression, and the licence gates nothing, so a comparison this route cannot
        // make must never block an activation. Only a term this route can prove is strictly shorter refuses.
        if (
          body.allowSupersede !== true
          && currentBeforeStore.valid
          && Number.isFinite(currentEnds)
          && Number.isFinite(incomingEnds)
          && incomingEnds < currentEnds
        ) {
          await recordDiagWrite(scheduler, "licence-refusal", () => scheduler.fetch(doURL("/licence-activation-refusal"), { method: "POST", body: JSON.stringify({ reasonCode: "supersedes-current-term" }), headers: { "content-type": "application/json" } }));
          return new Response(
            JSON.stringify({
              error: `this licence ends ${verified.notAfter}, earlier than the licence already active on this engine, which ends ${currentBeforeStore.notAfter}. Activating it would shorten your term, so nothing has been changed. Check you pasted the newest token from your renewal; if you did mean to move to this one, activate it again with allowSupersede.`,
              reasonCode: "supersedes-current-term",
              currentNotAfter: currentBeforeStore.notAfter,
              incomingNotAfter: verified.notAfter,
            }),
            { status: 400, headers: { "content-type": "application/json" } },
          );
        }
        // Store via the DO (re-resolves owner, audits who pinned it; never the token bytes). Then return
        // the now-active status (read back through the same DO-resolution a later GET /licence would use).
        stage = "persist";
        const storeResp = await scheduler.fetch(doURL("/licence-token"), { method: "POST", body: JSON.stringify({ token }), headers: callerHeaders(caller) });
        if (!storeResp.ok) return storeResp; // the DO's plain { error } + status, passed through unchanged
        const active = await readLicence(env, scheduler);
        // Credential lifecycle registry: observe the licence token's own notAfter (best-effort, fail-open).
        await recordDiagWrite(scheduler, "licence-refusal", () => scheduler.fetch(doURL("/expiry/observe-licence"), { method: "POST", body: JSON.stringify({ notAfter: active.notAfter ?? null }) })); // G331: a dropped observe silently disarms the expiry cockpit for this licence
        return jsonResponse(active);
      } catch {
        // "Licence activation intermittently errors" -- and the exception died with the browser tab, so nothing
        // server-side said whether the DO, the verify or the store was at fault. Closed route + closed stage only.
        await recordAdminRouteError(scheduler, { route: "licence-activate", stage });
        return jsonError("could not activate the licence right now; nothing was changed. Check the token and try again.", 400);
      }
    }

    // ---- safe-apply engine update (two-phase, canary-gated, auto-rollback; no CLI) -----------------
    // Phase 1 (apply, runs on the CURRENT/old version): resolve + verify the signed artefact, record the
    // rollback target, and (unless dryRun, the DEFAULT) upload + promote the new version. Phase 2 (settle)
    // is called by the console over its service binding immediately after a "promoted" result, so it hits
    // the NOW-LIVE new version: it flies the canary on the new code and keeps it or auto-rolls-back. The
    // one-shot deploy token is supplied to BOTH calls and is NEVER stored. Owner-only + rate-limited; the
    // data and recovery paths are never touched, and the whole flow is fail-safe (never a 500). See
    // src/admin/update-apply.ts.
    case "POST /update/apply": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // G183: see the licence route above. On THIS route the stage matters most: the outer catch asserts
      // "nothing was changed", and the promote REDEPLOYS THE ENGINE -- which momentarily resets the very DO the
      // follow-up write needs, so a throw can land AFTER the new version is live. A recorded stage of
      // `deploy-driver` or `persist` is the pack saying that sentence is not safe to believe.
      let stage: AdminRouteStage = "do-read";
      try {
        const body = (await req.json()) as { token?: unknown; dryRun?: unknown; allowDowngrade?: unknown; components?: unknown };
        const dryRun = body.dryRun !== false; // DEFAULT TRUE: going live is an explicit opt-in
        // allowDowngrade is the EXPLICIT owner opt-in to apply a NON-newer version (downgrade-to-recover).
        // DEFAULT FALSE: planAndPromote refuses a channel that recommends an older/unparseable version unless
        // this is set, so a (correctly-signed) older channel can never drive a silent downgrade.
        const allowDowngrade = body.allowDowngrade === true;
        // Multi-component updates (ADDITIVE): an OPTIONAL `components` array names what to apply. ABSENT
        // means the legacy ENGINE-ONLY apply, byte-for-byte (deployed consoles keep their exact
        // semantics); present, it is validated to the closed component set before anything else runs.
        // The refusal is an honest 400 and carries NO counter: no client can trip it (the console's component
        // ids are exactly the two this build plans), so a pack-visible name for it would never be written.
        const compReq = parseComponentsRequest(body.components);
        if (!compReq.ok) return jsonError(compReq.error, 400);
        const components = compReq.components;
        const token = typeof body.token === "string" ? body.token.trim() : "";
        // asvs-HI-14 (PRIMARY guard): refuse before any other work when a prior apply/ramp is still awaiting
        // verification (see pendingUpdateRefusal) -- otherwise the documented "finish the ramp" apply can
        // reach planAndPromote mid-split and corrupt the recorded rollback target.
        const pendingBlock = await pendingUpdateRefusal(scheduler);
        if (pendingBlock) {
          // R7: noteUpdateGuardRefusal, not recordUpdateRefusal alone. The audit event is stripped of its
          // `detail` by the pack's configEvents excerpt, so the audit-only form reached support as an unclassed
          // "update-refused / denied" row. The closed counter is what makes the guard legible in the pack.
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "pending-open");
          return pendingBlock;
        }
        // asvs-HI-14-r2: pending is confirmed clear above, so any live split remaining now can only be a
        // previously-settled ramp (or an unrecognised one, still refused by verifyAndGuard). Resolve the
        // persisted known-good so a "finish the ramp via apply" call can actually complete it.
        const trustedRampTarget = await resolveTrustedRampTarget(scheduler);
        const accountId = await resolveEngineAccount(env, scheduler);
        if (accountId === null) {
          // UPD engine-account-unmarked-blocks-update: record the refusal so a diagnoser sees "the owner tried to
          // update but the engine account was never marked", instead of a bare 400 that leaves no trace.
          // R7: the audit event alone did NOT do that. update-refused is allowlisted for the configEvents excerpt,
          // but the excerpt strips the target's `detail`, so the class died there and the pack carried an unclassed
          // denial. The counter carries the class. Best-effort; the guard behaviour is unchanged.
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "account-unmarked");
          return jsonError("the engine's own Cloudflare account is not marked yet; choose it under Sources first (the update deploys into that account). Or use the wrangler deploy path.", 400);
        }
        const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
        stage = "channel-fetch";
        // G332: collect the channel-metadata DEGRADATIONS the resolver would otherwise drop log-only (a
        // malformed components map, a dropped component entry or provenance block, a fall back to the legacy
        // artefacts[] mirror). Each one silently changes WHAT gets deployed, or WHAT is checked, while the
        // apply reports success. Folded into the pack; never a URL, a version string or a message.
        const degraded = new Set<string>();
        const art = await loadVerifiedChannel(env, undefined, degraded);
        if (degraded.size > 0) void noteUpdateDegradations(scheduler, [...degraded]);
        // UPD artefact-download-or-url-missing: a resolve/URL fault previously 400'd BEFORE any audit, so the
        // failed update attempt left no trace in the pack. Record it (update-refused) before the 400.
        if ("error" in art) {
          // G054: the CHANNEL leg of the update-fault ring, which had no producer at all -- so a customer who
          // "cannot update" because the signed channel will not verify produced a pack in which the update
          // pipeline had never been touched. The three verify causes are three different remediations (a wrong
          // signer is a key-pinning problem, a truncated CDN object is not, a shape drift is OUR bug), and they
          // all arrived at the operator as one sentence and at the pack as nothing. Component `channel`,
          // because the fault is in neither the engine nor the console: it is upstream of both.
          await recordUpdateFault(scheduler, { component: "channel", step: channelFaultStep(art.causeClass), cause: art.causeClass });
          // R7: the audit detail used to interpolate the resolver's own sentence, which the pack's excerpt drops
          // anyway. The closed guard class rides the counter instead, and the audit detail is now that class.
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "artefact-resolve");
          return jsonError(`no applicable update: ${art.error}`, 400);
        }
        // The ENGINE's target is the engine COMPONENT's own version. For every v1 (components-less)
        // channel the two coincide (the artefact was selected BY the recommended version, so this is
        // byte-for-byte today's behaviour); for a v2 console-only release the release version moves while
        // the engine row repeats the current engine version, and the honest engine-only reading of that
        // document is "the engine is up to date" -- never a re-deploy of the same bytes under a new label.
        const engineTarget = art.artefact.version;
        if (components === null && engineTarget === ENGINE_VERSION) {
          return jsonResponse({ phase: "promote", outcome: "no-update", recommendedVersion: engineTarget, steps: [] });
        }
        // R8 + R9: read the persisted anti-rollback floor + freshness watermark, then REFUSE a replayed/stale
        // descriptor (R9) before any download or deploy. The high-water mark (R8) is threaded into the apply
        // input and enforced in verifyAndGuard (even with allowDowngrade).
        //
        // G183: the floor read is a SCHEDULER DO READ and it is BRACKETED back to do-read for exactly that
        // reason. readUpdateFloor has no catch of its own (deliberately: a DO read failure must become this
        // route's clean fail-closed "nothing was changed" 400), so a scheduler DO outage here THROWS into the
        // outer catch below. Left inside the channel-fetch window, it recorded update-apply|channel-fetch --
        // the same row a DNS/TLS fault on the signed channel records -- and the pack's own legend then sent
        // the support engineer to check the vendor's CDN and the customer's egress while the real fault was
        // the customer's own scheduler DO. It is not a narrow window either: every other call in the
        // channel-fetch span is throw-proof (loadVerifiedChannel returns {error}, fetchArtefactBytesDetailed
        // returns a union, destinationConfigured catches both arms), so the DO read was a large share of the
        // real rows landing under the channel's label. Two different owners: two different stages.
        stage = "do-read";
        const floor = await readUpdateFloor(scheduler, env);
        stage = "channel-fetch";
        const stale = freshnessRefusal(art, floor.freshness, () => void noteUpdateGuardRefusal(scheduler, caller, sourceIp, "freshness-replay"), (names) => void noteUpdateDegradations(scheduler, names));
        if (stale) return stale;
        // ---- the COMPONENT-AWARE apply (an explicit `components` list) dispatches to its own flow; the
        // legacy engine-only path below continues byte-for-byte when the field was absent. ----
        if (components !== null) {
          return handleComponentApply({ env, scheduler, caller, sourceIp, components, art, floor, dryRun, allowDowngrade, token, accountId, engineScriptName: scriptName });
        }
        // Always download + verify the artefact, even on a dry-run (a dry-run's value is "verify + plan").
        const dl = await fetchArtefactBytesDetailed(art.artefact.url ?? "");
        if (!dl.ok) {
          // G159: the audit detail stays the fixed coarse class (unchanged), and the CLOSED MODE + the numeric
          // status now ride the update-fault ring: a CDN 404 (the signed channel names an artefact that is not
          // there), a 5xx (wait), a refused redirect (a signed update being steered elsewhere), an empty body,
          // an over-cap bundle and a network fault stop being one indistinguishable "download failed".
          await recordUpdateFault(scheduler, { component: "engine", step: "artefact-download", cause: dl.cause, ...(dl.httpStatus > 0 ? { httpStatus: dl.httpStatus } : {}) });
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "artefact-download");
          return jsonError("could not download the update artefact from the signed channel (it must be an https url that returns the bundle)", 400);
        }
        const bytes = dl.bytes;
        // DESTINATION GATE (design UPDATE-UX-015 §4): a LIVE apply (never dry-run/preview) with NO
        // destination configured refuses BEFORE any deploy. Updates verify themselves with a canary flight,
        // and a canary with nowhere to fly can never confirm anything (the confirmation-pending-forever
        // hole); checked before dual control/the token so an operator missing a destination is told that,
        // not asked to paste a token for an apply that could never verify itself. Nothing is uploaded.
        if (!dryRun && !(await destinationConfigured(env, scheduler))) {
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "no-destination");
          return jsonError(DESTINATION_GATE_REASON, 400);
        }
        // OPT-IN DUAL CONTROL (router-executed), W5: going LIVE (shipping arbitrary engine code) takes a
        // second owner's approval ONLY when the signed manifest flags the release "migration"/"breaking"
        // (the consequential releases) AND dual control is ON. A "routine" release applies without a second
        // approver even when dual control is ON (the common patch case; O-3). A DRY-RUN changes nothing, so
        // it is NEVER gated. The gate is bound to the TARGET VERSION + the artefact SHA (decision-relevant
        // facts), NEVER the deploy token. First live call (gate ON, no armed approval) records a pending
        // approval + 202 WITHOUT requiring the token; a second owner approves; the owner RE-SUBMITS with the
        // token and the gate consumes the armed approval here. The token requirement runs only AFTER the gate
        // says proceed. riskClass is normalised (absent/unknown -> migration -> gated; never silently routine).
        stage = "gate";
        const riskClass = normaliseRiskClass(art.artefact.riskClass, art.artefact.requiresMigration === true);
        // G332: the channel declared a risk class this build does not know (or none at all) and it was coerced.
        // The coercion is SAFE (unknown -> migration -> dual control), and it is also the state in which the
        // update the operator believes is "routine" is being gated, or a genuinely breaking release is being
        // described by a token nobody recognises. Neither was visible anywhere.
        if (typeof art.artefact.riskClass === "string" && !(RISK_CLASSES as readonly string[]).includes(art.artefact.riskClass)) {
          void noteUpdateDegradations(scheduler, ["update-degraded-riskclass-coerced"]);
        }
        if (!dryRun && updateNeedsDualControl(riskClass)) {
          const g = await ownerActionGate(
            scheduler,
            caller,
            "update-apply",
            { toVersion: engineTarget, sha384: art.artefact.sha384 ?? "" },
            `Promote the engine to ${engineTarget} (ships new engine code; risk: ${riskClass})`,
          );
          if (g.kind === "error") return g.response;
          if (g.kind === "queued") return ownerActionQueuedResponse(g.id);
          // proceed: a deploy is authorised (gate off/routine, or an armed approval was just consumed). Now
          // require the one-shot token (it was not needed on the first recording call).
        }
        if (!dryRun && !validateDeployToken(token)) {
          // R7: THE "UPDATE NOW" BUTTON'S OWN GUARD, and it recorded nothing at all -- not a counter, not even the
          // audit event its settle/rollback/ramp-settle siblings emit. So the single most-pressed refusal in the
          // whole family ("we clicked Update now three times last night and it just errored") reached the pack as
          // SILENCE, while the identical refusal on settle carried a named, counted, timestamped row.
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
          return jsonError('paste the one-shot Cloudflare deploy token (the "Edit Cloudflare Workers" template); it is used once and never stored', 400);
        }
        const driver = makeCfDeployDriver({ token, accountId, scriptName });
        const hgate = makeHealthGate(env, scheduler, engineTarget);
        const input: SafeApplyInput = {
          artefact: bytes,
          expectedSha384: art.artefact.sha384 ?? "",
          meta: { version: engineTarget, ...(art.artefact.requiresMigration ? { requiresMigration: true } : {}), ...(art.artefact.mainModule ? { mainModule: art.artefact.mainModule } : {}), ...(art.artefact.minEngineVersion ? { minEngineVersion: art.artefact.minEngineVersion } : {}) },
          runningVersion: ENGINE_VERSION,
          recommendedVersion: engineTarget,
          dryRun,
          ...(allowDowngrade ? { allowDowngrade: true } : {}),
          ...(floor.settledHighWaterMark ? { settledHighWaterMark: floor.settledHighWaterMark } : {}),
          ...trustedRampTarget,
          readbackMode: normaliseReadbackMode(env.UPDATE_READBACK_MODE),
        };
        // Snapshot the engine's LIVE source binding names BEFORE the new version goes live, so settle can
        // prove post-update that the update preserved them (and prompt a re-attach if it dropped any). NAMES
        // only; taken here on the still-current version so it reflects what was attached pre-update.
        const preBound = enumerateBoundSources(env);
        const sourceBindingsBefore = [...preBound.kv, ...preBound.r2, ...preBound.d1, ...preBound.secrets].sort();
        stage = "deploy-driver";
        const p = await planAndPromote(driver, hgate, input);
        if (p.outcome === "promoted" && p.fromVersion && p.toVersion) {
          // asvs-HI-19: the promote above JUST redeployed the engine (a live version cutover), the same
          // self-redeploy that momentarily resets THIS Durable Object (see router-audit.ts). Both follow-up
          // writes use the self-redeploy-safe helpers so a transient reset never silently drops the pending
          // record or the audit trail for the highest-consequence action class in the product, and never
          // throws into the outer catch's "nothing was changed" -- which would be false, it already did.
          // DP-0: the signed channel digest verifyAndGuard just enforced rides the pending record AND the
          // audit detail (the hash-chained audit alone then answers "which content hash was promoted",
          // even if the lifecycle record is later superseded).
          stage = "persist"; // the promote LANDED: the engine is live on the new version from here on
          const pendingWritten = await recordBookkeepingAfterSelfDeploy(env, "/update-pending", { fromVersion: p.fromVersion, toVersion: p.toVersion, recommendedVersion: p.recommendedVersion, ...(p.canaryBaseline ? { canaryBaseline: p.canaryBaseline } : {}), riskClass, promotedAt: Date.now(), promotedBy: caller.email ?? null, sourceBindingsBefore, ...(art.sequence !== undefined ? { channelSeq: art.sequence } : {}), ...(art.issuedAt !== undefined ? { channelIssuedAt: art.issuedAt } : {}), ...(art.artefact.sha384 ? { artefactSha384: art.artefact.sha384 } : {}), ...(p.readback !== undefined ? { readback: p.readback } : {}) });
          const audited = await recordAuditAfterSelfDeploy(env, caller, sourceIp, "update-promoted", { kind: "engine-state", field: "engineVersion", detail: `${p.fromVersion} -> ${p.toVersion} (${p.recommendedVersion}); pending canary verification${art.artefact.sha384 ? `; sha384 ${art.artefact.sha384}` : ""}` });
          // LICENCE-BINDING-ON-CLAIM follow-up: the promote above just proved this accountId
          // owns this engine's script (planAndPromote's driver reads /accounts/{accountId}/workers/scripts/
          // {scriptName} before writing), the same certainty CF_ACCOUNT_ID gives when hand-set. Persist it so
          // GET /admin/status can report cfAccountId without ever calling the Cloudflare API. Best-effort,
          // never checked: a dropped write here only delays when status starts reporting it, never fails an
          // update that already went live.
          await recordVerifiedEngineAccountAfterSelfDeploy(env, accountId, "update-apply");
          if (!pendingWritten || !audited) {
            // G101: the engine is LIVE ON THE NEW VERSION and the record of it did not persist. /update/status
            // then knows nothing, both settle routes refuse with "no update awaiting verification", and the ONLY
            // statement of the partial write was this HTTP response -- which the operator closed. A durable
            // marker in the update-fault ring means a pack taken LATER still proves the live-but-unrecorded
            // state, and says which half (the lifecycle record or the audit row) was lost.
            if (!pendingWritten) await recordUpdateFault(scheduler, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "pending" });
            if (!audited) await recordUpdateFault(scheduler, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "audit" });
            return jsonResponse({ ...p, reason: "the update went live but could not be fully recorded; check GET /admin/update/status and GET /admin/audit before trying again." });
          }
        } else if (p.outcome === "refused") {
          // G050: the refusal reason is a 200-char sentence already coarsened by msg(), so the pack could not
          // say WHICH STEP died -- and every step has a different remediation (a token scope on read-settings,
          // a CF incident on version-post, a binding type the pipeline will not risk dropping on binding-guard,
          // a shape drift on readback). classifyUpdateFailStep reads the ENGINE'S OWN literals only to SELECT
          // the closed pair and returns it; the sentence itself never reaches the record.
          const cls = classifyUpdateFailStep(p.reason ?? "");
          await recordUpdateFault(scheduler, { component: "engine", step: cls.step, cause: cls.cause });
          await recordAudit(scheduler, caller, sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: (p.reason ?? "refused").slice(0, 120) });
          // G332: the R8 ANTI-ROLLBACK FLOOR is the one update guard that refuses a SIGNED, VERIFIED channel, and
          // it is the guard that matters most: it is what stops a stale-but-validly-signed channel driving this
          // engine back below a version the customer has already run, re-introducing an already-patched issue.
          // It had a guard class and no producer, so a channel repeatedly trying to push the engine backwards
          // looked, in the pack, exactly like a channel nobody had asked for an update from.
          //
          // Read STRUCTURALLY, off the engine's own step log, not off the refusal sentence: the guard writes a
          // failing `anti-rollback-guard` step at the moment it establishes the fact, and a sentence is a thing
          // someone wrote for a human. Nothing from the log rides -- not the recommended version, not the
          // high-water mark, not the detail; only the closed guard class is counted.
          if (p.steps.some((s) => s.step === "anti-rollback-guard" && !s.ok)) await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "high-water");
        }
        return jsonResponse(p);
      } catch {
        // "Update apply always fails with a generic message" -- and the message is this one, which is a FIXED
        // string that asserts nothing changed. Record the LOCUS (which subsystem) and HOW FAR it got, so the
        // claim can be checked rather than taken on faith.
        await recordAdminRouteError(scheduler, { route: "update-apply", stage });
        return jsonError("could not start the update right now; nothing was changed.", 400);
      }
    }
    case "POST /update/settle": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // G183: the settle runs the CANARY and, on a bad verdict, the AUTO-ROLLBACK -- both real deploys. Its
      // outer catch is the one place a "nothing was changed" claim is most likely to be wrong.
      let stage: AdminRouteStage = "do-read";
      try {
        const body = (await req.json()) as { token?: unknown; components?: unknown };
        const token = typeof body.token === "string" ? body.token.trim() : "";
        // The console sends the SAME `components` split it sent to apply (client-update.ts settleUpdate), so
        // this route reads it through the SAME parser rather than ignoring the field: a split naming a
        // component this build cannot plan is refused here too, and recorded, instead of being silently
        // dropped and settled as though the operator had asked for the engine. WHICH component settles is
        // still decided by the armed pending record (the engine's pending owns any queued console phase);
        // the split is validated, never used to re-target a verification the record already fixed.
        const compReq = parseComponentsRequest(body.components);
        if (!compReq.ok) {
          await noteUpdateAttempt(scheduler, "settle-refused");
          return jsonError(compReq.error, 400);
        }
        const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
        const rec = (await recResp.json()) as { pending: null | { fromVersion: string; toVersion: string; recommendedVersion: string; canaryBaseline?: string; riskClass?: string; promotedAt?: number; sourceBindingsBefore?: string[]; percentage?: number; consoleQueued?: QueuedConsole | null; artefactSha384?: string; readback?: { verdict: string; mode: string; deployedSha384?: string; detail?: string } }; floors?: { console?: string } };
        if (!rec.pending) {
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "no-pending");
          await noteUpdateAttempt(scheduler, "settle-refused");
          return jsonError("there is no update awaiting verification", 400);
        }
        const pending = rec.pending;
        // A pending record carrying `percentage` came from the opt-in gradual ramp (asvs-HI-13), not the
        // atomic apply, so it is settled by POST /update/ramp/settle instead: that route freshly builds its
        // gate from the pending's OWN recommendedVersion and additionally requires self-identity before
        // trusting a keep (this settle's gate is only guaranteed to land on the atomic path's 100%-live new
        // version, never on a still-splitting ramp). Refusing here keeps the two settle paths mutually
        // exclusive so a ramp's pending can never be settled by the weaker, non-split-aware path.
        if (typeof pending.percentage === "number") {
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "ramp-shaped");
          await noteUpdateAttempt(scheduler, "settle-refused");
          return jsonError("this pending verification is a gradual ramp; use the ramp settle call instead. Nothing was changed.", 400);
        }
        // Multi-component: the apply may have QUEUED the console component behind this engine settle
        // (engine-first, engine-settled sequencing). Held in locals here because the engine's settled
        // record consumes the pending (and its queue) in the DO; the console phase runs after a KEEP.
        const queuedConsole = pending.consoleQueued ?? null;
        // W5: the KEEP dual-control gate below applies only to migration/breaking releases. The risk was
        // persisted at promote time; normalise the stored value (an absent/old riskClass defaults to the
        // safe gated path, exactly as apply does, never silently routine).
        stage = "gate";
        const pendingRisk = normaliseRiskClass(pending.riskClass, false);
        // Compute the keep/rollback decision FIRST by flying the canary (tokenless: read-only, isolated
        // _CANARY/ cell). The verdict drives BOTH the stale-pending guard below and the settle itself, and is
        // memoised so settleAfterPromote does not re-fly. (Moved above the TTL guard so the guard can be
        // health-aware: a STALE BUT UNHEALTHY pending must be ROLLED BACK, never silently cleared, see below.)
        // POST-SWAP TOLERANCE (incident): this request runs on the JUST-PROMOTED isolate, where
        // the code swap has reset every Durable Object, so a single canary flight here can transiently fail
        // to complete and must NOT be allowed to roll back a healthy update. probeSettleVerdict retries a
        // pending/ailing flight on a bounded backoff (a DEAD verdict is never retried) and consults the
        // self-check when the flight never resolves; its per-attempt steps ride into the response.
        const liveBaseline: CanaryLiveness = (pending.canaryBaseline as CanaryLiveness | undefined) ?? (await (makeHealthGate(env, scheduler, pending.recommendedVersion)).baseline());
        const decisionGate = makeHealthGate(env, scheduler, pending.recommendedVersion);
        const probe = await probeSettleVerdict(decisionGate);
        const liveVerdict: CanaryLiveness = probe.verdict;
        const liveSelfCheck: boolean = probe.selfCheckOk;
        // G275, NOISE. This route does NOT bump update-settle-inconclusive, and the absence is the fix.
        //
        // It used to bump on any non-alive/non-dead verdict. But an ailing/pending verdict here is the
        // documented POST-SWAP TOLERANCE (incident): decideKeep KEEPS, this settle records the
        // outcome "applied" and CLEARS the pending. That is a routine, CONCLUDED settle, and it was
        // incrementing a counter whose documented meaning (posture-counters.ts) is "the settle could not
        // decide and THE RAMP STAYS ARMED". A counter that fires on the commonest healthy settle in the
        // estate cannot answer "is the ramp stuck?", which is the only question it exists for.
        //
        // The verdict is not lost: this settle's canaryVerdict, selfCheckOk and the per-attempt settleTrace
        // are persisted into the settled record and projected into updates.last, where an inconclusive-looking
        // flight on a KEPT build is legible as what it is. The counter now has exactly one producer, the ramp
        // settle's inconclusive branch (router-updates-ramp.ts), which is the one path that genuinely leaves
        // the pending armed.
        const decision = decideKeep(liveBaseline, liveVerdict, liveSelfCheck);
        const memoGate: HealthGate = {
          baseline: async () => liveBaseline,
          flyNow: async () => liveVerdict,
          selfCheck: async () => liveSelfCheck,
        };
        // OBSERVABILITY: the full settle DECISION TRACE -- every post-swap retry's verdict +
        // the self-check + the decideKeep branch -- previously lived ONLY in the response (probe.attempts),
        // which races the isolate swap and is lost, so a rollback could never be diagnosed after the fact
        // (nor from a support pack). It is now (a) LOGGED here in real time (visible on `wrangler tail`),
        // and (b) PERSISTED into the settled record below (so a status re-read + the support pack carry it).
        // settleTrace is bounded (<=8 attempts, each detail clamped) so it stays a small, redaction-safe list.
        const settleTrace = probe.attempts.slice(-8).map((a) => ({ step: a.step, ok: a.ok, ...(a.detail !== undefined ? { detail: String(a.detail).slice(0, 160) } : {}) }));
        // The full trace goes into the log EVENT string (LogFields is a closed SIEM-standard shape, so the
        // decision detail rides in the message a `wrangler tail` shows in real time). The SAME facts are
        // persisted into the settled record below -- this line is the live view, that is the durable one.
        const traceStr = settleTrace.map((a) => `${a.step}:${a.detail ?? (a.ok ? "ok" : "fail")}`).join(" -> ");
        log(decision.keep ? "info" : "warn", `update settle ${decision.keep ? "KEEP" : "ROLLBACK"} ${pending.fromVersion}->${pending.toVersion} (${pending.recommendedVersion}) baseline=${liveBaseline} verdict=${liveVerdict} selfCheck=${liveSelfCheck ? "ok" : "inconclusive"} attempts=[${traceStr}] reason=${decision.reason}`);
        // STALE-PENDING GUARD (TTL), HEALTH-AWARE (FOLD 1). A pending verification older than the window was
        // abandoned (the page was closed between promote and settle). The OLD behaviour cleared it blindly,
        // which is WRONG when the now-live promoted version is unhealthy: it would forget the one thing that
        // still needs doing, the rollback. So the guard now branches on the canary verdict just computed:
        //   - live version HEALTHY (decision.keep) -> safe to clear as expired (nothing to revert; the hourly
        //     canary keeps covering it). This is the original, safe path.
        //   - live version NOT healthy -> do NOT clear. REVERT it: fall through to the settle machinery below,
        //     which (decision = rollback) deploys the recorded known-good with the operator's token, exactly
        //     the recovery a stale-yet-broken promote needs. (If no token is supplied, the fall-through returns
        //     the token-required prompt and LEAVES the pending intact so the one-click rollback stays offered.)
        if (typeof pending.promotedAt === "number" && Date.now() - pending.promotedAt > SETTLE_TTL_MS && decision.keep) {
          await scheduler.fetch(doURL("/update-settled"), { method: "POST", body: JSON.stringify({ outcome: "expired", recommendedVersion: pending.recommendedVersion, fromVersion: pending.fromVersion, toVersion: pending.toVersion, at: Date.now(), by: caller.email ?? null, reason: "the pending verification expired (over an hour old) and was cleared without any change; the hourly canary confirms the live version is healthy" }) });
          return jsonError("this pending update verification expired (over an hour old) and was cleared; nothing was changed. The hourly canary confirms the live version is healthy.", 409);
        }
        // OPT-IN DUAL CONTROL, GATE THE KEEP DIRECTION ONLY, NOT ROLLBACK. The settle finalises a deploy as
        // EITHER keep (promote/trust the NEW version) or rollback (revert to the known-good fromVersion).
        // Rollback is the SAFE RECOVERY direction: gating it would impede incident response (a lone owner left
        // holding an unhealthy engine could not revert), so per the "only gate dangerous activities" principle
        // ROLLBACK is NEVER gated. Only KEEP, trusting new engine code, the consequential direction, takes a
        // second owner's approval, bound to the SPECIFIC pending transition, NEVER the deploy token. The
        // keep/rollback decision (and its memoised gate) was computed above, before the TTL guard, so the
        // guard could be health-aware; settleAfterPromote reuses the memoised verdict rather than re-flying.
        //   - decision = ROLLBACK -> NOT gated: require the token, run the superseded guard, settle (revert).
        //   - decision = KEEP     -> gated: first call (no armed approval) records a pending approval + 202
        //     WITHOUT requiring the token; a second owner approves; the owner re-submits with the token and the
        //     gate consumes the armed approval here, then we require the token, run the superseded guard, and
        //     settle (keep = no deploy). The verdict was flown once above, so if the new version turns unhealthy
        //     the decision is ROLLBACK and reverts un-gated (safe).
        if (decision.keep && updateNeedsDualControl(pendingRisk)) {
          // KEEP of a migration/breaking release is gated behind a second owner (W5; a routine release keeps
          // without one even when dual control is ON). The bind is the exact pending version (NEVER the token).
          const g = await ownerActionGate(
            scheduler,
            caller,
            "update-settle",
            { fromVersion: pending.fromVersion, toVersion: pending.toVersion, recommendedVersion: pending.recommendedVersion },
            `Keep the engine update to ${pending.toVersion} (trust the new version; the canary sang; risk: ${pendingRisk}). Rolling back does not need approval.`,
          );
          if (g.kind === "error") return g.response;
          if (g.kind === "queued") return ownerActionQueuedResponse(g.id);
        }
        // ROLLBACK proceeds un-gated; KEEP proceeds only past the gate above. Both now require the token.
        if (!validateDeployToken(token)) {
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
          await noteUpdateAttempt(scheduler, "settle-refused");
          return jsonError("paste the one-shot deploy token again so the new version can be canary-verified and rolled back if it is unhealthy", 400);
        }
        const accountId = await resolveEngineAccount(env, scheduler);
        if (accountId === null) {
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "account-unmarked");
          await noteUpdateAttempt(scheduler, "settle-refused");
          return jsonError("the engine's own Cloudflare account is not marked", 400);
        }
        const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
        const driver = makeCfDeployDriver({ token, accountId, scriptName });
        // SUPERSEDED-PENDING GUARD: settle must only ever act on the version it promoted. If the live
        // version is no longer pending.toVersion (the owner re-deployed in between), settling now could
        // canary an unrelated version and roll back to a long-superseded one. We only treat the pending as
        // SUPERSEDED when the live deployment is a SINGLE version that DIFFERS from pending.toVersion. On a
        // multi-version SPLIT (a SEPARATE opt-in ramp still mid-flight; this pending's OWN ramp, if any, was
        // already refused above and never reaches here) we do NOT declare it superseded, settle proceeds
        // and, on a non-singing verdict, rolls back to fromVersion at 100% (which collapses the split
        // safely). The single-vs-split shape is read from the full slice set when the driver exposes it;
        // otherwise the reported version is treated as the single live version.
        let liveSingle: string | null;
        let liveLabel: string;
        if (typeof driver.currentLiveVersions === "function") {
          const slices = await driver.currentLiveVersions();
          liveSingle = liveSingleVersion(slices);
          liveLabel = liveSingle ?? slices.map((sl) => `${sl.versionId}@${sl.percentage}%`).join(", ");
        } else {
          liveSingle = await driver.currentLiveVersionId();
          liveLabel = liveSingle;
        }
        // LICENCE-BINDING-ON-CLAIM follow-up: the read just above (currentLiveVersions
        // / currentLiveVersionId) already proved this accountId owns this engine's script -- the SAME
        // proof-of-ownership shape the apply leg's own promote uses before its own persist call
        // (router-updates.ts:533). A settle is a SEPARATE request from apply, and on the very cycle that
        // installs this persist call, the apply leg's own call still ran on the pre-upgrade code (it does not
        // exist there) and could not fire; this settle request, arriving after the swap, is the first request
        // guaranteed to run on the new code, so it must not rely on the apply leg alone. Best-effort and
        // idempotent (recordVerifiedEngineAccount itself is write-once: a second call after the first is a
        // cheap no-op, never overwritten), and unconditional on the keep/rollback decision below: the account
        // that owns this script does not change with that decision.
        await recordVerifiedEngineAccountAfterSelfDeploy(env, accountId, "update-apply");
        if (liveSingle !== null && liveSingle !== pending.toVersion) {
          await scheduler.fetch(doURL("/update-settled"), { method: "POST", body: JSON.stringify({ outcome: "superseded", recommendedVersion: pending.recommendedVersion, fromVersion: pending.fromVersion, toVersion: pending.toVersion, at: Date.now(), by: caller.email ?? null, reason: `the live version (${liveLabel}) is no longer the one this update promoted (${pending.toVersion}); the pending verification was cleared without any change` }) });
          return jsonError(`the engine's live version (${liveLabel}) is no longer the one this update promoted (${pending.toVersion}); nothing was changed and the stale pending verification was cleared.`, 409);
        }
        // PERSISTENCE-FIRST HONESTY (incident): the decision is already final here (the probe
        // + decideKeep above are what settleAfterPromote will re-derive from the memoised gate), and the
        // ROLLBACK direction is about to re-deploy the prior version -- which tears down THIS isolate, so
        // the response (and any post-deploy write) can race its own teardown. Persist the decided outcome
        // BEFORE any deploy action, so a re-read of GET /update/status shows the truth even if this
        // response never lands. The one genuine divergence -- the rollback deploy itself failing -- is
        // written as a corrective record below. (Residual: a crash BETWEEN this write and the deploy would
        // record a rollback that never deployed; that window is not deploy-induced and the recorded target
        // stays correct, so a retried rollback is a safe no-op.)
        const preReason = decision.keep
          ? decision.reason
          : `the update to ${pending.recommendedVersion} did not pass the canary (${decision.reason}); your engine was automatically rolled back to the prior version. Nothing was lost and no backup or restore was affected.`;
        // confirmationPending: a KEEP the canary did not itself confirm (verdict not "alive") is
        // honest-but-provisional -- the hourly canary confirms it later (notify-passes.ts). PERSIST it here
        // (it was previously response-only, so a status re-read + the cron's own read never saw it -- the
        // exact "decision state not durable" gap this observability rework closes). Only-when-true keeps the
        // record clean; every rollback and every canary-confirmed keep omits it.
        const confirmationPending = decision.keep && liveVerdict !== "alive";
        await scheduler.fetch(doURL("/update-settled"), {
          method: "POST",
          body: JSON.stringify({ outcome: decision.keep ? "applied" : "rolled-back", recommendedVersion: pending.recommendedVersion, fromVersion: pending.fromVersion, toVersion: pending.toVersion, canaryVerdict: liveVerdict, selfCheckOk: liveSelfCheck, settleTrace, ...(confirmationPending ? { confirmationPending: true } : {}), at: Date.now(), by: caller.email ?? null, reason: preReason, ...(pending.artefactSha384 ? { artefactSha384: pending.artefactSha384 } : {}), ...(pending.readback !== undefined ? { readback: pending.readback } : {}) }),
        });
        // Settle with the MEMOISED gate (no re-fly), using the baseline captured at promote time for a stable
        // decision; settleAfterPromote re-derives the same keep/rollback verdict from the cached values.
        // settleAfterPromote can DEPLOY (its own auto-rollback), so from here the "nothing was changed"
        // sentence in the catch below is not safe to believe.
        stage = "deploy-driver";
        const s = await settleAfterPromote(driver, memoGate, { fromVersion: pending.fromVersion, toVersion: pending.toVersion, recommendedVersion: pending.recommendedVersion, canaryBaseline: liveBaseline });
        // asvs-HI-19: a "rolled-back" outcome above just redeployed fromVersion (settleAfterPromote's own
        // auto-rollback), the same self-redeploy that resets this DO; "applied" deploys nothing here but
        // shares this call site, so both follow-up writes always use the self-redeploy-safe helpers (a
        // harmless immediate success when nothing actually reset). This supersedes the narrower "only
        // correct the record if the rollback deploy step itself failed" approach: it is unconditional (so a
        // successful settle is ALSO recorded via the race-safe path, not just a plain write that could be
        // lost to the very self-redeploy it is racing) and it also carries the audit trail, not only the
        // bookkeeping record. Both writes carry the full settle DECISION TRACE (selfCheckOk, settleTrace)
        // the observability rework added, and the audit detail carries the WHOLE decision (verdict +
        // self-check + reason), so the tamper-evident audit chain alone answers "why did this settle keep
        // or roll back" even across a self-redeploy reset. setUpdateSettled REPLACES `last` wholesale, so
        // this write must carry s.confirmationPending forward too (an "applied" outcome the canary itself
        // never sang alive on) -- otherwise this second, always-runs write would silently clobber the
        // persist-first write's own confirmationPending with an absent field.
        stage = "persist";
        const settledWritten = await recordBookkeepingAfterSelfDeploy(env, "/update-settled", { outcome: s.outcome, recommendedVersion: s.recommendedVersion, fromVersion: s.fromVersion, toVersion: s.toVersion, ...(s.canaryVerdict ? { canaryVerdict: s.canaryVerdict } : {}), selfCheckOk: liveSelfCheck, settleTrace, ...(s.confirmationPending ? { confirmationPending: true } : {}), at: Date.now(), by: caller.email ?? null, ...(s.reason ? { reason: s.reason } : {}), ...(pending.artefactSha384 ? { artefactSha384: pending.artefactSha384 } : {}), ...(pending.readback !== undefined ? { readback: pending.readback } : {}) });
        const audited = await recordAuditAfterSelfDeploy(env, caller, sourceIp, s.outcome === "applied" ? "update-applied" : "update-rolled-back", { kind: "engine-state", field: "engineVersion", detail: `${s.fromVersion} -> ${s.outcome === "applied" ? s.toVersion : s.fromVersion} (canary ${s.canaryVerdict ?? "unknown"}, self-check ${liveSelfCheck ? "ok" : "inconclusive"}): ${(s.reason ?? decision.reason).slice(0, 240)}${pending.artefactSha384 ? `; sha384 ${pending.artefactSha384}` : ""}` });
        // The response carries the probe's per-attempt steps ahead of the settle's own (the operator sees
        // the retries that tolerated -- or failed to clear -- the post-swap window), on every return path.
        if (!settledWritten || !audited) {
          // G101: the SETTLE half. A settle that did not persist leaves the console unable to offer a rollback
          // ("no recorded prior version" immediately after an update) and a canary that can never be confirmed.
          if (!settledWritten) await recordUpdateFault(scheduler, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "settled" });
          if (!audited) await recordUpdateFault(scheduler, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "audit" });
          return jsonResponse({ ...s, steps: [...probe.attempts, ...s.steps], reason: "the update was settled but could not be fully recorded; check GET /admin/update/status and GET /admin/audit before trying again." });
        }
        const settled: Record<string, unknown> = { ...s, steps: [...probe.attempts, ...s.steps] };
        // POST-UPDATE SOURCE VERIFICATION. On a KEPT update (the new version is now live), re-read the live
        // source bindings and diff against the pre-update snapshot: if the update dropped any (it should not,
        // cf-deploy re-sends them, but this proves it after the fact instead of trusting it), surface the
        // dropped names so the console prompts the owner to re-attach (POST /sources/reattach-missing) with a
        // fresh deploy token. A ROLLED-BACK update is back on the prior version, whose bindings are the
        // pre-update set, so no diff is run. NAMES only cross the wire (to the owner, in their own account).
        if (s.outcome === "applied" && Array.isArray(pending.sourceBindingsBefore) && pending.sourceBindingsBefore.length > 0) {
          const postBound = enumerateBoundSources(env);
          const postNames = new Set<string>([...postBound.kv, ...postBound.r2, ...postBound.d1, ...postBound.secrets]);
          const droppedSources = pending.sourceBindingsBefore.filter((n) => !postNames.has(n));
          if (droppedSources.length > 0) {
            // The most consequential failure here was previously half-instrumented. The diff computes the EXACT names, the
            // audit row persisted only the COUNT, and the names rode the HTTP response and were gone -- so
            // support could PROVE bindings were dropped and could not say WHICH to re-attach. Binding names are
            // the operator's own labels, the identical redaction class the pack already ships in sourcesDetached
            // (capped 64, control-stripped, length-clamped by the DO-side applier).
            await recordUpdateFault(scheduler, { component: "engine", step: "binding-guard", cause: "sources-dropped", droppedSources });
            await recordAudit(scheduler, caller, sourceIp, "update-applied", "success", { kind: "engine-state", field: "engineVersion", detail: `update dropped ${droppedSources.length} source binding(s); re-attach needed` });
            settled.droppedSources = droppedSources;
          }
        }
        // ---- multi-component continuation: a QUEUED console component applies only AFTER the engine
        // settled as APPLIED (keep -- including a keep decided via the self-check, else consoles could
        // never update on an engine whose canary cannot gate). A rolled-back engine ABORTS the console
        // with the honest partial-state story (the DO recorded that abort in the persist-first write).
        if (queuedConsole !== null && typeof queuedConsole === "object" && typeof queuedConsole.version === "string") {
          let consoleResult: unknown;
          if (s.outcome === "applied") {
            // Re-verify the channel NOW (verify-before-deploy at the moment of the deploy) and require the
            // console component to still be the version that was approved + queued.
            const artNow = await loadVerifiedChannel(env);
            if ("error" in artNow) {
              // G054: the SETTLE-TIME channel re-verify. It fails with a half-applied release (the engine is on
              // the new version, the console is not), which is the update state a customer is most likely to
              // ring about, and the channel's cause was recorded nowhere. Same row, same closed cause.
              await recordUpdateFault(scheduler, { component: "channel", step: channelFaultStep(artNow.causeClass), cause: artNow.causeClass });
              consoleResult = await recordConsoleQueueResolution(scheduler, { caller, sourceIp }, queuedConsole.version, `the update channel could not be re-verified at settle time (${artNow.error}); the queued console component was not applied. The engine stays on the new version; apply the console component alone once the channel reads again.`);
            } else {
              const rc = resolveConsoleComponent(artNow);
              if (!rc.ok) {
                consoleResult = await recordConsoleQueueResolution(scheduler, { caller, sourceIp }, queuedConsole.version, `${rc.error}. The engine stays on the new version.`);
              } else if (rc.component.version !== queuedConsole.version) {
                consoleResult = await recordConsoleQueueResolution(scheduler, { caller, sourceIp }, queuedConsole.version, `the signed channel now offers console ${rc.component.version} but ${queuedConsole.version} was the version approved and queued; refusing a version that moved underneath the approval. The engine stays on the new version; re-run the apply to take the current release.`);
              } else {
                consoleResult = await executeConsoleApply({
                  env,
                  scheduler,
                  actor: { caller, sourceIp },
                  accountId,
                  token,
                  component: rc.component,
                  ...(rec.floors?.console !== undefined && rec.floors.console !== "" ? { consoleFloor: rec.floors.console } : {}),
                  dryRun: false,
                  ...(artNow.sequence !== undefined ? { channelSeq: artNow.sequence } : {}),
                  ...(artNow.issuedAt !== undefined ? { channelIssuedAt: artNow.issuedAt } : {}),
                });
              }
            }
          } else {
            consoleResult = { component: "console", outcome: "refused", recommendedVersion: queuedConsole.version, steps: [], reason: "the release was not applied; the engine rolled back and the console is unchanged" };
          }
          return jsonResponse({ ...settled, componentResults: [{ component: "engine", ...settled }, consoleResult] });
        }
        return jsonResponse(settled);
      } catch {
        await recordAdminRouteError(scheduler, { route: "update-settle", stage });
        return jsonError("could not report the settle outcome; refresh the update status to see the recorded result (the outcome is recorded before any deploy action, so the status shows what actually happened; if no outcome is recorded there, the settle did not reach a decision and nothing was changed).", 400);
      }
    }
    case "GET /update/status": {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      const resp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
      if (!resp.ok) return resp;
      // destinationConfigured (design §4/§7, ADDITIVE): the SAME authoritative read the live-apply gate
      // uses, so the console can replace the apply control with the "add a destination first" line (and
      // the eventual confirmation can arrive) WITHOUT first attempting an apply. No existing status fact
      // already carries this (discovery checked: UpdateRecord has no destination field at all), so it is
      // added here rather than duplicated onto a second endpoint.
      const rec = (await resp.json()) as Record<string, unknown>;
      return jsonResponse({ ...rec, destinationConfigured: await destinationConfigured(env, scheduler) });
    }
    // ---- W4: the STANDALONE one-click rollback (revert to the recorded known-good version) --------------
    // A first-class, ALWAYS-AVAILABLE revert, independent of an in-flight apply. It reverts to the prior live
    // version recorded by the last apply (pending.fromVersion if a verification is in flight, else
    // last.fromVersion). This is the SAFE recovery direction (the same direction the settle auto-rollback
    // takes), so by design it needs NO second-owner approval (W5 gates only the consequential apply/keep
    // direction). Owner-gated (keys.ceremony) + rate-limited; the one-shot deploy token is required + never
    // stored; fail-safe (never a 500). It NEVER touches the data or recovery path. The BODY lives in
    // router-updates-rollback.ts (size-budget split, the router-updates-ramp.ts precedent); behaviour is
    // verbatim, and the gate below did not move with it.
    case "POST /update/rollback": {
      // The gate stays HERE rather than moving with the body, and that is not tidiness: the gated surface
      // validate-gate-observed-as-refused.ts drives a viewer against is enumerated by reading
      // gate(caller, cap) out of a route's own case body, so a gate that moves into a delegated handler
      // stops being observed. The handler's own first act is still the rate limit, so the order is
      // unchanged from when both read inline here.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      return handleStandaloneRollback({ env, scheduler, caller, sourceIp, req });
    }
    // ---- W4 + asvs-HI-13: the OPT-IN gradual ramp (start + settle) live in router-updates-ramp.ts
    // (size-budget split, the router-updates-components.ts precedent); behaviour is verbatim. Ramp is
    // ENGINE-ONLY forever and mutually exclusive with POST /update/settle (each settle route refuses the
    // other's pending shape).
    case "POST /update/ramp":
      return handleRampStart({ env, scheduler, caller, sourceIp, req });
    case "POST /update/ramp/settle":
      return handleRampSettle({ env, scheduler, caller, sourceIp, req });
    default:
      return null;
  }
}
