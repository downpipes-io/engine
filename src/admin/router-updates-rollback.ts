// router-updates-rollback.ts -- the STANDALONE one-click rollback route (POST /update/rollback), split
// out of router-updates.ts so the route hub stays within the module size budget, the same seam
// router-updates-ramp.ts and router-updates-components.ts already carry. The body is VERBATIM from
// router-updates.ts apart from the two gate lines named below; the case body's locals now arrive as an
// argument object instead of being read off the hub's RouterCtx.
//
// THE keys.ceremony GATE DELIBERATELY DID NOT MOVE. It stays inline in the hub's case body, and the first
// thing this handler does is the rate limit that used to sit second. The order of operations is unchanged,
// and the reason the gate stayed is a gate that reads it: validate-gate-observed-as-refused.ts enumerates
// the capability-gated surface by finding gate(caller, cap) INSIDE a route's own case body, and drives a
// viewer at every route it finds to prove the refusal is observed and names the capability. A gate that
// moves into a delegated handler leaves that surface silently, which is why POST /update/ramp and POST
// /update/ramp/settle are gated in production and are not in the observed set. This split declined to add a
// third. Imports the shared router primitives + router-updates-shared.ts; never imports router.ts or
// router-updates.ts.

import type { Env } from "../env.d.ts";
import { doURL } from "../do-url.ts";
import { makeCfDeployDriver } from "./cf-deploy.ts";
import { recordUpdateFault } from "./diag-admin.ts";
import { recordAdminRouteError } from "./diag-counters.ts";
import type { AdminRouteStage } from "./diag-records.ts";
import { jsonError, jsonResponse, rateLimited, recordAudit, recordAuditAfterSelfDeploy, recordBookkeepingAfterSelfDeploy, resolveRollbackTarget, validateDeployToken } from "./router-core.ts";
import { resolveEngineAccount } from "./router-sources.ts";
import { consoleRollbackTargetFrom, executeConsoleRollback } from "./router-updates-components.ts";
import { noteUpdateAttempt, noteUpdateGuardRefusal } from "./router-updates-shared.ts";
import { runStandaloneRollback } from "./update-apply.ts";
import { makeHealthGate } from "./update-gate.ts";
import { parseComponentsRequest } from "./update-orchestrate.ts";
import { engineRollbackSatisfiesConsoleFloor, PAIRED_ROLLBACK_COPY } from "./update-rollback.ts";

// RollbackRouteArgs carries the rollback route's request context from the hub into the handler, the same
// shape RampRouteArgs carries for the two ramp routes.
export interface RollbackRouteArgs {
  env: Env;
  scheduler: DurableObjectStub;
  caller: Parameters<typeof recordAudit>[1];
  sourceIp: string | null;
  req: Request;
}

// ---- W4: STANDALONE one-click rollback (revert to the recorded known-good version) ----------------
// A first-class, ALWAYS-AVAILABLE revert, independent of an in-flight apply. It reverts to the prior live
// version recorded by the last apply (pending.fromVersion if a verification is in flight, else
// last.fromVersion). This is the SAFE recovery direction (the same direction the settle auto-rollback
// takes), so by design it needs NO second-owner approval (W5 gates only the consequential apply/keep
// direction). Owner-gated (keys.ceremony) + rate-limited; the one-shot deploy token is required + never
// stored; fail-safe (never a 500). It NEVER touches the data or recovery path.
export async function handleStandaloneRollback(a: RollbackRouteArgs): Promise<Response> {
  const { env, scheduler, caller, sourceIp, req } = a;
  const limited = await rateLimited(scheduler, caller);
  if (limited) return limited;
  // G183: a rollback is a real deploy. Its catch says "if no rollback is recorded there, nothing was
  // changed" -- which is a claim about a record that may itself have failed to write.
  let stage: AdminRouteStage = "do-read";
  try {
    const body = (await req.json()) as { token?: unknown; components?: unknown; dryRun?: unknown };
    const token = typeof body.token === "string" ? body.token.trim() : "";
    // dryRun (design UPDATE-UX-015 §6/§7, ADDITIVE): an explicit opt-in PREVIEW. UNLIKE apply/ramp
    // (which default dryRun TRUE, going live is the opt-in), this route predates any dry-run concept
    // and every existing caller relies on an absent field meaning LIVE -- so absent/false stays exactly
    // today's behaviour. true reports the resolved target (and, on the engine arm, whether it would be
    // a PAIRED rollback) before any token is read or spent.
    const dryRun = body.dryRun === true;
    // WHICH COMPONENT TO REVERT is read from `components` -- the PLURAL array the console actually
    // sends on every rollback call it makes: rollbackUpdate(token, ["console"]) from the post-apply
    // console build check (console update-console-check.ts:127), rollbackUpdate(token, [id]) from the
    // per-component controls (update-components-advanced.ts:137), and rollbackPlan(components) behind
    // the confirm dialog (update-rollback-confirm.ts:31). This route used to read a SINGULAR `component`
    // key that no client has ever sent, so `components:["console"]` fell through to the engine arm and
    // an operator asking to revert the CONSOLE got an ENGINE rollback (and a preview describing one).
    // The singular key is GONE: one parser (parseComponentsRequest), the same one apply/settle/ramp use,
    // so the four routes cannot drift apart again. Absent = the engine rollback, byte-for-byte.
    const compReq = parseComponentsRequest(body.components);
    if (!compReq.ok) {
      await noteUpdateAttempt(scheduler, "rollback-refused");
      return jsonError(compReq.error, 400);
    }
    const wantsEngine = compReq.components === null || compReq.components.includes("engine");
    const wantsConsole = compReq.components?.includes("console") ?? false;
    if (wantsConsole && !wantsEngine) {
      // CONSOLE-ONLY revert: the safe direction on its own script. dryRun resolves the console's own
      // recorded known-good and spends no token (the same preview contract the engine arm honours);
      // anything else deploys it.
      if (dryRun) {
        const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
        const rec = (await recResp.json()) as { lastConsole?: { outcome?: string; fromVersion?: string } | null };
        const consoleTarget = consoleRollbackTargetFrom(rec).trim();
        if (consoleTarget === "") {
          await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "no-target");
          await noteUpdateAttempt(scheduler, "rollback-refused");
          return jsonError("there is no recorded prior console version to roll back to; nothing was changed. (A rollback target is recorded the first time you apply a console update from here.)", 400);
        }
        return jsonResponse({ component: "console", outcome: "dry-run", toVersion: consoleTarget });
      }
      if (!validateDeployToken(token)) {
        await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
        await noteUpdateAttempt(scheduler, "rollback-refused");
        return jsonError('paste the one-shot Cloudflare deploy token (the "Edit Cloudflare Workers" template); it is used once and never stored', 400);
      }
      const accountId = await resolveEngineAccount(env, scheduler);
      if (accountId === null) {
        await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "account-unmarked");
        await noteUpdateAttempt(scheduler, "rollback-refused");
        return jsonError("the engine's own Cloudflare account is not marked", 400);
      }
      const r = await executeConsoleRollback({ env, scheduler, actor: { caller, sourceIp }, accountId, token });
      return jsonResponse(r);
    }
    // Resolve the known-good target from the persisted lifecycle. The known-good is the version to put
    // back live, and it depends on the LAST outcome (NOT a blind last.fromVersion, which on a prior
    // rollback would be the abandoned BAD version, deploying it forward would corrupt the rollback into a
    // re-application of the bad build). The rule:
    //   - a verification in flight (pending)  -> pending.fromVersion (the version it promoted away from)
    //   - last outcome "applied"              -> last.fromVersion   (the prior known-good)
    //   - last outcome "rolled-back"          -> last.fromVersion   (the version we reverted TO; we are
    //                                            ALREADY on it, so a redundant 2nd rollback is a no-op,
    //                                            both rollback writers record the reverted-to version in
    //                                            fromVersion, the same field the console shows)
    //   - last outcome "superseded"/"expired"/other -> NO target (the pending was cleared WITHOUT a
    //                                            deploy, so neither field is a reliable known-good; refuse
    //                                            rather than deploy a stale/abandoned version)
    // The orchestration treats an empty target as a clean "no-target" (never a blind deploy).
    const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
    const rec = (await recResp.json()) as { pending: null | { fromVersion?: string }; last: null | { outcome?: string; fromVersion?: string }; lastConsole?: { minEngineVersion?: string } | null };
    const target = resolveRollbackTarget(rec).trim();
    if (target === "") {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "no-target");
      await noteUpdateAttempt(scheduler, "rollback-refused");
      return jsonError("there is no recorded prior engine version to roll back to; nothing was changed. (A rollback target is recorded the first time you apply an update from here, and is cleared once you are back on a known-good version.)", 400);
    }
    // CONDITIONAL-BUNDLING FLOOR CHECK (design §6): the live console's persisted minEngineVersion (from
    // its own applied record, absent = no console / no floor). An UNPARSEABLE comparison is
    // engineRollbackSatisfiesConsoleFloor's OWN fail-closed rule (never strand), which reads here as
    // "does NOT satisfy" -> paired, exactly like a genuine violation.
    // A split that names BOTH components ASKED for the pair, so it pairs whatever the floor says: the
    // request is the stronger statement, and narrowing it to the engine alone would be the same silent
    // re-targeting the singular-key defect caused.
    const consoleFloor = rec.lastConsole?.minEngineVersion;
    const paired = wantsConsole || !engineRollbackSatisfiesConsoleFloor(target, consoleFloor);
    // PREVIEW (§7): report the target + whether it would pair, before a token is read or spent, so the
    // console can show the §6 copy line ahead of confirm. Nothing is read/changed beyond the status GET
    // above (no deploy token needed -- the engine holds no ambient Cloudflare credential either way).
    if (dryRun) {
      return jsonResponse({ component: "engine", outcome: "dry-run", toVersion: target, ...(paired ? { paired: true as const, reason: PAIRED_ROLLBACK_COPY } : {}) });
    }
    if (!validateDeployToken(token)) {
      // G275: "we tried to roll back at 02:00 and it refused." A rollback refused for want of a deploy
      // token, and one refused because there is no recorded target, are different tickets with different
      // fixes -- and both were a bare 400 into a browser at two in the morning.
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
      await noteUpdateAttempt(scheduler, "rollback-refused");
      return jsonError('paste the one-shot Cloudflare deploy token (the "Edit Cloudflare Workers" template); it is used once and never stored', 400);
    }
    const accountId = await resolveEngineAccount(env, scheduler);
    if (accountId === null) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "account-unmarked");
      await noteUpdateAttempt(scheduler, "rollback-refused");
      return jsonError("the engine's own Cloudflare account is not marked", 400);
    }
    const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
    const driver = makeCfDeployDriver({ token, accountId, scriptName });
    const hgate = makeHealthGate(env, scheduler, target);
    stage = "deploy-driver";
    const r = await runStandaloneRollback(driver, hgate, { toVersion: target });
    // Record the outcome on the lifecycle (the console reads it) + audit (ids + outcome, never the token).
    // CONVENTION (shared with the settle auto-rollback record so the resolver above + the console display
    // are consistent): on a rolled-back outcome, fromVersion = the version we reverted TO (the known-good,
    // now live, what the console shows and what a redundant next rollback no-ops against), toVersion = the
    // bad version we left. We must NOT record the abandoned bad version (r.fromVersion) in fromVersion: a
    // later rollback would then resolve it as the target and deploy FORWARD onto the bad build.
    if (r.outcome === "reverted" || r.outcome === "reverted-unverified") {
      // asvs-HI-19: the rollback above just redeployed the known-good version, the same self-redeploy
      // that resets this DO, so both follow-up writes use the self-redeploy-safe helpers.
      stage = "persist"; // the revert LANDED
      const settledWritten = await recordBookkeepingAfterSelfDeploy(env, "/update-settled", { outcome: "rolled-back", recommendedVersion: target, fromVersion: target, ...(r.fromVersion ? { toVersion: r.fromVersion } : {}), ...(r.canaryVerdict ? { canaryVerdict: r.canaryVerdict } : {}), at: Date.now(), by: caller.email ?? null, ...(r.reason ? { reason: r.reason } : {}) });
      const audited = await recordAuditAfterSelfDeploy(env, caller, sourceIp, "update-rolled-back", { kind: "engine-state", field: "engineVersion", detail: `standalone rollback ${r.fromVersion ?? "?"} -> ${target} (canary ${r.canaryVerdict ?? "unknown"})` });
      if (!settledWritten || !audited) {
        return jsonResponse({ ...r, reason: "the rollback went live but could not be fully recorded; check GET /admin/update/status and GET /admin/audit before trying again." });
      }
      // PAIRED ROLLBACK (design §6): the engine reverted PAST what the live console requires -> the
      // console pairs down to ITS OWN recorded known-good, ONE action, spending the SAME token + the
      // SAME (already-marked) account. Honest per-component results either way (executeConsoleRollback
      // never throws -- a no-target/failed console arm still returns a structured result, never
      // stranding the engine's own outcome).
      if (paired) {
        const consoleR = await executeConsoleRollback({ env, scheduler, actor: { caller, sourceIp }, accountId, token });
        return jsonResponse({ ...r, paired: true as const, componentResults: [{ component: "engine" as const, ...r }, consoleR] });
      }
    } else if (r.outcome === "failed") {
      // G219: the FAILED standalone rollback. The operator pressed "Roll back" on an engine they know is
      // bad, the revert deploy did not land, and the ONLY record of it was a 100-character CLIPPED prose
      // fragment on an `update-refused` audit row -- an action name with no outcome. No lifecycle record
      // was written at all, so GET /update/status (and therefore the pack, the console badge and the bot)
      // still showed whatever the PREVIOUS settle had left there: very often "applied", on the very build
      // the operator just tried to escape.
      //
      // Persist the real thing: a lifecycle record whose closed outcome SAYS the rollback failed, and a
      // fault row carrying the closed cause. The engine is still serving the version the operator wanted
      // gone, and every consumer now reads that from the enum rather than from a truncated sentence.
      stage = "persist";
      await recordBookkeepingAfterSelfDeploy(env, "/update-settled", { outcome: "rollback-failed", recommendedVersion: target, fromVersion: target, ...(r.fromVersion ? { toVersion: r.fromVersion } : {}), ...(r.canaryVerdict ? { canaryVerdict: r.canaryVerdict } : {}), at: Date.now(), by: caller.email ?? null, ...(r.reason ? { reason: r.reason } : {}) });
      await recordUpdateFault(scheduler, { component: "engine", step: "promote", cause: "rollback-failed", rollbackFailed: true });
      await recordAudit(scheduler, caller, sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: `standalone rollback failed: ${(r.reason ?? "").slice(0, 100)}` });
    }
    return jsonResponse(r);
  } catch {
    // Honest either way (a deploy that landed tears down this isolate, so the response can race its
    // own teardown): never assert what happened -- point at the recorded result.
    await recordAdminRouteError(scheduler, { route: "update-rollback", stage });
    return jsonError("could not report the rollback outcome; refresh the update status to see the recorded result (if no rollback is recorded there, nothing was changed). The hourly canary independently verifies the live version.", 400);
  }
}
