// router-updates-ramp.ts -- the OPT-IN gradual-ramp halves of the update routes (W4 phase 1 start +
// asvs-HI-13 phase 2 settle), split out of router-updates.ts so the route hub stays within the module
// size budget (the same seam split router-updates-components.ts carries for the console halves). These
// helpers are route-shaped (they read env/scheduler/caller and write the DO records + audit), but every
// deploy decision lives in the pure state machines they call (startGradualRamp / settleAfterRamp in
// update-ramp.ts). Imports the shared router primitives + router-updates-shared.ts; never imports
// router.ts or router-updates.ts. Bodies are verbatim from router-updates.ts; only the module moved.

import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { makeCfDeployDriver } from "./cf-deploy.ts";
import { recordAdminRouteError } from "./diag-counters.ts";
import type { AdminRouteStage } from "./diag-records.ts";
import { gate, jsonError, jsonResponse, ownerActionGate, ownerActionQueuedResponse, rateLimited, recordAudit, recordAuditAfterSelfDeploy, recordBookkeepingAfterSelfDeploy, updateNeedsDualControl, validateDeployToken } from "./router-core.ts";
import { doURL } from "../do-url.ts";
import { fetchArtefactBytes, resolveEngineAccount } from "./router-sources.ts";
import { freshnessRefusal, noteUpdateAttempt, noteUpdateDegradations, noteUpdateGuardRefusal, pendingUpdateRefusal, readUpdateFloor } from "./router-updates-shared.ts";
import { liveSingleVersion, type RampInput, rampPercentageValid, settleAfterRamp, startGradualRamp } from "./update-apply.ts";
import { makeHealthGate } from "./update-gate.ts";
import { parseComponentsRequest } from "./update-orchestrate.ts";
import { loadVerifiedChannel, normaliseRiskClass } from "./updates.ts";

// RampRouteArgs carries one ramp route's request context from the hub into the handler.
export interface RampRouteArgs {
  env: Env;
  scheduler: DurableObjectStub;
  caller: Parameters<typeof recordAudit>[1];
  sourceIp: string | null;
  req: Request;
}

// handleRampStart is POST /update/ramp (W4, phase 1): upload + ramp `percentage`% of LIVE traffic to the
// new version. A ramp serves REAL traffic (not an isolated preview, isolated previews need *.workers.dev,
// banned). Same owner gate + verify-before-deploy + migration/compat guards as the atomic path; dual
// control applies exactly as for apply (W5: gated only for migration/breaking); the token is required +
// never stored. startGradualRamp never flies the canary inline (this call still runs the PRE-ramp code);
// POST /update/ramp/settle (below) is the genuinely separate dispatch that gates it. Fail-safe.
export async function handleRampStart(a: RampRouteArgs): Promise<Response> {
  const { env, scheduler, caller, sourceIp, req } = a;
  const denied = gate(caller, "keys.ceremony");
  if (denied) return denied;
  const limited = await rateLimited(scheduler, caller);
  if (limited) return limited;
  // G183: "the gradual ramp always errors" -- and the outer catch returned a fixed sentence and dropped the
  // exception. `stage` is the last checkpoint passed, so the pack says whether the ramp's traffic SPLIT was
  // ever driven (deploy-driver / persist), which is the difference between "nothing happened" and "a live
  // traffic split is now routing real customers to a version you were told was never deployed".
  let stage: AdminRouteStage = "do-read";
  try {
    const body = (await req.json()) as { token?: unknown; percentage?: unknown; allowDowngrade?: unknown; components?: unknown };
    // The components split is read through the SAME parser the apply, settle and rollback routes use (the
    // singular `component` key this route also tested is GONE: no client has ever sent it, and keeping a
    // second spelling of the same field is how the rollback route came to ignore what the console sends).
    const compReq = parseComponentsRequest(body.components);
    if (!compReq.ok) return jsonError(compReq.error, 400);
    // RAMP IS ENGINE-ONLY, FOREVER: a static-assets console swap is atomic at promote and has no
    // traffic-percentage concept, so a ramp request naming the console is refused honestly (never
    // silently narrowed to the engine).
    if (compReq.components?.includes("console") === true) {
      return jsonError("a gradual ramp applies to the engine only: a console (static-assets) swap is atomic at promote and has no traffic-percentage concept. Apply the console component with the normal apply instead. Nothing was changed.", 400);
    }
    const percentage = typeof body.percentage === "number" ? body.percentage : NaN;
    if (!rampPercentageValid(percentage)) {
      return jsonError("a gradual ramp needs a percentage between 1 and 99 (100% is the normal atomic apply); nothing was changed.", 400);
    }
    // asvs-HI-14 (PRIMARY guard): same refusal as apply (see pendingUpdateRefusal) -- a second ramp/apply
    // call while a prior verification is open must not be able to reach startGradualRamp mid-split.
    const pendingBlock = await pendingUpdateRefusal(scheduler);
    if (pendingBlock) {
      // R7: the closed guard class, not an audit-only refusal whose detail the pack's excerpt strips.
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "pending-open");
      return pendingBlock;
    }
    const allowDowngrade = body.allowDowngrade === true; // explicit downgrade-to-recover opt-in (default false)
    const token = typeof body.token === "string" ? body.token.trim() : "";
    const accountId = await resolveEngineAccount(env, scheduler);
    if (accountId === null) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "account-unmarked");
      return jsonError("the engine's own Cloudflare account is not marked yet; choose it under Sources first. Or use the wrangler deploy path.", 400);
    }
    const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
    stage = "channel-fetch";
    const degraded = new Set<string>();
    const art = await loadVerifiedChannel(env, undefined, degraded);
    if (degraded.size > 0) void noteUpdateDegradations(scheduler, [...degraded]);
    if ("error" in art) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "artefact-resolve");
      return jsonError(`no applicable update: ${art.error}`, 400);
    }
    // The engine COMPONENT's own version (identical to the release version for every v1 channel; a v2
    // console-only release repeats the current engine version here, an honest no-update for a ramp).
    const engineTarget = art.artefact.version;
    if (engineTarget === ENGINE_VERSION) {
      return jsonResponse({ outcome: "no-update", recommendedVersion: engineTarget, steps: [] });
    }
    // R8 + R9: same anti-rollback floor + freshness enforcement as the atomic apply -- and the same G183
    // bracket. readUpdateFloor is a SCHEDULER DO READ with no catch of its own, so a DO outage here throws into
    // this route's outer catch; recorded under channel-fetch it would be indistinguishable from a signed-channel
    // fault, which has a completely different owner (the vendor's CDN / the customer's egress vs the customer's
    // own scheduler DO). The stage is the last checkpoint PASSED, so it is restored immediately afterwards.
    stage = "do-read";
    const floor = await readUpdateFloor(scheduler, env);
    stage = "channel-fetch";
    const stale = freshnessRefusal(art, floor.freshness, () => void noteUpdateGuardRefusal(scheduler, caller, sourceIp, "freshness-replay"), (names) => void noteUpdateDegradations(scheduler, names));
    if (stale) return stale;
    const bytes = await fetchArtefactBytes(art.artefact.url ?? "");
    if (!bytes) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "artefact-download");
      return jsonError("could not download the update artefact from the signed channel (it must be an https url that returns the bundle)", 400);
    }
    // OPT-IN DUAL CONTROL, identical rule to apply (W5): a ramp ships new engine code, so a migration/
    // breaking release takes a second owner when dual control is ON; a routine release does not. Bound to
    // the target version + artefact sha (NEVER the token). The first recording call carries no token.
    stage = "gate";
    const riskClass = normaliseRiskClass(art.artefact.riskClass, art.artefact.requiresMigration === true);
    if (updateNeedsDualControl(riskClass)) {
      const g = await ownerActionGate(
        scheduler,
        caller,
        "update-apply",
        { toVersion: engineTarget, sha384: art.artefact.sha384 ?? "" },
        `Gradually ramp the engine to ${engineTarget} at ${percentage}% (ships new engine code; risk: ${riskClass})`,
      );
      if (g.kind === "error") return g.response;
      if (g.kind === "queued") return ownerActionQueuedResponse(g.id);
    }
    if (!validateDeployToken(token)) {
      // R7: the ramp-START token guard recorded nothing, while the ramp-SETTLE token guard four lines of code away
      // recorded a named row. Same button, same paste, two different packs.
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
      return jsonError('paste the one-shot Cloudflare deploy token (the "Edit Cloudflare Workers" template); it is used once and never stored', 400);
    }
    const driver = makeCfDeployDriver({ token, accountId, scriptName });
    // No hgate is built here (asvs-HI-13): a gate created at ramp/upload time would be stale by the time
    // it could ever be flown, since the FRESH gate that actually settles the ramp is built by POST
    // /update/ramp/settle, a genuinely separate dispatch (see handleRampSettle below).
    const rampInput: RampInput = {
      artefact: bytes,
      expectedSha384: art.artefact.sha384 ?? "",
      meta: { version: engineTarget, ...(art.artefact.requiresMigration ? { requiresMigration: true } : {}), ...(art.artefact.mainModule ? { mainModule: art.artefact.mainModule } : {}), ...(art.artefact.minEngineVersion ? { minEngineVersion: art.artefact.minEngineVersion } : {}) },
      runningVersion: ENGINE_VERSION,
      recommendedVersion: engineTarget,
      percentage,
      ...(allowDowngrade ? { allowDowngrade: true } : {}),
      ...(floor.settledHighWaterMark ? { settledHighWaterMark: floor.settledHighWaterMark } : {}),
    };
    // startGradualRamp (asvs-HI-13) never flies the canary inline -- it cannot, this call is still
    // running the PRE-ramp code -- so it never returns "rolled-back" here; only ramp-pending / refused /
    // no-update. A genuinely separate POST /update/ramp/settle call (below) is what actually gates it.
    stage = "deploy-driver";
    const r = await startGradualRamp(driver, rampInput);
    // On a successful ramp, record a pending verification (carrying `percentage`, which marks it as a
    // ramp's own record so the two settle routes stay mutually exclusive, see POST /update/settle)
    // so the console can offer a verify/promote/rollback control.
    if (r.outcome === "ramp-pending" && r.fromVersion && r.toVersion) {
      // asvs-HI-19: rampVersion above just shifted live traffic to the new version (cf-deploy.ts's ramp
      // is the same deployments-endpoint cutover as promote), the same self-redeploy that resets this DO.
      stage = "persist"; // the SPLIT is live: traffic is already reaching the ramped version
      const pendingWritten = await recordBookkeepingAfterSelfDeploy(env, "/update-pending", { fromVersion: r.fromVersion, toVersion: r.toVersion, recommendedVersion: r.recommendedVersion, percentage: r.percentage ?? percentage, promotedAt: Date.now(), promotedBy: caller.email ?? null, ...(art.sequence !== undefined ? { channelSeq: art.sequence } : {}), ...(art.issuedAt !== undefined ? { channelIssuedAt: art.issuedAt } : {}), ...(art.artefact.sha384 ? { artefactSha384: art.artefact.sha384 } : {}) });
      const audited = await recordAuditAfterSelfDeploy(env, caller, sourceIp, "update-promoted", { kind: "engine-state", field: "engineVersion", detail: `gradual ramp ${r.fromVersion} -> ${r.toVersion} at ${r.percentage ?? percentage}% (${r.recommendedVersion}); awaiting verification (see /update/ramp/settle)` });
      if (!pendingWritten || !audited) {
        return jsonResponse({ ...r, reason: "the gradual ramp went live but could not be fully recorded; check GET /admin/update/status and GET /admin/audit before trying again." });
      }
    } else if (r.outcome === "refused") {
      await recordAudit(scheduler, caller, sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: (r.reason ?? "refused").slice(0, 120) });
    }
    return jsonResponse(r);
  } catch {
    await recordAdminRouteError(scheduler, { route: "ramp-start", stage });
    return jsonError("could not start the gradual ramp right now; nothing was changed.", 400);
  }
}

// handleRampSettle is POST /update/ramp/settle (asvs-HI-13, phase 2): a genuinely SEPARATE request from
// the ramp start (which never flies the canary -- see update-ramp.ts's module header): Cloudflare freshly
// routes THIS dispatch, giving it a real `percentage`% chance of landing on the ramped slice, so a verdict
// computed here can genuinely test the new code. Mutually exclusive with POST /update/settle: that route
// refuses a ramp-shaped (`percentage`-carrying) pending, this route refuses a non-ramp one, so a pending
// record is always settled by exactly one of the two. Owner-gated + rate-limited; the one-shot deploy
// token is required (a rollback is a real deploy) and never stored; fail-safe (never a 500).
export async function handleRampSettle(a: RampRouteArgs): Promise<Response> {
  const { env, scheduler, caller, sourceIp, req } = a;
  const denied = gate(caller, "keys.ceremony");
  if (denied) return denied;
  const limited = await rateLimited(scheduler, caller);
  if (limited) return limited;
  let stage: AdminRouteStage = "do-read";
  try {
    const body = (await req.json()) as { token?: unknown };
    const token = typeof body.token === "string" ? body.token.trim() : "";
    const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
    const rec = (await recResp.json()) as { pending: null | { fromVersion: string; toVersion: string; recommendedVersion: string; percentage?: number; artefactSha384?: string } };
    if (!rec.pending || typeof rec.pending.percentage !== "number") {
      // G275: "we kept trying to settle the ramp overnight." Every settle guard here returned a bare 400 and
      // recorded nothing at all, so the pack showed an armed-or-expired pending record and ZERO evidence that
      // any attempt was ever made -- let alone which guard tripped, or how many times.
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, rec.pending ? "ramp-shaped" : "no-pending");
      await noteUpdateAttempt(scheduler, "settle-refused");
      return jsonError("there is no gradual ramp awaiting verification", 400);
    }
    const pending = rec.pending;
    if (!validateDeployToken(token)) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
      await noteUpdateAttempt(scheduler, "settle-refused");
      return jsonError("paste the one-shot deploy token again so the ramped version can be canary-verified and rolled back if it is unhealthy", 400);
    }
    const accountId = await resolveEngineAccount(env, scheduler);
    if (accountId === null) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "account-unmarked");
      await noteUpdateAttempt(scheduler, "settle-refused");
      return jsonError("the engine's own Cloudflare account is not marked", 400);
    }
    const scriptName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
    const driver = makeCfDeployDriver({ token, accountId, scriptName });
    // SUPERSEDED-PENDING GUARD (mirrors POST /update/settle): only declare superseded on a SINGLE
    // live version that differs from pending.toVersion -- a still-live SPLIT is exactly what a genuine,
    // still-in-flight ramp looks like, so it proceeds (a non-singing verdict collapses it to fromVersion
    // at 100%).
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
    if (liveSingle !== null && liveSingle !== pending.toVersion) {
      await scheduler.fetch(doURL("/update-settled"), { method: "POST", body: JSON.stringify({ outcome: "superseded", recommendedVersion: pending.recommendedVersion, fromVersion: pending.fromVersion, toVersion: pending.toVersion, at: Date.now(), by: caller.email ?? null, reason: `the live version (${liveLabel}) is no longer the one this ramp promoted (${pending.toVersion}); the pending verification was cleared without any change` }) });
      return jsonError(`the engine's live version (${liveLabel}) is no longer the one this ramp promoted (${pending.toVersion}); nothing was changed and the stale pending verification was cleared.`, 409);
    }
    // A FRESH gate, built by THIS request (the whole point: it has a real chance of being routed onto
    // the ramped slice), from the pending's OWN recommendedVersion -- never a possibly-since-advanced
    // live channel read, and never toVersion (a Cloudflare version id, not a semver).
    const hgate = makeHealthGate(env, scheduler, pending.recommendedVersion);
    // settleAfterRamp can DEPLOY (its rollback to 100% prior), so from here "nothing was changed" is unsafe.
    stage = "deploy-driver";
    const s = await settleAfterRamp(driver, hgate, { fromVersion: pending.fromVersion, toVersion: pending.toVersion, recommendedVersion: pending.recommendedVersion });
    if (s.outcome === "inconclusive") {
      // Nothing changed: the pending stays armed so the caller can simply retry (a fresh dispatch has
      // its own chance of landing on the ramped slice). Not an audited state transition.
      //
      // G275, and this is the counter's ONLY producer, deliberately. "The ramp has been pending verification
      // for two days, how many settle attempts were inconclusive?" is the question that separates a ramp that
      // is STUCK (the dispatch never lands on the ramped slice, so no attempt can ever conclude) from a ramp
      // NOBODY HAS TRIED TO SETTLE, and the two demand opposite answers: unpick the split by hand, or press
      // the button. A ramp-shaped pending can be settled ONLY here (POST /update/settle refuses it with the
      // "ramp-shaped" guard), so before this line forty overnight attempts and zero attempts left a
      // byte-identical pack: an armed pending record, and no evidence any attempt was ever made.
      //
      // The state this counter NAMES is "the settle ran and the pending is STILL ARMED", which is true on this
      // branch and on no other: every other outcome below consumes the pending. That is why the plain settle no
      // longer bumps it (it always concludes, so its bump was a routine, concluded settle incrementing the
      // stuck-ramp signal).
      await noteUpdateAttempt(scheduler, "settle-inconclusive");
      return jsonResponse(s);
    }
    // asvs-HI-19: a "rolled-back" outcome above just redeployed fromVersion at 100% (settleAfterRamp's
    // own rollback), the same self-redeploy that resets this DO; "applied" deploys nothing here but
    // shares this call site, so both follow-up writes always use the self-redeploy-safe helpers.
    stage = "persist";
    const settledWritten = await recordBookkeepingAfterSelfDeploy(env, "/update-settled", { outcome: s.outcome, recommendedVersion: s.recommendedVersion, fromVersion: s.fromVersion, toVersion: s.toVersion, ...(s.canaryVerdict ? { canaryVerdict: s.canaryVerdict } : {}), at: Date.now(), by: caller.email ?? null, ...(s.reason ? { reason: s.reason } : {}), ...(pending.artefactSha384 ? { artefactSha384: pending.artefactSha384 } : {}), ...(s.outcome === "applied" && typeof pending.percentage === "number" ? { percentage: pending.percentage } : {}) });
    const audited = await recordAuditAfterSelfDeploy(env, caller, sourceIp, s.outcome === "applied" ? "update-applied" : "update-rolled-back", { kind: "engine-state", field: "engineVersion", detail: `gradual ramp settle: ${s.fromVersion} -> ${s.outcome === "applied" ? s.toVersion : s.fromVersion} (canary ${s.canaryVerdict ?? "unknown"})${pending.artefactSha384 ? `; sha384 ${pending.artefactSha384}` : ""}` });
    if (!settledWritten || !audited) {
      return jsonResponse({ ...s, reason: "the gradual ramp was settled but could not be fully recorded; check GET /admin/update/status and GET /admin/audit before trying again." });
    }
    return jsonResponse(s);
  } catch {
    await recordAdminRouteError(scheduler, { route: "ramp-settle", stage });
    return jsonError("could not settle the gradual ramp right now; the hourly canary will independently verify the ramped version and the console will offer a rollback if it is unhealthy.", 400);
  }
}
