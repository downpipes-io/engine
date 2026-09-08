// router-updates-components.ts -- the CONSOLE-component halves of the multi-component update routes
// (apply / settle-continuation / standalone rollback), split out of router-updates.ts so the route hub
// stays within the module size budget. These helpers are route-shaped (they read env/scheduler/caller and
// write the DO records + audit), but every deploy decision lives in the pure state machines they call
// (update-orchestrate.ts over cf-assets-deploy.ts). Imports the shared router primitives; never imports
// router.ts or router-updates.ts.

import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { makeCfAssetsDeployDriver } from "./cf-assets-deploy.ts";
import { makeCfDeployDriver } from "./cf-deploy.ts";
import { recordUpdateFault } from "./diag-admin.ts";
import { classifyUpdateFailStep } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { jsonError, jsonResponse, ownerActionGate, ownerActionQueuedResponse, recordAudit, recordAuditAfterSelfDeploy, recordBookkeepingAfterSelfDeploy, recordVerifiedEngineAccountAfterSelfDeploy, updateNeedsDualControl, validateDeployToken } from "./router-core.ts";
import { doURL } from "../do-url.ts";
import { noteUpdateGuardRefusal } from "./router-updates-shared.ts";
import { enumerateBoundSources, fetchArtefactBytes } from "./router-sources.ts";
import { type PromoteResult, planAndPromote, type SafeApplyInput } from "./update-apply.ts";
import { DESTINATION_GATE_REASON, destinationConfigured, makeHealthGate } from "./update-gate.ts";
import { applyConsoleComponent, type ConsoleApplyResult, type ConsoleRollbackResult, rollbackConsoleComponent, type UpdateComponent } from "./update-orchestrate.ts";
import { normaliseReadbackMode } from "./update-types.ts";
import { type ComponentArtefact, normaliseRiskClass, type RecommendedArtefact, type RiskClass } from "./updates.ts";

// QueuedConsole is the persisted console intent riding an engine pending (UpdatePending.consoleQueued):
// version + risk only, never a url or hash (the settle re-verifies the signed channel).
export interface QueuedConsole {
  version: string;
  riskClass?: string;
  queuedAt: number;
}

// consoleScriptName resolves the CONSOLE's script name: env.CONSOLE_WORKER_NAME, defaulting to
// "downpipe-console" (the console's wrangler.toml name) -- the twin of the engine's WORKER_NAME guard.
// A Cloudflare token cannot be scoped to a script name, so the deploy-target guarantee is TWO layered
// checks: this resolved name, plus the driver's ownership proof (the target's live bindings must include
// a service binding pointing at THIS engine) -- which is what makes the default safe even on an engine
// whose live vars predate this feature (a channel-upgraded install, a -demo engine).
export function consoleScriptName(env: Env): string {
  return typeof env.CONSOLE_WORKER_NAME === "string" && env.CONSOLE_WORKER_NAME.trim() !== "" ? env.CONSOLE_WORKER_NAME.trim() : "downpipe-console";
}

// engineScriptName resolves THIS engine's own script name (the same expression the engine's own apply
// uses); the assets driver's ownership proof checks the console's ENGINE service binding against it.
export function engineScriptName(env: Env): string {
  return typeof env.WORKER_NAME === "string" && env.WORKER_NAME.trim() !== "" ? env.WORKER_NAME.trim() : "downpipe-engine";
}

// combinedRiskClass folds the per-component normalised risks into the ONE class that drives the apply's
// dual-control gate (W5: one approval gates the whole live apply, so the gate takes the most cautious
// class any requested component declares). Pure.
export function combinedRiskClass(risks: RiskClass[]): RiskClass {
  if (risks.includes("breaking")) return "breaking";
  if (risks.includes("migration")) return "migration";
  return "routine";
}

// resolveConsoleComponent narrows a verified-channel resolution to its console component, or the honest
// refusal reason: the channel carried none, or carried one that cannot be fetch-verified (consoleIssue).
export function resolveConsoleComponent(art: RecommendedArtefact): { ok: true; component: ComponentArtefact } | { ok: false; error: string } {
  if (art.console !== undefined) return { ok: true, component: art.console };
  return { ok: false, error: art.consoleIssue ?? "this release does not carry a console component (the signed channel lists none); nothing was changed" };
}

// RouteActor is the caller/attribution subset these helpers need for records + audit.
export interface RouteActor {
  caller: Parameters<typeof recordAudit>[1];
  sourceIp: string | null;
}

// ConsoleApplyArgs carries one console-component apply's inputs from the route into the executor.
export interface ConsoleApplyArgs {
  env: Env;
  scheduler: DurableObjectStub;
  actor: RouteActor;
  accountId: string;
  token: string; // the one-shot deploy token ("" on a tokenless dry-run preview)
  component: ComponentArtefact; // the verified channel's console entry (version + url + sha384)
  consoleFloor?: string; // floors.console (R8)
  dryRun: boolean;
  // R9: the verified document's freshness claim; an APPLIED console outcome advances the watermark (a
  // console-only apply records no engine pending, so the settle record is its accepting act).
  channelSeq?: number;
  channelIssuedAt?: string;
}

// executeConsoleApply downloads + verifies + applies ONE console component and persists the outcome:
//   applied      -> a component:"console" settled record (advancing floors.console + the R9 watermark)
//                   + an update-applied audit; the record is the console's rollback-target source.
//   rolled-back  -> a component:"console" rolled-back record (fromVersion = the reverted-to known-good,
//                   the SAME convention as the engine records) + an update-rolled-back audit.
//   refused      -> an update-refused audit only (refusals never clobber the last-outcome records,
//                   matching the engine apply's discipline). dry-run persists nothing.
// The persisted record is written BEFORE this returns, and a console deploy never tears down the ENGINE
// isolate (it swaps the console script), so record-after-deploy is race-safe here -- unlike the engine
// settle, which persists FIRST (see router-updates.ts).
export async function executeConsoleApply(args: ConsoleApplyArgs): Promise<ConsoleApplyResult> {
  const { env, scheduler, actor, component } = args;
  const bytes = await fetchArtefactBytes(component.url ?? "");
  if (!bytes) {
    const refusal: ConsoleApplyResult = {
      component: "console",
      outcome: "refused",
      recommendedVersion: component.version,
      steps: [{ step: "download-console-bundle", ok: false, detail: component.url ?? "(no url)" }],
      reason: "could not download the console component from the signed channel (it must be an https url that returns the bundle); nothing was changed",
    };
    if (!args.dryRun) {
      // R7: the CONSOLE component's own download guard. It audited and stopped there, and the pack's configEvents
      // excerpt strips the audit detail, so "the console update never shows up" reached support as an unclassed
      // denial. Same closed class as the engine leg's download guard: the component is not what is being asked.
      await noteUpdateGuardRefusal(scheduler, actor.caller, actor.sourceIp, "artefact-download");
    }
    return refusal;
  }
  const driver = makeCfAssetsDeployDriver({ token: args.token, accountId: args.accountId, scriptName: consoleScriptName(env), engineScriptName: engineScriptName(env) });
  const r = await applyConsoleComponent(driver, {
    bundleBytes: bytes,
    component,
    runningEngineVersion: ENGINE_VERSION,
    ...(args.consoleFloor !== undefined ? { consoleFloor: args.consoleFloor } : {}),
    dryRun: args.dryRun,
  });
  if (args.dryRun) return r;
  // G219: applied-unconfirmed and rollback-failed MUST be recorded here. Without them this branch simply does
  // not fire, so the console's two worst states would persist NO lifecycle record at all -- the pack would
  // carry whatever the PREVIOUS apply left behind, which is the same class of lie the enum widening exists to
  // end, arrived at a different way.
  const applyLanded = r.outcome === "applied" || r.outcome === "applied-unconfirmed";
  if (applyLanded || r.outcome === "rolled-back" || r.outcome === "rollback-failed") {
    // G100/G331: CHECKED. This write is what the console reads to offer a rollback; when it is dropped the
    // console reports "no recorded prior version" IMMEDIATELY AFTER a successful update, and nothing anywhere
    // marks the loss. recordDiagWrite counts it in droppedWrites (and never fails the already-completed deploy).
    await recordDiagWrite(scheduler, "update-settled", () => scheduler.fetch(doURL("/update-settled"), {
      method: "POST",
      body: JSON.stringify({
        outcome: r.outcome, // the HONEST outcome, verbatim: never coerced back into applied / rolled-back
        component: "console",
        recommendedVersion: component.version,
        // CONVENTION (shared with the engine records): on rolled-back, fromVersion = the version reverted
        // TO (the known-good, now live) and toVersion = the version left; on applied, fromVersion = the
        // prior (the recorded rollback target) and toVersion = the now-live new version. Both outcomes
        // always carry these fields (and a reason); JSON.stringify drops any undefined defensively.
        fromVersion: r.fromVersion,
        toVersion: r.toVersion,
        at: Date.now(),
        by: actor.caller.email ?? null,
        reason: r.reason,
        ...(applyLanded && args.channelSeq !== undefined ? { channelSeq: args.channelSeq } : {}),
        ...(applyLanded && args.channelIssuedAt !== undefined ? { channelIssuedAt: args.channelIssuedAt } : {}),
        // 0.1.5 UX design §6: persist the APPLIED console's own minEngineVersion floor (from the verified
        // channel entry, never a client value) so the engine's standalone rollback can later decide whether
        // it may revert alone or must pair the console with it. Applied-only (a rolled-back console record
        // carries no floor -- see executeConsoleRollback -- read as "no requirement" by the floor check).
        ...(applyLanded && component.minEngineVersion !== undefined ? { minEngineVersion: component.minEngineVersion } : {}),
        // DP-0: the verified channel entry's own digest, on both outcomes (either way this record is a
        // statement about THAT bundle; the digest is what identifies it durably).
        ...(component.sha384 ? { artefactSha384: component.sha384 } : {}),
      }),
    }));
    // The AUDIT outcome tells the truth too: a promote that could not be confirmed, and a rollback that
    // FAILED, are not "success". AuditOutcome already carries "failed"; using it here means the audit trail
    // and the lifecycle record agree, instead of the trail asserting a success the record denies.
    await recordAudit(scheduler, actor.caller, actor.sourceIp, applyLanded ? "update-applied" : "update-rolled-back", r.outcome === "applied" || r.outcome === "rolled-back" ? "success" : "failed", {
      kind: "engine-state",
      field: "engineVersion",
      detail: `console ${r.fromVersion ?? "?"} -> ${applyLanded ? (r.toVersion ?? "?") : (r.fromVersion ?? "?")} (${component.version})${r.outcome === "applied-unconfirmed" ? "; the live version could not be confirmed" : r.outcome === "rollback-failed" ? "; THE ROLLBACK FAILED and the console may still be serving the unexpected version" : ""}`,
    });
  } else if (r.outcome === "refused") {
    await recordAudit(scheduler, actor.caller, actor.sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: `console: ${(r.reason ?? "refused").slice(0, 100)}` });
  }
  return r;
}

// recordConsoleQueueResolution closes a QUEUED console intent that could not proceed to a deploy (the
// engine settled applied, but the channel re-resolve failed or the release moved underneath the queue).
// Unlike a plain apply refusal, the queue was a PERSISTED intent, so its closure must be visible: a
// component:"console" refused record lands in the history + lastConsole, and the refusal is audited.
export async function recordConsoleQueueResolution(scheduler: DurableObjectStub, actor: RouteActor, queuedVersion: string, reason: string): Promise<ConsoleApplyResult> {
  // G100/G331: CHECKED -- a QUEUED intent whose closure record is dropped stays queued forever in the pack.
  await recordDiagWrite(scheduler, "update-settled", () => scheduler.fetch(doURL("/update-settled"), {
    method: "POST",
    body: JSON.stringify({ outcome: "refused", component: "console", recommendedVersion: queuedVersion, at: Date.now(), by: actor.caller.email ?? null, reason }),
  }));
  await recordAudit(scheduler, actor.caller, actor.sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: `console: ${reason.slice(0, 100)}` });
  return { component: "console", outcome: "refused", recommendedVersion: queuedVersion, steps: [{ step: "console-queue", ok: false, detail: reason }], reason };
}

// consoleRollbackTargetFrom resolves the console's recorded known-good version from the persisted
// lifecycle, mirroring resolveRollbackTarget's rule for the engine: an applied console record's
// fromVersion is the prior known-good; a rolled-back record's fromVersion is the version reverted TO
// (already live; a redundant rollback no-ops against it); any other outcome (refused/aborted) changed
// nothing and is no target. Pure.
export function consoleRollbackTargetFrom(rec: { lastConsole?: { outcome?: string; fromVersion?: string } | null }): string {
  const lastConsole = rec.lastConsole;
  if (!lastConsole) return "";
  // G219: applied-unconfirmed and rollback-failed keep the SAME fromVersion convention (the known-good prior),
  // and both are states in which a rollback is needed MORE, not less -- an unconfirmed promote may be serving
  // anything, and a failed rollback is definitely still serving the bad build. Excluding them would refuse the
  // operator a target in exactly the states the target exists for.
  if (lastConsole.outcome === "applied" || lastConsole.outcome === "rolled-back" || lastConsole.outcome === "applied-unconfirmed" || lastConsole.outcome === "rollback-failed") {
    return typeof lastConsole.fromVersion === "string" ? lastConsole.fromVersion : "";
  }
  return "";
}

// executeConsoleRollback runs the standalone console rollback (the console arm of POST /update/rollback):
// resolve the recorded known-good, deploy it at 100%, confirm, and persist + audit the outcome. The same
// safe-recovery-direction rule as the engine rollback: never dual-control-gated.
export async function executeConsoleRollback(args: { env: Env; scheduler: DurableObjectStub; actor: RouteActor; accountId: string; token: string }): Promise<ConsoleRollbackResult> {
  const { env, scheduler, actor } = args;
  const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
  const rec = (await recResp.json()) as { lastConsole?: { outcome?: string; fromVersion?: string } | null };
  const target = consoleRollbackTargetFrom(rec).trim();
  const driver = makeCfAssetsDeployDriver({ token: args.token, accountId: args.accountId, scriptName: consoleScriptName(env), engineScriptName: engineScriptName(env) });
  const r = await rollbackConsoleComponent(driver, { toVersion: target });
  if (r.outcome === "reverted" || r.outcome === "reverted-unverified") {
    // Same record convention as the engine's standalone rollback: fromVersion = the version reverted TO
    // (the known-good, what a redundant next rollback no-ops against), toVersion = the version left.
    // G100/G331: CHECKED -- a rollback whose record is dropped leaves the fleet on a version nothing recorded.
    await recordDiagWrite(scheduler, "update-settled", () => scheduler.fetch(doURL("/update-settled"), {
      method: "POST",
      body: JSON.stringify({ outcome: "rolled-back", component: "console", recommendedVersion: target, fromVersion: target, toVersion: r.fromVersion, at: Date.now(), by: actor.caller.email ?? null, reason: r.reason }),
    }));
    await recordAudit(scheduler, actor.caller, actor.sourceIp, "update-rolled-back", "success", { kind: "engine-state", field: "engineVersion", detail: `console standalone rollback ${r.fromVersion ?? "?"} -> ${target}` });
  } else if (r.outcome === "failed") {
    await recordAudit(scheduler, actor.caller, actor.sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: `console standalone rollback failed: ${(r.reason ?? "").slice(0, 100)}` });
  }
  return r;
}

// ComponentApplyArgs carries the validated apply-route context into handleComponentApply. The route has
// already: parsed + validated `components`, resolved the account, verified the channel (art), read the
// floors and passed the R9 freshness gate. Everything else (dual control, token, deploys, records) runs
// here so the component-aware flow is one readable sequence.
export interface ComponentApplyArgs {
  env: Env;
  scheduler: DurableObjectStub;
  caller: Parameters<typeof recordAudit>[1];
  sourceIp: string | null;
  components: UpdateComponent[];
  art: RecommendedArtefact;
  floor: { settledHighWaterMark?: string; consoleFloor?: string };
  dryRun: boolean;
  allowDowngrade: boolean;
  token: string;
  accountId: string;
  engineScriptName: string;
}

// handleComponentApply is the COMPONENT-AWARE apply flow (POST /update/apply with an explicit
// `components` list). Sequencing contract: when BOTH components ship, the engine promotes first and the
// console is QUEUED on the pending record -- it applies only after the engine SETTLES as applied (the
// settle route runs the continuation). When the engine is already current (or was not requested), the
// console applies INLINE (the "engine first and settled" precondition is trivially met by the running,
// already-settled engine). Response contract: a SINGLE requested component keeps today's top-level result
// shape (describing that component); more than one adds the additive componentResults array.
export async function handleComponentApply(a: ComponentApplyArgs): Promise<Response> {
  const { env, scheduler, caller, sourceIp } = a;
  const actor: RouteActor = { caller, sourceIp };
  const wantsEngine = a.components.includes("engine");
  const wantsConsole = a.components.includes("console");
  // Resolve the console component FIRST when requested, so a both-apply against a console-less (or
  // unverifiable-console) release refuses BEFORE any engine action -- never a half-run into nothing.
  let consoleComp: ComponentArtefact | null = null;
  if (wantsConsole) {
    const rc = resolveConsoleComponent(a.art);
    if (!rc.ok) {
      await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "artefact-resolve");
      return jsonError(`no applicable update: ${rc.error}`, 400);
    }
    consoleComp = rc.component;
  }
  const engineTarget = a.art.artefact.version;
  const engineIsCurrent = engineTarget === ENGINE_VERSION;
  const engineRuns = wantsEngine && !engineIsCurrent;

  // DESTINATION GATE (design UPDATE-UX-015 §4): a LIVE apply with NO destination configured refuses before
  // any deploy, whatever the component set (see router-updates.ts's legacy-path twin for the full
  // rationale). Checked before dual control/the token, unconditionally on !dryRun (mirroring the token
  // check just below, which is itself unconditional on the component set -- a no-op components-aware apply
  // already requires a token today; this gate keeps that same discipline rather than special-casing a no-op).
  if (!a.dryRun && !(await destinationConfigured(env, scheduler))) {
    await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "no-destination");
    return jsonError(DESTINATION_GATE_REASON, 400);
  }

  // OPT-IN DUAL CONTROL (W5): ONE approval gates the WHOLE live apply, whatever the component set. The
  // gate class is the most cautious any acting component declares; the bind is the leading component's
  // target version + sha (the engine's when it moves, else the console's) -- decision-relevant facts,
  // never the token. A dry-run changes nothing and is never gated.
  const engineRisk = normaliseRiskClass(a.art.artefact.riskClass, a.art.artefact.requiresMigration === true);
  const consoleRisk = consoleComp !== null ? normaliseRiskClass(consoleComp.riskClass, false) : null;
  const acting: RiskClass[] = [...(engineRuns ? [engineRisk] : []), ...(consoleRisk !== null ? [consoleRisk] : [])];
  const combined = combinedRiskClass(acting.length > 0 ? acting : ["routine"]);
  if (!a.dryRun && acting.length > 0 && updateNeedsDualControl(combined)) {
    const description = engineRuns
      ? consoleComp !== null
        ? `Promote the engine to ${engineTarget} and then the console to ${consoleComp.version} (ships new engine + console code; risk: ${combined})`
        : `Promote the engine to ${engineTarget} (ships new engine code; risk: ${combined})`
      : `Apply the console component ${consoleComp!.version} (ships new console code; risk: ${combined})`;
    const g = await ownerActionGate(
      scheduler,
      caller,
      "update-apply",
      engineRuns ? { toVersion: engineTarget, sha384: a.art.artefact.sha384 ?? "" } : { toVersion: consoleComp!.version, sha384: consoleComp!.sha384 ?? "" },
      description,
    );
    if (g.kind === "error") return g.response;
    if (g.kind === "queued") return ownerActionQueuedResponse(g.id);
  }
  if (!a.dryRun && !validateDeployToken(a.token)) {
    // R7: the multi-component apply leg the console drives for a console component. It recorded NOTHING AT ALL --
    // no counter and not even the audit event -- so a refused "Update now" on a console-bearing release was
    // invisible in the pack, exactly as the legacy engine-only leg's twin was.
    await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "deploy-token");
    return jsonError('paste the one-shot Cloudflare deploy token (the "Edit Cloudflare Workers" template); it is used once and never stored', 400);
  }

  // ---- ENGINE first (when requested). The flow mirrors the legacy engine-only apply exactly; the one
  // addition is the consoleQueued intent riding the pending record when the console follows. ----
  let engineResult: PromoteResult | null = null;
  if (wantsEngine) {
    if (engineIsCurrent) {
      engineResult = { phase: "promote", outcome: "no-update", recommendedVersion: engineTarget, steps: [] };
    } else {
      const bytes = await fetchArtefactBytes(a.art.artefact.url ?? "");
      if (!bytes) {
        await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "artefact-download");
        return jsonError("could not download the update artefact from the signed channel (it must be an https url that returns the bundle)", 400);
      }
      const driver = makeCfDeployDriver({ token: a.token, accountId: a.accountId, scriptName: a.engineScriptName });
      const hgate = makeHealthGate(env, scheduler, engineTarget);
      const input: SafeApplyInput = {
        artefact: bytes,
        expectedSha384: a.art.artefact.sha384 ?? "",
        meta: { version: engineTarget, ...(a.art.artefact.requiresMigration ? { requiresMigration: true } : {}), ...(a.art.artefact.mainModule ? { mainModule: a.art.artefact.mainModule } : {}), ...(a.art.artefact.minEngineVersion ? { minEngineVersion: a.art.artefact.minEngineVersion } : {}) },
        runningVersion: ENGINE_VERSION,
        recommendedVersion: engineTarget,
        dryRun: a.dryRun,
        ...(a.allowDowngrade ? { allowDowngrade: true } : {}),
        ...(a.floor.settledHighWaterMark !== undefined ? { settledHighWaterMark: a.floor.settledHighWaterMark } : {}),
        readbackMode: normaliseReadbackMode(env.UPDATE_READBACK_MODE),
      };
      const preBound = enumerateBoundSources(env);
      const sourceBindingsBefore = [...preBound.kv, ...preBound.r2, ...preBound.d1, ...preBound.secrets].sort();
      const p = await planAndPromote(driver, hgate, input);
      if (p.outcome === "promoted" && p.fromVersion && p.toVersion) {
        // asvs-HI-19: the promote above JUST redeployed the engine (a live version cutover), the same
        // self-redeploy that momentarily resets THIS Durable Object (see router-audit.ts). This leg reaches
        // it through the SAME planAndPromote against the SAME makeCfDeployDriver as the legacy engine-only
        // apply, so the reset is not a lesser risk here; it is the identical one.
        //
        // recordDiagWrite CATCHES, so the pending record was simply lost -- and a
        // dropped pending record makes an IN-FLIGHT update invisible to the canary gate and to the pack,
        // which then cannot explain why no rollback target exists. The bare recordAudit does NOT catch, so
        // the reset threw out of this route and into the apply route's outer catch, which answers "could
        // not start the update right now; nothing was changed" WHILE THE ENGINE IS LIVE ON THE NEW VERSION.
        // That sentence being false is the exact failure the legacy leg's own comment engineered against.
        const pendingWritten = await recordBookkeepingAfterSelfDeploy(env, "/update-pending", {
          fromVersion: p.fromVersion,
          toVersion: p.toVersion,
          recommendedVersion: p.recommendedVersion,
          ...(p.canaryBaseline ? { canaryBaseline: p.canaryBaseline } : {}),
          riskClass: engineRisk,
          promotedAt: Date.now(),
          promotedBy: caller.email ?? null,
          sourceBindingsBefore,
          ...(a.art.sequence !== undefined ? { channelSeq: a.art.sequence } : {}),
          ...(a.art.issuedAt !== undefined ? { channelIssuedAt: a.art.issuedAt } : {}),
          ...(consoleComp !== null ? { consoleQueued: { version: consoleComp.version, riskClass: consoleRisk, queuedAt: Date.now() } } : {}),
          ...(a.art.artefact.sha384 ? { artefactSha384: a.art.artefact.sha384 } : {}),
          ...(p.readback !== undefined ? { readback: p.readback } : {}),
        });
        const audited = await recordAuditAfterSelfDeploy(env, caller, sourceIp, "update-promoted", { kind: "engine-state", field: "engineVersion", detail: `${p.fromVersion} -> ${p.toVersion} (${p.recommendedVersion}); pending canary verification${consoleComp !== null ? `; console ${consoleComp.version} queued behind the settle` : ""}${a.art.artefact.sha384 ? `; sha384 ${a.art.artefact.sha384}` : ""}` });
        // LICENCE-BINDING-ON-CLAIM follow-up: see the legacy apply leg's identical comment in
        // router-updates.ts. Best-effort, never checked.
        await recordVerifiedEngineAccountAfterSelfDeploy(env, a.accountId, "update-apply");
        if (!pendingWritten || !audited) {
          // G101, the legacy leg's own honesty branch: the engine is LIVE ON THE NEW VERSION and the record
          // of it did not persist, so /update/status knows nothing and both settle routes refuse with "no
          // update awaiting verification". A durable marker in the update-fault ring means a pack taken
          // LATER still proves the live-but-unrecorded state, and says WHICH half was lost. The reason rides
          // the promote result rather than returning early, because the console phase below still has to
          // resolve (this leg's response is composed from engineResult, not returned here).
          if (!pendingWritten) await recordUpdateFault(scheduler, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "pending" });
          if (!audited) await recordUpdateFault(scheduler, { component: "engine", step: "bookkeeping", cause: "record-write-failed", recordPhase: "audit" });
          p.reason = "the update went live but could not be fully recorded; check GET /admin/update/status and GET /admin/audit before trying again.";
        }
      } else if (p.outcome === "refused") {
        // R7 (the sibling of router-updates.ts's legacy promote arm): a promote REFUSED on this leg used to file
        // an audit row and nothing else -- no update-fault, and no high-water guard class. So the SAME downgrade
        // the console refuses on the engine-only apply, driven through the components-aware apply the console
        // uses whenever a release carries a console component, reached the pack as an unclassed denial.
        const cls = classifyUpdateFailStep(p.reason ?? "");
        await recordUpdateFault(scheduler, { component: "engine", step: cls.step, cause: cls.cause });
        await recordAudit(scheduler, caller, sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: (p.reason ?? "refused").slice(0, 120) });
        // Read STRUCTURALLY off the engine's own step log (the guard writes a failing anti-rollback-guard step),
        // never off the refusal sentence. Only the closed guard class is counted.
        if (p.steps.some((s) => s.step === "anti-rollback-guard" && !s.ok)) await noteUpdateGuardRefusal(scheduler, caller, sourceIp, "high-water");
      }
      engineResult = p;
    }
  }

  // ---- CONSOLE. Inline ONLY when no engine promote from this request is pending verification:
  // console-only requests, engine already current, and every dry-run (both plans are useful together). ----
  let consoleResult: ConsoleApplyResult | Record<string, unknown> | null = null;
  if (consoleComp !== null) {
    const enginePromoted = engineResult?.outcome === "promoted";
    const engineRefused = engineResult?.outcome === "refused";
    if (engineRefused) {
      // Honest partial state: the engine refused BEFORE any change, so nothing proceeds.
      consoleResult = { component: "console", outcome: "refused", recommendedVersion: consoleComp.version, steps: [], reason: "the release was not applied; the engine refused and the console is unchanged" };
    } else if (enginePromoted && !a.dryRun) {
      consoleResult = { component: "console", outcome: "queued", recommendedVersion: consoleComp.version, steps: [], reason: "the console component applies after the engine settles (canary keep); complete the settle to continue" };
    } else {
      consoleResult = await executeConsoleApply({
        env,
        scheduler,
        actor,
        accountId: a.accountId,
        token: a.token,
        component: consoleComp,
        ...(a.floor.consoleFloor !== undefined ? { consoleFloor: a.floor.consoleFloor } : {}),
        dryRun: a.dryRun,
        ...(a.art.sequence !== undefined ? { channelSeq: a.art.sequence } : {}),
        ...(a.art.issuedAt !== undefined ? { channelIssuedAt: a.art.issuedAt } : {}),
      });
    }
  }

  // ---- response shapes (contract): one component -> today's top-level shape for THAT component; more
  // than one -> the engine's top-level shape + the additive componentResults array. ----
  if (!wantsEngine) return jsonResponse(consoleResult);
  if (consoleResult === null) return jsonResponse(engineResult);
  return jsonResponse({ ...engineResult, componentResults: [{ component: "engine", ...engineResult }, consoleResult] });
}
