// router-pipelines.ts -- the downpipe-config mutations, run-now trigger, integrity-canary control and the
// drill rehearsal. The per-route capability gate runs inline per route.

import type { DownpipeConfig, DownpipeState } from "../sched/scheduler-do.ts";
import type { AuditTarget } from "./audit.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { adminRefusalReasonForStatus, recordAdminRefusal } from "./diag-admin.ts";
import { runDrill } from "./drill.ts";
import { recordDrillOutcome } from "./restore-faults.ts";
import { callerHeaders, gate, rateLimited, recordAudit, stampRestoreTested } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { withRunDestFallback } from "./router-sources.ts";

// fireInBackground: see router-identity.ts's identical helper.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// handlePipelines dispatches the downpipe / trigger / canary / drill group. Returns the route's Response,
// or null when no case here matched (the hub falls to the next spoke).
export async function handlePipelines(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, sourceIp, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- mutations: Operator+ (engine role) ----------------------------------------------
    case "POST /downpipes": {
      // Read the body ONCE: it is needed both to forward to the DO and to build the redaction-safe
      // audit target (the downpipe id + name, both the customer's own config, never a secret).
      const body = (await req.json()) as Partial<DownpipeConfig>;
      const target: AuditTarget = { kind: "downpipe", id: String(body.id ?? ""), ...(body.name ? { name: String(body.name) } : {}) };
      // Section 8: the upsert gates on downpipe.write. operator/approver/owner hold it; restore-operator
      // and access-admin do not (recovery/people roles do not edit downpipes). Same allow/deny as the
      // prior "operator" rank gate for the four existing roles. CHANGING restoreTestCadenceSeconds carries
      // a SECOND, narrower gate (scheduledtest.config), re-checked in the DO's addDownpipe against its own
      // resolved authority because only the DO holds the prior cadence to detect a change: for the six
      // built-ins that is invisible (downpipe.write implies scheduledtest.config), and it bites only a
      // composable custom role that holds downpipe.write WITHOUT scheduledtest.config (the DO returns a
      // 403, forwarded verbatim and recorded as failed below).
      const denied = gate(caller, "downpipe.write");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "downpipe-create", "denied", target);
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const resp = await scheduler.fetch(doURL("/downpipes"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      // The DO returns 200 on a valid upsert, 400 { error } on a validation failure, or 403 { error:
      // "forbidden" } when a custom role lacking scheduledtest.config tried to CHANGE the restore-test
      // cadence; record success or failed accordingly (the outcome a reviewer cares about), never the body.
      // G245: the audit row says "failed" and never why. The closed reason class rides alongside it, so a
      // customer who "could not get the downpipe to save all week" leaves a trail with a cause in it.
      // ONLY a genuine REFUSAL (>= 400) is recorded: a 202 is a dual-control proposal that was QUEUED, which is
      // a success, and recording it would both lie and write DO state on a path that must leave none.
      // The reason comes from adminRefusalReasonForStatus rather than this site's own three-way ternary. That
      // ternary read EVERY non-403, non-5xx refusal as "validation", so the precondition refusal the upsert
      // now answers (409, a colliding write) would have been filed in the support pack as a validation
      // failure, i.e. as the customer's typo. The shared function already owns the 409/412 -> "conflict"
      // mapping the admin hub uses, so this site now agrees with the hub instead of drifting from it.
      if (resp.status >= 400) fireInBackground(runtime, recordAdminRefusal(scheduler, "downpipe-write", adminRefusalReasonForStatus(resp.status)));
      await recordAudit(scheduler, caller, sourceIp, "downpipe-create", resp.status === 200 ? "success" : "failed", target);
      return resp;
    }
    case "POST /downpipes/bulk": {
      // Many-at-once create/upsert (the console's multi-source wizard + bulk protect): same downpipe.write
      // gate and rate-limit class as the single upsert, one DO round trip for the whole batch. The DO runs
      // each item through the SAME gated single-upsert path (validation + change control), continue-on-error,
      // capped per request (an oversized batch is refused whole with the cap echoed as maxBatch), and appends
      // the per-item downpipe-create audit rows itself (it holds each item's outcome); the router records
      // only the DENIED case here so a refused bulk attempt is not silently absent from the trail.
      const denied = gate(caller, "downpipe.write");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "downpipe-create", "denied", { kind: "downpipe", id: "" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/downpipes/bulk"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /downpipes/delete": {
      // Delete is Operator (not Approver): it stops scheduling and drops the history ring but
      // does NOT delete archives, so it is reversible-by-recreate and lower blast radius than a
      // restore apply.
      const body = (await req.json()) as { id?: string };
      const target: AuditTarget = { kind: "downpipe", id: String(body.id ?? "") };
      // Section 8: delete gates on downpipe.delete (operator/approver/owner). Same allow/deny as the
      // prior "operator" rank gate for the four existing roles.
      const denied = gate(caller, "downpipe.delete");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "downpipe-delete", "denied", target);
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const resp = await scheduler.fetch(doURL("/delete"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      await recordAudit(scheduler, caller, sourceIp, "downpipe-delete", resp.status === 200 ? "success" : "failed", target);
      return resp;
    }
    // This comment named its own floor by naming its sibling: "the same read class as GET /downpipes
    // itself" is true once GET /downpipes is itself gated on downpipe.read, so the sentence resolves to a
    // capability and this route takes it. The forward carries no callerHeaders, so the DO arm
    // (roster-hygiene) has no principal to check and the router is the only possible home. downpipe.read is
    // a viewer-floor capability, so this refuses nobody: it makes "every authenticated role reads the list,
    // so it reads this too" checkable against the route it points at instead of against the role table
    // nobody re-reads.
    case "GET /downpipes/roster-hygiene": {
      // Roster structural integrity (ghost rows the delete route cannot reach + never-ran entries):
      // the customer's own downpipe ids and storage keys only, redaction-safe, the same read class as
      // GET /downpipes itself (every authenticated role reads the list, so it reads this too). The
      // console's map drawer uses it to explain an undeletable "Unknown" edge; the support pack
      // projects the same report.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/roster-hygiene"), { method: "GET" });
    }
    case "POST /downpipes/reconcile-roster": {
      // HEAL the roster's structural ghosts (key-id mismatch / malformed rows). Like POST
      // /sources/reattach-missing, this is a heal-to-invariant repair, not a configuration change: it
      // restores the "storage key = config.id" invariant every consumer already assumes and touches
      // nothing an operator approved, so it is owner-grade (keys.ceremony) + rate-limited rather than
      // dual-control gated. Never-ran downpipes are valid configs and are NOT touched (deleting one is
      // the normal gated delete's job). The audit row mirrors the sources-attached heal precedent.
      const denied = gate(caller, "keys.ceremony");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "downpipe-roster-reconcile", "denied", { kind: "access-policy" });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const resp = await scheduler.fetch(doURL("/roster-reconcile"), { method: "POST", body: "{}", headers: callerHeaders(caller) });
      await recordAudit(scheduler, caller, sourceIp, "downpipe-roster-reconcile", resp.status === 200 ? "success" : "failed", { kind: "access-policy" });
      return resp;
    }
    case "POST /trigger": {
      // Section 8: run-now gates on run.trigger (operator/approver/owner).
      const denied = gate(caller, "run.trigger");
      if (denied) {
        // G245: "Run now does nothing". For a caller whose role does not hold run.trigger that is precisely
        // what it does -- and nothing, anywhere, said so.
        fireInBackground(runtime, recordAdminRefusal(scheduler, "run-trigger", "forbidden"));
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "run-trigger", "rate-limited"));
        return limited;
      }
      // Allocate the run in the DO (which sets the in-flight lease and appends the in-flight history
      // row), then drive the actual seal in this invocation's background so run-now genuinely writes
      // bytes rather than stranding the downpipe in flight and reporting a fake success (XC-B1/B2). The
      // DO returns the config so the seal can build the source adapter without a second round trip.
      const tr = await scheduler.fetch(doURL("/trigger"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
      if (!tr.ok) {
        // G245: a run that was never ALLOCATED produces no run row at all, so "Run now fails every time" had no
        // engine artefact whatsoever -- the pack simply showed a downpipe that had not run.
        fireInBackground(runtime, recordAdminRefusal(scheduler, "run-trigger", tr.status >= 500 ? "do-fault" : "validation"));
        return tr;
      }
      const trig = (await tr.json()) as { runId: string; index: number; prevRunId: string | null; config: DownpipeConfig } | { skipped: string };
      if ("skipped" in trig) {
        return new Response(JSON.stringify(trig), { headers: { "content-type": "application/json" } });
      }
      // Record WHO manually triggered this run into the tamper-evident chain. A run-now is a gated,
      // state-mutating privileged action (it allocates a run + sets the in-flight lease), so it carries an
      // audit row like every other mutation; the run itself is in the history ring, but the actor that
      // initiated an off-schedule run would otherwise be lost. Recorded once the allocation succeeded (a
      // skipped no-op above writes nothing). The target is the run kind: runId only, never config or a value.
      await recordAudit(scheduler, caller, sourceIp, "run-trigger", "success", { kind: "run", runId: trig.runId });
      if (runtime?.sealNow) {
        const state: DownpipeState = { config: trig.config, nextRunAt: 0, lastRunId: trig.prevRunId, inFlight: true };
        runtime.sealNow(state, { runId: trig.runId, index: trig.index, prevRunId: trig.prevRunId });
        return new Response(JSON.stringify({ runId: trig.runId, index: trig.index, running: true }), { headers: { "content-type": "application/json" } });
      }
      // No run-now seal capability was injected (a direct handleAdmin call without the fetch runtime,
      // e.g. a test): return the allocation. The live fetch path always injects sealNow, so a real
      // run-now always seals; this branch never strands a pipe on the live path.
      return new Response(JSON.stringify({ runId: trig.runId, index: trig.index }), { headers: { "content-type": "application/json" } });
    }
    case "GET /canary":
      // The canary view is read state (liveness, the last flight's aspects, the history ring), not a
      // write and not a secret. It gates on NOTHING: no capability in this engine names canary state, and
      // its write siblings gate run.trigger and owner, both above the viewer floor, so matching one would
      // refuse readers rather than pin the floor. Authentication is therefore the whole of what stands in
      // front of it, and it is recorded as such in test/validate-admin-route-manifest.ts (class
      // authenticated-only) rather than left as a sentence claiming a check nobody runs.
      return scheduler.fetch(doURL("/canary"), { method: "GET" });
    case "POST /canary/config": {
      // Owner-only, like the config-approval toggle and the destination pointer: changing whether the
      // integrity canary flies, where it flies, or how often is a governance decision. This authority is
      // owner-exclusive by design and is intentionally NOT mapped to a custom-role capability, so the bare
      // owner-role test is used rather than gate(caller, cap). The DO records the SUCCESS case at its commit
      // point (canary-config audit) and validates a repoint against the real destination set; the router
      // records the DENIED case here so a refused attempt is not silently dropped from the trail.
      if (caller.role !== "owner") {
        await recordAudit(scheduler, caller, sourceIp, "canary-config", "denied", { kind: "access-policy" });
        return new Response(JSON.stringify({ error: "forbidden", required: "owner", have: caller.role }), { status: 403, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/canary/config"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /canary/run": {
      // Fly the canary now (operator+): the DO arms the bird due and reclaims a stale lease, then the
      // injected runtime seals/reads/restores it in the background so the operator sees a fresh flight
      // without waiting for the next cron tick. The DO refuses (400) on a disabled bird.
      const denied = gate(caller, "run.trigger");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const armed = await scheduler.fetch(doURL("/canary/run-now"), { method: "POST", headers: callerHeaders(caller) });
      if (!armed.ok) return armed;
      runtime?.canaryNow?.();
      return new Response(JSON.stringify({ ok: true, flying: Boolean(runtime?.canaryNow) }), { headers: { "content-type": "application/json" } });
    }
    case "POST /drill": {
      // Section 8: drill gates on drill.run (operator/restore-operator/approver/owner). restore-operator
      // holds drill.run (a recovery rehearsal is part of the recovery role) even though it cannot edit
      // downpipes.
      const denied = gate(caller, "drill.run");
      if (denied) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "drill", "forbidden"));
        return denied;
      }
      const { runId, destinationId } = (await req.json()) as { runId?: string; destinationId?: string };
      if (!runId) {
        fireInBackground(runtime, recordAdminRefusal(scheduler, "drill", "validation"));
        return new Response(JSON.stringify({ error: "runId required" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const result = await withRunDestFallback(scheduler, runId, destinationId, (cfg) => runDrill(env, runId, cfg), loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      // G070: a FAILED drill left only a coarse reason on the downpipe's restore-test stamp. Project it into
      // the bounded restoreFaults ring so the pack names the phase and the closed failure class (an integrity
      // fault on the archive vs an availability fault on the destination -- the two the operator must never
      // confuse). A PASS records nothing.
      // G029: the DRILL projector (not the generic one): it carries the blast radius (how many records failed),
      // the first failing index, the missing ARCHIVE OBJECT key and WHICH engine binding was absent -- the four
      // facts that tell a corrupt archive from an expired bucket object from a deploy that wiped SIGNER_PRIVATE.
      await recordDrillOutcome(scheduler, result);
      // A manual drill is the same operation the scheduled restore test runs, so stamp the "Last restore
      // test" recency for this downpipe on a drill that actually ran (the run was opened, so downpipeId is
      // present), with its outcome + measured cost. Best-effort: a stamp hiccup never fails the drill.
      // A DRILL THAT VERIFIED NOTHING MOVES THE RECENCY IN NEITHER DIRECTION. nothingToVerify means the run
      // opened and its chain verified but it holds no records, so this rehearsal is not evidence that the
      // downpipe is recoverable and not evidence that it is not. Stamping ok:true would write the false pass
      // this repair exists to remove; stamping ok:false would be worse, because stampRestoreTested never sets
      // a deferral kind and posture-checks.ts reads a not-ok WITHOUT one as real failure evidence that
      // outranks an older genuine proof. So leave the recency alone and let it age: "not tested recently" is
      // true, and it is the only sentence here that is.
      if (result.downpipeId && result.nothingToVerify !== true) {
        await stampRestoreTested(scheduler, caller, result.downpipeId, result.ok, { recordsVerified: result.recordsVerified, durationMs: result.durationMs, bytesVerified: result.bytesVerified });
      }
      return new Response(JSON.stringify(result), { headers: { "content-type": "application/json" } });
    }
    case "POST /drill-all": {
      // SCALE-2: start an ON-DEMAND bulk restore-test campaign ("drill the whole fleet now"). Same authority
      // as a single drill (drill.run: operator/restore-operator/approver/owner) since it is the same
      // read-only operation fanned across the fleet; the DO re-checks drill.run and refuses to clobber an
      // in-progress campaign. The cron driver then drains the campaign capped-per-tick under the shared
      // subrequest budget, so a fleet drill never competes with backups. An optional { downpipeIds } body
      // narrows the campaign; an absent/empty body drills everything.
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = await req.text();
      return scheduler.fetch(doURL("/fleet-drill/start"), { method: "POST", body: body && body.trim() !== "" ? body : "{}", headers: callerHeaders(caller) });
    }
    case "GET /drill-all":
      // The fleet-drill progress view (active campaign or the last finished one). Read-only state (counts +
      // a small failed-id sample), no secret. GATE-CLAIM: this said "so it gates on the read
      // every authenticated role holds, exactly like GET /canary", and it was exactly like GET /canary in
      // the way it did not mean: neither route gated on anything. Corrected in place for the reasons set
      // out there, including why matching the write sibling would be wrong here too (POST /drill-all gates
      // drill.run, which viewer and access-admin do not hold).
      return scheduler.fetch(doURL("/fleet-drill/status"), { method: "GET" });
    default:
      return null;
  }
}
