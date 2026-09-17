// The HARNESS-ONLY /admin/test-fault/* spoke: the owner-gated engine test-fault-hook the self-update
// fault-provocation journeys (G-P0-072/073/076/077) drive. It EXISTS only when HARNESS_TEST_FAULTS is set;
// the router's pre-auth edge 404s the whole prefix otherwise (mirroring the DEMO_MODE reset gate), so a
// production engine has no surface here at all. This spoke additionally requires the caller be an Owner. It
// arms/reads/disarms the ONE persisted fault (scheduler-do-test-fault.ts) and runs one hourly-canary cron
// tick on demand so a journey need not wait a real hour.

import { runCanaryIfDue } from "../cron/notify-passes.ts";
import { runRetentionPrunes } from "../cron/retention-pass.ts";
import { callerHeaders } from "./router-audit.ts";
import { jsonError, jsonResponse } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { ARMABLE_FAULT_KINDS, testFaultsEnabled } from "./test-faults.ts";

export async function handleTestFault(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub } = ctx;
  // Defence in depth: the router's pre-auth edge already 404s /admin/test-fault/* when the flag is off, so
  // this spoke is only reached with the flag ON. Re-check regardless, and ignore any non-test-fault path.
  if (!testFaultsEnabled(env) || !sub.startsWith("/test-fault/")) return null;
  // OWNER-ONLY. The admin authorise() gate already ran; this surface is Owner-exclusive on top (the ADMIN_TOKEN
  // break-glass bearer the harness presents resolves to role owner; a passkey/Access non-owner is refused).
  if (caller.role !== "owner") return jsonError("forbidden: the test-fault surface is Owner-only", 403);
  switch (`${req.method} ${sub}`) {
    case "GET /test-fault/status": {
      const r = await scheduler.fetch(doURL("/test-fault/status"), { method: "GET" });
      const { armed } = (await r.json()) as { armed: { kind: string; binding?: string } | null };
      // harnessFaultHook:true is the probe the harness reads to confirm the hook is wired on this estate.
      // controlPlaneFaultHook:true is the NARROWER probe lib/verbs-recovery-transitions.ts's
      // probeControlPlaneFaultHook reads to confirm the control-plane-recovery-required fault kind
      // specifically is wired (G-P0-096) -- a capability flag, not an armed-state read, so it is always true
      // once this route exists at all (ARMABLE_FAULT_KINDS is a closed, hardcoded set on this deployed build).
      return jsonResponse({ harnessFaultHook: true, controlPlaneFaultHook: true, armed });
    }
    case "POST /test-fault/arm": {
      const body = (await req.json().catch(() => ({}))) as { kind?: unknown; binding?: unknown };
      const kind = typeof body.kind === "string" ? body.kind : "";
      if (!ARMABLE_FAULT_KINDS.has(kind)) return jsonError(`unknown test-fault kind "${kind}"`, 400);
      // The caller is forwarded so the DO's arm event names the Owner who loaded the fault. Arming, clearing
      // and FIRING a fault are now audit-chain events (test-fault-armed / -disarmed / -fired): the hook can
      // force an engine-internal failure, and it used to leave no trace, which made "was a fault armed when
      // this verdict was banked" unanswerable after the fact for every verdict a fault-carrying estate ever
      // produced.
      const r = await scheduler.fetch(doURL("/test-fault/arm"), {
        method: "POST",
        headers: { "content-type": "application/json", ...callerHeaders(caller) },
        body: JSON.stringify({ kind, ...(typeof body.binding === "string" && body.binding !== "" ? { binding: body.binding } : {}) }),
      });
      const { armed } = (await r.json()) as { armed: boolean };
      return jsonResponse({ armed });
    }
    case "POST /test-fault/disarm": {
      await scheduler.fetch(doURL("/test-fault/disarm"), { method: "POST", headers: callerHeaders(caller) });
      return jsonResponse({ disarmed: true });
    }
    case "POST /test-fault/control-plane-clear": {
      // Releases the REAL recovery-required latch a control-plane-recovery-required fault set (G-P0-096).
      // Deliberately bypasses acknowledgeControlPlaneRecovery's authenticated-owner + non-empty-role-table
      // gates: this fault-hook's own throwaway recovery estate is built to carry exactly the empty-role-table
      // state those gates exist to protect on a REAL estate, so neither production clear path (acknowledge,
      // the break-glass reconcile) is ever open there. Gated identically to every other route in this spoke
      // (HARNESS_TEST_FAULTS + Owner-only), so it is reachable nowhere else.
      await scheduler.fetch(doURL("/test-fault/control-plane-clear"), { method: "POST", headers: callerHeaders(caller) });
      return jsonResponse({ cleared: true });
    }
    case "POST /test-fault/canary-tick": {
      // Run ONE hourly-canary cron tick on demand: force the canary due, then fly it (the SAME runCanaryIfDue
      // the cron calls). If an hourly-canary-unhealthy fault is armed, the flight comes back unhealthy and the
      // cron's escalateRollbackIfNeeded claims the one-shot rollbackNeeded; we surface its shouldAlert so a
      // journey can assert the FOLD-1 dedupe. It NEVER deploys (the engine holds no deploy credential).
      await scheduler.fetch(doURL("/canary/run-now"), { method: "POST" }).catch(() => undefined);
      const { shouldAlert } = await runCanaryIfDue(env, scheduler);
      return jsonResponse({ shouldAlert });
    }
    case "POST /test-fault/retention-tick": {
      // Run ONE retention prune pass on demand: the SAME runRetentionPrunes the cron drive loop calls
      // (cron/retention-pass.ts, via drive.ts:runRetentionPrunes), so an Axis-2 prune-safety journey need
      // not wait for the */15 cron and firing stays deterministic. It is DRY-RUN unless a downpipe carries
      // retention.enforce===true: the pass itself is the delete gate (retention-pass.ts checks enforce), so
      // this seam never decides to delete anything. It inherits the canary-tick guards unchanged (the whole
      // /test-fault/* prefix 404s without HARNESS_TEST_FAULTS, and this spoke is Owner-only), reads and
      // mutates only this estate's own scheduler DO + destination, and NEVER deploys. Modelled byte-for-byte
      // on canary-tick above.
      await runRetentionPrunes(env, scheduler);
      return jsonResponse({ ticked: true });
    }
    default:
      return null;
  }
}
