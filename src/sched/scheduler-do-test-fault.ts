// The HARNESS-ONLY test-fault store (owner-gated engine test-fault-hook). This mixin is the Durable Object
// persistence for ONE armed update-lifecycle fault, so the self-update fault-provocation journeys
// can provoke engine-INTERNAL faults that page.route and the harness-sink cannot reach. It is inert on its own: the DO cannot read env, so the WHOLE gate lives in the Worker, which only
// ever routes here when HARNESS_TEST_FAULTS is set AND the caller is an Owner (see src/admin/router.ts's
// pre-auth 404 gate and src/admin/router-test-fault.ts). A production engine never sets the flag, so the
// Worker never arms or consumes, so this store is never written or read there (exactly as the DEMO_MODE
// reset routes exist in the DO but are only ever reached through the DEMO_MODE-gated Worker path).
//
// The record is SINGLE-SHOT and SELF-CLEARING: consumeTestFault reads-checks-deletes inside
// blockConcurrencyWhile (atomic on the single-threaded DO), so an armed fault fires at most once, at the
// next matching op, then clears itself. Each injection seam consumes only the kinds IT owns, so one settle
// consuming the verdict fault never eats a drop-source-binding fault the same settle's diff must still see.

import { CALLER_HEADER, decodeCaller } from "../admin/identity.ts";
import { type SchedulerDOCtor, TEST_FAULT_KEY } from "./scheduler-do-base.ts";

type FaultCaller = { method: import("../admin/identity.ts").AuthMethod; email: string | null; subject: string | null; sourceIp?: string | null } | null;

// The closed set of arm-able fault kinds. Each maps to the branch it forces:
//   canary-dead              the settle canary returns DEAD -> decideKeep = rollback
//   rollback-deploy-fail     COMPOUND: the settle canary DEAD *and* the auto-rollback deployVersion THROWS
//                            -> outcome "rollback-failed", still on the bad build (rather than a falsely
//                            reported success)
//   hourly-canary-unhealthy  the hourly canary finds the promoted-unsettled live version unhealthy
//   drop-source-binding      the deploy omits a named source binding so the settle diff reports it
//   dest-header-corrupt      the NEXT seal WRITE sees a malformed/unexpected destination response header, so
//                            the seal's real write path fails LOUD and the run is recorded FAILED, never a
//                            silent good backup over a header-faulted write (chaos MFG-2/MFG-6). It
//                            is the destination-WRITE analogue of the four update-lifecycle kinds above: the
//                            store persists it, sliceDepsFromEnv's consume seam wraps the destination once,
//                            and the wrapped write throws the header-fault the engine already fails loud on.
//   licence-token-read-fail  the NEXT readLicence DO read of /licence-token is forced to fail, so the
//                            fail-open fallback to the deploy-time env token fires for real.
//   report-data-read-fail    the NEXT compliance report-data DO read (restore-tests / change-requests /
//                            sla-compliance) is forced to fail, so assertReportData's throw-to-5xx guard
//                            fires for real instead of a report ever being signed over an unavailable read.
//   passkey-session-mint-fail the NEXT verified passkey finish ceremony's /passkey/session/issue DO call is
//                            forced to fail, so sessionCookieForFinish's fail-open (no session, ceremony body
//                            still returned) fires for real and recordPasskeyOutcome logs
//                            passkey-session-mint-failed rather than the failure vanishing.
//   control-plane-recovery-required  the NEXT GET /admin/control-plane/status read LATCHES the real
//                            recovery-required flag, via the SAME setControlPlaneRecoveryRequired the cron
//                            health pass calls on a genuine wipe, so this read and every later one on the
//                            same estate (whoami's degrade-to-viewer, the console recovery banner) see the
//                            real product behaviour rather than a spoofed response. Single-shot:
//                            only the FIRST read after arming triggers the latch; the latch then PERSISTS
//                            exactly as production's does, because a real wipe's latch persists too. The
//                            harness-only POST /test-fault/control-plane-clear action releases it: the real
//                            acknowledge/reconcile clears both refuse over an empty role table, which is
//                            exactly the state this fault-hook's own throwaway recovery estate is built to
//                            carry, so neither production clear path is reachable there.
export const ARMABLE_FAULT_KINDS: ReadonlySet<string> = new Set([
  "canary-dead",
  "rollback-deploy-fail",
  "hourly-canary-unhealthy",
  "drop-source-binding",
  "dest-header-corrupt",
  "licence-token-read-fail",
  "report-data-read-fail",
  "passkey-session-mint-fail",
  "control-plane-recovery-required",
]);

// The persisted armed-fault record: the kind, an optional named binding (drop-source-binding), and when it
// was armed. Redaction-safe: a closed kind enum, the operator's own binding label, and a timestamp.
export interface ArmedTestFault {
  kind: string;
  binding?: string;
  at: number;
}

export function TestFaultMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // armTestFault stores ONE armed fault (replacing any prior), validating the kind against the closed set
    // (defence in depth: the Worker already validates). An unknown kind arms nothing.
    async armTestFault(req: { kind?: unknown; binding?: unknown }, caller?: FaultCaller): Promise<{ armed: boolean }> {
      const kind = typeof req.kind === "string" ? req.kind : "";
      if (!ARMABLE_FAULT_KINDS.has(kind)) return { armed: false };
      const rec: ArmedTestFault = { kind, at: Date.now(), ...(typeof req.binding === "string" && req.binding !== "" ? { binding: req.binding } : {}) };
      await this.state.storage.put(TEST_FAULT_KEY, rec);
      // AUDITED: loading a fault is a privileged act by a named Owner that changes how
      // this engine behaves, so it must leave a trace. Recorded only on a successful arm; a
      // rejected kind writes nothing to storage, so there is nothing about the estate for it to say.
      await this.appendAudit({
        actorSubject: caller?.subject ?? null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller?.method ?? "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "test-fault-armed",
        outcome: "success",
        target: { kind: "test-fault", op: "arm", faultKind: kind, ...(rec.binding !== undefined ? { binding: rec.binding } : {}) },
      });
      return { armed: true };
    }

    // readTestFault is the non-consuming status read (the harness probe + GET status).
    async readTestFault(): Promise<{ armed: { kind: string; binding?: string } | null }> {
      const rec = await this.state.storage.get<ArmedTestFault>(TEST_FAULT_KEY);
      return { armed: rec ? { kind: rec.kind, ...(rec.binding ? { binding: rec.binding } : {}) } : null };
    }

    // disarmTestFault clears any armed fault (best-effort cleanup; idempotent).
    //
    // AUDITED, but ONLY when something was actually cleared. The return value stays an unconditional
    // { disarmed: true } so no caller changes behaviour, and the read that decides whether to record is the
    // interesting half: a disarm that found nothing means the fault had ALREADY FIRED, and the fired event
    // says that far better than a reassuring "disarmed" row would. Writing a row for the no-op would put the
    // most comforting entry in the chain at the moment the estate was least clean.
    async disarmTestFault(caller?: FaultCaller): Promise<{ disarmed: boolean }> {
      const rec = await this.state.storage.get<ArmedTestFault>(TEST_FAULT_KEY);
      await this.state.storage.delete(TEST_FAULT_KEY);
      if (rec !== undefined && typeof rec.kind === "string" && rec.kind.length > 0) {
        await this.appendAudit({
          actorSubject: caller?.subject ?? null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller?.method ?? "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "test-fault-disarmed",
          outcome: "success",
          target: { kind: "test-fault", op: "disarm", faultKind: rec.kind, ...(typeof rec.binding === "string" && rec.binding !== "" ? { binding: rec.binding } : {}), ...(Number.isFinite(rec.at) ? { armedAt: new Date(rec.at).toISOString() } : {}) },
        });
      }
      return { disarmed: true };
    }

    // consumeTestFault is the SINGLE-SHOT read-check-delete: if a fault is armed AND its kind is one of the
    // requested kinds, delete it and return it; otherwise leave the store untouched and return null. Wrapped
    // in blockConcurrencyWhile so two concurrent ops cannot both consume the same record. The selectivity
    // (kinds) lets one settle's verdict seam and its binding-diff seam each consume only their own kind.
    async consumeTestFault(req: { kinds?: unknown }): Promise<{ fault: { kind: string; binding?: string } | null }> {
      const kinds = Array.isArray(req.kinds) ? req.kinds.filter((k): k is string => typeof k === "string") : [];
      const consumed = await this.blockConcurrencyWhile(async () => {
        const rec = await this.state.storage.get<ArmedTestFault>(TEST_FAULT_KEY);
        if (!rec || !kinds.includes(rec.kind)) return null;
        await this.state.storage.delete(TEST_FAULT_KEY);
        return rec;
      });
      if (consumed === null) return { fault: null };
      // THE LOAD-BEARING EVENT, and the reason this whole change is worth its size: this is the instant the
      // hook actually altered engine behaviour. Without it, a verdict banked on a fault-carrying estate could
      // not be told apart from one banked on a clean run, retrospectively, ever. armedAt gives the suspect
      // window its far end; the event's own ts gives it the near one.
      //
      // Appended OUTSIDE blockConcurrencyWhile, deliberately. The consume must stay a tight read-check-delete
      // so an armed fault still fires at most once; the chain write is a separate concern and holding the
      // input lock across it would widen the atomic section for no gain. The delete has already committed by
      // the time this runs, so the ordering cannot resurrect a consumed fault.
      //
      // actorMethod "engine": there is no human here. The consume fires from an internal injection seam
      // reached by ordinary traffic, so attributing it to whoever happened to be signed in would be a
      // fabrication, and the actor that matters is already recorded on the arm event.
      await this.appendAudit({
        actorSubject: null,
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "test-fault-fired",
        outcome: "success",
        target: { kind: "test-fault", op: "fire", faultKind: consumed.kind, ...(typeof consumed.binding === "string" && consumed.binding !== "" ? { binding: consumed.binding } : {}), ...(Number.isFinite(consumed.at) ? { armedAt: new Date(consumed.at).toISOString() } : {}) },
      });
      return { fault: { kind: consumed.kind, ...(consumed.binding ? { binding: consumed.binding } : {}) } };
    }

    // routeTestFault dispatches the INTERNAL DO endpoints the Worker calls (never reachable from outside the
    // account: the DO is bound only to the Worker, which gates every one of these on HARNESS_TEST_FAULTS +
    // Owner). Returns the handler Response for a path it owns, or null so the route() chain tries the next.
    async routeTestFault(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
        case "POST /test-fault/arm":
          // The caller rides the same CALLER_HEADER every other authority-bearing DO route uses, so the arm
          // event names the Owner who loaded the fault rather than an anonymous "engine".
          return this.json(await this.armTestFault((await req.json()) as { kind?: unknown; binding?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
        case "GET /test-fault/status":
          return this.json(await this.readTestFault());
        case "POST /test-fault/disarm":
          return this.json(await this.disarmTestFault(decodeCaller(req.headers.get(CALLER_HEADER))));
        case "POST /test-fault/consume":
          return this.json(await this.consumeTestFault((await req.json()) as { kinds?: unknown }));
        // HARNESS-ONLY: releases the REAL recovery-required latch a control-plane-recovery-required fault
        // set, deliberately bypassing acknowledgeControlPlaneRecovery's authenticated-owner + non-empty-
        // role-table gates -- this fault-hook's own throwaway recovery estate is built to carry exactly the
        // empty-role-table state those gates exist to protect on a REAL estate, so neither production clear
        // path (acknowledge, the break-glass reconcile) is ever open there. AUDITED, distinct from a genuine
        // acknowledge/reconcile, so the trail can tell the harness cleared it apart from either.
        case "POST /test-fault/control-plane-clear": {
          const caller = decodeCaller(req.headers.get(CALLER_HEADER));
          await this.clearControlPlaneRecoveryRequired();
          await this.appendAudit({
            actorSubject: caller?.subject ?? null,
            actorEmail: caller?.email ? caller.email : null,
            actorMethod: caller?.method ?? "access",
            sourceIp: caller?.sourceIp ?? null,
            action: "test-fault-control-plane-cleared",
            outcome: "success",
            target: { kind: "test-fault", op: "control-plane-clear", faultKind: "control-plane-recovery-required" },
          });
          return this.json({ cleared: true });
        }
        default:
          return null;
      }
    }
  };
}
