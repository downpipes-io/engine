// SchedulerDiagMixin: the SchedulerDO's DIAGNOSTIC RECORDERS -- the small, best-effort, never-throwing writers
// that promote an otherwise-silent scheduler fault into durable, redaction-safe evidence the support pack can
// carry. They are split out of the scheduling core (which owns the due-index, the run-state machine and the
// alarm) because they are a distinct concern with a single shape: classify the fault into a CLOSED vocabulary,
// clamp everything, write a bounded counter or stamp, and NEVER let the observation break the path it observed.
//
// What each recorder exists for:
//   recordStorageFault  (G040) persist-state storage.put faults, ATTRIBUTED to the downpipe being persisted, so
//                       a climbing value-too-large count finally names the downpipe whose state has outgrown the
//                       DO 128 KiB per-value cap (the one that then never advances its next-run time).
//   recordSchedHealth   (G040) the three housekeeping faults that were fully silent: a housekeeping sweep that
//                       keeps THROWING (DO storage grows for months until the limits bite), a fleet enumeration
//                       TRUNCATED by the paging guard (downpipes past the cap are never scheduled and read as
//                       nonexistent), and a due-index parity stamp whose write FAILED (the pack then serves the
//                       prior snapshot as if it were fresh).
//   recordStateRefusal  (G095 / G210) a persisted dp:<id> record REFUSED at read time by migrateOrRejectConfig:
//   clearStateRefusal   the engine was rolled back and is reading new-shape state, or the version stamp is
//                       corrupt. Such a downpipe silently STOPS (due() skips it, trigger() 500s, no run row is
//                       ever created); the one fact that explains it otherwise lives only in a Workers Logs line
//                       the vendor cannot pull. The stamp is cleared once the record reads clean again.
//
// Every field written here is a count, a clamped integer, a closed enum, a clamped timestamp, or the customer's
// OWN downpipe label (the same redaction class the pack already carries in downpipes[] and sealFaults). A raw
// storage error message, a key, a value or a schedule string NEVER rides.
import { CONFIG_SCHEMA_VERSION, SCHED_HEALTH_KEY, type SchedulerDOCtor, STATE_REFUSED_PREFIX, STORAGE_FAULT_KEY } from "./scheduler-do-base.ts";
import { applySchedHealth, applyStateRefusal, applyStorageFault, safeDownpipeId } from "./scheduler-helpers.ts";
import type { SchedHealthCounters, SchedHealthKind, StateRefusal, StateRefusedClass, StorageFaultCounter, StorageFaultKind } from "./types.ts";

export function SchedulerDiagMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // recordStorageFault PROMOTES a persist-state storage.put fault (SCHED persist-state-storage-fault) into the
    // DISTINCT, cumulative persisted counter, classifying the DO value-too-large put (INFRA do-value-size-limit)
    // from a generic storage failure, and ATTRIBUTING it to the downpipe whose record was being written (G040).
    // BEST-EFFORT by construction: a value-too-large fault is per-key so this small counter write succeeds, and a
    // transient blip clears; only a TOTAL storage outage prevents even the counter write, where the tick
    // sealErrors/passErrors + the missed-tick interval remain the evidence. It NEVER throws (a fault WHILE
    // recording a fault must not mask the original error persistDownpipeState re-throws).
    async recordStorageFault(kind: StorageFaultKind, downpipeId?: string): Promise<void> {
      try {
        const prior = await this.state.storage.get<StorageFaultCounter>(STORAGE_FAULT_KEY);
        await this.state.storage.put(STORAGE_FAULT_KEY, applyStorageFault(prior, kind, Date.now(), downpipeId));
      } catch {
        /* best-effort: during a TOTAL storage outage even this counter write fails; the indirect tick
           sealErrors/passErrors + the interval gap remain the evidence (documented at STORAGE_FAULT_KEY). */
      }
    }

    // recordSchedHealth PROMOTES a scheduler HOUSEKEEPING fault (G040) into the bounded counter record at
    // SCHED_HEALTH_KEY. Best-effort and never throwing, exactly like recordStorageFault: observing a fault must
    // never break the path that hit it. Counts + clamped timestamps only (the three classes are fleet-level).
    async recordSchedHealth(kind: SchedHealthKind): Promise<void> {
      try {
        const prior = await this.state.storage.get<SchedHealthCounters>(SCHED_HEALTH_KEY);
        await this.state.storage.put(SCHED_HEALTH_KEY, applySchedHealth(prior, kind, Date.now()));
      } catch {
        /* best-effort: a counter write that fails in a total storage outage leaves the tick ring as the evidence */
      }
    }

    // recordStateRefusal STAMPS a read-time state REFUSAL for one downpipe (G095 / G210). The stamp goes to its
    // OWN key (staterefused:<id>), NEVER onto the dp: record: persistDownpipeState re-stamps schemaVersion at the
    // storage boundary, so writing back would OVERWRITE the newer-schema state the guard exists to protect with
    // this older engine's version. Best-effort and never throwing: the caller's skip/throw behaviour is unchanged,
    // only the evidence is new. Closed class + two clamped ints + a count + a clamped time.
    async recordStateRefusal(downpipeId: string, cls: StateRefusedClass, storedVersion: number): Promise<void> {
      try {
        const id = safeDownpipeId(downpipeId);
        if (id === null) return;
        const key = `${STATE_REFUSED_PREFIX}${id}`;
        const prior = await this.state.storage.get<StateRefusal>(key);
        await this.state.storage.put(key, applyStateRefusal(prior, cls, storedVersion, CONFIG_SCHEMA_VERSION, Date.now()));
      } catch {
        /* best-effort: the refusal already fails loud to the caller; the stamp is diagnostic only */
      }
    }

    // clearStateRefusal drops a downpipe's refusal stamp once its record READS CLEAN again (a re-upgrade or a
    // migration repaired it), so a repaired downpipe stops reporting a fault it no longer has. Called from the
    // trigger() success path (once per run, not on a hot loop). Best-effort: a failed delete only leaves a stale
    // stamp whose `at` is visibly old, never a wrong dispatch.
    async clearStateRefusal(downpipeId: string): Promise<void> {
      try {
        const id = safeDownpipeId(downpipeId);
        if (id !== null) await this.state.storage.delete(`${STATE_REFUSED_PREFIX}${id}`);
      } catch {
        /* best-effort */
      }
    }
  };
}
