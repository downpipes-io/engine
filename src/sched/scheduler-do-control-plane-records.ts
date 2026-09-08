// engine-sys-struct: the control-plane RECOVERY-RECORD + observability accessors, MOVED VERBATIM out of
// scheduler-do-control-plane.ts so neither file exceeds the module-size guardrail. These are the pure
// state readers/writers around the staged-recovery record, the amnesia probe, the deploy observation and
// the export health; the export builder, the reconcile/import keystone and the auto-heal apply slices
// stay in the parent module. Same mixin discipline as every sibling (`this` is SchedulerDOSurface); the
// assembly chains ControlPlaneRecordsMixin right after ControlPlaneMixin in scheduler-do.ts. A leaf the
// assembly depends on, never the reverse (madge 0 cycles). No behaviour, storage key, status code or
// response change: the method bodies are byte-identical moves.

import type {
  AmnesiaProbeClass,
  AutoHealRefusalCode,
  AutoHealSubCause,
  CandidateScan,
  ControlPlaneAmnesiaProbe,
  ControlPlaneDeployObservation,
  ControlPlaneExportHealth,
  ControlPlaneImportOutcome,
  ControlPlaneRecoveryRecord,
  StagedControlPlane,
} from "../admin/control-plane.ts";
import { CP_EXPORT_FAIL_CLASSES, type CpExportFailClass } from "../cron/cron-fault-ledger.ts";
import { recordCapTruncation, recordStagedApplyRefusal } from "./sched-fault-ledger.ts";
import {
  CONTROL_PLANE_AMNESIA_PROBE_KEY,
  CONTROL_PLANE_DEPLOY_OBS_KEY,
  CONTROL_PLANE_EXPORT_HEALTH_KEY,
  CONTROL_PLANE_LAST_IMPORT_KEY,
  CONTROL_PLANE_STAGED_KEY,
  type SchedulerDOCtor,
} from "./scheduler-do-base.ts";

// The DO-side redaction gate for the per-destination export reason (G202): the vocabulary is taken from the
// module that CLASSIFIES the fault, so a store message, an endpoint or a bucket cannot enter the record.
const CP_EXPORT_FAIL_CLASS_SET: ReadonlySet<string> = new Set(CP_EXPORT_FAIL_CLASSES);

import { nowMillisISO } from "./scheduler-helpers.ts";

export function ControlPlaneRecordsMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // getControlPlaneRecoveryRecord reads the staged-export / refusal record (null when nothing staged).
    async getControlPlaneRecoveryRecord(): Promise<ControlPlaneRecoveryRecord | null> {
      return (await this.state.storage.get<ControlPlaneRecoveryRecord>(CONTROL_PLANE_STAGED_KEY)) ?? null;
    }

    // stageControlPlaneRecovery parks a Worker-VERIFIED export for the break-glass confirm. The Worker
    // verified the signature + no-custody before calling; the DO stores it verbatim (it holds no signer key).
    async stageControlPlaneRecovery(staged: StagedControlPlane): Promise<void> {
      await this.state.storage.put(CONTROL_PLANE_STAGED_KEY, { staged } satisfies ControlPlaneRecoveryRecord);
    }

    // recordControlPlaneRecoveryRefused remembers that the auto-heal found nothing it could SAFELY apply
    // (no export, an ambiguous latest generation, an unsigned/unverifiable artefact, or no signer to verify
    // with). It steps back to the manual break-glass path and stops the cron re-probing/re-alerting forever.
    // `code` is the CLOSED AutoHealRefusalCode (redaction-safe, surfaced to the support pack); `reason` stays
    // the operator-facing free text (which the pack deliberately does NOT forward, since the shape-check path
    // can embed a secret field name). Optional so a caller that has not classified still records the reason.
    async recordControlPlaneRecoveryRefused(reason: string, code?: AutoHealRefusalCode, extra?: { subCause?: AutoHealSubCause; scan?: CandidateScan }): Promise<void> {
      await this.state.storage.put(CONTROL_PLANE_STAGED_KEY, {
        refused: {
          reason,
          at: nowMillisISO(),
          ...(code !== undefined ? { code } : {}),
          // G218: the closed sub-cause (WHY, within the code) and the candidate-scan counts (what the bucket
          // actually held). Already gated + clamped at the route; carried verbatim here.
          ...(extra?.subCause !== undefined ? { subCause: extra.subCause } : {}),
          ...(extra?.scan !== undefined ? { scan: extra.scan } : {}),
        },
      } satisfies ControlPlaneRecoveryRecord);
      // G103: a refusal recorded with NO closed code carries only the operator-facing free text, which the
      // pack deliberately does not forward (the shape-check path can embed a secret FIELD NAME). So the pack's
      // recovery section shows a refusal with an EMPTY reason, and the account's recovery is stalled with no
      // diagnosable cause at all. Count the unclassified refusals so that blank is self-explaining, and so an
      // unclassified call site shows up as a defect rather than as silence.
      if (code === undefined) await recordStagedApplyRefusal(this.state.storage, "refusal-unclassified");
    }

    // clearControlPlaneStaged drops the staged/refusal record (consumed by a successful authority reconcile).
    async clearControlPlaneStaged(): Promise<void> {
      await this.state.storage.delete(CONTROL_PLANE_STAGED_KEY);
    }

    // ---- (5) recovery-latch SELF-DIAGNOSIS + deploy identity + export health (needs-new-logging) -------

    // recordControlPlaneAmnesiaProbe stores the OUTCOME CLASS of the cron health pass's last amnesia-detection
    // attempt (CPR: amnesia-undetectable-console-only-dest + amnesia-false-negative-runlog-missing). The
    // recovery latch's own blind spots (no bucket to probe; a bucket whose RUNLOG is absent/unreadable) left
    // no signal, so a support engineer could not distinguish a healthy new account from an amnesia the latch
    // could not confirm. Redaction-safe (a closed enum + a timestamp).
    async recordControlPlaneAmnesiaProbe(probe: AmnesiaProbeClass): Promise<void> {
      await this.state.storage.put(CONTROL_PLANE_AMNESIA_PROBE_KEY, { probe, at: nowMillisISO() } satisfies ControlPlaneAmnesiaProbe);
    }

    // getControlPlaneAmnesiaProbe reads the last amnesia-probe record (null when the pass never ran a detect).
    async getControlPlaneAmnesiaProbe(): Promise<ControlPlaneAmnesiaProbe | null> {
      return (await this.state.storage.get<ControlPlaneAmnesiaProbe>(CONTROL_PLANE_AMNESIA_PROBE_KEY)) ?? null;
    }

    // recordControlPlaneDeployObservation is the DETERMINISTIC per-tick deploy-identity observer (CPR:
    // version-change-observation-gated / -first-poll-baseline / cfversionid-absent-redeploy-invisible). The
    // Worker passes the running engine version + the cf deploy id (when the CF_VERSION_METADATA binding is
    // present); the DO compares it to the stored observation and records a BASELINE on the first observation
    // (so the first tick never fabricates a "change") vs a real CHANGE (a deploy) thereafter, and flags when
    // no cf deploy id is available (a same-software redeploy is then only visible via the engine version). It
    // returns whether this observation was the baseline or a change, for the caller's log. No secret.
    async recordControlPlaneDeployObservation(obs: { engineVersion: string; cfVersionId?: string }): Promise<{ baseline: boolean; changed: boolean }> {
      const prior = (await this.state.storage.get<ControlPlaneDeployObservation>(CONTROL_PLANE_DEPLOY_OBS_KEY)) ?? null;
      const now = nowMillisISO();
      const cfVersionIdAbsent = obs.cfVersionId === undefined || obs.cfVersionId === "";
      if (prior === null) {
        // Baseline: establish the identity WITHOUT recording a change (the first observation is not a deploy).
        await this.state.storage.put(CONTROL_PLANE_DEPLOY_OBS_KEY, {
          engineVersion: obs.engineVersion,
          ...(obs.cfVersionId !== undefined && obs.cfVersionId !== "" ? { cfVersionId: obs.cfVersionId } : {}),
          cfVersionIdAbsent,
          firstSeenAt: now,
          lastSeenAt: now,
          baselineEstablished: true,
          changesObserved: 0,
        } satisfies ControlPlaneDeployObservation);
        return { baseline: true, changed: false };
      }
      // A change is a differing engine version OR a differing cf deploy id (a same-software redeploy). When no
      // cf id is available on either side, only an engine-version change is observable (documented blind spot).
      const softwareChanged = prior.engineVersion !== obs.engineVersion;
      const deployChanged = !!prior.cfVersionId && !!obs.cfVersionId && prior.cfVersionId !== obs.cfVersionId;
      const changed = softwareChanged || deployChanged;
      await this.state.storage.put(CONTROL_PLANE_DEPLOY_OBS_KEY, {
        engineVersion: obs.engineVersion,
        ...(obs.cfVersionId !== undefined && obs.cfVersionId !== "" ? { cfVersionId: obs.cfVersionId } : {}),
        cfVersionIdAbsent,
        firstSeenAt: prior.firstSeenAt,
        lastSeenAt: now,
        baselineEstablished: true,
        changesObserved: prior.changesObserved + (changed ? 1 : 0),
        ...(changed ? { lastChangeAt: now } : prior.lastChangeAt !== undefined ? { lastChangeAt: prior.lastChangeAt } : {}),
      } satisfies ControlPlaneDeployObservation);
      return { baseline: false, changed };
    }

    // getControlPlaneDeployObservation reads the deploy-identity observation (null before the first tick).
    async getControlPlaneDeployObservation(): Promise<ControlPlaneDeployObservation | null> {
      return (await this.state.storage.get<ControlPlaneDeployObservation>(CONTROL_PLANE_DEPLOY_OBS_KEY)) ?? null;
    }

    // recordControlPlaneExportHealth stores the outcome of the last control-plane export pass (CPR:
    // export-budget-starved-stale-generation + export-per-dest-write-fault): whether it wrote a fresh
    // generation, the closed skip reason when it did not, and the PER-DESTINATION write outcome so a partial
    // write (one dest rejected the recovery artefact, leaving it without a recovery copy) is visible.
    // Redaction-safe (a timestamp, a closed enum, ints, per-dest {id, ok} booleans).
    async recordControlPlaneExportHealth(health: ControlPlaneExportHealth): Promise<void> {
      // Defensive clamp: bound the per-dest array so a hostile/oversized caller cannot store an unbounded list.
      const perDestAll = Array.isArray(health.perDest) ? health.perDest : [];
      // G202: the per-destination REASON rides alongside ok. It is gated against the closed CpExportFailClass
      // set here (the DO is the redaction chokepoint), so a store's message, an endpoint or a bucket cannot
      // enter the record even if a future writer posted one. Only carried on a FAILED destination.
      const perDest = perDestAll.slice(0, 64).map((d) => {
        const raw = (d as { reason?: unknown }).reason;
        const reason = typeof raw === "string" && CP_EXPORT_FAIL_CLASS_SET.has(raw) ? (raw as CpExportFailClass) : undefined;
        return { id: String(d.id).slice(0, 128), ok: d.ok === true, ...(d.ok !== true && reason !== undefined ? { reason } : {}) };
      });
      // G325: THE 65TH DESTINATION'S OUTCOME WAS BEING DROPPED SILENTLY. This record is what the self-backup
      // posture check reads to decide allDestinationsWrote, so a large-fleet tenant whose 65th destination
      // FAILED to take the recovery artefact read as fully-covered -- a MISSING RECOVERY COPY, invisible. The
      // record now carries the TRUE total and an explicit truncated flag (the cfConfigDiscovery
      // unavailableCount pattern), and the dropped rows are counted in the ledger too. Counts only; the
      // dropped destinations' ids stay out.
      if (perDestAll.length > perDest.length) await recordCapTruncation(this.state.storage, "export-health-perdest", perDestAll.length - perDest.length);
      await this.state.storage.put(CONTROL_PLANE_EXPORT_HEALTH_KEY, {
        at: health.at,
        ...(health.skipped !== undefined ? { skipped: health.skipped } : {}),
        wroteAny: health.wroteAny === true,
        ...(typeof health.configVersion === "number" && Number.isFinite(health.configVersion) ? { configVersion: health.configVersion } : {}),
        perDest,
        perDestTotal: perDestAll.length,
        ...(perDestAll.length > perDest.length ? { perDestTruncated: true as const } : {}),
      } satisfies ControlPlaneExportHealth);
    }

    // getControlPlaneExportHealth reads the last export-pass outcome (null before the first export pass ran).
    async getControlPlaneExportHealth(): Promise<ControlPlaneExportHealth | null> {
      return (await this.state.storage.get<ControlPlaneExportHealth>(CONTROL_PLANE_EXPORT_HEALTH_KEY)) ?? null;
    }

    // recordControlPlaneImportOutcome (G218) persists the OUTCOME of the last estate import. The import
    // answered with crossAccount + accountIdAbsent on its HTTP response and stored NEITHER, so the pack (built
    // after the incident, when that response is long gone) could not tell a genuine cross-account rebuild from
    // a pre-account-discovery export -- two states with the same disabled roster and OPPOSITE remedies. This is
    // the record that makes them two rows. Every field is a boolean, a count or a timestamp.
    async recordControlPlaneImportOutcome(outcome: { crossAccount: boolean; accountIdAbsent: boolean; downpipesDisabled: boolean; downpipes: number; destinations: number }): Promise<void> {
      await this.state.storage.put(CONTROL_PLANE_LAST_IMPORT_KEY, {
        at: nowMillisISO(),
        crossAccount: outcome.crossAccount === true,
        accountIdAbsent: outcome.accountIdAbsent === true,
        downpipesDisabled: outcome.downpipesDisabled === true,
        downpipes: Math.max(0, Math.min(1_000_000, Math.floor(outcome.downpipes))),
        destinations: Math.max(0, Math.min(1_000_000, Math.floor(outcome.destinations))),
      } satisfies ControlPlaneImportOutcome);
    }

    // getControlPlaneLastImport reads the last estate-import outcome (null when no import has ever run, which
    // is the ordinary state of every engine that has never been rebuilt from a kit).
    async getControlPlaneLastImport(): Promise<ControlPlaneImportOutcome | null> {
      return (await this.state.storage.get<ControlPlaneImportOutcome>(CONTROL_PLANE_LAST_IMPORT_KEY)) ?? null;
    }
  };
}
