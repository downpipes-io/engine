// The reporting + RTO + coverage cluster of the read-mostly observability subsystem (contract section
// 6 reporting and the coverage/gap detection). Sibling sub-mixin of ObservabilityMixin (restore tests +
// posture stay there); both layer over a base whose `this` is SchedulerDOSurface, so a method here
// still calls this.listDownpipes / this.rtoInputs / this.requireCapabilityResolved and a method there
// still calls this.coverage.

import { COVERAGE_INVENTORY_KEY, type CoverageDownpipeInput, type CoverageReport, computeCoverage, coverageExcludeReason, type ResourceInventory, validateInventory } from "../admin/coverage.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { buildRestoreTestsReport, buildSlaComplianceReport, type ReportPeriod, type RestoreTestsData, type SlaComplianceData } from "../admin/reports.ts";
import { estimateFleetRto, estimateRto, type RtoDownpipeInput, type RtoEstimate } from "../admin/rto.ts";
import { isApiDiscoverySourceType } from "../sources/types.ts";
import { type DownpipeState, DRILL_EVIDENCE_PREFIX, type DrillEvidenceEntry, type RunHistoryEntry, type SchedulerDOCtor } from "./scheduler-do-base.ts";

export function ReportingMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Reporting (contract section 6): per-kind data the DO owns ------------------------------------
    // The DO gathers the data for the two time-bounded reports it has the state for (restore-tests reads
    // the drill-evidence log + the per-downpipe recency; sla-compliance derives run stats from the per-
    // downpipe run-history ring), and returns the structured body for the router to assemble + sign (the
    // signer lives in env, which the DO does not hold). The posture and immutability bodies are assembled
    // by the router (posture via POST /posture; immutability from the env presence slice), so they need no
    // DO data route. NO-CUSTODY: every figure is a count/recency/coarse-state projection; no secret.

    // parseReportPeriod bounds the optional {fromSeconds,toSeconds} window the router forwards. A missing or
    // malformed period is null ("all time"); a window with from > to is normalised (swapped) so a flipped
    // pair never silently excludes everything. Both bounds must be finite non-negative integers.
    parseReportPeriod(raw: unknown): ReportPeriod {
      if (typeof raw !== "object" || raw === null) return null;
      const p = raw as Record<string, unknown>;
      const from = p.fromSeconds;
      const to = p.toSeconds;
      if (typeof from !== "number" || typeof to !== "number" || !Number.isFinite(from) || !Number.isFinite(to) || from < 0 || to < 0) return null;
      const f = Math.floor(from);
      const t = Math.floor(to);
      return f <= t ? { fromSeconds: f, toSeconds: t } : { fromSeconds: t, toSeconds: f };
    }

    // restoreTestsReportData gathers the restore-tests report body (contract section 6): the drill-evidence
    // entries in the period + the per-downpipe last-test recency, via the pure buildRestoreTestsReport. It
    // reads the same drill-evidence log GET /drill-evidence serves and the downpipe states; no secret.
    async restoreTestsReportData(req: { period?: unknown }): Promise<RestoreTestsData> {
      const period = this.parseReportPeriod(req.period);
      const states = await this.listDownpipes();
      const evidenceMap = await this.listAllByPrefix<DrillEvidenceEntry>(DRILL_EVIDENCE_PREFIX);
      // The stated interval travels with the report, so the artefact an auditor reads carries the TARGET it
      // is grading against rather than only the measurements.
      return buildRestoreTestsReport(states, [...evidenceMap.values()], period, await this.getAttendedCadenceDays());
    }

    // slaReportData gathers the sla-compliance report body: per-downpipe expected-vs-successful run counts,
    // freshness and a strikes count. The expected count is derived from the cadence + period in the pure
    // buildSlaComplianceReport; the per-downpipe run stats (successful count in period, the consecutive-
    // failure strikes, and the last success time) are derived HERE from the per-downpipe run-history ring,
    // which is the DO's own redaction-safe operational state (run id/status/time only, no key, no value).
    async slaReportData(req: { period?: unknown }): Promise<SlaComplianceData> {
      const now = Date.now();
      const period = this.parseReportPeriod(req.period);
      const states = await this.listDownpipes();
      const runStats = new Map<string, { successfulRuns: number; strikes: number; lastSuccessAt?: number }>();
      // earliestRunSeconds is the SLA window-clamp fallback (reports.ts's buildSlaComplianceReport) for a
      // downpipe with no ds.createdAt: a record persisted before that field shipped. It is the epoch-
      // seconds start of the OLDEST run its history ring still holds (ring[0]; the ring is stored
      // newest-LAST, see the strikes loop below), computed from the SAME ring already fetched for
      // successfulRuns so this costs no extra read. Absent for a downpipe whose ring is empty (never run)
      // -- that legacy case has no start signal at all and the report honestly falls back to its own
      // period, exactly as it did before this fix.
      const earliestRunSeconds = new Map<string, number>();
      // The per-downpipe ring reads are independent, so fetch them concurrently rather than one storage.get
      // per downpipe sequentially down the loop.
      const rings = new Map<string, RunHistoryEntry[]>(
        await Promise.all(states.map(async (ds): Promise<[string, RunHistoryEntry[]]> => [ds.config.id, (await this.state.storage.get<RunHistoryEntry[]>(`hist:${ds.config.id}`)) ?? []])),
      );
      for (const ds of states) {
        const ring = rings.get(ds.config.id) ?? [];
        if (ds.createdAt === undefined && ring.length > 0) {
          const oldest = Date.parse(ring[0]!.startedAt);
          if (Number.isFinite(oldest)) earliestRunSeconds.set(ds.config.id, Math.floor(oldest / 1000));
        }
        let successfulRuns = 0;
        let lastSuccessAt: number | undefined;
        // strikes = the number of consecutive non-successful runs at the END of the ring (newest first), the
        // same coarse "how broken is it right now" signal the alerting uses. The ring is stored newest-LAST.
        let strikes = 0;
        let countingStrikes = true;
        for (let i = ring.length - 1; i >= 0; i--) {
          const entry = ring[i];
          if (entry === undefined) continue;
          const startedMs = Date.parse(entry.startedAt);
          const inPeriod = period === null || (Number.isFinite(startedMs) && Math.floor(startedMs / 1000) >= period.fromSeconds && Math.floor(startedMs / 1000) <= period.toSeconds);
          if (entry.status === "ok") {
            countingStrikes = false;
            if (inPeriod) successfulRuns++;
            if (lastSuccessAt === undefined && Number.isFinite(startedMs)) lastSuccessAt = startedMs;
          } else if (entry.status === "failed" || entry.status === "abandoned") {
            if (countingStrikes) strikes++;
          }
          // an in-flight run neither counts as success nor breaks the strike streak (it is not yet resolved).
        }
        runStats.set(ds.config.id, { successfulRuns, strikes, ...(lastSuccessAt !== undefined ? { lastSuccessAt } : {}) });
      }
      // Derive the per-downpipe RTO estimate (E4/C1) so the SLA report surfaces recovery TIME next to the
      // freshness/RPO recovery POINT. Each is the honest estimateRto over the downpipe's recovery samples +
      // archive size; an unknown estimate (no drill history) is passed through known:false so the report
      // leaves the rto fields absent rather than fabricating a number.
      const rtoMap = new Map<string, { known: boolean; estimateSeconds?: number; basedOnDrills?: number }>();
      for (const i of await this.rtoInputs(states)) {
        const est = estimateRto(i);
        rtoMap.set(i.id, { known: est.known, ...(est.estimateSeconds !== undefined ? { estimateSeconds: est.estimateSeconds } : {}), ...(est.basedOnDrills !== undefined ? { basedOnDrills: est.basedOnDrills } : {}) });
      }
      return buildSlaComplianceReport(states, runStats, period, now, rtoMap, earliestRunSeconds);
    }

    // rtoInputs builds the per-downpipe RTO input slice (the recovery-test samples + the current archive
    // size the estimate scales to). The archive size is the LATEST SUCCESSFUL run's plaintext byte/record
    // total from the run-history ring (the bytes a full recovery of the freshest run would move). A
    // downpipe with no successful run has no archive-size signal (the estimate then reports only the
    // observed per-drill time, at low confidence). Reads only redaction-safe state (samples = durations +
    // counts; ring = run id/status/bytes); no secret. Shared by the RTO route and the SLA report so they
    // derive RTO from one source.
    async rtoInputs(states: DownpipeState[]): Promise<RtoDownpipeInput[]> {
      const inputs: RtoDownpipeInput[] = [];
      // The per-downpipe ring reads are independent, so fetch them concurrently rather than one storage.get
      // per downpipe sequentially down the loop.
      const rings = new Map<string, RunHistoryEntry[]>(
        await Promise.all(states.map(async (ds): Promise<[string, RunHistoryEntry[]]> => [ds.config.id, (await this.state.storage.get<RunHistoryEntry[]>(`hist:${ds.config.id}`)) ?? []])),
      );
      for (const ds of states) {
        const ring = rings.get(ds.config.id) ?? [];
        // The latest successful run's archive size (newest-LAST ring), the recovery upper bound. Absent when
        // no run has succeeded yet.
        let archiveBytes: number | undefined;
        let archiveRecords: number | undefined;
        for (let i = ring.length - 1; i >= 0; i--) {
          const e = ring[i];
          if (e === undefined || e.status !== "ok") continue;
          if (typeof e.bytes === "number" && Number.isFinite(e.bytes) && e.bytes > 0) archiveBytes = e.bytes;
          if (typeof e.recordCount === "number" && Number.isFinite(e.recordCount) && e.recordCount > 0) archiveRecords = e.recordCount;
          break;
        }
        inputs.push({
          id: ds.config.id,
          name: ds.config.name,
          samples: Array.isArray(ds.recoverySamples) ? ds.recoverySamples : [],
          ...(archiveBytes !== undefined ? { archiveBytes } : {}),
          ...(archiveRecords !== undefined ? { archiveRecords } : {}),
        });
      }
      return inputs;
    }

    // rtoData is the GET /rto handler (E4/C1, the RTO companion to RPO/freshness): the per-downpipe derived
    // recovery-time estimate + a fleet roll-up, each an HONEST projection from observed drill throughput
    // (never a fabricated number; "unknown" with no drill history). The router exposes it next to the
    // freshness/RPO signal. When ?id= is given, only that downpipe's estimate is returned (still with the
    // fleet roll-up over all downpipes, so a console can show "this pipe vs the fleet"). Read-only.
    async rtoData(id: string | null): Promise<{ fleet: RtoEstimate; downpipes: RtoEstimate[] }> {
      const states = await this.listDownpipes();
      const inputs = await this.rtoInputs(states);
      const fleet = estimateFleetRto(inputs);
      const scoped = id ? inputs.filter((i) => i.id === id) : inputs;
      const downpipes = scoped.map((i) => estimateRto(i));
      return { fleet, downpipes };
    }

    // ---- Coverage and gap detection (what is and is not backed up) ------------------------------
    // setCoverageInventory stores the operator-supplied (or read-only-discovery-supplied) resource
    // inventory as REFERENCE DATA ONLY, under the single COVERAGE_INVENTORY_KEY, entirely distinct from
    // the dp:/secrets/binding state. It is gated on access.policy: the DO RE-RESOLVES the caller's
    // effective authority from its own tables (requireCapabilityResolved, the same defence-in-depth the
    // people/access-policy writes use) rather than trusting the asserted role, so a router bug cannot let
    // an unauthorised caller plant a misleading inventory. The body is validated + bounded by the shared
    // validateInventory (a malformed/oversized inventory is a 400 { error }); a missing group defaults to
    // empty. The stored inventory NEVER grants data access: it is a checklist the gap view reads, never a
    // binding a seal/restore path consults. It returns the per-type stored counts so the console can
    // confirm what landed, never echoing back a value (there is none to echo; an inventory carries only
    // ids/labels).
    async setCoverageInventory(
      raw: unknown,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ stored: true; counts: { kv: number; r2: number; d1: number; secrets: number } }> {
      await this.requireCapabilityResolved(caller, "access.policy");
      const result = validateInventory(raw);
      if (!result.ok) {
        // G273: the refusal reached only the immediate HTTP caller. The customer believes they uploaded an
        // inventory, the gap view stays empty forever, and the pack could not show that a submission was even
        // attempted -- let alone that an ENTERPRISE-sized one is refused WHOLE every time it is tried (the
        // over-cap case, which no amount of re-submitting will ever fix). The closed code is chosen at the
        // refusing branch; the submitted inventory, its ids and its labels never ride.
        await this.bumpAdminCounterLocal(result.code);
        throw new Error(result.reason); // the fetch() catch maps it to a 400 { error }
      }
      const inventory = result.inventory;
      await this.state.storage.put(COVERAGE_INVENTORY_KEY, inventory);
      return {
        stored: true,
        counts: { kv: inventory.kv.length, r2: inventory.r2.length, d1: inventory.d1.length, secrets: inventory.secrets.length },
      };
    }

    // coverage computes the gap view (protected/unprotected/untested + rollup) from the stored reference
    // inventory cross-referenced against the downpipe states this DO already holds. With NO inventory
    // stored it returns the HONEST UNKNOWN shape (hasInventory:false, empty resources, zeroed rollup),
    // never implying full coverage. The matching is the pure computeCoverage: for each inventoried
    // resource it finds a same-type downpipe whose CONFIGURED identity (namespaceId/bucketName/binding/
    // secret-name, exactly what buildAdapter would use) matches the resource id, then folds that
    // downpipe's recovery state (a successful run AND a proven restore => protected; covered but not yet
    // both => untested; uncovered => unprotected). The inventory is read ONLY for comparison; it is never
    // used to reach a resource, so it cannot grant data access.
    async coverage(): Promise<CoverageReport> {
      const inventory = (await this.state.storage.get<ResourceInventory>(COVERAGE_INVENTORY_KEY)) ?? null;
      const states = await this.listDownpipes();
      const inputs: CoverageDownpipeInput[] = [];
      for (const ds of states) {
        // The API-discovery source types (cf-config / workers / stream / images / artifacts) back up
        // configuration surfaces, Worker scripts, and the media inventories; none is one of the
        // KV/R2/D1/Secrets data resources the coverage inventory enumerates, so none participates in the
        // data gap view. Tested against the shared set so this skip can never drift from the adapters.
        if (isApiDiscoverySourceType(ds.config.source.type)) continue;
        // hasSuccessfulRun: any completed-ok run in this downpipe's history ring. The ring is the
        // recent-activity view; an "ok" entry is an affirmative successful backup. A downpipe with no
        // ring (never run) honestly reports false.
        const hist = (await this.state.storage.get<RunHistoryEntry[]>(`hist:${ds.config.id}`)) ?? [];
        const hasSuccessfulRun = hist.some((h) => h.status === "ok");
        // restoreProven: a passed BLIND restore test or KEYLESS attestation stamped the per-downpipe
        // "offline restorability last proven" record. Its mere presence is the affirmative proof.
        const restoreProven = ds.restoreProven !== undefined;
        inputs.push({
          id: ds.config.id,
          source: {
            type: ds.config.source.type,
            ...(ds.config.source.binding !== undefined ? { binding: ds.config.source.binding } : {}),
            ...(ds.config.source.namespaceId !== undefined ? { namespaceId: ds.config.source.namespaceId } : {}),
            ...(ds.config.source.bucketName !== undefined ? { bucketName: ds.config.source.bucketName } : {}),
            ...(ds.config.source.databaseId !== undefined ? { databaseId: ds.config.source.databaseId } : {}),
            ...(ds.config.source.secrets !== undefined ? { secrets: ds.config.source.secrets.map((s) => ({ name: s.name })) } : {}),
          },
          hasSuccessfulRun,
          restoreProven,
        });
      }
      // G273: the downpipes the MATCHER silently drops. A source type the matcher does not know, or a source
      // with no identity key to match on, covers nothing -- so the resource it really does protect is reported
      // UNPROTECTED on the screen the customer is audited against, and the exclusion left no trace anywhere.
      // The exclusion decision is coverageExcludeReason, the SAME call bucketByType makes, so the count can
      // never disagree with the verdict. Counts only: never the source, the binding or the downpipe id. A
      // healthy fleet excludes nothing and records nothing.
      for (const dp of inputs) {
        const excluded = coverageExcludeReason(dp);
        if (excluded !== null) await this.bumpAdminCounterLocal(excluded);
      }
      return computeCoverage(inventory, inputs, Date.now());
    }
  };
}
