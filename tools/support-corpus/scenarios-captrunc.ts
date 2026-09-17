// CAP-TRUNCATION corpus scenarios (, another pass): GENERATED FAULT PACKS for the three
// subject-keyed bounded records, defects 8, 9 and 10 of the boundary table.
//
// WHY THESE EXIST AS SCENARIOS RATHER THAN AS UNIT ASSERTIONS. One pass and another closed all
// three by declaring a COUNT against capTruncations, and a third pass then measured the pack and found
// the consequence had SURVIVED the fix in the one place that matters: the pack said N ROWS WERE DROPPED and
// could not say WHICH SUBJECT, so `freshnessUncomputableIndex` could only ever mark a downpipe INSIDE the
// cap, and the downpipe PAST it was absent from the map, carried no marker, and its pack row went on reading
// as a downpipe with a working staleness rule. The clean assertion sat on the row and the caveat sat in a
// different section. That third pass also recorded its own weakness in its own words -- it proved the corpus
// instrument and never used it, so every verdict it reached was a READING OF THE GENERATOR. These scenarios
// are the answer to that: a REAL signed bundle, built by the REAL projector, from a ledger written by the
// REAL recorders, in which the question "which subject was dropped" is put to the pack rather than to source.
//
// FIDELITY. The ledgers below are driven at module load through the ACTUAL write paths -- the real
// `recordFreshnessFault` for defect 8, and the real `SchedulerDO.recordIntegrityFaults` /
// `recordDestProbeFaults` routes over the real in-memory storage double for defects 9 and 10 -- and the
// `/sched-diag` route then serves the REAL `readSchedDiag` bundle those writes produced. Nothing here is a
// hand-shaped fixture of the shape the recorder is supposed to write.
//
// THE POPULATION IS ASSERTED, which is the trap these captures are written against: "every dropped downpipe
// carries a marker" is also true of a pack with no dropped downpipes, and "no row asserts a clean staleness
// rule" is also true of a pack with no rows. Each capture therefore pins the fleet size, the count of rows
// marked uncomputable, the count marked unknown AND the count of rows that carry NEITHER marker, so a
// scenario that silently stopped inducing the fault fails rather than passes.

import { DEST_PROBE_FAULTS_KEY, INTEGRITY_FAULTS_KEY } from "../../src/admin/diag-records.ts";
import { readSchedDiag, recordFreshnessFault, type LedgerStorage } from "../../src/sched/sched-fault-ledger.ts";
import { SchedulerDO } from "../../src/sched/scheduler-do.ts";
import { MockStorage } from "../../test/mock-storage.ts";
import type { Scenario, World } from "./harness.ts";

const HOUR = 3_600_000;
type Dict = Record<string, unknown>;

/** The minimal two-method ledger storage `recordFreshnessFault` and `readSchedDiag` take. */
function memStorage(): LedgerStorage {
  const map = new Map<string, unknown>();
  return {
    async get<T>(k: string): Promise<T | undefined> {
      return map.get(k) as T | undefined;
    },
    async put<T>(k: string, v: T): Promise<void> {
      map.set(k, v);
    },
  };
}

/** The REAL DO over the in-memory storage double: every byte crosses the real route and the real writer. */
interface DiagDO {
  recordIntegrityFaults(b: { id?: unknown; snapshot?: unknown }): Promise<{ ok: true }>;
  recordDestProbeFaults(b: { rows?: unknown; refusedUpstream?: unknown }): Promise<{ ok: true }>;
}
function makeDO(): { dobj: DiagDO; storage: MockStorage } {
  const storage = new MockStorage();
  return { dobj: new SchedulerDO({ storage } as never) as unknown as DiagDO, storage };
}

// ---------------------------------------------------------------------------------------------------------
// Defect 8: the freshness-fault cap, driven past its edge through the real recorder.
//
// FLEET_SIZE is deliberately larger than FRESHNESS_FAULTS_CAP (50) and the faulting set is deliberately a
// PROPER SUBSET of the fleet, so the pack carries all three states at once: a downpipe whose staleness rule
// is known-unarmable, a downpipe whose status was REFUSED by the cap, and a healthy downpipe that must keep
// carrying neither field. Without the third the "no row lies" assertion would be vacuous.

const FLEET_SIZE = 60;
const FAULTING = 55; // 50 admitted, 5 refused
const dpId = (i: number): string => `dp-${String(i).padStart(4, "0")}`;

const freshnessDiag = await (async (): Promise<Dict> => {
  const s = memStorage();
  for (let i = 0; i < FAULTING; i++) await recordFreshnessFault(s, dpId(i), "cadence-malformed");
  return (await readSchedDiag(s)) as unknown as Dict;
})();

/** A roster of FLEET_SIZE downpipes, every one of them otherwise healthy and freshly run. */
function fleetRoster(now: number): Dict[] {
  return Array.from({ length: FLEET_SIZE }, (_, i) => ({
    config: {
      id: dpId(i),
      name: `pipe ${i}`,
      enabled: true,
      cadenceSeconds: 3600,
      source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "ns-uploads", include: ["uploads/*"], exclude: [] },
    },
    lastRunId: "01RUNOK",
    inFlight: false,
    nextRunAt: now + 30 * 60_000,
    cronResolve: { class: "ok", at: now + 30 * 60_000 },
    lastRestoreTestAt: now - 6 * HOUR,
    lastRestoreTestOk: true,
  }));
}

function rowsOf(b: Dict): Dict[] {
  return Array.isArray(b.downpipes) ? (b.downpipes as Dict[]) : [];
}
function rowFor(b: Dict, id: string): Dict | undefined {
  return rowsOf(b).find((r) => r.id === id);
}
function schedDiagOf(b: Dict): Dict {
  return (typeof b.schedDiag === "object" && b.schedDiag !== null ? b.schedDiag : {}) as Dict;
}
function subjectsFor(b: Dict, surface: string): { ids: string[]; incomplete: boolean } {
  const cts = schedDiagOf(b).capTruncationSubjects;
  const e = (typeof cts === "object" && cts !== null ? (cts as Dict)[surface] : undefined) as { ids?: unknown; incomplete?: unknown } | undefined;
  return {
    ids: Array.isArray(e?.ids) ? (e.ids as unknown[]).filter((v): v is string => typeof v === "string") : [],
    incomplete: e?.incomplete === true,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Defects 9 and 10, driven through the REAL DO routes.

const INTEGRITY_REFUSED = "acme-payroll-nightly";
const DEST_REFUSED = "acme-crown-jewels-offsite";
const SNAP = {
  cryptoFaults: [{ cls: "recipient-no-capsule-match", role: "operational", heldFingerprint: "0123456789ab", wantFingerprint: "ba9876543210" }],
  defaultedEmptyRecords: 1,
};

const { integrityDiag, integrityRecord } = await (async (): Promise<{ integrityDiag: Dict; integrityRecord: Dict }> => {
  const { dobj, storage } = makeDO();
  for (let i = 0; i < 100; i++) await dobj.recordIntegrityFaults({ id: dpId(i), snapshot: SNAP });
  await dobj.recordIntegrityFaults({ id: INTEGRITY_REFUSED, snapshot: SNAP }); // refused: the map is full
  return {
    integrityDiag: (await readSchedDiag(storage as unknown as LedgerStorage)) as unknown as Dict,
    integrityRecord: (await storage.get<Dict>(INTEGRITY_FAULTS_KEY)) ?? {},
  };
})();

const { destProbeDiag, destProbeRecord } = await (async (): Promise<{ destProbeDiag: Dict; destProbeRecord: Dict }> => {
  const { dobj, storage } = makeDO();
  // 70 rows against a 64 cap: cut one slices 6 away before the map is consulted. `refusedUpstream` is the
  // third cut, counted in the Worker's own cron accumulator, whose rows this DO never sees.
  const rows = [
    ...Array.from({ length: 69 }, (_, i) => ({ id: `dest-${String(i).padStart(4, "0")}`, reason: "auth" })),
    { id: DEST_REFUSED, reason: "auth" },
  ];
  await dobj.recordDestProbeFaults({ rows, refusedUpstream: 7 });
  return {
    destProbeDiag: (await readSchedDiag(storage as unknown as LedgerStorage)) as unknown as Dict,
    destProbeRecord: (await storage.get<Dict>(DEST_PROBE_FAULTS_KEY)) ?? {},
  };
})();

export const CAP_TRUNCATION_SCENARIOS: Scenario[] = [
  {
    id: "captrunc.freshness-past-cap-names-the-downpipe",
    title: "55 downpipes cannot compute staleness, the record holds 50, and the pack names the 5 it refused",
    domain: "sched",
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    mutate: (w: World): void => {
      const now = Date.now();
      w.routes["/downpipes"] = fleetRoster(now);
      w.routes["/sched-diag"] = freshnessDiag;
      // The history route keys by downpipe; the extra pipes simply have none, which is not what is under
      // test here and keeps the fault single.
    },
    capture: (b: Dict): string[] => {
      const f: string[] = [];
      const rows = rowsOf(b);
      const uncomputable = rows.filter((r) => r.freshnessComputable === false);
      const unknown = rows.filter((r) => r.freshnessComputableUnknown === true);
      const neither = rows.filter((r) => r.freshnessComputable === undefined && r.freshnessComputableUnknown === undefined);

      // THE POPULATION, asserted first: without these the three counts below are satisfiable by an empty pack.
      if (rows.length !== FLEET_SIZE) f.push(`population: expected ${FLEET_SIZE} downpipe rows, got ${rows.length}`);
      if (uncomputable.length !== 50) f.push(`population: expected 50 rows marked freshnessComputable:false, got ${uncomputable.length}`);
      if (neither.length !== FLEET_SIZE - FAULTING) f.push(`population: expected ${FLEET_SIZE - FAULTING} rows carrying NEITHER freshness field, got ${neither.length}`);

      // THE REPAIR: the downpipes past the cap no longer read as downpipes with a working staleness rule.
      if (unknown.length !== FAULTING - 50) f.push(`expected ${FAULTING - 50} rows marked freshnessComputableUnknown, got ${unknown.length}`);
      const past = rowFor(b, dpId(FAULTING - 1));
      if (past === undefined) f.push(`the downpipe past the cap (${dpId(FAULTING - 1)}) has no pack row at all`);
      else if (past.freshnessComputableUnknown !== true) f.push(`the downpipe past the cap reads as a downpipe with a working staleness rule (row: ${JSON.stringify(past.freshnessComputable ?? null)})`);

      // A downpipe INSIDE the cap keeps the KNOWN answer rather than being downgraded to the caveat.
      const inside = rowFor(b, dpId(0));
      if (inside?.freshnessComputable !== false) f.push(`a downpipe inside the cap lost its known freshnessComputable:false`);
      if (inside?.freshnessComputableUnknown !== undefined) f.push(`a downpipe inside the cap was downgraded to unknown over a known fact`);

      // AND THE PACK NAMES THE SUBJECT, which is the whole of this pass.
      const subj = subjectsFor(b, "freshness-faults");
      if (!subj.ids.includes(dpId(FAULTING - 1))) f.push(`capTruncationSubjects does not name the dropped downpipe (ids: ${JSON.stringify(subj.ids)})`);
      if (subj.ids.length !== FAULTING - 50) f.push(`expected ${FAULTING - 50} named dropped subjects, got ${subj.ids.length}`);
      if (subj.incomplete) f.push(`the subject list declares itself incomplete when every drop was nameable`);
      const trunc = schedDiagOf(b).capTruncations as Dict | undefined;
      const count = (trunc?.["freshness-faults"] as { count?: unknown } | undefined)?.count;
      if (count !== FAULTING - 50) f.push(`capTruncations count is ${String(count)}, expected ${FAULTING - 50}`);
      return f;
    },
  },
  {
    id: "captrunc.integrity-past-cap-names-the-downpipe",
    title: "the 101st downpipe to fail verification is refused, and the pack names which one",
    domain: "sched",
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    mutate: (w: World): void => {
      w.routes["/sched-diag"] = integrityDiag;
      w.routes["/integrity-faults"] = integrityRecord;
    },
    capture: (b: Dict): string[] => {
      const f: string[] = [];
      const rec = (typeof b.integrityFaults === "object" && b.integrityFaults !== null ? b.integrityFaults : {}) as Dict;
      // POPULATION: the record itself must be full, or "the refused one is named" proves nothing.
      if (Object.keys(rec).length !== 100) f.push(`population: expected 100 integrityFaults rows, got ${Object.keys(rec).length}`);
      if (Object.hasOwn(rec, INTEGRITY_REFUSED)) f.push(`the refused downpipe is present in the record, so nothing was refused`);
      const subj = subjectsFor(b, "integrity-faults-downpipe");
      if (!subj.ids.includes(INTEGRITY_REFUSED)) f.push(`capTruncationSubjects does not name the refused downpipe (ids: ${JSON.stringify(subj.ids.slice(0, 5))} of ${subj.ids.length})`);
      if (subj.ids.length === 0) f.push(`no subject named at all`);
      return f;
    },
  },
  {
    id: "captrunc.dest-probe-past-cap-names-the-destination",
    title: "a 70-destination probe batch past the 64 cap, with an upstream refusal that can never be named",
    domain: "sched",
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    mutate: (w: World): void => {
      w.routes["/sched-diag"] = destProbeDiag;
      w.routes["/dest-probe-faults"] = destProbeRecord;
    },
    capture: (b: Dict): string[] => {
      const f: string[] = [];
      const rec = (typeof b.destProbeFaults === "object" && b.destProbeFaults !== null ? b.destProbeFaults : {}) as Dict;
      if (Object.keys(rec).length !== 64) f.push(`population: expected 64 destProbeFaults rows, got ${Object.keys(rec).length}`);
      if (Object.hasOwn(rec, DEST_REFUSED)) f.push(`the refused destination is present in the record, so nothing was refused`);
      const subj = subjectsFor(b, "dest-probe-faults");
      if (!subj.ids.includes(DEST_REFUSED)) f.push(`capTruncationSubjects does not name the refused destination (ids: ${JSON.stringify(subj.ids.slice(0, 5))} of ${subj.ids.length})`);
      // THE HONESTY BIT: the Worker-side cron accumulator counts refusals whose ROWS never reach the DO, so
      // this surface MUST declare itself incomplete rather than let its named list read as the whole truth.
      if (!subj.incomplete) f.push(`an unnameable upstream refusal did not mark the subject list incomplete`);
      return f;
    },
  },
];

