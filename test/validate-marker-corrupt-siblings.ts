// validate-marker-corrupt-siblings: THREE MARKERS COERCE A CORRUPT RECORD TO ZERO AND ONLY ONE SAID SO.
//
// THE DEFECT THIS PINS. `readEmergencyChangeMarker` (scheduler-do-change-management.ts) reads a stored
// `{count,lastAt}` marker, coerces a PRESENT-but-malformed record to `count: 0`, and books
// `marker-corrupt-defaulted` for exactly that, with its own note naming the harm: "the compliance posture
// saying no emergency changes were raised about an account that raised them. The safe default is right; the
// silence is not."
//
// `getChangeControlRefusals` and `getConfigSnapshotHealth` performed the IDENTICAL coercion and booked
// nothing. Both are served to the support pack, over GET /change-control/refusals and
// GET /config-snapshot-health, and read by `fetchConfigIntegrity`.
//
// ZERO IS NOT ABSENCE, AND HERE IT IS WORSE THAN A LOW NUMBER: the pack surfaces both blocks ONLY when
// `count > 0`, so a coerced zero does not read as "few refusals", it makes the block VANISH. Measured before
// the repair: `fetchConfigIntegrity` returned `{}` for a clean account and `{}` for a corrupt marker at
// either site, with `unavailableProbes` EMPTY -- and `unavailableProbes` is the mechanism that function
// already carries to tell a faulted sub-read from a clean one. A throw was the only failure it could see; a
// defensive coercion answers 200 and is the quiet way to fail.
//
// AND THE CONFIG-SNAPSHOT SITE WAS WORSE THAN THE SHAPE IT WAS RECORDED AS, which is why this measures the
// premise rather than inheriting it. `autoSnapshotConfig` read the prior RAW -- trusting
// `storage.get<ConfigSnapshotFailureState>`, which is a type ASSERTION and not a check -- and then applied
// JavaScript's `+`: a stored count of `"7"` became `"71"`, then `"711"`. The record moved FURTHER from repair
// with every failure and the health read stayed at zero PERMANENTLY. `NaN` and `Infinity` latch the same way.
// Its two siblings (`bumpEmergencyMarker`, `bumpChangeControlRefusal`) bump through their validating reader
// and heal in one write. So "coerces exactly as readEmergencyChangeMarker does" is true of the READER and
// false of the SITE, and section E is the difference.
//
// THE REMEDY WAS ALREADY IN THE PRODUCT AND ALREADY USED AT THE SIBLING SITE, twice over, so nothing new is
// invented: `recordStorageAnomaly(storage, "marker-corrupt-defaulted")` in the DO, and `unavailableProbes`
// in the pack. The third repair is a DELETION of a raw read, not a new mechanism.
//
// THE STORAGE MOCK HERE IS STRUCTURED-CLONE, NOT JSON, AND THAT IS LOAD-BEARING. Durable Object storage is
// structured clone; `test/validate-scheduler-shared.ts`'s MockStorage round-trips through
// `JSON.parse(JSON.stringify(v))`, which turns `NaN` and `Infinity` into `null`, so a mock like that would
// report the NaN and Infinity doses as HEALED when only the instrument healed them. Section B asserts the
// difference directly, so a future move back to a JSON mock fails loudly here rather than quietly reporting a
// repair that was the mock's.
//
// TWO INSTRUMENT CONTROLS MUST HOLD BEFORE ANY ZERO BELOW IS A MEASUREMENT (sections A and B), and either
// failing REFUSES the run at exit 2 rather than reporting a pass.
//
// THE SENTINEL IS A VALUE THAT MUST BE REACHED, not an absence (section G): two DISTINCT coercions on ONE
// subject must arrive at `marker-corrupt-defaulted` = 2 through `fetchSchedDiag`, the projection the support
// pack itself takes. An assertion made only of absences holds over a blank page.
//
// Run: node test/validate-marker-corrupt-siblings.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { CHANGE_CONTROL_REFUSAL_KEY, CONFIG_SNAPSHOT_FAILURE_KEY } from "../src/sched/scheduler-do-base.ts";
import { STORAGE_ANOMALIES_KEY, type FaultCountAgg } from "../src/sched/sched-fault-ledger.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";
import { fetchConfigIntegrity } from "../src/admin/support-sections-config.ts";

declare const process: { exit(code?: number): never; exitCode?: number };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The emergency-change marker's key is module-private to scheduler-do-change-management.ts. It is repeated
// here as the literal the DO stores under, deliberately: this validator's whole subject is what a record
// PLANTED IN STORAGE does, so the plant has to name the key the way a corrupt byte would find it.
const EMERGENCY_CHANGE_MARKER_KEY = "change-emergency-marker";

// The sentinel a corrupt record could carry. A marker is a count and a timestamp, so there is no field for a
// value to travel in -- which is the claim section I proves rather than assumes.
const POISON = "victim@customer.example/sk-live-DEADBEEF";

// ---- storage: STRUCTURED CLONE, as the platform is (see the header) -------------------------------------
class CloneStorage {
  private map = new Map<string, unknown>();
  lastAlarmAt: number | null = null;
  async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
    if (Array.isArray(keyOrKeys)) {
      const out = new Map<string, T>();
      for (const k of keyOrKeys) {
        const hit = this.map.get(k);
        if (hit !== undefined) out.set(k, structuredClone(hit) as T);
      }
      return out;
    }
    const v = this.map.get(keyOrKeys);
    return v === undefined ? undefined : (structuredClone(v) as T);
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, structuredClone(value));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string }): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    for (const k of [...this.map.keys()].sort()) {
      if (opts?.prefix !== undefined && !k.startsWith(opts.prefix)) continue;
      out.set(k, this.map.get(k) as T);
    }
    return out;
  }
  async setAlarm(t: number): Promise<void> {
    this.lastAlarmAt = t;
  }
  async getAlarm(): Promise<number | null> {
    return this.lastAlarmAt;
  }
  raw(key: string): unknown {
    return this.map.get(key);
  }
}

interface Subject {
  storage: CloneStorage;
  stub: SchedulerDO;
}
// ONE FRESH SUBJECT PER DOSE, so no dose inherits another's ledger.
function subject(): Subject {
  const storage = new CloneStorage();
  return { storage, stub: new SchedulerDO({ storage } as unknown as DurableObjectState) };
}

// bumpChangeControlRefusal and readEmergencyChangeMarker are mixin methods that are NOT declared on
// SchedulerDOSurface (their callers are all inside their own mixin), so they are reached through a narrow
// cast rather than by widening the shared type surface for a test's benefit.
function refusalBumper(s: Subject): (kind: string) => Promise<void> {
  return (s.stub as unknown as { bumpChangeControlRefusal(kind: string): Promise<void> }).bumpChangeControlRefusal.bind(s.stub);
}

async function anomalyCount(storage: CloneStorage): Promise<number | undefined> {
  const agg = (await storage.get<FaultCountAgg>(STORAGE_ANOMALIES_KEY)) as FaultCountAgg | undefined;
  return agg?.["marker-corrupt-defaulted"]?.count;
}

function stubOf(s: Subject): DurableObjectStub {
  return { fetch: (u: string | Request, init?: RequestInit) => s.stub.fetch(new Request(u as string, init)) } as unknown as DurableObjectStub;
}

// Make every auto-snapshot capture FAIL, which is the real fault autoSnapshotConfig's counter exists to
// count. Returns the restore.
function plantSnapshotFailure(s: Subject): () => void {
  const real = (s.stub as unknown as { snapshotConfigNow: unknown }).snapshotConfigNow;
  (s.stub as unknown as { snapshotConfigNow: () => Promise<never> }).snapshotConfigNow = async () => {
    throw new Error(`planted snapshot failure ${POISON}`);
  };
  return () => {
    (s.stub as unknown as { snapshotConfigNow: unknown }).snapshotConfigNow = real;
  };
}

// The doses. WELL-FORMED, MALFORMED (nine shapes a corrupt read can take) and ABSENT.
const MALFORMED: { label: string; value: unknown }[] = [
  { label: "count is a STRING", value: { count: "7", lastAt: "2026-08-12T00:00:00.000Z" } },
  { label: "count is NaN", value: { count: Number.NaN, lastAt: "2026-08-12T00:00:00.000Z" } },
  { label: "count is Infinity", value: { count: Number.POSITIVE_INFINITY, lastAt: "2026-08-12T00:00:00.000Z" } },
  { label: "count is null", value: { count: null, lastAt: "2026-08-12T00:00:00.000Z" } },
  { label: "count is an object", value: { count: {}, lastAt: "2026-08-12T00:00:00.000Z" } },
  { label: "count key absent", value: { lastAt: "2026-08-12T00:00:00.000Z" } },
  { label: "the record is a bare number", value: 0 },
  { label: "the record is a bare string", value: `corrupt ${POISON}` },
  { label: "the record is an array", value: [1, 2, 3] },
];

// ---------------------------------------------------------------------------------------------------------
// A. THE INJECTION IS PROVEN BEFORE ANY ZERO IT REPORTS IS TRUSTED.
// A dose that never reaches the code reads exactly like a site that is already correct. So: the plant must
// change what the READER answers, at the site under test, before anything below counts.
// ---------------------------------------------------------------------------------------------------------
async function sectionInjection(): Promise<boolean> {
  console.log("\nA. known positive: the planted record REACHES the readers");
  const before = subject();
  const ccClean = await before.stub.getChangeControlRefusals();
  const csClean = await before.stub.getConfigSnapshotHealth();
  const a1 = ccClean.count === 0 && ccClean.coerced === undefined && csClean.count === 0 && csClean.coerced === undefined;
  ok("A1 an untouched subject answers 0 with NO coerced flag (the null dose)", a1);

  const wf = subject();
  await wf.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: 5, lastAt: "2026-08-12T00:00:00.000Z", lastActionKind: "dest-remove" });
  await wf.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: 5, lastAt: "2026-08-12T00:00:00.000Z" });
  const ccWf = await wf.stub.getChangeControlRefusals();
  const csWf = await wf.stub.getConfigSnapshotHealth();
  const a2 = ccWf.count === 5 && csWf.count === 5;
  ok("A2 a WELL-FORMED plant is read back as 5 at both sites (the dose reaches the code)", a2);

  const mf = subject();
  await mf.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: "7", lastAt: 42 });
  await mf.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: "7", lastAt: 42 });
  const ccMf = await mf.stub.getChangeControlRefusals();
  const csMf = await mf.stub.getConfigSnapshotHealth();
  const a3 = ccMf.count === 0 && csMf.count === 0;
  ok("A3 a MALFORMED plant is coerced to 0 at both sites (the coercion under test is live)", a3);
  return a1 && a2 && a3;
}

// ---------------------------------------------------------------------------------------------------------
// B. THE INSTRUMENT CONTROLS. The DECLARED sibling books on the same rig in the same session, so a zero from
// either site under test is attributable to that site rather than to a dead ledger. And the storage is
// faithful about NaN, which a JSON mock is not.
// ---------------------------------------------------------------------------------------------------------
async function sectionInstrument(): Promise<boolean> {
  console.log("\nB. instrument controls: the DECLARED sibling books, and the storage is structured-clone");
  const sib = subject();
  await sib.storage.put(EMERGENCY_CHANGE_MARKER_KEY, { count: `many ${POISON}`, lastAt: 42 });
  await (sib.stub as unknown as { readEmergencyChangeMarker: () => Promise<{ count: number }> }).readEmergencyChangeMarker();
  const b1 = (await anomalyCount(sib.storage)) === 1;
  ok("B1 readEmergencyChangeMarker (the DECLARED sibling, untouched by this change) books on this rig", b1);

  const b2 = Number.isNaN(structuredClone({ c: Number.NaN }).c) && structuredClone({ c: Number.POSITIVE_INFINITY }).c === Number.POSITIVE_INFINITY;
  ok("B2 the mock preserves NaN and Infinity, as DO structured clone does (a JSON mock nulls both)", b2);
  const b3 = JSON.parse(JSON.stringify({ c: Number.NaN })).c === null;
  ok("B3 and a JSON round-trip demonstrably does NOT, which is why B2 is asserted rather than assumed", b3);

  const rt = subject();
  await rt.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: Number.NaN, lastAt: "x" });
  const b4 = Number.isNaN((rt.storage.raw(CONFIG_SNAPSHOT_FAILURE_KEY) as { count: number }).count);
  ok("B4 a planted NaN survives the put/get round trip in this rig", b4);
  return b1 && b2 && b3 && b4;
}

// ---------------------------------------------------------------------------------------------------------
// C. DOSE-RESPONSE, BOTH TREES IN ONE SESSION, DISTINCT SUBJECTS. The declaration is recorded for every dose.
// ---------------------------------------------------------------------------------------------------------
async function sectionDoseResponse(): Promise<void> {
  console.log("\nC. dose-response over well-formed, malformed and absent, both sites, one subject per dose");
  for (const d of MALFORMED) {
    const cc = subject();
    await cc.storage.put(CHANGE_CONTROL_REFUSAL_KEY, d.value);
    const ccR = await cc.stub.getChangeControlRefusals();
    ok(`C-cc ${d.label}: coerced to 0, coerced:true, and ONE anomaly booked`, ccR.count === 0 && ccR.coerced === true && (await anomalyCount(cc.storage)) === 1);

    const cs = subject();
    await cs.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, d.value);
    const csR = await cs.stub.getConfigSnapshotHealth();
    ok(`C-cs ${d.label}: coerced to 0, coerced:true, and ONE anomaly booked`, csR.count === 0 && csR.coerced === true && (await anomalyCount(cs.storage)) === 1);
  }
  for (const n of [1, 2, 7, 1000, 2_000_000_000]) {
    const cc = subject();
    await cc.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: n, lastAt: "2026-08-12T00:00:00.000Z" });
    const ccR = await cc.stub.getChangeControlRefusals();
    const cs = subject();
    await cs.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: n, lastAt: "2026-08-12T00:00:00.000Z" });
    const csR = await cs.stub.getConfigSnapshotHealth();
    ok(`C-wf a well-formed count of ${n} reads back exactly, books NOTHING, and carries no flag`,
      ccR.count === n && csR.count === n && ccR.coerced === undefined && csR.coerced === undefined &&
      (await anomalyCount(cc.storage)) === undefined && (await anomalyCount(cs.storage)) === undefined);
  }
}

// ---------------------------------------------------------------------------------------------------------
// D. THE BOUNDARY, WHERE THE THREE VALUES THAT HAVE EACH BEEN A SEPARATE DEFECT TODAY ARE SEPARATED BY NAME:
// ABSENT (no record at all), ZERO (a record that reads zero) and INVERTED (a record below zero). The first
// must stay silent; the other two must not.
// ---------------------------------------------------------------------------------------------------------
async function sectionBoundary(): Promise<void> {
  console.log("\nD. the boundary: ABSENT is not ZERO, and neither is INVERTED");
  const absent = subject();
  const ccA = await absent.stub.getChangeControlRefusals();
  const csA = await absent.stub.getConfigSnapshotHealth();
  ok("D1 ABSENT: no record at either site books NOTHING (an honest absence stays an honest absence)",
    ccA.count === 0 && csA.count === 0 && ccA.coerced === undefined && csA.coerced === undefined && (await anomalyCount(absent.storage)) === undefined);
  ok("D2 ABSENT: and the ledger key is not merely zero, it is not present at all", (await absent.storage.get(STORAGE_ANOMALIES_KEY)) === undefined);

  const zero = subject();
  await zero.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: 0, lastAt: null });
  const ccZ = await zero.stub.getChangeControlRefusals();
  // A stored ZERO is flagged, and deliberately: no writer in the engine ever stores one (every bump writes
  // the read count plus one, so the smallest value any writer can produce is 1). A zero on disk therefore did
  // not come from the engine, which is the same statement as a malformed value. This is the DECLARED
  // sibling's behaviour too, unchanged by this pass, and it is asserted here so the three agree by test
  // rather than by claim.
  ok("D3 ZERO: a stored count of 0 is flagged, exactly as the declared sibling flags it", ccZ.count === 0 && ccZ.coerced === true && (await anomalyCount(zero.storage)) === 1);
  const zeroSib = subject();
  await zeroSib.storage.put(EMERGENCY_CHANGE_MARKER_KEY, { count: 0, lastAt: null });
  await (zeroSib.stub as unknown as { readEmergencyChangeMarker: () => Promise<unknown> }).readEmergencyChangeMarker();
  ok("D4 ZERO: and the declared sibling agrees, which is what makes D3 consistency and not a new rule", (await anomalyCount(zeroSib.storage)) === 1);

  const inverted = subject();
  await inverted.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: -4, lastAt: "2026-08-12T00:00:00.000Z" });
  const csI = await inverted.stub.getConfigSnapshotHealth();
  ok("D5 INVERTED: a NEGATIVE count is flagged rather than read as a small number", csI.count === 0 && csI.coerced === true && (await anomalyCount(inverted.storage)) === 1);

  // The smallest well-formed value must NOT be flagged: the edge is at 0, from both sides.
  const one = subject();
  await one.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: 1, lastAt: "2026-08-12T00:00:00.000Z" });
  const csO = await one.stub.getConfigSnapshotHealth();
  ok("D6 the edge from the other side: a count of exactly 1 reads 1, is not flagged, and books nothing",
    csO.count === 1 && csO.coerced === undefined && (await anomalyCount(one.storage)) === undefined);

  // A fractional count is a real value expressed wrongly: floored, not discarded.
  const frac = subject();
  await frac.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: 3.7, lastAt: "2026-08-12T00:00:00.000Z" });
  const csF = await frac.stub.getConfigSnapshotHealth();
  ok("D7 a fractional count floors to 3 and is NOT flagged (it is legible, not lost)", csF.count === 3 && csF.coerced === undefined);
}

// ---------------------------------------------------------------------------------------------------------
// E. THE LATCH. The config-snapshot WRITER did not go through its reader, so a malformed count was carried into
// JavaScript's `+` and the record got further from repair with every real failure. Ten REAL failures against
// each malformed seed must now arrive at exactly ten, and the stored count must be a finite number.
// ---------------------------------------------------------------------------------------------------------
async function sectionLatch(): Promise<void> {
  console.log("\nE. the latch: ten REAL auto-snapshot failures must reach ten from every malformed seed");
  for (const d of [...MALFORMED, { label: "count is a boolean", value: { count: true, lastAt: "x" } }, { label: "count is NEGATIVE", value: { count: -4, lastAt: "x" } }]) {
    const s = subject();
    await s.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, d.value);
    const restore = plantSnapshotFailure(s);
    for (let i = 0; i < 10; i++) await s.stub.autoSnapshotConfig(null);
    restore();
    const health = await s.stub.getConfigSnapshotHealth();
    const raw = s.storage.raw(CONFIG_SNAPSHOT_FAILURE_KEY) as { count: unknown };
    ok(`E ${d.label}: reads 10 after ten real failures, and the stored count is a finite number`,
      health.count === 10 && typeof raw.count === "number" && Number.isFinite(raw.count));
  }
  // And the sibling writer, which always went through its reader, is unchanged by this fix.
  const cc = subject();
  await cc.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: "7", lastAt: "x" });
  const bump = refusalBumper(cc);
  for (let i = 0; i < 10; i++) await bump("dest-remove");
  ok("E-sib bumpChangeControlRefusal reaches 10 too (it always healed; the two sites now agree)", (await cc.stub.getChangeControlRefusals()).count === 10);
}

// ---------------------------------------------------------------------------------------------------------
// F. WHAT THE SUPPORT PACK SAYS, which is the whole reason the silence mattered. A corrupt account and a
// clean one must NOT produce the same configIntegrity, and the probe that could not answer must be NAMED.
// ---------------------------------------------------------------------------------------------------------
async function sectionPack(): Promise<void> {
  console.log("\nF. the support pack: a corrupt account must not read as a clean one");
  const clean = subject();
  const packClean = await fetchConfigIntegrity(stubOf(clean));
  ok("F1 a clean account still carries NOTHING (the honest absence is preserved)", JSON.stringify(packClean) === "{}");

  const ccCorrupt = subject();
  await ccCorrupt.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: `many ${POISON}`, lastAt: 42 });
  const packCc = await fetchConfigIntegrity(stubOf(ccCorrupt));
  ok("F2 a corrupt change-control marker is NOT byte-identical to a clean account", JSON.stringify(packCc) !== JSON.stringify(packClean));
  ok("F3 and the pack NAMES the probe that could not answer", (packCc.unavailableProbes as string[] | undefined)?.includes("change-control-refusals") === true);

  const csCorrupt = subject();
  await csCorrupt.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: Number.NaN, lastAt: null });
  const packCs = await fetchConfigIntegrity(stubOf(csCorrupt));
  ok("F4 a corrupt config-snapshot marker is NOT byte-identical to a clean account", JSON.stringify(packCs) !== JSON.stringify(packClean));
  ok("F5 and the pack names config-snapshot specifically, not merely 'something'", (packCs.unavailableProbes as string[] | undefined)?.includes("config-snapshot") === true);

  const both = subject();
  await both.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: "x", lastAt: 42 });
  await both.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: {}, lastAt: 42 });
  const packBoth = await fetchConfigIntegrity(stubOf(both));
  ok("F6 both corrupt: both probes are named", (packBoth.unavailableProbes as string[] | undefined)?.length === 2);

  // The positive direction, so F is not made only of unavailability: a GENUINE tally still surfaces as a
  // count, with no probe marked unavailable.
  const real = subject();
  await real.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: 3, lastAt: "2026-08-12T00:00:00.000Z", lastActionKind: "dest-remove" });
  await real.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: 2, lastAt: "2026-08-12T00:00:00.000Z" });
  const packReal = await fetchConfigIntegrity(stubOf(real));
  ok("F7 a GENUINE tally still surfaces its counts and marks nothing unavailable",
    (packReal.changeControlRefusals as { count: number } | undefined)?.count === 3 &&
    (packReal.snapshotFailures as { count: number } | undefined)?.count === 2 &&
    packReal.unavailableProbes === undefined);
}

// ---------------------------------------------------------------------------------------------------------
// G. THE SENTINEL THAT MUST BE REACHED. Two DISTINCT coercions on ONE subject must arrive at the value 2
// through fetchSchedDiag, the projection the support pack itself takes -- following the declaration all the
// way to the reader rather than stopping at the ledger. A blank page cannot satisfy this.
// ---------------------------------------------------------------------------------------------------------
async function sectionSentinel(): Promise<void> {
  console.log("\nG. the declaration reaches the PACK PROJECTOR, at a value that must be REACHED");
  const s = subject();
  await s.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: "7", lastAt: 42 });
  await s.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: Number.NaN, lastAt: 42 });
  await s.stub.getChangeControlRefusals();
  await s.stub.getConfigSnapshotHealth();
  ok("G1 two distinct coercions accumulate to 2 in the ledger", (await anomalyCount(s.storage)) === 2);

  const diag = await fetchSchedDiag(stubOf(s));
  const sa = diag.storageAnomalies as Record<string, { count: number; lastAt: string }> | undefined;
  ok("G2 the pack projection carries storageAnomalies at all", sa !== undefined);
  ok("G3 SENTINEL: the pack reader reports marker-corrupt-defaulted = 2 (a value that must be REACHED)", sa?.["marker-corrupt-defaulted"]?.count === 2);
  ok("G4 the projected row carries a parseable instant", typeof sa?.["marker-corrupt-defaulted"]?.lastAt === "string" && !Number.isNaN(Date.parse(sa!["marker-corrupt-defaulted"]!.lastAt)));
}

// ---------------------------------------------------------------------------------------------------------
// H. OVER-FIX NEGATIVES. The repair must not turn a healthy account noisy, and it must not persist the
// read-side flag into storage where a later read would see it as data.
// ---------------------------------------------------------------------------------------------------------
async function sectionOverFix(): Promise<void> {
  console.log("\nH. over-fix negatives: a healthy account must stay silent, and the flag must never be STORED");
  const busy = subject();
  const restore = plantSnapshotFailure(busy);
  for (let i = 0; i < 25; i++) await busy.stub.autoSnapshotConfig(null);
  restore();
  const bumpBusy = refusalBumper(busy);
  for (let i = 0; i < 25; i++) await bumpBusy("dest-remove");
  ok("H1 fifty REAL faults on a virgin account book ZERO coercions (the counter is not a fault counter)", (await anomalyCount(busy.storage)) === undefined);
  ok("H2 and both tallies are right: 25 and 25", (await busy.stub.getConfigSnapshotHealth()).count === 25 && (await busy.stub.getChangeControlRefusals()).count === 25);
  const rawCs = busy.storage.raw(CONFIG_SNAPSHOT_FAILURE_KEY) as Record<string, unknown>;
  const rawCc = busy.storage.raw(CHANGE_CONTROL_REFUSAL_KEY) as Record<string, unknown>;
  ok("H3 the read-side coerced flag is NEVER written to storage at either site", !("coerced" in rawCs) && !("coerced" in rawCc));

  // Repeated reads of the SAME corrupt record book once per read, not once ever: the count is of coerced
  // READS, which is what makes a record that stays corrupt visible as a rising number rather than a stale 1.
  const rep = subject();
  await rep.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: "7", lastAt: 42 });
  await rep.stub.getChangeControlRefusals();
  await rep.stub.getChangeControlRefusals();
  await rep.stub.getChangeControlRefusals();
  ok("H4 three reads of one corrupt record book three coercions (a coerced READ is the unit)", (await anomalyCount(rep.storage)) === 3);

  // And the healed record stops booking, so the counter does not stick on after the repair took effect.
  const healed = subject();
  await healed.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: "7", lastAt: 42 });
  const r2 = plantSnapshotFailure(healed);
  await healed.stub.autoSnapshotConfig(null);
  r2();
  const afterFirst = await anomalyCount(healed.storage);
  await healed.stub.getConfigSnapshotHealth();
  await healed.stub.getConfigSnapshotHealth();
  ok("H5 once the write has healed the record, further reads book NOTHING more", (await anomalyCount(healed.storage)) === afterFirst);
}

// ---------------------------------------------------------------------------------------------------------
// I. REDACTION. The corrupt value is by definition arbitrary bytes and could hold anything, so a sentinel is
// planted IN the corrupt record and IN the throw the snapshot failure raises, and the whole evidence surface
// is scanned for it.
// ---------------------------------------------------------------------------------------------------------
async function sectionRedaction(): Promise<void> {
  console.log("\nI. redaction: the corrupt value never rides on the evidence");
  const s = subject();
  await s.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: `many ${POISON}`, lastAt: POISON, lastActionKind: POISON });
  await s.storage.put(CONFIG_SNAPSHOT_FAILURE_KEY, { count: [POISON], lastAt: POISON });
  const cc = await s.stub.getChangeControlRefusals();
  const cs = await s.stub.getConfigSnapshotHealth();
  const restore = plantSnapshotFailure(s);
  await s.stub.autoSnapshotConfig(null);
  restore();
  const diag = await fetchSchedDiag(stubOf(s));
  const pack = await fetchConfigIntegrity(stubOf(s));
  ok("I1 the coerced reader returns no planted value", !JSON.stringify(cc).includes(POISON) && !JSON.stringify(cs).includes(POISON));
  ok("I2 the anomaly ledger projection carries no planted value", !JSON.stringify(diag.storageAnomalies ?? {}).includes(POISON));
  ok("I3 the configIntegrity block carries no planted value", !JSON.stringify(pack).includes(POISON));
  ok("I4 nor does the whole sched-diag bundle", !JSON.stringify(diag).includes(POISON));
  // `lastAt` was gated on being a NON-EMPTY STRING and `lastActionKind` on LENGTH ALONE, so a corrupt record's
  // arbitrary bytes could be returned verbatim by a method whose own contract says it "never returns an
  // operator value". A coerced record's qualifiers are dropped, and `lastAt` is gated on PARSING at both sites.
  ok("I5 a coerced read carries NO lastAt and NO lastActionKind (they came from the rejected record)",
    cc.lastAt === null && cc.lastActionKind === undefined && cs.lastAt === null);
  const skew = subject();
  await skew.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: 5, lastAt: `not-a-timestamp ${POISON}`, lastActionKind: "dest-remove" });
  const skewR = await skew.stub.getChangeControlRefusals();
  ok("I6 an UNPARSEABLE lastAt beside a well-formed count reads as absent, not verbatim", skewR.count === 5 && skewR.lastAt === null && !JSON.stringify(skewR).includes(POISON));
  const good = subject();
  await good.storage.put(CHANGE_CONTROL_REFUSAL_KEY, { count: 5, lastAt: "2026-08-12T00:00:00.000Z", lastActionKind: "dest-remove" });
  const goodR = await good.stub.getChangeControlRefusals();
  ok("I7 and a GENUINE instant still survives, so I6 is a gate and not a deletion", goodR.lastAt === "2026-08-12T00:00:00.000Z" && goodR.lastActionKind === "dest-remove");
}

async function main(): Promise<void> {
  const injectionOk = await sectionInjection();
  const instrumentOk = await sectionInstrument();
  if (!injectionOk || !instrumentOk) {
    console.log("\nREFUSED: the injection or an instrument control did not hold, so no zero below is a measurement");
    if (1 > 0) process.exitCode = 1;
    process.exit(2);
  }
  await sectionDoseResponse();
  await sectionBoundary();
  await sectionLatch();
  await sectionPack();
  await sectionSentinel();
  await sectionOverFix();
  await sectionRedaction();
  console.log(failures === 0 ? "\nMARKER CORRUPT SIBLINGS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exit(1);
}

void main();
