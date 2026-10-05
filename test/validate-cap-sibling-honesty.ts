// validate-cap-sibling-honesty.ts
//
// THE TWO SIBLINGS below share one shape: a SUBJECT-KEYED MAP THAT REFUSES A NEW SUBJECT rather than
// evicting an old one. A ring is honest
// about being recent; a map that refuses a new subject loses a DIFFERENT SUBJECT ENTIRELY, and a subject
// absent from a FAULT record is read as a subject with no fault. The absence states the opposite of the
// truth, which is why the defect is never the cap.
//
//   applyIntegrityFaults, per DOWNPIPE at 100. A systematic verification fault -- a mis-provisioned wrap
//   key, a format drift -- reaches the whole fleet at once rather than one downpipe at a time, so the record
//   that answers "which downpipes failed verification" reported exactly 100 and the 101st read as verified.
//
//   applyDestProbeFaults, per DESTINATION, at THREE cuts and all three silent: the cron accumulator refuses
//   a new destination in the isolate before the DO is ever called, the DO writer slices the posted batch,
//   and the map then refuses a new destination. This is the record that answers "all destinations
//   unreachable" by naming a cause for EACH one, so its cap bites in exactly the state it was built for.
//   "Needs a mass-failure state to reach" is not a mitigation here: the mass-failure state is the design
//   point.
//
// THE 32/64 DISAGREEMENT, SETTLED FROM HARM RATHER THAN TIDINESS. Two caps bound the same subject space --
// the estate's destinations -- and they disagreed. `recordControlPlaneExportHealth` slices perDest at 64 and
// DECLARES the drop; this one refused at 32 and said nothing. Nothing in the product caps how many
// destinations an estate may hold, so that 64 is the only statement the product makes about the size of a
// destination fleet. 64 costs a few kilobytes of DO storage; 32 costs a total outage diagnosed as a partial
// one. All three cuts share the same number, so a future raise at one of them cannot re-open a second
// undeclared cut on the path.
//
// THE CONTROLS, and what each is for:
//   - DOSE-RESPONSE over DISTINCT subjects through the REAL DO recorder and the REAL pack projector, at
//     0/1/cap-1/cap/cap+1/mid/far-past on both trees.
//   - THE EDGE, EXACTLY: at the cap the capTruncations KEY IS ABSENT, not a zero. That distinction was the
//     whole of the eighth defect.
//   - POSITION CONTROL: what IS recorded must not move with the dose (the closed reason, the fold count, the
//     clamped label, a parseable stamp).
//   - DIFFERENTIAL CONTROL, TWICE. `applySourceFaults` is the same per-downpipe subject-map shape in this
//     engine and ADMITS a new subject past its cap by evicting the oldest, so refusing one is a choice
//     rather than a house convention. And `recordControlPlaneExportHealth` caps the SAME SUBJECT SPACE --
//     destinations -- and has declared its drop all along, which is what makes the disagreement a finding.
//   - INSTRUMENT CONTROL: a surface already declared elsewhere books through this same rig and this same
//     ledger reader. Without a known positive, a zero from the reader is not a result: a reader that reports
//     zero undeclared refusals could equally be broken, so an instrument is assumed broken until a known
//     positive proves otherwise.
//   - REACHABILITY, MEASURED RATHER THAN INHERITED: the bulk create path admits exactly the integrity cap in
//     ONE request, and all three destination cuts agree so none is silently narrower than the declared one.
//   - NEGATIVE CONTROLS THAT MUST CLASSIFY DIFFERENTLY: a VOCABULARY drop is not a CAPACITY drop and must
//     not be declared as one; a malformed snapshot is not a truncation; a fleet under the cap declares
//     nothing at all.
//   - THE PACK, THROUGH ITS OWN READER: a surface booked but not REGISTERED would be dropped again on the
//     read path, because fetchSchedDiag gates capTruncations against the closed surface set.
//   - THE SUBJECT: a count says N ROWS WERE DROPPED and not WHICH, and a
//     reader holding one of these subject-keyed maps needs the name. Both refusal sites already hold it. The
//     surface that CANNOT name every drop -- dest-probe, because the upstream accumulator counts refusals
//     whose rows never reach the DO -- declares itself INCOMPLETE rather than looking enumerated.
//   - REDACTION: both capped maps are keyed by the CUSTOMER'S OWN label. The COUNT ledger is still a count
//     and still names no row; the SUBJECT ledger carries the id and nothing beside it, and that id is
//     byte-identical to the key the map itself would have used, so a refusal discloses no class an
//     admission does not.
//
// Run: node test/validate-cap-sibling-honesty.ts

import {
  applyDestProbeFaultsCounted,
  applyIntegrityFaultsCounted,
  DEST_PROBE_FAULTS_CAP,
  DEST_PROBE_FAULTS_KEY,
  INTEGRITY_FAULTS_DOWNPIPE_CAP,
  INTEGRITY_FAULTS_KEY,
} from "../src/admin/diag-records.ts";
import { applySourceFaults, RUN_FAULT_DOWNPIPES_MAX } from "../src/admin/run-fault-records.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";
import { fetchDestProbeFaults, fetchIntegrityFaults } from "../src/admin/support-sections-faults.ts";
import { DEST_PROBE_MAX, drainCronDestProbeFaults, noteDestProbeFault, resetCronFaultLedger } from "../src/cron/cron-fault-ledger.ts";
import { BULK_DOWNPIPES_MAX } from "../src/sched/config-validate.ts";
import { CAP_TRUNCATION_SUBJECTS_KEY, CAP_TRUNCATION_SURFACES, CAP_TRUNCATIONS_KEY } from "../src/sched/sched-fault-ledger.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

declare const process: { exit(code?: number): never };

let checks = 0;
let failures = 0;
function ok(label: string, pass: boolean): void {
  checks++;
  if (!pass) failures++;
  console.log(`  ${pass ? "ok  " : "FAIL"}  ${label}`);
}

// The POISON labels planted as a downpipe id and a destination id: the customer's own names. The COUNT
// declarations may never carry them; the SUBJECT ledger must, because naming the refused key is the repair.
const POISON_DOWNPIPE = "acme-payroll-nightly";
const POISON_DEST = "acme-crown-jewels-offsite";

type CountAgg = Record<string, { count: number; lastAt: string }>;

interface DiagDO {
  recordIntegrityFaults(b: { id?: unknown; snapshot?: unknown }): Promise<{ ok: true }>;
  recordDestProbeFaults(b: { rows?: unknown; refusedUpstream?: unknown }): Promise<{ ok: true }>;
  recordControlPlaneExportHealth(h: unknown): Promise<void>;
  fetch(r: Request): Promise<Response>;
}

// The REAL DO over the shared in-memory storage double. The stub adapter exists only because the DO's own
// fetch takes a Request while the pack projector calls stub.fetch(url, init): every byte still crosses the
// real route and the real projector.
function makeDO(): { dobj: DiagDO; stub: { fetch(i: unknown, init?: unknown): Promise<Response> }; storage: MockStorage } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as never) as unknown as DiagDO;
  return { dobj, stub: { fetch: (i: unknown, init?: unknown) => dobj.fetch(new Request(String(i), init as RequestInit)) }, storage };
}

// truncAgg reads the WHOLE ledger key, so "the key is absent" and "the key is present holding a zero" are
// distinguishable. They were not distinguishable in the eighth defect and that was the whole of it.
async function truncAgg(storage: MockStorage): Promise<CountAgg | undefined> {
  return await storage.get<CountAgg>(CAP_TRUNCATIONS_KEY);
}

// ONE integrity snapshot: a real crypto-provisioning fault, which is the SYSTEMATIC kind -- a rotated wrap
// key writes this onto every downpipe in the fleet on the same pass, not onto the unlucky hundredth.
const SNAP = {
  cryptoFaults: [{ cls: "recipient-no-capsule-match", role: "operational", heldFingerprint: "0123456789ab", wantFingerprint: "ba9876543210" }],
  defaultedEmptyRecords: 1,
};

async function doseIntegrity(n: number): Promise<{ rows: number; projected: number; declared: number | undefined; keyPresent: boolean; newestInPack: boolean; storage: MockStorage }> {
  const { dobj, stub, storage } = makeDO();
  for (let i = 0; i < n; i++) await dobj.recordIntegrityFaults({ id: `dp-${String(i).padStart(4, "0")}`, snapshot: SNAP });
  const rec = (await storage.get<Record<string, unknown>>(INTEGRITY_FAULTS_KEY)) ?? {};
  const projected = await fetchIntegrityFaults(stub as never);
  const agg = await truncAgg(storage);
  return {
    rows: Object.keys(rec).length,
    projected: Object.keys(projected).length,
    declared: agg?.["integrity-faults-downpipe"]?.count,
    keyPresent: agg !== undefined,
    newestInPack: n > 0 && Object.hasOwn(projected, `dp-${String(n - 1).padStart(4, "0")}`),
    storage,
  };
}

// n distinct destinations posted as ONE batch, which is exactly the shape the cron drain posts.
async function doseDest(n: number): Promise<{ rows: number; projected: number; declared: number | undefined; keyPresent: boolean; newestInPack: boolean; storage: MockStorage }> {
  const { dobj, stub, storage } = makeDO();
  const rows = Array.from({ length: n }, (_, i) => ({ id: `dest-${String(i).padStart(4, "0")}`, reason: "auth" }));
  await dobj.recordDestProbeFaults({ rows });
  const rec = (await storage.get<Record<string, unknown>>(DEST_PROBE_FAULTS_KEY)) ?? {};
  const projected = await fetchDestProbeFaults(stub as never);
  const agg = await truncAgg(storage);
  return {
    rows: Object.keys(rec).length,
    projected: Object.keys(projected).length,
    declared: agg?.["dest-probe-faults"]?.count,
    keyPresent: agg !== undefined,
    newestInPack: n > 0 && Object.hasOwn(projected, `dest-${String(n - 1).padStart(4, "0")}`),
    storage,
  };
}

const IC = INTEGRITY_FAULTS_DOWNPIPE_CAP;
const DC = DEST_PROBE_FAULTS_CAP;

console.log("cap-sibling honesty: the two subject-keyed maps that refused a NEW subject\n");

// ---- THE SURFACES ARE REGISTERED AT ALL ----------------------------------------------------------
console.log("THE SURFACES:");
ok("`integrity-faults-downpipe` is a member of the closed capTruncation surface vocabulary", (CAP_TRUNCATION_SURFACES as readonly string[]).includes("integrity-faults-downpipe"));
ok("`dest-probe-faults` is a member of the closed capTruncation surface vocabulary", (CAP_TRUNCATION_SURFACES as readonly string[]).includes("dest-probe-faults"));

// ---- DOSE-RESPONSE: the per-downpipe integrity record ---------------------------------------------
console.log("\nDOSE-RESPONSE A (distinct FAULTING DOWNPIPES -> rows recorded / rows declared dropped):");
for (const n of [0, 1, IC - 1, IC, IC + 1, 150, 300]) {
  const r = await doseIntegrity(n);
  const expectRows = Math.min(n, IC);
  const expectDeclared = Math.max(0, n - IC);
  console.log(`   dose ${String(n).padStart(4)}  rows ${String(r.rows).padStart(4)}  projected ${String(r.projected).padStart(4)}  declared ${r.declared ?? (r.keyPresent ? "0(present)" : "ABSENT")}`);
  ok(`integrity dose ${n}: the record holds ${expectRows} downpipes`, r.rows === expectRows);
  ok(`integrity dose ${n}: the pack is told ${expectDeclared} downpipes were dropped`, (r.declared ?? 0) === expectDeclared);
  ok(`integrity dose ${n}: the pack projector carries the same ${expectRows} rows (no second cut on the read path)`, r.projected === expectRows);
}

// ---- DOSE-RESPONSE: the per-destination probe record ----------------------------------------------
console.log("\nDOSE-RESPONSE B (distinct FAILING DESTINATIONS -> rows recorded / rows declared dropped):");
for (const n of [0, 1, 40, DC - 1, DC, DC + 1, 100]) {
  const r = await doseDest(n);
  const expectRows = Math.min(n, DC);
  const expectDeclared = Math.max(0, n - DC);
  console.log(`   dose ${String(n).padStart(4)}  rows ${String(r.rows).padStart(4)}  projected ${String(r.projected).padStart(4)}  declared ${r.declared ?? (r.keyPresent ? "0(present)" : "ABSENT")}`);
  ok(`dest dose ${n}: the record holds ${expectRows} destinations`, r.rows === expectRows);
  ok(`dest dose ${n}: the pack is told ${expectDeclared} destination rows were dropped`, (r.declared ?? 0) === expectDeclared);
  ok(`dest dose ${n}: the pack projector carries the same ${expectRows} rows (no second cut on the read path)`, r.projected === expectRows);
}

// ---- THE EDGE, AND THE ABSENT-VERSUS-ZERO DISTINCTION --------------------------------------------
console.log("\nTHE EDGE (absent is not zero: that distinction WAS the eighth defect):");
const iAt = await doseIntegrity(IC);
const iOver = await doseIntegrity(IC + 1);
ok(`at exactly ${IC} downpipes the capTruncations KEY IS ABSENT, not a zero`, (await truncAgg(iAt.storage)) === undefined);
ok(`one downpipe past ${IC} declares exactly one dropped row`, iOver.declared === 1);
ok(`and the downpipe past ${IC} is genuinely ABSENT from the pack, which is why the declaration is needed`, iAt.newestInPack && !iOver.newestInPack);
const dAt = await doseDest(DC);
const dOver = await doseDest(DC + 1);
ok(`at exactly ${DC} destinations the capTruncations KEY IS ABSENT, not a zero`, (await truncAgg(dAt.storage)) === undefined);
ok(`one destination past ${DC} declares exactly one dropped row`, dOver.declared === 1);
ok(`and the destination past ${DC} is genuinely ABSENT from the pack`, dAt.newestInPack && !dOver.newestInPack);

// ---- THE THIRD CUT: the in-isolate cron accumulator, upstream of the DO ---------------------------
console.log("\nTHE UPSTREAM CUT (a destination refused HERE never reaches the DO by any route):");
resetCronFaultLedger();
for (let i = 0; i < DEST_PROBE_MAX + 36; i++) noteDestProbeFault(`dest-${String(i).padStart(4, "0")}`, new Error("PUT: status 403 AccessDenied"));
const drained = drainCronDestProbeFaults();
ok(`the accumulator holds exactly ${DEST_PROBE_MAX} destinations`, drained.rows.length === DEST_PROBE_MAX);
ok("and it REPORTS the 36 it refused, rather than the count dying in the isolate", drained.refusedUpstream === 36);
{
  const { dobj, storage } = makeDO();
  await dobj.recordDestProbeFaults({ rows: drained.rows, refusedUpstream: drained.refusedUpstream });
  ok("posted with the rows, the upstream refusal lands in the SAME surface count", (await truncAgg(storage))?.["dest-probe-faults"]?.count === 36);
}
resetCronFaultLedger();
for (let i = 0; i < 3; i++) noteDestProbeFault(`dest-${i}`, new Error("timeout"));
const small = drainCronDestProbeFaults();
ok("a fleet under the accumulator's bound reports no refusal at all", small.rows.length === 3 && small.refusedUpstream === 0);
ok("and the drain CLEARS the count, so the next invocation cannot inherit it", drainCronDestProbeFaults().refusedUpstream === 0);

// ---- POSITION CONTROL ----------------------------------------------------------------------------
console.log("\nPOSITION CONTROL (the dose must not move what IS recorded):");
{
  const { dobj, stub, storage } = makeDO();
  for (let i = 0; i < 300; i++) await dobj.recordIntegrityFaults({ id: `dp-${String(i).padStart(4, "0")}`, snapshot: SNAP });
  const rec = (await storage.get<Record<string, { cryptoFaults?: unknown[]; defaultedEmptyRecords?: number; at?: number }>>(INTEGRITY_FAULTS_KEY)) ?? {};
  ok("a downpipe inside the cap keeps its crypto fault row", Array.isArray(rec["dp-0000"]?.cryptoFaults) && rec["dp-0000"].cryptoFaults.length === 1);
  ok("and its clamped counter", rec["dp-0000"]?.defaultedEmptyRecords === 1);
  ok("and a finite stamp", Number.isFinite(rec["dp-0000"]?.at));
  const projected = (await fetchIntegrityFaults(stub as never)) as Record<string, { defaultedEmptyRecords?: number }>;
  ok("and the projector's view of it is unmoved by a dose three times the cap", projected["dp-0000"]?.defaultedEmptyRecords === 1);
}
{
  const r = await doseDest(100);
  const rec = (await r.storage.get<Record<string, { reason?: string; count?: number }>>(DEST_PROBE_FAULTS_KEY)) ?? {};
  ok("a destination inside the cap keeps its closed reason at a dose far past the cap", rec["dest-0000"]?.reason === "auth");
  ok("and its fold count", rec["dest-0000"]?.count === 1);
}

// ---- DIFFERENTIAL CONTROL 1: the same shape, behaving correctly ----------------------------------
console.log("\nDIFFERENTIAL CONTROL 1 (a subject-keyed map in this engine that ADMITS a new subject):");
{
  let agg: Parameters<typeof applySourceFaults>[0];
  for (let i = 0; i < RUN_FAULT_DOWNPIPES_MAX + 20; i++) {
    agg = applySourceFaults(agg, `dp-${String(i).padStart(4, "0")}`, { incompleteReasons: { _truncated: { "rate-limited": 1 } } }, 1_700_000_000_000 + i);
  }
  const keys = Object.keys(agg ?? {});
  ok("applySourceFaults holds exactly its own cap", keys.length === RUN_FAULT_DOWNPIPES_MAX);
  ok("and ADMITS the newest subject past it by evicting the oldest", keys.includes(`dp-${String(RUN_FAULT_DOWNPIPES_MAX + 19).padStart(4, "0")}`) && !keys.includes("dp-0000"));
}

// ---- DIFFERENTIAL CONTROL 2: the SAME SUBJECT SPACE, already declared ----------------------------
console.log("\nDIFFERENTIAL CONTROL 2 (the other per-DESTINATION cap in this product, declared all along):");
{
  const { dobj, storage } = makeDO();
  await dobj.recordControlPlaneExportHealth({
    at: new Date(1_700_000_000_000).toISOString(),
    wroteAny: true,
    perDest: Array.from({ length: 70 }, (_, i) => ({ id: `dest-${i}`, ok: false, reason: "worm-locked" })),
  });
  const agg = await truncAgg(storage);
  ok("recordControlPlaneExportHealth caps the SAME subject at 64 and declares the 6 it dropped", agg?.["export-health-perdest"]?.count === 6);
  ok("so 32 was the outlier and the disagreement is a finding, not a preference", DEST_PROBE_FAULTS_CAP === 64);
}

// ---- INSTRUMENT CONTROL --------------------------------------------------------------------------
console.log("\nINSTRUMENT CONTROL (a KNOWN POSITIVE: assume the reader is broken until it fires):");
{
  // `export-health-perdest` is a declared surface in its own right. If this reader can see that one book
  // through this ledger on this rig, a zero from it about the two surfaces under test is a result rather
  // than a broken probe.
  const { dobj, storage } = makeDO();
  await dobj.recordControlPlaneExportHealth({
    at: new Date(1_700_000_000_000).toISOString(),
    wroteAny: false,
    perDest: Array.from({ length: 65 }, (_, i) => ({ id: `d${i}`, ok: true })),
  });
  const agg = await truncAgg(storage);
  ok("the reader FIRES on a surface that was declared before this change", agg?.["export-health-perdest"]?.count === 1);
  ok("and the same reader reports my surfaces ABSENT on that same storage, so absence is discriminating", agg?.["dest-probe-faults"] === undefined && agg?.["integrity-faults-downpipe"] === undefined);
}

// ---- REACHABILITY, MEASURED RATHER THAN INHERITED ------------------------------------------------
console.log("\nREACHABILITY (both need a mass-failure state to reach; that is measured here, not assumed):");
ok(`the bulk create path admits ${BULK_DOWNPIPES_MAX} downpipes in ONE request, which is the integrity cap itself`, BULK_DOWNPIPES_MAX >= IC);
ok("all three destination cuts are the SAME number, so no cut is silently narrower than the declared one", DEST_PROBE_MAX === DEST_PROBE_FAULTS_CAP);
{
  // The systematic cause is the point: one rotated wrap key faults every downpipe on the same pass, so the
  // dose is the FLEET SIZE rather than a run of bad luck. Driven at a fleet of 300.
  const r = await doseIntegrity(300);
  ok("one systematic cause over a 300-downpipe fleet declares all 200 it could not record", r.declared === 300 - IC);
}

// ---- NEGATIVE CONTROLS ---------------------------------------------------------------------------
console.log("\nNEGATIVE CONTROLS (a VOCABULARY drop is not a CAPACITY drop and must classify differently):");
{
  const { record, refusedRows } = applyDestProbeFaultsCounted({}, [{ id: "d1", reason: "not-a-real-reason" }, { id: "", reason: "auth" }, "junk"], 1);
  ok("an out-of-vocabulary reason, an empty id and a non-object are all dropped", Object.keys(record).length === 0);
  ok("and NONE of them is declared as a truncation (nothing was lost for want of room)", refusedRows === 0);
}
{
  const { record, refusedSubjects } = applyIntegrityFaultsCounted(undefined, "dp1", "not-an-object", 1);
  ok("a malformed integrity snapshot records nothing", Object.keys(record).length === 0);
  ok("and is not declared as a truncation either", refusedSubjects === 0);
}
{
  // A downpipe ALREADY in the map must always be folded: the cap bounds the SUBJECT space, never the
  // evidence about a subject already known to be faulting.
  let rec: Parameters<typeof applyIntegrityFaultsCounted>[0];
  for (let i = 0; i < IC; i++) rec = applyIntegrityFaultsCounted(rec, `dp-${i}`, SNAP, 1).record;
  const again = applyIntegrityFaultsCounted(rec, "dp-0", SNAP, 2);
  ok("a downpipe already in a FULL map is still folded", again.record["dp-0"]?.defaultedEmptyRecords === 2);
  ok("and folding it declares no truncation", again.refusedSubjects === 0);
}
{
  const under = await doseIntegrity(5);
  const dUnder = await doseDest(5);
  ok("a fleet under both caps declares nothing at all", !under.keyPresent && !dUnder.keyPresent);
}

// ---- THE PACK, THROUGH ITS OWN READER ------------------------------------------------------------
console.log("\nTHE PACK (fetchSchedDiag is what support opens, and it gates on a CLOSED surface set):");
{
  // A surface booked but not REGISTERED would be dropped again on the read path, so booking is only half of
  // the fix: this is the same value read back out through the reader support actually uses.
  const { dobj, stub, storage } = makeDO();
  for (let i = 0; i < 150; i++) await dobj.recordIntegrityFaults({ id: `dp-${i}`, snapshot: SNAP });
  await dobj.recordDestProbeFaults({ rows: Array.from({ length: 100 }, (_, i) => ({ id: `d-${i}`, reason: "auth" })), refusedUpstream: 7 });
  const section = (await fetchSchedDiag(stub as never)) as { capTruncations?: CountAgg };
  ok("the pack section carries the 50 downpipes the integrity record could not hold", section.capTruncations?.["integrity-faults-downpipe"]?.count === 150 - IC);
  ok("and the 43 destination rows the three cuts dropped, upstream refusal included", section.capTruncations?.["dest-probe-faults"]?.count === 100 - DC + 7);
  ok("and the ledger it read agrees, so the read path adds no third cut", (await truncAgg(storage))?.["dest-probe-faults"]?.count === 100 - DC + 7);
}

// ---- THE SUBJECT ----------------------------------------------------------------------------
//
// A COUNT SAYS N ROWS WERE DROPPED AND NOT WHICH SUBJECT, measured here across all three of these surfaces.
// Both siblings are subject-keyed maps whose absent row reads as a subject with no
// fault, so a reader holding `integrityFaults` or `destProbeFaults` needs the name, not the tally. Both
// refusal sites already hold it: the integrity route is refusing the very id it was handed, and the dest-probe
// writer strips and clamps the label before deciding it has no room for it.
console.log("\nTHE SUBJECT (which downpipe, which destination -- not merely how many):");
{
  const { dobj, storage } = makeDO();
  for (let i = 0; i < IC; i++) await dobj.recordIntegrityFaults({ id: `filler-${i}`, snapshot: SNAP });
  await dobj.recordIntegrityFaults({ id: POISON_DOWNPIPE, snapshot: SNAP }); // refused by the cap
  const subj = (await storage.get<Record<string, { ids?: string[]; incomplete?: boolean }>>(CAP_TRUNCATION_SUBJECTS_KEY)) ?? {};
  ok("the integrity refusal names the downpipe it refused", subj["integrity-faults-downpipe"]?.ids?.includes(POISON_DOWNPIPE) === true);
  ok("a downpipe INSIDE the cap is not named as refused", subj["integrity-faults-downpipe"]?.ids?.includes("filler-0") !== true);
  ok("and with one nameable refusal the surface does NOT claim to be incomplete", subj["integrity-faults-downpipe"]?.incomplete === false);
}
{
  const { dobj, storage } = makeDO();
  // Both DO-side cuts at once, plus the upstream cut whose ROWS this DO never sees.
  await dobj.recordDestProbeFaults({
    rows: [...Array.from({ length: DC + 5 }, (_, i) => ({ id: `filler-${i}`, reason: "auth" })), { id: POISON_DEST, reason: "auth" }],
    refusedUpstream: 7,
  });
  const subj = (await storage.get<Record<string, { ids?: string[]; incomplete?: boolean }>>(CAP_TRUNCATION_SUBJECTS_KEY)) ?? {};
  ok("the dest-probe refusal names the destination the per-call slice dropped", subj["dest-probe-faults"]?.ids?.includes(POISON_DEST) === true);
  // THE HONESTY BIT. The upstream accumulator counts refusals it has no rows for, so the named list can never
  // be the whole truth here, and saying so is the difference between a lower bound and a false enumeration.
  ok("and an UNNAMEABLE upstream refusal marks the surface incomplete rather than looking enumerated", subj["dest-probe-faults"]?.incomplete === true);
  ok("a destination ADMITTED to the map is not named as refused", subj["dest-probe-faults"]?.ids?.includes("filler-0") !== true);
}

// ---- REDACTION -----------------------------------------------------------------------------------
//
// The named subject is BYTE-IDENTICAL to the key the capped map would have used, and both key spaces already
// ride in the pack verbatim (`integrityFaults`, `destProbeFaults`, `downpipes[].id`), so declaring a REFUSAL
// of a key discloses no class the ADMISSION of the same key does not. What must never ride is anything BESIDE
// the key: no fault class, no reason, no count, no free text. The COUNT ledger is unchanged and still counts.
console.log("\nREDACTION (both capped maps are keyed by the CUSTOMER'S OWN label):");
{
  const { dobj, storage } = makeDO();
  for (let i = 0; i < IC; i++) await dobj.recordIntegrityFaults({ id: `filler-${i}`, snapshot: SNAP });
  await dobj.recordIntegrityFaults({ id: POISON_DOWNPIPE, snapshot: SNAP }); // refused by the cap
  await dobj.recordDestProbeFaults({
    rows: [...Array.from({ length: DC }, (_, i) => ({ id: `filler-${i}`, reason: "auth" })), { id: POISON_DEST, reason: "auth" }],
  });
  const declared = JSON.stringify((await truncAgg(storage)) ?? null);
  ok("the COUNT declaration names neither dropped downpipe nor dropped destination", !declared.includes(POISON_DOWNPIPE) && !declared.includes(POISON_DEST));
  ok("and it DID declare both drops (a redaction that declares nothing is not a redaction)", declared.includes("integrity-faults-downpipe") && declared.includes("dest-probe-faults"));
  // Nothing BESIDE the key crosses into the subject ledger: the integrity fault class is a closed enum the
  // record itself keeps, and it must not follow the id out.
  const subjJson = JSON.stringify((await storage.get(CAP_TRUNCATION_SUBJECTS_KEY)) ?? null);
  ok("the SUBJECT ledger carries ids only, with no fault class, reason or digest", !subjJson.includes("recipient-no-capsule-match") && !subjJson.includes("0123456789ab") && !subjJson.includes("auth"));
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}  ${checks - failures}/${checks} checks`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
