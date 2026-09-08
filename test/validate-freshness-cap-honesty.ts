// validate-freshness-cap-honesty.ts
//
// FRESHNESS_FAULTS_CAP bounds the per-account record of downpipes whose staleness rule can never arm. Once
// the cap is reached, recordFreshnessFault does not evict the oldest to admit a new subject: it refuses the
// new one outright, so a downpipe past the cap is absent from the record rather than marked stale.
//
// An absent record is read downstream as healthy: freshnessUncomputableIndex joins this map onto
// downpipes[], and a downpipe not in the map carries no field at all, which the projector's convention reads
// as "does not apply". So a downpipe refused by the cap is not merely omitted from a count, it is asserted
// to have a working staleness rule on the evidence pack a customer relies on.
//
// The fix: capTruncations declares how many rows were dropped for a surface, and a subject index now names
// WHICH downpipes were refused (up to its own cap, after which it marks itself incomplete rather than
// pretending to be a complete enumeration). projectDownpipeRow reads that subject index and marks a refused
// downpipe's row `freshnessComputableUnknown: true` instead of leaving it silently healthy.
//
// THE CONTROLS, and what each is for:
//   - DOSE-RESPONSE over DISTINCT faulting downpipes, not a point test, and far past the edge (200).
//   - THE EDGE IS EXACTLY 50/51: nothing is declared at 50 and exactly one row at 51.
//   - POSITION CONTROL: what IS recorded is unchanged by the dose (cause, label clamp, timestamp).
//   - DIFFERENTIAL CONTROL: applySourceFaults' capAggregate is the SAME per-downpipe subject-map shape in
//     the same engine and ADMITS a new subject past its cap by evicting the oldest, so refusing the new
//     subject is this site's choice and not a house convention.
//   - THE PACK JOIN: a downpipe past the cap is absent from the fault map, which is why a count alone can
//     never reach its row.
//   - THE SUBJECT AND THE ROW: the refusal names the downpipe it refused, and projectDownpipeRow turns that
//     name into freshnessComputableUnknown on the row. Past the id list's own cap the record declares itself
//     INCOMPLETE and every unmarked row takes the caveat.
//   - POPULATION: a genuinely unaffected downpipe must still carry NEITHER field, because a marker on every
//     row would discriminate nothing.
//   - INSTRUMENT CONTROL: a declared surface books a truncation on this rig, so the pre-fix zero is a result
//     rather than a broken probe.
//   - NEGATIVE CONTROLS THAT MUST CLASSIFY DIFFERENTLY: an out-of-vocabulary surface, a non-positive
//     dropped count and a healthy fleet must all leave the ledger untouched.
//   - REDACTION: the customer's own downpipe label is the key of the capped map. The COUNT ledger still
//     carries counts only; the SUBJECT ledger carries the id and nothing beside it, and the id is
//     byte-identical to the key the map would have used, so a refusal discloses no class an admission does
//     not. A non-string subject cannot enter, an over-long one is clamped, and a subject that cannot be
//     named marks the surface incomplete rather than leaving it looking enumerated.
//
// Run: node test/validate-freshness-cap-honesty.ts

import { applySourceFaults, RUN_FAULT_DOWNPIPES_MAX } from "../src/admin/run-fault-records.ts";
import { capTruncationSubjectIndex, freshnessUncomputableIndex } from "../src/admin/support-sections-diag.ts";
import { projectDownpipeRow } from "../src/admin/support-sections-downpipes.ts";
import {
  CAP_TRUNCATION_SUBJECT_IDS_CAP,
  CAP_TRUNCATION_SUBJECTS_KEY,
  CAP_TRUNCATION_SURFACES,
  CAP_TRUNCATIONS_KEY,
  FRESHNESS_FAULTS_CAP,
  FRESHNESS_FAULTS_KEY,
  type LedgerStorage,
  readSchedDiag,
  recordCapTruncation,
  recordFreshnessFault,
  safeLabel,
} from "../src/sched/sched-fault-ledger.ts";

declare const process: { exit(code?: number): never };

let checks = 0;
let failures = 0;
function ok(label: string, pass: boolean): void {
  checks++;
  if (!pass) failures++;
  console.log(`  ${pass ? "ok  " : "FAIL"}  ${label}`);
}

// The POISON label planted as a downpipe id: a customer's own bucket name. The COUNT ledger may never carry
// it; the SUBJECT ledger must, because naming the refused key is the repair -- see REDACTION at the bottom.
const POISON_LABEL = "acme-crown-jewels-nightly";

function store(): { s: LedgerStorage; map: Map<string, unknown> } {
  const map = new Map<string, unknown>();
  return {
    map,
    s: {
      async get<T>(k: string): Promise<T | undefined> {
        return map.get(k) as T | undefined;
      },
      async put<T>(k: string, v: T): Promise<void> {
        map.set(k, v);
      },
    },
  };
}

type CountAgg = Record<string, { count: number; lastAt: string }>;

async function dose(n: number): Promise<{ recorded: number; declared: number; map: Map<string, unknown>; s: LedgerStorage }> {
  const { s, map } = store();
  for (let i = 0; i < n; i++) await recordFreshnessFault(s, `dp-${String(i).padStart(4, "0")}`, "cadence-malformed");
  const rec = (map.get(FRESHNESS_FAULTS_KEY) ?? {}) as Record<string, unknown>;
  const trunc = (map.get(CAP_TRUNCATIONS_KEY) ?? {}) as CountAgg;
  return { recorded: Object.keys(rec).length, declared: trunc["freshness-faults"]?.count ?? 0, map, s };
}

console.log("freshness-fault cap honesty (G076 record x G325 declaration)\n");

// ---- the surface is registered at all ------------------------------------------------------------
console.log("THE SURFACE:");
ok(
  "`freshness-faults` is a member of the closed capTruncation surface vocabulary",
  (CAP_TRUNCATION_SURFACES as readonly string[]).includes("freshness-faults"),
);

// ---- DOSE-RESPONSE -------------------------------------------------------------------------------
console.log("\nDOSE-RESPONSE (distinct faulting downpipes -> rows recorded / rows declared dropped):");
const DOSES = [0, 1, 25, FRESHNESS_FAULTS_CAP - 1, FRESHNESS_FAULTS_CAP, FRESHNESS_FAULTS_CAP + 1, 60, 200];
for (const n of DOSES) {
  const r = await dose(n);
  const expectRecorded = Math.min(n, FRESHNESS_FAULTS_CAP);
  const expectDeclared = Math.max(0, n - FRESHNESS_FAULTS_CAP);
  console.log(`  ${String(n).padStart(3)}\trecorded ${r.recorded}\tdeclared ${r.declared}`);
  ok(`dose ${n}: the record holds ${expectRecorded} rows`, r.recorded === expectRecorded);
  ok(`dose ${n}: the pack is told ${expectDeclared} rows were dropped`, r.declared === expectDeclared);
}

// ---- THE EDGE IS EXACTLY AT THE CAP --------------------------------------------------------------
console.log("\nTHE EDGE:");
const atCap = await dose(FRESHNESS_FAULTS_CAP);
const overCap = await dose(FRESHNESS_FAULTS_CAP + 1);
ok("at exactly the cap NOTHING is declared (a declaration over a complete record would be a false alarm)", atCap.declared === 0);
ok("at the cap the key is absent entirely, not a zero", (atCap.map.get(CAP_TRUNCATIONS_KEY) as CountAgg | undefined)?.["freshness-faults"] === undefined);
ok("one downpipe past the cap declares exactly one dropped row", overCap.declared === 1);

// ---- POSITION CONTROL ----------------------------------------------------------------------------
console.log("\nPOSITION CONTROL (the dose must not move what IS recorded):");
const big = await dose(200);
const rows = big.map.get(FRESHNESS_FAULTS_KEY) as Record<string, { cause?: string; at?: string }>;
const first = rows["dp-0000"];
ok("a row inside the cap keeps its closed cause", first?.cause === "cadence-malformed");
ok("a row inside the cap keeps a parseable timestamp", Number.isFinite(Date.parse(String(first?.at))));
ok("the record never grows past the cap however far the dose runs", Object.keys(rows).length === FRESHNESS_FAULTS_CAP);

// ---- THE PACK JOIN, WHICH IS WHERE THE HARM LANDS ------------------------------------------------
//
// A count alone is not enough: the fault map is what freshnessUncomputableIndex joins onto downpipes[], a
// downpipe past the cap is ABSENT from it, so it carries NO field, and the projector's convention reads an
// absent field as "does not apply". Naming which downpipe was dropped (below) is what lets the row itself
// carry the caveat instead of leaving it in a different section of the pack.
console.log("\nTHE PACK JOIN (through the real projector):");
const bundle = await readSchedDiag(big.s);
const idx = freshnessUncomputableIndex(bundle as unknown as Record<string, unknown>);
ok("a downpipe INSIDE the cap is marked uncomputable", idx.has("dp-0000"));
ok("a downpipe PAST the cap is absent from the FAULT MAP, which is why the count alone could not save its row", !idx.has("dp-0199"));
ok(
  "and the pack now carries the truncation that says so",
  (bundle.capTruncations as CountAgg)["freshness-faults"]?.count === 200 - FRESHNESS_FAULTS_CAP,
);

// ---- THE SUBJECT, AND THE ROW IT REACHES ---------------------------------------------------------
console.log("\nTHE SUBJECT (the refusal now names what it refused, and the row stops asserting health):");
const subjects = capTruncationSubjectIndex(bundle as unknown as Record<string, unknown>, "freshness-faults");
ok("the refusal names a subject at all", subjects.named.size > 0);
ok("and it names a downpipe the cap actually refused", subjects.named.has("dp-0050"));
ok("a downpipe INSIDE the cap is NOT named as refused (a name for every row would name nothing)", !subjects.named.has("dp-0000"));
// AT THIS DOSE THE ID LIST IS ITSELF OVERRUN, which is the one place this repair could have reproduced the
// defect it removes. 150 refusals against a 32-id list means dp-0199 is refused and UNNAMED -- so the record
// must not read as a complete enumeration, and the caller must generalise the caveat to every unmarked row.
ok(
  "past the id list's own cap the record declares itself INCOMPLETE rather than repeating the defect it repairs",
  subjects.incomplete && subjects.named.size === CAP_TRUNCATION_SUBJECT_IDS_CAP,
);
ok("and a refused downpipe it could not name is NOT silently absent, because incomplete covers it", !subjects.named.has("dp-0199") && subjects.incomplete);

// The ROW, through the real projector. A dose of 200 overflows the id list, so `incomplete` is set and EVERY
// unmarked downpipe must take the caveat: at that point any row could be the dropped one. The 60-downpipe
// dose below is the case where every refusal IS nameable, which is where the population control bites.
function rowFor(id: string, index: Map<string, string>, trunc: ReturnType<typeof capTruncationSubjectIndex>): Record<string, unknown> {
  return projectDownpipeRow(
    { config: { id, name: id, enabled: true, cadenceSeconds: 3600, source: { type: "kv" } }, lastRunId: null, inFlight: false } as never,
    { replication: null, destIdSet: null, sealErrors: {}, freshnessIndex: index, freshnessTruncation: trunc, refusalIndex: new Map() },
  );
}
const modest = await dose(55); // 50 admitted, 5 refused, every refusal nameable
const modestBundle = await readSchedDiag(modest.s);
const mIdx = freshnessUncomputableIndex(modestBundle as unknown as Record<string, unknown>);
const mSub = capTruncationSubjectIndex(modestBundle as unknown as Record<string, unknown>, "freshness-faults");
ok("with every refusal nameable the record does NOT claim to be incomplete", !mSub.incomplete);
ok("and it names exactly the 5 downpipes the cap refused", mSub.named.size === 5);
const refusedRow = rowFor("dp-0054", mIdx, mSub);
const knownRow = rowFor("dp-0000", mIdx, mSub);
const healthyRow = rowFor("dp-9999", mIdx, mSub); // never faulted, never refused
ok("THE ROW THAT LIED: a downpipe past the cap now says its staleness rule is UNKNOWN", refusedRow.freshnessComputableUnknown === true);
ok("and it no longer asserts a working staleness rule by carrying nothing", refusedRow.freshnessComputable === undefined && Object.hasOwn(refusedRow, "freshnessComputableUnknown"));
ok("a downpipe INSIDE the cap keeps the KNOWN answer rather than being downgraded to a caveat", knownRow.freshnessComputable === false && knownRow.freshnessComputableUnknown === undefined);
// THE POPULATION CONTROL: "no row asserts a clean staleness rule" is also true of a pack where EVERY row
// carries the caveat, which would be a marker that says nothing. A genuinely unaffected downpipe must stay clean.
ok(
  "POPULATION: an unaffected downpipe carries NEITHER field, so the marker discriminates",
  healthyRow.freshnessComputable === undefined && healthyRow.freshnessComputableUnknown === undefined,
);
// And when nothing at all was refused, no row may carry the caveat.
const cleanFleet = await dose(3);
const cleanSub = capTruncationSubjectIndex((await readSchedDiag(cleanFleet.s)) as unknown as Record<string, unknown>, "freshness-faults");
ok("with no truncation at all the index is empty and complete", cleanSub.named.size === 0 && !cleanSub.incomplete);
ok("so no row takes the caveat on a fleet under the cap", rowFor("dp-0000", new Map(), cleanSub).freshnessComputableUnknown === undefined);

// ---- DIFFERENTIAL CONTROL ------------------------------------------------------------------------
console.log("\nDIFFERENTIAL CONTROL (the same subject-map shape elsewhere in this engine):");
let agg: Parameters<typeof applySourceFaults>[0];
for (let i = 0; i < RUN_FAULT_DOWNPIPES_MAX + 20; i++) {
  agg = applySourceFaults(agg, `dp-${String(i).padStart(4, "0")}`, { incompleteReasons: { _truncated: { "rate-limited": 1 } } }, 1_700_000_000_000 + i);
}
const aggKeys = Object.keys(agg ?? {});
const newest = `dp-${String(RUN_FAULT_DOWNPIPES_MAX + 19).padStart(4, "0")}`;
ok("applySourceFaults holds exactly its own cap", aggKeys.length === RUN_FAULT_DOWNPIPES_MAX);
ok("and ADMITS the newest subject past that cap", aggKeys.includes(newest));
ok("by evicting the oldest, so refusing a NEW subject is this site's choice and not a house convention", !aggKeys.includes("dp-0000"));

// ---- INSTRUMENT CONTROL --------------------------------------------------------------------------
console.log("\nINSTRUMENT CONTROL (a declared surface books on this rig in this session):");
const { s: ictrl, map: imap } = store();
await recordCapTruncation(ictrl, "roster-ghosts", 7);
ok("recordCapTruncation books a DECLARED sibling surface", ((imap.get(CAP_TRUNCATIONS_KEY) ?? {}) as CountAgg)["roster-ghosts"]?.count === 7);

// ---- NEGATIVE CONTROLS ---------------------------------------------------------------------------
console.log("\nNEGATIVE CONTROLS (these must classify differently):");
const { s: nctrl, map: nmap } = store();
await recordCapTruncation(nctrl, "not-a-real-surface" as never, 5);
ok("an out-of-vocabulary surface is refused (no key can be added by a caller-derived string)", nmap.get(CAP_TRUNCATIONS_KEY) === undefined);
await recordCapTruncation(nctrl, "roster-ghosts", 0);
ok("a zero dropped count writes nothing (a truncation that did not happen is not declared)", nmap.get(CAP_TRUNCATIONS_KEY) === undefined);
await recordCapTruncation(nctrl, "roster-ghosts", -3);
ok("a negative dropped count writes nothing", nmap.get(CAP_TRUNCATIONS_KEY) === undefined);
const healthy = await dose(3);
ok("a fleet under the cap declares nothing at all", healthy.map.get(CAP_TRUNCATIONS_KEY) === undefined);

// ---- REDACTION -----------------------------------------------------------------------------------
//
// THE ARGUMENT: naming the refused downpipe id is redaction-NEUTRAL rather than a widening, because the id
// emitted is EXACTLY the id that would have been the KEY of this map had there been room -- the same key
// space `schedDiag.freshnessFaults` and `downpipes[].id` already carry verbatim. Declaring a REFUSAL of a key
// cannot disclose a class the ADMISSION of the same key does not. What must still never ride is anything
// BESIDE the key, and that is what the checks below pin.
console.log("\nREDACTION (the named subject is the map's own key, and nothing else crosses):");
const { s: rs, map: rmap } = store();
for (let i = 0; i < FRESHNESS_FAULTS_CAP; i++) await recordFreshnessFault(rs, `filler-${i}`, "cadence-malformed");
await recordFreshnessFault(rs, POISON_LABEL, "timestamp-malformed"); // dropped by the cap
const declared = JSON.stringify(rmap.get(CAP_TRUNCATIONS_KEY) ?? null);
ok("the COUNT ledger is still a count and never names the row", !declared.includes(POISON_LABEL));
ok("and it did declare the drop", ((rmap.get(CAP_TRUNCATIONS_KEY) ?? {}) as CountAgg)["freshness-faults"]?.count === 1);
const subjEntry = ((rmap.get(CAP_TRUNCATION_SUBJECTS_KEY) ?? {}) as Record<string, { ids?: string[] }>)["freshness-faults"];
ok("the SUBJECT ledger names the refused downpipe, which is the whole point of it", subjEntry?.ids?.includes(POISON_LABEL) === true);
ok(
  "the named subject is BYTE-IDENTICAL to the key the map would have used, so no new value is minted",
  subjEntry?.ids?.find((v) => v === POISON_LABEL) === safeLabel(POISON_LABEL),
);
// Nothing BESIDE the key: the cause is a closed enum the record keeps, and it must not follow the id out.
const subjJson = JSON.stringify(rmap.get(CAP_TRUNCATION_SUBJECTS_KEY) ?? null);
ok("and the subject entry carries no cause, no count and no free text", !subjJson.includes("timestamp-malformed") && !subjJson.includes("cadence-malformed"));
// A subject that fails the label gate is DROPPED rather than coerced, exactly as the map's own key would be.
const { s: gs, map: gmap } = store();
await recordCapTruncation(gs, "roster-ghosts", 3, [123, null, "", { id: "x" }]);
const ghosts = ((gmap.get(CAP_TRUNCATION_SUBJECTS_KEY) ?? {}) as Record<string, { ids?: string[]; incomplete?: boolean }>)["roster-ghosts"];
ok("a non-string subject cannot enter the ledger through this seam", (ghosts?.ids ?? []).length === 0);
ok("and refusing to name them marks the surface INCOMPLETE rather than leaving it looking enumerated", ghosts?.incomplete === true);
// The id itself is clamped at the same LABEL_MAX the map's key takes.
const { s: cs, map: cmap } = store();
await recordCapTruncation(cs, "roster-ghosts", 1, ["z".repeat(4096)]);
const clamped = ((cmap.get(CAP_TRUNCATION_SUBJECTS_KEY) ?? {}) as Record<string, { ids?: string[] }>)["roster-ghosts"]?.ids?.[0] ?? "";
ok("an over-long subject is clamped to the same ceiling the map's key takes", clamped.length === 128);

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}  ${checks - failures}/${checks} checks`);
if (failures > 0) process.exit(1);
