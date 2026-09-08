// validate-audit-rollover-count-honesty.ts
//
// A ROLLOVER THE ENGINE ITSELF BOOKS AS LOST WAS REPORTED AS A ROLLOVER OF ZERO.
//
// verifyAudit resolved the rolled-over count as `rollover?.rolledOverCount ?? derived`. Its own comment
// says "Prefer the recorded cumulative count; fall back to the derived count", and `??` does not fall
// through on 0, so the fallback was kept out of the one case that needs it most: a rollover record whose
// count has been lost. The engine ALREADY booked `rollover-record-lost` for that state -- the very line
// above the count tested `rollover.rolledOverCount === 0` -- and then reported the lost value anyway.
//
// THE INTERNAL DIFFERENTIAL IS THE ARGUMENT, and it is why this is a defect rather than a preference:
// the SAME storage state answered TWO different counts depending on whether the record was ABSENT or
// PRESENT-BUT-ZEROED. Absent gave the true count from the derived fallback. Zeroed gave zero. Nothing
// about the destroyed entries differs between the two.
//
// THE SIBLING DISAGREEMENT IS THE SECOND ARGUMENT. auditCountAndNearCap reads the SAME field of the SAME
// record and sanitises it (`Number.isFinite(...) && > 0 ? Math.floor(...) : 0`). verifyAudit read it raw.
// Two readers of one record, one hardened and one not, and the unhardened one is the one the console
// renders.
//
// WHAT THE ZERO COSTS ON SCREEN, which is why it is not cosmetic. console/src/screens/access-security/
// audit-events.ts gated its rollover notice on `rolledOver === true && (count ?? 0) > 0`, so the zero fell
// through to the plain "Chain intact ... recomputes cleanly from the earliest retained entry" surface --
// the reading that file's own comment records as the defect it fixed, "identical on a log
// that begins at entry 1 and on one whose first two thousand entries have been destroyed". An operator
// looking at a destroyed audit history was told nothing had happened.
//
// AND AN ASSERTION HAD PINNED IT. console/test/validate-audit-capacity-screen.ts asserted "a rolledOver
// flag with a zero count does not claim a loss" and required the screen to stay silent. It is corrected in
// the console half, with the reason written at the site.
//
// No network, no deploy, no estate. Run: node test/validate-audit-rollover-count-honesty.ts
import { AUDIT_PREFIX, type AuditDraft, type AuditEvent } from "../src/admin/audit.ts";
import { AUDIT_ROLLOVER_KEY, SchedulerDO } from "../src/sched/scheduler-do.ts";
// Importing the verdict guard ARMS it: a run that exits without reaching verdictReached below is forced to
// exit 1, so a drained event loop can never read as a clean sweep.

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// FaithfulStorage honours list()'s prefix, limit and startAfter, which rollOverAudit and listAllByPrefix
// both depend on. A double that ignores `limit` deletes the WHOLE chain on a one-entry rollover, which is
// the instrument defect validate-audit-cap-boundary.ts records; this one does not have it, and the first
// check below proves the rig can produce a real rollover before any zero it reports is trusted.
class FaithfulStorage {
  readonly map = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, structuredClone(value));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string; limit?: number; startAfter?: string }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    const after = opts?.startAfter;
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (after !== undefined) keys = keys.filter((k) => k > after);
    if (opts?.limit !== undefined) keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    return out;
  }
  async setAlarm(_t: number): Promise<void> {
    /* no-op */
  }
  rawKeys(prefix: string): string[] {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
  }
  rawGet<T>(key: string): T | undefined {
    return this.map.get(key) as T | undefined;
  }
  rawPut<T>(key: string, value: T): void {
    this.map.set(key, structuredClone(value));
  }
}

interface AuditDO {
  appendAudit(d: AuditDraft): Promise<AuditEvent>;
  rollOverAudit(dropCount: number): Promise<void>;
  verifyAudit(): Promise<{ intact: boolean; rolledOver: boolean; rolledOverCount: number; earliestSeq: number }>;
  auditCountAndNearCap(): Promise<{ auditCount: number; auditNearCap: boolean; auditRolledOverCount: number }>;
}

function draftAt(i: number): AuditDraft {
  return { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "engine-state", field: "engineVersion", detail: `0.0.${i}` } } as unknown as AuditDraft;
}

// silence swallows appendAudit's per-entry console line so the verdict lines are readable. It restores the
// real console before returning, so a later failure still prints.
async function silence<T>(fn: () => Promise<T>): Promise<T> {
  const real = console.log;
  console.log = (): void => {};
  try {
    return await fn();
  } finally {
    console.log = real;
  }
}

interface Rig {
  storage: FaithfulStorage;
  dobj: AuditDO;
}

// rolledRig appends `total` entries and drops the oldest `drop` through the DO's OWN rollOverAudit, so the
// storage state below is one the product produces rather than one this file draws.
async function rolledRig(total: number, drop: number): Promise<Rig> {
  const storage = new FaithfulStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState) as unknown as AuditDO;
  await silence(async () => {
    for (let i = 1; i <= total; i++) await dobj.appendAudit(draftAt(i));
  });
  await dobj.rollOverAudit(drop);
  return { storage, dobj };
}

async function main(): Promise<void> {
  console.log("PART 1: the rig can produce a REAL rollover (the known positive, run before any zero is trusted)");
  const real = await rolledRig(12, 2);
  const realV = await real.dobj.verifyAudit();
  ok("a real rollover through the DO's own path leaves the chain intact", realV.intact === true);
  ok("it reports rolledOver true", realV.rolledOver === true);
  ok("it reports the true count (2 entries dropped)", realV.rolledOverCount === 2);
  ok("it reports the earliest retained seq (the chain begins at 3)", realV.earliestSeq === 3);
  ok("and the entries really are gone (10 retained of 12)", real.storage.rawKeys(AUDIT_PREFIX).length === 10);

  console.log("\nPART 2: THE INTERNAL DIFFERENTIAL. One storage state, two readings, decided by the record alone");
  // ABSENT: the case the `??` fallback already covered. Carried as the POSITION CONTROL for the fallback:
  // if this were ever zero the fallback would be dead and the fix below would prove nothing.
  const absent = await rolledRig(12, 2);
  await absent.storage.delete(AUDIT_ROLLOVER_KEY);
  const absentV = await absent.dobj.verifyAudit();
  ok("record ABSENT: still rolledOver", absentV.rolledOver === true);
  ok("record ABSENT: the derived fallback answers the TRUE count", absentV.rolledOverCount === 2);

  // ZEROED: the same destroyed entries, the same retained chain, the same earliest seq. Only the record
  // differs, and it differs in a way the engine itself already calls a LOSS.
  const zeroed = await rolledRig(12, 2);
  zeroed.storage.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: 3, rolledOverCount: 0 });
  const zeroedV = await zeroed.dobj.verifyAudit();
  ok("record ZEROED: still rolledOver, because the entries are still gone", zeroedV.rolledOver === true);
  ok("record ZEROED: the count is NOT zero -- a rollover of nothing is not a thing", zeroedV.rolledOverCount !== 0);
  ok("record ZEROED: it is the same count the ABSENT record yields, because the storage state is the same", zeroedV.rolledOverCount === absentV.rolledOverCount);
  ok("record ZEROED: the earliest retained seq is unchanged by the record's loss", zeroedV.earliestSeq === 3);

  console.log("\nPART 3: the other unusable shapes a lost record can take");
  for (const [name, value] of [
    ["negative", -5],
    ["fractional", 2.7],
    ["non-numeric", "2" as unknown as number],
    ["NaN", Number.NaN],
  ] as Array<[string, number]>) {
    const rig = await rolledRig(12, 2);
    rig.storage.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: 3, rolledOverCount: value });
    const v = await rig.dobj.verifyAudit();
    // fractional is the one shape that IS usable: it is a positive finite number and floors to 2, which is
    // the true count here, so it is asserted as a NUMBER rather than as the fallback.
    // Object.is rather than !==, because `NaN !== NaN` is TRUE and this check passed pre-repair for that
    // reason alone. A check that holds against the defect is not a check.
    ok(`a ${name} recorded count never reaches the wire as itself`, !Object.is(v.rolledOverCount as unknown, value));
    ok(`a ${name} recorded count still answers a usable positive integer`, Number.isInteger(v.rolledOverCount) && v.rolledOverCount > 0);
    ok(`a ${name} recorded count still reports rolledOver`, v.rolledOver === true);
  }

  console.log("\nPART 4: NEGATIVE CONTROLS -- a clean chain must not be talked into a rollover");
  const clean = new FaithfulStorage();
  const cleanDo = new SchedulerDO({ storage: clean } as unknown as DurableObjectState) as unknown as AuditDO;
  await silence(async () => {
    for (let i = 1; i <= 6; i++) await cleanDo.appendAudit(draftAt(i));
  });
  const cleanV = await cleanDo.verifyAudit();
  ok("a chain that begins at genesis is NOT rolled over", cleanV.rolledOver === false);
  ok("and its count is zero, which is the ONE place a zero is the right answer", cleanV.rolledOverCount === 0);
  ok("and it is intact", cleanV.intact === true);
  // A zeroed record on a chain that never rolled must not manufacture a rollover either.
  clean.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: 1, rolledOverCount: 0 });
  const cleanZ = await cleanDo.verifyAudit();
  ok("a zeroed record on a genesis chain does not manufacture a rollover", cleanZ.rolledOver === false && cleanZ.rolledOverCount === 0);

  console.log("\nPART 5: THE SIBLING that already got this right, on the same rig in the same session");
  // INSTRUMENT CONTROL. auditCountAndNearCap applies the finite-and-positive test to the same field of the
  // same record. If this booked nothing the rig would be dead and Part 2's verdicts would be unattributable.
  const sib = await rolledRig(12, 2);
  const sibReal = await sib.dobj.auditCountAndNearCap();
  ok("INSTRUMENT: the sibling reader answers the true count on a healthy record", sibReal.auditRolledOverCount === 2);
  sib.storage.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: 3, rolledOverCount: 0 });
  const sibZero = await sib.dobj.auditCountAndNearCap();
  ok("the sibling reader has ALWAYS sanitised the zeroed record (this is the disagreement, not the fix)", sibZero.auditRolledOverCount === 0);
  const sibVerify = await sib.dobj.verifyAudit();
  ok("and verifyAudit no longer disagrees with it about whether a rollover happened", sibVerify.rolledOver === true);

  console.log("\nPART 6: THE ENGINE WRITES A ZERO-COUNT RECORD ITSELF, so this is not only an out-of-band edit");
  // rollOverAudit adds toDrop.length to the prior count. With a positive dropCount and nothing left under
  // the prefix to drop, toDrop.length is 0 and the record is WRITTEN carrying zero, on the product's own
  // path, with no anomaly booked at the write.
  const selfZero = new FaithfulStorage();
  const selfDo = new SchedulerDO({ storage: selfZero } as unknown as DurableObjectState) as unknown as AuditDO;
  await silence(async () => {
    for (let i = 1; i <= 4; i++) await selfDo.appendAudit(draftAt(i));
  });
  for (const k of selfZero.rawKeys(AUDIT_PREFIX)) selfZero.map.delete(k);
  await selfDo.rollOverAudit(1);
  const written = selfZero.rawGet<{ rolledOverCount: number }>(AUDIT_ROLLOVER_KEY);
  ok("rollOverAudit writes a rollover record carrying zero when it finds nothing to drop", written !== undefined && written.rolledOverCount === 0);

  console.log("\nPART 7: STRUCTURAL -- one definition of 'the record cannot answer', not three");
  const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("../src/sched/scheduler-do-audit.ts", import.meta.url), "utf8"));
  ok("verifyAudit resolves the recorded count through one sanitised binding", src.includes("const recordedRolledOverCount ="));
  ok("the count falls back on that binding rather than on the raw record field", src.includes("rolledOverCount: recordedRolledOverCount ??"));
  ok("the rolled-over FLAG is decided by the same binding", src.includes("const rolledOver = recordedRolledOverCount !== undefined || derivedRolledOver"));
  ok("the anomaly booking is decided by the same binding", src.includes("if (derivedRolledOver && recordedRolledOverCount === undefined)"));
  // INVERSION SENTINEL: the pre-fix expression must be GONE, not merely out-ranked. An assertion set that
  // only counts absences would hold over a blank file, so this one names the exact text it must not find.
  ok("SENTINEL: the raw `rollover?.rolledOverCount ??` read is gone", !src.includes("rollover?.rolledOverCount ??"));

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${checks - failures}/${checks} checks passed`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
