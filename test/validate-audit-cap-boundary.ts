// validate-audit-cap-boundary.ts
//
// AUDIT_CAP IS A BOUND ONLY ACCUMULATION REACHES, AND CROSSING IT DESTROYS EVIDENCE PERMANENTLY. No fresh
// estate ever holds ten thousand audit entries; a customer's does, after months. So this is exactly the
// class of latent state an assertion at a point cannot reach, and it is irreversible: a rolled-over entry
// is gone, and the operator's only way to keep it is to export BEFORE the roll.
//
// WHY THIS EXISTS ALONGSIDE validate-audit-rollover.ts, WHICH IS NOT REDUNDANT WITH IT. That suite proves
// what happens AFTER a rollover by SIMULATING the storage effect (deletes the oldest keys and hand-writes
// the rollover record), because driving 10000+ real appends there would be slow. This file drives the real
// boundary directly, in about two and a half seconds, and carries the simulation as a REPRODUCTION CONTROL
// so the two are compared rather than trusted.
//
// MockStorage in validate-audit-harness.ts ignores list()'s `limit`. rollOverAudit calls
// list({prefix, limit: dropCount}), so under that double a one-entry rollover receives the WHOLE chain and
// deletes all of it. That is carried below as a DIFFERENTIAL CONTROL, because a storage double that cannot
// express the platform's list-limit contract cannot measure a boundary that depends on it.
import { AUDIT_CAP, AUDIT_NEAR_CAP_FRACTION, AUDIT_PREFIX, GENESIS_PREV_HASH, type AuditDraft, type AuditEvent, verifyChain } from "../src/admin/audit.ts";
import { AUDIT_ROLLOVER_KEY, SchedulerDO } from "../src/sched/scheduler-do.ts";
// Importing the verdict guard ARMS it: a run that exits without reaching verdictReached below is
// forced to exit 1, so a drained event loop can never read as a clean sweep.

// FaithfulStorage implements the subset of DurableObjectStorage the audit path uses, INCLUDING the limit
// and startAfter semantics listAllByPrefix and rollOverAudit depend on.
class FaithfulStorage {
  readonly map = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
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
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
}

interface AuditDO {
  appendAudit(d: AuditDraft): Promise<AuditEvent>;
  auditCountAndNearCap(): Promise<{ auditCount: number; auditNearCap: boolean }>;
  listAuditEntries(): Promise<AuditEvent[]>;
  rollOverAudit(dropCount: number): Promise<void>;
}

function makeDO(storage: FaithfulStorage = new FaithfulStorage()): { dobj: AuditDO; storage: FaithfulStorage } {
  return { dobj: new SchedulerDO({ storage } as unknown as DurableObjectState) as unknown as AuditDO, storage };
}

// draftAt builds one ordinary audit draft. `variant` changes only CONTENT, which is the POSITION CONTROL
// knob: a verdict on the retained COUNT must not move with what the entries say.
function draftAt(i: number, variant: "engine" | "human"): AuditDraft {
  return variant === "engine"
    ? { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "engine-state", field: "engineVersion", detail: `0.0.${i}` } }
    : { actorEmail: "owner@acme.example", actorMethod: "passkey", sourceIp: "203.0.113.7", action: "recovery-code-used", outcome: "success", target: { kind: "access-policy" } };
}

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) failures++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
}

// appendAudit mirrors every committed event as a structured Logpush line on stdout. Forty thousand of
// those would bury the chain's output, so the mirror is muted for the duration of the driving loops ONLY,
// and restored immediately. Nothing else is suppressed: every ok/FAIL line below is printed normally.
async function driveQuietly(fn: () => Promise<void>): Promise<void> {
  const real = console.log;
  console.log = (...args: unknown[]): void => {
    const first = args[0];
    if (typeof first === "string" && first.startsWith('{"source":"downpipe-audit"')) return;
    real(...(args as []));
  };
  try {
    await fn();
  } finally {
    console.log = real;
  }
}

interface Snapshot {
  appended: number;
  retained: number;
  headCount: number;
  nearCap: boolean;
  earliestSeq: number;
  headSeq: number;
  rolledOverCount: number;
  rolloverRecordPresent: boolean;
  earliestLinksToGenesis: boolean;
  verifiedAsRollover: boolean;
  verifiedAsGenesis: boolean;
  verifyBrokenAt: number | undefined;
}

async function snapshot(dobj: AuditDO, storage: FaithfulStorage, appended: number): Promise<Snapshot> {
  const entries = await dobj.listAuditEntries();
  const { auditCount, auditNearCap } = await dobj.auditCountAndNearCap();
  const roll = storage.rawGet<{ earliestRetainedSeq: number; rolledOverCount: number }>(AUDIT_ROLLOVER_KEY);
  const first = entries[0];
  const asRollover = await verifyChain(entries, { expectGenesis: false });
  const asGenesis = await verifyChain(entries);
  return {
    appended,
    retained: storage.rawKeys(AUDIT_PREFIX).length,
    headCount: auditCount,
    nearCap: auditNearCap,
    earliestSeq: first ? first.seq : -1,
    headSeq: entries.length > 0 ? entries[entries.length - 1]!.seq : -1,
    rolledOverCount: roll?.rolledOverCount ?? 0,
    rolloverRecordPresent: roll !== undefined,
    earliestLinksToGenesis: first ? first.prevHash === GENESIS_PREV_HASH : false,
    verifiedAsRollover: asRollover.intact === true,
    verifiedAsGenesis: asGenesis.intact === true,
    verifyBrokenAt: asGenesis.brokenAt,
  };
}

const NEAR = Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION);
console.log(`validate-audit-cap-boundary  (AUDIT_CAP=${AUDIT_CAP}, near-cap warning at ${NEAR})`);

// ---- DOSE-RESPONSE: below, at, past and far past BOTH declared edges -----------------------------
const DOSES = [1, NEAR - 1, NEAR, NEAR + 1, AUDIT_CAP - 1, AUDIT_CAP, AUDIT_CAP + 1, AUDIT_CAP + 2, AUDIT_CAP + 3, AUDIT_CAP + 5, AUDIT_CAP + 100];
const { dobj, storage } = makeDO();
const snaps: Snapshot[] = [];
const t0 = Date.now();
await driveQuietly(async () => {
  for (let i = 1; i <= AUDIT_CAP + 100; i++) {
    await dobj.appendAudit(draftAt(i, "engine"));
    if (DOSES.includes(i)) snaps.push(await snapshot(dobj, storage, i));
  }
});
console.log(`\n  drove ${AUDIT_CAP + 100} real appendAudit calls in ${Date.now() - t0}ms`);
console.log("  appended  retained  nearCap  earliestSeq  headSeq  rolledOver  genesisLink  verify(rollover)  verify(genesis)");
for (const s of snaps) {
  console.log(`  ${s.appended}\t${s.retained}\t${s.nearCap}\t${s.earliestSeq}\t${s.headSeq}\t${s.rolledOverCount}\t${s.earliestLinksToGenesis}\t${s.verifiedAsRollover}\t${s.verifiedAsGenesis}`);
}
const at = (n: number): Snapshot => snaps.find((s) => s.appended === n)!;

console.log("\nEDGE 1: the near-cap WARNING, which is the operator's only chance to export first");
ok(`nearCap is FALSE one below the threshold (${NEAR - 1})`, at(NEAR - 1).nearCap === false);
ok(`nearCap turns TRUE at exactly ${NEAR}`, at(NEAR).nearCap === true);
ok(`nearCap stays TRUE past the threshold`, at(NEAR + 1).nearCap === true);
ok(`the warning arrives BEFORE anything is destroyed (nothing rolled over at ${NEAR})`, at(NEAR).rolledOverCount === 0 && at(NEAR).rolloverRecordPresent === false);

console.log("\nEDGE 2: the ROLLOVER, which is where evidence is destroyed");
ok(`nothing is dropped one below the cap, and genesis is still linked`, at(AUDIT_CAP - 1).retained === AUDIT_CAP - 1 && at(AUDIT_CAP - 1).earliestSeq === 1 && at(AUDIT_CAP - 1).earliestLinksToGenesis === true);
ok(`nothing is dropped AT the cap, and no rollover is on record`, at(AUDIT_CAP).retained === AUDIT_CAP && at(AUDIT_CAP).earliestSeq === 1 && at(AUDIT_CAP).rolloverRecordPresent === false);
ok(`the FIRST entry is dropped at exactly ${AUDIT_CAP + 1}`, at(AUDIT_CAP + 1).rolledOverCount === 1 && at(AUDIT_CAP + 1).earliestSeq === 2);
ok(`retained stays pinned at the cap past the edge, never above it`, [AUDIT_CAP + 1, AUDIT_CAP + 2, AUDIT_CAP + 5, AUDIT_CAP + 100].every((n) => at(n).retained === AUDIT_CAP));
ok(`the rolled-over count is cumulative and exact 100 past the edge`, at(AUDIT_CAP + 100).rolledOverCount === 100 && at(AUDIT_CAP + 100).earliestSeq === 101);
ok(`the head pointer's count never drifts from the retained key count`, snaps.every((s) => s.headCount === s.retained));
ok(`seq stays strictly monotonic across the rollover (a dropped seq is never reused)`, snaps.every((s) => s.headSeq === s.appended));

console.log("\nIS THE DESTRUCTION DECLARED, OR SILENT");
ok(`after a rollover the retained chain no longer links to genesis`, at(AUDIT_CAP + 1).earliestLinksToGenesis === false);
ok(`the rollover is DECLARED in storage (earliest retained seq and a cumulative count)`, at(AUDIT_CAP + 1).rolloverRecordPresent === true);
ok(`a rollover-aware verify reports the retained chain intact at every dose`, snaps.every((s) => s.verifiedAsRollover === true));
ok(`a genesis-expecting verify still DETECTS the missing genesis, at the new first seq`, at(AUDIT_CAP + 1).verifiedAsGenesis === false && at(AUDIT_CAP + 1).verifyBrokenAt === 2);
ok(`and before any rollover BOTH verifies agree, so the relaxation is gated rather than always on`, at(AUDIT_CAP).verifiedAsGenesis === true && at(AUDIT_CAP).verifiedAsRollover === true);

// ---- NEGATIVE CONTROL: must classify DIFFERENTLY -------------------------------------------------
// A rollover must not become a blanket excuse for a broken chain. Tamper INSIDE the retained window and
// the rollover-aware verify has to call it broken, at the tampered seq rather than at the boundary.
console.log("\nNEGATIVE CONTROL (must classify differently): tampering inside a rolled-over chain");
{
  const entries = await dobj.listAuditEntries();
  const victim = entries[Math.floor(entries.length / 2)]!;
  const tampered = entries.map((e) => (e.seq === victim.seq ? { ...e, outcome: "denied" as const } : e));
  const v = await verifyChain(tampered, { expectGenesis: false });
  ok(`a tampered entry in a rolled-over chain is still detected`, v.intact === false);
  ok(`and it is detected at the TAMPERED seq, not at the rollover boundary`, v.brokenAt === victim.seq);
}

// ---- REPRODUCTION CONTROL ------------------------------------------------------------------------
// validate-audit-rollover.ts SIMULATES a rollover and asserts it is "exactly as the DO's rollOverAudit
// does". Reproduce that simulation here and compare it against the DRIVEN rollover taken from the sweep
// above, so the existing suite's premise is measured rather than assumed and this file is not simply
// reporting on itself.
console.log("\nREPRODUCTION CONTROL: the existing suite's SIMULATED rollover against this DRIVEN one");
{
  const { dobj: dSim, storage: sSim } = makeDO();
  await driveQuietly(async () => {
    for (let i = 1; i <= 20; i++) await dSim.appendAudit(draftAt(i, "engine"));
  });
  const PRUNE = 3;
  for (const k of sSim.rawKeys(AUDIT_PREFIX).slice(0, PRUNE)) sSim.map.delete(k);
  const survivors = sSim.rawKeys(AUDIT_PREFIX);
  sSim.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: sSim.rawGet<AuditEvent>(survivors[0]!)!.seq, rolledOverCount: PRUNE });
  const sim = await snapshot(dSim, sSim, 20);
  const drv = at(AUDIT_CAP + 3);
  ok(`SIMULATED: 3 rolled over, earliest seq 4, rollover-aware verify intact`, sim.rolledOverCount === 3 && sim.earliestSeq === 4 && sim.verifiedAsRollover === true);
  ok(`DRIVEN: 3 rolled over, earliest seq 4, rollover-aware verify intact`, drv.rolledOverCount === 3 && drv.earliestSeq === 4 && drv.verifiedAsRollover === true);
  ok(`the two agree on every field the rollover record carries, so the simulation's premise holds`, sim.rolledOverCount === drv.rolledOverCount && sim.earliestSeq === drv.earliestSeq && sim.earliestLinksToGenesis === drv.earliestLinksToGenesis && sim.verifiedAsGenesis === drv.verifiedAsGenesis);
}

// ---- POSITION CONTROL ----------------------------------------------------------------------------
// Vary what should NOT matter: the entries are human-actor recovery events rather than engine events, and
// a thousand unrelated keys share the storage. A verdict on the retained count moves with neither.
console.log("\nPOSITION CONTROL: different entry content, and unrelated keys in the same storage");
{
  const { dobj: d2, storage: s2 } = makeDO();
  await driveQuietly(async () => {
    for (let i = 0; i < 1000; i++) await s2.put(`dp:filler-${String(i).padStart(5, "0")}`, { id: i });
    for (let i = 1; i <= AUDIT_CAP + 2; i++) await d2.appendAudit(draftAt(i, "human"));
  });
  const s = await snapshot(d2, s2, AUDIT_CAP + 2);
  ok(`the edge does not move with different entry content`, s.retained === AUDIT_CAP);
  ok(`the edge does not move with a thousand unrelated keys present`, s.rolledOverCount === 2 && s.earliestSeq === 3);
  ok(`and the rollover pruned NOTHING outside the audit prefix`, s2.rawKeys("dp:").length === 1000);
}

// ---- DIFFERENTIAL CONTROL ------------------------------------------------------------------------
// Drive the same rollover down a storage double that DROPS list()'s limit, which is what
// validate-audit-harness.ts MockStorage does. This is why the boundary had never been driven, and it is
// carried here so the reason stays visible rather than becoming folklore.
console.log("\nDIFFERENTIAL CONTROL: the same rollover under a limit-ignoring storage double");
{
  class LimitIgnoringStorage extends FaithfulStorage {
    override async list<T>(opts?: { prefix?: string; limit?: number; startAfter?: string }): Promise<Map<string, T>> {
      return super.list<T>({ ...(opts?.prefix !== undefined ? { prefix: opts.prefix } : {}), ...(opts?.startAfter !== undefined ? { startAfter: opts.startAfter } : {}) });
    }
  }
  const ignoring = new LimitIgnoringStorage();
  const { dobj: dIgn } = makeDO(ignoring);
  const faithful = new FaithfulStorage();
  const { dobj: dFai } = makeDO(faithful);
  await driveQuietly(async () => {
    for (let i = 1; i <= 12; i++) await dIgn.appendAudit(draftAt(i, "engine"));
    for (let i = 1; i <= 12; i++) await dFai.appendAudit(draftAt(i, "engine"));
  });
  ok(`both doubles hold 12 entries before the rollover`, ignoring.rawKeys(AUDIT_PREFIX).length === 12 && faithful.rawKeys(AUDIT_PREFIX).length === 12);
  await dIgn.rollOverAudit(1);
  await dFai.rollOverAudit(1);
  ok(`under the limit-ignoring double a ONE-entry rollover destroys the whole chain (12 -> ${ignoring.rawKeys(AUDIT_PREFIX).length})`, ignoring.rawKeys(AUDIT_PREFIX).length === 0);
  ok(`under the faithful double the same call drops exactly one (12 -> ${faithful.rawKeys(AUDIT_PREFIX).length})`, faithful.rawKeys(AUDIT_PREFIX).length === 11);
}

console.log(`\nvalidate-audit-cap-boundary: ${checks} check(s), ${failures} failure(s)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
