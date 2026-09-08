// validate-audit-capacity-wire.ts
//
// THE AUDIT NEAR-CAP WARNING HAD NEVER FIRED ON ANY ENGINE, AND COULD NOT.
//
// buildStatus derives `auditNearCap` only from an `auditCount` a CALLER supplies, because the count lives
// in the scheduler DO and the status builder is pure. NO call site anywhere supplies one: the field has
// never appeared in router-status.ts since the retention cap was introduced. GET /admin/status posts the
// status observation to the DO -- whose reply carries the count -- and DISCARDS the response.
//
// So `auditNearCap` was absent from every status body the engine has ever served, and the console's
// capacity card rendered its "this engine build does not report audit-log capacity, so the console cannot
// warn you before entries roll over" branch on every estate, for ever. The one warning whose entire purpose
// is to prompt an export BEFORE the retention rollover destroys evidence was structurally unreachable.
//
// AND THE BOOLEAN ALONE WOULD STILL NOT HAVE BEEN ENOUGH, which is the second half of this file. The
// retained count SATURATES: from the first rollover onwards it is pinned at exactly AUDIT_CAP, so
// {auditCount: 10000, auditNearCap: true} is the reading both when nothing has been lost and after ten
// thousand entries have been destroyed. A screen given only that boolean cannot tell an operator who can
// still export everything from one who lost a year of entries months ago, and the copy it carries says
// "Export now to retain the full history", which is a remedy that no longer exists in the second state.
// `auditRolledOverCount` is what separates them, and it now travels with the boolean.
//
// The ENGINE's rollover behaviour itself is not re-litigated here: validate-audit-cap-boundary.ts drives it
// and it is honest. This file is about whether the fact REACHES A CALLER.
import { AUDIT_CAP, AUDIT_NEAR_CAP_FRACTION, AUDIT_PREFIX, type AuditDraft, type AuditEvent } from "../src/admin/audit.ts";
import { auditNearCapAt, buildStatus, withAuditCapacity } from "../src/admin/status.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
// Importing the verdict guard ARMS it: a run that exits without reaching verdictReached below is
// forced to exit 1, so a drained event loop can never read as a clean sweep.

// FaithfulStorage implements the subset of DurableObjectStorage the audit path uses, INCLUDING list()'s
// limit and startAfter semantics, which rollOverAudit depends on (validate-audit-cap-boundary.ts records
// why a double that drops `limit` cannot measure this at all).
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
  async list<T>(opts?: { prefix?: string; limit?: number; startAfter?: string; start?: string; reverse?: boolean }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    if (opts?.reverse === true) keys = keys.reverse();
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
}

interface AuditDO {
  appendAudit(d: AuditDraft): Promise<AuditEvent>;
  auditCountAndNearCap(): Promise<{ auditCount: number; auditNearCap: boolean; auditRolledOverCount: number }>;
  observeStatus(obs: { signerConfigured: boolean; breakGlassConfigured: boolean; destConfigured: boolean; engineVersion: string }): Promise<{ appended: number; auditCount: number; auditNearCap: boolean; auditRolledOverCount: number }>;
}

function makeDO(storage: FaithfulStorage = new FaithfulStorage()): { dobj: AuditDO; storage: FaithfulStorage } {
  return { dobj: new SchedulerDO({ storage } as unknown as DurableObjectState) as unknown as AuditDO, storage };
}

// draftAt varies only CONTENT, which is the POSITION CONTROL knob: a capacity verdict must not move with
// what the entries say.
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

// The env buildStatus reads. Presence only; no value is a secret here.
const env = { SIGNER_PRIVATE: "s", BREAK_GLASS_PUBLIC: "b", ENGINE_VERSION: "0.2.0" } as unknown as Env;

// ROUTER_OPTS is the literal GET /admin/status passes to buildStatus, every optional present. If a future
// edit adds auditCount to that call site this stays correct: the point below is that the field is not in
// THIS object, and that the fold-in path is what supplies it.
const ROUTER_OPTS = {
  expiryWarnings: 0,
  restorabilityProven: 1,
  bootstrapConsumed: true,
  breakGlassTokenRetired: false,
  recoveryCodesRemaining: 8,
  consoleDestSet: true,
  consoleDestHost: "s3.example",
  cleanupPending: 0,
  selfReportedArtefactSha384: "abc",
  sourcesDetachedCount: 0,
};

const NEAR = Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION);
console.log(`validate-audit-capacity-wire  (AUDIT_CAP=${AUDIT_CAP}, near-cap warning at ${NEAR})`);

console.log("\nPART 1: the status body without a supplied count, which is what every engine served");
{
  const bare = buildStatus(env, 3, ROUTER_OPTS);
  ok("a report built from the router's own opts carries NO auditNearCap", bare.auditNearCap === undefined);
  ok("and no auditRolledOverCount either", bare.auditRolledOverCount === undefined);
  // INSTRUMENT CONTROL: the builder is not broken, so the absence above is the CALLER's, and a zero from
  // an instrument that cannot see a positive would mean nothing.
  ok("the builder DOES light the warning when a count is supplied (instrument sees a positive)", buildStatus(env, 3, { ...ROUTER_OPTS, auditCount: NEAR }).auditNearCap === true);
  ok("and leaves it false below the threshold", buildStatus(env, 3, { ...ROUTER_OPTS, auditCount: NEAR - 1 }).auditNearCap === false);
}

console.log("\nPART 2: withAuditCapacity, the fold-in the status route now performs (dose-response)");
{
  const bare = buildStatus(env, 3, ROUTER_OPTS);
  for (const [count, want] of [
    [0, false],
    [1, false],
    [NEAR - 1, false],
    [NEAR, true],
    [NEAR + 1, true],
    [AUDIT_CAP, true],
  ] as const) {
    const r = withAuditCapacity(bare, count, 0);
    ok(`count ${count} -> auditNearCap ${want}`, r.auditNearCap === want);
  }
  ok("the threshold helper and the builder agree at the edge", auditNearCapAt(NEAR) === true && auditNearCapAt(NEAR - 1) === false);
  ok("a rolled-over count travels with it", withAuditCapacity(bare, AUDIT_CAP, 2345).auditRolledOverCount === 2345);
  ok("and reads 0, not absent, on a log that has never rolled", withAuditCapacity(bare, AUDIT_CAP, 0).auditRolledOverCount === 0);
}

console.log("\nNEGATIVE CONTROL (must classify differently): a malformed count must NOT become an all-clear");
{
  const bare = buildStatus(env, 3, ROUTER_OPTS);
  for (const bad of [undefined, null, "9000", Number.NaN, Number.POSITIVE_INFINITY, -1]) {
    const r = withAuditCapacity(bare, bad, 0);
    ok(`a ${JSON.stringify(bad) ?? "undefined"} count leaves the report at the honest unknown`, r.auditNearCap === undefined && r.auditRolledOverCount === undefined);
  }
  // The distinction that matters: an unknown is NOT the same as a false. A false says "the engine answered
  // and the log is fine"; the console renders those two differently and must keep being able to.
  ok("an absent reading is distinguishable from a reported all-clear", withAuditCapacity(bare, undefined, 0).auditNearCap === undefined && withAuditCapacity(bare, 1, 0).auditNearCap === false);
}

console.log("\nPART 3: the saturation, driven past the cap on the REAL durable object");
{
  const { dobj, storage } = makeDO();
  const DOSES = [1, NEAR, AUDIT_CAP, AUDIT_CAP + 1, AUDIT_CAP + 100];
  const seen: { dose: number; count: number; nearCap: boolean; rolled: number }[] = [];
  const t0 = Date.now();
  await driveQuietly(async () => {
    for (let i = 1; i <= AUDIT_CAP + 100; i++) {
      await dobj.appendAudit(draftAt(i, "engine"));
      if (DOSES.includes(i)) {
        const c = await dobj.auditCountAndNearCap();
        seen.push({ dose: i, count: c.auditCount, nearCap: c.auditNearCap, rolled: c.auditRolledOverCount });
      }
    }
  });
  console.log(`  drove ${AUDIT_CAP + 100} real appendAudit calls in ${Date.now() - t0}ms`);
  for (const s of seen) console.log(`  appended ${s.dose}\tretained ${s.count}\tnearCap ${s.nearCap}\trolledOver ${s.rolled}`);
  const at = (n: number) => seen.find((s) => s.dose === n)!;
  ok("the retained count saturates: identical at the cap and 100 past it", at(AUDIT_CAP).count === at(AUDIT_CAP + 100).count);
  ok("the near-cap boolean saturates with it: true in both states", at(AUDIT_CAP).nearCap === true && at(AUDIT_CAP + 100).nearCap === true);
  ok("so the boolean ALONE cannot separate them, which is the defect", at(AUDIT_CAP).count === at(AUDIT_CAP + 100).count && at(AUDIT_CAP).nearCap === at(AUDIT_CAP + 100).nearCap);
  ok("the rolled-over count DOES separate them: 0 at the cap, 100 past it", at(AUDIT_CAP).rolled === 0 && at(AUDIT_CAP + 100).rolled === 100);
  ok("nothing is reported rolled over before the edge", at(1).rolled === 0 && at(NEAR).rolled === 0);
  ok("the first entry is reported rolled over at exactly one past the cap", at(AUDIT_CAP + 1).rolled === 1);
  ok("the retained key count never exceeds the cap", storage.rawKeys(AUDIT_PREFIX).length === AUDIT_CAP);

  // The route's own reply, which is where the router now reads the count from.
  const observed = await dobj.observeStatus({ signerConfigured: true, breakGlassConfigured: true, destConfigured: true, engineVersion: "0.2.0" });
  ok("POST /audit-status replies with the retained count", observed.auditCount === AUDIT_CAP);
  ok("POST /audit-status replies with the near-cap verdict", observed.auditNearCap === true);
  ok("POST /audit-status replies with the rolled-over count, which is what the router was discarding", observed.auditRolledOverCount >= 100);

  // END TO END: the reply folded into the report, which is what a console now receives.
  const folded = withAuditCapacity(buildStatus(env, 3, ROUTER_OPTS), observed.auditCount, observed.auditRolledOverCount);
  ok("the folded status body warns", folded.auditNearCap === true);
  ok("and says how much is already gone", (folded.auditRolledOverCount ?? 0) >= 100);
}

console.log("\nPOSITION CONTROL: different entry content, and unrelated keys in the same storage");
{
  const { dobj, storage } = makeDO();
  await driveQuietly(async () => {
    for (let i = 0; i < 500; i++) await storage.put(`dp:filler-${String(i).padStart(5, "0")}`, { id: i });
    for (let i = 1; i <= AUDIT_CAP + 7; i++) await dobj.appendAudit(draftAt(i, "human"));
  });
  const c = await dobj.auditCountAndNearCap();
  ok("the capacity verdict does not move with entry content", c.auditCount === AUDIT_CAP && c.auditNearCap === true);
  ok("nor with 500 unrelated keys present", c.auditRolledOverCount === 7);
  ok("and the rollover pruned nothing outside the audit prefix", storage.rawKeys("dp:").length === 500);
}

console.log(`\nvalidate-audit-capacity-wire: ${checks} check(s), ${failures} failure(s)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
