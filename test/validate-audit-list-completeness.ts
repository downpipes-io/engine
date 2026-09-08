// Proves finding F2 (surfaced by the F-W4-4 refuter): the audit READ paths -- readAudit (GET
// /admin/audit), verifyAudit (GET /admin/audit/verify), exportAudit's WITH-limit branch (the support
// pack's per-action keystone probe, action=X&limit=1), and loadAuditHead's migration-reconstruction
// fallback -- all funnelled through listAuditEntries()/a direct list(), a SINGLE UNBOUNDED
// storage.list({prefix: AUDIT_PREFIX}): no limit, no cursor. If the platform caps a single list() at
// ~1000 keys (this codebase asserts it repeatedly, e.g. scheduler-do-limits.ts / validate-fleet-scale.ts,
// though current Cloudflare docs are ambiguous on it), a chain longer than a page would silently
// TRUNCATE: readAudit would show a stale head, verifyAudit would under-check the chain, and a keystone
// probe hunting for the latest occurrence of an action could settle for a stale match from the first
// page instead of the true latest -- the exact defect shape the F-W4-4 fix already closed for the
// whole-log (no-limit) export path.
//
// FIX: listAuditEntries() (the ONE method all four sites read through) and loadAuditHead()'s
// reconstruction fallback now read via listAllByPrefix, the same bounded startAfter-cursor loop the
// F-W4-4 fix introduced, so the read is complete regardless of whether the ~1000-key cap is real.
//
// PROOF STRATEGY. The shared MockStorage (./mock-storage.ts) does NOT enforce a default page cap when a
// caller omits `limit` (it bounds a result only when `limit` is explicitly supplied), so a chain over
// 1000 events does not, by itself, reproduce a truncation against the OLD code under this mock -- a
// single unbounded list() call would still get everything back from the mock. What the mock DOES do
// faithfully is honour `startAfter` + `limit` (a page is capped at exactly `limit`, offset by
// `startAfter`), so this file combines two independent checks that together pin the fix:
//
//  1. DATA-PLANE cross-page correctness: seed a chain of DO_LIST_PAGE + 260 events (1260, strictly two
//     storage pages) with a "needle" audit action planted PAST the first-page boundary (seq 1150),
//     alongside two decoys of the SAME action planted WITHIN the first page (seq 3, seq 777) and ~110
//     more filler events AFTER the needle (so it is not simply "the newest entry" either). Drive the
//     real readAudit / verifyAudit / exportAudit / loadAuditHead methods and assert they surface the
//     second page: the true head (seq 1260, not page 1's boundary at 1000), the true checkedThrough
//     count, and the keystone probe's true latest match (seq 1150, not a page-1 decoy).
//
//  2. CONTROL-PLANE structural proof (the genuine negative control): MockStorage.listCalls records every
//     list() call's options, so this asserts every `audit:`-prefix scan issued by the paths under test
//     carries an explicit `limit: DO_LIST_PAGE` (never `undefined`, i.e. never a single unbounded call)
//     and that the >1-page chain issues MULTIPLE such calls, cursoring on `startAfter`. This assertion is
//     true ONLY after the fix -- pre-fix, listAuditEntries()/loadAuditHead() each issued exactly one
//     list() call with no `limit` at all. Verified by hand during development: reverting the src fix and
//     re-running this file turns every assertion in this section red (the practical negative control).
//
// Run: node test/validate-audit-list-completeness.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { AUDIT_HEAD_KEY, DO_LIST_PAGE, type AuditHead } from "../src/sched/scheduler-do-base.ts";
import { MockStorage } from "./mock-storage.ts";
import { AUDIT_PAGE_MAX, AUDIT_PREFIX, auditKey, buildEvent, type AuditDraft, type AuditEvent } from "../src/admin/audit.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

const FILLER_ACTION = "role-change";
const NEEDLE_ACTION = "dest-config-cleared"; // a real action, matching production's auditDest() target shape
const TOTAL = DO_LIST_PAGE + 260; // 1260: strictly TWO storage pages (1000 + 260)
const DECOY_SEQ_A = 3; // page 1 (a stale match a truncated read would wrongly settle for)
const DECOY_SEQ_B = 777; // page 1 (ditto)
const NEEDLE_SEQ = 1150; // page 2, past the DO_LIST_PAGE boundary, and NOT the chain's final entry either

function fillerDraft(i: number): AuditDraft {
  return {
    actorEmail: `u${i}@acme.example`,
    actorMethod: "access",
    sourceIp: null,
    action: FILLER_ACTION,
    outcome: "success",
    target: { kind: "role", email: `u${i}@acme.example`, role: "viewer" },
  };
}
const needleDraft: AuditDraft = {
  actorEmail: null,
  actorMethod: "engine",
  sourceIp: null,
  action: NEEDLE_ACTION,
  outcome: "success",
  target: { kind: "access-policy" }, // the exact target shape auditDest() uses for a real dest-config-cleared event
};

async function main(): Promise<void> {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);

  // ---- Seed the chain DIRECTLY (buildEvent + rawPut, genesis-anchored prevHash chaining), the same
  // technique test/validate-audit-export-complete.ts uses to exceed a cap cheaply without hundreds of
  // route-level appends. Track the true last event + the true needle event independently as we go, so the
  // assertions below have an oracle that never touches the code paths under test.
  let prev: AuditEvent | null = null;
  let needleEvent: AuditEvent | null = null;
  for (let seq = 1; seq <= TOTAL; seq++) {
    const isNeedle = seq === DECOY_SEQ_A || seq === DECOY_SEQ_B || seq === NEEDLE_SEQ;
    const draft = isNeedle ? needleDraft : fillerDraft(seq);
    const ts = `2026-06-01T00:00:${String(seq % 60).padStart(2, "0")}.000Z`;
    const e = await buildEvent(draft, seq, ts, prev);
    storage.rawPut(auditKey(seq), e);
    prev = e;
    if (seq === NEEDLE_SEQ) needleEvent = e;
  }
  if (prev === null || needleEvent === null) throw new Error("seeding invariant broken");
  const lastEvent: AuditEvent = prev;
  // Persist AUDIT_HEAD_KEY as a real appendAudit() run would have left it, so section 4 starts from a
  // realistic "pointer already correct" state before it is removed to simulate the post-upgrade gap.
  storage.rawPut(AUDIT_HEAD_KEY, { headSeq: TOTAL, headHash: lastEvent.hash, count: TOTAL } satisfies AuditHead);
  ok(`seeded a chain of ${TOTAL} events, strictly more than one storage page (DO_LIST_PAGE=${DO_LIST_PAGE})`, TOTAL > DO_LIST_PAGE && lastEvent.seq === TOTAL);

  // =====================================================================================================
  // SECTION 1 -- readAudit (GET /audit): the head must be the TRUE head, not page 1's last entry ---------
  // =====================================================================================================
  storage.listCalls.length = 0;
  // A large limit exercises the AUDIT_PAGE_MAX ceiling deliberately (the task's own bound: the interactive
  // PAGE cap stays UNCHANGED -- only the underlying full-chain READ becomes complete).
  const page = await dobj.readAudit(new URLSearchParams("limit=100000"));
  ok(`readAudit reports the TRUE headSeq (${TOTAL}), not page 1's boundary (${DO_LIST_PAGE})`, page.headSeq === TOTAL);
  ok("readAudit reports the TRUE headHash (matches the actually-appended last event's own hash)", page.headHash === lastEvent.hash);
  ok(`readAudit's interactive page still caps at AUDIT_PAGE_MAX (${AUDIT_PAGE_MAX}) -- the VIEW cap is UNCHANGED`, page.events.length === AUDIT_PAGE_MAX);
  ok(`readAudit's page is newest-first, starting at the true head (seq ${TOTAL})`, page.events[0]?.seq === TOTAL);

  const readCalls = storage.listCalls.filter((c) => (c.prefix ?? "") === AUDIT_PREFIX);
  ok(`readAudit's read is PAGED past DO_LIST_PAGE -- exactly 2 bounded calls for ${TOTAL} entries, not 1`, readCalls.length === 2);
  ok("readAudit's underlying read is NEVER an unbounded list() (every call carries limit: DO_LIST_PAGE) -- F2", readCalls.every((c) => c.limit === DO_LIST_PAGE));
  ok("readAudit's first page has no cursor (starts at the beginning of the prefix)", readCalls[0]?.startAfter === undefined);
  ok(`readAudit's second page cursors past page 1's last key (startAfter=${auditKey(DO_LIST_PAGE)})`, readCalls[1]?.startAfter === auditKey(DO_LIST_PAGE));

  // =====================================================================================================
  // SECTION 2 -- verifyAudit (GET /audit/verify): must check THROUGH the whole chain, not just page 1 -----
  // =====================================================================================================
  storage.listCalls.length = 0;
  const verify = await dobj.verifyAudit();
  ok("verifyAudit reports intact:true across the WHOLE chain", verify.intact === true);
  ok(`verifyAudit's checkedThrough is the TRUE last seq (${TOTAL}), not page 1's boundary`, verify.checkedThrough === TOTAL);
  ok(`verifyAudit's auditCount is the TRUE retained count (${TOTAL})`, verify.auditCount === TOTAL);

  const verifyCalls = storage.listCalls.filter((c) => (c.prefix ?? "") === AUDIT_PREFIX);
  ok(`verifyAudit's read is PAGED past DO_LIST_PAGE -- exactly 2 bounded calls for ${TOTAL} entries, not 1`, verifyCalls.length === 2);
  ok("verifyAudit's underlying read is NEVER an unbounded list() (every call carries limit: DO_LIST_PAGE) -- F2", verifyCalls.every((c) => c.limit === DO_LIST_PAGE));

  // =====================================================================================================
  // SECTION 3 -- exportAudit WITH a limit: the support pack's per-action keystone probe (action=X&limit=1)
  // =====================================================================================================
  storage.listCalls.length = 0;
  const probeResp = await dobj.exportAudit(new URLSearchParams(`action=${NEEDLE_ACTION}&limit=1`));
  const probeDoc = JSON.parse(await probeResp.text()) as { events: AuditEvent[] };
  ok(`keystone probe (action=${NEEDLE_ACTION}&limit=1) finds all 3 matches, ascending`, probeDoc.events.map((e) => e.seq).join(",") === `${DECOY_SEQ_A},${DECOY_SEQ_B},${NEEDLE_SEQ}`);
  ok(`keystone probe's LATEST match is the TRUE needle at seq ${NEEDLE_SEQ} (past the page boundary), not a page-1 decoy`, probeDoc.events[probeDoc.events.length - 1]?.seq === NEEDLE_SEQ);
  ok("keystone probe's needle event is hash-exact to what was actually appended", probeDoc.events[probeDoc.events.length - 1]?.hash === needleEvent.hash);

  const probeCalls = storage.listCalls.filter((c) => (c.prefix ?? "") === AUDIT_PREFIX);
  ok(`keystone probe's read is PAGED past DO_LIST_PAGE -- exactly 2 bounded calls for ${TOTAL} entries, not 1`, probeCalls.length === 2);
  ok("keystone probe's underlying read is NEVER an unbounded list() (every call carries limit: DO_LIST_PAGE) -- F2", probeCalls.every((c) => c.limit === DO_LIST_PAGE));

  // =====================================================================================================
  // SECTION 4 -- loadAuditHead's migration-reconstruction fallback: a post-upgrade DO with entries but no
  // pointer must reconstruct the TRUE head, or a future append silently re-anchors the chain at a stale seq.
  // =====================================================================================================
  const before = await storage.get<AuditHead>(AUDIT_HEAD_KEY);
  ok("AUDIT_HEAD_KEY is set before the fallback test (sanity)", before !== undefined && before.headSeq === TOTAL);
  await storage.delete(AUDIT_HEAD_KEY);
  ok("AUDIT_HEAD_KEY removed (simulating a deployment upgraded mid-life: entries exist, pointer does not)", (await storage.get(AUDIT_HEAD_KEY)) === undefined);

  storage.listCalls.length = 0;
  const rebuilt = await dobj.loadAuditHead();
  ok(`loadAuditHead reconstructs the TRUE headSeq (${TOTAL}), not page 1's boundary`, rebuilt.headSeq === TOTAL);
  ok("loadAuditHead reconstructs the TRUE headHash (matches the actually-appended last event's own hash)", rebuilt.headHash === lastEvent.hash);
  ok(`loadAuditHead reconstructs the TRUE count (${TOTAL})`, rebuilt.count === TOTAL);

  const rebuildCalls = storage.listCalls.filter((c) => (c.prefix ?? "") === AUDIT_PREFIX);
  ok(`loadAuditHead's reconstruction read is PAGED past DO_LIST_PAGE -- exactly 2 bounded calls, not 1`, rebuildCalls.length === 2);
  ok("loadAuditHead's reconstruction read is NEVER an unbounded list() (every call carries limit: DO_LIST_PAGE) -- F2", rebuildCalls.every((c) => c.limit === DO_LIST_PAGE));

  const persisted = await storage.get<AuditHead>(AUDIT_HEAD_KEY);
  ok("the reconstructed pointer is PERSISTED (a later read need not redo the scan)", persisted !== undefined && persisted.headSeq === TOTAL && persisted.headHash === lastEvent.hash);

  console.log(failures === 0 ? "\nAUDIT LIST-COMPLETENESS (F2) PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
