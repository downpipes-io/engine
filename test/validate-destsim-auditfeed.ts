// Validates earliestSeq exposure and the O(limit) forward-page read, driving the REAL
// SchedulerDO.exportAudit over MockStorage.
//
// Silent audit gap: if the feed envelope carried headSeq/headHash but never the OLDEST retained seq, a
// collector whose checkpoint fell below the earliest retained entry (after a retention rollover pruned the
// gap) would get the next window with no signal that it missed events -- the highest-severity class for a
// security feed. The DO export returns earliestSeq; the Worker envelope derives gapBefore from it.
//
// Paging cost: the `audit:` keys are zero-padded seq, so the forward page is a bounded storage.list from
// the cursor key (+ one bounded read each for head and earliest) -- genuinely O(limit), rather than loading
// the whole retained chain per feed poll and paging it in memory. A richer query or a whole-log export reads
// the whole set via the PAGED full-prefix scan (listAllByPrefix, bounded DO_LIST_PAGE pages looped on a
// cursor), which is complete at scale, not a single unbounded list.
//
// Run: node test/validate-destsim-auditfeed.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { DO_LIST_PAGE } from "../src/sched/scheduler-do-base.ts";
import { MockStorage } from "./mock-storage.ts";
import { AUDIT_PREFIX } from "../src/admin/audit.ts";
import type { AuditEvent } from "../src/admin/audit-types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

interface ExportDoc {
  events: AuditEvent[];
  headSeq: number;
  headHash: string;
  earliestSeq?: number;
}

async function main(): Promise<void> {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);

  // Seed a real chain of 60 events via the DO's own append (valid hash chain, seqs 1..60).
  for (let i = 0; i < 60; i++) {
    await dobj.appendAudit({
      actorEmail: `u${i}@acme.example`,
      actorMethod: "access",
      sourceIp: null,
      action: "role-change",
      outcome: "success",
      target: { kind: "role", email: `u${i}@acme.example`, role: "viewer" },
    });
  }

  const exportOf = async (qs: string): Promise<ExportDoc> => JSON.parse(await (await dobj.exportAudit(new URLSearchParams(qs))).text()) as ExportDoc;

  // --- a forward feed page is a BOUNDED read (O(limit)), and returns the right window ---
  storage.listCalls.length = 0;
  const page = await exportOf("afterSeq=10&limit=5");
  ok("forward page returns exactly the 5 oldest events after the cursor", page.events.length === 5);
  ok("forward page is seq 11..15 ascending", page.events.map((e) => e.seq).join(",") === "11,12,13,14,15");
  ok("forward page reports headSeq=60", page.headSeq === 60);
  // Every list call the feed page issued was BOUNDED (carried a limit); none was an unbounded full-prefix scan.
  const feedCalls = storage.listCalls.filter((c) => (c.prefix ?? "") === AUDIT_PREFIX);
  ok("feed page issued at least one list call", feedCalls.length > 0);
  ok("feed page issued NO unbounded full-prefix scan (every call bounded by a limit) -- O(limit)", feedCalls.every((c) => typeof c.limit === "number"));
  const boundedPageCall = feedCalls.find((c) => c.limit === 5 && typeof c.start === "string");
  ok("feed page used a bounded list from the cursor key (start + limit=5)", boundedPageCall !== undefined);

  // Contrast: a whole-log export (no cursor) reads the WHOLE set, but via the PAGED full-prefix scan
  // (listAllByPrefix: bounded DO_LIST_PAGE pages looped on a startAfter cursor until the prefix is
  // exhausted), NOT a single unbounded list(). A bare unbounded list truncates at one platform page
  // (~DO_LIST_PAGE) on the real backend, so a chain longer than a page would export INCOMPLETE while
  // presenting itself as the whole log; the paged scan enumerates every retained entry.
  // It is still O(retained) -- the whole set IS the point -- just complete at scale, unlike the feed page.
  storage.listCalls.length = 0;
  const whole = await exportOf("");
  ok("whole export returns all 60 events", whole.events.length === 60);
  const wholeCalls = storage.listCalls.filter((c) => (c.prefix ?? "") === AUDIT_PREFIX);
  ok("whole export issued at least one prefix scan", wholeCalls.length > 0);
  ok("whole export pages the full prefix (every scan bounded by DO_LIST_PAGE, none an unbounded list) -- complete at scale", wholeCalls.every((c) => c.limit === DO_LIST_PAGE));

  // --- earliestSeq is exposed, and reflects rollover ---
  ok("export exposes earliestSeq", typeof page.earliestSeq === "number");
  ok("earliestSeq is 1 before any rollover", page.earliestSeq === 1);

  // Simulate a retention rollover: prune the oldest 20 entries (seqs 1..20) directly in storage. The chain
  // now legitimately begins at seq 21 (exactly the post-AUDIT_CAP-rollover state verifyAudit already handles).
  for (let seq = 1; seq <= 20; seq++) {
    await storage.delete(AUDIT_PREFIX + String(seq).padStart(20, "0"));
  }
  const afterRollover = await exportOf("afterSeq=2&limit=5");
  ok("after rollover, earliestSeq reflects the oldest RETAINED entry (21)", afterRollover.earliestSeq === 21);
  ok("after rollover, a stale cursor (afterSeq=2) returns the oldest retained window (21..25), not a throw", afterRollover.events.map((e) => e.seq).join(",") === "21,22,23,24,25");

  // The Worker envelope's gap signal is a pure function of afterSeq + earliestSeq; assert both the gap and the
  // no-gap cases against the exact rule the Worker applies (afterSeq + 1 < earliestSeq).
  const gapBefore = (afterSeq: number, earliestSeq: number): boolean => earliestSeq > 0 && afterSeq + 1 < earliestSeq;
  ok("gap DETECTED: a collector at afterSeq=2 with earliestSeq=21 sees gapBefore=true", gapBefore(2, afterRollover.earliestSeq!) === true);
  ok("NO false gap: a caught-up collector at afterSeq=20 with earliestSeq=21 sees gapBefore=false", gapBefore(20, afterRollover.earliestSeq!) === false);
  ok("NO false gap: exactly at the boundary afterSeq=earliestSeq-1 is not a gap", gapBefore(afterRollover.earliestSeq! - 1, afterRollover.earliestSeq!) === false);

  // --- parity: the bounded fast path agrees with the slow path for the same window ---
  // A limit larger than the retained tail returns everything after the cursor, same as a full scan would.
  const tail = await exportOf("afterSeq=50&limit=1000");
  ok("fast path with a big limit returns the whole retained tail after the cursor (51..60)", tail.events.map((e) => e.seq).join(",") === "51,52,53,54,55,56,57,58,59,60");

  console.log(failures === 0 ? "\nDESTSIM AUDIT-FEED PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
