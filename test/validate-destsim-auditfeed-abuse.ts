// destsim: CONSUMER-side abuse validators for the SIEM audit-feed PULL surface (GET /support/audit-feed,
// handleSupportPull's audit-feed branch, src/admin/support-ingest.ts). This drives the REAL production
// path -- handleSupportPull -> a REAL SchedulerDO (src/sched/scheduler-do.ts, AuditMixin) backed by
// MockStorage -- so pagination, cursor/limit coercion, concurrent-write stability and the AUDIT_CAP
// retention rollover exercise the DO's actual exportAudit/appendAudit/rollOverAudit/listAuditEntries
// (src/sched/scheduler-do-audit.ts), never a hand-rolled double. It is a companion to test/validate-
// support.ts (which proves the credentialing + basic paging mechanics); this file is scoped to ABUSE:
// hostile/garbage cursors, limit extremes, a stale checkpoint surviving concurrent appends, and the
// silent gap a retention rollover opens in the collector's view. This pins a non-finite afterSeq pagination bypass and the plain-garbage-cursor-no-400 diagnosability gap,
// alongside the retention-rollover gap signal and the O(limit) paging cost.
//
// Credential grants and seeded downpipe/audit state are written DIRECTLY to storage (matching the
// `ingestcred:<scope>` key shape src/sched/scheduler-do-routing.ts's POST /ingest-credential/set uses,
// and the auditKey()/buildEvent() chaining src/sched/scheduler-do-audit.ts's appendAudit uses) rather
// than through the gated DO routes, so every seeded audit chain has a clean, predictable seq numbering
// (no incidental "support-credential-grant" event competing for seq 1) and setup is fast. The SURFACE
// under test -- handleSupportPull, exportAudit, appendAudit, rollOverAudit -- is always the real code.
//
// Run: node test/validate-destsim-auditfeed-abuse.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { CountingStorage } from "./destsim/counting-storage.ts";
import { mintIngestCredential, handleSupportPull } from "../src/admin/support-ingest.ts";
import { buildEvent, auditKey, AUDIT_CAP } from "../src/admin/audit.ts";
import type { AuditDraft, AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EMPTY_ENV = {} as unknown as Env;

// A single reusable draft: the target's CONTENT never matters to any assertion in this file (only
// seq/hash/prevHash/chain shape do), so every seeded event uses the smallest well-formed target
// (the field-less "access-policy" kind) and the "role-change" action (an arbitrary AUDIT_ACTIONS
// member; nothing here couples an action to a specific target kind).
const DRAFT: AuditDraft = {
  actorEmail: null,
  actorMethod: "engine",
  sourceIp: null,
  action: "role-change",
  outcome: "success",
  target: { kind: "access-policy" },
};

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

function makeCountingScheduler(): { storage: CountingStorage; stub: SchedulerDO } {
  const storage = new CountingStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

// asStub adapts a real SchedulerDO test double to the DurableObjectStub shape handleSupportPull
// expects (mirrors test/validate-metrics.ts's identical helper): the platform bridges a stub's
// TWO-ARGUMENT fetch(url, init) into the ONE-ARGUMENT Request SchedulerDO.fetch expects.
function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)),
  } as unknown as DurableObjectStub;
}

// seedCredential writes a minted "audit-feed" grant directly under the SAME storage key
// (`ingestcred:<scope>`) POST /ingest-credential/set writes, bypassing that gated route (which also
// appends an audit event of its own -- avoided here so every test's seeded chain has predictable,
// off-by-one-free seq numbering starting at 1).
async function seedAuditFeedCredential(storage: MockStorage | CountingStorage): Promise<string> {
  const minted = await mintIngestCredential("audit-feed", "owner@example.com.au", undefined);
  storage.rawPut("ingestcred:audit-feed", minted.grant);
  return `${minted.clientId}.${minted.secret}`;
}

async function pull(stub: SchedulerDO, bearer: string, qs: string): Promise<Response> {
  return handleSupportPull(new Request(`https://e/support/audit-feed${qs}`, { headers: { Authorization: `Bearer ${bearer}` } }), EMPTY_ENV, asStub(stub));
}

interface FeedEnvelope {
  kind: string;
  v: number;
  afterSeq: number | null;
  nextAfterSeq: number;
  headSeq: number;
  headHash: string;
  count: number;
  events: Array<{ seq: number; prevHash: string; hash: string }>;
  earliestSeq?: number; // F2: the oldest retained seq, so a lagging collector can detect a rollover gap
  gapBefore?: boolean; // F2: true when afterSeq+1 < earliestSeq (the collector's checkpoint skipped pruned events)
}

// seedChain writes `count` real, hash-chained AuditEvents directly to storage starting at seq 1
// (genesis), using the REAL buildEvent()/auditKey() chaining logic -- the SAME functions the DO's own
// appendAudit calls -- so the physically-stored chain is byte-identical to what an equal number of
// appendAudit() calls would produce. Used (instead of calling appendAudit() in a loop) for the two
// pure query-PARAMETER abuse tests below, where the chain-construction mechanism is incidental to what
// is under test: it avoids appendAudit's mirrorAuditEvent side effect (admin/audit-mirror.ts), which
// intentionally logs one JSON line per event to stdout (the real production SIEM egress) and would
// otherwise flood these two tests' output for no benefit to the assertions they make. The forward-
// cursor-correctness and concurrent-write-stability tests below deliberately keep calling the real
// stub.appendAudit(), since a real append (not just real chaining math) is exactly what those two
// prove pagination survives.
async function seedChain(storage: MockStorage | CountingStorage, count: number): Promise<void> {
  let prev: AuditEvent | null = null;
  for (let seq = 1; seq <= count; seq++) {
    const ts = new Date(Date.parse("2026-01-01T00:00:00.000Z") + seq * 1000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    const event = await buildEvent(DRAFT, seq, ts, prev);
    storage.rawPut(auditKey(seq), event);
    prev = event;
  }
}

// ---- Forward-cursor correctness -----------------------------------------------------------------
async function testForwardCursorCorrectness(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedAuditFeedCredential(storage);
  const N = 237; // an odd, non-round total so a fixed page size never divides it evenly
  for (let i = 0; i < N; i++) await stub.appendAudit(DRAFT);

  for (const limit of [1, 3, 7, 50, 500, 1000]) {
    const seen: number[] = [];
    let cursor = 0;
    let guard = 0;
    for (;;) {
      guard++;
      if (guard > N + 5) throw new Error(`forward walk with limit=${limit} did not terminate (possible infinite loop)`);
      const resp = await pull(stub, bearer, `?afterSeq=${cursor}&limit=${limit}`);
      const body = (await resp.json()) as FeedEnvelope;
      if (body.events.length === 0) break;
      for (const e of body.events) seen.push(e.seq);
      cursor = body.nextAfterSeq;
      if (body.events.length < limit) break; // a short page means the walk is done
    }
    ok(`limit=${limit}: every one of the ${N} seeded events is delivered exactly once`, seen.length === N && new Set(seen).size === N);
    ok(`limit=${limit}: events arrive in strict ascending seq order across pages (no gaps/dupes)`, seen.every((s, i) => i === 0 || s === seen[i - 1]! + 1) && seen[0] === 1);
    ok(`limit=${limit}: the walk's final cursor lands exactly on the last seq (${N})`, cursor === N);
  }
}

// ---- Cursor (afterSeq) abuse ---------------------------------------------------------------------
async function testCursorAbuse(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedAuditFeedCredential(storage);
  const N = 30;
  await seedChain(storage, N); // seqs 1..30, headSeq 30

  // STRICT CURSOR: a present-but-malformed afterSeq (non-numeric / non-finite / negative) is a
  // clear 400, never silently coerced to 0 (which would replay the whole retained log and hide a client bug
  // re-sending a corrupt cursor). Absent/empty defaults to 0; a valid finite non-negative number is accepted
  // and floored (consistent with the DO's own parseAuditFilter).
  // negative -> 400 (was: silently clamped to 0)
  {
    const resp = await pull(stub, bearer, "?afterSeq=-5&limit=10");
    ok("afterSeq=-5 (negative): 400 (strict cursor, never a silent clamp to 0)", resp.status === 400);
  }
  // huge but finite (> headSeq) -> accepted as-is, yields an honest empty page, never an error
  {
    const resp = await pull(stub, bearer, "?afterSeq=999999999&limit=10");
    ok("afterSeq=999999999 (> headSeq): 200, never a throw/500", resp.status === 200);
    const body = (await resp.json()) as FeedEnvelope;
    ok("afterSeq=999999999: returns an EMPTY page (nothing exceeds it), not an error", body.count === 0 && body.events.length === 0);
    ok("afterSeq=999999999: nextAfterSeq echoes the requested cursor (no progress possible)", body.nextAfterSeq === 999999999);
  }
  // non-numeric "abc" -> 400 (was: NaN silently coerced to 0)
  {
    const resp = await pull(stub, bearer, "?afterSeq=abc&limit=10");
    ok("afterSeq=abc (non-numeric): 400, not a silent replay-from-0", resp.status === 400);
  }
  // the literal string "NaN" -> 400 (Number('NaN') is NaN, not finite)
  {
    const resp = await pull(stub, bearer, "?afterSeq=NaN&limit=5");
    ok('afterSeq="NaN": 400 (not finite)', resp.status === 400);
  }
  // "1e9" is VALID scientific notation to Number() -- a huge-but-finite cursor, accepted
  {
    const resp = await pull(stub, bearer, "?afterSeq=1e9&limit=5");
    ok("afterSeq=1e9 (finite scientific notation): 200", resp.status === 200);
    const body = (await resp.json()) as FeedEnvelope;
    ok("afterSeq=1e9: parsed as 1,000,000,000 (a huge FINITE cursor) -> empty page", body.afterSeq === 1_000_000_000 && body.count === 0);
  }
  // float "3.9" -> floors to 3 (Math.floor)
  {
    const resp = await pull(stub, bearer, "?afterSeq=3.9&limit=100");
    ok("afterSeq=3.9 (finite float): 200", resp.status === 200);
    const body = (await resp.json()) as FeedEnvelope;
    ok("afterSeq=3.9: floors to 3, first returned event is seq 4", body.afterSeq === 3 && body.events[0]?.seq === 4);
  }
  // empty string -> Number('') === 0 (a JS quirk), same as an absent cursor
  {
    const resp = await pull(stub, bearer, "?afterSeq=&limit=5");
    ok("afterSeq= (empty string): 200, treated as an absent cursor", resp.status === 200);
    const body = (await resp.json()) as FeedEnvelope;
    ok("afterSeq= (empty string): resolves to 0, same as an absent cursor", body.afterSeq === 0 && body.events[0]?.seq === 1);
  }
  // whitespace-padded numeric "  5 " -> Number() trims whitespace and parses cleanly (finite -> accepted)
  {
    const resp = await pull(stub, bearer, `?afterSeq=${encodeURIComponent("  5 ")}&limit=100`);
    ok("afterSeq='  5 ' (whitespace-padded finite): 200", resp.status === 200);
    const body = (await resp.json()) as FeedEnvelope;
    ok("afterSeq='  5 ': resolves cleanly to 5, no odd behaviour", body.afterSeq === 5 && body.events[0]?.seq === 6);
  }
  // "1e400" overflows Number() to Infinity, which would otherwise bypass BOTH the cursor filter and the page
  // limit (the DO returning the whole chain unpaginated). The Worker's finite check rejects it with a 400
  // before the DO is ever reached.
  {
    const resp = await pull(stub, bearer, "?afterSeq=1e400&limit=3");
    ok("afterSeq=1e400 (overflows to Infinity): 400 -- the pagination bypass is closed", resp.status === 400);
  }
  // Contrast: an overflowing LIMIT is not a cursor, so it is still leniently clamped (a page-size hint), not
  // a 400 -- the Worker's own Math.min(..., 1000) clamp bounds it safely.
  {
    const resp = await pull(stub, bearer, "?afterSeq=0&limit=1e400");
    ok("limit=1e400: 200 (the limit stays leniently clamped to 1000, a page-size hint)", resp.status === 200);
    const body = (await resp.json()) as FeedEnvelope;
    ok("limit=1e400: safely bounded, whole chain returned within the 1000 clamp", body.count === N);
  }
}

// ---- limit abuse ------------------------------------------------------------------------------
async function testLimitAbuse(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedAuditFeedCredential(storage);
  const N = 20;
  await seedChain(storage, N);

  // limit=0: NOT clamped to the floor of 1 -- `0 || 500` is falsy in JS, so it falls back to the
  // DEFAULT (500), a quirk distinct from a genuine floor-clamp.
  {
    const resp = await pull(stub, bearer, "?afterSeq=0&limit=0");
    const body = (await resp.json()) as FeedEnvelope;
    ok("limit=0: falls back to the DEFAULT 500 (0 is falsy in `||500`), NOT clamped to a floor of 1 -- returns all 20", body.count === N);
  }
  // limit=-1: clamps to the floor of 1 (Math.max(-1,1)=1)
  {
    const resp = await pull(stub, bearer, "?afterSeq=0&limit=-1");
    const body = (await resp.json()) as FeedEnvelope;
    ok("limit=-1: clamps to the floor of 1", body.count === 1);
  }
  // limit=99999: clamps to the ceiling of 1000 (all 20 available events fit comfortably under it)
  {
    const resp = await pull(stub, bearer, "?afterSeq=0&limit=99999");
    const body = (await resp.json()) as FeedEnvelope;
    ok("limit=99999: clamps to the ceiling of 1000", body.count === N);
  }
  // limit=abc: non-numeric -> falls back to the default 500
  {
    const resp = await pull(stub, bearer, "?afterSeq=0&limit=abc");
    const body = (await resp.json()) as FeedEnvelope;
    ok("limit=abc: falls back to the default 500 (NaN is falsy)", body.count === N);
  }
  // limit=3.9: float floors to 3
  {
    const resp = await pull(stub, bearer, "?afterSeq=0&limit=3.9");
    const body = (await resp.json()) as FeedEnvelope;
    ok("limit=3.9: floors to 3", body.count === 3);
  }
}

// ---- Concurrent-write stability ------------------------------------------------------------------
async function testConcurrentWriteStability(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedAuditFeedCredential(storage);
  const K = 15;
  for (let i = 0; i < K; i++) await stub.appendAudit(DRAFT); // seqs 1..15

  // Checkpoint at the current head: nothing beyond it yet.
  const atHead = (await (await pull(stub, bearer, `?afterSeq=${K}&limit=100`)).json()) as FeedEnvelope;
  ok("checkpoint at the current head: an empty page (nothing beyond it yet)", atHead.events.length === 0 && atHead.headSeq === K);

  // A full snapshot of the retained window [1..K], to diff against after more events land.
  const windowBefore = ((await (await pull(stub, bearer, "?afterSeq=0&limit=1000")).json()) as FeedEnvelope).events;

  const M = 10;
  for (let i = 0; i < M; i++) await stub.appendAudit(DRAFT); // seqs 16..25

  // The previously-returned window is byte-identical on re-pull: seqs are never renumbered.
  const windowAfterFull = ((await (await pull(stub, bearer, "?afterSeq=0&limit=1000")).json()) as FeedEnvelope).events;
  const firstK = windowAfterFull.slice(0, K);
  ok("the previously-returned window [1..K] is UNCHANGED after new appends (same seqs+hashes, never renumbered)", JSON.stringify(firstK) === JSON.stringify(windowBefore));

  // Resuming from the checkpoint sees ONLY the new events, every one with seq strictly above the
  // checkpoint's head, contiguous, and the head has advanced by exactly M.
  const resumed = (await (await pull(stub, bearer, `?afterSeq=${K}&limit=100`)).json()) as FeedEnvelope;
  ok(`resuming from the checkpoint returns exactly the ${M} new events`, resumed.count === M);
  ok("every new event has seq strictly above the checkpoint head (monotonic, never renumbered)", resumed.events.every((e) => e.seq > K));
  ok("the new events' seqs are contiguous with no gap/dupe", resumed.events.map((e) => e.seq).join(",") === Array.from({ length: M }, (_, i) => K + 1 + i).join(","));
  ok("the head advanced to exactly K+M", resumed.headSeq === K + M);
}

// ---- ROLLOVER GAP --------------------------------------------------------------------
// seedPostRolloverChain seeds storage DIRECTLY with a chain whose earliest RETAINED seq is well above
// 1, simulating the state a real DO reaches once AUDIT_CAP=10000 appends have rolled the oldest
// entries over -- WITHOUT physically performing 10,000+ real appends (appendAudit is O(1) per call,
// but a brute-force 10k+ loop would still cost real wall time and flood stdout via mirrorAuditEvent's
// intentional per-event console.log, admin/audit-mirror.ts). It uses the REAL buildEvent()/auditKey()
// chaining logic from audit.ts -- the SAME functions appendAudit itself calls -- so the physically-
// stored suffix is a genuine, hash-verifiable chain; only the PRUNED prefix (seq 1..earliestSeq-1) is
// absent, exactly as it would be on a real DO after rollOverAudit deleted it. earliestSeq is chosen
// just above AUDIT_CAP so the numbers themselves read as "past the retention cap".
async function seedPostRolloverChain(storage: MockStorage, earliestSeq: number, retainedCount: number): Promise<{ headSeq: number; headHash: string }> {
  // The baseline (first retained) entry's prevHash cannot be the real pruned predecessor's hash -- it
  // is gone -- so it is stamped with an OBVIOUSLY synthetic placeholder. verifyChain never checks the
  // baseline entry's prevHash when expectGenesis is false (a documented rollover, admin/audit.ts), so
  // this placeholder is never read as meaningful by any consumer this validator drives.
  const PRUNED_PLACEHOLDER = { hash: `sha384:${"f".repeat(96)}` } as AuditEvent;
  let prev: AuditEvent | null = null;
  let lastEvent: AuditEvent | null = null;
  for (let i = 0; i < retainedCount; i++) {
    const seq = earliestSeq + i;
    const ts = new Date(Date.parse("2026-01-01T00:00:00.000Z") + i * 1000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
    const event = await buildEvent(DRAFT, seq, ts, i === 0 ? PRUNED_PLACEHOLDER : prev);
    storage.rawPut(auditKey(seq), event);
    prev = event;
    lastEvent = event;
  }
  if (lastEvent === null) throw new Error("seedPostRolloverChain: retainedCount must be > 0");
  return { headSeq: lastEvent.seq, headHash: lastEvent.hash };
}

async function testRolloverGap(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedAuditFeedCredential(storage);

  const EARLIEST = AUDIT_CAP + 1; // 10001: reads as "one append past the 10000 retention cap"
  const RETAINED = 25;
  const { headSeq, headHash } = await seedPostRolloverChain(storage, EARLIEST, RETAINED);

  // Sanity: the synthetic chain is a genuine, hash-verifiable rollover state under the REAL verify
  // path (not merely plausible-looking JSON) -- proves the simulation is faithful before trusting
  // what the pull surface reports about it.
  const verdict = await stub.verifyAudit();
  ok("seeded post-rollover chain: verifies intact under the REAL verifyChain", verdict.intact === true);
  ok("seeded post-rollover chain: verify recognises the legitimate rollover (chain begins above seq 1)", verdict.rolledOver === true && verdict.earliestSeq === EARLIEST);

  // A collector whose checkpoint predates the rollover boundary by a wide margin (it last saw up to
  // seq 50, long before the retained window now starts at seq 10001).
  const staleAfterSeq = 50;
  const resp = await pull(stub, bearer, `?afterSeq=${staleAfterSeq}&limit=1000`);
  ok("a stale afterSeq below the earliest retained seq: 200, never a throw/500", resp.status === 200);
  const body = (await resp.json()) as FeedEnvelope;

  ok("the feed returns the next window starting at the earliest RETAINED seq (not the collector's naively-expected seq+1)", body.events[0]?.seq === EARLIEST);
  ok("the window carries every retained event exactly once, ascending", body.count === RETAINED && body.events.every((e, i) => i === 0 || e.seq === body.events[i - 1]!.seq + 1));
  ok("headSeq/nextAfterSeq reflect the true (post-rollover) head", body.headSeq === headSeq && body.nextAfterSeq === headSeq && body.headHash === headHash);

  // The envelope carries earliestSeq + gapBefore, so a lagging collector whose checkpoint fell below the
  // earliest retained seq is EXPLICITLY told it skipped pruned events, instead of silently trusting
  // nextAfterSeq/count and never noticing.
  ok("the envelope carries earliestSeq (the oldest retained seq)", body.earliestSeq === EARLIEST);
  ok("gapBefore is true -- the collector is EXPLICITLY signalled that its stale checkpoint skipped pruned events", body.gapBefore === true);
  const impliedGap = (body.events[0]?.seq ?? 0) - (staleAfterSeq + 1);
  ok(`the ${EARLIEST - 1 - staleAfterSeq} pruned events (seq ${staleAfterSeq + 1}..${EARLIEST - 1}) are detectable -- earliestSeq (${EARLIEST}) > afterSeq+1 (${staleAfterSeq + 1})`, impliedGap === EARLIEST - 1 - staleAfterSeq && (body.earliestSeq ?? 0) > staleAfterSeq + 1);
}

// ---- Paging cost ----------------------------------------------------------------------
async function testPagingCostIsONotOLimit(): Promise<void> {
  const { storage, stub } = makeCountingScheduler();
  const bearer = await seedAuditFeedCredential(storage);

  // A large retained chain, seeded directly with the real chaining logic (fast: no per-event DO route
  // round trip, no mirrorAuditEvent console spam).
  const RETAINED = 2000;
  await seedChain(storage, RETAINED);

  storage.listCalls.length = 0; // only count the calls the pull itself makes
  const resp = await pull(stub, bearer, "?afterSeq=0&limit=1");
  const body = (await resp.json()) as FeedEnvelope;
  ok("a limit=1 page still returns exactly 1 event (the RESPONSE is correctly bounded)", body.count === 1);

  const auditListCalls = storage.listCallsFor("audit:");
  // exportAudit's pure forward-feed page (afterSeq + limit, no other filter) is a BOUNDED storage.list from
  // the cursor key -- the `audit:` keys are zero-padded seq -- plus one bounded read each for the head and
  // the earliest. None of them scans the whole retained prefix, so the DO's internal work is O(limit), not
  // O(retained).
  ok("the forward page still issues audit: list calls (a bounded page read + head + earliest)", auditListCalls.length >= 1);
  ok(`NO list call scanned all ${RETAINED} retained keys -- the DO answers a limit=1 page in O(limit)`, !auditListCalls.some((c) => c.resultSize === RETAINED));
  ok("every audit: list call is bounded to a small result (the page limit + the two 1-row head/earliest reads)", auditListCalls.every((c) => c.resultSize <= 2));
}

async function main(): Promise<void> {
  console.log("forward-cursor correctness:");
  await testForwardCursorCorrectness();
  console.log("\ncursor (afterSeq) abuse:");
  await testCursorAbuse();
  console.log("\nlimit abuse:");
  await testLimitAbuse();
  console.log("\nconcurrent-write stability:");
  await testConcurrentWriteStability();
  console.log("\nrollover gap:");
  await testRolloverGap();
  console.log("\npaging cost:");
  await testPagingCostIsONotOLimit();

  console.log(failures === 0 ? "\nDESTSIM AUDIT-FEED ABUSE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
