// Digest-flush vectors for the validate-notify suite (TC-N-19..TC-N-24), split out of
// validate-notify.ts. Covers the daily/weekly success-stream
// summary: digestWindowElapsed, summariseDigest/renderDigestDetail, groupDigestDue, deferral
// accumulation, the digest-due window + digest-sent clear, and the fail-open behaviour.

import {
  summariseDigest,
  renderDigestDetail,
  digestEmissionFor,
  groupDigestDue,
  digestWindowElapsed,
  type PendingDigestEntry,
  type DigestBatch,
  type NotifyChannel,
} from "../src/notify.ts";
import { ok, makeScheduler, stubFetch, callerFetch, isoAt, mkPending, DAY_MS, WEEK_MS } from "./validate-notify-shared.ts";

// ---- TC-N-19: digestWindowElapsed (the clockless window predicate) -------------------------

function testDigestWindowElapsed(): void {
  const base = Date.UTC(2026, 5, 1, 0, 0, 0); // a fixed reference epoch
  // daily: not due at 23h59m, due at exactly 24h and beyond.
  ok("digestWindowElapsed: daily not due before 24h", digestWindowElapsed("daily", base, base + DAY_MS - 1000) === false);
  ok("digestWindowElapsed: daily due at exactly 24h", digestWindowElapsed("daily", base, base + DAY_MS) === true);
  ok("digestWindowElapsed: daily due past 24h", digestWindowElapsed("daily", base, base + DAY_MS + 60_000) === true);
  // weekly: daily-aged batch (1 day) is NOT due under a weekly window; due at 7d.
  ok("digestWindowElapsed: weekly not due at 1 day", digestWindowElapsed("weekly", base, base + DAY_MS) === false);
  ok("digestWindowElapsed: weekly not due before 7d", digestWindowElapsed("weekly", base, base + WEEK_MS - 1000) === false);
  ok("digestWindowElapsed: weekly due at exactly 7d", digestWindowElapsed("weekly", base, base + WEEK_MS) === true);
  // conservative guards: future oldest (skew) and non-finite inputs are never due.
  ok("digestWindowElapsed: future oldest -> not due (skew)", digestWindowElapsed("daily", base + 10_000, base) === false);
  ok("digestWindowElapsed: NaN oldest -> not due", digestWindowElapsed("daily", Number.NaN, base + WEEK_MS) === false);
  ok("digestWindowElapsed: NaN now -> not due", digestWindowElapsed("daily", base, Number.NaN) === false);
}

// ---- TC-N-20: summariseDigest + renderDigestDetail (redaction-safe roll-up) ----------------

// Core summary/render: counts, deduped names, account-level count, the redaction-safe rendered line,
// the digest emission and the bounded "and N more" names tail. 
function testDigestSummaryRollup(): void {
  const base = Date.UTC(2026, 5, 1, 0, 0, 0);
  const entries: PendingDigestEntry[] = [
    mkPending({ seq: 1, atMs: base + 5000, event: "backup-success", downpipeId: "p1", downpipeName: "Prod KV" }),
    mkPending({ seq: 2, atMs: base + 1000, event: "backup-success", downpipeId: "p2", downpipeName: "Prod R2" }), // oldest
    mkPending({ seq: 3, atMs: base + 9000, event: "restore-test-pass", downpipeId: "p1", downpipeName: "Prod KV" }), // dup name
    mkPending({ seq: 4, atMs: base + 7000, event: "role-change", downpipeId: null, downpipeName: null }), // account-level
  ];
  const s = summariseDigest(entries);
  ok("summariseDigest: total counts all", s.total === 4);
  ok("summariseDigest: per-event count backup-success=2", s.byEvent["backup-success"] === 2);
  ok("summariseDigest: per-event count restore-test-pass=1", s.byEvent["restore-test-pass"] === 1);
  ok("summariseDigest: per-event count role-change=1", s.byEvent["role-change"] === 1);
  ok("summariseDigest: distinct downpipe names, deduped + sorted", s.downpipeNames.length === 2 && s.downpipeNames[0] === "Prod KV" && s.downpipeNames[1] === "Prod R2");
  ok("summariseDigest: account-level occurrence counted", s.accountLevelCount === 1);
  ok("summariseDigest: window from oldest..newest", s.fromAt === isoAt(base + 1000) && s.toAt === isoAt(base + 9000));

  // The rendered line is redaction-safe: it carries counts + names, and NO url/secret/key token.
  const line = renderDigestDetail(s);
  ok("renderDigestDetail: mentions the total", line.includes("4 updates"));
  ok("renderDigestDetail: mentions an event count", line.includes("2 backup-success"));
  ok("renderDigestDetail: mentions the downpipe names", line.includes("Prod KV") && line.includes("Prod R2"));
  ok("renderDigestDetail: no secret/url/key token in the roll-up", !/https?:|secret|routingKey|key=|authorization/i.test(line));

  // digestEmissionFor: info severity, account-level (null downpipe), detail = the roll-up line.
  const em = digestEmissionFor(s, isoAt(base + WEEK_MS));
  ok("digestEmissionFor: severity is info (success-class roll-up)", em.severity === "info");
  ok("digestEmissionFor: downpipeId/Name null (spans many pipes)", em.downpipeId === null && em.downpipeName === null);
  ok("digestEmissionFor: modal event is backup-success (most frequent)", em.event === "backup-success");
  ok("digestEmissionFor: detail is the rendered roll-up", em.detail === line);

  // Names line is bounded: a large fan-out is capped with an "and N more" tail (no unbounded line).
  const many: PendingDigestEntry[] = [];
  for (let i = 0; i < 20; i++) many.push(mkPending({ seq: i + 1, atMs: base + i, downpipeId: `p${i}`, downpipeName: `Pipe ${String(i).padStart(2, "0")}` }));
  const bigLine = renderDigestDetail(summariseDigest(many));
  ok("renderDigestDetail: bounded names with 'and N more'", bigLine.includes("and 12 more"));
}

// instant-ordering: fromAt/toAt are chosen by instant (not lexical string order) and a non-finite
// `at` never wins the window. 
function testDigestSummaryInstantWindow(): void {
  const base = Date.UTC(2026, 5, 1, 0, 0, 0);
  // fromAt/toAt must be chosen by INSTANT, not by lexical RFC-3339 string order. We
  // seed three entries whose raw `at` strings sort lexically in a DIFFERENT order than their true
  // instants (mixed offset + precision), so a lexical < / > would pick the WRONG window ends:
  //   - "...T20:00:00+10:00"  -> instant 10:00:00Z  (the EARLIEST instant, but sorts LAST lexically
  //                                                   because "2" > "1")
  //   - "...T12:00:00Z"       -> instant 12:00:00Z  (middle instant; sorts FIRST lexically)
  //   - "...T18:00:00.5Z"     -> instant 18:00:00.5Z (the LATEST instant; sorts MIDDLE lexically)
  // Lexical order would give fromAt = the 12:00Z string and toAt = the +10:00 string (both wrong).
  // By instant the oldest is the +10:00 entry and the newest is the .5Z entry, and summariseDigest must
  // EMIT each chosen entry's OWN original string (not a re-serialised form).
  {
    const earliestInstant = "2026-06-01T20:00:00+10:00";
    const middleInstant = "2026-06-01T12:00:00Z";
    const latestInstant = "2026-06-01T18:00:00.5Z";
    // Precondition: assert the lexical order really is the misleading one, so this test cannot pass
    // vacuously if the inputs were ever changed to already-sorted strings.
    const lex = [earliestInstant, middleInstant, latestInstant].slice().sort();
    ok(
      "precondition: raw strings sort lexically in a DIFFERENT order than their instants",
      lex[0] === middleInstant && lex[1] === latestInstant && lex[2] === earliestInstant,
    );
    const mixed: PendingDigestEntry[] = [
      mkPending({ seq: 1, atMs: 0, event: "backup-success" }),
      mkPending({ seq: 2, atMs: 0, event: "backup-success" }),
      mkPending({ seq: 3, atMs: 0, event: "backup-success" }),
    ];
    // Override the `at` strings directly (mkPending always uses isoAt, which is canonical Z).
    mixed[0]!.at = middleInstant;
    mixed[1]!.at = earliestInstant;
    mixed[2]!.at = latestInstant;
    const sm = summariseDigest(mixed);
    ok("fromAt is the EARLIEST INSTANT entry's own string (the +10:00 offset)", sm.fromAt === earliestInstant);
    ok("toAt is the LATEST INSTANT entry's own string (the .5Z fractional)", sm.toAt === latestInstant);
    // And the chosen ends are real, comparable instants in the right order.
    ok("chosen window ends are ordered by instant (from <= to)", Date.parse(sm.fromAt) <= Date.parse(sm.toAt));
  }

  // GUARD: a non-finite (unparseable) `at` must NOT win the min/max; it is ignored for the window so
  // the chosen ends are always real instants. Here a garbage `at` sits alongside two valid ones; the
  // window must come from the two parseable entries, never the garbage string.
  {
    const valids: PendingDigestEntry[] = [
      mkPending({ seq: 1, atMs: base + 2000, event: "backup-success" }),
      mkPending({ seq: 2, atMs: base + 8000, event: "backup-success" }),
    ];
    const withGarbage: PendingDigestEntry[] = [valids[0]!, { ...valids[1]!, seq: 3, at: "not-a-date" }, valids[1]!];
    const sg = summariseDigest(withGarbage);
    ok("guard: unparseable `at` never becomes fromAt", sg.fromAt === isoAt(base + 2000));
    ok("guard: unparseable `at` never becomes toAt", sg.toAt === isoAt(base + 8000));
    ok("guard: total still counts the garbage-`at` entry", sg.total === 3);
  }
}

// ---- TC-N-21: groupDigestDue (pure grouping + per-channel window, daily vs weekly) ----------

function testGroupDigestDue(): void {
  const base = Date.UTC(2026, 5, 1, 0, 0, 0);
  // Channel A: daily, oldest 25h ago -> due. Channel B: daily, oldest 1h ago -> not due.
  const now = base + 25 * 60 * 60 * 1000;
  const entries: PendingDigestEntry[] = [
    mkPending({ seq: 1, atMs: base, channelId: "A", period: "daily", downpipeName: "KV A" }),
    mkPending({ seq: 2, atMs: base + 60_000, channelId: "A", period: "daily", downpipeName: "R2 A" }),
    mkPending({ seq: 3, atMs: now - 60 * 60 * 1000, channelId: "B", period: "daily", downpipeName: "KV B" }), // 1h old
  ];
  const batches = groupDigestDue(entries, now);
  ok("groupDigestDue: only the due channel (A) is returned", batches.length === 1 && batches[0]?.channelId === "A");
  ok("groupDigestDue: due batch carries both of A's entries' seqs", batches[0]?.seqs.length === 2 && batches[0]?.seqs[0] === 1 && batches[0]?.seqs[1] === 2);
  ok("groupDigestDue: due batch summary totals A's two entries", batches[0]?.summary.total === 2);

  // Weekly window: a 2-day-old weekly batch is NOT due; the same batch at 8 days IS due.
  const weeklyEntries: PendingDigestEntry[] = [mkPending({ seq: 9, atMs: base, channelId: "W", period: "weekly" })];
  ok("groupDigestDue: weekly batch not due at 2 days", groupDigestDue(weeklyEntries, base + 2 * DAY_MS).length === 0);
  ok("groupDigestDue: weekly batch due at 8 days", groupDigestDue(weeklyEntries, base + 8 * DAY_MS).length === 1);

  // Mixed cadence on ONE channel: a daily entry makes the channel's effective window daily (shortest
  // wins), so a channel holding a daily + a weekly entry flushes on the daily window.
  const mixed: PendingDigestEntry[] = [
    mkPending({ seq: 10, atMs: base, channelId: "M", period: "weekly" }),
    mkPending({ seq: 11, atMs: base + 1000, channelId: "M", period: "daily" }),
  ];
  const mixedBatches = groupDigestDue(mixed, base + DAY_MS + 1000);
  ok("groupDigestDue: mixed-cadence channel flushes on the SHORTEST (daily) window", mixedBatches.length === 1 && mixedBatches[0]?.period === "daily");
  ok("groupDigestDue: mixed batch consumes both seqs", mixedBatches[0]?.seqs.length === 2);

  // Empty input -> no batches; deterministic channel ordering (sorted by channelId).
  ok("groupDigestDue: empty -> no batches", groupDigestDue([], now).length === 0);
  {
    const two: PendingDigestEntry[] = [
      mkPending({ seq: 1, atMs: base, channelId: "zeta", period: "daily" }),
      mkPending({ seq: 2, atMs: base, channelId: "alpha", period: "daily" }),
    ];
    const ordered = groupDigestDue(two, base + 2 * DAY_MS);
    ok("groupDigestDue: channels emitted sorted by id (alpha before zeta)", ordered.length === 2 && ordered[0]?.channelId === "alpha" && ordered[1]?.channelId === "zeta");
  }
}

// ---- TC-N-22: deferral ACCUMULATES via /notify/resolve + a digest rule (DO storage) ---------

async function testDigestDeferralAccumulates(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // A channel + a global digest rule selecting the success-class at daily cadence.
  const c = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "email", name: "ops", toAddresses: ["ops@example.com"] })).json()) as NotifyChannel;
  await callerFetch(stub, "operator", "POST", "/notify/rules", {
    scope: { kind: "global" },
    minSeverity: "info",
    events: ["backup-success"],
    channelIds: [c.id],
    digest: "daily",
    enabled: true,
  });
  // Three success emissions resolve to DEFERRED (digested), not now.
  for (let i = 0; i < 3; i++) {
    const r = await stubFetch(stub, "POST", "/notify/resolve", {
      emission: { event: "backup-success", severity: "info", downpipeId: `p${i}`, downpipeName: `Pipe ${i}`, detail: `Pipe ${i} backup succeeded`, at: isoAt(Date.UTC(2026, 5, 1) + i * 1000) },
    });
    const body = (await r.json()) as { now: NotifyChannel[]; digestedCount: number };
    ok(`defer: success #${i} -> nothing now`, body.now.length === 0);
    ok(`defer: success #${i} -> digested`, body.digestedCount === 1);
  }
  // The pending entries accumulated under the notify-digest: prefix.
  const pending = await storage.list<PendingDigestEntry>({ prefix: "notify-digest:" });
  ok("defer: three pending digest entries accumulated", pending.size === 3);
  // Each pending entry is redaction-safe: it carries the period + safe name, and no secret/url/key.
  let allSafe = true;
  let allDaily = true;
  for (const e of pending.values()) {
    if (e.period !== "daily") allDaily = false;
    const blob = JSON.stringify(e);
    if (/https?:|secret|routingKey|toAddresses|authorization|key=/i.test(blob)) allSafe = false;
  }
  ok("defer: pending entries stamped with the rule's daily period", allDaily);
  ok("defer: pending entries carry no secret/url/recipient", allSafe);
  // A FAILURE event (not success-class) is delivered NOW even though the rule digests success.
  {
    const r = await stubFetch(stub, "POST", "/notify/resolve", {
      emission: { event: "backup-failure", severity: "critical", downpipeId: "p1", downpipeName: "Pipe 1", detail: "Pipe 1 failed", at: isoAt(Date.UTC(2026, 5, 1)) },
    });
    const body = (await r.json()) as { now: NotifyChannel[]; digestedCount: number };
    // The default-on rule + this digest rule: the failure is not success-class, so it is delivered now,
    // never digested (only success-class is deferred).
    ok("defer: a failure is delivered now, never digested", body.digestedCount === 0 && body.now.length >= 1);
  }
}

// ---- TC-N-23: digest-due window + digest-sent clears (DO, clockless nowMs) ------------------

async function testDigestDueAndSent(): Promise<void> {
  const { stub, storage } = makeScheduler();
  const c = (await (await callerFetch(stub, "operator", "POST", "/notify/channels", { kind: "webhook", name: "SIEM", url: "https://siem.example.com/h" })).json()) as NotifyChannel;
  await callerFetch(stub, "operator", "POST", "/notify/rules", {
    scope: { kind: "global" }, minSeverity: "info", events: ["backup-success"], channelIds: [c.id], digest: "daily", enabled: true,
  });
  const t0 = Date.UTC(2026, 5, 1, 0, 0, 0);
  // Defer two successes at t0.
  for (let i = 0; i < 2; i++) {
    await stubFetch(stub, "POST", "/notify/resolve", {
      emission: { event: "backup-success", severity: "info", downpipeId: `p${i}`, downpipeName: `Pipe ${i}`, detail: `Pipe ${i} ok`, at: isoAt(t0 + i * 1000) },
    });
  }
  // digest-due BEFORE the window (12h later): nothing due.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-due", { nowMs: t0 + 12 * 60 * 60 * 1000 });
    ok("digest-due: 200 before window", r.status === 200);
    const { batches } = (await r.json()) as { batches: DigestBatch[] };
    ok("digest-due: nothing due before the daily window", batches.length === 0);
  }
  // digest-due AFTER the window (25h later): one batch for the channel.
  let dueSeqs: number[] = [];
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-due", { nowMs: t0 + 25 * 60 * 60 * 1000 });
    const { batches } = (await r.json()) as { batches: DigestBatch[] };
    ok("digest-due: one batch due after the daily window", batches.length === 1);
    const b = batches[0]!;
    ok("digest-due: batch is for the configured channel", b.channelId === c.id && b.channelKind === "webhook");
    ok("digest-due: batch summary totals the two deferrals", b.summary.total === 2);
    ok("digest-due: batch detail is redaction-safe (no url/secret)", !/https?:|secret|routingKey|key=/i.test(b.detail));
    ok("digest-due: batch carries the seqs to clear", b.seqs.length === 2);
    dueSeqs = b.seqs;
  }
  // A success deferred AFTER the due-read gets a LATER seq; digest-sent must not clear it.
  await stubFetch(stub, "POST", "/notify/resolve", {
    emission: { event: "backup-success", severity: "info", downpipeId: "p9", downpipeName: "Pipe 9", detail: "Pipe 9 ok", at: isoAt(t0 + 25 * 60 * 60 * 1000) },
  });
  ok("digest-sent: three pending before clear (two due + one new)", (await storage.list({ prefix: "notify-digest:" })).size === 3);
  // Clear exactly the due seqs.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-sent", { ids: dueSeqs });
    ok("digest-sent: 200", r.status === 200);
    const { cleared } = (await r.json()) as { cleared: number };
    ok("digest-sent: cleared the two due entries", cleared === 2);
  }
  const after = await storage.list<PendingDigestEntry>({ prefix: "notify-digest:" });
  ok("digest-sent: only the later-deferred entry survives", after.size === 1);
  ok("digest-sent: the survivor is the post-read deferral (p9)", [...after.values()][0]?.downpipeId === "p9");
  // Re-running digest-due at the same now: the survivor is NOT yet due (its window is measured from its
  // own at, the post-read time), so no batch.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-due", { nowMs: t0 + 25 * 60 * 60 * 1000 });
    const { batches } = (await r.json()) as { batches: DigestBatch[] };
    ok("digest-due: survivor not yet due (window from its own timestamp)", batches.length === 0);
  }
}

// ---- TC-N-24: digest flush is FAIL-OPEN (malformed inputs, empty store, idempotent clear) ---

async function testDigestFailOpen(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // Empty store: digest-due returns an empty batch list, never a 500.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-due", { nowMs: Date.now() });
    ok("fail-open: empty store -> 200 empty batches", r.status === 200 && (await r.json() as { batches: DigestBatch[] }).batches.length === 0);
  }
  // Missing nowMs: the DO falls back to its own clock (no throw). With nothing deferred this is empty.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-due", {});
    ok("fail-open: missing nowMs -> 200 (DO-clock fallback)", r.status === 200);
  }
  // Non-numeric nowMs: same fallback, no throw.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-due", { nowMs: "tomorrow" });
    ok("fail-open: non-numeric nowMs -> 200", r.status === 200);
  }
  // digest-sent with a non-array / bad ids -> cleared 0, no throw.
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-sent", { ids: "nope" });
    ok("fail-open: digest-sent non-array ids -> 200 cleared 0", r.status === 200 && (await r.json() as { cleared: number }).cleared === 0);
  }
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-sent", { ids: [0, -1, 1.5, "x", null] });
    ok("fail-open: digest-sent skips out-of-range/non-integer ids", (await r.json() as { cleared: number }).cleared === 0);
  }
  // digest-sent for an unknown (absent) seq -> idempotent no-op (cleared 0).
  {
    const r = await stubFetch(stub, "POST", "/notify/digest-sent", { ids: [99999] });
    ok("fail-open: digest-sent absent seq -> cleared 0 (idempotent)", (await r.json() as { cleared: number }).cleared === 0);
  }
  void storage;
}

// runDigest runs the digest-flush groups in their original order.
export async function runDigest(): Promise<void> {
  console.log("digest: window predicate (clockless)");
  testDigestWindowElapsed();

  console.log("digest: summary roll-up + render (redaction-safe)");
  testDigestSummaryRollup();
  testDigestSummaryInstantWindow();

  console.log("digest: groupDigestDue (pure grouping + daily vs weekly window)");
  testGroupDigestDue();

  console.log("digest: deferral accumulates via resolve + digest rule");
  await testDigestDeferralAccumulates();

  console.log("digest: digest-due window + digest-sent clears");
  await testDigestDueAndSent();

  console.log("digest: flush is fail-open");
  await testDigestFailOpen();
}
