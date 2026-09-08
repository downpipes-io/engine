// validate-cov-sched-scheduler-do-scheduling: focused branch-coverage vectors for the per-downpipe
// SCHEDULING CORE (src/sched/scheduler-do-scheduling.ts, SchedulerCoreMixin). It drives the real
// SchedulerDO over the shared in-memory storage double and exercises the less-trodden branches the
// broad lifecycle suite leaves uncovered: the dueIndexKeyFor null guards (disabled / non-numeric /
// non-finite nextRunAt), the leased lease window, nextWithJitter's cron + malformed-cron-degrade
// paths, persistDownpipeState's skip-delete cases, heartbeat ownership, completeRun's verify-at-seal
// / replication / down-destination / status-default branches, recordReplicationState's forward-only
// advance, the no-id replication/history roll-ups, runAt's input guards, the reconcile cadence,
// rebuildDueIndex over malformed states, due()'s stale/malformed/predicate filters and its >1-page
// range paging, and alarm()'s housekeeping sweeps + best-effort catch. Every assertion checks a real
// outcome (a returned field, a stored due/index/repl/history effect, or an armed alarm) of the real
// production method, never a stub.
//
// Run: node test/validate-cov-sched-scheduler-do-scheduling.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";
import { SEEN_ASSERTION_PREFIX, PASSKEY_CHALLENGE_PREFIX, STEPUP_TOKEN_PREFIX } from "../src/sched/scheduler-do-base.ts";
import { RECONCILE_EVERY_TICKS, DUE_RECONCILE_TICK_KEY, RING_CAP } from "../src/sched/scheduler-do-limits.ts";
import { makeScheduler, stubFetch, makeConfig, pad16, DUE_INDEX_PREFIX, LEASE_EXPIRED_MS } from "./validate-scheduler-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// surf casts the real SchedulerDO to its public testable surface so internal methods (dueIndexKeyFor,
// leased, nextWithJitter, rebuildDueIndex, maybeReconcileDueIndex, alarm) can be driven directly; these
// are the SAME production methods the routes call, not doubles.
const surf = (dobj: unknown): SchedulerDOSurface => dobj as unknown as SchedulerDOSurface;

// FlexStorage is a fuller DurableObjectState["storage"] double than the shared one: its list() honours
// the half-open [start, end) range AND the startAfter exclusive cursor (so due()'s multi-page range
// scan is exercised faithfully), get() deep-clones a single key, and list() returns the LIVE stored
// value (no clone) so a non-finite nextRunAt survives the rebuild read (mirroring how the platform's
// structured clone preserves Infinity, which JSON does not). getAlarm is present unless opted out (to
// exercise completeRun's "mock omits getAlarm" tolerance), and list throws for one configured prefix
// (to exercise alarm()'s best-effort catch). The map is public so a vector can seed exact on-disk shapes.
class FlexStorage {
  map = new Map<string, unknown>();
  lastAlarmAt: number | null = null;
  throwListPrefix: string | undefined;
  throwPutKeySubstr: string | undefined;
  throwPutMessage: string;
  constructor(opts?: { withGetAlarm?: boolean; throwListPrefix?: string; throwPutKeySubstr?: string; throwPutMessage?: string }) {
    this.throwListPrefix = opts?.throwListPrefix;
    this.throwPutKeySubstr = opts?.throwPutKeySubstr;
    this.throwPutMessage = opts?.throwPutMessage ?? "simulated storage put failure";
    if (opts?.withGetAlarm !== false) {
      (this as { getAlarm?: () => Promise<number | null> }).getAlarm = async (): Promise<number | null> => this.lastAlarmAt;
    }
  }
  async get<T>(key: string): Promise<T | undefined> {
    const v = this.map.get(key);
    return v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T);
  }
  async put<T>(key: string, value: T): Promise<void> {
    // A configured put-fault simulates a persist-state storage.put throwing for a matching key (e.g. "dp:"),
    // so the persistDownpipeState catch (the storage-fault promotion) and the recordStorageFault best-effort
    // swallow are exercised. The counter key ("storageFaultCounter") is deliberately NOT the dp: substring, so
    // the counter write itself succeeds during a per-key value-too-large fault (the recordable case).
    if (this.throwPutKeySubstr !== undefined && key.includes(this.throwPutKeySubstr)) throw new Error(this.throwPutMessage);
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string; start?: string; startAfter?: string; end?: string; limit?: number }): Promise<Map<string, T>> {
    if (this.throwListPrefix !== undefined && opts?.prefix === this.throwListPrefix) throw new Error("simulated storage list failure");
    let keys = [...this.map.keys()].sort();
    if (opts?.prefix !== undefined) keys = keys.filter((k) => k.startsWith(opts.prefix!));
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (opts?.end !== undefined) keys = keys.filter((k) => k < opts.end!);
    if (opts?.limit !== undefined) keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    return out;
  }
  async setAlarm(t: number): Promise<void> {
    this.lastAlarmAt = t;
  }
}
function makeFlex(opts?: { withGetAlarm?: boolean; throwListPrefix?: string; throwPutKeySubstr?: string; throwPutMessage?: string }): { storage: FlexStorage; stub: SchedulerDO } {
  const storage = new FlexStorage(opts);
  const stub = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return { storage, stub };
}
const flexDueKeys = (s: FlexStorage): string[] => [...s.map.keys()].filter((k) => k.startsWith(DUE_INDEX_PREFIX)).sort();

async function main(): Promise<void> {
  // ===== BLOCK 1: dueIndexKeyFor null guards + key shape (all four branches) ==================
  {
    const { stub } = makeScheduler();
    const s = surf(stub);
    ok("dueIndexKeyFor: a disabled downpipe yields no index key (null)", s.dueIndexKeyFor({ config: { id: "x", enabled: false } } as never) === null);
    ok("dueIndexKeyFor: a non-numeric nextRunAt yields null (defensive)", s.dueIndexKeyFor({ config: { id: "x", enabled: true }, nextRunAt: "nope" } as never) === null);
    ok("dueIndexKeyFor: a non-finite nextRunAt yields null (defensive)", s.dueIndexKeyFor({ config: { id: "x", enabled: true }, nextRunAt: Infinity } as never) === null);
    ok("dueIndexKeyFor: an enabled numeric state yields the due:<pad16>:id key", s.dueIndexKeyFor({ config: { id: "x", enabled: true }, nextRunAt: 1000 } as never) === `${DUE_INDEX_PREFIX}${pad16(1000)}:x`);
  }

  // ===== BLOCK 2: leased lease window (all three conjuncts) ==================================
  {
    const { stub } = makeScheduler();
    const s = surf(stub);
    const now = Date.now();
    ok("leased: a not-in-flight pipe is never leased", s.leased({ inFlight: false } as never, now) === false);
    ok("leased: in-flight with no timestamp reads as crashed (not leased)", s.leased({ inFlight: true } as never, now) === false);
    ok("leased: in-flight within the lease window is leased", s.leased({ inFlight: true, inFlightSince: now - 1000 } as never, now) === true);
    ok("leased: in-flight past the lease window is crashed (not leased)", s.leased({ inFlight: true, inFlightSince: now - LEASE_EXPIRED_MS } as never, now) === false);
  }

  // ===== BLOCK 3: nextWithJitter cadence / cron / malformed-cron-degrade / no-cron-schedule ==
  {
    const { stub } = makeScheduler();
    const s = surf(stub);
    const cadMs = 3600 * 1000;
    const before = Date.now();
    // nextWithJitter now returns { next, cronResolve }: the epoch is unchanged from before, and cronResolve is
    // the closed cron-resolution class (null for a cadence-only downpipe, so the caller clears any stale stamp).
    const cad = s.nextWithJitter(3600);
    ok("nextWithJitter: no schedule -> cadence path within the backward-jitter window", cad.next <= Date.now() + cadMs + 5 && cad.next >= before + cadMs * 0.9 - 5);
    ok("nextWithJitter: no schedule -> cronResolve null (nothing to resolve)", cad.cronResolve === null);

    const before2 = Date.now();
    const noCron = s.nextWithJitter(3600, { blackoutWindows: [] });
    ok("nextWithJitter: a schedule WITHOUT cron also takes the cadence path", noCron.next <= Date.now() + cadMs + 5 && noCron.next >= before2 + cadMs * 0.9 - 5);
    ok("nextWithJitter: a schedule WITHOUT cron -> cronResolve null", noCron.cronResolve === null);

    const cron = s.nextWithJitter(3600, { cron: "30 2 * * *", timeZone: "UTC" });
    const w = new Date(cron.next);
    ok("nextWithJitter: a valid cron computes a clock-aligned 02:30 UTC instant (not cadence)", w.getUTCHours() === 2 && w.getUTCMinutes() === 30 && w.getUTCSeconds() === 0);
    ok("nextWithJitter: the cron instant is strictly in the future", cron.next > Date.now());
    ok("nextWithJitter: a valid cron resolves class 'ok'", cron.cronResolve?.class === "ok" && typeof cron.cronResolve.at === "number");

    const before3 = Date.now();
    const bad = s.nextWithJitter(3600, { cron: "* * *" } as never); // 3 fields -> parseCron fails -> cron-parse -> cadence
    ok("nextWithJitter: a malformed cron degrades to the cadence path (defence-in-depth catch)", bad.next <= Date.now() + cadMs + 5 && bad.next >= before3 + cadMs * 0.9 - 5);
    ok("nextWithJitter: a malformed cron resolves class 'cron-parse'", bad.cronResolve?.class === "cron-parse");

    // An UNKNOWN IANA timezone: nextFireAfter would throw, so it is classified tz-invalid and degrades to cadence.
    const badTz = s.nextWithJitter(3600, { cron: "30 2 * * *", timeZone: "Mars/Phobos" });
    ok("nextWithJitter: an unknown IANA timezone resolves class 'tz-invalid' and degrades to cadence", badTz.cronResolve?.class === "tz-invalid" && badTz.next <= Date.now() + cadMs + 5);

    // A parseable-but-IMPOSSIBLE cron (Feb 30 never occurs): parses fine, but has no next fire -> no-next-fire.
    const impossible = s.nextWithJitter(3600, { cron: "0 0 30 2 *", timeZone: "UTC" });
    ok("nextWithJitter: an impossible cron (Feb 30) resolves class 'no-next-fire' and degrades to cadence", impossible.cronResolve?.class === "no-next-fire" && impossible.next <= Date.now() + cadMs + 5);
  }

  // ===== BLOCK 4: persistDownpipeState - add (prior null), disabled (newKey null), re-enable =
  {
    const { stub, storage } = makeScheduler();
    const dueKeysFor = (id: string): string[] => storage.rawListKeys().filter((k) => k.startsWith(DUE_INDEX_PREFIX) && k.endsWith(`:${id}`));

    // prior null + newKey non-null: a brand-new enabled downpipe gets exactly one due: entry.
    await stubFetch(stub, "POST", "/downpipes", makeConfig("p-add", { enabled: true }));
    ok("persist: a new enabled downpipe writes exactly one due: index entry", dueKeysFor("p-add").length === 1);

    // newKey null: a disabled downpipe writes NO due: entry (the put is skipped).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("p-dis", { enabled: false }));
    ok("persist: a disabled downpipe writes no due: index entry (newKey null)", dueKeysFor("p-dis").length === 0);

    // prior priorKey === null (was disabled) -> new enabled: the prior-delete is SKIPPED, the new put runs.
    await stubFetch(stub, "POST", "/downpipes", makeConfig("p-dis", { enabled: true }));
    ok("persist: re-enabling a disabled downpipe creates its due: entry (prior had no key to delete)", dueKeysFor("p-dis").length === 1);
  }

  // ===== BLOCK 5: heartbeat ownership + persist skip-delete (priorKey === newKey) ============
  {
    const { stub, storage } = makeScheduler();
    const dueKeysFor = (id: string): string[] => storage.rawListKeys().filter((k) => k.startsWith(DUE_INDEX_PREFIX) && k.endsWith(`:${id}`));
    await stubFetch(stub, "POST", "/downpipes", makeConfig("hb", { enabled: true }));

    // heartbeat on a downpipe that is NOT in flight -> owned:false (the !ds?.inFlight guard).
    const hbIdle = (await (await stubFetch(stub, "POST", "/heartbeat", { id: "hb", runId: "r", index: 1 })).json()) as { owned: boolean };
    ok("heartbeat: a not-in-flight downpipe is not owned", hbIdle.owned === false);

    // heartbeat on an UNKNOWN downpipe -> owned:false (ds undefined).
    const hbGhost = (await (await stubFetch(stub, "POST", "/heartbeat", { id: "ghost", runId: "r", index: 1 })).json()) as { owned: boolean };
    ok("heartbeat: an unknown downpipe is not owned", hbGhost.owned === false);

    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "hb" })).json()) as { runId: string; index: number };
    const keyBefore = dueKeysFor("hb")[0];

    // heartbeat with a WRONG runId -> the row is in-flight but does not record this run -> owned:false.
    const hbWrong = (await (await stubFetch(stub, "POST", "/heartbeat", { id: "hb", runId: "not-the-run", index: t.index })).json()) as { owned: boolean };
    ok("heartbeat: a mismatched runId does not own the in-flight row", hbWrong.owned === false);

    // heartbeat at a non-existent index -> no row -> owned:false.
    const hbNoRow = (await (await stubFetch(stub, "POST", "/heartbeat", { id: "hb", runId: t.runId, index: 9999 })).json()) as { owned: boolean };
    ok("heartbeat: an unknown index finds no row to own", hbNoRow.owned === false);

    // The genuine owner heartbeats -> owned:true, lease bumped, due: key UNCHANGED (persist skips the re-key).
    const beforeSince = storage.rawGet<{ inFlightSince?: number }>("dp:hb")!.inFlightSince;
    const hbOwn = (await (await stubFetch(stub, "POST", "/heartbeat", { id: "hb", runId: t.runId, index: t.index })).json()) as { owned: boolean };
    ok("heartbeat: the genuine owner renews the lease (owned:true)", hbOwn.owned === true);
    const afterSince = storage.rawGet<{ inFlightSince?: number }>("dp:hb")!.inFlightSince;
    ok("heartbeat: the in-flight lease timestamp was bumped (or preserved) on renewal", typeof afterSince === "number" && (beforeSince === undefined || afterSince >= beforeSince));
    ok("heartbeat: a lease-only renewal leaves the due: index key unchanged (skip re-key)", dueKeysFor("hb")[0] === keyBefore && keyBefore !== undefined);
  }

  // ===== BLOCK 6: completeRun verify-at-seal / counts / replication / status defaults ========
  {
    const { stub, storage } = makeScheduler();

    // dpA: a SUCCESSFUL run with a VERIFIED verify-at-seal verdict, full counts and a destination.
    await stubFetch(stub, "POST", "/downpipes", makeConfig("c-ok", { enabled: true }));
    const ta = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-ok" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", {
      id: "c-ok", runId: ta.runId, index: ta.index, // status OMITTED -> defaults to "ok" from the non-empty runId
      recordCount: 11, bytes: 222, archiveBytesWritten: 333, segmentsWritten: 4, durationMs: 555,
      recordsSkipped: 2, recordsIncomplete: 1, incompleteByMarker: { _truncated: 1 }, opCounts: { kvReads: 1, subrequests: 2 },
      destinationId: "dest-a", sealVerification: { status: "verified", tier: "full", sampled: 11, at: Date.now() },
    });
    const dsA = storage.rawGet<{ inFlight: boolean; lastRunId: string | null; integrityVerified?: { how: string }; lastSealVerify?: { status: string } }>("dp:c-ok")!;
    ok("completeRun ok(default status): cleared in-flight + advanced lastRunId", dsA.inFlight === false && dsA.lastRunId === ta.runId);
    ok("completeRun ok: a verified verdict stamps integrity-verified how:run", dsA.integrityVerified?.how === "run");
    ok("completeRun ok: the verify-at-seal verdict is recorded on the state", dsA.lastSealVerify?.status === "verified");
    const rowA = (storage.rawGet<Array<{ index: number; status: string; recordCount?: number; recordsSkipped?: number; recordsIncomplete?: number; incompleteByMarker?: Record<string, number>; opCounts?: unknown; sealVerification?: { status: string }; destinationId?: string }>>("hist:c-ok") ?? []).find((h) => h.index === ta.index)!;
    ok("completeRun ok: status defaulted to ok and all coarse counts landed on the row", rowA.status === "ok" && rowA.recordCount === 11 && rowA.recordsSkipped === 2 && rowA.recordsIncomplete === 1 && rowA.opCounts !== undefined);
    ok("completeRun ok: the per-marker incompleteByMarker breakdown landed on the row (which kinds, for the pack)", rowA.incompleteByMarker?._truncated === 1);
    ok("completeRun ok: the verify-at-seal verdict + sealed destination are on the row", rowA.sealVerification?.status === "verified" && rowA.destinationId === "dest-a");
    const replA = (await (await stubFetch(stub, "GET", "/replication?id=c-ok")).json()) as { dests: Record<string, { holdsRunId: string | null; holdsIndex: number; lastOk: boolean }> };
    ok("completeRun ok: the sealed destination's replication state was seeded (proven copy)", replA.dests["dest-a"]?.holdsRunId === ta.runId && replA.dests["dest-a"]?.holdsIndex === ta.index && replA.dests["dest-a"]?.lastOk === true);

    // dpB (fresh): a SUCCESSFUL run with a SUSPECT verdict must NOT stamp integrity-verified.
    await stubFetch(stub, "POST", "/downpipes", makeConfig("c-suspect", { enabled: true }));
    const tb = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-suspect" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "c-suspect", runId: tb.runId, index: tb.index, status: "ok", sealVerification: { status: "suspect", tier: "tier-0", sampled: 0, at: Date.now(), reason: "readback mismatch" } });
    const dsB = storage.rawGet<{ integrityVerified?: unknown; lastSealVerify?: { status: string } }>("dp:c-suspect")!;
    ok("completeRun ok+suspect: integrity-verified is NOT stamped on a suspect readback", dsB.integrityVerified === undefined);
    ok("completeRun ok+suspect: the suspect verdict is still recorded (observable)", dsB.lastSealVerify?.status === "suspect");
    const rowB = (storage.rawGet<Array<{ index: number; sealVerification?: { status: string } }>>("hist:c-suspect") ?? []).find((h) => h.index === tb.index)!;
    ok("completeRun ok+suspect: the row carries the suspect verdict", rowB.sealVerification?.status === "suspect");

    // dpC (fresh): a FAILED run (empty runId default) with an error and a down-destination set (mixed types).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("c-fail", { enabled: true }));
    const tc = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-fail" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "c-fail", runId: "", index: tc.index, error: "destination access error", downDestinationIds: ["dest-down", "", 123] });
    const dsC = storage.rawGet<{ inFlight: boolean; lastRunId: string | null; integrityVerified?: unknown }>("dp:c-fail")!;
    ok("completeRun failed(default status): in-flight cleared, lastRunId NOT advanced", dsC.inFlight === false && dsC.lastRunId === null);
    ok("completeRun failed: a failed run never stamps integrity-verified", dsC.integrityVerified === undefined);
    const rowC = (storage.rawGet<Array<{ index: number; status: string; error?: string }>>("hist:c-fail") ?? []).find((h) => h.index === tc.index)!;
    ok("completeRun failed: status defaulted to failed and the coarse error landed", rowC.status === "failed" && rowC.error === "destination access error");
    const replC = (await (await stubFetch(stub, "GET", "/replication?id=c-fail")).json()) as { dests: Record<string, { lastOk: boolean; reason?: string }> };
    ok("completeRun failed: only the valid down-destination id recorded an unreachable heartbeat", replC.dests["dest-down"]?.lastOk === false && replC.dests["dest-down"]?.reason === "unreachable");
    ok("completeRun failed: the empty/non-string down ids were filtered out", replC.dests[""] === undefined && replC.dests["123"] === undefined);

    // dpD (fresh): explicit status + NO verify-at-seal + NO destination -> exercises the negative sides.
    await stubFetch(stub, "POST", "/downpipes", makeConfig("c-plain", { enabled: true }));
    const td = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-plain" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "c-plain", runId: td.runId, index: td.index, status: "ok" });
    const dsD = storage.rawGet<{ integrityVerified?: { how: string }; lastSealVerify?: unknown }>("dp:c-plain")!;
    ok("completeRun ok(no verdict): a clean run with no verdict still stamps integrity-verified", dsD.integrityVerified?.how === "run");
    ok("completeRun ok(no verdict): no verify-at-seal verdict is recorded", dsD.lastSealVerify === undefined);
    const rowD = (storage.rawGet<Array<{ index: number; sealVerification?: unknown; error?: unknown }>>("hist:c-plain") ?? []).find((h) => h.index === td.index)!;
    ok("completeRun ok(no verdict): the row carries no verify-at-seal verdict and no error", rowD.sealVerification === undefined && rowD.error === undefined);
    const replD = (await (await stubFetch(stub, "GET", "/replication?id=c-plain")).json()) as { dests: Record<string, unknown> };
    ok("completeRun ok(no destination): no replication state is recorded for a destination-less run", Object.keys(replD.dests).length === 0);
  }

  // ===== BLOCK 6b: completeRun arms an O(1) safety-net alarm when NONE is pending (getAlarm null)
  {
    const { stub, storage } = makeScheduler();
    // Seed the state directly (no addDownpipe -> no alarm armed), so getAlarm() reads null at completion.
    await storage.put("dp:c-arm", { config: makeConfig("c-arm", { enabled: true }), nextRunAt: Date.now() - 1000, lastRunId: null, inFlight: false });
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-arm" })).json()) as { runId: string; index: number };
    ok("completeRun safety-net: no alarm is pending after a raw-seeded trigger (precondition)", storage.lastAlarmAt === null);
    await stubFetch(stub, "POST", "/complete", { id: "c-arm", runId: t.runId, index: t.index, status: "ok" });
    ok("completeRun safety-net: with no alarm pending, completion arms one (getAlarm()===null branch)", storage.lastAlarmAt !== null && (storage.lastAlarmAt ?? 0) >= Date.now() - 1000);
  }

  // ===== BLOCK 6c: completeRun tolerates a storage mock that omits getAlarm (typeof guard false)
  {
    const { storage, stub } = makeFlex({ withGetAlarm: false });
    storage.map.set("dp:c-nog", { config: makeConfig("c-nog", { enabled: true }), nextRunAt: Date.now() - 1000, lastRunId: null, inFlight: false });
    const t = (await surf(stub).trigger({ id: "c-nog" })) as { runId: string; index: number };
    const res = await surf(stub).completeRun({ id: "c-nog", runId: t.runId, index: t.index, status: "ok" });
    ok("completeRun (no getAlarm): completion still succeeds (the safety-net is skipped, no throw)", res.ok === true);
    const ds = await storage.get<{ inFlight: boolean; lastRunId: string | null }>("dp:c-nog");
    ok("completeRun (no getAlarm): the run still resolved (in-flight cleared, lastRunId advanced)", ds?.inFlight === false && ds?.lastRunId === t.runId);
  }

  // ===== BLOCK 6d: completeRun with a history row but NO dp: state (ds && ownsInFlight, ds null) =
  {
    const { stub, storage } = makeScheduler();
    await storage.put("hist:c-orphan", [{ runId: "r-orphan", index: 3, startedAt: new Date().toISOString(), status: "in-flight" }]);
    const res = (await (await stubFetch(stub, "POST", "/complete", { id: "c-orphan", runId: "r-orphan", index: 3, status: "ok" })).json()) as { ok: boolean };
    ok("completeRun (no state): the call still returns ok with a hist row but no dp: state", res.ok === true);
    const row = (storage.rawGet<Array<{ index: number; status: string }>>("hist:c-orphan") ?? []).find((h) => h.index === 3)!;
    ok("completeRun (no state): the named row is still resolved even though the dp: state is absent", row.status === "ok");
  }

  // ===== BLOCK 7: recordReplicationState - no-id no-op, first record, forward-only, failure ===
  {
    const { stub } = makeScheduler();
    const record = (body: unknown): Promise<Response> => stubFetch(stub, "POST", "/replication/record", body);

    // No destinationId -> early return (records nothing).
    await record({ id: "r-x", ok: true, runId: "r1", index: 1 });
    const noDest = (await (await stubFetch(stub, "GET", "/replication?id=r-x")).json()) as { dests: Record<string, unknown> };
    ok("recordReplicationState: a record with no destinationId stores nothing (early return)", Object.keys(noDest.dests).length === 0);

    // First record (no prior) advances holds*; lastOk true.
    await record({ id: "r-y", destinationId: "d", ok: true, runId: "r5", index: 5 });
    let y = (await (await stubFetch(stub, "GET", "/replication?id=r-y")).json()) as { dests: Record<string, { holdsRunId: string | null; holdsIndex: number; lastOk: boolean; reason?: string }> };
    ok("recordReplicationState: a first success seeds holdsRunId/holdsIndex from defaults", y.dests["d"]?.holdsRunId === "r5" && y.dests["d"]?.holdsIndex === 5 && y.dests["d"]?.lastOk === true);

    // A LOWER index does not rewind the proven copy (forward-only), but lastOk still updates.
    await record({ id: "r-y", destinationId: "d", ok: true, runId: "r3", index: 3 });
    y = (await (await stubFetch(stub, "GET", "/replication?id=r-y")).json()) as { dests: Record<string, { holdsRunId: string | null; holdsIndex: number; lastOk: boolean }> };
    ok("recordReplicationState: a lower index never rewinds holdsRunId/holdsIndex (forward-only)", y.dests["d"]?.holdsRunId === "r5" && y.dests["d"]?.holdsIndex === 5);

    // A failure leaves holds* intact and records the coarse reason.
    await record({ id: "r-y", destinationId: "d", ok: false, reason: "unreachable" });
    y = (await (await stubFetch(stub, "GET", "/replication?id=r-y")).json()) as { dests: Record<string, { holdsRunId: string | null; holdsIndex: number; lastOk: boolean; reason?: string }> };
    ok("recordReplicationState: a failure records lastOk:false + reason, holds* preserved", y.dests["d"]?.lastOk === false && y.dests["d"]?.reason === "unreachable" && y.dests["d"]?.holdsIndex === 5);

    // A failure with NO prior row seeds the defaults (holdsRunId null, holdsIndex -1).
    await record({ id: "r-z", destinationId: "d", ok: false, reason: "down" });
    const z = (await (await stubFetch(stub, "GET", "/replication?id=r-z")).json()) as { dests: Record<string, { holdsRunId: string | null; holdsIndex: number; lastOk: boolean }> };
    ok("recordReplicationState: a first-time failure seeds holdsRunId null / holdsIndex -1", z.dests["d"]?.holdsRunId === null && z.dests["d"]?.holdsIndex === -1 && z.dests["d"]?.lastOk === false);

    // holdsFrom (the proven FLOOR) advances forward-only UP alongside holdsIndex: a record carrying a higher
    // floor raises it; a lower or absent floor never lowers it, so a stale/duplicate record can never widen
    // the covered window.
    await record({ id: "r-f", destinationId: "d", ok: true, runId: "r30", index: 30, holdsFrom: 5 });
    let f = (await (await stubFetch(stub, "GET", "/replication?id=r-f")).json()) as { dests: Record<string, { holdsIndex: number; holdsFrom?: number }> };
    ok("recordReplicationState: a success carrying holdsFrom seeds the proven floor", f.dests["d"]?.holdsFrom === 5 && f.dests["d"]?.holdsIndex === 30);
    await record({ id: "r-f", destinationId: "d", ok: true, runId: "r40", index: 40, holdsFrom: 11 });
    f = (await (await stubFetch(stub, "GET", "/replication?id=r-f")).json()) as { dests: Record<string, { holdsIndex: number; holdsFrom?: number }> };
    ok("recordReplicationState: a higher holdsFrom advances the floor (forward-only up)", f.dests["d"]?.holdsFrom === 11);
    await record({ id: "r-f", destinationId: "d", ok: true, runId: "r45", index: 45, holdsFrom: 3 });
    f = (await (await stubFetch(stub, "GET", "/replication?id=r-f")).json()) as { dests: Record<string, { holdsIndex: number; holdsFrom?: number }> };
    ok("recordReplicationState: a lower holdsFrom never rewinds the floor (forward-only)", f.dests["d"]?.holdsFrom === 11);
    await record({ id: "r-f", destinationId: "d", ok: true, runId: "r50", index: 50 });
    f = (await (await stubFetch(stub, "GET", "/replication?id=r-f")).json()) as { dests: Record<string, { holdsIndex: number; holdsFrom?: number }> };
    ok("recordReplicationState: a record with no holdsFrom preserves the floor + advances the top", f.dests["d"]?.holdsFrom === 11 && f.dests["d"]?.holdsIndex === 50);
  }

  // ===== BLOCK 8: replication + history roll-ups (the no-id whole-fleet path) ================
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/replication/record", { id: "agg-1", destinationId: "d1", ok: true, runId: "ra", index: 1 });
    await stubFetch(stub, "POST", "/replication/record", { id: "agg-2", destinationId: "d2", ok: true, runId: "rb", index: 1 });
    const replAll = (await (await stubFetch(stub, "GET", "/replication")).json()) as { byDownpipe: Record<string, Record<string, unknown>> };
    ok("replication(no id): the whole-fleet roll-up is keyed by downpipe id", replAll.byDownpipe["agg-1"]?.["d1"] !== undefined && replAll.byDownpipe["agg-2"]?.["d2"] !== undefined);

    // history(id) on a downpipe with NO ring returns an empty entries list (the ?? [] fallback).
    const emptyHist = (await (await stubFetch(stub, "GET", "/history?id=nope")).json()) as { entries: unknown[] };
    ok("history(id): an unknown downpipe returns an empty ring (no throw)", Array.isArray(emptyHist.entries) && emptyHist.entries.length === 0);

    // Seed two rings then read the no-id roll-up (newest-first per downpipe).
    await storage.put("hist:h1", [{ runId: "h1a", index: 1, startedAt: new Date().toISOString(), status: "ok" }]);
    await storage.put("hist:h2", [{ runId: "h2a", index: 1, startedAt: new Date().toISOString(), status: "ok" }]);
    const histAll = (await (await stubFetch(stub, "GET", "/history")).json()) as { byDownpipe: Record<string, Array<{ runId: string }>> };
    ok("history(no id): the whole-fleet roll-up is keyed by downpipe id", histAll.byDownpipe["h1"]?.[0]?.runId === "h1a" && histAll.byDownpipe["h2"]?.[0]?.runId === "h2a");
  }

  // ===== BLOCK 9: runAt input guards + a real resolution =====================================
  {
    const { stub, storage } = makeScheduler();
    const noDp = (await (await stubFetch(stub, "GET", "/runs/at")).json()) as { found: boolean; error?: string };
    ok("runAt: a missing downpipe is rejected honestly (found:false, error)", noDp.found === false && noDp.error === "downpipe required");

    const noAt = (await (await stubFetch(stub, "GET", "/runs/at?downpipe=d")).json()) as { found: boolean; error?: string };
    ok("runAt: a missing at= timestamp is rejected (atRaw null -> NaN)", noAt.found === false && noAt.error === "at required");

    const badAt = (await (await stubFetch(stub, "GET", "/runs/at?downpipe=d&at=not-a-date")).json()) as { found: boolean; error?: string };
    ok("runAt: an unparseable at= is rejected (Date.parse NaN)", badAt.found === false && badAt.error === "at required");

    // A real downpipe with a successful run, queried after the run completed -> found:true.
    const startedAt = new Date(Date.now() - 60_000).toISOString();
    await storage.put("hist:d-pit", [{ runId: "pit-1", index: 1, startedAt, status: "ok" }]);
    const found = (await (await stubFetch(stub, "GET", `/runs/at?downpipe=d-pit&at=${encodeURIComponent(new Date().toISOString())}`)).json()) as { found: boolean; runId?: string };
    ok("runAt: resolves the latest successful run at-or-before T from the ring", found.found === true && found.runId === "pit-1");

    // A valid at= but an empty ring -> found:false (the ?? [] empty-ring path).
    const emptyRing = (await (await stubFetch(stub, "GET", `/runs/at?downpipe=d-empty&at=${encodeURIComponent(new Date().toISOString())}`)).json()) as { found: boolean };
    ok("runAt: an empty ring resolves to found:false (no successful run retained)", emptyRing.found === false);
  }

  // ===== BLOCK 10: maybeReconcileDueIndex - lazy build, periodic cadence, and the no-op path ==
  {
    // (a) lazy build: dp: states exist but the index is empty -> reconcile rebuilds it (returns true).
    const a = makeScheduler();
    await a.storage.put("dp:lz", { config: makeConfig("lz", { enabled: true }), nextRunAt: Date.now() - 1000, lastRunId: null, inFlight: false });
    const lzBuilt = await surf(a.stub).maybeReconcileDueIndex();
    ok("maybeReconcile: an empty index over a non-empty fleet triggers a rebuild (returns true)", lzBuilt === true);
    ok("maybeReconcile: the lazy rebuild populated the due: entry from dp: truth", a.storage.rawListKeys().some((k) => k.startsWith(DUE_INDEX_PREFIX) && k.endsWith(":lz")));

    // (b) periodic cadence: at the RECONCILE_EVERY_TICKS-th tick a rebuild runs even with no emptiness,
    //     and it heals injected drift (a stale ghost key is dropped, the true key rebuilt).
    const b = makeScheduler();
    await b.storage.put("dp:pc", { config: makeConfig("pc", { enabled: true }), nextRunAt: Date.now() - 1000, lastRunId: null, inFlight: false });
    await b.storage.put(`${DUE_INDEX_PREFIX}${pad16(1)}:ghost`, 1); // injected drift: a stale entry for a non-existent downpipe
    await b.storage.put(DUE_RECONCILE_TICK_KEY, RECONCILE_EVERY_TICKS - 1); // next tick lands on the cadence boundary
    const pcRan = await surf(b.stub).maybeReconcileDueIndex();
    ok("maybeReconcile: the periodic cadence (tick % N === 0) triggers a rebuild (returns true)", pcRan === true);
    ok("maybeReconcile: the cadence rebuild dropped the stale ghost index entry", !b.storage.rawListKeys().includes(`${DUE_INDEX_PREFIX}${pad16(1)}:ghost`));
    ok("maybeReconcile: the cadence rebuild restored the real downpipe's index entry", b.storage.rawListKeys().some((k) => k.startsWith(DUE_INDEX_PREFIX) && k.endsWith(":pc")));

    // (c) no-op: an empty fleet off the cadence boundary does NOT rebuild (returns false).
    const c = makeScheduler();
    await c.storage.put(DUE_RECONCILE_TICK_KEY, 0); // next tick = 1, not on the cadence boundary
    const noop = await surf(c.stub).maybeReconcileDueIndex();
    ok("maybeReconcile: an empty fleet off the cadence does nothing (returns false)", noop === false);
  }

  // ===== BLOCK 11: rebuildDueIndex over malformed states (dueIndexKeyFor null in the rebuild) =
  {
    const { storage, stub } = makeFlex();
    const now = Date.now();
    storage.map.set("dp:rb-good", { config: makeConfig("rb-good", { enabled: true }), nextRunAt: now - 1000, lastRunId: null, inFlight: false });
    storage.map.set("dp:rb-dis", { config: makeConfig("rb-dis", { enabled: false }), nextRunAt: now - 1000, lastRunId: null, inFlight: false });
    storage.map.set("dp:rb-str", { config: makeConfig("rb-str", { enabled: true }), nextRunAt: "not-a-number", lastRunId: null, inFlight: false });
    storage.map.set("dp:rb-inf", { config: makeConfig("rb-inf", { enabled: true }), nextRunAt: Infinity, lastRunId: null, inFlight: false });
    storage.map.set(`${DUE_INDEX_PREFIX}${pad16(1)}:rb-stale`, 1); // a pre-existing index entry the rebuild must drop
    await surf(stub).rebuildDueIndex();
    const keys = flexDueKeys(storage);
    ok("rebuildDueIndex: exactly ONE due: entry survives - only the enabled, finite-numeric downpipe", keys.length === 1 && keys[0]!.endsWith(":rb-good"));
    ok("rebuildDueIndex: the disabled / string / Infinity states produced no index key (null path)", !keys.some((k) => k.endsWith(":rb-dis") || k.endsWith(":rb-str") || k.endsWith(":rb-inf")));
    ok("rebuildDueIndex: the pre-existing stale entry was dropped before the rebuild", !keys.some((k) => k.endsWith(":rb-stale")));
  }

  // ===== BLOCK 12: due() filters - empty range, malformed key, stale id, and the predicate sides
  {
    const { stub, storage } = makeScheduler();
    const now = Date.now();
    const past = pad16(now - 60_000);

    // The ONE genuinely-due downpipe (enabled, past, not in flight) with its correct index entry.
    await storage.put("dp:d-good", { config: makeConfig("d-good", { enabled: true }), nextRunAt: now - 60_000, lastRunId: null, inFlight: false });
    await storage.put(`${DUE_INDEX_PREFIX}${past}:d-good`, 1);

    // A malformed index key with an EMPTY id (skipped: id.length === 0).
    await storage.put(`${DUE_INDEX_PREFIX}${past}:`, 1);
    // A stale index key pointing at a since-deleted downpipe (skipped: dp: state absent).
    await storage.put(`${DUE_INDEX_PREFIX}${past}:d-ghost`, 1);
    // A since-DISABLED downpipe still carrying a stale index key (skipped: predicate enabled === false).
    await storage.put("dp:d-dis", { config: makeConfig("d-dis", { enabled: false }), nextRunAt: now - 60_000, lastRunId: null, inFlight: false });
    await storage.put(`${DUE_INDEX_PREFIX}${past}:d-dis`, 1);
    // A rescheduled-into-the-future downpipe with a stale PAST-keyed entry (skipped: nextRunAt > now).
    await storage.put("dp:d-future", { config: makeConfig("d-future", { enabled: true }), nextRunAt: now + 3_600_000, lastRunId: null, inFlight: false });
    await storage.put(`${DUE_INDEX_PREFIX}${past}:d-future`, 1);
    // A freshly in-flight downpipe with a stale past key (skipped: genuinely leased).
    await storage.put("dp:d-leased", { config: makeConfig("d-leased", { enabled: true }), nextRunAt: now - 60_000, lastRunId: null, inFlight: true, inFlightSince: now - 1000 });
    await storage.put(`${DUE_INDEX_PREFIX}${past}:d-leased`, 1);

    const { due } = (await (await stubFetch(stub, "GET", "/due")).json()) as { due: Array<{ config: { id: string } }> };
    ok("due(): returns ONLY the genuinely-due downpipe; every stale/malformed/predicate case is filtered", due.length === 1 && due[0]?.config.id === "d-good");

    // Empty-range break: a fleet of only-future downpipes -> the due-index range scan returns nothing.
    const ef = makeScheduler();
    await stubFetch(ef.stub, "POST", "/downpipes", makeConfig("only-future", { enabled: true, cadenceSeconds: 86_400 }));
    const { due: dueEmpty } = (await (await stubFetch(ef.stub, "GET", "/due")).json()) as { due: unknown[] };
    ok("due(): a fleet with no due candidates returns an empty set (empty range, page.size 0)", dueEmpty.length === 0);
  }

  // ===== BLOCK 13: due() range PAGING - more than one DO_LIST_PAGE of due candidates ==========
  {
    const { storage, stub } = makeFlex();
    const now = Date.now();
    const past = pad16(now - 60_000);
    const N = 1001; // strictly greater than DO_LIST_PAGE (1000) so the range scan must page twice
    for (let i = 0; i < N; i++) {
      const id = `pg-${String(i).padStart(4, "0")}`;
      storage.map.set(`dp:${id}`, { config: makeConfig(id, { enabled: true }), nextRunAt: now - 60_000, lastRunId: null, inFlight: false });
      storage.map.set(`${DUE_INDEX_PREFIX}${past}:${id}`, 1);
    }
    const { due } = await surf(stub).due();
    ok("due(): pages a >1000-candidate due range across multiple list() pages (no truncation)", due.length === N);
  }

  // ===== BLOCK 14: alarm() housekeeping sweeps - expired pruned, valid + out-of-scope kept ====
  {
    const { stub, storage } = makeScheduler();
    const now = Date.now();
    const past = now - 100_000;
    const future = now + 100_000;

    // SAML one-time assertion markers (value = notOnOrAfter epoch ms): expired / valid / malformed.
    await storage.put(`${SEEN_ASSERTION_PREFIX}exp`, past);
    await storage.put(`${SEEN_ASSERTION_PREFIX}live`, future);
    await storage.put(`${SEEN_ASSERTION_PREFIX}bad`, "not-a-number");
    // Step-up assertion challenges (the stepup: scope) + a NON-stepup challenge that must be left alone.
    await storage.put(`${PASSKEY_CHALLENGE_PREFIX}stepup:exp`, { expiresAt: past });
    await storage.put(`${PASSKEY_CHALLENGE_PREFIX}stepup:live`, { expiresAt: future });
    await storage.put(`${PASSKEY_CHALLENGE_PREFIX}stepup:nul`, null);
    await storage.put(`${PASSKEY_CHALLENGE_PREFIX}reg:keep`, { expiresAt: past });
    // Step-up tokens: expired / valid / malformed.
    await storage.put(`${STEPUP_TOKEN_PREFIX}exp`, { expiresAt: past });
    await storage.put(`${STEPUP_TOKEN_PREFIX}live`, { expiresAt: future });
    await storage.put(`${STEPUP_TOKEN_PREFIX}bad`, { expiresAt: "x" });

    await surf(stub).alarm();

    ok("alarm sweep (seen): an expired SAML marker is pruned", storage.rawGet(`${SEEN_ASSERTION_PREFIX}exp`) === undefined);
    ok("alarm sweep (seen): a still-valid SAML marker is kept", storage.rawGet(`${SEEN_ASSERTION_PREFIX}live`) !== undefined);
    ok("alarm sweep (seen): a malformed (non-numeric) marker is pruned", storage.rawGet(`${SEEN_ASSERTION_PREFIX}bad`) === undefined);
    ok("alarm sweep (stepup challenge): an expired challenge is pruned", storage.rawGet(`${PASSKEY_CHALLENGE_PREFIX}stepup:exp`) === undefined);
    ok("alarm sweep (stepup challenge): a valid challenge is kept", storage.rawGet(`${PASSKEY_CHALLENGE_PREFIX}stepup:live`) !== undefined);
    ok("alarm sweep (stepup challenge): a null/malformed challenge is pruned", storage.rawGet(`${PASSKEY_CHALLENGE_PREFIX}stepup:nul`) === undefined);
    ok("alarm sweep: a NON-stepup challenge outside the swept scope is left untouched", storage.rawGet(`${PASSKEY_CHALLENGE_PREFIX}reg:keep`) !== undefined);
    ok("alarm sweep (stepup token): an expired token is pruned", storage.rawGet(`${STEPUP_TOKEN_PREFIX}exp`) === undefined);
    ok("alarm sweep (stepup token): a valid token is kept", storage.rawGet(`${STEPUP_TOKEN_PREFIX}live`) !== undefined);
    ok("alarm sweep (stepup token): a malformed token is pruned", storage.rawGet(`${STEPUP_TOKEN_PREFIX}bad`) === undefined);
  }

  // ===== BLOCK 15: trigger reclaims a crashed run - the orphaned in-flight row -> abandoned ===
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("rcl", { enabled: true }));
    const t1 = (await (await stubFetch(stub, "POST", "/trigger", { id: "rcl" })).json()) as { runId: string; index: number };

    // Age the lease past INFLIGHT_LEASE_MS so the next trigger treats run 1 as crashed and reclaims it.
    const stored = storage.rawGet<{ inFlightSince?: number }>("dp:rcl")!;
    stored.inFlightSince = Date.now() - LEASE_EXPIRED_MS;
    await storage.put("dp:rcl", stored);

    const t2 = (await (await stubFetch(stub, "POST", "/trigger", { id: "rcl" })).json()) as { runId?: string; index?: number; skipped?: string };
    ok("trigger reclaim: an expired-lease run is reclaimed (a fresh run at the next index, not skipped)", typeof t2.runId === "string" && t2.runId !== t1.runId && t2.index === t1.index + 1);
    const orphan = (storage.rawGet<Array<{ index: number; status: string; error?: string }>>("hist:rcl") ?? []).find((h) => h.index === t1.index)!;
    ok("trigger reclaim: the orphaned in-flight row is resolved to abandoned with a reason", orphan.status === "abandoned" && typeof orphan.error === "string" && orphan.error.length > 0);

    // Coalesce control: a still-fresh lease is NOT reclaimed (the leased-skip branch).
    const t3 = (await (await stubFetch(stub, "POST", "/trigger", { id: "rcl" })).json()) as { skipped?: string };
    ok("trigger reclaim: a freshly leased run still coalesces (skipped), never double-run", typeof t3.skipped === "string");
  }

  // ===== BLOCK 16: alarm() best-effort catch - a housekeeping failure never breaks the re-arm =
  {
    const { storage, stub } = makeFlex({ throwListPrefix: "oidcstate:" });
    // A single enabled due: index entry so rearmAlarm (after the catch) has something to arm against.
    storage.map.set(`${DUE_INDEX_PREFIX}${pad16(Date.now() + 3_600_000)}:arm`, 1);
    await surf(stub).alarm(); // the oidc sweep throws -> caught -> rearmAlarm still runs
    ok("alarm catch: a thrown housekeeping sweep is swallowed and the alarm is still re-armed", storage.lastAlarmAt !== null && (storage.lastAlarmAt ?? 0) >= Date.now() - 1000);
  }

  // ===== BLOCK 17: trigger unknown-id, RING_CAP truncation, empty/missing-ring no-ops, rearm NaN
  {
    const { stub, storage } = makeScheduler();

    // trigger on an unknown downpipe throws -> the route maps it to 400 (the !ds guard).
    const unk = await stubFetch(stub, "POST", "/trigger", { id: "no-such-pipe" });
    ok("trigger: an unknown downpipe is a 400 (the !ds throw)", unk.status === 400);
    ok("trigger: the unknown-id error names the id", ((await unk.json()) as { error: string }).error.includes("no-such-pipe"));

    // RING_CAP truncation: seed a full ring + counter, then one trigger pushes past the cap and shifts.
    const fullRing = Array.from({ length: RING_CAP }, (_, i) => ({ runId: `seed-${i + 1}`, index: i + 1, startedAt: new Date(i + 1).toISOString(), status: "ok" }));
    await storage.put("dp:ringcap", { config: makeConfig("ringcap", { enabled: true }), nextRunAt: Date.now() + 3_600_000, lastRunId: "seed-50", inFlight: false });
    await storage.put("hist:ringcap", fullRing);
    await storage.put("runlogCounter", RING_CAP);
    const tCap = (await (await stubFetch(stub, "POST", "/trigger", { id: "ringcap" })).json()) as { index: number };
    const ring = storage.rawGet<Array<{ index: number }>>("hist:ringcap")!;
    ok("trigger: the ring is truncated to RING_CAP newest-last after a push past the cap", ring.length === RING_CAP);
    ok("trigger: the oldest entry was shifted out and the newest allocated index is retained", !ring.some((h) => h.index === 1) && ring.some((h) => h.index === tCap.index));

    // heartbeat on an in-flight downpipe that has NO history ring -> owned:false (the ?? [] empty path).
    await storage.put("dp:hb-nh", { config: makeConfig("hb-nh", { enabled: true }), nextRunAt: Date.now() + 3_600_000, lastRunId: null, inFlight: true, inFlightSince: Date.now() });
    const hbNoHist = (await (await stubFetch(stub, "POST", "/heartbeat", { id: "hb-nh", runId: "r", index: 1 })).json()) as { owned: boolean };
    ok("heartbeat: an in-flight downpipe with no ring owns nothing (empty-ring fallback)", hbNoHist.owned === false);

    // completeRun on a downpipe with NO history ring at all -> a clean no-op (hist ?? null, row null).
    const compNoHist = (await (await stubFetch(stub, "POST", "/complete", { id: "comp-nh", runId: "r", index: 1, status: "ok" })).json()) as { ok: boolean };
    ok("completeRun: a downpipe with no ring is a clean no-op (returns ok)", compNoHist.ok === true);

    // completeRun naming an index NOT in an existing ring -> the find ?? null no-op; the real row is intact.
    await storage.put("dp:comp-wi", { config: makeConfig("comp-wi", { enabled: true }), nextRunAt: Date.now() + 3_600_000, lastRunId: null, inFlight: true, inFlightSince: Date.now() });
    await storage.put("hist:comp-wi", [{ runId: "live-1", index: 1, startedAt: new Date().toISOString(), status: "in-flight" }]);
    await stubFetch(stub, "POST", "/complete", { id: "comp-wi", runId: "", index: 9999, status: "failed" });
    const wiRow = storage.rawGet<Array<{ index: number; status: string }>>("hist:comp-wi")!.find((h) => h.index === 1)!;
    ok("completeRun: an unknown index leaves the real in-flight row untouched (find ?? null no-op)", wiRow.status === "in-flight");

    // rearmAlarm over a malformed due: key whose time block is non-numeric -> NaN -> no alarm armed.
    const rn = makeScheduler();
    await rn.storage.put(`${DUE_INDEX_PREFIX}zzzzzzzzzzzzzzzz:bad`, 1);
    await surf(rn.stub).rearmAlarm();
    ok("rearmAlarm: a malformed (non-numeric) due: key parses to NaN and arms no alarm", rn.storage.lastAlarmAt === null);
  }

  // ===== BLOCK 12: recordTickOutcome ring + schedulerSignals (scheduler-liveness new-logging) ======
  {
    const { stub, storage } = makeScheduler();
    const s = surf(stub);
    // Seed a runlog counter + a history ring whose max index EXCEEDS the counter (the runlog-counter-reset
    // condition), and a due-index health stamp, so schedulerSignals surfaces all three signal groups.
    await storage.put("runlogCounter", 3);
    await storage.put("hist:dp-x", [{ runId: "01A", index: 7, startedAt: "2026-06-10T00:00:00.000Z", status: "ok" }]);

    // recordTickOutcome appends to the bounded ring, stamping the time + deriving the interval.
    await s.recordTickOutcome({ due: 4, dispatched: 4, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 100 });
    await s.recordTickOutcome({ due: 5, dispatched: 0, coalesced: 2, carried: 3, sealErrors: 0, passErrors: 1, budgetCap: 700, budgetSpent: 720 });
    const sig1 = await s.schedulerSignals();
    ok("recordTickOutcome: the ring holds both ticks with the derived overBudget/interval", sig1.ticks.length === 2 && sig1.ticks[1]!.overBudget === true && sig1.ticks[1]!.carried === 3 && sig1.ticks[1]!.intervalMs >= 0);
    ok("schedulerSignals: runlog surfaces the counter + the max history index (7 > 3)", sig1.runlog.counter === 3 && sig1.runlog.maxHistoryIndex === 7);
    ok("schedulerSignals: listCaps surfaces the DO page/max-page caps + the live history-ring count", sig1.listCaps.pageSize > 0 && sig1.listCaps.maxPages > 0 && sig1.listCaps.historyRings === 1);

    // rebuildDueIndex stamps the due-index parity snapshot; schedulerSignals reads it back.
    await storage.put("dp:dp-x", { config: makeConfig("dp-x"), nextRunAt: Date.now() + 60_000, lastRunId: null, inFlight: false });
    await s.rebuildDueIndex();
    const sig2 = await s.schedulerSignals();
    ok("schedulerSignals: dueIndex parity snapshot is stamped by rebuildDueIndex", typeof (sig2.dueIndex as { indexEntriesRequired?: number }).indexEntriesRequired === "number" && typeof (sig2.dueIndex as { matched?: boolean }).matched === "boolean");

    // The ring trims to the cap: append well past TICK_RING_CAP and confirm it stays bounded.
    for (let i = 0; i < 80; i++) await s.recordTickOutcome({ due: 1, dispatched: 1, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 10 });
    const sig3 = await s.schedulerSignals();
    ok("recordTickOutcome: the stored ring stays bounded (<= 64) across many ticks", sig3.ticks.length <= 64);
  }

  // ===== BLOCK 18: persist-state storage-fault counter ================================================
  {
    // recordStorageFault directly: two faults of DISTINCT classes accumulate into the distinct persisted
    // counter, and schedulerSignals surfaces it (total + per-class sub-counts + the last class/time).
    const { stub } = makeScheduler();
    const s = surf(stub);
    const empty = await s.schedulerSignals();
    ok("storageFaults: a healthy engine reports a zeroed counter (never faulted)", empty.storageFaults.total === 0 && empty.storageFaults.lastKind === null);
    await s.recordStorageFault("value-too-large");
    await s.recordStorageFault("put-failed");
    const sig = await s.schedulerSignals();
    ok("storageFaults: two distinct faults accumulate (total 2, one per class)", sig.storageFaults.total === 2 && sig.storageFaults.valueTooLarge === 1 && sig.storageFaults.putFailed === 1);
    ok("storageFaults: the most-recent fault class + a clamped timestamp are stamped", sig.storageFaults.lastKind === "put-failed" && sig.storageFaults.lastAt > 0);
  }
  {
    // persistDownpipeState PROMOTES a persist-state put fault into the counter (classified) and STILL re-throws
    // (fails loud): a generic storage error -> "put-failed". The counter write is a DIFFERENT key, so it
    // succeeds during the per-key fault (the recordable case).
    const { storage, stub } = makeFlex({ throwPutKeySubstr: "dp:", throwPutMessage: "storage subsystem unavailable" });
    const s = surf(stub);
    let threw = false;
    try {
      await s.persistDownpipeState({ config: makeConfig("sf-put", { enabled: true }), nextRunAt: Date.now(), lastRunId: null, inFlight: false } as never);
    } catch {
      threw = true;
    }
    ok("persist fault: a persist-state put fault still fails LOUD (re-thrown)", threw === true);
    const sig = await s.schedulerSignals();
    ok("persist fault: the generic storage fault was promoted to the distinct counter as 'put-failed'", sig.storageFaults.total === 1 && sig.storageFaults.putFailed === 1 && sig.storageFaults.lastKind === "put-failed");
    ok("persist fault: the faulted dp: state did not land (the put genuinely failed, not swallowed)", storage.map.get("dp:sf-put") === undefined);
  }
  {
    // A DO value-too-large put fault is classified as its own sub-class (INFRA do-value-size-limit).
    const { stub } = makeFlex({ throwPutKeySubstr: "dp:", throwPutMessage: "put() failed: value too large (limit 131072 bytes)" });
    const s = surf(stub);
    await s.persistDownpipeState({ config: makeConfig("sf-big", { enabled: true }), nextRunAt: Date.now(), lastRunId: null, inFlight: false } as never).catch(() => {});
    const sig = await s.schedulerSignals();
    ok("persist fault: a value-too-large put is promoted as the do-value-size-limit sub-class", sig.storageFaults.total === 1 && sig.storageFaults.valueTooLarge === 1 && sig.storageFaults.lastKind === "value-too-large");
  }
  {
    // recordStorageFault is BEST-EFFORT: when even the small counter write faults (a TOTAL storage outage), it
    // is SWALLOWED (never throws) so it cannot mask the original error persistDownpipeState re-throws.
    const { stub } = makeFlex({ throwPutKeySubstr: "storageFaultCounter", throwPutMessage: "total storage outage" });
    const s = surf(stub);
    let threw = false;
    try {
      await s.recordStorageFault("put-failed");
    } catch {
      threw = true;
    }
    ok("storageFaults: a counter-write fault during recording is swallowed (best-effort, never throws)", threw === false);
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-SCHEDULING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
