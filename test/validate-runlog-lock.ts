// Prove the single-writer RUNLOG lock plane of the SchedulerDO end to end with in-memory
// doubles only. No network, no deploy, no cost. Run:
//   node test/validate-runlog-lock.ts
//
// Why this exists: the account-wide RUNLOG read-modify-write is serialised
// through the scheduler DO so the RUNLOG and its detached .sig are written by ONE run at a
// time (the single-writer refinement that closes the two-object window). That lock plane
// (acquireRunlogLock / releaseRunlogLock, the lease, and the lock token) had no direct test
// coverage. This file drives the two public endpoints the router actually calls
// (POST /runlog-lock/acquire and POST /runlog-lock/release; see engine/src/index.ts) using
// the SAME in-memory MockStorage + stubFetch harness as validate-scheduler.ts.
//
// What this proves (each via a NEGATIVE control, not a vacuous assert):
//  - acquire on a free lock returns acquired:true with a fresh token, and persists the lease;
//  - a SECOND acquire while the lease is live is REFUSED (acquired:false, no token leaked);
//  - release with the correct token frees the lock, and a re-acquire then mints a DIFFERENT
//    token (a genuine re-grant, not an echo of the old one);
//  - a LEASE-EXPIRED lock is reclaimable by a new acquire WITHOUT a release (backdating the
//    stored expiry in storage exactly as validate-scheduler.ts backdates nextRunAt), and the
//    reclaimed token differs from the abandoned one;
//  - release with a STALE/WRONG token does NOT free another holder's lock (the holder still
//    has it: a concurrent acquire is still refused), and an empty/missing-token release is a
//    harmless no-op that also does not free the holder;
//  - the classic hazard: a suspended writer that wakes after its lease expired and a NEW
//    holder has reclaimed must NOT free the new holder's lock with its stale token;
//  - release on an unheld lock is a harmless no-op that creates nothing;
//  - the pipeline's RunlogLock contract (engine/src/seal/pipeline.ts), backed by these two DO
//    endpoints exactly as engine/src/index.ts wires it, delivers real mutual exclusion: while
//    one run holds the lease a concurrent run's acquire() returns null.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { RunlogLock } from "../src/seal/pipeline.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

// The DO's persisted lock shape (mirrors the inline type in acquire/releaseRunlogLock). Used
// only by the test to read and to backdate the stored lease.
interface StoredLock {
  token: string;
  expiresAt: number;
}
const LOCK_KEY = "runlogLock";

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  // Partial stub: only the storage field is used by SchedulerDO on the lock paths under test.
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  return { storage, stub: dobj };
}

// stubFetch drives the HTTP surface of the DO the same way the router would, without any
// network (identical to validate-scheduler.ts).
function stubFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const init: RequestInit = {
    method,
    headers: body !== undefined ? { "content-type": "application/json" } : {},
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return dobj.fetch(new Request(url, init));
}

type AcquireResult = { acquired: boolean; token?: string };

async function acquire(stub: SchedulerDO): Promise<{ status: number; body: AcquireResult }> {
  const r = await stubFetch(stub, "POST", "/runlog-lock/acquire");
  return { status: r.status, body: (await r.json()) as AcquireResult };
}

async function release(stub: SchedulerDO, token: unknown): Promise<{ status: number; body: { ok?: true; error?: string } }> {
  // token is passed through as-is so a test can send a wrong token, or {} (missing token).
  const r = await stubFetch(stub, "POST", "/runlog-lock/release", token === undefined ? {} : { token });
  return { status: r.status, body: (await r.json()) as { ok?: true; error?: string } };
}

// Age the stored lease into the past so the next acquire treats the holder as crashed and
// reclaims (the same direct-storage backdating validate-scheduler.ts uses for nextRunAt /
// inFlightSince). Returns the prior token so the test can assert the reclaim mints a new one.
function expireLease(storage: MockStorage): string {
  const cur = storage.rawGet<StoredLock>(LOCK_KEY);
  if (!cur) throw new Error("test bug: expected a stored lock to expire");
  const prior = cur.token;
  cur.expiresAt = Date.now() - 1000; // one second in the past: strictly < now, so not "live"
  storage.rawPut(LOCK_KEY, cur);
  return prior;
}

// ---- TC-RL-01: acquire on a free lock returns a fresh token and persists the lease ------
async function testAcquireOnFree(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const a = await acquire(stub);
    ok("acquire: 200 response", a.status === 200);
    ok("acquire: acquired is true on a free lock", a.body.acquired === true);
    ok("acquire: returns a non-empty token", typeof a.body.token === "string" && (a.body.token as string).length > 0);

    // The lease must be persisted under runlogLock with that token and a future expiry.
    const stored = storage.rawGet<StoredLock>(LOCK_KEY);
    ok("acquire: lease persisted in storage", stored !== undefined);
    ok("acquire: stored token matches the returned token", stored?.token === a.body.token);
    ok("acquire: stored lease expires in the future", typeof stored?.expiresAt === "number" && stored!.expiresAt > Date.now());
  }
}

// ---- TC-RL-02: a second acquire while the lease is live is REFUSED ----------------------
// Negative control: the lock is mutually exclusive. A second acquire must report
// acquired:false and must NOT leak a token (a refused caller gets nothing to release with).
async function testContention(): Promise<void> {
  {
    const { stub } = makeScheduler();
    const first = await acquire(stub);
    ok("contention: first acquire succeeds", first.body.acquired === true && typeof first.body.token === "string");

    const second = await acquire(stub);
    ok("contention: second acquire while held is refused", second.body.acquired === false);
    ok("contention: refused acquire carries no token", second.body.token === undefined);

    // Belt and braces: a third attempt is still refused (the live lease is not consumed by a
    // refused attempt, so it does not somehow free itself).
    const third = await acquire(stub);
    ok("contention: a third acquire while held is still refused", third.body.acquired === false);
  }
}

// ---- TC-RL-03: release with the correct token frees the lock; re-acquire mints a NEW token
async function testRelease(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const first = await acquire(stub);
    const token = first.body.token as string;
    ok("release: acquired before release", first.body.acquired === true && typeof token === "string");

    const rel = await release(stub, token);
    ok("release: 200 response", rel.status === 200);
    ok("release: body is { ok: true }", rel.body.ok === true);
    ok("release: lease removed from storage", !storage.has(LOCK_KEY));

    // A re-acquire after release must succeed AND hand out a genuinely different token (proving
    // the lock was actually freed and a fresh lease minted, not the old token echoed back).
    const reAcq = await acquire(stub);
    ok("release: re-acquire after release succeeds", reAcq.body.acquired === true);
    ok("release: re-acquire mints a new token (not the freed one)", typeof reAcq.body.token === "string" && reAcq.body.token !== token);
  }
}

// ---- TC-RL-04: a LEASE-EXPIRED lock is reclaimable by a new acquire (no release needed) --
// A holder that crashes never releases. The lease (RUNLOG_LEASE_MS) bounds that: once it has
// elapsed, the next run reclaims. We prove BOTH sides of the boundary in one flow:
//   (a) while the lease is fresh, a second acquire is refused (the lock really is held);
//   (b) after backdating the stored expiry into the past, a new acquire reclaims it.
async function testLeaseReclaim(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const held = await acquire(stub);
    const heldToken = held.body.token as string;
    ok("lease-reclaim: initial acquire holds the lock", held.body.acquired === true && typeof heldToken === "string");

    // (a) lease fresh -> refused.
    const refusedWhileFresh = await acquire(stub);
    ok("lease-reclaim: a fresh lease refuses a second acquire", refusedWhileFresh.body.acquired === false);

    // (b) age the lease past RUNLOG_LEASE_MS without sleeping, exactly as validate-scheduler.ts
    // backdates a stored field, then a new acquire reclaims the crashed holder's lock.
    const prior = expireLease(storage);
    ok("lease-reclaim: backdated the held token's lease", prior === heldToken);

    const reclaimed = await acquire(stub);
    ok("lease-reclaim: an expired lease is reclaimable by a new acquire", reclaimed.body.acquired === true);
    ok("lease-reclaim: the reclaimed token differs from the abandoned one", typeof reclaimed.body.token === "string" && reclaimed.body.token !== heldToken);

    // The reclaimed lease is the live one now: another acquire is refused again, and storage
    // holds the NEW token (the abandoned token is gone, not lingering).
    const refusedAfterReclaim = await acquire(stub);
    ok("lease-reclaim: the reclaimed lease again refuses a second acquire", refusedAfterReclaim.body.acquired === false);
    const stored = storage.rawGet<StoredLock>(LOCK_KEY);
    ok("lease-reclaim: storage now holds the reclaimed token", stored?.token === reclaimed.body.token);
  }
}

// ---- TC-RL-05: a STALE/WRONG token does not free another holder's lock ------------------
// The defining single-writer guarantee: only the CURRENT holder's token frees the lock.
// A release carrying any other token (a stale token from a prior run, a forged one, or a
// missing one) must leave the holder's lock intact.
async function testWrongToken(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const holder = await acquire(stub);
    const holderToken = holder.body.token as string;
    ok("wrong-token: holder acquires the lock", holder.body.acquired === true && typeof holderToken === "string");

    // A release with a WRONG token returns ok:true (it is a no-op, never an error) but must NOT
    // delete the holder's lease.
    const wrong = await release(stub, "not-the-real-token");
    ok("wrong-token: wrong-token release still returns { ok: true }", wrong.body.ok === true);
    ok("wrong-token: holder's lease survives a wrong-token release", storage.rawGet<StoredLock>(LOCK_KEY)?.token === holderToken);

    // Proof the holder still HOLDS it: a fresh acquire is still refused.
    const stillRefused = await acquire(stub);
    ok("wrong-token: lock still held after wrong-token release (acquire refused)", stillRefused.body.acquired === false);

    // An empty/missing-token release ({} body, so req.token is undefined) is likewise a no-op.
    const missing = await release(stub, undefined);
    ok("wrong-token: missing-token release returns { ok: true }", missing.body.ok === true);
    ok("wrong-token: holder's lease survives a missing-token release", storage.rawGet<StoredLock>(LOCK_KEY)?.token === holderToken);
    const stillRefused2 = await acquire(stub);
    ok("wrong-token: lock still held after missing-token release (acquire refused)", stillRefused2.body.acquired === false);

    // Finally, the CORRECT token frees it, confirming the lock was genuinely held throughout
    // (so the refusals above were the lock working, not an unrelated failure).
    const right = await release(stub, holderToken);
    ok("wrong-token: correct-token release frees the lock", right.body.ok === true && !storage.has(LOCK_KEY));
    const nowFree = await acquire(stub);
    ok("wrong-token: lock is acquirable once the correct token releases it", nowFree.body.acquired === true);
  }
}

// ---- TC-RL-06: release on an unheld lock is a harmless no-op ----------------------------
// Releasing when nothing is held must not error and must not conjure a lock into existence.
async function testReleaseUnheld(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const rel = await release(stub, "phantom-token");
    ok("release-unheld: 200 response", rel.status === 200);
    ok("release-unheld: body is { ok: true }", rel.body.ok === true);
    ok("release-unheld: no lock was created in storage", !storage.has(LOCK_KEY));
    // The lock is still freely acquirable afterwards.
    const a = await acquire(stub);
    ok("release-unheld: lock remains acquirable", a.body.acquired === true);
  }
}

// ---- TC-RL-07: a suspended writer must not free a NEW holder's reclaimed lock -----------
// The real-world hazard the token check defends against: run A takes the lock, stalls past
// its lease, run B reclaims (a NEW token), and THEN A wakes and calls release(A.token). A's
// stale token must not free B's lease, or two writers could touch the RUNLOG at once.
async function testSuspendedWriter(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const a = await acquire(stub);
    const tokenA = a.body.token as string;
    ok("suspended-writer: run A acquires the lock", a.body.acquired === true && typeof tokenA === "string");

    // A stalls; its lease expires; B reclaims with a fresh token.
    expireLease(storage);
    const b = await acquire(stub);
    const tokenB = b.body.token as string;
    ok("suspended-writer: run B reclaims after A's lease expires", b.body.acquired === true && typeof tokenB === "string");
    ok("suspended-writer: A and B hold different tokens", tokenA !== tokenB);

    // A wakes up late and releases with its STALE token: must NOT free B's lock.
    const staleRelease = await release(stub, tokenA);
    ok("suspended-writer: A's stale release returns { ok: true } (no-op)", staleRelease.body.ok === true);
    ok("suspended-writer: B's lease survives A's stale release", storage.rawGet<StoredLock>(LOCK_KEY)?.token === tokenB);

    // Proof B still holds it: a concurrent acquire is still refused.
    const refused = await acquire(stub);
    ok("suspended-writer: B still holds the lock (concurrent acquire refused)", refused.body.acquired === false);

    // B's own token still frees it normally.
    const bReleases = await release(stub, tokenB);
    ok("suspended-writer: B's own token frees its lease", bReleases.body.ok === true && !storage.has(LOCK_KEY));
  }
}

// ---- TC-RL-INT: the pipeline RunlogLock contract over the real DO endpoints --------------
async function testPipelineLock(): Promise<void> {
  // engine/src/seal/pipeline.ts's appendRunlog drives a RunlogLock (acquire(): token|null,
  // release(token)) to serialise the account-wide RUNLOG write. engine/src/index.ts implements
  // that contract by calling exactly these two DO endpoints. We build the SAME adapter here and
  // prove it delivers real mutual exclusion: while one run holds the lease a concurrent run's
  // acquire() returns null, which is the property the best-effort serialisation depends on.
  // (appendRunlog is module-private; its RUNLOG accumulation is covered through the public
  // runBackup in validate-pipeline-runlog.ts, so it is not re-imported here.)
  {
    const { stub, storage } = makeScheduler();

    // The DO-backed RunlogLock, wired identically to engine/src/index.ts.
    const lock: RunlogLock = {
      acquire: async () => {
        const r = (await (await stubFetch(stub, "POST", "/runlog-lock/acquire")).json()) as AcquireResult;
        return r.acquired && r.token ? r.token : null;
      },
      release: async (token: string) => {
        await stubFetch(stub, "POST", "/runlog-lock/release", { token });
      },
    };

    // Run 1 takes the lock.
    const tokenRun1 = await lock.acquire();
    ok("pipeline-lock: a run acquires a token through the RunlogLock", typeof tokenRun1 === "string" && (tokenRun1 as string).length > 0);

    // Run 2, attempting to write concurrently, gets null (it must NOT also enter the critical
    // section). This is the mutual exclusion appendRunlog relies on when a lock is provided.
    const tokenRun2 = await lock.acquire();
    ok("pipeline-lock: a concurrent run's acquire returns null while held", tokenRun2 === null);

    // Run 1 finishes its RUNLOG write and releases.
    await lock.release(tokenRun1 as string);
    ok("pipeline-lock: lease cleared from storage after release", !storage.has(LOCK_KEY));

    // Now run 2 (or the next run) can take it and proceed.
    const tokenRun3 = await lock.acquire();
    ok("pipeline-lock: the next run acquires once the holder releases", typeof tokenRun3 === "string" && (tokenRun3 as string).length > 0);
    ok("pipeline-lock: the next run's token differs from the first holder's", tokenRun3 !== tokenRun1);
    await lock.release(tokenRun3 as string);
  }
}

async function main(): Promise<void> {
  await testAcquireOnFree();
  await testContention();
  await testRelease();
  await testLeaseReclaim();
  await testWrongToken();
  await testReleaseUnheld();
  await testSuspendedWriter();
  await testPipelineLock();

  console.log(failures === 0 ? "\nRUNLOG-LOCK VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
