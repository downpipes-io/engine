// AUTH-72: sweepAndBoundLoginChallenges enforces PASSKEY_LOGIN_CHALLENGE_CAP, SERVER-SIDE, driving the
// REAL scheduler DO (src/sched/scheduler-do.ts) with the in-memory storage double only. No network, no
// deploy, no cost. Run:
//   node test/validate-passkey-login-cap.ts
//
// A login/begin mints a `login:<id>` challenge BEFORE any credential is known, so an unauthenticated
// login/begin flood would otherwise grow DO storage without bound (each is consumed only by a matching
// finish an attacker never sends). The DO's first line of defence is the per-IP /admin/auth/* limiter (so a
// real attacker is rate-limited long before the cap matters); the STORAGE cap is the second line, run on
// every login/begin: it deletes EXPIRED login challenges first, then, if still over the cap, evicts the
// OLDEST survivors down to the cap. This validator drives the DO method directly so the cap itself is
// exercised (the full-router flood is bounded by the per-IP limiter, which validate-session.ts/the live
// chaos tier cover).
//
// What this proves: (a) after a flood the stored login-challenge set is BOUNDED to the cap; (b) EXPIRED
// challenges are SWEPT FIRST (unconditionally, regardless of the cap); (c) when still over the cap the
// OLDEST survivors are evicted first (the DoS-by-eviction window: an old in-flight challenge can be evicted
// before its finish), keeping the NEWEST; (d) at/below the cap the sweep is a no-op (a legitimate burst is
// never evicted mid-ceremony); and the sweep touches ONLY the login-challenge family.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { PASSKEY_CHALLENGE_PREFIX, PASSKEY_LOGIN_CHALLENGE_CAP } from "../src/sched/scheduler-do-base.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const LOGIN_PREFIX = `${PASSKEY_CHALLENGE_PREFIX}login:`;

// seedLogin writes a login-challenge record straight into storage (the exact shape putPasskeyChallenge
// persists for a `login:<id>` scope), so the sweep is exercised without standing up the WebAuthn ceremony.
async function seedLogin(storage: MockStorage, id: string, createdAt: number, ttlMs: number): Promise<void> {
  await storage.put(`${LOGIN_PREFIX}${id}`, { challenge: `chal-${id}`, scope: `login:${id}`, createdAt, expiresAt: createdAt + ttlMs });
}
function countLogin(storage: MockStorage): number {
  return storage.countPrefix(LOGIN_PREFIX);
}
// pad keeps the seeded ids in ascending lexicographic order so the createdAt order and the key order agree
// (the eviction is by createdAt; padding makes the assertions read straightforwardly).
function pad(n: number): string {
  return String(n).padStart(5, "0");
}

async function run(): Promise<void> {
  console.log("validate-passkey-login-cap: sweepAndBoundLoginChallenges enforces PASSKEY_LOGIN_CHALLENGE_CAP");
  const now = 1_780_000_000_000;

  // (a) BOUND TO THE CAP: seed cap+50 LIVE login challenges, then sweep -> exactly the cap survives.
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const over = PASSKEY_LOGIN_CHALLENGE_CAP + 50;
    for (let i = 0; i < over; i++) await seedLogin(storage, `live-${pad(i)}`, now - over + i, 60_000);
    ok("AUTH-72(a): setup seeded MORE than the cap", countLogin(storage) === over);
    await dobj.sweepAndBoundLoginChallenges(now);
    ok("AUTH-72(a): after the sweep the login-challenge set is bounded to PASSKEY_LOGIN_CHALLENGE_CAP", countLogin(storage) === PASSKEY_LOGIN_CHALLENGE_CAP);
  }

  // (b) EXPIRED SWEPT FIRST: a mix of expired + live below the cap -> only the expired are deleted, every
  // live one survives (expiry is unconditional, independent of the cap).
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const liveN = 10;
    const expiredN = 7;
    for (let i = 0; i < liveN; i++) await seedLogin(storage, `live-${pad(i)}`, now - 1000, 60_000); // exp in the future
    for (let i = 0; i < expiredN; i++) await seedLogin(storage, `dead-${pad(i)}`, now - 120_000, 60_000); // exp in the past
    ok("AUTH-72(b): setup seeded live + expired BELOW the cap", countLogin(storage) === liveN + expiredN);
    await dobj.sweepAndBoundLoginChallenges(now);
    ok("AUTH-72(b): EXPIRED login challenges are swept (deleted) regardless of the cap", countLogin(storage) === liveN);
    const survivors = await storage.list<{ expiresAt: number }>({ prefix: LOGIN_PREFIX });
    ok("AUTH-72(b): every survivor is unexpired", [...survivors.values()].every((r) => r.expiresAt > now));
  }

  // (c) OLDEST EVICTED FIRST (the DoS-by-eviction window): over the cap with all live, the OLDEST by
  // createdAt are evicted and the NEWEST kept - so an OLD in-flight challenge can be evicted before its
  // finish. Seed cap+overflow live with strictly increasing createdAt and assert the oldest are gone.
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const overflow = 5;
    const total = PASSKEY_LOGIN_CHALLENGE_CAP + overflow;
    for (let i = 0; i < total; i++) await seedLogin(storage, `c-${pad(i)}`, now - total + i, 60_000); // createdAt strictly increasing
    await dobj.sweepAndBoundLoginChallenges(now);
    ok("AUTH-72(c): still bounded to the cap when ALL are live", countLogin(storage) === PASSKEY_LOGIN_CHALLENGE_CAP);
    let oldestGone = true;
    let newestKept = true;
    for (let i = 0; i < overflow; i++) if ((await storage.get(`${LOGIN_PREFIX}c-${pad(i)}`)) !== undefined) oldestGone = false;
    for (let i = overflow; i < total; i++) if ((await storage.get(`${LOGIN_PREFIX}c-${pad(i)}`)) === undefined) newestKept = false;
    ok("AUTH-72(c): the OLDEST survivors are evicted first (an old in-flight challenge can die before its finish)", oldestGone);
    ok("AUTH-72(c): the NEWEST challenges (most likely to be completed) are kept", newestKept);
  }

  // (d) AT/BELOW THE CAP IS A NO-OP: a live set at the cap is fully preserved (no eviction of an in-flight
  // challenge a legitimate burst is mid-ceremony on).
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    for (let i = 0; i < PASSKEY_LOGIN_CHALLENGE_CAP; i++) await seedLogin(storage, `k-${pad(i)}`, now - 1000, 60_000);
    await dobj.sweepAndBoundLoginChallenges(now);
    ok("AUTH-72(d): a live set AT the cap is fully preserved (no eviction at/below the cap)", countLogin(storage) === PASSKEY_LOGIN_CHALLENGE_CAP);
  }

  // (d2) FAMILY-SCOPED: the login sweep touches ONLY `login:` challenges. An EXPIRED registration challenge
  // (reg:) is NOT deleted by the login sweep (registration challenges are one-per-email, bounded elsewhere),
  // and only the login family is bounded.
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    await storage.put(`${PASSKEY_CHALLENGE_PREFIX}reg:someone@example.com`, { challenge: "r", scope: "reg:someone@example.com", createdAt: now - 200_000, expiresAt: now - 100_000 }); // EXPIRED reg
    for (let i = 0; i < PASSKEY_LOGIN_CHALLENGE_CAP + 3; i++) await seedLogin(storage, `m-${pad(i)}`, now - 1000, 60_000);
    await dobj.sweepAndBoundLoginChallenges(now);
    ok("AUTH-72(d2): the login sweep does NOT touch a (even expired) registration challenge (reg:)", (await storage.get(`${PASSKEY_CHALLENGE_PREFIX}reg:someone@example.com`)) !== undefined);
    ok("AUTH-72(d2): only the login-challenge family is bounded by the sweep", countLogin(storage) === PASSKEY_LOGIN_CHALLENGE_CAP);
  }

  // RESIDUAL: this exercises the cap method faithfully over the real DO + storage double. The end-to-end
  // login/begin flood through the full router is bounded FIRST by the per-IP /admin/auth/* limiter (the
  // front line), which is not the cap under test here and is covered separately; a true concurrent flood
  // under load belongs to the live chaos tier.

  console.log(failures === 0 ? "\nvalidate-passkey-login-cap: ALL PASS" : `\nvalidate-passkey-login-cap: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
