// Prove the RECOVERY-CODE break-glass end to end, SERVER-SIDE, driving the REAL scheduler DO
// (src/sched/scheduler-do.ts), the REAL router (src/admin/router.ts) and the REAL pure core
// (src/admin/recovery.ts), with in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-recovery-codes.ts
//
// A recovery code is the normal-app account-recovery pattern: an Owner (or any user) who loses their passkey
// signs in with a single-use recovery code at the sign-in screen and gets a NORMAL signed session, then is
// prompted to enrol a fresh passkey. It is the ONGOING admin break-glass, distinct from the ADMIN_TOKEN (a
// one-time bootstrap, then disposed) and from the backup BREAK-GLASS KEY (offline DATA recovery).
//
// What this proves (the build contract):
//  - a valid code recovers a session for that email and is then CONSUMED (the same code fails the 2nd time);
//  - ONLY salted hashes are stored - never a plaintext code, and the codes are not returned again after the
//    one-time generation;
//  - a wrong code fails GENERICALLY (a single 401, no oracle on which part failed) and is HARD rate-limited
//    (per IP + per email, fail closed);
//  - regenerate invalidates ALL prior codes for that email;
//  - the remaining-count + the recovery-codes-low posture finding behave;
//  - the token-dispose (retire) is REFUSED until a break-glass way back in exists (recovery codes for an
//    Owner OR a 2nd Owner) and ALLOWED after;
//  - every recovery attempt is AUDITED (success AND failure) and a successful use / repeated failure WOULD
//    alert (the DO returns the alert signal the router routes);
//  - one user cannot see or consume another user's codes.
//
// The pure recovery.ts core (generate/hash/verify/count) is also exercised directly with a real key, so the
// path under test is the one that ships.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { encodeCaller, passkeySubject, type Caller } from "../src/admin/identity.ts";
import {
  generateRecoveryCodes,
  fakeRecoveryRecord,
  verifyCode,
  remainingCount,
  normaliseCode,
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_CHARS,
  type RecoveryRecord,
} from "../src/admin/recovery.ts";
import type { Env } from "../src/env.d.ts";
// The in-memory DO storage double (the subset SchedulerDO uses) is shared across the DO validators.
import { readFile } from "node:fs/promises";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://downpipe-console.example";
const ADMIN_TOKEN = "test-admin-token-recovery-recovery";
const TEAM = "downpipes.cloudflareaccess.com";
const AUD = "test-aud-recovery";

function makeScheduler(): { env: Env; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD } as unknown as Env;
  return { env, storage, stub };
}

// doFetch drives a route straight into the DO (bypassing the router) so a test can seed/inspect DO state
// (e.g. mint a recovery set for an email, read the record) without standing up the WebAuthn enrolment.
async function doFetch(stub: DurableObjectStub, path: string, init?: RequestInit): Promise<Response> {
  return stub.fetch(`https://scheduler.internal${path}`, init);
}

// seedRoleOwner writes an Owner role row for an email directly into the DO store (the same shape roleSet
// persists), so a test can establish an account with known Owners without the bootstrap ceremony.
async function seedRole(storage: MockStorage, email: string, role: string): Promise<void> {
  await storage.put(`role:${email}`, { email, role, grantedBy: "test", grantedAt: new Date().toISOString() });
}

// mintCodesFor mints a recovery set for an email via the DO's regenerate route and returns the plaintext
// codes (the one-time display). It is the test's stand-in for "the user enrolled and was shown codes".
async function mintCodesFor(stub: DurableObjectStub, email: string): Promise<string[]> {
  const resp = await doFetch(stub, "/recovery/regenerate", {
    method: "POST",
    body: JSON.stringify({ email }),
    headers: { "content-type": "application/json" },
  });
  const j = (await resp.json()) as { ok?: boolean; codes?: string[] };
  return j.codes ?? [];
}

// recoverViaRouter drives POST /admin/auth/recovery through the REAL router (the unauthenticated sign-in
// path), returning the status, parsed body and the Set-Cookie header (the session on success).
// RecoveryBody is the JSON-OBJECT shape /admin/auth/recovery returns on a successful (200) recovery; the
// 401 path answers the plaintext string "unauthorised", so RecoveryResponse keeps the string|null members
// and a test still asserts body === "unauthorised" directly. recoveryBody narrows a response to the object
// form (or undefined for the string/null path) so the .role/.enrolPasskey/.recoveryCodesRemaining reads on
// the 200 path are type-checked while preserving the existing `body?.field` null-safe semantics.
type RecoveryBody = { ok?: boolean; role?: string; enrolPasskey?: boolean; recoveryCodesRemaining?: number };
type RecoveryResponse = RecoveryBody | string | null;
function recoveryBody(r: { body: RecoveryResponse }): RecoveryBody | undefined {
  return typeof r.body === "object" && r.body !== null ? r.body : undefined;
}
async function recoverViaRouter(env: Env, email: string, code: string, ip = "203.0.113.50"): Promise<{ status: number; body: RecoveryResponse; setCookie: string | null }> {
  const resp = await handleAdmin(
    new Request("https://engine.example/admin/auth/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": ip },
      body: JSON.stringify({ email, code }),
    }),
    env,
  );
  let body: RecoveryResponse = null;
  const text = await resp.text();
  try {
    body = JSON.parse(text);
  } catch {
    body = text; // the 401 path is plaintext "unauthorised"
  }
  return { status: resp.status, body, setCookie: resp.headers.get("set-cookie") };
}

// ===========================================================================================
// 1. THE PURE CORE (recovery.ts): generate -> only hashes -> constant-time verify -> consume.
// ===========================================================================================
async function testPureCore(): Promise<void> {
  {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const { codes, record } = await generateRecoveryCodes(key, "user@example.com", "2026-01-01T00:00:00.000Z");
    ok("pure: generate mints exactly RECOVERY_CODE_COUNT codes", codes.length === RECOVERY_CODE_COUNT);
    ok("pure: the record holds exactly that many hashes", record.codes.length === RECOVERY_CODE_COUNT);
    ok("pure: each code is the six-group xxxxx-...-xxxxx human format (30 chars / 150 bits)", codes.every((c) => /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){5}$/.test(c)));
    ok("pure: codes are distinct", new Set(codes).size === codes.length);
    ok("pure: the record stores ONLY hashes (no plaintext), all unconsumed", record.codes.every((c) => c.hash.startsWith("hmac-sha256:") && c.consumed === false && typeof c.salt === "string"));
    const recordJson = JSON.stringify(record);
    ok("pure: NO plaintext code appears in the serialised record", codes.every((c) => !recordJson.includes(c) && !recordJson.includes(c.replaceAll("-", ""))));
    // A valid code verifies and reports its index; a wrong code does not.
    const good = await verifyCode(key, record, codes[3]!);
    ok("pure: a valid code verifies and reports its index", good.matched === true && good.index === 3);
    const bad = await verifyCode(key, record, "00000-00000-00000-00000-00000-00000");
    ok("pure: a wrong code does not verify", bad.matched === false && bad.index === -1);
    // Normalisation: lower-case + hyphen/space tolerance maps to the same match.
    const lower = await verifyCode(key, record, codes[3]!.toLowerCase());
    ok("pure: a lower-cased code still verifies (normalisation)", lower.matched === true && lower.index === 3);
    const spaced = await verifyCode(key, record, ` ${codes[3]!.replace("-", " ")} `);
    ok("pure: a code with stray spacing still verifies (normalisation)", spaced.matched === true);
    // A different key never verifies a code minted under the first (the in-DO secret binds the hash).
    const otherKey = crypto.getRandomValues(new Uint8Array(32));
    ok("pure: a code does NOT verify under a different signing key", (await verifyCode(otherKey, record, codes[0]!)).matched === false);
    // Consumed codes never match.
    record.codes[3]!.consumed = true;
    ok("pure: a CONSUMED code never matches again", (await verifyCode(key, record, codes[3]!)).matched === false);
    ok("pure: remainingCount reflects the consumed one", remainingCount(record) === RECOVERY_CODE_COUNT - 1);
    ok("pure: remainingCount of a null record is 0", remainingCount(null) === 0);
    // normaliseCode shape.
    ok("pure: normaliseCode strips to the bare alphabet length", normaliseCode("abcde-fghjk-mnpqr-stvwx-yz234-56789").length === RECOVERY_CODE_CHARS);
    ok("pure: normaliseCode of a non-string is empty", normaliseCode(42 as unknown) === "");
    // Structural gate: a code whose normalised length is not exactly RECOVERY_CODE_CHARS never matches, so
    // the wrong-length timing-uniformity path is exercised directly (short and long).
    const shortIn = await verifyCode(key, record, "1234");
    ok("pure: a too-short code never matches (structural gate)", shortIn.matched === false && shortIn.index === -1);
    const longIn = await verifyCode(key, record, `${codes[0]!}-23456`);
    ok("pure: a too-long code never matches (structural gate)", longIn.matched === false && longIn.index === -1);

    // ===== THE CONFUSABLE MAP: I/L RESOLVE TO 1 AND O TO 0, THEY ARE NOT DELETED. =====
    //
    // I/L/O/U are absent from the alphabet BECAUSE a recovery code is read off paper and typed back, and
    // those characters are the ones a reader confuses. normaliseCode must MAP them rather than strip them, so
    // a customer who types O for 0 -- the single typo the alphabet exists to tolerate -- is not told the code
    // did not work, on a break-glass path, at the one moment they are locked out.
    //
    // Asserted on the RESOLVED VALUE, not on the shape around it: the mapped string must equal the code the
    // customer really holds, and it must then actually VERIFY against the stored record.
    ok("confusables: I and L resolve to 1, O resolves to 0", normaliseCode("IL-O") === "110");
    ok("confusables: U has no visual twin and stays stripped (Crockford excludes it for a different reason)", normaliseCode("U") === "");
    {
      // A code the customer really holds, retyped with every 0 read back as O and every 1 as I: the exact
      // paper-to-keyboard mistake. It must match, and the CONTROL below must not.
      const real = codes[4]!;
      const mistyped = real.replace(/0/g, "O").replace(/1/g, "I");
      const r = await verifyCode(key, record, mistyped);
      ok("confusables: a code retyped with O for 0 and I for 1 VERIFIES against the stored record", r.matched === true);
      // NEGATIVE CONTROL that must DISCRIMINATE: a code differing by a real alphabet character (not a
      // confusable) must still fail. Without this, a normaliser that mapped everything to nothing would pass.
      const wrong = `${real.slice(0, -1)}${real.endsWith("Z") ? "Y" : "Z"}`;
      ok("confusables CONTROL: a code differing by one REAL alphabet character still fails", (await verifyCode(key, record, wrong)).matched === false);
    }

    // fakeRecoveryRecord (the anti-enumeration dummy builder) is the standard size, hash-shaped, and
    // never matches anything - but built from plain random bytes, not a real HMAC (proven by cost in
    // testDummyRecordCostSymmetry below; this just checks its shape and non-matching behaviour).
    const dummy = fakeRecoveryRecord();
    ok("pure: fakeRecoveryRecord is the standard size", dummy.codes.length === RECOVERY_CODE_COUNT);
    ok(
      "pure: fakeRecoveryRecord's slots are hash-shaped (tagged hex) and unconsumed",
      dummy.codes.every((c) => c.hash.startsWith("hmac-sha256:") && /^[0-9a-f]{64}$/.test(c.hash.slice("hmac-sha256:".length)) && c.consumed === false),
    );
    ok("pure: fakeRecoveryRecord never matches a presented code under any key", (await verifyCode(key, dummy, codes[0]!)).matched === false);
    ok("pure: two fakeRecoveryRecord calls are not identical (fresh CSPRNG each time)", JSON.stringify(fakeRecoveryRecord()) !== JSON.stringify(dummy));
  }
}

// ===========================================================================================
// 2. RECOVER via the router: a valid code mints a session, is single-use, and prompts re-enrolment.
// ===========================================================================================
async function testRecoverViaRouter(): Promise<void> {
  {
    const { env, storage, stub } = makeScheduler();
    const OWNER = "owner-recover@acme.example";
    await seedRole(storage, OWNER, "owner");
    const codes = await mintCodesFor(stub, OWNER);
    ok("recover: setup minted a 10-code set for the Owner", codes.length === 10);

    // A valid code recovers: 200, a session cookie, the resolved role, and the enrol-a-fresh-passkey prompt.
    const r1 = await recoverViaRouter(env, OWNER, codes[0]!);
    ok("recover: a valid code returns 200", r1.status === 200);
    ok("recover: a valid recovery sets a __Host- session cookie", r1.setCookie !== null && r1.setCookie.includes("__Host-downpipes_session="));
    ok("recover: the response carries the recovered role", recoveryBody(r1)?.role === "owner");
    ok("recover: the response prompts a fresh passkey enrolment", recoveryBody(r1)?.enrolPasskey === true);
    ok("recover: the response reports the remaining count (9 after one use)", recoveryBody(r1)?.recoveryCodesRemaining === 9);
    // The session cookie actually authenticates: the same cookie on GET /admin/whoami resolves the Owner.
    const cookie = (r1.setCookie ?? "").split(";")[0]!; // "__Host-downpipes_session=<token>"
    const who = await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { cookie } }), env);
    const whoBody = (await who.json()) as { role?: string; method?: string; email?: string };
    ok("recover: the recovered session authenticates as the Owner (passkey-class session)", who.status === 200 && whoBody.role === "owner" && whoBody.method === "passkey" && whoBody.email === OWNER);

    // SINGLE USE: the SAME code fails the second time (generic 401), and the count did not drop further.
    const r2 = await recoverViaRouter(env, OWNER, codes[0]!);
    ok("recover: the SAME code fails the second time (single-use consumed)", r2.status === 401 && r2.body === "unauthorised");
    // A DIFFERENT, still-unconsumed code still works (proving only the one code was consumed).
    const r3 = await recoverViaRouter(env, OWNER, codes[1]!);
    ok("recover: a different unconsumed code still recovers", r3.status === 200 && recoveryBody(r3)?.role === "owner");

    // The stored record marks exactly the two used codes consumed; the plaintext is never stored.
    const rec = await storage.get<RecoveryRecord>(`recovery:${OWNER}`);
    ok("recover: exactly two stored codes are now consumed", rec !== undefined && rec.codes.filter((c) => c.consumed).length === 2);
    const recJson = JSON.stringify(rec);
    ok("recover: no plaintext code is ever persisted", codes.every((c) => !recJson.includes(c)));
  }
}

// ===========================================================================================
// 3. GENERIC FAILURE + HARD RATE LIMIT (no oracle, fail closed, per IP + per email).
// ===========================================================================================
async function testGenericFailureRateLimit(): Promise<void> {
  {
    const { env, storage, stub } = makeScheduler();
    const USER = "ratelimit@acme.example";
    await seedRole(storage, USER, "operator");
    await mintCodesFor(stub, USER);

    // A wrong code for a REAL email and a code for an UNKNOWN email both return the SAME generic 401 plaintext
    // (no "email not found" distinction, no oracle on which part failed).
    const wrong = await recoverViaRouter(env, USER, "ZZZZZ-ZZZZZ", "203.0.113.60");
    ok("ratelimit: a wrong code is a generic 401 'unauthorised'", wrong.status === 401 && wrong.body === "unauthorised");
    const unknownEmail = await recoverViaRouter(env, "nobody@acme.example", "ZZZZZ-ZZZZZ", "203.0.113.61");
    ok("ratelimit: an unknown email is the SAME generic 401 (no oracle)", unknownEmail.status === 401 && unknownEmail.body === "unauthorised");

    // HARD per-email rate limit: hammer one email from varied IPs; after the per-email cap (5/window) the
    // attempts are throttled (the DO fails closed). We already spent some; keep going until we see throttling.
    let sawThrottle = false;
    for (let i = 0; i < 12; i++) {
      const r = await recoverViaRouter(env, USER, "ZZZZZ-ZZZZZ", `198.51.100.${i}`);
      // A throttled attempt is still a 401 to the client (generic), but the DO's per-email bucket is now over
      // cap; we detect it by asserting it audited a denied (rate-limited) attempt below. Here we just drive.
      void r;
    }
    // The audit trail must show denied (rate-limited) recovery attempts: the per-email bucket tripped.
    const audits = [...(await storage.list<{ action?: string; outcome?: string }>({ prefix: "audit:" })).values()];
    const recoveryAttempts = audits.filter((e) => e.action === "recovery-code-used");
    ok("ratelimit: failed recovery attempts are audited", recoveryAttempts.some((e) => e.outcome === "failed"));
    sawThrottle = recoveryAttempts.some((e) => e.outcome === "denied");
    ok("ratelimit: the per-email hard limit trips (denied/rate-limited attempts audited)", sawThrottle);
    // The fail-closed deny also recorded the bounded recovery-ratelimited auth-signal for the support pack.
    const authSig = (await storage.get<Record<string, { count: number; lastAt: string }>>("authsignals:agg")) ?? {};
    ok("ratelimit: the deny recorded the recovery-ratelimited auth-signal (break-glass sign-in refused)", (authSig["recovery-ratelimited"]?.count ?? 0) > 0);

    // HARD per-IP rate limit: hammer ONE IP across MANY distinct emails (so the per-email bucket never
    // trips first), and assert the per-IP bucket trips and audits a denied attempt. This exercises the
    // per-IP path independently of the per-email path.
    const { env: ipEnv, storage: ipStorage } = makeScheduler();
    const HOT_IP = "198.51.100.200";
    let sawIpDeny = false;
    for (let i = 0; i < 40 && !sawIpDeny; i++) {
      await recoverViaRouter(ipEnv, `victim-${i}@acme.example`, "ZZZZZ-ZZZZZ", HOT_IP);
      const ipAudits = [...(await ipStorage.list<{ action?: string; outcome?: string }>({ prefix: "audit:" })).values()];
      sawIpDeny = ipAudits.some((e) => e.action === "recovery-code-used" && e.outcome === "denied");
    }
    ok("ratelimit: the per-IP hard limit trips when one IP hammers many emails (denied attempt audited)", sawIpDeny);

    // FAIL CLOSED: if the limiter's backing store is unavailable, the DO denies (never admits). We simulate by
    // driving the DO's recover route directly with a storage whose get throws on the rate key. Simplest proof:
    // a fresh DO whose storage.get throws denies the attempt.
    const throwingStorage = {
      get: async (k: string) => {
        if (k.startsWith("recovery-rate:")) throw new Error("store down");
        return undefined;
      },
      put: async () => {},
      delete: async () => false,
      list: async () => new Map(),
      setAlarm: async () => {},
    } as unknown as DurableObjectState["storage"];
    const failDo = new SchedulerDO({ storage: throwingStorage } as unknown as DurableObjectState);
    const failResp = await failDo.fetch(new Request("https://scheduler.internal/recovery/recover", { method: "POST", body: JSON.stringify({ email: USER, code: "ABCDE-FGHJK", ip: "203.0.113.99" }), headers: { "content-type": "application/json" } }));
    const failBody = (await failResp.json()) as { ok?: boolean };
    ok("ratelimit: the recover route FAILS CLOSED when the limiter store is unavailable", failBody.ok !== true);
  }
}

// ===========================================================================================
// 4. REGENERATE invalidates ALL prior codes for that email.
// ===========================================================================================
async function testRegenerate(): Promise<void> {
  {
    const { env, storage, stub } = makeScheduler();
    const USER = "regen@acme.example";
    await seedRole(storage, USER, "operator");
    const first = await mintCodesFor(stub, USER);
    // A first-set code works before regenerate.
    ok("regenerate: a first-set code recovers before regenerate", (await recoverViaRouter(env, USER, first[2]!, "203.0.113.70")).status === 200);
    // Regenerate: a brand-new set, and ALL prior codes are now invalid.
    const second = await mintCodesFor(stub, USER);
    ok("regenerate: a fresh set is minted", second.length === 10 && second.every((c) => !first.includes(c)));
    // A DIFFERENT first-set code (unused) now FAILS (the whole prior set was invalidated).
    const oldFails = await recoverViaRouter(env, USER, first[5]!, "203.0.113.71");
    ok("regenerate: a prior (unused) code now FAILS after regenerate", oldFails.status === 401);
    // A new-set code works.
    ok("regenerate: a new-set code recovers", (await recoverViaRouter(env, USER, second[0]!, "203.0.113.72")).status === 200);
    // Only the new set is stored (10 codes, the old hashes are gone).
    const rec = await storage.get<RecoveryRecord>(`recovery:${USER}`);
    ok("regenerate: the stored record is the new set only", rec !== undefined && rec.codes.length === 10);
  }
}

// ===========================================================================================
// 5. REMAINING COUNT + the recovery-codes-low posture finding.
// ===========================================================================================
async function testRemainingCountPosture(): Promise<void> {
  {
    const { storage, stub } = makeScheduler();
    const USER = "count@acme.example";
    await seedRole(storage, USER, "owner");
    await mintCodesFor(stub, USER);
    // GET /recovery/remaining for the user's own email reports 10, not low.
    const r10 = (await (await doFetch(stub, `/recovery/remaining?email=${encodeURIComponent(USER)}`, { method: "GET" })).json()) as { remaining: number; low: boolean };
    ok("count: a fresh set reports 10 remaining, not low", r10.remaining === 10 && r10.low === false);
    // Consume down to 2 by directly marking codes consumed, then the count is low.
    const rec = await storage.get<RecoveryRecord>(`recovery:${USER}`);
    for (let i = 0; i < 8; i++) rec!.codes[i]!.consumed = true;
    await storage.put(`recovery:${USER}`, rec);
    const r2 = (await (await doFetch(stub, `/recovery/remaining?email=${encodeURIComponent(USER)}`, { method: "GET" })).json()) as { remaining: number; low: boolean };
    ok("count: at 2 remaining the count reports low", r2.remaining === 2 && r2.low === true);

    // The posture report (computed in the DO, scoped to the caller email) raises recovery-codes-low.
    const postureResp = await doFetch(stub, "/posture", {
      method: "POST",
      body: JSON.stringify({ status: { destConfigured: true, breakGlassConfigured: true, tokenFallbackDisabled: true }, authMethod: "access", beaconEnabled: false, callerEmail: USER }),
      headers: { "content-type": "application/json" },
    });
    const { report } = (await postureResp.json()) as { report: { checks: { id: string; status: string }[] } };
    const low = report.checks.find((c) => c.id === "recovery-codes-low");
    ok("count: the posture recovery-codes-low finding FAILS at 2 remaining", low !== undefined && low.status === "fail");

    // CROSS-USER ISOLATION via posture: a DIFFERENT caller's posture does NOT carry this user's low state.
    // OTHER has a FULL set, so their own recovery-codes-low passes (their count, not USER's).
    const OTHER = "other-count@acme.example";
    await seedRole(storage, OTHER, "owner");
    await mintCodesFor(stub, OTHER);
    const otherPosture = await doFetch(stub, "/posture", {
      method: "POST",
      body: JSON.stringify({ status: { destConfigured: true, breakGlassConfigured: true, tokenFallbackDisabled: true }, authMethod: "access", beaconEnabled: false, callerEmail: OTHER }),
      headers: { "content-type": "application/json" },
    });
    const otherReport = (await otherPosture.json()) as { report: { checks: { id: string; status: string }[] } };
    const otherLow = otherReport.report.checks.find((c) => c.id === "recovery-codes-low");
    ok("count: another user's posture reads THEIR own count (low passes for the full-set user)", otherLow !== undefined && otherLow.status === "pass");
  }
}

// ===========================================================================================
// 6. CROSS-USER ISOLATION: one user cannot see or consume another user's codes.
// ===========================================================================================
async function testCrossUserIsolation(): Promise<void> {
  {
    const { env, storage, stub } = makeScheduler();
    const ALICE = "alice@acme.example";
    const BOB = "bob@acme.example";
    await seedRole(storage, ALICE, "owner");
    await seedRole(storage, BOB, "operator");
    const aliceCodes = await mintCodesFor(stub, ALICE);
    await mintCodesFor(stub, BOB);

    // Alice's code does NOT recover BOB's account (the code is checked against BOB's record only).
    const wrongAccount = await recoverViaRouter(env, BOB, aliceCodes[0]!, "203.0.113.80");
    ok("isolation: one user's code cannot recover ANOTHER user's account", wrongAccount.status === 401);
    // And Alice's code is NOT consumed by that failed attempt against Bob (it is still valid for Alice).
    const aliceStillWorks = await recoverViaRouter(env, ALICE, aliceCodes[0]!, "203.0.113.81");
    ok("isolation: the cross-account attempt did NOT consume the real owner's code", aliceStillWorks.status === 200 && recoveryBody(aliceStillWorks)?.role === "owner");
    // The remaining count is per-email: reading ALICE's count never reveals BOB's, and vice versa.
    const aliceRemaining = (await (await doFetch(stub, `/recovery/remaining?email=${encodeURIComponent(ALICE)}`, { method: "GET" })).json()) as { remaining: number };
    const bobRemaining = (await (await doFetch(stub, `/recovery/remaining?email=${encodeURIComponent(BOB)}`, { method: "GET" })).json()) as { remaining: number };
    ok("isolation: per-email counts are independent (Alice spent one, Bob spent none)", aliceRemaining.remaining === 9 && bobRemaining.remaining === 10);
  }
}

// ===========================================================================================
// 7. THE DISPOSE-GATE: retire the bootstrap token is REFUSED until break-glass exists, ALLOWED after.
// ===========================================================================================
// disposeSubjectOf builds the stable subject the dispose-gate cases seed/authorise an Access Owner on.
function disposeSubjectOf(email: string): string {
  return `https://${TEAM}|sub-of-${email}`;
}

// Case A: a SOLE Owner with NO recovery codes cannot retire (would strand); generating ACCESS-bound
// codes still does NOT unlock it (those recover to viewer, not Owner, in the passkey namespace).
async function testDisposeGateAccessOwner(): Promise<void> {
  {
    const { storage, stub } = makeScheduler();
    const SOLE = "sole-owner@acme.example";
    await seedRole(storage, SOLE, "owner");
    // The DO RE-RESOLVES the caller's role from its own seeded role table (the header role is only a hint that
    // must be a valid Role), so encodeCaller with role "owner" + the seeded owner row authenticates as Owner.
    // The caller carries its STABLE subject (the key authorisation uses); the seeded legacy email row binds
    // to that subject on the caller's first resolved request (bind-on-first-auth).
    const ownerCaller = (email: string): Caller => ({ method: "access", email, subject: disposeSubjectOf(email), role: "owner", groups: [] });
    const ownerHeader = (email: string): Record<string, string> => ({ "content-type": "application/json", "x-downpipe-caller": encodeCaller(ownerCaller(email)) });

    // REFUSED: sole Owner, no codes -> the retire route returns a non-2xx with a clear reason.
    const refused = await doFetch(stub, "/policy/break-glass-retired", { method: "POST", body: JSON.stringify({ retired: true }), headers: ownerHeader(SOLE) });
    ok("dispose-gate: a sole Owner with no recovery codes is REFUSED the retire (would strand)", refused.status !== 200);
    const refusedBody = (await refused.json()) as { error?: string };
    ok("dispose-gate: the refusal explains a way back in must exist first", typeof refusedBody.error === "string" && /way back in|recovery codes|second Owner/i.test(refusedBody.error));
    // The flag stays NOT retired.
    const stillLive = (await (await doFetch(stub, "/policy/break-glass-retired", { method: "GET" })).json()) as { breakGlassTokenRetired: boolean };
    ok("dispose-gate: the token stays live after the refused retire", stillLive.breakGlassTokenRetired === false);

    // The ACCESS-bound Owner generates recovery codes. This must NOT unlock the retire:
    // recoveryRecover resolves the recovered session via the PASSKEY subject namespace, so an
    // Access-bound Owner's codes would recover to viewer; honouring them here would let the
    // token be retired with no path back to Owner (the stranding the gate exists to prevent).
    await mintCodesFor(stub, SOLE);
    const stillRefused = await doFetch(stub, "/policy/break-glass-retired", { method: "POST", body: JSON.stringify({ retired: true }), headers: ownerHeader(SOLE) });
    ok("dispose-gate: codes for an ACCESS-bound Owner do NOT unlock the retire (would recover to viewer)", stillRefused.status !== 200);
    const stillRefusedBody = (await stillRefused.json()) as { error?: string };
    ok("dispose-gate: the refusal names the passkey precondition", typeof stillRefusedBody.error === "string" && /passkey/i.test(stillRefusedBody.error));
  }
}

// Case A2 + Case B: a PASSKEY-BOUND Owner's codes ARE the real way back in (recovery restores Owner),
// so generating them unlocks the retire; and a SECOND Owner is the OTHER acceptable break-glass.
async function testDisposeGatePasskeyAndSecondOwner(): Promise<void> {
  {
    // Case A2: a PASSKEY-BOUND Owner's codes are the real way back in (recovery restores Owner
    // in that namespace), so generating them unlocks the retire.
    const pk = makeScheduler();
    const PK_OWNER = "pk-owner@acme.example";
    await pk.storage.put(`role:sub:${passkeySubject(PK_OWNER)}`, { subject: passkeySubject(PK_OWNER), email: PK_OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
    const pkCaller: Caller = { method: "passkey", email: PK_OWNER, subject: passkeySubject(PK_OWNER), role: "owner", groups: [] };
    const pkHeader = { "content-type": "application/json", "x-downpipe-caller": encodeCaller(pkCaller) };
    const pkRefused = await doFetch(pk.stub, "/policy/break-glass-retired", { method: "POST", body: JSON.stringify({ retired: true }), headers: pkHeader });
    ok("dispose-gate: a sole passkey-bound Owner with no codes is still refused", pkRefused.status !== 200);
    await mintCodesFor(pk.stub, PK_OWNER);
    const allowed = await doFetch(pk.stub, "/policy/break-glass-retired", { method: "POST", body: JSON.stringify({ retired: true }), headers: pkHeader });
    ok("dispose-gate: ALLOWED once recovery codes are generated for a PASSKEY-bound Owner (200)", allowed.status === 200 && ((await allowed.json()) as { breakGlassTokenRetired?: boolean }).breakGlassTokenRetired === true);

    // Case B: a SECOND Owner is the OTHER acceptable break-glass. Fresh tenant, two Owners, no codes -> retire
    // is allowed.
    const b = makeScheduler();
    await seedRole(b.storage, "owner-a@acme.example", "owner");
    await seedRole(b.storage, "owner-b@acme.example", "owner");
    const twoOwnerRetire = await doFetch(b.stub, "/policy/break-glass-retired", { method: "POST", body: JSON.stringify({ retired: true }), headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller({ method: "access", email: "owner-a@acme.example", subject: disposeSubjectOf("owner-a@acme.example"), role: "owner", groups: [] }) } });
    ok("dispose-gate: a SECOND Owner is also an acceptable way back in (retire allowed)", twoOwnerRetire.status === 200);
  }
}

// ===========================================================================================
// 8. AUDIT + ALERT: a successful recovery is audited AND returns the used alert signal; repeated
//    failures return the abuse signal (so the router would fire the alerter).
// ===========================================================================================
async function testAuditAndAlert(): Promise<void> {
  {
    const { storage, stub } = makeScheduler();
    const USER = "audit-alert@acme.example";
    await seedRole(storage, USER, "owner");
    const codes = await mintCodesFor(stub, USER);

    // Drive the DO recover route DIRECTLY so we can read the alert signal it returns to the router.
    const okResp = await doFetch(stub, "/recovery/recover", { method: "POST", body: JSON.stringify({ email: USER, code: codes[0]!, ip: "203.0.113.90" }), headers: { "content-type": "application/json" } });
    const recoverBody = (await okResp.json()) as { ok?: boolean; enrolPasskey?: boolean; alert?: string };
    ok("audit-alert: a successful recovery returns ok + the enrol-passkey prompt", recoverBody.ok === true && recoverBody.enrolPasskey === true);

    const failResp = await doFetch(stub, "/recovery/recover", { method: "POST", body: JSON.stringify({ email: USER, code: "ZZZZZ-ZZZZZ", ip: "203.0.113.91" }), headers: { "content-type": "application/json" } });
    const failBody = (await failResp.json()) as { ok?: boolean; alert?: string };
    ok("audit-alert: a failed recovery signals recovery-code-abuse (the router fires the alert)", failBody.ok !== true && failBody.alert === "recovery-code-abuse");

    // The audit trail holds BOTH a success and a failure recovery-code-used event (who+when+outcome, no code).
    const audits = [...(await storage.list<{ action?: string; outcome?: string; actorEmail?: string; target?: { kind?: string } }>({ prefix: "audit:" })).values()];
    const recUsed = audits.filter((e) => e.action === "recovery-code-used");
    ok("audit-alert: the successful recovery is audited", recUsed.some((e) => e.outcome === "success" && e.actorEmail === USER));
    ok("audit-alert: the failed recovery is audited", recUsed.some((e) => e.outcome === "failed"));
    ok("audit-alert: the recovery audit target is the redaction-safe access-policy kind (no code)", recUsed.every((e) => e.target?.kind === "access-policy"));
    // recovery-codes-used / -abuse are valid NotifyEvents the router can route (proven by the severity map in
    // notify.ts); here we assert the DO produced the signal the router consumes.
    ok("audit-alert: the success path produced no abuse signal (only -used is routed on success)", recoverBody.alert === undefined);
  }
}

// ===========================================================================================
// 9. AUTH-29: the recovery-code HMAC key must be SEPARATE from the in-DO session signing key, so that
//    terminateAllSessions (which deletes the session key) does not also destroy every banked recovery code.
//    The keys are two records (RECOVERY_SIGNING_KEY_KEY, adopted from the session key on first use so no
//    banked code is ever re-hashed). This asserts BOTH directions of the fix, because a test that only
//    checked the code still verified could be satisfied by simply not deleting the key, which would
//    silently break the sign-out:
//      (a) terminate-all still does its real job: the session key is gone and a session minted before it no
//          longer verifies.
//      (b) a banked, unconsumed recovery code STILL verifies afterwards.
//    Both must hold. Either one alone is a passing test for a broken engine.
// ===========================================================================================
async function testTerminateAllPreservesRecoveryCodes(): Promise<void> {
  {
    const { env, storage, stub } = makeScheduler();
    const OWNER = "term-all-owner@acme.example";
    // Seed BOTH the legacy email row (recovery role resolution) AND the passkey-subject row (the owner-guard
    // terminateAllSessions re-resolves), so the passkey owner caller authorises for terminate-all.
    await seedRole(storage, OWNER, "owner");
    await storage.put(`role:sub:${passkeySubject(OWNER)}`, { subject: passkeySubject(OWNER), email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
    const codes = await mintCodesFor(stub, OWNER);
    ok("AUTH-29: setup minted a recovery set", codes.length === 10);
    // BASELINE: a code recovers BEFORE terminate-all, and the session it mints verifies.
    const before = await recoverViaRouter(env, OWNER, codes[0]!, "203.0.113.120");
    ok("AUTH-29: a recovery code verifies BEFORE terminate-all", before.status === 200);
    const sessionBefore = /(?:^|;\s*)__Host-downpipes_session=([^;]+)/.exec(before.setCookie ?? "")?.[1] ?? "";
    ok("AUTH-29: the pre-terminate-all recovery minted a session cookie", sessionBefore.length > 0);
    ok("AUTH-29: the session signing key is persisted before terminate-all", (await storage.get("passkeySessionKey")) !== undefined);
    // Drive the REAL terminate-all route (owner caller): it DELETES the session signing key.
    const caller: Caller = { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), role: "owner", groups: [] };
    const term = await doFetch(stub, "/passkey/session/terminate-all", { method: "POST", headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(caller) } });
    ok("AUTH-29: terminate-all succeeds for the owner", term.status === 200 && ((await term.json()) as { ok?: boolean }).ok === true);
    // (a) THE SIGN-OUT STILL HAPPENS. Both halves: the key record is gone, and a token minted under it is dead.
    ok("AUTH-29: terminate-all DELETED the session signing key", (await storage.get("passkeySessionKey")) === undefined);
    const verifyOld = await doFetch(stub, "/passkey/session/verify", { method: "POST", body: JSON.stringify({ token: sessionBefore }), headers: { "content-type": "application/json" } });
    ok("AUTH-29: a session minted BEFORE terminate-all no longer verifies (the sign-out is real)", ((await verifyOld.json()) as { email?: string | null }).email == null);
    // The stored recovery RECORD is untouched (the codes were never explicitly regenerated).
    const rec = await storage.get<RecoveryRecord>(`recovery:${OWNER}`);
    ok("AUTH-29: the recovery record still holds its hashes", rec !== undefined && rec.codes.length === 10);
    // (b) THE BREAK-GLASS SURVIVES. The recovery key was materialised by adoption BEFORE the session key was
    // deleted, so this hash - minted under the pre-terminate-all bytes - still recomputes to a match.
    ok("AUTH-29: the recovery HMAC key is materialised and separate from the session key", (await storage.get("recoverySigningKey")) !== undefined);
    const after = await recoverViaRouter(env, OWNER, codes[5]!, "203.0.113.121");
    ok("AUTH-29 (THE FIX): a banked unconsumed recovery code STILL verifies after terminate-all", after.status === 200);
    // And single-use is unaffected: the code just consumed cannot be replayed.
    ok("AUTH-29: the code consumed after terminate-all is still single-use", (await recoverViaRouter(env, OWNER, codes[5]!, "203.0.113.122")).status === 401);
  }
}

// ===========================================================================================
// 9b. THE MIGRATION'S OWN FAILURE MODES, driven rather than reasoned. Each case is one way the
//     adopt-from-the-session-key migration could leave an account WORSE off than the defect it replaces,
//     which is the bar an unrecoverable-lockout fix has to clear.
// ===========================================================================================
async function testRecoveryKeyMigrationEdges(): Promise<void> {
  // (i) MID-MIGRATION: an account whose codes were minted under the SHARED key, before the recovery key
  // record existed. This is every existing account, so it is the case the migration is for. The record is
  // adopted lazily on the next recovery operation and the banked codes keep verifying with no rewrite.
  {
    const { env, storage, stub } = makeScheduler();
    const OWNER = "pre-split@acme.example";
    await seedRole(storage, OWNER, "owner");
    const codes = await mintCodesFor(stub, OWNER);
    // Reproduce the PRE-SPLIT storage byte for byte: the hashes were minted under bytes X, the SESSION key
    // record holds X (they were one key), and there is no recovery key record at all. Copying the minting key
    // into the session key record and then removing the recovery record is exactly that state, and it is the
    // state every existing account is in on the deploy that lands this.
    const minted = await storage.get<{ key: string; createdAt: string }>("recoverySigningKey");
    await storage.put("passkeySessionKey", { key: minted!.key, createdAt: minted!.createdAt });
    await storage.delete("recoverySigningKey");
    ok("migration: the pre-split state has no recovery key record", (await storage.get("recoverySigningKey")) === undefined);
    ok("migration: a pre-split banked code still verifies (adoption re-hashes nothing)", (await recoverViaRouter(env, OWNER, codes[0]!, "203.0.113.130")).status === 200);
    const adopted = (await storage.get<{ key?: string; adoptedFromSessionKey?: boolean }>("recoverySigningKey")) ?? {};
    const session = (await storage.get<{ key?: string }>("passkeySessionKey")) ?? {};
    ok("migration: the adopted recovery key is the session key's bytes, flagged as adopted", adopted.key === session.key && adopted.adoptedFromSessionKey === true);
  }
  // (ii) RUN TWICE / RUN MANY TIMES: the accessor is idempotent. A present record is NEVER rewritten, so the
  // second (or the twentieth) terminate-all cannot rotate the recovery key out from under the stored hashes.
  // Driven through repeated terminate-all because that is the real double-run: each one re-enters the
  // materialisation path against a session key that has since been regenerated.
  {
    const { env, storage, stub } = makeScheduler();
    const OWNER = "twice@acme.example";
    await seedRole(storage, OWNER, "owner");
    await storage.put(`role:sub:${passkeySubject(OWNER)}`, { subject: passkeySubject(OWNER), email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
    const codes = await mintCodesFor(stub, OWNER);
    const first = (await storage.get<{ key?: string }>("recoverySigningKey"))?.key;
    const caller: Caller = { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), role: "owner", groups: [] };
    for (let i = 0; i < 3; i++) {
      const t = await doFetch(stub, "/passkey/session/terminate-all", { method: "POST", headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(caller) } });
      ok(`migration: terminate-all run ${i + 1} succeeds`, t.status === 200);
      await doFetch(stub, "/passkey/session/issue", { method: "POST", body: JSON.stringify({ email: OWNER }), headers: { "content-type": "application/json" } }); // a fresh session key exists again
    }
    ok("migration: repeated terminate-all leaves the recovery key byte-identical", (await storage.get<{ key?: string }>("recoverySigningKey"))?.key === first);
    ok("migration: the banked code still verifies after three terminate-alls", (await recoverViaRouter(env, OWNER, codes[0]!, "203.0.113.150")).status === 200);
  }
  // (iii) ZERO-CODE ACCOUNT: an account that never minted a set. Materialisation must be a no-op that cannot
  // fault the sign-out, and terminate-all must still work.
  {
    const { storage, stub } = makeScheduler();
    const OWNER = "no-codes@acme.example";
    await seedRole(storage, OWNER, "owner");
    await storage.put(`role:sub:${passkeySubject(OWNER)}`, { subject: passkeySubject(OWNER), email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
    const caller: Caller = { method: "passkey", email: OWNER, subject: passkeySubject(OWNER), role: "owner", groups: [] };
    const term = await doFetch(stub, "/passkey/session/terminate-all", { method: "POST", headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(caller) } });
    ok("migration: terminate-all on a zero-code account still succeeds", term.status === 200);
    ok("migration: a zero-code account has no recovery record to protect", (await storage.get(`recovery:${OWNER}`)) === undefined);
  }
  // (iv) THE ORDERING. This is the property that makes the migration safe, so it is asserted structurally as
  // well as behaviourally: terminate-all materialises the recovery key BEFORE it deletes the session key. If
  // the two were reversed, the adoption would copy a key freshly generated by sessionSigningKey() and every
  // banked code would die - the defect, reintroduced by its own fix. An interruption between the two lines can
  // therefore only mean the sign-out did not happen, never that a factor was lost.
  {
    const src = await readFile(new URL("../src/sched/scheduler-do-session.ts", import.meta.url), "utf8");
    const materialise = src.indexOf("await this.recoverySigningKey();");
    const del = src.indexOf("await this.state.storage.delete(PASSKEY_SESSION_KEY_KEY);");
    ok("migration: terminateAllSessions materialises the recovery key BEFORE deleting the session key", materialise > 0 && del > 0 && materialise < del);
    // And the adoption must read the session key record DIRECTLY. Going through sessionSigningKey() would
    // GENERATE one on an absent/corrupt record and freeze a key no stored hash was ever computed under.
    const rec = await readFile(new URL("../src/sched/scheduler-do-recovery.ts", import.meta.url), "utf8");
    const accessor = rec.slice(rec.indexOf("async recoverySigningKey()"), rec.indexOf("async recoverySigningKeyHealth()"));
    ok("migration: the adoption reads PASSKEY_SESSION_KEY_KEY from storage, never through sessionSigningKey()", accessor.includes("PASSKEY_SESSION_KEY_KEY") && !accessor.includes("this.sessionSigningKey("));
  }
  // (v) ALREADY-TERMINATED ACCOUNT (the pre-fix casualty): no session key AND orphaned hashes. No key anywhere
  // can revive those codes, so the honest outcome is a fresh recovery key and a refusal - never a crash, and
  // never a silent success. The account must still be able to mint a NEW set that then works.
  {
    const { env, storage, stub } = makeScheduler();
    const OWNER = "already-burnt@acme.example";
    await seedRole(storage, OWNER, "owner");
    const dead = await mintCodesFor(stub, OWNER);
    await storage.delete("recoverySigningKey");
    await storage.delete("passkeySessionKey"); // the pre-fix terminate-all, faithfully reproduced
    ok("migration: an already-terminated account refuses its orphaned codes (never a 500)", (await recoverViaRouter(env, OWNER, dead[0]!, "203.0.113.160")).status === 401);
    ok("migration: it generated a fresh recovery key rather than faulting", (await storage.get("recoverySigningKey")) !== undefined);
    const fresh = await mintCodesFor(stub, OWNER);
    ok("migration: the account can mint a NEW set that verifies", fresh.length === 10 && (await recoverViaRouter(env, OWNER, fresh[0]!, "203.0.113.161")).status === 200);
  }
  // (vi) CAN ANY ORDERING LEAVE NEITHER A WORKING SESSION KEY NOR WORKING CODES? Only if the recovery key
  // record were itself corrupt at the moment of adoption. A corrupt/short record is treated as ABSENT (the
  // decode guard), so it is replaced rather than used - which loses nothing that was not already lost, and
  // never leaves the recovery path throwing 500s at a locked-out Owner.
  {
    const { env, storage, stub } = makeScheduler();
    const OWNER = "corrupt-key@acme.example";
    await seedRole(storage, OWNER, "owner");
    await mintCodesFor(stub, OWNER);
    await storage.put("recoverySigningKey", { key: "!!!!not-base64url!!!!", createdAt: "x" });
    ok("migration: a corrupt recovery key record refuses generically, never a 500", (await recoverViaRouter(env, OWNER, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "203.0.113.170")).status === 401);
    const replaced = await storage.get<{ key?: string }>("recoverySigningKey");
    ok("migration: the corrupt record was replaced with a usable key", typeof replaced?.key === "string" && replaced.key !== "!!!!not-base64url!!!!");
    const fresh = await mintCodesFor(stub, OWNER);
    ok("migration: a set minted after the repair verifies", (await recoverViaRouter(env, OWNER, fresh[0]!, "203.0.113.171")).status === 200);
  }
}

// ===========================================================================================
// 10. AUTH-36: regenerate vs first-enrolment SESSION-EPOCH differential. recoveryRegenerate rotates a
//     sign-in factor, so it BUMPS the session epoch (V7.4.3) - a session minted before it is signed out.
//     A FIRST enrolment (the generateRecoveryFor hook) does NOT bump, so initial setup never signs the
//     operator out (scheduler-do-recovery.ts:101-105). The existing testRegenerate proves the CODES die;
//     this proves the SESSION-epoch side, driving the DO methods directly to isolate the two paths.
// ===========================================================================================
async function testRegenerateBumpsSessionEpoch(): Promise<void> {
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);

    // FIRST ENROLMENT (generateRecoveryFor): mints codes WITHOUT bumping the session epoch.
    const ENROL = "first-enrol@acme.example";
    ok("AUTH-36: the enrolment email starts at session epoch 0", (await dobj.getSessionEpoch(ENROL)) === 0);
    await dobj.generateRecoveryFor(ENROL, "passkey");
    ok("AUTH-36: a FIRST enrolment (generateRecoveryFor) does NOT bump the session epoch (still 0)", (await dobj.getSessionEpoch(ENROL)) === 0);

    // EXPLICIT REGENERATE (recoveryRegenerate): rotates the factor, so it DOES bump the epoch, signing out
    // sessions minted before the rotation.
    const REGEN = "explicit-regen@acme.example";
    ok("AUTH-36: the regenerate email starts at session epoch 0", (await dobj.getSessionEpoch(REGEN)) === 0);
    const issued = await dobj.passkeySessionIssue({ email: REGEN });
    const tok = issued.ok ? issued.token : "";
    ok("AUTH-36: a session is minted at the pre-regenerate epoch and verifies", issued.ok === true && (await dobj.passkeySessionVerify({ token: tok })).email === REGEN);
    const regen = await dobj.recoveryRegenerate({ email: REGEN });
    ok("AUTH-36: recoveryRegenerate succeeds", regen.ok === true);
    ok("AUTH-36: an explicit regenerate BUMPS the session epoch (0 -> 1)", (await dobj.getSessionEpoch(REGEN)) === 1);
    // The session minted BEFORE the regenerate is now invalid (stale epoch) - signed out (V7.4.3).
    ok("AUTH-36: a session minted BEFORE regenerate is now invalid (email:null, stale epoch)", (await dobj.passkeySessionVerify({ token: tok })).email === null);
    // A session minted AFTER the bump carries the new epoch and still authorises (a targeted sign-out, not a
    // global key rotation).
    const issued2 = await dobj.passkeySessionIssue({ email: REGEN });
    ok("AUTH-36: a session minted AFTER regenerate (new epoch) still authorises", issued2.ok === true && (await dobj.passkeySessionVerify({ token: issued2.ok ? issued2.token : "" })).email === REGEN);
  }
}

// ===========================================================================================
// 11. The anti-enumeration dummy path must cost the SAME crypto work as the real-record path, not
//     double it. We spy on crypto.subtle.sign/importKey (the two WebCrypto primitives hashOf/hmacKey call)
//     to literally COUNT HMAC operations rather than infer them from wall-clock, then compare a known email
//     (wrong code) against a totally unknown email (dummy path) end to end through the real router.
// ===========================================================================================
async function testDummyRecordCostSymmetry(): Promise<void> {
  {
    const realSign = crypto.subtle.sign.bind(crypto.subtle);
    const realImportKey = crypto.subtle.importKey.bind(crypto.subtle);
    let signCount = 0;
    let importCount = 0;
    crypto.subtle.sign = (async (...args: Parameters<typeof crypto.subtle.sign>) => {
      signCount++;
      return realSign(...args);
    }) as typeof crypto.subtle.sign;
    crypto.subtle.importKey = (async (...args: Parameters<typeof crypto.subtle.importKey>) => {
      importCount++;
      return realImportKey(...args);
    }) as typeof crypto.subtle.importKey;
    try {
      // Building the dummy record ALONE must do ZERO signs/imports: it is pure CSPRNG bytes shaped like a
      // real slot, never a freshly-hashed set (dummyRecoveryRecord must never mint via generateRecoveryCodes
      // -- a full extra RECOVERY_CODE_COUNT-op HMAC pass -- before verifyCode even runs).
      const soloStorage = new MockStorage();
      const soloDo = new SchedulerDO({ storage: soloStorage } as unknown as DurableObjectState);
      const dummy = await soloDo.dummyRecoveryRecord();
      ok("dummyRecoveryRecord alone performs ZERO HMAC signs", signCount === 0);
      ok("dummyRecoveryRecord alone performs ZERO key imports", importCount === 0);
      ok("dummyRecoveryRecord still returns the standard size", dummy.codes.length === RECOVERY_CODE_COUNT);

      // END-TO-END SYMMETRY: a wrong code against a KNOWN, fully-populated record (real path) and the same
      // wrong code against a totally UNKNOWN email (dummy path) must cost the IDENTICAL number of
      // signs/imports, driven through the real router.
      const { env, storage, stub } = makeScheduler();
      const KNOWN = "known-cost@acme.example";
      await seedRole(storage, KNOWN, "operator");
      await mintCodesFor(stub, KNOWN);

      signCount = 0;
      importCount = 0;
      await recoverViaRouter(env, KNOWN, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "203.0.113.201");
      const knownSigns = signCount;
      const knownImports = importCount;

      signCount = 0;
      importCount = 0;
      await recoverViaRouter(env, "totally-unknown@acme.example", "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "203.0.113.202");
      const unknownSigns = signCount;
      const unknownImports = importCount;

      ok("a known email and an unknown email perform the SAME number of HMAC signs (no 2x oracle)", knownSigns > 0 && knownSigns === unknownSigns);
      ok("a known email and an unknown email perform the SAME number of key imports", knownImports > 0 && knownImports === unknownImports);
      ok("the count is exactly RECOVERY_CODE_COUNT (verifyCode's own loop only, nothing extra)", knownSigns === RECOVERY_CODE_COUNT);
    } finally {
      crypto.subtle.sign = realSign;
      crypto.subtle.importKey = realImportKey;
    }
  }
}

// main runs the scenarios in order; each is a named function so a single scenario can be run in
// isolation and a failure anywhere is still attributed to its section.
async function main(): Promise<void> {
  console.log("validate-recovery-codes: the recovery-code admin break-glass, driving the real DO + router");
  await testPureCore();
  await testRecoverViaRouter();
  await testGenericFailureRateLimit();
  await testRegenerate();
  await testRemainingCountPosture();
  await testCrossUserIsolation();
  await testDisposeGateAccessOwner();
  await testDisposeGatePasskeyAndSecondOwner();
  await testAuditAndAlert();
  await testTerminateAllPreservesRecoveryCodes();
  await testRecoveryKeyMigrationEdges();
  await testRegenerateBumpsSessionEpoch();
  await testDummyRecordCostSymmetry();
  console.log(failures === 0 ? "\nRECOVERY-CODE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
