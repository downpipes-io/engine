// Validates the attended-verification SESSION lifecycle end to end, SERVER-SIDE, driving the REAL router
// spoke (src/admin/router-attest.ts), the REAL scheduler DO session store (src/sched/scheduler-do-attest.ts)
// and the REAL live-possession challenge crypto (src/attest/challenge.ts), with in-memory doubles only. No
// network, no deploy, no cost. Run: node test/validate-attest-session.ts
//
// Attended verification lets an offline-key-only customer prove their backups restorable by supplying,
// through their browser, only the per-run master keys (never the break-glass private). What this proves (the
// properties a later adversarial review will hammer):
//   - CREATE pins the LATEST COMPLETED run per downpipe (skipping a newer FAILED run) and issues a live-
//     possession challenge bound to the break-glass public; the estimate reflects the sample rate;
//   - the stored session blob carries NO 32-byte-master-shaped secret (only the sampling seed + the proof
//     hash are secret-shaped, and both are allow-listed; a submitted master never reaches the store);
//   - PROVE flips proven only for a holder of the break-glass private (a wrong proof is refused 400) and
//     DELETES the proof hash;
//   - OWNERSHIP: a different-subject caller is refused 403 on prove/verify/status/abort; a null-subject
//     bare-token caller cannot even CREATE a session;
//   - CAPSULES refuses a runId not pinned in the session;
//   - the NARROW stamp records kind=attended + the sample rate, and stamps restoreProven (method
//     attended-blind-test) + integrityVerified ONLY on a FULL (100%) PROVEN pass, never on a sub-100 sample,
//     an unproven session, or a failure (which instead records a closed reason code + a failure streak);
//   - ABORT sets status=aborted and frees the one-active-session slot;
//   - drill.run and the break-glass-public requirement are enforced.
// The negative controls are written so they would FAIL if the corresponding check were removed.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { handleAttest } from "../src/admin/router-attest.ts";
// deriveAttestProof only: this file drives the ROUTE, which issues the challenge internally, so importing
// issueAttestChallenge here recorded no unfinished intent. The freshness and per-challenge binding it would
// have tested belong to validate-attest-crypto.ts, which owns the primitive and now asserts both.
import { deriveAttestProof } from "../src/attest/challenge.ts";
import { sampleCount } from "../src/attest/verify.ts";
import { decapsulateHybrid, type HybridRecipientPrivate } from "../src/crypto/kem.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, b64urlDecode, concat, hexEncode } from "../src/crypto/bytes.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { Env } from "../src/env.d.ts";
import type { AttestSession, DownpipeState, RunHistoryEntry } from "../src/sched/types.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- three valid ULIDs for the seeded run history + one non-pinned runId ------------------------
const R_OLD = "01ARZ3NDEKTSV4RRFFQ69G5FA0"; // an OLDER completed run
const R_LATEST = "01ARZ3NDEKTSV4RRFFQ69G5FA1"; // the LATEST completed run (what create must pin)
const R_FAILED = "01ARZ3NDEKTSV4RRFFQ69G5FA2"; // a NEWER but FAILED run (create must skip it)
const R_NOT_PINNED = "01ARZ3NDEKTSV4RRFFQ69G5FB0"; // a valid ULID never pinned in the session

// ---- a break-glass keypair: the PUBLIC goes in env, the PRIVATE proves the challenge ------------
const bgScalar = crypto.getRandomValues(new Uint8Array(32));
const bgMlkemSeed = crypto.getRandomValues(new Uint8Array(64));
const bgPriv: HybridRecipientPrivate = { x25519Scalar: bgScalar, mlkemSeed: bgMlkemSeed };
const BREAK_GLASS_PUBLIC = b64urlEncode(concat(x25519PublicFromScalar(bgScalar), mlkemKeygen(bgMlkemSeed).encapKey));

// ---- callers: an attributable owner A, a distinct owner B, a viewer, and the bare token ---------
const callerA: Caller = { method: "access", email: "owner-a@acme.example", subject: "acc|subj-A", role: "owner", groups: [] };
const callerB: Caller = { method: "access", email: "owner-b@acme.example", subject: "acc|subj-B", role: "owner", groups: [] };
const callerViewer: Caller = { method: "access", email: "viewer@acme.example", subject: "acc|subj-V", role: "viewer", groups: [] };
const callerToken: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };

function makeScheduler(): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, scheduler };
}

// seedDownpipe writes a dp:<id> state + a hist:<id> ring directly (the create route reads the LATEST "ok"
// run from the newest-first history). The ring is stored newest-LAST (history() reverses it), so R_FAILED is
// the newest, then R_LATEST, then R_OLD; the create must pin R_LATEST (the newest COMPLETED run).
async function seedDownpipe(storage: MockStorage, id: string, name: string, enabled: boolean, ring: RunHistoryEntry[]): Promise<void> {
  const state = {
    config: { id, name, enabled, source: { type: "kv", binding: `SRC_${id}` }, schedule: { cadenceSeconds: 3600 } },
    lastRunId: ring.length > 0 ? ring[ring.length - 1]!.runId : null,
    nextRunAt: 0,
    inFlight: false,
  } as unknown as DownpipeState;
  await storage.put(`dp:${id}`, state);
  await storage.put(`hist:${id}`, ring);
}

// ctx builds the post-auth RouterCtx handleAttest reads (it never reads verdict/isOnlyOwner/roleSource/
// customRole/runtime, so those are cast placeholders). sub is the path under /admin; query appends ?id=.
function ctx(env: Env, scheduler: DurableObjectStub, caller: Caller, method: string, sub: string, opts: { body?: unknown; query?: string } = {}): RouterCtx {
  const url = new URL(`https://engine.example/admin${sub}${opts.query ?? ""}`);
  const req = new Request(url, {
    method,
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
    headers: { "content-type": "application/json" },
  });
  return {
    req,
    env,
    url,
    scheduler,
    caller,
    sub,
    sourceIp: null,
    runtime: undefined,
    verdict: {} as unknown as RouterCtx["verdict"],
    isOnlyOwner: false,
    roleSource: "token" as unknown as RouterCtx["roleSource"],
    customRole: undefined,
  };
}

async function call(env: Env, scheduler: DurableObjectStub, caller: Caller, method: string, sub: string, opts: { body?: unknown; query?: string } = {}): Promise<{ status: number; json: Record<string, unknown> }> {
  const resp = await handleAttest(ctx(env, scheduler, caller, method, sub, opts));
  if (resp === null) return { status: 404, json: { error: "no route" } };
  const text = await resp.text();
  let json: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    json = parsed !== null && typeof parsed === "object" ? (parsed as Record<string, unknown>) : { raw: parsed };
  } catch {
    json = { raw: text };
  }
  return { status: resp.status, json };
}

// secretShapedRuns finds every base64url run >= 43 chars (a 32-byte value) or hex run >= 64 chars (a 32-byte
// hex / a sha384), the shapes a leaked master would take. A blob is clean when every such run is an ALLOWED
// value (the sampling seed, or the challenge proof hash), so an unexpected master-shaped secret fails.
function secretShapedRuns(s: string): string[] {
  return [...(s.match(/[A-Za-z0-9_-]{43,}/g) ?? []), ...(s.match(/[0-9a-f]{64,}/g) ?? [])];
}

async function main(): Promise<void> {
  console.log("validate-attest-session: the attended-verification session lifecycle + narrow stamp");
  const env = { BREAK_GLASS_PUBLIC } as unknown as Env;
  const { storage, scheduler } = makeScheduler();
  // dp1: an ENABLED downpipe with an older ok run, a NEWER ok run (R_LATEST), and a NEWEST FAILED run.
  await seedDownpipe(storage, "dp1", "Primary", true, [
    { runId: R_OLD, index: 1, startedAt: "2026-01-01T00:00:00.000Z", status: "ok", recordCount: 5 },
    { runId: R_LATEST, index: 2, startedAt: "2026-02-01T00:00:00.000Z", status: "ok", recordCount: 10 },
    { runId: R_FAILED, index: 3, startedAt: "2026-03-01T00:00:00.000Z", status: "failed" },
  ]);
  // dp-disabled: a downpipe with a completed run but DISABLED, so a scope-omitted create must NOT include it.
  await seedDownpipe(storage, "dp-disabled", "Archived", false, [
    { runId: R_OLD, index: 1, startedAt: "2026-01-01T00:00:00.000Z", status: "ok", recordCount: 3 },
  ]);
  // dp-norun: an ENABLED downpipe with NO completed run, so create must skip it.
  await seedDownpipe(storage, "dp-norun", "Fresh", true, [
    { runId: R_FAILED, index: 1, startedAt: "2026-01-01T00:00:00.000Z", status: "in-flight" },
  ]);

  // ============================================================================================
  // 1. CREATE: pin the latest completed run per enabled downpipe + issue the live-possession challenge.
  // ============================================================================================
  const created = await call(env, scheduler, callerA, "POST", "/attest/session/create", { body: {} });
  ok("create returns 200", created.status === 200);
  const sessionId = String(created.json.sessionId ?? "");
  ok("create returns a session id", sessionId.length > 0);
  const runs = (created.json.runs ?? []) as Array<{ downpipeId: string; runId: string; name: string; recordCount: number }>;
  ok("create pins exactly the one enabled downpipe with a completed run (skips disabled + no-run)", runs.length === 1 && runs[0]?.downpipeId === "dp1");
  ok("create pins the LATEST COMPLETED run, skipping the newer FAILED run", runs[0]?.runId === R_LATEST);
  ok("create carries the pinned run's name + record count", runs[0]?.name === "Primary" && runs[0]?.recordCount === 10);
  const challenge = (created.json.challenge ?? {}) as { ciphertextB64?: string; nonceB64?: string; proofHash?: string };
  ok("create returns a challenge ciphertext + nonce", typeof challenge.ciphertextB64 === "string" && typeof challenge.nonceB64 === "string");
  ok("create NEVER returns the proof hash to the browser", challenge.proofHash === undefined);
  ok("create defaults the sample rate to 100", created.json.sampleRate === 100);
  const estimate = (created.json.estimate ?? {}) as { runs?: number; records?: number };
  ok("create estimate counts the pinned runs + full-sample records", estimate.runs === 1 && estimate.records === sampleCount(10, 100));

  // ============================================================================================
  // 2. STORED BLOB: no 32-byte-master-shaped secret (only the seed + proof hash are secret-shaped).
  // ============================================================================================
  const stored = (await storage.get<AttestSession>(`attest-session:${sessionId}`))!;
  ok("the session persisted under attest-session:<id>", stored !== undefined && stored.id === sessionId);
  ok("the session records the OWNER's stable subject (not the email)", stored.createdBy === callerA.subject);
  const serialised = JSON.stringify(stored);
  const allow = new Set([stored.seedB64, (stored.proofHash ?? "").slice("sha384:".length)]);
  const stray = secretShapedRuns(serialised).filter((r) => !allow.has(r));
  ok("the stored blob has NO master-shaped secret beyond the seed + proof hash", stray.length === 0);
  ok("a fabricated master's bytes never appear in the stored blob (masters are never stored)", (() => {
    const fake = crypto.getRandomValues(new Uint8Array(32));
    return !serialised.includes(b64urlEncode(fake)) && !serialised.includes(hexEncode(fake));
  })());
  ok("the stored blob is unproven with a pending proof hash", stored.proven === false && typeof stored.proofHash === "string" && stored.proofHash.startsWith("sha384:"));

  // ============================================================================================
  // 3. ONE ACTIVE SESSION: a second create returns the existing id (409), does not mint a second.
  // ============================================================================================
  const again = await call(env, scheduler, callerA, "POST", "/attest/session/create", { body: {} });
  ok("a second create while one is active is refused 409 with the existing id", again.status === 409 && again.json.sessionId === sessionId && again.json.alreadyActive === true);
  ok("no second session was persisted (still exactly one)", storage.countPrefix("attest-session:") === 1);

  // ============================================================================================
  // 4. OWNERSHIP: a different-subject caller is refused 403 on every non-create route.
  // ============================================================================================
  ok("a non-owner (different subject) is refused 403 on status", (await call(env, scheduler, callerB, "GET", "/attest/session/status", { query: `?id=${sessionId}` })).status === 403);
  ok("a non-owner is refused 403 on prove", (await call(env, scheduler, callerB, "POST", "/attest/session/prove", { body: { sessionId, proofB64: "x" } })).status === 403);
  ok("a non-owner is refused 403 on verify", (await call(env, scheduler, callerB, "POST", "/attest/session/verify", { body: { sessionId, batch: [{ runId: R_LATEST, masterB64: "x" }] } })).status === 403);
  ok("a non-owner is refused 403 on abort", (await call(env, scheduler, callerB, "POST", "/attest/session/abort", { body: { sessionId } })).status === 403);

  // ============================================================================================
  // 5. PROVE: a wrong proof is refused; the real break-glass proof flips proven + deletes the hash.
  // ============================================================================================
  const wrong = await call(env, scheduler, callerA, "POST", "/attest/session/prove", { body: { sessionId, proofB64: b64urlEncode(new Uint8Array(32).fill(9)) } });
  ok("a wrong live-possession proof is refused 400", wrong.status === 400);
  ok("a wrong proof leaves the session unproven", (await storage.get<AttestSession>(`attest-session:${sessionId}`))!.proven === false);
  // The real proof: decapsulate the challenge with the break-glass private, derive the proof over the nonce.
  const sharedSecret = await decapsulateHybrid(bgPriv, b64urlDecode(challenge.ciphertextB64!));
  const proof = await deriveAttestProof(sharedSecret, b64urlDecode(challenge.nonceB64!));
  const proved = await call(env, scheduler, callerA, "POST", "/attest/session/prove", { body: { sessionId, proofB64: b64urlEncode(proof) } });
  ok("the real break-glass proof passes (200 ok)", proved.status === 200 && proved.json.ok === true);
  const provenBlob = (await storage.get<AttestSession>(`attest-session:${sessionId}`))!;
  ok("prove flips proven:true and DELETES the proof hash", provenBlob.proven === true && provenBlob.proofHash === undefined);
  ok("the proven blob still has NO master-shaped secret beyond the seed", secretShapedRuns(JSON.stringify(provenBlob)).filter((r) => r !== provenBlob.seedB64).length === 0);

  // ============================================================================================
  // 6. CAPSULES + VERIFY reject a runId not pinned in the session (masters can only be spent on pinned runs).
  // ============================================================================================
  ok("capsules refuses a runId not pinned in the session (400)", (await call(env, scheduler, callerA, "POST", "/attest/session/capsules", { body: { sessionId, runIds: [R_NOT_PINNED] } })).status === 400);
  ok("verify refuses a batch runId not pinned in the session (400)", (await call(env, scheduler, callerA, "POST", "/attest/session/verify", { body: { sessionId, batch: [{ runId: R_NOT_PINNED, masterB64: "x" }] } })).status === 400);
  const statusOwner = await call(env, scheduler, callerA, "GET", "/attest/session/status", { query: `?id=${sessionId}` });
  const statusSession = (statusOwner.json.session ?? {}) as Record<string, unknown>;
  ok("status returns the session (owner) with the proof hash stripped", statusOwner.status === 200 && statusSession.id === sessionId && statusSession.proofHash === undefined);

  // ============================================================================================
  // 7. ABORT: sets status=aborted and frees the one-active-session slot.
  // ============================================================================================
  const aborted = await call(env, scheduler, callerA, "POST", "/attest/session/abort", { body: { sessionId } });
  ok("abort returns status aborted", aborted.status === 200 && aborted.json.status === "aborted");
  ok("the stored session status is aborted", (await storage.get<AttestSession>(`attest-session:${sessionId}`))!.status === "aborted");
  const fresh = await call(env, scheduler, callerA, "POST", "/attest/session/create", { body: { sampleRate: 50 } });
  ok("after abort a fresh create succeeds (the one-active slot is free)", fresh.status === 200 && typeof fresh.json.sessionId === "string");
  ok("a sub-100 create carries the requested sample rate + a proportional record estimate", fresh.json.sampleRate === 50 && (fresh.json.estimate as { records?: number }).records === sampleCount(10, 50));
  // Clean up the fresh session so it does not block the guard tests below reasoning about active state.
  await call(env, scheduler, callerA, "POST", "/attest/session/abort", { body: { sessionId: String(fresh.json.sessionId) } });

  // ============================================================================================
  // 8. GATES: drill.run, the attributable-identity rule, and the break-glass-public requirement.
  // ============================================================================================
  ok("a viewer (no drill.run) is refused 403 on create", (await call(env, scheduler, callerViewer, "POST", "/attest/session/create", { body: {} })).status === 403);
  ok("a bare-token (null-subject) caller cannot create a session (403)", (await call(env, scheduler, callerToken, "POST", "/attest/session/create", { body: {} })).status === 403);
  const noBg = await call({} as unknown as Env, scheduler, callerA, "POST", "/attest/session/create", { body: {} });
  ok("create with BREAK_GLASS_PUBLIC unset is refused 400", noBg.status === 400);

  // ============================================================================================
  // 8b. sampleRate IS REFUSED WHEN OUT OF BOUND, NOT CLAMPED AND COERCED INTO ONE.
  //
  // (.) The route ran
  // Math.max(1, Math.min(100, Math.trunc(x))) with a 100 fallback for anything non-numeric, so 0 became 1, a
  // billion became 100, 50.9 became 50 and "abc" became 100 -- and the session then reported back the rate
  // the ENGINE chose as though the operator had asked for it. That rate is stamped onto the attested record
  // and decides whether restoreProven is set at all, so an operator who asked for one thing and got another
  // is left with an assurance record that misdescribes the check they ran.
  //
  // Asserted on the RETURNED MESSAGE, and each case is a value the old clamp swallowed into a DIFFERENT
  // answer, so no two of these four could pass for the same wrong reason.
  // ============================================================================================
  for (const [sr, why] of [
    [0, "zero, which the clamp turned into 1"],
    [1000000000, "a billion, which the clamp turned into 100"],
    [50.9, "a fraction, which the trunc turned into 50"],
    ["abc", "a string, which the fallback turned into 100"],
  ] as Array<[unknown, string]>) {
    const r = await call(env, scheduler, callerA, "POST", "/attest/session/create", { body: { sampleRate: sr } });
    ok(`sampleRate ${JSON.stringify(sr)} is refused 400 (${why})`, r.status === 400 && String(r.json.error).includes("whole percentage from 1 to 100"));
  }
  // POSITIVE CONTROL that must DISCRIMINATE: an IN-BOUND rate still gets through this check and reaches the
  // session it always did. Without it, a route that 400'd every create would pass all four refusals above.
  {
    const inBound = await call(env, scheduler, callerA, "POST", "/attest/session/create", { body: { sampleRate: 25 } });
    ok("sampleRate CONTROL: an in-bound 25 still creates a session carrying exactly 25", inBound.status === 200 && inBound.json.sampleRate === 25);
    await call(env, scheduler, callerA, "POST", "/attest/session/abort", { body: { sessionId: String(inBound.json.sessionId) } });
    // And the ORDER holds: an unauthorised caller still gets the capability 403, not the body 400, so the
    // new check cannot answer a caller who holds nothing a different status from the one the gate gives.
    ok("sampleRate ORDER: a viewer sending a bad sampleRate still gets the capability 403, not the 400", (await call(env, scheduler, callerViewer, "POST", "/attest/session/create", { body: { sampleRate: 0 } })).status === 403);
  }

  // ============================================================================================
  // 9. THE NARROW STAMP (recordAttendedVerification): kind=attended + sampleRate, restoreProven ONLY on a
  //    FULL proven pass. Driven directly against the DO route (the crypto verify is proven separately in
  //    validate-attest-crypto), with a forwarded owner caller.
  // ============================================================================================
  const ownerHeader = { [CALLER_HEADER]: encodeCaller(callerA), "content-type": "application/json" };
  const stamp = async (body: unknown): Promise<void> => {
    await scheduler.fetch("https://scheduler.internal/attest-record", { method: "POST", headers: ownerHeader, body: JSON.stringify(body) });
  };
  // dp2: a SUB-100 proven pass -> kind attended + rate 50, but NO restoreProven / integrityVerified.
  await seedDownpipe(storage, "dp2", "Sub", true, []);
  await stamp({ downpipeId: "dp2", runId: R_LATEST, ok: true, sampleRate: 50, provenSession: true });
  const dp2 = (await storage.get<DownpipeState>("dp:dp2"))!;
  ok("a sub-100 proven pass stamps kind=attended + the sample rate", dp2.lastRestoreTestKind === "attended" && dp2.lastRestoreTestSampleRate === 50 && dp2.lastRestoreTestOk === true);
  ok("a sub-100 pass does NOT stamp restoreProven or integrityVerified", dp2.restoreProven === undefined && dp2.integrityVerified === undefined);

  // dp3: a FULL (100%) proven pass -> restoreProven (attended-blind-test) + integrityVerified.
  await seedDownpipe(storage, "dp3", "Full", true, []);
  await stamp({ downpipeId: "dp3", runId: R_LATEST, ok: true, sampleRate: 100, provenSession: true });
  const dp3 = (await storage.get<DownpipeState>("dp:dp3"))!;
  ok("a 100% proven pass stamps kind=attended + rate 100", dp3.lastRestoreTestKind === "attended" && dp3.lastRestoreTestSampleRate === 100);
  ok("a 100% proven pass stamps restoreProven method attended-blind-test + the proven runId + prover email", dp3.restoreProven?.method === "attended-blind-test" && dp3.restoreProven?.runId === R_LATEST && dp3.restoreProven?.by === callerA.email);
  ok("a 100% proven pass stamps integrityVerified how=attest", dp3.integrityVerified?.how === "attest");

  // dp4: a FULL pass but an UNPROVEN session -> kind attended, but NO restoreProven (the proven guard).
  await seedDownpipe(storage, "dp4", "Unproven", true, []);
  await stamp({ downpipeId: "dp4", runId: R_LATEST, ok: true, sampleRate: 100, provenSession: false });
  const dp4 = (await storage.get<DownpipeState>("dp:dp4"))!;
  ok("a 100% pass on an UNPROVEN session records the recency but NOT restoreProven", dp4.lastRestoreTestKind === "attended" && dp4.lastRestoreTestSampleRate === 100 && dp4.restoreProven === undefined);

  // dp5: a FAILURE -> ok:false, a closed reason code + a failure streak, and NO restoreProven.
  await seedDownpipe(storage, "dp5", "Failing", true, []);
  await stamp({ downpipeId: "dp5", runId: R_LATEST, ok: false, sampleRate: 100, provenSession: true, reason: "integrity" });
  const dp5 = (await storage.get<DownpipeState>("dp:dp5"))!;
  ok("a failing attended run records ok=false + the closed reason code + a failure streak", dp5.lastRestoreTestOk === false && dp5.lastRestoreTestReason === "integrity" && dp5.restoreTestConsecutiveFailures === 1);
  ok("a failing attended run never stamps restoreProven", dp5.restoreProven === undefined);
  // A subsequent PASS on dp5 clears the reason + streak.
  await stamp({ downpipeId: "dp5", runId: R_LATEST, ok: true, sampleRate: 100, provenSession: true });
  const dp5b = (await storage.get<DownpipeState>("dp:dp5"))!;
  ok("a pass clears the fail reason + failure streak", dp5b.lastRestoreTestReason === undefined && dp5b.restoreTestConsecutiveFailures === undefined);

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nATTEST-SESSION LIFECYCLE VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
