// Proves the recovery-codes stage/confirm sequence end to end over the REAL scheduler DO and the REAL
// router (src/admin/router.ts), in-memory storage only. Run:
//   node test/validate-recovery-codes-confirm-gate.ts
//
// THE DEFECT. An Owner who lost their passkey signs in with a saved recovery code (the documented
// "lost your passkey" path), is forced to enrol a fresh passkey, and completing that enrolment used to call
// generateRecoveryFor unconditionally -- the SAME immediate mint the first-ever (bootstrap) enrolment uses --
// which REPLACES the live recovery record on the spot. The old (still-unspent) codes died the instant the DO
// stored the fresh set, before the console's save-confirm panel had even rendered, so a closed tab or a
// crashed browser between register/finish and the operator ticking "I have saved my recovery codes" left them
// with nothing but the ONE code they had just spent to get in.
//
// THE FIX proved here: when register/finish's self-add mint runs while a LIVE record already exists, it
// mints to a STAGED key instead (generateRecoveryStaged) and reports recoveryCodesPending:true. The live
// record, and every code in it, keeps verifying exactly as before. Only a subsequent authenticated
// POST /admin/auth/recovery-codes/confirm (confirmRecoveryStaged) promotes the staged set to live -- the real
// invalidation boundary -- which is what the console's save-confirm "Continue" now calls before it proceeds.
// An abandoned staged offer (confirm never called) costs nothing: the old set is still the working one.
//
// What this proves, in the order the rehearsal hit them:
//  1. bootstrap enrolment mints the FIRST set immediately (unchanged: nothing to protect yet);
//  2. a recovery-code sign-in consumes one code and, per the documented flow, requires a fresh passkey;
//  3. that forced self-add enrolment does NOT touch the live record: it stages a fresh set and answers
//     recoveryCodesPending:true, and the audit trail records recovery-codes-staged, not recovery-codes-generated;
//  4. every OTHER original code still signs in -- the invariant a customer needs, "I always know which codes
//     are valid", held throughout the enrolment;
//  5. a code from the STAGED set does NOT yet sign in (it is not live);
//  6. confirming (POST /admin/auth/recovery-codes/confirm) promotes the staged set: audits
//     recovery-codes-generated exactly once, at THIS instant, and from here the OLD codes are dead and the
//     STAGED ones work;
//  7. a bootstrap/invite enrolment is untouched throughout: no staged key is ever written for it, and its
//     mint is exactly the byte-for-byte immediate path validate-passkey-roundtrip.ts already pins.
//  8. a second self-add whose staged offer is NEVER confirmed leaves the original set as the one that keeps
//     working, indefinitely -- the safe abandonment case.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { AuditEvent } from "../src/admin/audit-types.ts";
import { verifyCode, type RecoveryRecord } from "../src/admin/recovery.ts";
import type { Env } from "../src/env.d.ts";
import {
  ok,
  failureCount,
  makeScheduler,
  makeAuthenticator,
  buildAttestation,
  registerBegin,
  registerFinish,
  challengeFor,
  extractSessionCookie,
  post,
  enrolBootstrapOwner,
  ORIGIN,
  type PasskeyBody,
} from "./validate-passkey-harness.ts";
import { MockStorage } from "./mock-storage.ts";

const OWNER = "owner-lost-passkey@example.com";

// recoverWithCode drives POST /admin/auth/recovery (the recovery-code sign-in) straight through the router.
async function recoverWithCode(env: Env, email: string, code: string): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  return post(env, "/admin/auth/recovery", { email, code });
}

// confirmStaged drives POST /admin/auth/recovery-codes/confirm authenticated by the given session cookie.
async function confirmStaged(env: Env, cookie: string): Promise<{ status: number; json: PasskeyBody; setCookie: string | null }> {
  return post(env, "/admin/auth/recovery-codes/confirm", {}, { cookie, origin: ORIGIN });
}

// liveVerifies asks "does this code verify against the LIVE record right now", via the same pure verifyCode
// core the route uses, read directly against storage. NON-CONSUMING and NOT rate-limited: it exists so this
// test can check many codes against many points in time without tripping RECOVERY_RATE_MAX_PER_EMAIL (5 per
// 60s), which a dozen full /admin/auth/recovery round trips on one email inside one test run would. The
// handful of full-route calls this file does make (the actual sign-in, and one post-confirm sign-in) still
// prove the end-to-end ceremony; this proves the record's CONTENT at each checkpoint.
async function liveVerifies(inspector: SchedulerDO, email: string, code: string): Promise<boolean> {
  const key = await inspector.recoverySigningKey();
  const record = await inspector.getRecoveryRecord(email);
  if (record === null) return false;
  const result = await verifyCode(key, record as RecoveryRecord, code);
  return result.matched === true;
}

async function run(): Promise<void> {
  console.log("validate-recovery-codes-confirm-gate: the stage/confirm sequence, before and after the fix");

  const { env, storage } = makeScheduler();
  // A second SchedulerDO instance over the SAME MockStorage, used ONLY to read state directly (the live and
  // staged records, the audit trail) the way a test inspects a database -- never to serve a request.
  const inspector = new SchedulerDO({ storage } as unknown as DurableObjectState);

  // ---- 1. Bootstrap: the FIRST set mints immediately (nothing staged, nothing to protect yet) -------------
  const owner = await makeAuthenticator("ES256");
  const bootFin = await enrolBootstrapOwner(env, owner, OWNER);
  ok("(1) bootstrap enrolment succeeds", bootFin.json.ok === true);
  const originalCodes = bootFin.json.recoveryCodes;
  ok("(1) bootstrap issues 10 recovery codes", Array.isArray(originalCodes) && originalCodes.length === 10);
  ok("(1) bootstrap reports recoveryCodesPending:false (nothing staged; minted straight to live)", bootFin.json.recoveryCodesPending === false || bootFin.json.recoveryCodesPending === undefined);
  ok("(1) no staged record exists yet", (await storage.get(inspector.stagedRecoveryKey(OWNER))) === undefined);
  const codes = originalCodes as string[];

  // ---- 2. Lost the passkey: sign in with one of the original codes -----------------------------------------
  const spentCode = codes[0]!;
  const recover = await recoverWithCode(env, OWNER, spentCode);
  ok("(2) recovery-code sign-in succeeds", recover.status === 200 && recover.json.ok === true);
  ok("(2) the engine asks for a fresh passkey enrolment (enrolPasskey)", recover.json.enrolPasskey === true);
  const recoverySession = extractSessionCookie(recover.setCookie);
  ok("(2) a session cookie was minted", recoverySession !== null);
  ok("(2) the spent code no longer signs in a second time (single-use)", (await recoverWithCode(env, OWNER, spentCode)).json.ok !== true);

  // ---- 3. The forced re-enrolment: register a fresh passkey over the SAME (recovery) session --------------
  const newAuthenticator = await makeAuthenticator("ES256");
  const begin = await registerBegin(env, OWNER, { cookie: recoverySession!, origin: ORIGIN });
  ok("(3) self-add register/begin is authorised by the recovery session", begin.json.ok === true);
  const att = await buildAttestation(newAuthenticator, challengeFor(begin));
  const finish = await registerFinish(env, OWNER, att, { cookie: recoverySession!, origin: ORIGIN });
  ok("(3) the forced re-enrolment succeeds", finish.json.ok === true);
  const stagedCodes = finish.json.recoveryCodes;
  ok("(3) it returns a fresh set of 10 codes for display", Array.isArray(stagedCodes) && stagedCodes.length === 10);
  ok(
    "(3) THE FIX: recoveryCodesPending:true -- these codes are STAGED, not yet live",
    finish.json.recoveryCodesPending === true,
  );
  ok(
    "(3) the fresh set shares NO code with the original set (it really is a new mint, not an echo)",
    (stagedCodes as string[]).every((c) => !codes.includes(c)),
  );

  // ---- 4. THE INVARIANT: every OTHER original code still works, right after the enrolment ------------------
  const untouchedOriginal = codes[1]!;
  const stillWorks = await recoverWithCode(env, OWNER, untouchedOriginal);
  ok(
    "(4) THE INVARIANT HELD: an untouched ORIGINAL code still signs in immediately after the forced re-enrolment",
    stillWorks.status === 200 && stillWorks.json.ok === true,
  );

  // ---- 5. The staged codes do NOT yet work (they are not live) ---------------------------------------------
  // Checked against the live record directly (liveVerifies), not the rate-limited route: see its own comment.
  const stagedCode = (stagedCodes as string[])[0]!;
  ok("(5) a STAGED code does NOT verify against the live record before it is confirmed", !(await liveVerifies(inspector, OWNER, stagedCode)));

  // ---- audit trail so far: staged, not generated -------------------------------------------------------
  {
    const audit = await inspector.listAuditEntries();
    const actions = audit.map((e: AuditEvent) => e.action);
    ok("(audit) recovery-codes-staged was recorded for the forced re-enrolment", actions.includes("recovery-codes-staged"));
    // Exactly one recovery-codes-generated so far: the bootstrap mint. The forced re-enrolment must NOT have
    // added a second one yet -- that is the exact defect (silent full regeneration) this fix closes.
    ok(
      "(audit) recovery-codes-generated has fired exactly ONCE so far (the bootstrap mint; the re-enrolment did not add a second)",
      actions.filter((a: string) => a === "recovery-codes-generated").length === 1,
    );
  }

  // ---- storage: the live record is UNCHANGED by the enrolment; the staged record holds the new set --------
  {
    const liveAfterEnrol = await storage.get<{ email: string }>(inspector.recoveryKey(OWNER));
    const stagedAfterEnrol = await storage.get<{ email: string }>(inspector.stagedRecoveryKey(OWNER));
    ok("(storage) a live record still exists", liveAfterEnrol !== undefined);
    ok("(storage) a staged record now exists", stagedAfterEnrol !== undefined);
  }

  // ---- 6. Confirming promotes the staged set: NOW the old codes die and the new ones work -------------------
  const newSession = extractSessionCookie(finish.setCookie) ?? recoverySession!;
  const confirmResp = await confirmStaged(env, newSession);
  ok("(6) confirm succeeds", confirmResp.status === 200 && confirmResp.json.ok === true);
  ok("(6) confirm reports promoted:true", confirmResp.json.promoted === true);

  {
    const audit = await inspector.listAuditEntries();
    const actions = audit.map((e: AuditEvent) => e.action);
    ok(
      "(6 audit) recovery-codes-generated now fires a SECOND time, exactly at confirm -- the real invalidation boundary",
      actions.filter((a: string) => a === "recovery-codes-generated").length === 2,
    );
    ok("(6 storage) the staged key is gone after promotion", (await storage.get(inspector.stagedRecoveryKey(OWNER))) === undefined);
  }

  // ---- 7. NOW the original codes are dead, and the staged ones are the live set ------------------------------
  // codes[2] was never touched by any earlier step, so this proves the LIVE RECORD no longer holds the
  // original set at all -- not merely that one code was already spent (untouchedOriginal was consumed by
  // step 4's own route call, which would make that check true for the wrong reason).
  const neverTouchedOriginal = codes[2]!;
  ok(
    "(7) an ORIGINAL code that was NEVER used no longer verifies, now that the new set is confirmed",
    !(await liveVerifies(inspector, OWNER, neverTouchedOriginal)),
  );
  const stagedNowLive = await recoverWithCode(env, OWNER, (stagedCodes as string[])[1]!);
  ok("(7) a code from the CONFIRMED (formerly staged) set signs in end to end (session mint included)", stagedNowLive.status === 200 && stagedNowLive.json.ok === true);

  // ---- 8. Confirming twice is a harmless no-op (idempotent) ---------------------------------------------------
  const secondConfirm = await confirmStaged(env, newSession);
  ok("(8) a second confirm with nothing staged is ok:true", secondConfirm.json.ok === true);
  ok("(8) and reports promoted:false (nothing to promote)", secondConfirm.json.promoted === false);

  // ---- 9. An abandoned staged offer never confirmed leaves the ORIGINAL set as the one that keeps working ---
  {
    const newAuth2 = await makeAuthenticator("ES256");
    const begin2 = await registerBegin(env, OWNER, { cookie: newSession, origin: ORIGIN });
    const att2 = await buildAttestation(newAuth2, challengeFor(begin2));
    const finish2 = await registerFinish(env, OWNER, att2, { cookie: newSession, origin: ORIGIN });
    ok("(9) a THIRD self-add enrolment also stages rather than mints immediately", finish2.json.recoveryCodesPending === true);
    const abandonedCodes = finish2.json.recoveryCodes as string[];
    // No confirm call is ever made for this one: the tab was "closed". Checked via liveVerifies (see its own
    // comment) rather than the route, which is already at 4 of the 5-per-60s recovery-rate budget by here.
    ok(
      "(9) THE SAFE ABANDONMENT: the (formerly staged, now confirmed) set from step 6 keeps working when a LATER staged offer is simply never confirmed",
      await liveVerifies(inspector, OWNER, (stagedCodes as string[])[2]!),
    );
    ok("(9) the abandoned staged codes never went live", !(await liveVerifies(inspector, OWNER, abandonedCodes[0]!)));
  }

  // ---- 10. A bootstrap enrolment on a DIFFERENT, fresh account is untouched: no staging, immediate mint -----
  {
    const freshStorage = new MockStorage();
    const freshState = { storage: freshStorage } as unknown as DurableObjectState;
    const dobj = new SchedulerDO(freshState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input.toString(), init)) } as unknown as DurableObjectStub;
    const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
    const freshEnv = { ...env, SCHEDULER: namespace };
    const freshOwner = await makeAuthenticator("ES256");
    const freshBoot = await enrolBootstrapOwner(freshEnv, freshOwner, "fresh-owner@example.com");
    ok("(10) a fresh account's bootstrap enrolment is unaffected: recoveryCodesPending is false/absent", freshBoot.json.recoveryCodesPending !== true);
    ok("(10) and mints straight to the live key, exactly as validate-passkey-roundtrip.ts pins", (await freshStorage.get(dobj.recoveryKey("fresh-owner@example.com"))) !== undefined);
    ok("(10) no staged key was ever written for the fresh account", (await freshStorage.get(dobj.stagedRecoveryKey("fresh-owner@example.com"))) === undefined);
  }

  console.log(failureCount() === 0 ? "\nvalidate-recovery-codes-confirm-gate: ALL PASS" : `\nvalidate-recovery-codes-confirm-gate: ${failureCount()} FAILED`);
}

await run();
if (failureCount() > 0) process.exitCode = 1;
if (failureCount() > 0) process.exit(1);
