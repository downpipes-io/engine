// validate-runlog-sig-restore-route: a RUNLOG whose .sig was deleted, while its .sig.pending still verifies
// the stored body, is restored from the pending signature, and the restore leaves a sig-restored anomaly row
// in the support pack.
//
// resolveRunlogSignature (src/seal/pipeline.ts) publishes a verifying pending signature as the .sig. A crash
// between the two writes leaves a stale .sig in place, and a .sig that something deleted leaves none. The
// bytes are the engine's own in both cases, so the write goes ahead. The absent case also records a
// sig-restored row, so the pack shows that the signature file was removed.
//
// THIS FILE PROVES, against a real SchedulerDO, a real R2 destination double and a real signed RUNLOG:
//   1. with RUNLOG.sig deleted and RUNLOG.sig.pending verifying the stored body, resolveRunlogSignature
//      returns "promoted", republishes .sig, and records one sig-restored row with the RUNLOG digest;
//   2. the same state, met through the admin route, answers POST /runlog/resign with outcome "resumed" and
//      records a sig-restored row too.
//
// Run: node test/validate-runlog-sig-restore-route.ts

import { b64urlEncode, concat, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import { buildDestination } from "../src/dest/factory.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { appendRunlog, resolveRunlogSignature } from "../src/seal/pipeline.ts";
import { drainIntegrityFaultLedger } from "../src/format/integrity-fault-ledger.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { memoryBucket } from "./lib/memory-r2.ts";
import { challengeFor, challengeIdFor, enrolBootstrapOwner, extractSessionCookie, loginBegin, loginFinish, makeAuthenticator, makeScheduler, ORIGIN, signAssertion, type Authenticator, type MockStorage } from "./validate-passkey-harness.ts";

const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const RUNLOG_PENDING = "_RECOVERY/RUNLOG.sig.pending";
const DP = "dp_sigrestore";
const OWNER = "alice@acme.example";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FE${n}`;

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));
const entry = (n: number, prev: string | null) => ({ index: n, runId: R(n), downpipeId: DP, time: `2026-10-01T0${n}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" as const });

type Reply = { status: number; body: Record<string, unknown> };

// admin drives one request through handleAdmin, as the other router validators do: a session cookie, the
// matching Origin (the CSRF origin check) and CF-Connecting-IP.
async function admin(env: Env, method: string, path: string, cookie: string, body?: unknown): Promise<Reply> {
  const headers: Record<string, string> = { "content-type": "application/json", cookie, origin: ORIGIN, "CF-Connecting-IP": "198.51.100.23" };
  const resp = await handleAdmin(new Request(`https://engine.example/admin${path}`, body === undefined ? { method, headers } : { method, headers, body: JSON.stringify(body) }), env);
  const text = await resp.text();
  let parsed: Record<string, unknown> = {};
  try {
    const v = JSON.parse(text) as unknown;
    parsed = Array.isArray(v) ? { list: v } : v !== null && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    parsed = { text };
  }
  return { status: resp.status, body: parsed };
}

async function signIn(env: Env, key: Authenticator, email: string): Promise<string> {
  const begin = await loginBegin(env, email);
  const assertion = await signAssertion(key, challengeFor(begin));
  key.signCount++;
  const finish = await loginFinish(env, challengeIdFor(begin), assertion);
  const cookie = extractSessionCookie(finish.setCookie);
  if (finish.status !== 200 || cookie === null) throw new Error(`sign-in failed: ${finish.status}`);
  return cookie;
}

interface Estate {
  env: Env;
  storage: MockStorage;
  key: Authenticator;
  cookie: string;
  dest: Destination;
  verifier: HybridVerifier;
  body: Uint8Array;
  digest: string;
}

// estate bootstraps an Owner, writes a clean two-entry RUNLOG (so both .sig and .sig.pending verify the body),
// and hands back the digest POST /runlog/resign's confirmed-bytes check needs.
async function estate(): Promise<Estate> {
  const { env, storage } = makeScheduler();
  const { bucket } = memoryBucket();
  const signerPriv = signerB64();
  Object.assign(env as unknown as Record<string, unknown>, { DEST_KIND: "r2", DEST_R2: bucket, SIGNER_PRIVATE: signerPriv });
  const key = await makeAuthenticator("ES256");
  if ((await enrolBootstrapOwner(env, key, OWNER)).status !== 200) throw new Error("bootstrap of the Owner failed");
  const cookie = await signIn(env, key, OWNER);
  const dest = await buildDestination(env);
  const signer = await loadSigner(signerPriv);
  await appendRunlog(dest, signer, entry(1, null));
  await appendRunlog(dest, signer, entry(2, R(1)));
  const body = (await dest.get(RUNLOG))!.body;
  const digest = hexEncode(await sha384(body));
  return { env, storage, key, cookie, dest, verifier: verifierFrom(signer), body, digest };
}

let failures = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

const restoredRows = (): Array<{ digest?: string }> => drainIntegrityFaultLedger().runlogAnomalies.filter((a) => a.kind === "sig-restored");

async function main(): Promise<void> {
  const e = await estate();

  console.log("-- CONTROL: a freshly written RUNLOG verifies under its own .sig, with a matching .sig.pending --");
  ok("the fresh RUNLOG's .sig verifies", (await resolveRunlogSignature(e.dest, e.body, e.verifier)) === "verified");
  ok("the fresh RUNLOG's .sig.pending is present (the writer's own resume trail)", (await e.dest.get(RUNLOG_PENDING)) !== null);

  console.log("\n-- 1. RUNLOG.sig deleted, .sig.pending left verifying the body --");
  await e.dest.delete(RUNLOG_SIG);
  ok("CONTROL: .sig is now actually absent", (await e.dest.get(RUNLOG_SIG)) === null);
  drainIntegrityFaultLedger();
  const state = await resolveRunlogSignature(e.dest, e.body, e.verifier);
  const rows = restoredRows();
  ok(`resolveRunlogSignature promotes the pending signature over the body (got "${state}")`, state === "promoted");
  ok("the .sig object is republished from the pending signature and now itself verifies", (await e.dest.get(RUNLOG_SIG)) !== null && (await resolveRunlogSignature(e.dest, e.body, e.verifier)) === "verified");
  ok("one sig-restored row names the restore, with the 12-hex RUNLOG digest", rows.length === 1 && /^[0-9a-f]{12}$/.test(rows[0]?.digest ?? ""), rows);

  console.log("\n-- 2. the same state through POST /runlog/resign --");
  await e.dest.delete(RUNLOG_SIG);
  drainIntegrityFaultLedger();
  const resign = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest: e.digest });
  ok(`POST /runlog/resign over the same state answers outcome "resumed" (got ${resign.status} ${JSON.stringify(resign.body)})`, resign.status === 200 && resign.body.outcome === "resumed");
  ok("the route's restore records a sig-restored row too", restoredRows().length === 1);

  console.log(failures === 0 ? "\nVERDICT: PASS failures=0\n" : `\nVERDICT: FAIL failures=${failures}\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
