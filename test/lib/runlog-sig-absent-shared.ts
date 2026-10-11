// Shared estate for validate-runlog-sig-absent-promote.ts: a bootstrapped
// Owner, a real R2 destination double, and a two-entry signed RUNLOG, built the same way
// validate-runlog-attended-resign.ts's estate() does, trimmed to what the absent-signature check needs (no notify
// channels, no step-up: POST /runlog/resign's "pending-verifies" branch runs before step-up is checked).

import { b64urlEncode, concat, hexEncode } from "../../src/crypto/bytes.ts";
import { sha384 } from "../../src/crypto/primitives.ts";
import type { HybridVerifier } from "../../src/crypto/sign.ts";
import { buildDestination } from "../../src/dest/factory.ts";
import type { Destination } from "../../src/dest/types.ts";
import type { Env } from "../../src/env.d.ts";
import { handleAdmin } from "../../src/admin/router.ts";
import { loadSigner, verifierFrom } from "../../src/keys-env.ts";
import { appendRunlog } from "../../src/seal/pipeline.ts";
import { memoryBucket } from "./memory-r2.ts";
import { challengeFor, challengeIdFor, enrolBootstrapOwner, extractSessionCookie, loginBegin, loginFinish, makeAuthenticator, makeScheduler, ORIGIN, signAssertion, type Authenticator, type MockStorage } from "../validate-passkey-harness.ts";

export const RUNLOG = "_RECOVERY/RUNLOG";
export const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
export const RUNLOG_PENDING = "_RECOVERY/RUNLOG.sig.pending";
export const DP = "dp_sigabsent";
export const OWNER = "alice@acme.example";
export const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FE${n}`;

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));
const entry = (n: number, prev: string | null) => ({ index: n, runId: R(n), downpipeId: DP, time: `2026-10-01T0${n}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" as const });

export type Reply = { status: number; body: Record<string, unknown> };

// admin drives one request through handleAdmin, as the other router validators do: a session cookie, the
// matching Origin (the CSRF origin check) and CF-Connecting-IP, always present here.
export async function admin(env: Env, method: string, path: string, cookie: string, body?: unknown): Promise<Reply> {
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

export interface SigAbsentEstate {
  env: Env;
  storage: MockStorage;
  key: Authenticator;
  cookie: string;
  dest: Destination;
  verifier: HybridVerifier;
  body: Uint8Array;
  digest: string;
}

// sigAbsentEstate bootstraps an Owner, writes a clean two-entry RUNLOG (so both .sig and .sig.pending verify the
// body before the check touches anything), and hands back the digest it needs for
// POST /runlog/resign's confirmed-bytes check.
export async function sigAbsentEstate(): Promise<SigAbsentEstate> {
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
