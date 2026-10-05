// validate-status-signer-pin: GET /admin/status reports the update-signer key the engine verifies with.
//
// RELEASE_SIGNER_PIN is a value the operator types. The engine verifies update-channel signatures with
// UPDATE_SIGNER_PUBLIC. The console showed the typed value as the release-signer pin, and nothing compared
// the two, so the row could name a key the engine does not use. This test drives the real handleAdmin over
// a real SchedulerDO and checks:
//   - the status carries the edmldsa1 fingerprint of UPDATE_SIGNER_PUBLIC, computed here with node:crypto
//     as an independent oracle;
//   - a set pin equal to that fingerprint reads as declared and matching, with no warning;
//   - a set pin that differs reads as not matching and raises releaseSignerPinWarning;
//   - a set pin with no valid pinned key reads as not matching and raises the warning;
//   - an unset pin reads as not declared, with no match verdict and no warning;
//   - the typed value is still reported only as releaseSignerPin, never as the fingerprint.
//
// It also checks the release-signer-pin posture check (not raised when no pin is declared, pass on a match,
// fail at medium severity with the status warning text otherwise) and the support pack (keys.updateSigner and
// the status verdict fields).
//
// Run: node test/validate-status-signer-pin.ts

import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { handleAdmin } from "../src/admin/router.ts";
import { computePostureViaDO } from "../src/admin/router-posture.ts";
import { buildSupportBundle } from "../src/admin/support.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ADMIN_TOKEN = "status-signer-pin-break-glass-token-1234567890";

const STUBS = new WeakMap<object, DurableObjectStub>();
function freshEnv(extra: Record<string, unknown>): Env {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(input as string, init)) } as unknown as DurableObjectStub;
  const SCHEDULER = { idFromName: () => ({}) as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER, ADMIN_TOKEN, ...extra } as unknown as Env;
  STUBS.set(env, stub);
  return env;
}

function stubOf(env: Env): DurableObjectStub {
  const s = STUBS.get(env);
  if (s === undefined) throw new Error("no stub for env");
  return s;
}

async function pinCheck(env: Env): Promise<{ status: string; severity: string; detail: string } | undefined> {
  const report = await computePostureViaDO(env, stubOf(env), null);
  return report.checks.find((c) => c.id === "release-signer-pin") as { status: string; severity: string; detail: string } | undefined;
}

const expectedWarning = (fp: string): string => `RELEASE_SIGNER_PIN is only a label. The engine verifies updates with key ${fp}. Set RELEASE_SIGNER_PIN to that value, or clear it.`;

async function status(env: Env): Promise<Record<string, unknown>> {
  const r = await handleAdmin(new Request("https://engine.pin.example/admin/status", { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
  ok(`status read is 200 (got ${r.status})`, r.status === 200);
  return (await r.json()) as Record<string, unknown>;
}

function makeSignerPublic(): { pub: string; fingerprint: string } {
  const ed = ed25519.getPublicKey(crypto.getRandomValues(new Uint8Array(32)));
  const ml = mldsaKeygen().publicKey;
  const raw = concat(ed, ml);
  return { pub: b64urlEncode(raw), fingerprint: `edmldsa1:${createHash("sha384").update(raw).digest("hex")}` };
}

async function supportPack(env: Env): Promise<Record<string, unknown>> {
  return buildSupportBundle(env, stubOf(env));
}

async function main(): Promise<void> {
  const signer = makeSignerPublic();
  const other = makeSignerPublic();
  ok("oracle: two generated keys have different fingerprints", signer.fingerprint !== other.fingerprint);
  const channel = { UPDATE_CHANNEL_URL: "https://update.downpipes.io/channel.json", UPDATE_SIGNER_PUBLIC: signer.pub };

  console.log("-- the status names the key the engine verifies with --");
  {
    const b = await status(freshEnv(channel));
    ok("updateSignerFingerprint equals SHA-384 of UPDATE_SIGNER_PUBLIC (edmldsa1 form)", b.updateSignerFingerprint === signer.fingerprint);
    ok("unset pin: releaseSignerPinDeclared is false", b.releaseSignerPinDeclared === false);
    ok("unset pin: no match verdict", b.releaseSignerPinMatches === undefined);
    ok("unset pin: no warning", b.releaseSignerPinWarning === undefined);
    ok("unset pin: no declared value", b.releaseSignerPin === undefined);
    ok("unset pin: posture check release-signer-pin not raised", (await pinCheck(freshEnv(channel))) === undefined);
  }

  console.log("-- a declared pin that matches --");
  {
    const b = await status(freshEnv({ ...channel, RELEASE_SIGNER_PIN: ` ${signer.fingerprint.toUpperCase().replace("EDMLDSA1:", "edmldsa1:")} ` }));
    ok("matching pin: releaseSignerPinDeclared is true", b.releaseSignerPinDeclared === true);
    ok("matching pin: releaseSignerPinMatches is true (trim, hex case ignored)", b.releaseSignerPinMatches === true);
    ok("matching pin: no warning", b.releaseSignerPinWarning === undefined);
    const c = await pinCheck(freshEnv({ ...channel, RELEASE_SIGNER_PIN: signer.fingerprint }));
    ok("matching pin: posture check passes", c?.status === "pass");
  }

  console.log("-- a declared pin that differs --");
  {
    const typed = other.fingerprint;
    const b = await status(freshEnv({ ...channel, RELEASE_SIGNER_PIN: typed }));
    ok("different pin: releaseSignerPinDeclared is true", b.releaseSignerPinDeclared === true);
    ok("different pin: releaseSignerPinMatches is false", b.releaseSignerPinMatches === false);
    ok("different pin: releaseSignerPinWarning is set", typeof b.releaseSignerPinWarning === "string" && (b.releaseSignerPinWarning as string).includes("RELEASE_SIGNER_PIN"));
    ok("different pin: the fingerprint is still the verifying key, not the typed value", b.updateSignerFingerprint === signer.fingerprint);
    ok("different pin: the typed value is reported only as releaseSignerPin", b.releaseSignerPin === typed);
    ok("different pin: warning text names the verifying key", b.releaseSignerPinWarning === expectedWarning(signer.fingerprint));
    const c = await pinCheck(freshEnv({ ...channel, RELEASE_SIGNER_PIN: typed }));
    ok("different pin: posture check fails at medium (warning) severity", c?.status === "fail" && c.severity === "medium");
    ok("different pin: posture detail is the status warning text", c?.detail === expectedWarning(signer.fingerprint));
  }

  console.log("-- a short label is not the key --");
  {
    const b = await status(freshEnv({ ...channel, RELEASE_SIGNER_PIN: "release-signer-2026" }));
    ok("label pin: releaseSignerPinMatches is false", b.releaseSignerPinMatches === false);
    ok("label pin: warning is set", typeof b.releaseSignerPinWarning === "string");
  }

  console.log("-- a declared pin with no valid pinned key --");
  {
    const b = await status(freshEnv({ RELEASE_SIGNER_PIN: signer.fingerprint }));
    ok("no key: updateSignerFingerprint absent", b.updateSignerFingerprint === undefined);
    ok("no key: releaseSignerPinMatches is false", b.releaseSignerPinMatches === false);
    ok("no key: warning is set", typeof b.releaseSignerPinWarning === "string");
    const c = await pinCheck(freshEnv({ RELEASE_SIGNER_PIN: signer.fingerprint }));
    ok("no key: posture check fails with the same text as the status warning", c?.status === "fail" && c.detail === b.releaseSignerPinWarning);
    const bad = await status(freshEnv({ UPDATE_CHANNEL_URL: channel.UPDATE_CHANNEL_URL, UPDATE_SIGNER_PUBLIC: "not-a-key", RELEASE_SIGNER_PIN: signer.fingerprint }));
    ok("malformed key: updateSignerFingerprint absent", bad.updateSignerFingerprint === undefined);
    ok("malformed key: releaseSignerPinMatches is false", bad.releaseSignerPinMatches === false);
  }

  console.log("-- the support pack carries the fingerprint and the verdict --");
  {
    const pack = await supportPack(freshEnv({ ...channel, RELEASE_SIGNER_PIN: other.fingerprint }));
    const keys = pack.keys as { updateSigner?: { configured?: boolean; signerFingerprint?: string; malformed?: boolean } };
    ok("pack keys.updateSigner.signerFingerprint is the verifying key", keys.updateSigner?.configured === true && keys.updateSigner.signerFingerprint === signer.fingerprint);
    const st = pack.status as Record<string, unknown>;
    ok("pack status carries the fingerprint and the mismatch", st.updateSignerFingerprint === signer.fingerprint && st.releaseSignerPinMatches === false && st.releaseSignerPinWarning === expectedWarning(signer.fingerprint));
    const bad = await supportPack(freshEnv({ UPDATE_CHANNEL_URL: channel.UPDATE_CHANNEL_URL, UPDATE_SIGNER_PUBLIC: "not-a-key" }));
    const badKeys = bad.keys as { updateSigner?: { configured?: boolean; signerFingerprint?: string; malformed?: boolean } };
    ok("pack flags a malformed update-signer key with no fingerprint", badKeys.updateSigner?.malformed === true && badKeys.updateSigner.signerFingerprint === undefined);
    const none = await supportPack(freshEnv({}));
    ok("pack reports an unset update-signer key as not configured", (none.keys as { updateSigner?: { configured?: boolean } }).updateSigner?.configured === false);
  }

  console.log("-- no channel and no pin --");
  {
    const b = await status(freshEnv({}));
    ok("bare engine: no fingerprint, pin not declared, no warning", b.updateSignerFingerprint === undefined && b.releaseSignerPinDeclared === false && b.releaseSignerPinWarning === undefined);
  }
}

await main();
console.log(failures === 0 ? "\nSTATUS SIGNER PIN PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
