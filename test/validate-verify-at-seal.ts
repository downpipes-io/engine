// Verify-at-seal: right after a run seals, the engine reads the
// just-written archive BACK from the destination and verifies it, so a corrupt/partial backup
// is caught at seal time rather than at the next periodic drill (up to a week later). This
// validator proves the behaviour end to end with IN-MEMORY doubles (no network, no deploy, no
// cost), exactly the way validate-drill.ts exercises the drill:
//
//   1. A GOOD run + the operational key VERIFIES at the sampled-decrypt tier (Tier-0 chain +
//      a decrypt sample of records), is flagged verified, and the verify writes/deletes NOTHING.
//   2. A GOOD run with NO operational key (break-glass-only posture) verifies at Tier-0 only,
//      flagged verified, sampled 0 (honest: no in-account read-back key to decrypt with).
//   3. A deliberately CORRUPTED written archive (a shard byte flipped, so the signed shard hash
//      no longer matches) is CAUGHT -> flagged SUSPECT, the archive is NOT deleted and the verify
//      does NOT throw (fail-open). The suspect verdict raises a CRITICAL posture finding
//      (computePosture seal-verification) and fires a CRITICAL notification (routeSealVerifyAlert
//      reaches the notify route; sealVerifyEmission is a critical restore-test-fail).
//   4. A TRUNCATED segment (a chunk lopped off the just-written segment) is CAUGHT by the decrypt
//      sample -> suspect, fail-open, archive intact.
//   5. The feature gate (VERIFY_AT_SEAL) DEFAULTS ON and an explicit falsey value disables it.
//   6. The size threshold (SEAL_VERIFY_MAX_BYTES) forces Tier-0 only on a large run even with the
//      operational key, so verify-at-seal stays bounded on the metered account.
//
// Run: node test/validate-verify-at-seal.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import {
  verifyAtSeal,
  verifyAtSealEnabled,
  sealVerifyEmission,
  routeSealVerifyAlert,
  resolveSealVerifyKnobs,
  type SealVerification,
} from "../src/seal/verify-at-seal.ts";
import { computePosture, type PostureInput } from "../src/admin/posture.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify.ts";
import { flipBit } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_seal";
const KVSET: Record<string, string> = {
  "key:alpha": "value-alpha",
  "key:beta": "value-beta-longer",
  "key:gamma": "gamma-value-here",
  "key:delta": "delta-value-padded",
  "key:epsilon": "epsilon-value-content",
};

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// SpyDestination is a full in-memory Destination that records every mutating call, so the test
// can assert verify-at-seal NEVER deletes or writes (fail-open: the bytes are already written).
class SpyDestination implements Destination {
  private store = new Map<string, Uint8Array>();
  readonly mutateLog: string[] = [];
  // transientFailsRemaining models the R2 S3-compat read-after-write window: the next N get() calls
  // return null (a just-written object briefly reading as a 404), simulating the lag the bounded
  // read-after-write retry exists to ride out. The underlying bytes are intact, so a later attempt
  // serves them and the verify self-heals (recovered, NOT a suspect).
  transientFailsRemaining = 0;
  // thawNeeded models a COLD-storage-class archive (bucket-lifecycle-to-glacier): a bucket lifecycle rule
  // silently transitioned the objects to GLACIER/DEEP_ARCHIVE, so a read throws the classified `thaw-needed`
  // fault (s3-read-ops get() produces this from the S3 InvalidObjectState code). It is NOT retryable — a
  // read-after-write retry cannot thaw the object — so the verdict surfaces immediately after one attempt.
  thawNeeded = false;
  async get(key: string): Promise<GetResult | null> {
    if (this.thawNeeded) throw new Error(`GET ${key}: thaw-needed (object is in a cold storage class and must be restored/thawed before it can be read)`);
    if (this.transientFailsRemaining > 0) {
      this.transientFailsRemaining--;
      return null;
    }
    const v = this.store.get(key);
    return v ? { body: v, etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.mutateLog.push(`put:${key}`);
    this.store.set(key, body);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    let n = 0;
    for (const p of parts) n += p.length;
    const merged = new Uint8Array(n);
    let off = 0;
    for (const p of parts) { merged.set(p, off); off += p.length; }
    this.mutateLog.push(`putStream:${key}`);
    this.store.set(key, merged);
  }
  async putConditional(key: string, body: Uint8Array, _opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    this.mutateLog.push(`putConditional:${key}`);
    this.store.set(key, body);
    return { ok: true, etag: `"${key.length}"` };
  }
  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }
  async delete(key: string): Promise<void> {
    this.mutateLog.push(`delete:${key}`);
    this.store.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix));
  }
  has(key: string): boolean {
    return this.store.has(key);
  }
  countSegments(): number {
    return [...this.store.keys()].filter((k) => k.startsWith("seg/") && k.endsWith(".seg")).length;
  }
  seed(archive: Map<string, Uint8Array>): void {
    for (const [k, v] of archive) this.store.set(k, v);
    this.mutateLog.length = 0;
  }
  // tamperShard flips one byte inside a stored shard manifest object. The shard's SHA-384 is in the
  // SIGNED root, so a flipped shard byte breaks the completeness check (Tier-0 keyless) without
  // needing any key: the readback verify must catch it.
  firstShardKey(): string {
    for (const k of this.store.keys()) if (k.includes("/manifest/") && k.endsWith(".dpe")) return k;
    throw new Error("no shard manifest object in the store");
  }
  tamperShard(): string {
    const key = this.firstShardKey();
    const bytes = this.store.get(key)!;
    const copy = new Uint8Array(bytes);
    // Flip a byte well past the container header so the ciphertext (and thus the object hash) changes.
    flipBit(copy, copy.length - 1);
    this.store.set(key, copy);
    return key;
  }
  // firstSegmentKey returns the storage key of the first segment object in the store. Scenario 4
  // uses it to obtain the key before truncating that object inline (lopping the last STREAM chunk
  // off), so the segment's decrypted chunk count no longer matches its declared chunkRange and the
  // AEAD/plaintext check fails inside the decrypt sample. The shard hash is unaffected (the segment
  // is not in a shard), so Tier-0 passes and the sampled-decrypt tier is what catches it.
  firstSegmentKey(): string {
    for (const k of this.store.keys()) if (k.startsWith("seg/") && k.endsWith(".seg")) return k;
    throw new Error("no segment object in the store");
  }
}

// FakeScheduler is a minimal DurableObjectStub recording the notify route calls routeSealVerifyAlert
// makes, so the test can prove the CRITICAL notification path actually fires (reaches /notify/resolve
// and, when a channel resolves, delivers + records). It returns the channels passed to its
// constructor for /notify/resolve, accepts /notify/record, and 404s anything else.
class FakeScheduler {
  readonly calls: string[] = [];
  private channels: NotifyChannel[];
  lastResolveEmission: NotifyEmission | null = null;
  constructor(channels: NotifyChannel[]) {
    this.channels = channels;
  }
  async fetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const path = new URL(url).pathname;
    this.calls.push(path);
    if (path === "/notify/resolve") {
      try {
        const body = JSON.parse(String(init?.body ?? "{}")) as { emission?: NotifyEmission };
        this.lastResolveEmission = body.emission ?? null;
      } catch { /* ignore */ }
      return new Response(JSON.stringify({ now: this.channels, digestedCount: 0, emission: this.lastResolveEmission }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (path === "/notify/record") {
      return new Response(JSON.stringify({ recorded: 1 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("not found", { status: 404 });
  }
}

// basePostureInput is a minimal, all-passing PostureInput so the seal-verification check can be
// exercised in isolation (only the downpipes slice varies between the two assertions).
function basePostureInput(downpipes: PostureInput["downpipes"]): PostureInput {
  return {
    status: {
      destConfigured: true,
      breakGlassConfigured: true,
      operationalConfigured: { public: true, private: true },
      tokenFallbackDisabled: true,
      adminTokenPresent: false,
      bootstrapConsumed: true,
      breakGlassTokenRetired: true,
      recoveryBreakGlassReady: true,
    },
    downpipes,
    expiry: [],
    notifyFailureRuleSet: true,
    ownerCount: 2,
    operationalPrivatePresent: false,
    beaconEnabled: false,
    overrides: new Map(),
    // No pin recorded in this fixture. Stated rather than omitted: PostureInput makes this REQUIRED
    // and nullable so a caller cannot silently default a tamper signal to "no drift".
    recipientPinDrift: null,
  };
}

async function main(): Promise<void> {
  const signerSeed = rand(64);
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);
  verifierFrom(signer); // pin a verifier once to prove the keys load (verifyAtSeal loads its own)

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  const records = Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS }));
  // The total plaintext byte count (what the seal driver passes as plaintextBytes).
  const totalBytes = records.reduce((n, r) => n + r.value.length, 0);

  // freshArchiveWithMaster is freshArchive plus the master it sealed with. The production seal paths hand
  // that master to verify-at-seal so a break-glass-only downpipe can reach the keyed decrypt tier without
  // any in-account recipient private; scenario 2c drives exactly that.
  async function freshArchiveWithMaster(): Promise<{ map: Map<string, Uint8Array>; master: Uint8Array }> {
    const master = rand(32);
    const map = await buildArchive({
      downpipeId: "dp_seal",
      downpipeName: "seal-test",
      cadence: "3600s",
      runId: RUN_ID,
      master,
      recipients: [breakGlass.entry, op.entry],
      signer,
      records,
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
    return { map, master };
  }

  async function freshArchive(): Promise<Map<string, Uint8Array>> {
    return buildArchive({
      downpipeId: "dp_seal",
      downpipeName: "seal-test",
      cadence: "3600s",
      runId: RUN_ID,
      master: rand(32),
      recipients: [breakGlass.entry, op.entry],
      signer,
      records,
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
  }

  const envOp = { SCHEDULER: {} as unknown as DurableObjectNamespace, SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64 } as unknown as Env;
  const envBgOnly = { SCHEDULER: {} as unknown as DurableObjectNamespace, SIGNER_PRIVATE: signerPrivateB64 } as unknown as Env;

  // ---- SCENARIO 1: good small run + operational key -> verified, FULL coverage, no writes -------
  // A small run (well within SEAL_VERIFY_FULL_BYTES) decrypts EVERY record at seal time,
  // so a flipped byte in ANY record is caught now, not only if it landed in the old strided sample.
  console.log("scenario-1: good small run + operational key -> full-coverage verified");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    const v = await verifyAtSeal(envOp, dest, RUN_ID, totalBytes);
    ok("verdict is verified", v.status === "verified");
    ok("tier is full (small run -> full coverage)", v.tier === "full");
    ok("EVERY record was decrypt-checked (full coverage)", v.sampled === records.length);
    ok("no reason on a verified verdict", v.reason === undefined);
    // tier0-only-reason-unknown: a verdict that RAN the decrypt sample (tier full/sampled-decrypt) is NOT
    // an intentional-Tier-0 posture, so it carries no tier0Cause (the enum rides ONLY the Tier-0 return).
    ok("no tier0Cause on a full/sampled verdict", v.tier0Cause === undefined);
    // The operational posture is unchanged and still opens through the capsule, which is what proves the
    // recipient wrap written into this root actually opens. That property is the reason the master path is
    // a FALLBACK rather than the preference.
    ok("via is 'recipient': the operational key decapsulated the wrap", v.via === "recipient");
    ok("verify wrote/deleted NOTHING (read-only)", dest.mutateLog.length === 0);
  }

  // ---- SCENARIO 2: good run, break-glass-only -> Tier-0 only, verified, sampled 0 -------------
  console.log("scenario-2: good run, break-glass-only -> Tier-0 verified");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    const v = await verifyAtSeal(envBgOnly, dest, RUN_ID, totalBytes);
    ok("verdict is verified", v.status === "verified");
    ok("tier is tier-0 (no in-account read-back key)", v.tier === "tier-0");
    ok("sampled is 0 on a break-glass-only downpipe (honest: no decrypt)", v.sampled === 0);
    // tier0-only-reason-unknown: the honest cause is break-glass (no in-account read-back key). This
    // takes precedence over the other two causes (with no key there is no sample to run at all).
    ok("tier0Cause is break-glass (no operational read-back key)", v.tier0Cause === "break-glass");
    ok("verify wrote/deleted NOTHING", dest.mutateLog.length === 0);
  }

  // ---- SCENARIO 2c: break-glass-only + the run's OWN master -> full keyed tier ----------------
  // The point of the operational-key reduction: the same estate as scenario 2, holding NO in-account
  // recipient private, reaches the FULL decrypt tier purely because the seal path passed in the master it
  // had in scope anyway. Scenario 2 stays as the honest Tier-0 case for when no master is supplied, so the
  // two together pin the whole gate: the tier now follows "can I reach this run's master", not "do I hold
  // the operational key".
  console.log("scenario-2c: good run, break-glass-only + supplied master -> FULL keyed tier");
  {
    const dest = new SpyDestination();
    const { map, master } = await freshArchiveWithMaster();
    dest.seed(map);
    const v = await verifyAtSeal(envBgOnly, dest, RUN_ID, totalBytes, master);
    ok("verdict is verified", v.status === "verified");
    ok("tier is FULL, not tier-0, with no operational key present", v.tier === "full");
    ok("EVERY record was decrypt-checked from the run's own master", v.sampled === records.length);
    ok("no tier0Cause (the decrypt tier ran, so it is not an intentional Tier-0)", v.tier0Cause === undefined);
    // The honesty field. This verdict looks identical to a two-recipient estate's "full" verdict, and it
    // proves something different: the bytes decrypt, but no recipient wrap was touched, so nothing here
    // says the operational wrap opens. A reader must be able to tell those apart.
    ok("via is 'master': the run was opened from the seal path's own master, not by decapsulating a wrap", v.via === "master");
    ok("verify wrote/deleted NOTHING (still read-only)", dest.mutateLog.length === 0);

    // A WRONG master must not read as tampering. It fails the run key commitment, which the shared
    // classifier maps to "signature check failed" -- the most serious reason, retryable, and escalated to
    // a critical tamper alert. On the master arm that would blame the customer's archive for the engine's
    // own bug, so it is reclassified and made non-retryable.
    const dest2 = new SpyDestination();
    const { map: map2 } = await freshArchiveWithMaster();
    dest2.seed(map2);
    const bad = await verifyAtSeal(envBgOnly, dest2, RUN_ID, totalBytes, rand(32));
    ok("a WRONG master is suspect, not a fabricated pass", bad.status === "suspect");
    ok("it reads as an engine key fault, NOT 'signature check failed'", bad.reason === "engine key fault");
    ok("and it is not retried (attempts stays at 1)", bad.attempts === undefined || bad.attempts === 1);
  }

  // ---- SCENARIO 2d: too many shards -> Tier-0, because BOTH passes walk the shard list ---------
  // Tier-0 walks the shards, then the decrypt tier's openRun walks them AGAIN with no sampling of its own.
  // The 900-shard Tier-0 figure was derived for one walk against the ~1000 platform cap; the second walk
  // was never in that arithmetic. Past the ceiling the decrypt pass could not complete anyway, and the
  // failure mode is the bad one: a cap trip is fail-open, so it surfaces as SUSPECT plus a critical alert
  // on an archive that is perfectly intact.
  console.log("scenario-2d: shard count over the decrypt budget -> Tier-0, not a cap trip");
  {
    const dest = new SpyDestination();
    const { map, master } = await freshArchiveWithMaster();
    dest.seed(map);
    // A ceiling of 0 puts any run over budget, which exercises the guard without needing a huge fixture.
    const v = await verifyAtSeal({ ...envBgOnly, SEAL_VERIFY_DECRYPT_MAX_SHARDS: "0" } as typeof envBgOnly, dest, RUN_ID, totalBytes, master);
    ok("verdict is still verified (Tier-0 passed; this is a budget decision, not a fault)", v.status === "verified");
    ok("tier is tier-0", v.tier === "tier-0");
    ok("and it says WHY, so a support read does not mistake it for a posture or a knob", v.tier0Cause === "too-many-shards");
    ok("no records were decrypt-checked", v.sampled === 0);
  }

  // ---- SCENARIO 2b: MISSING root manifest -> OBJECT-MISSING sub-class, NOT signature ----------
  // attestKeyless returns signatureValid:false for BOTH a true signature-verify failure AND a missing/
  // unreadable root manifest ("root manifest or signature missing"). The latter must NOT be reported as
  // "signature check failed" (which advises an authenticity/posture review + "do NOT re-run, bytes not
  // deleted") -- it is a missing-OBJECT problem (re-running re-seals it, the bytes are NOT intact). So the
  // !signatureValid branch routes a missing root through coarseVerifyReason -> "object missing".
  // A missing root must never be mistaken for a signature failure.
  console.log("scenario-2b: missing root manifest -> object-missing (not signature)");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    await dest.delete(`run/${RUN_ID}/root.manifest.json`);
    dest.mutateLog.length = 0; // ignore the setup delete; assert verify itself writes/deletes nothing
    const v = await verifyAtSeal(envOp, dest, RUN_ID, totalBytes);
    ok("verdict is suspect (the root manifest is gone)", v.status === "suspect");
    ok("a missing root is the OBJECT-MISSING reason, NOT 'signature check failed'", v.reason === "object missing");
    ok("verify wrote/deleted NOTHING (fail-open, read-only)", dest.mutateLog.length === 0);
  }

  // scenario-2c: a COLD-storage-class archive (bucket-lifecycle-to-glacier) -> a distinct `thaw-needed`
  // verdict reason. A bucket lifecycle rule silently transitioned the just-written archive to a cold class,
  // so the read-back GET fails on an object that IS present + recoverable but unreadable until restored. The
  // verdict reason must read `thaw-needed` (the actionable cause) — NOT a generic destination-access error —
  // and, since a read-after-write retry can never thaw it, the verify surfaces the suspect on the FIRST
  // attempt (thaw-needed is non-retryable), fail-open (no throw, no mutation). This rides into the support
  // pack via sealVerification.reason, so no new pack surface is needed.
  console.log("scenario-2c: cold-storage-class archive -> thaw-needed (bucket-lifecycle-to-glacier)");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    dest.mutateLog.length = 0;
    dest.thawNeeded = true;
    let threw = false;
    let v: SealVerification | undefined;
    try {
      v = await verifyAtSeal(envOp, dest, RUN_ID, totalBytes);
    } catch {
      threw = true;
    }
    ok("verify did NOT throw on a cold-storage archive (fail-open)", !threw && v !== undefined);
    ok("verdict is suspect (the archive cannot be read back)", v?.status === "suspect");
    ok("the reason is the actionable thaw-needed, NOT a generic destination-access error", v?.reason === "thaw-needed");
    ok("thaw-needed is non-retryable -> the suspect surfaces on the FIRST attempt", v?.attempts === 1);
    ok("verify wrote/deleted NOTHING on a cold archive (fail-open, read-only)", dest.mutateLog.length === 0);
  }

  // ---- SCENARIO 3: corrupted shard -> suspect, fail-open, posture + notification --------------
  console.log("scenario-3: corrupted shard -> suspect (fail-open) + posture + notification");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    const segsBefore = dest.countSegments();
    const tamperedKey = dest.tamperShard();
    dest.mutateLog.length = 0; // only count verify-induced mutations from here

    let threw = false;
    let v: SealVerification | undefined;
    try {
      v = await verifyAtSeal(envOp, dest, RUN_ID, totalBytes);
    } catch {
      threw = true;
    }
    ok("verify did NOT throw (fail-open)", !threw && v !== undefined);
    ok("verdict is suspect", v?.status === "suspect");
    ok("suspect carries a coarse, secret-free reason", typeof v?.reason === "string" && v!.reason!.length > 0 && !v!.reason!.includes(tamperedKey));
    ok("the tampered archive object was NOT deleted (fail-open)", dest.has(tamperedKey));
    ok("verify deleted NOTHING and wrote NOTHING", dest.mutateLog.length === 0);
    ok("every segment object is still present (nothing removed)", dest.countSegments() === segsBefore);

    // The suspect verdict raises a CRITICAL posture finding (computePosture seal-verification).
    const failReport = computePosture(basePostureInput([{ id: "dp_seal", name: "seal-test", lastSealVerifyOk: false, lastSealVerifyAt: v!.at }]), Date.now());
    const sealCheckFail = failReport.checks.find((c) => c.id === "seal-verification");
    ok("posture has a seal-verification check", sealCheckFail !== undefined);
    ok("the seal-verification check is critical", sealCheckFail?.severity === "critical");
    ok("the seal-verification check FAILS on a suspect last verdict", sealCheckFail?.status === "fail");

    // A verified last verdict (or absence) PASSES the same check (negative control).
    const passReport = computePosture(basePostureInput([{ id: "dp_seal", name: "seal-test", lastSealVerifyOk: true, lastSealVerifyAt: Date.now() }]), Date.now());
    ok("the seal-verification check PASSES on a verified last verdict", passReport.checks.find((c) => c.id === "seal-verification")?.status === "pass");
    const absentReport = computePosture(basePostureInput([{ id: "dp_seal", name: "seal-test" }]), Date.now());
    ok("the seal-verification check PASSES when no verdict exists yet (feature off / fresh)", absentReport.checks.find((c) => c.id === "seal-verification")?.status === "pass");

    // The notification: sealVerifyEmission is a CRITICAL restore-test-fail, and routeSealVerifyAlert
    // reaches the notify route and delivers when a channel resolves.
    const emission = sealVerifyEmission("dp_seal", "seal-test", v!);
    ok("the emission is critical severity", emission.severity === "critical");
    ok("the emission uses the restore-test-fail event", emission.event === "restore-test-fail");
    ok("the emission detail carries no raw object key", !emission.detail.includes(tamperedKey));

    const channel: NotifyChannel = { id: "ch1", kind: "webhook", name: "test", url: "https://example.test/hook", enabled: true, createdAt: "2026-06-07T00:00:00.000Z" };
    const sched = new FakeScheduler([channel]);
    await routeSealVerifyAlert(envOp, sched as unknown as DurableObjectStub, emission);
    // The notification FIRES: it reaches /notify/resolve and (a channel having resolved) attempts
    // delivery and posts the per-channel outcomes back to /notify/record. The actual webhook POST is
    // best-effort and has no network here, so we assert the FIRING PATH (resolve + record), not a
    // successful outbound POST. Delivery itself is fail-open by design. /notify/record is
    // fire-and-forget, so allow a microtask for it to land.
    await new Promise((r) => setTimeout(r, 0));
    ok("the alert reached the notify resolve route", sched.calls.includes("/notify/resolve"));
    ok("the alert attempted delivery and recorded the outcome (notification fired)", sched.calls.includes("/notify/record"));
    ok("the resolve was asked about the critical seal-verify emission", sched.lastResolveEmission?.event === "restore-test-fail" && sched.lastResolveEmission?.severity === "critical");

    // routeSealVerifyAlert is fail-open: a throwing scheduler degrades to not-delivered, never escapes.
    const throwing = { fetch: async () => { throw new Error("scheduler down"); } } as unknown as DurableObjectStub;
    let alertThrew = false;
    try {
      const r = await routeSealVerifyAlert(envOp, throwing, emission);
      ok("a failing notify route degrades to delivered:false (fail-open)", r.delivered === false);
    } catch {
      alertThrew = true;
    }
    ok("the alert never throws even when the scheduler is down", !alertThrew);
  }

  // ---- SCENARIO 4: truncated segment -> caught by the decrypt sample, suspect, fail-open ------
  console.log("scenario-4: truncated segment -> sampled-decrypt catches it (fail-open)");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    const segKey = dest.firstSegmentKey();
    const segBytes = (await dest.get(segKey))!.body;
    // Lop the last STREAM chunk (CHUNK_SIZE+TAG, but these small records are one chunk; remove the
    // final 32 bytes of ciphertext+tag so the stream no longer authenticates / the count is wrong).
    const truncated = segBytes.subarray(0, Math.max(0, segBytes.length - 32));
    // Replace the object directly (a corrupt write that LANDED), bypassing the mutate log.
    await dest.put(segKey, truncated);
    dest.mutateLog.length = 0;

    let threw = false;
    let v: SealVerification | undefined;
    try {
      v = await verifyAtSeal(envOp, dest, RUN_ID, totalBytes);
    } catch {
      threw = true;
    }
    ok("verify did NOT throw (fail-open)", !threw && v !== undefined);
    ok("verdict is suspect (the decrypt sample caught the truncation)", v?.status === "suspect");
    ok("the truncated segment was NOT deleted (fail-open)", dest.has(segKey));
    ok("verify deleted NOTHING and wrote NOTHING", dest.mutateLog.length === 0);
  }

  // ---- SCENARIO 5: the feature gate (default ON; explicit falsey disables) --------------------
  console.log("scenario-5: VERIFY_AT_SEAL gate (default ON)");
  {
    ok("default (unset) is ON", verifyAtSealEnabled(envOp) === true);
    ok('"off" disables it', verifyAtSealEnabled({ ...envOp, VERIFY_AT_SEAL: "off" } as Env) === false);
    ok('"0" disables it', verifyAtSealEnabled({ ...envOp, VERIFY_AT_SEAL: "0" } as Env) === false);
    ok('"false" disables it', verifyAtSealEnabled({ ...envOp, VERIFY_AT_SEAL: "false" } as Env) === false);
    ok('"on" / any other value keeps it ON', verifyAtSealEnabled({ ...envOp, VERIFY_AT_SEAL: "on" } as Env) === true);
  }

  // ---- SCENARIO 6: the size threshold forces Tier-0 only even with the operational key --------
  console.log("scenario-6: SEAL_VERIFY_MAX_BYTES forces Tier-0 on a large run");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    // Pass a plaintextBytes ABOVE a tiny SEAL_VERIFY_MAX_BYTES so the decrypt sample is skipped.
    const env = { ...envOp, SEAL_VERIFY_MAX_BYTES: "1" } as Env;
    const v = await verifyAtSeal(env, dest, RUN_ID, totalBytes);
    ok("a run over the size threshold verifies at Tier-0 only", v.status === "verified" && v.tier === "tier-0" && v.sampled === 0);
    // tier0-only-reason-unknown: the operational key IS held here, so the cause is the run being over
    // SEAL_VERIFY_MAX_BYTES ("too-large"), NOT break-glass -- the diagnosis a bare tier:"tier-0" could not give.
    ok("tier0Cause is too-large (run over SEAL_VERIFY_MAX_BYTES)", v.tier0Cause === "too-large");
    ok("verify still wrote/deleted NOTHING", dest.mutateLog.length === 0);

    // And SEAL_VERIFY_SAMPLE=0 turns the decrypt sample off (Tier-0 only) even under the threshold.
    const dest2 = new SpyDestination();
    dest2.seed(await freshArchive());
    const v2 = await verifyAtSeal({ ...envOp, SEAL_VERIFY_SAMPLE: "0" } as Env, dest2, RUN_ID, totalBytes);
    ok("SEAL_VERIFY_SAMPLE=0 yields Tier-0 only", v2.status === "verified" && v2.tier === "tier-0" && v2.sampled === 0);
    // tier0-only-reason-unknown: an operator-disabled sample under the size threshold is "sample-off".
    ok("tier0Cause is sample-off (SEAL_VERIFY_SAMPLE=0)", v2.tier0Cause === "sample-off");
  }

  // ---- SCENARIO 7: SEAL_VERIFY_FULL_BYTES gates full coverage; full coverage catches a late record
  // Full coverage decrypts every record (so a flipped byte in a record the strided sample would
  // skip is caught at seal time). Setting SEAL_VERIFY_FULL_BYTES=0 reverts to the bounded strided
  // sample (the cost ceiling for large runs is preserved).
  console.log("scenario-7: SEAL_VERIFY_FULL_BYTES gates full coverage (default on; 0 reverts to sample)");
  {
    // With full coverage disabled (threshold 0), the run falls back to the strided sample (<= 3).
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    const vSample = await verifyAtSeal({ ...envOp, SEAL_VERIFY_FULL_BYTES: "0" } as Env, dest, RUN_ID, totalBytes);
    ok("threshold 0 -> strided sample tier", vSample.status === "verified" && vSample.tier === "sampled-decrypt");
    ok("the strided sample is bounded (sampled <= default 3 < record count)", vSample.sampled <= 3 && vSample.sampled < records.length);

    // Full coverage (default) catches a corruption that the head-biased strided sample could miss:
    // corrupt the LAST segment object in the store and confirm the seal verify goes suspect. Because
    // full coverage decrypts every record, a corruption anywhere is caught regardless of position.
    const dest2 = new SpyDestination();
    dest2.seed(await freshArchive());
    const segKeys = await dest2.list("seg/");
    const lastSeg = segKeys[segKeys.length - 1]!;
    const segBytes = (await dest2.get(lastSeg))!.body;
    const corrupt = new Uint8Array(segBytes);
    flipBit(corrupt, corrupt.length - 1); // flip a tag byte so AEAD fails on that record
    await dest2.put(lastSeg, corrupt);
    dest2.mutateLog.length = 0;
    const vFull = await verifyAtSeal(envOp, dest2, RUN_ID, totalBytes);
    ok("full coverage catches a corrupted (potentially non-sampled) record -> suspect", vFull.status === "suspect");
    ok("the suspect verdict is the full-coverage tier", vFull.tier === "full");
    ok("full-coverage verify wrote/deleted NOTHING (fail-open)", dest2.mutateLog.length === 0 && dest2.has(lastSeg));
  }

  // ---- SCENARIO 7b: the strided sample's `sampled` count must be EARNED ---------------------------
  // Everything above drives the FULL tier. The strided tier is what every run over
  // SEAL_VERIFY_FULL_BYTES (64 MiB) gets, which is to say the large customers, and nothing asserted
  // that its sample decrypts anything at all.
  //
  // Measured, and this is the reason for the scenario rather than its motivation. `sampled` is a
  // counter incremented BESIDE the decrypt rather than derived from it, so three separate mutations
  // of the strided loop reported `sampled: 3` having verified nothing, and every one of them survived
  // this file and its three siblings:
  //   deleting `await run.restoreRecord(...)`, dropping only the `await`, and re-reading
  //   `run.records[0]` on every iteration instead of `run.records[i]`.
  // The first two turn a corrupt segment from "suspect" into "verified" on a run of any size above the
  // threshold. Reported clean, they read exactly like a real verification.
  //
  // A COUNT CANNOT BE ASSERTED AGAINST ITSELF, so this measures coverage from the outside: corrupt one
  // segment at a time in an otherwise identical archive and count how many of them the strided verify
  // actually notices. A sample that genuinely decrypts N records must go suspect for at least N
  // distinct segments. One that decrypts nothing notices none; one that re-reads record 0 every
  // iteration notices exactly one.
  console.log("scenario-7b: the strided sample's reported count is earned, not asserted");
  {
    const snapshot = await freshArchive();
    const segKeys = [...snapshot.keys()].filter((k) => k.startsWith("seg/") && k.endsWith(".seg"));
    ok(`the fixture has one segment per record (${segKeys.length} segments, ${records.length} records)`, segKeys.length === records.length && segKeys.length >= 3);

    const clean = await verifyAtSeal({ ...envOp, SEAL_VERIFY_FULL_BYTES: "0" } as Env, (() => { const d = new SpyDestination(); d.seed(new Map(snapshot)); return d; })(), RUN_ID, totalBytes);
    ok("the clean archive verifies at the strided tier", clean.status === "verified" && clean.tier === "sampled-decrypt");
    ok("the strided tier reports a non-zero sample", clean.sampled > 0);

    let noticed = 0;
    for (const seg of segKeys) {
      const d = new SpyDestination();
      d.seed(new Map(snapshot));
      const body = (await d.get(seg))!.body;
      const corrupt = new Uint8Array(body);
      flipBit(corrupt, corrupt.length - 1); // a tag byte, so the AEAD fails on that record alone
      await d.put(seg, corrupt);
      d.mutateLog.length = 0;
      const v = await verifyAtSeal({ ...envOp, SEAL_VERIFY_FULL_BYTES: "0" } as Env, d, RUN_ID, totalBytes);
      if (v.status === "suspect") noticed++;
      ok(`corrupting ${seg.slice(0, 12)} leaves the strided verify fail-open (wrote and deleted nothing)`, d.mutateLog.length === 0);
    }
    ok(`the strided sample NOTICED a corruption in at least as many segments as it claims to have sampled (${noticed} noticed, ${clean.sampled} claimed)`, noticed >= clean.sampled);
    ok("and it did NOT notice every segment, so the bounded sample really is bounded", noticed < segKeys.length);
  }

  // ---- SCENARIO 7a: Fix-A bounded Tier-0 shard re-read wires through verifyAtSeal -------------------
  // Fix-A bounds the ALWAYS-run Tier-0 keyless completeness re-read: above SEAL_VERIFY_FULL_SHARDS only a
  // strided SEAL_VERIFY_SHARD_SAMPLE of shards is re-read, so a very large run's at-seal verify cannot trip
  // the subrequest cap (the live "reported-failed-forever at ~970 shards" wedge). The root signature still
  // authenticates the whole shard listing. This proves the production entry point honours the knob: forcing
  // the bounded path on this archive (FULL_SHARDS=0) still returns verified, and SHARD_SAMPLE=0 (read no
  // shards, signature-only completeness) does too. The unchanged default keeps every run today FULL.
  console.log("scenario-7a: Fix-A SEAL_VERIFY_FULL_SHARDS bounds the Tier-0 shard re-read (still verified)");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    const vBounded = await verifyAtSeal({ ...envOp, SEAL_VERIFY_FULL_SHARDS: "0", SEAL_VERIFY_SHARD_SAMPLE: "1" } as Env, dest, RUN_ID, totalBytes);
    ok("Fix-A: forcing the bounded shard re-read still verifies the archive", vBounded.status === "verified");

    const dest2 = new SpyDestination();
    dest2.seed(await freshArchive());
    const vNone = await verifyAtSeal({ ...envOp, SEAL_VERIFY_FULL_SHARDS: "0", SEAL_VERIFY_SHARD_SAMPLE: "0" } as Env, dest2, RUN_ID, totalBytes);
    ok("Fix-A: sample 0 above the threshold verifies on the signature alone (completeness still attested)", vNone.status === "verified");
    ok("Fix-A: the bounded Tier-0 re-read wrote/deleted NOTHING (read-only)", dest.mutateLog.length === 0 && dest2.mutateLog.length === 0);
  }

  // captureLog runs fn with console.error/console.warn intercepted, returning the lines log() emitted
  // (level routed: error->console.error, warn->console.warn). The engine's structured logger writes a
  // JSON line whose human message is in the "event" field, so the tests assert on that field.
  async function captureLog<T>(fn: () => Promise<T>): Promise<{ result: T; errors: string[]; warns: string[] }> {
    const errors: string[] = [];
    const warns: string[] = [];
    const origErr = console.error;
    const origWarn = console.warn;
    const eventOf = (args: unknown[]): string => {
      try { return (JSON.parse(String(args[0])) as { event?: string }).event ?? String(args[0]); } catch { return String(args[0]); }
    };
    console.error = (...args: unknown[]): void => { errors.push(eventOf(args)); };
    console.warn = (...args: unknown[]): void => { warns.push(eventOf(args)); };
    try {
      const result = await fn();
      return { result, errors, warns };
    } finally {
      console.error = origErr;
      console.warn = origWarn;
    }
  }

  // ---- SCENARIO 8: transient-then-consistent read -> self-heals, no suspect (truth-table row 1) --
  console.log("scenario-8: transient read-after-write 404 then consistent -> recovered verified, no suspect");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    dest.transientFailsRemaining = 1; // attempt-1's first read 404s (a just-written object lag), then heals
    const { result: v, errors, warns } = await captureLog(() => verifyAtSeal({ ...envOp, SEAL_VERIFY_ATTEMPTS: "3" } as Env, dest, RUN_ID, totalBytes));
    ok("verdict is verified (the retry rode out the lag)", v.status === "verified");
    ok("recovered:true (an attempt-1 consistency failure healed on a retry)", v.recovered === true);
    ok("attempts records the actual try count (>1, <=3)", typeof v.attempts === "number" && v.attempts! > 1 && v.attempts! <= 3);
    ok("NO suspect error line was emitted (no false alarm)", errors.filter((e) => e.includes("verify-at-seal SUSPECT")).length === 0);
    ok("exactly one transient-recovered warn line (self-heal is never silent)", warns.filter((w) => w.includes("verify-at-seal transient-recovered")).length === 1);
    ok("the recovered warn does NOT carry the counted hyphenated reason token", warns.every((w) => !/-check-failed/.test(w)));
    ok("verify wrote/deleted NOTHING", dest.mutateLog.length === 0);
  }

  // ---- SCENARIO 9: permanently-bad object -> still suspect after exactly N (truth-table row 2) ----
  console.log("scenario-9: permanently-tampered shard -> suspect after exactly N, one SUSPECT error line");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    dest.tamperShard(); // a real corruption: fails EVERY re-verify, never heals
    dest.mutateLog.length = 0;
    const N = 2;
    const { result: v, errors, warns } = await captureLog(() => verifyAtSeal({ ...envOp, SEAL_VERIFY_ATTEMPTS: String(N) } as Env, dest, RUN_ID, totalBytes));
    ok("verdict is suspect (a real corruption survives the bounded retries)", v.status === "suspect");
    ok("attempts === N (the configured bound was exhausted)", v.attempts === N);
    // A flipped shard byte breaks the Tier-0 keyless COMPLETENESS check (att.complete === false), now
    // sub-classified as "completeness check failed" rather than collapsed into the generic integrity bucket
    // -- so the consumer can tell a missing/mismatched shard from a signature/authenticity failure.
    ok("the suspect reason is the COMPLETENESS sub-class (not the generic integrity bucket)", v.reason === "completeness check failed");
    ok("exactly one SUSPECT error line (final verdict, not per-attempt noise)", errors.filter((e) => e.includes("verify-at-seal SUSPECT")).length === 1);
    ok("the SUSPECT line carries attempts=N and the hyphenated reason", errors.some((e) => e.includes(`attempts=${N}`) && e.includes("completeness-check-failed")));
    ok("no transient-recovered warn on a genuine failure", warns.filter((w) => w.includes("transient-recovered")).length === 0);
    ok("verify deleted NOTHING and wrote NOTHING (fail-open)", dest.mutateLog.length === 0);
  }

  // ---- SCENARIO 10: a config fault is NOT retried (non-retryable reason -> attempts:1) -------------
  console.log("scenario-10: engine-not-configured is non-retryable -> attempts:1 even with N high");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    // No SIGNER_PRIVATE -> setup throws "missing required configuration" -> "engine not fully
    // configured", which never heals, so the loop surfaces it immediately without burning retries.
    const envNoSigner = { SCHEDULER: {} as unknown as DurableObjectNamespace } as unknown as Env;
    const { result: v } = await captureLog(() => verifyAtSeal({ ...envNoSigner, SEAL_VERIFY_ATTEMPTS: "5" } as Env, dest, RUN_ID, totalBytes));
    ok("verdict is suspect", v.status === "suspect");
    ok("reason is engine not fully configured", v.reason === "engine not fully configured");
    ok("attempts === 1 (non-retryable break, NOT the configured max of 5)", v.attempts === 1);
  }

  // ---- SCENARIO 11: SEAL_VERIFY_ATTEMPTS=1 is the exact pre-retry rollback ------------------------
  console.log("scenario-11: SEAL_VERIFY_ATTEMPTS=1 -> single attempt, no retry (exact rollback)");
  {
    const dest = new SpyDestination();
    dest.seed(await freshArchive());
    dest.tamperShard();
    const { result: v, errors } = await captureLog(() => verifyAtSeal({ ...envOp, SEAL_VERIFY_ATTEMPTS: "1" } as Env, dest, RUN_ID, totalBytes));
    ok("verdict is suspect on a single read", v.status === "suspect");
    ok("attempts === 1 (no retry)", v.attempts === 1);
    ok("one SUSPECT error line", errors.filter((e) => e.includes("verify-at-seal SUSPECT")).length === 1);

    // And a healthy run at =1 returns a clean verified verdict with NO attempts/recovered fields, so a
    // row looks byte-for-byte like today (no console/posture coordination needed).
    const dest2 = new SpyDestination();
    dest2.seed(await freshArchive());
    const v2 = await verifyAtSeal({ ...envOp, SEAL_VERIFY_ATTEMPTS: "1" } as Env, dest2, RUN_ID, totalBytes);
    ok("a healthy first-try verified verdict carries no attempts/recovered fields", v2.status === "verified" && v2.attempts === undefined && v2.recovered === undefined);
  }

  // resolveSealVerifyKnobs (Phase 3 support-pack: seal-verify-knobs-invisible / verify-at-seal-disabled).
  // The pure knob resolver the support pack surfaces MUST stay in lockstep with the values verifyAtSealOnce
  // actually uses (defaults + clamps). Pin the documented defaults on an empty env, the OFF case, and the
  // clamp/floor edges on abusive input, so the pack can never report a knob the seal path did not use.
  {
    const defaults = resolveSealVerifyKnobs({} as Env);
    ok("knobs default: verify-at-seal ON", defaults.enabled === true);
    ok("knobs default: sample 3", defaults.sample === 3);
    ok("knobs default: maxBytes 5 GiB", defaults.maxBytes === 5 * 1024 * 1024 * 1024);
    ok("knobs default: fullBytes 64 MiB", defaults.fullBytes === 64 * 1024 * 1024);
    ok("knobs default: attempts 3", defaults.attempts === 3);
    ok("knobs default: fullShards 900", defaults.fullShards === 900);
    ok("knobs default: shardSample 64", defaults.shardSample === 64);

    const off = resolveSealVerifyKnobs({ VERIFY_AT_SEAL: "off" } as Env);
    ok("knobs: VERIFY_AT_SEAL=off resolves enabled=false", off.enabled === false);

    // Abusive / out-of-range values clamp exactly as the path clamps (sample->50, attempts->8, shards->5000,
    // shardSample->256); a malformed value falls back to the default; attempts is floored to >=1.
    const clamped = resolveSealVerifyKnobs({ SEAL_VERIFY_SAMPLE: "9999", SEAL_VERIFY_ATTEMPTS: "9999", SEAL_VERIFY_FULL_SHARDS: "999999", SEAL_VERIFY_SHARD_SAMPLE: "9999", SEAL_VERIFY_MAX_BYTES: "not-a-number" } as Env);
    ok("knobs clamp: sample -> 50 (SEAL_VERIFY_SAMPLE_MAX)", clamped.sample === 50);
    ok("knobs clamp: attempts -> 8 (SEAL_VERIFY_ATTEMPTS_MAX)", clamped.attempts === 8);
    ok("knobs clamp: fullShards -> 5000 (SEAL_VERIFY_FULL_SHARDS_MAX)", clamped.fullShards === 5000);
    ok("knobs clamp: shardSample -> 256 (SEAL_VERIFY_SHARD_SAMPLE_MAX)", clamped.shardSample === 256);
    ok("knobs: a malformed value falls back to the default (maxBytes 5 GiB)", clamped.maxBytes === 5 * 1024 * 1024 * 1024);
    const zeroAttempts = resolveSealVerifyKnobs({ SEAL_VERIFY_ATTEMPTS: "0" } as Env);
    ok("knobs: attempts is floored to >=1 (matches maxAttempts Math.max(1,...))", zeroAttempts.attempts === 1);
  }

  console.log(failures === 0 ? "\nVERIFY-AT-SEAL PASS (good runs verify; corrupt/truncated writes are caught suspect, fail-open, posture + notification)" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
