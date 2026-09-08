// Prove the restore drill (engine/src/admin/drill.ts) against a real in-memory
// archive. The drill is the in-account read-back check (SPEC 12.6): it opens a sealed run
// with the operational private key, verifies the chain and restores a sample record, then
// reports a coarse result without throwing. Four scenarios are covered:
//
//   1. Healthy archive + operational key  -> ok:true, expected verified counts, no write.
//   2. No operational key (break-glass-only posture) -> ok:false with the posture message,
//      no throw.
//   3. Tampered manifest (merkleRoot field flipped) -> the signature check fires first
//      (the manifest bytes changed), ok:false with reason "integrity check failed", no throw.
//   4. Tampered segment bytes -> the AEAD authentication tag check fires inside
//      restoreRecord (openRun succeeds; openNonSecretSegment fails), ok:false with reason
//      "integrity check failed", no throw. This is the leaf/segment integrity path: each
//      segment is encrypted under a key derived from its segment ID, so any byte flip
//      causes AES-GCM authentication to fail, proving that segment-level corruption is
//      detected when the signature is still valid. A PRESENT-but-corrupt segment is a
//      DAMAGED backup (an INTEGRITY fault), NOT an availability fault: the reader now
//      re-labels a decrypt/AEAD/framing failure of already-fetched bytes as a structured
//      integrity failure, so classifyDrillError -> classifyRestoreFailure returns the
//      non-fallback "integrity check failed" -- matching the MISSING-segment
//      classification and the restore apply/verify passes. (Before the
//      reader re-labelled it, the raw AES-GCM OperationError matched no integrity keyword
//      and fell through to the availability catch-all "recovery check failed", so a
//      present-but-corrupt backup wrongly read as availability -- the drill vs offline-Go
//      classification mismatch this scenario now guards.)
//
// Run:  node test/validate-drill.ts
// In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom, } from "../src/keys-env.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { runDrill, RESTORE_OOM_SAFE_BYTES } from "../src/admin/drill.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { flipBit } from "./memdest.ts";

// ---- helpers ----------------------------------------------------------------

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_drill";
const KVSET: Record<string, string> = {
  "key:alpha": "value-alpha",
  "key:beta": "value-beta-longer",
  "key:gamma": "gamma-value",
};

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// makeRecipient builds a hybrid recipient entry and the 96-byte private identity
// (x25519 scalar(32) || ML-KEM seed(64)), matching the idiom in validate-restore.ts.
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } },
    identity: concat(xk.secretKey, seed),
  };
}

// SpyDestination wraps a MemoryDestination and records every put/putStream/putConditional
// call so the test can assert the drill wrote nothing back.
class SpyDestination implements Destination {
  private store = new Map<string, Uint8Array>();
  readonly putLog: string[] = [];

  async get(key: string): Promise<GetResult | null> {
    const v = this.store.get(key);
    return v ? { body: v, etag: `"${key.length}"` } : null;
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    this.putLog.push(`put:${key}`);
    this.store.set(key, body);
  }

  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    // Drain the stream (so any upstream logic completes) but still log the attempt.
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
    this.putLog.push(`putStream:${key}`);
    this.store.set(key, merged);
  }

  async putConditional(key: string, body: Uint8Array, _opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    this.putLog.push(`putConditional:${key}`);
    const etag = `"${key.length}"`;
    this.store.set(key, body);
    return { ok: true, etag };
  }

  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }

  async delete(key: string): Promise<void> {
    this.putLog.push(`delete:${key}`);
    this.store.delete(key);
  }

  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix));
  }

  // seed populates the destination from the archive map returned by buildArchive.
  seed(archive: Map<string, Uint8Array>): void {
    for (const [k, v] of archive) this.store.set(k, v);
    // The put log is not poisoned by seeding (seeding is not a drill write).
    this.putLog.length = 0;
  }

  // tamperManifest flips one byte in the root manifest's merkleRoot hex string. The
  // manifest bytes are signed, so changing any field (including merkleRoot) invalidates
  // the Ed25519+ML-DSA signature. The drill's signature check fires FIRST, before the
  // Merkle recomputation is reached. This is by design: the signature is over the whole
  // manifest blob, so a flipped merkleRoot is caught at the signature boundary.
  tamperManifest(): void {
    const key = `run/${RUN_ID}/root.manifest.json`;
    const bytes = this.store.get(key);
    if (!bytes) throw new Error("manifest not in store");
    const text = new TextDecoder().decode(bytes);
    // Flip the last hex digit of the merkleRoot value. The root is canonical JSON so the
    // merkleRoot field is present; switching one hex character invalides the signature.
    const tampered = text.replace(/"merkleRoot":"([0-9a-f]{95})([0-9a-f])"/, (_m, prefix, last) => {
      const flipped = last === "a" ? "b" : "a";
      return `"merkleRoot":"${prefix}${flipped}"`;
    });
    if (tampered === text) throw new Error("tampering regex did not match; update the pattern");
    this.store.set(key, new TextEncoder().encode(tampered));
  }

  // tamperShard corrupts one byte of the FIRST manifest SHARD object (run/<runId>/manifest/<id>.dpe),
  // leaving the root manifest + signature INTACT. So the root signature still verifies, but the shard's
  // recomputed SHA-384 no longer matches the value the signed root pins: openShards throws an integrity
  // error ("shard NNNNN hash does not match the signed root"). This is the SHARD-integrity path (distinct
  // from tamperManifest's signature path and tamperSegment's AEAD path), and it is the RV-CLI drill
  // classification finding: a shard hash mismatch must classify as an INTEGRITY reason, never a generic
  // destination-access error.
  tamperShard(): void {
    let shardKey: string | undefined;
    for (const k of this.store.keys()) {
      if (k.startsWith(`run/${RUN_ID}/manifest/`) && k.endsWith(".dpe")) {
        shardKey = k;
        break;
      }
    }
    if (!shardKey) throw new Error("no manifest shard object found in the store");
    const bytes = this.store.get(shardKey)!;
    const copy = new Uint8Array(bytes);
    // Flip a byte well inside the framed sealed shard body (past the frame header) so the object's SHA-384
    // changes but it is still a plausible object. Any changed byte invalidates the pinned shard SHA-384.
    const at = Math.min(copy.length - 1, 32);
    flipBit(copy, at);
    this.store.set(shardKey, copy);
  }

  // tamperSegment corrupts the first byte of the encrypted payload in the first segment
  // file found in the store (any key matching seg/**/*.seg). Because the segment is sealed
  // with AES-256-GCM, any bit flip in the ciphertext body fails the AEAD authentication
  // tag check inside openNonSecretSegment -> openStream -> aesGcmOpen. The signature over
  // the root manifest remains valid (the segment bytes are not covered by the root
  // signature or by the shard SHA-384; they are only covered by the AEAD tag and by the
  // post-decryption plaintextSha384 check in restoreRecord). openRun therefore succeeds;
  // the failure surfaces when runDrill calls run.restoreRecord(sample).
  tamperSegment(): void {
    let segKey: string | undefined;
    for (const k of this.store.keys()) {
      if (k.startsWith("seg/") && k.endsWith(".seg")) {
        segKey = k;
        break;
      }
    }
    if (!segKey) throw new Error("no segment file found in the store");
    const bytes = this.store.get(segKey)!;
    const copy = new Uint8Array(bytes);
    // The segment layout is: 5-byte header (4-byte magic + 1-byte version), 16-byte payload
    // nonce, then AES-GCM ciphertext chunks. Flip a byte inside the first chunk body (byte
    // 21 onwards) so the AEAD tag verification fails.
    const HEADER = 5;
    const NONCE = 16;
    const PAYLOAD_START = HEADER + NONCE;
    if (copy.length <= PAYLOAD_START) throw new Error("segment file too short to tamper");
    flipBit(copy, PAYLOAD_START);
    this.store.set(segKey, copy);
  }
}

// buildEnv wires a minimal Env from the signer, operational private and the spy destination.
// DEST_KIND:"r2" with a mock R2-surface binding causes buildDestination to choose R2Destination,
// so we need the DEST_R2 binding to be the spy. The R2Destination reads via .get() and writes
// via .put() -- but it wraps an R2Bucket, not a Destination. To avoid that coupling we wire
// DEST_KIND:"s3" and set up the S3 credentials pointing at a no-op URL; that path fails at
// network time, which we don't reach because we directly build the ObjectStore inside runDrill.
//
// runDrill calls buildDestination(env) to get a Destination, then wraps it as ObjectStore.
// To make that work in tests we use a thin R2Bucket-shaped adapter over SpyDestination.
function makeR2Adapter(spy: SpyDestination): R2Bucket {
  // R2Bucket surface the engine uses: get -> R2Object | null, put -> R2Object | null
  // The R2Destination.get calls bucket.get(key) and awaits .arrayBuffer(), then reads .etag.
  // The R2Destination.put calls bucket.put(key, body) -- the return value is not checked.
  return {
    async get(key: string): Promise<R2ObjectBody | null> {
      const r = await spy.get(key);
      if (!r) return null;
      const body = r.body;
      return {
        arrayBuffer: async () => {
          const out = new ArrayBuffer(body.byteLength);
          new Uint8Array(out).set(body);
          return out;
        },
        etag: `${key.length}`,
        httpEtag: `"${key.length}"`,
        // remaining R2ObjectBody fields -- typed as any so we don't need to stub them all
      } as unknown as R2ObjectBody;
    },
    async put(key: string, body: ArrayBuffer | Uint8Array | ReadableStream): Promise<R2Object | null> {
      // Record the write attempt; the drill should NOT call put.
      if (body instanceof ReadableStream) {
        await spy.putStream(key, body);
      } else {
        const bytes = body instanceof Uint8Array ? body : new Uint8Array(body as ArrayBuffer);
        await spy.put(key, bytes);
      }
      return null;
    },
    async head(key: string): Promise<R2Object | null> {
      const exists = await spy.exists(key);
      return exists ? ({ etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2Object) : null;
    },
    // Stub unused surface methods.
    list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] } as unknown as R2Objects),
    delete: async () => { return; },
    createMultipartUpload: async () => { throw new Error("not implemented"); },
    resumeMultipartUpload: () => { throw new Error("not implemented"); },
  } as unknown as R2Bucket;
}

// ---- test body --------------------------------------------------------------

async function main(): Promise<void> {
  // Build the signer the engine uses to sign runs and pin the verifier from.
  const signerSeed = rand(64); // ed25519 seed(32) || ML-DSA seed(32)
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // Seal a small KV archive into the spy destination.
  const records = Object.entries(KVSET).map(([name, v]) => ({
    sourceType: "kv",
    name,
    value: utf8(v),
    namespace: NS,
  }));

  const archive = await buildArchive({
    downpipeId: "dp_drill",
    downpipeName: "drill-test",
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

  // ---- SCENARIO 1: healthy archive with operational key --------------------
  console.log("drill-scenario-1: healthy archive + operational key");

  const spy1 = new SpyDestination();
  spy1.seed(archive);
  const r2Adapter1 = makeR2Adapter(spy1);

  // Clear the putLog after seeding (seeding pre-populates the store; we only care about
  // drill-induced writes).
  spy1.putLog.length = 0;

  const env1 = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2Adapter1,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  const result1 = await runDrill(env1, RUN_ID);

  ok("healthy: ok is true", result1.ok === true);
  ok("healthy: runId echoed", result1.runId === RUN_ID);
  ok("healthy: recordsVerified equals archive record count", result1.recordsVerified === records.length);
  ok("healthy: sampleRestored is true (at least one record)", result1.sampleRestored === true);
  ok("healthy: no reason field on success", result1.reason === undefined);
  // The drill is read-only: it must not write back to the destination.
  ok("healthy: drill wrote nothing (read-only)", spy1.putLog.length === 0);
  // isLatest should be a boolean (the drill surfaces freshness).
  ok("healthy: isLatest is a boolean", typeof result1.isLatest === "boolean");
  // The restore-subsystem OOM-risk marker (INFRA isolate-oom-restore): the drill buffers each sampled record
  // WHOLE (no streaming path), so it reports the largest record it buffered, the memory-safe ceiling, and whether
  // it crossed. The tiny KV corpus is far under the ceiling, so the marker rides with overSafe FALSE (present, not
  // risky) — the per-record size, not the archive total (a single small record stays well under 1 KiB).
  ok("healthy: the drill carries the OOM-risk marker (largest buffered record, ceiling, overSafe)", result1.oom !== undefined && result1.oom.maxRecordBytes > 0 && result1.oom.maxRecordBytes < 1024 && result1.oom.safeBytes === RESTORE_OOM_SAFE_BYTES && result1.oom.overSafe === false);

  // ---- SCENARIO 2: no operational key (break-glass-only posture) ----------
  console.log("drill-scenario-2: no operational key");

  const spy2 = new SpyDestination();
  spy2.seed(archive);
  spy2.putLog.length = 0;

  const env2 = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: makeR2Adapter(spy2),
    SIGNER_PRIVATE: signerPrivateB64,
    // OPERATIONAL_PRIVATE absent -> break-glass-only posture
  } as unknown as Env;

  let noKeyResult: Awaited<ReturnType<typeof runDrill>> | undefined;
  let noKeyThrew = false;
  try {
    noKeyResult = await runDrill(env2, RUN_ID);
  } catch {
    noKeyThrew = true;
  }

  ok("no-key: did not throw", !noKeyThrew);
  ok("no-key: ok is false", noKeyResult?.ok === false);
  ok("no-key: runId echoed", noKeyResult?.runId === RUN_ID);
  ok("no-key: reason mentions break-glass-only posture", /break-glass-only posture/.test(noKeyResult?.reason ?? ""));
  ok("no-key: drill wrote nothing", spy2.putLog.length === 0);

  // ---- SCENARIO 3: tampered manifest (merkleRoot field flipped) -----------
  // The manifest bytes are signed. Flipping any field (including merkleRoot) invalidates
  // the Ed25519+ML-DSA signature, so the signature check fires first. This exercises the
  // signature-integrity path, not the Merkle recomputation path.
  console.log("drill-scenario-3: tampered manifest (signature check fires)");

  const spy3 = new SpyDestination();
  spy3.seed(archive);
  spy3.tamperManifest();
  spy3.putLog.length = 0;

  const env3 = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: makeR2Adapter(spy3),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  let tamperedResult: Awaited<ReturnType<typeof runDrill>> | undefined;
  let tamperedThrew = false;
  try {
    tamperedResult = await runDrill(env3, RUN_ID);
  } catch {
    tamperedThrew = true;
  }

  ok("tampered-manifest: did not throw (failure is in-flow)", !tamperedThrew);
  ok("tampered-manifest: ok is false", tamperedResult?.ok === false);
  ok("tampered-manifest: runId echoed", tamperedResult?.runId === RUN_ID);
  // The signature check matches /signature did not verify/ in the catch, producing this
  // specific coarse reason. Assert the exact value so any regression in the coarse-reason
  // mapping is immediately visible.
  ok("tampered-manifest: reason is 'integrity check failed' (signature check fired)", tamperedResult?.reason === "integrity check failed");
  ok("tampered-manifest: drill wrote nothing", spy3.putLog.length === 0);

  // ---- SCENARIO 4: tampered segment bytes (present-but-corrupt -> INTEGRITY, not availability) ----
  // Corrupt a segment file (.seg) after sealing. The root manifest signature remains
  // valid (segment bytes are not covered by the signature or the shard SHA-384). openRun
  // completes successfully; the AEAD authentication tag failure surfaces when runDrill
  // calls run.restoreRecord(sample). This exercises the leaf/segment integrity detection
  // path -- the per-segment AES-256-GCM tag is the cryptographic equivalent of a Merkle
  // leaf check at the ciphertext layer.
  //
  // The segment bytes were FETCHED (present), so a decrypt/AEAD failure is a DAMAGED-backup
  // INTEGRITY fault, never availability. The reader re-labels the raw AES-GCM OperationError
  // as a structured integrity failure, so classifyDrillError returns the non-fallback
  // "integrity check failed" -- the SAME class the offline Go restore reports for the
  // identical damage, and the same class a MISSING segment already gets. Before
  // the fix, the raw OperationError matched no integrity keyword and fell through to the
  // availability catch-all "recovery check failed" (a present-but-corrupt backup wrongly
  // read as "the destination is unreachable" -- sending an operator to check bucket/creds).
  console.log("drill-scenario-4: tampered segment (present-but-corrupt -> integrity, not availability)");

  const spy4 = new SpyDestination();
  spy4.seed(archive);
  spy4.tamperSegment();
  spy4.putLog.length = 0;

  const env4 = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: makeR2Adapter(spy4),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  let segTamperedResult: Awaited<ReturnType<typeof runDrill>> | undefined;
  let segTamperedThrew = false;
  try {
    segTamperedResult = await runDrill(env4, RUN_ID);
  } catch {
    segTamperedThrew = true;
  }

  ok("tampered-segment: did not throw (failure is in-flow)", !segTamperedThrew);
  ok("tampered-segment: ok is false", segTamperedResult?.ok === false);
  ok("tampered-segment: runId echoed", segTamperedResult?.runId === RUN_ID);
  // Segment bytes are covered by AEAD authentication, not the manifest signature. The
  // signature verifies; the AEAD tag check fails inside openNonSecretSegment on FETCHED
  // (present) bytes, so the reader re-labels it as a structured integrity failure and the
  // drill classifies it as the non-fallback "integrity check failed" -- NOT an availability
  // class. This is the load-bearing regression guard: a present-but-corrupt segment is a
  // damaged backup, never "the destination is unreachable".
  ok("tampered-segment: reason is the INTEGRITY class ('integrity check failed'), NOT availability", segTamperedResult?.reason === "integrity check failed");
  ok("tampered-segment: reason is NOT a destination-access/availability/recovery-check class", !/destination access|object missing|recovery check/.test(segTamperedResult?.reason ?? ""));
  ok("tampered-segment: drill wrote nothing", spy4.putLog.length === 0);

  // ---- SCENARIO 5: windowed cursor rotates FULL decrypt coverage across ticks ----------
  // The previous scheduled drill re-decrypted the SAME strided <=8 records every tick, so a flipped byte
  // in an off-stride record was never caught by the drill. The scheduled drill now runs in WINDOWED mode:
  // each tick decrypts a window of records starting at the persisted cursor and advances it, so over
  // ceil(records / window) ticks EVERY record is decrypted-and-verified. This scenario threads the cursor
  // across ticks exactly as the DO persists it and proves (a) a full pass completes within ceil(n/window)
  // ticks, (b) a corrupted (potentially late/non-sampled) record is caught within that many ticks while
  // the cursor still advances past it, and (c) the manual drill is unchanged.
  console.log("drill-scenario-5: windowed cursor rotation (full coverage across ticks)");
  {
    const WINDOW = 2;
    const n = records.length; // 5
    const ticksForFullPass = Math.ceil(n / WINDOW); // 3

    // (a) Good archive: rotate the cursor and prove a full pass within ceil(n/window) ticks.
    const spyGood = new SpyDestination();
    spyGood.seed(archive);
    spyGood.putLog.length = 0;
    const envGood = { SCHEDULER: {} as unknown as DurableObjectNamespace, DEST_KIND: "r2", DEST_R2: makeR2Adapter(spyGood), SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64 } as unknown as Env;
    let cursor = 0;
    let sawWrap = false;
    let everyTickOk = true;
    const covered = new Set<number>();
    for (let t = 0; t < ticksForFullPass; t++) {
      const start = cursor;
      const res = await runDrill(envGood, RUN_ID, null, { cursor, window: WINDOW });
      if (!res.ok || !res.deepVerify) { everyTickOk = false; break; }
      for (let k = 0; k < Math.min(WINDOW, n); k++) covered.add((start + k) % n);
      if (res.deepVerify.wrapped) sawWrap = true;
      cursor = res.deepVerify.cursor;
    }
    ok("rotation: a full decrypt pass (every record) completes within ceil(n/window) ticks", covered.size === n);
    ok("rotation: a wrap (full pass) is signalled within the pass", sawWrap);
    ok("rotation: every tick over a good archive verified with a windowed result", everyTickOk);
    ok("rotation: drill wrote nothing (read-only)", spyGood.putLog.length === 0);
    // The windowed (scheduled restore-test) path also carries the OOM-risk marker (isolate-oom-restore): a
    // window that buffered records reports the largest one + the ceiling + the crossed flag, same as the sample path.
    const oomRes = await runDrill(envGood, RUN_ID, null, { cursor: 0, window: WINDOW });
    ok("rotation: a windowed drill carries the OOM-risk marker (largest buffered record, ceiling, overSafe)", oomRes.oom !== undefined && oomRes.oom.maxRecordBytes > 0 && oomRes.oom.safeBytes === RESTORE_OOM_SAFE_BYTES && oomRes.oom.overSafe === false);

    // (b) Corrupted record: caught within ceil(n/window) ticks; the cursor still advances past it.
    const spyBad = new SpyDestination();
    spyBad.seed(archive);
    spyBad.tamperSegment(); // corrupts one record's segment (its position in the run is opaque here)
    spyBad.putLog.length = 0;
    const envBad = { ...envGood, DEST_R2: makeR2Adapter(spyBad) } as unknown as Env;
    let badCursor = 0;
    let caught = false;
    let advancedEveryTick = true;
    for (let t = 0; t < ticksForFullPass; t++) {
      const res = await runDrill(envBad, RUN_ID, null, { cursor: badCursor, window: WINDOW });
      if (!res.deepVerify) { advancedEveryTick = false; break; }
      if (res.ok === false) caught = true; // a drained per-record failure still returns an advanced cursor
      badCursor = res.deepVerify.cursor;
    }
    ok("rotation-catch: a corrupted record is caught within ceil(n/window) ticks", caught);
    ok("rotation-catch: the cursor advanced past the bad record every tick (never wedged)", advancedEveryTick);
    ok("rotation-catch: drill wrote nothing", spyBad.putLog.length === 0);

    // (c) Manual drill (no window option) is unchanged: strided sample, no deepVerify field.
    const spyManual = new SpyDestination();
    spyManual.seed(archive);
    const resManual = await runDrill({ ...envGood, DEST_R2: makeR2Adapter(spyManual) } as unknown as Env, RUN_ID);
    ok("manual drill is unchanged (strided sample, no deepVerify field)", resManual.ok === true && resManual.deepVerify === undefined);
  }

  // ---- SCENARIO 6: tampered manifest SHARD (shard-hash integrity path) ----
  // Corrupt a manifest shard object (run/<runId>/manifest/<id>.dpe) but leave the root manifest + signature
  // intact. The root signature still verifies; openShards then recomputes the shard SHA-384 and finds it no
  // longer matches the value the signed root pins, throwing a typed integrity error ("shard NNNNN hash does
  // not match the signed root"). classifyDrillError must map this to the INTEGRITY reason, NOT a generic
  // destination-access reason: a hash mismatch is tamper/corruption (non-availability), the identical damage
  // the restore path classifies accurately.
  console.log("drill-scenario-6: tampered manifest shard (shard-hash integrity path)");

  const spy6 = new SpyDestination();
  spy6.seed(archive);
  spy6.tamperShard();
  spy6.putLog.length = 0;

  const env6 = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: makeR2Adapter(spy6),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  let shardTamperedResult: Awaited<ReturnType<typeof runDrill>> | undefined;
  let shardTamperedThrew = false;
  try {
    shardTamperedResult = await runDrill(env6, RUN_ID);
  } catch {
    shardTamperedThrew = true;
  }

  console.log(`    (observed reason: ${JSON.stringify(shardTamperedResult?.reason)})`);
  ok("tampered-shard: did not throw (failure is in-flow)", !shardTamperedThrew);
  ok("tampered-shard: ok is false (the corruption is DETECTED)", shardTamperedResult?.ok === false);
  ok("tampered-shard: runId echoed", shardTamperedResult?.runId === RUN_ID);
  // The load-bearing assertion: a shard hash mismatch classifies as an INTEGRITY reason, never a
  // destination-access / availability reason. "integrity check failed" is the shared classifier's REASON_INTEGRITY.
  ok("tampered-shard: reason is the INTEGRITY class ('integrity check failed'), NOT destination access", shardTamperedResult?.reason === "integrity check failed");
  ok("tampered-shard: reason is NOT a destination-access/availability class", !/destination access|object missing|recovery check/.test(shardTamperedResult?.reason ?? ""));
  ok("tampered-shard: drill wrote nothing (read-only)", spy6.putLog.length === 0);

  // ---- summary ------------------------------------------------------------
  console.log(failures === 0 ? "\nALL DRILL VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
