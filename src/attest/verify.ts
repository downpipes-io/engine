import type { Env } from "../env.d.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import { openRunWithMaster, type ObjectStore, type Run } from "../format/reader.ts";
import { shouldStream, verifyRecordStreamingDiscard, bufferedRestoreMaxBytes } from "../admin/restore-sinks.ts";
import { classifyRestoreFailure } from "../restore-reasons.ts";
import { log } from "../log.ts";
import { errId } from "../admin/passkey-types.ts";

// The attended-verification CEK verify. It opens a run from a PER-RUN MASTER the operator's browser
// recovered (openRunWithMaster; the break-glass private never leaves the browser), then decrypts a SEEDED
// SAMPLE of its records to a DISCARD sink exactly as the blind restore test does: each sampled record's
// plaintext is materialised (or streamed for a large record), its SHA-384 checked against the signed hash,
// the count summed, and the bytes dropped. Nothing is written and no value is returned or logged. A sub-100
// per-cent sample verifies a random subset chosen deterministically from the session seed, so the sample is
// reproducible and recorded; a 100 per-cent sample verifies every record. The result is honest about how
// much it proved: recordsVerified out of recordsTotal, plus the sample rate the caller records.

// AttestRunResult is one run's outcome. failures is the count of sampled records that did not decrypt-and-
// verify (the archive is partially unrecoverable); ok is a clean pass over the whole sample.
export interface AttestRunResult {
  ok: boolean;
  runId: string;
  downpipeId?: string;
  recordsVerified: number;
  recordsTotal: number;
  isLatest: boolean;
  failures: number;
  reason?: string;
}

// makePrng builds a deterministic xorshift128 PRNG seeded from the 32-byte session seed (four 32-bit words),
// so the sample selection is reproducible given the recorded seed. It is used ONLY to choose which records to
// verify; it is never a source of cryptographic randomness.
function makePrng(seed: Uint8Array): () => number {
  const dv = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
  let x = dv.getUint32(0) || 1;
  let y = dv.getUint32(4) || 2;
  let z = dv.getUint32(8) || 3;
  let w = dv.getUint32(12) || 4;
  return () => {
    const t = x ^ (x << 11);
    x = y;
    y = z;
    z = w;
    w = (w ^ (w >>> 19) ^ (t ^ (t >>> 8))) >>> 0;
    return w / 4294967296;
  };
}

// sampleCount resolves how many of `total` records a sampleRate (1..100) verifies: ceil(total * rate/100),
// at least one record per run (a sample must exercise something) and never more than the run holds.
export function sampleCount(total: number, sampleRate: number): number {
  if (total <= 0) return 0;
  const rate = Math.max(1, Math.min(100, Math.trunc(sampleRate)));
  if (rate >= 100) return total;
  return Math.min(total, Math.max(1, Math.ceil((total * rate) / 100)));
}

// sampleIndices deterministically selects `count` of `total` record indices from the seed via a partial
// Fisher-Yates shuffle (O(total) build, O(count) selection), returning them in ascending order. Given the
// same seed + total + count it always returns the same subset.
function sampleIndices(seed: Uint8Array, total: number, count: number): number[] {
  const idx = Array.from({ length: total }, (_, i) => i);
  if (count >= total) return idx;
  const rng = makePrng(seed);
  for (let i = 0; i < count; i++) {
    const j = i + Math.floor(rng() * (total - i));
    const tmp = idx[i]!;
    idx[i] = idx[j]!;
    idx[j] = tmp;
  }
  return idx.slice(0, count).sort((a, b) => a - b);
}

// verifySampledRun verifies a seeded sample of an ALREADY-OPENED run to a discard sink, returning the
// per-run result. It is factored out of verifyRunWithMaster so it can be exercised directly against a
// fixture-opened run (validate-attest-crypto) without a live destination. bufferedMaxBytes routes a large
// record to the constant-memory streaming path exactly as the blind restore test does.
export async function verifySampledRun(run: Run, sampleRate: number, seed: Uint8Array, bufferedMaxBytes: number): Promise<AttestRunResult> {
  const runId = run.root.runId;
  const total = run.records.length;
  const count = sampleCount(total, sampleRate);
  const indices = sampleIndices(seed, total, count);
  let recordsVerified = 0;
  let failures = 0;
  for (const i of indices) {
    const rec = run.records[i];
    if (!rec) continue;
    try {
      if (shouldStream(rec, bufferedMaxBytes)) {
        await verifyRecordStreamingDiscard(run, rec);
      } else {
        await run.restoreRecord(rec); // decrypts + verifies the plaintext SHA-384; the value is dropped
      }
      recordsVerified++;
    } catch (e) {
      failures++;
      log("error", `attest-verify ${runId} record ${rec.name} [err:${errId(e)} record-verify-failed]`);
    }
  }
  return {
    ok: failures === 0 && recordsVerified > 0,
    runId,
    ...(run.root.downpipeId ? { downpipeId: run.root.downpipeId } : {}),
    recordsVerified,
    recordsTotal: total,
    isLatest: run.freshness?.isLatestForDownpipe ?? false,
    failures,
  };
}

// verifyRunWithMaster opens a run from the browser-recovered master and verifies a seeded sample of its
// records to a discard sink. It is break-glass-safe by construction (it never needs the operational key; the
// master is the whole key it uses). minRunlogIndex, when supplied by the caller from the scheduler's live
// runlogCounter, pins the anti-rollback freshness check so a whole-document RUNLOG replay is caught (the same
// pin the blind test uses, since this endpoint persists the same compliance stamp). Freshness is advisory
// otherwise (allowStale), and the result surfaces isLatest.
export async function verifyRunWithMaster(
  env: Env,
  runId: string,
  master: Uint8Array,
  sampleRate: number,
  seed: Uint8Array,
  destOverride?: RuntimeDestConfig | null,
  minRunlogIndex?: number,
): Promise<AttestRunResult> {
  try {
    const signer = await loadSigner(reqSigner(env.SIGNER_PRIVATE));
    const verifier = verifierFrom(signer);
    const dest = await buildDestination(env, undefined, destOverride ?? null);
    const store: ObjectStore = {
      get: async (k: string) => {
        const r = await dest.get(k);
        if (!r) throw new Error(`object ${k} is missing`);
        return r.body;
      },
    };
    const run = await openRunWithMaster(store, runId, master, verifier, {
      verifyFreshness: true,
      allowStale: true,
      ...(minRunlogIndex !== undefined ? { minRunlogIndex } : {}),
    });
    try {
      return await verifySampledRun(run, sampleRate, seed, bufferedRestoreMaxBytes(env));
    } finally {
      // A no-op for this path by design, and kept because it states the lifetime. openRunWithMaster hands
      // the Run the CALLER'S buffer, so Run.dispose() leaves a supplied master alone; the frame that decoded
      // it (router-attest.ts) zeroises it in its own finally. Calling it here keeps every Run site uniform,
      // and it becomes load-bearing the moment this function is given a run it opened itself.
      run.dispose();
    }
  } catch (e) {
    const reason = classifyRestoreFailure(e);
    log("error", `attest-verify ${runId} [err:${errId(e)} ${reason.replace(/ /g, "-")}]`);
    return { ok: false, runId, recordsVerified: 0, recordsTotal: 0, isLatest: false, failures: 0, reason };
  }
}

function reqSigner(v: string | undefined): string {
  if (!v) throw new Error("missing required configuration: SIGNER_PRIVATE");
  return v;
}
