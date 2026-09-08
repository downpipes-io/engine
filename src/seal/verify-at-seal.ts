import type { HybridVerifier } from "../crypto/sign.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { attestKeyless, type ObjectStore, openRun, openRunWithMaster } from "../format/reader.ts";
import type { Signer } from "../format/writer.ts";
import { loadIdentity, loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { routeEngineNotification, type NotifyEmission } from "../notify.ts";
import { destAccessReason, REASON_OBJECT_MISSING } from "../restore-reasons.ts";

import { classifyEnvKnob, classifyFlagKnob, type KnobResolution } from "./budget.ts";

// Verify-at-seal (finding ENG-RST-01): right after a run seals successfully (archive +
// RUNLOG written to the destination) and BEFORE the run is reported a clean success, read the
// just-written archive BACK from the destination and verify it, so a corrupt or partial backup
// is caught NOW instead of at the next periodic drill (up to a week later). It REUSES the
// existing reader (src/format/reader.ts), the same machinery the in-account drill, canary and
// restore use, and never reinvents verification.
//
// FAIL-OPEN, ALWAYS (sacred). The bytes are already written when this runs. A verify FAILURE
// must NEVER delete the archive, block, or fail the run: this module only ever RETURNS a verdict
// (it never throws, every path is wrapped, and never mutates the destination). The caller
// records the verdict on the run row, and on a failure the caller raises a posture finding and
// fires a critical notification; the run still completes. A verify that could not even be
// attempted (engine not configured, reader threw before a verdict) is reported honestly as a
// failure with a coarse reason, never a fabricated pass.
//
// COST/BUDGET (the read is on the CUSTOMER's metered account). Tier-0 reads the signed root,
// the detached signature, the RUNLOG and each shard manifest (cheap: manifests + hashes, not
// record payloads) and is ALWAYS run. The decrypt SAMPLE reads only a few record values
// (SEAL_VERIFY_SAMPLE, default 3) and runs whenever the engine can reach the run master: either
// the in-account operational key, or the per-run master the seal path passes in. That second
// route is what gives a BREAK-GLASS-ONLY downpipe a real decrypt tier, where before it was
// Tier-0 only; the cost it now pays is the same cost the two-recipient posture already pays, and
// the same SEAL_VERIFY_* ceilings bound it. With neither route the verdict is honestly Tier-0 and
// says so. For a very large run (plaintext over SEAL_VERIFY_MAX_BYTES) the sample is skipped and
// Tier-0 is used alone, so verify-at-seal can never become an unbounded re-read of a huge archive.

// SealVerificationTier and SealVerification moved to the leaf ../sched/types.ts to break the import
// cycle that ran scheduler-do -> verify-at-seal -> notify -> scheduler-do (scheduler-do needed the
// SealVerification type that lived here). Re-exported so callers importing them by name from this
// module keep working.
export type { SealVerification, SealVerificationTier } from "../sched/types.ts";

import type { SealVerification, SealVerificationTier } from "../sched/types.ts";

// SEAL_VERIFY_SAMPLE_DEFAULT is the default number of records the decrypt sample reads + hash-checks
// (a few, per the design). It is small so the metered read stays cheap; a custom value tunes it.
// MASTER_BYTES is the per-run master's exact length (the 32-byte root of the run key tree, src/crypto/
// derive.ts). The decrypt-tier gate length-checks against it rather than merely testing for presence.
const MASTER_BYTES = 32;

// REASON_ENGINE_KEY_FAULT is the coarse reason for a run that was opened from a SUPPLIED master and then
// failed its run key commitment. That is the engine handing itself the wrong 32 bytes, which is a bug in
// this engine, NOT evidence about the archive. It is deliberately distinct from "signature check failed"
// (which asserts an authenticity problem and fires the critical tamper alert) and it is NON-RETRYABLE:
// re-reading the destination cannot mend the engine's own buffer, so a retry would only spend metered
// reads. Secret-free and closed, like every other reason in this file.
const REASON_ENGINE_KEY_FAULT = "engine key fault";

const SEAL_VERIFY_SAMPLE_DEFAULT = 3;
// SEAL_VERIFY_SAMPLE_MAX bounds an explicit sample so a malformed/abusive value cannot drive a read
// storm over the customer's metered account; the real value is a handful.
const SEAL_VERIFY_SAMPLE_MAX = 50;
// SEAL_VERIFY_MAX_BYTES_DEFAULT is the plaintext-size threshold above which only Tier-0 runs (the
// decrypt sample is skipped). 5 GiB is well past a small-to-moderate run; a larger or smaller value
// tunes the cost ceiling. Tier-0 itself is always cheap (manifests + hashes), so it is never gated.
const SEAL_VERIFY_MAX_BYTES_DEFAULT = 5 * 1024 * 1024 * 1024;
// SEAL_VERIFY_FULL_BYTES_DEFAULT is the plaintext-size threshold AT OR BELOW which the decrypt step
// covers EVERY record (full coverage), not just a strided sample (INT-1). Below this the metered
// re-read is bounded and cheap, so verify-at-seal decrypts the whole run and catches a flipped byte
// in ANY record at seal time; above it the strided SEAL_VERIFY_SAMPLE applies so a large run stays
// bounded. 64 MiB covers the vast majority of config/KV/secrets runs while keeping the seal-time
// re-read small relative to the seal that just wrote it. Set to 0 to disable full coverage (revert to
// the strided sample for all runs). Must be <= SEAL_VERIFY_MAX_BYTES to take effect (the max-bytes
// Tier-0 cutoff is checked first).
const SEAL_VERIFY_FULL_BYTES_DEFAULT = 64 * 1024 * 1024;

// SEAL_VERIFY_FULL_SHARDS_DEFAULT is the shard-count threshold AT OR BELOW which the ALWAYS-run Tier-0
// keyless completeness step re-reads back EVERY listed shard (full), so the at-seal verdict for every run
// that seals today is byte-identical. ABOVE it, only a strided SEAL_VERIFY_SHARD_SAMPLE of shards is
// re-read (Fix-A), so a very large run's at-seal verify cannot trip the platform subrequest cap re-reading
// thousands of shards (the live "reported-failed-forever at ~970 shards" wedge). 900 keeps a full re-read
// under the ~1000 cap (finaliseRun already spent ~30) for every run that stays full. The root SIGNATURE
// still authenticates the WHOLE shard list in-memory at sign time, so the per-shard read-back is only a
// durability smoke test; the offline CLI and the periodic drill always re-read every shard ("full").
// Raising this past ~900 risks the at-seal re-read tripping the subrequest cap (fail-open -> a false
// suspect, never a wedge or a fabricated pass); the offline/drill full path is the completeness authority.
const SEAL_VERIFY_FULL_SHARDS_DEFAULT = 900;
// SEAL_VERIFY_DECRYPT_MAX_SHARDS_DEFAULT is the shard-count ceiling for running the KEYED decrypt tier at
// all, and it exists because Tier-0 and the decrypt tier each read the shard list SEPARATELY.
//
// Tier-0's attestKeyless walks the shards itself (bounded to SEAL_VERIFY_FULL_SHARDS, 900). The decrypt
// tier then calls openRun, whose openShards fetches EVERY shard eagerly (format/reader.ts) with no
// sampling of its own, and only then reads the sampled records' segments. So a run with N shards under
// both thresholds spends roughly 2N subrequests before a single record is decrypted, plus finaliseRun's
// ~30. The 900 figure was derived for ONE full walk against the ~1000 platform cap, and the second walk
// was never in that arithmetic.
//
// Above this ceiling the verdict is honestly Tier-0. That is not a new restriction dressed up as a fix:
// past this point the decrypt tier could not complete anyway, and the failure mode is the bad one, since
// verify-at-seal is fail-open on the run and a cap trip surfaces as a SUSPECT verdict plus a critical
// alert telling the customer their just-written archive may be corrupt when nothing is wrong with it.
//
// 400 keeps 2N + overhead comfortably under the cap while leaving the vast majority of runs decrypt-checked
// (400 shards is 2 million records at the 5000-per-shard default). This bounds BOTH postures: the
// operational posture has always taken this path and has always had the latent overrun.
const SEAL_VERIFY_DECRYPT_MAX_SHARDS_DEFAULT = 400;
const SEAL_VERIFY_DECRYPT_MAX_SHARDS_MAX = 5000;
const SEAL_VERIFY_FULL_SHARDS_MAX = 5000;
// SEAL_VERIFY_SHARD_SAMPLE_DEFAULT is how many shards the bounded at-seal completeness re-read samples
// (evenly strided) on a run ABOVE the full threshold. 64 is a durability smoke test bounded well under the
// subrequest cap; the signature is the real completeness proof. 0 reads none above the threshold (the
// signature alone), capped at SEAL_VERIFY_SHARD_SAMPLE_MAX so an abusive value cannot drive a read storm.
const SEAL_VERIFY_SHARD_SAMPLE_DEFAULT = 64;
const SEAL_VERIFY_SHARD_SAMPLE_MAX = 256;

// verifyAtSealEnabled reports whether verify-at-seal runs. It DEFAULTS ON: only an explicit falsey
// VERIFY_AT_SEAL ("0"/"false"/"no"/"off") disables it, so a deployment that sets nothing gets the
// safety. Exported so a caller can skip the dest read entirely when off.
export function verifyAtSealEnabled(env: Env): boolean {
  const v = env.VERIFY_AT_SEAL;
  if (v === undefined) return true; // default ON
  const s = v.trim().toLowerCase();
  if (s === "0" || s === "false" || s === "no" || s === "off") return false;
  return true;
}

// parseNonNegativeInt parses a bounded non-negative integer env value, falling back to def on absent /
// malformed / out-of-range (mirrors the SCALE_* knob discipline). max bounds an abusive value. 0 is a
// valid input (for SEAL_VERIFY_SAMPLE it means "no sample"), so the name says non-negative not positive.
function parseNonNegativeInt(v: string | undefined, def: number, max: number): number {
  if (v === undefined) return def;
  const n = Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) return def;
  if (n > max) return max;
  return n;
}

// SEAL_VERIFY_ATTEMPTS_DEFAULT is the total number of WHOLE verification attempts on the read-back
// path (1 = today's behaviour, no retry). Default 3 = one try + up to two read-after-write retries.
// The R2 S3-compatibility endpoint is read-after-write inconsistent under concurrency: a just-PUT
// object can briefly read as a 404 or a stale prior version (RV-READBACK-R2 / RL-VAS-02), so a verify
// run milliseconds after the write hits that window and flags a perfectly-recoverable archive
// "suspect". A bounded re-read separates a consistency LAG (heals with time) from a real CORRUPTION
// (never heals): a transient failure clears on a retry; a persistent failure still surfaces as a
// suspect after the final attempt (§2.1 safety theorem). This NEVER weakens tamper detection -- every
// attempt is a full, independent cryptographic verification; the loop returns "verified" only when
// some attempt produced a complete clean proof, and "suspect" only when the FINAL attempt failed.
const SEAL_VERIFY_ATTEMPTS_DEFAULT = 3;
// SEAL_VERIFY_ATTEMPTS_MAX bounds the knob so a misconfiguration cannot drive a read storm on the
// customer's metered account or stall the seal path: each whole attempt re-reads ALL shards, and the
// sleeps extend the per-run invocation's wall clock (cf. seal/retry.ts MAX_RETRY_SLEEP_MS). Keep the
// default at 3; raising toward 8 must be validated against the invocation budget.
const SEAL_VERIFY_ATTEMPTS_MAX = 8;
// Backoff between attempts: jittered exponential base*2^(k-1) capped, with FULL CSPRNG jitter so a
// fleet of finalisers that all miss attempt 1 at the same instant do NOT re-read in lockstep (it
// decorrelates the extra load on the hot RUNLOG key). base 300ms / cap 2000ms gives, at the default 3
// attempts, a worst-case added wall of ~300+600 = ~900ms; at the MAX of 8 it is ~10s (the operator's
// explicit ceiling, not the default).
const SEAL_VERIFY_RETRY_BASE_MS = 300;
const SEAL_VERIFY_RETRY_CAP_MS = 2_000;

// ResolvedSealVerifyKnobs is the resolved verify-at-seal tuning, for the support pack's DIAGNOSTIC knobs
// block (support-pack modes verify-at-seal-disabled / seal-verify-knobs-invisible / tier0-only-reason).
// Every field is a resolved int or bool: nothing here is a key, value or record name (NO-CUSTODY safe).
export interface ResolvedSealVerifyKnobs {
  enabled: boolean; // whether verify-at-seal runs at all (VERIFY_AT_SEAL; default ON)
  sample: number; // SEAL_VERIFY_SAMPLE: records the decrypt step reads (0 = no sample; Tier-0 only)
  maxBytes: number; // SEAL_VERIFY_MAX_BYTES: plaintext size above which the decrypt sample is skipped (Tier-0 only)
  fullBytes: number; // SEAL_VERIFY_FULL_BYTES: plaintext size at/below which the decrypt covers EVERY record
  attempts: number; // SEAL_VERIFY_ATTEMPTS: whole read-back attempts (>=1) separating R2 read-after-write lag from corruption
  fullShards: number; // SEAL_VERIFY_FULL_SHARDS: shard count at/below which the completeness re-read is FULL
  shardSample: number; // SEAL_VERIFY_SHARD_SAMPLE: strided shard re-reads above the full-shards threshold
}

// resolveSealVerifyKnobs re-runs the verify-at-seal knob resolution (the SAME parse + defaults + clamps
// verifyAtSealOnce and verifyAtSeal use) so the support pack can surface the
// resolved values a diagnosis otherwise cannot see: verify-at-seal turned OFF, a decrypt sample of 0, a
// tiny max-bytes cutoff forcing Tier-0-only, an abusively large attempts count. PURE (env in, ints/bool
// out): it records NOTHING, reads no destination, and touches no seal / verify path or verdict -- it only
// reflects config. Env is shared by the Worker and the scheduler DO, so these ARE the values in force.
// validate-verify-at-seal pins this to the documented defaults + clamps so it cannot drift from the path.
export function resolveSealVerifyKnobs(env: Env): ResolvedSealVerifyKnobs {
  return {
    enabled: verifyAtSealEnabled(env),
    sample: parseNonNegativeInt(env.SEAL_VERIFY_SAMPLE, SEAL_VERIFY_SAMPLE_DEFAULT, SEAL_VERIFY_SAMPLE_MAX),
    maxBytes: parseNonNegativeInt(env.SEAL_VERIFY_MAX_BYTES, SEAL_VERIFY_MAX_BYTES_DEFAULT, Number.MAX_SAFE_INTEGER),
    fullBytes: parseNonNegativeInt(env.SEAL_VERIFY_FULL_BYTES, SEAL_VERIFY_FULL_BYTES_DEFAULT, Number.MAX_SAFE_INTEGER),
    attempts: Math.max(1, parseNonNegativeInt(env.SEAL_VERIFY_ATTEMPTS, SEAL_VERIFY_ATTEMPTS_DEFAULT, SEAL_VERIFY_ATTEMPTS_MAX)),
    fullShards: parseNonNegativeInt(env.SEAL_VERIFY_FULL_SHARDS, SEAL_VERIFY_FULL_SHARDS_DEFAULT, SEAL_VERIFY_FULL_SHARDS_MAX),
    shardSample: parseNonNegativeInt(env.SEAL_VERIFY_SHARD_SAMPLE, SEAL_VERIFY_SHARD_SAMPLE_DEFAULT, SEAL_VERIFY_SHARD_SAMPLE_MAX),
  };
}

// sealVerifyKnobSources reports the SOURCE of every verify-at-seal knob (gap G169). resolveSealVerifyKnobs
// above surfaces the VALUES in force, but a value alone cannot answer the ticket "I set SEAL_VERIFY_SAMPLE and
// nothing changed": a rejected typo and an unset knob both report the default. The classifier mirrors
// parseNonNegativeInt EXACTLY -- absent -> default, non-numeric / non-integer / negative -> invalid (the
// default runs), over the max -> clamped -- with positiveOnly=false because 0 is a MEANINGFUL value here (it
// means "no decrypt sample", Tier-0 only). VERIFY_AT_SEAL is a flag (any string parses), so it has no invalid
// arm. PURE: env in, a closed enum + bounded ints out. The raw operator string never rides.
export function sealVerifyKnobSources(env: Env): Record<string, KnobResolution> {
  return {
    verifyAtSeal: { source: classifyFlagKnob(env.VERIFY_AT_SEAL) },
    sealVerifySample: classifyEnvKnob(env.SEAL_VERIFY_SAMPLE, SEAL_VERIFY_SAMPLE_DEFAULT, SEAL_VERIFY_SAMPLE_MAX, false),
    sealVerifyMaxBytes: classifyEnvKnob(env.SEAL_VERIFY_MAX_BYTES, SEAL_VERIFY_MAX_BYTES_DEFAULT, Number.MAX_SAFE_INTEGER, false),
    sealVerifyFullBytes: classifyEnvKnob(env.SEAL_VERIFY_FULL_BYTES, SEAL_VERIFY_FULL_BYTES_DEFAULT, Number.MAX_SAFE_INTEGER, false),
    sealVerifyAttempts: classifyEnvKnob(env.SEAL_VERIFY_ATTEMPTS, SEAL_VERIFY_ATTEMPTS_DEFAULT, SEAL_VERIFY_ATTEMPTS_MAX, false),
    sealVerifyFullShards: classifyEnvKnob(env.SEAL_VERIFY_FULL_SHARDS, SEAL_VERIFY_FULL_SHARDS_DEFAULT, SEAL_VERIFY_FULL_SHARDS_MAX, false),
    sealVerifyShardSample: classifyEnvKnob(env.SEAL_VERIFY_SHARD_SAMPLE, SEAL_VERIFY_SHARD_SAMPLE_DEFAULT, SEAL_VERIFY_SHARD_SAMPLE_MAX, false),
  };
}

// causeDigest is the 8-hex FNV-1a CORRELATION handle of a RAW failure text (gap G067). It is the SAME idiom the
// restore fault ring's errId uses: the raw message -- which can embed a shard id, an object key or a recordId --
// is READ only to derive a 32-bit fingerprint and is NEVER returned, stored or logged. Two occurrences of the
// same underlying reader fault produce the same handle, which is the whole question support cannot answer today
// ("is this the same fault as last week, or a new one?"); the handle reveals nothing about the text itself.
function causeDigest(raw: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

// storeOver wraps a Destination as the reader's read-only ObjectStore, exactly as the drill does
// (a missing object becomes a thrown "object is missing", which the reader turns into a verdict).
function storeOver(dest: Destination): ObjectStore {
  return {
    get: async (k: string): Promise<Uint8Array> => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
    // RL-VAS-05: expose the destination's LIST so attestKeyless's >900-shard sampled branch can cross-check
    // every signed shard object is PRESENT by name (one list per run) without an N-GET storm. A single run's
    // run/<runId>/manifest/ prefix is a small, bounded scan (one object per shard), well within list()'s contract.
    list: (prefix: string): Promise<string[]> => dest.list(prefix),
  };
}

// coarseVerifyReason maps a caught exception OR a keyless-attestation failure to an ENUMERATED,
// secret-free reason, matching the drill/restore vocabulary (drill.ts / reader.ts use the same
// buckets), so a suspect verdict never carries raw exception text (which could embed a shard id or
// object key). The raw message is NEVER returned and NEVER logged in plaintext.
function coarseVerifyReason(m: string): string {
  // Split the former single "integrity check failed" bucket into WHICH check failed, so the consumer can give
  // the RIGHT remediation instead of a blanket "re-run": a SIGNATURE / key-commitment failure is an
  // authenticity/posture problem (re-running with the same signer reproduces it), a RECORD-integrity failure
  // (plaintext-hash / Merkle / chunk-range) is content tamper/corruption, and a COMPLETENESS failure (a shard
  // hash mismatch vs the signed root, a record-count disagreement) is a missing/mismatched shard. All remain
  // secret-free ENUM words; the raw message (which can embed a shard id / object key / recordId) is NEVER
  // returned. Order is precedence: signature (most serious) before record-integrity before completeness; the
  // legacy "integrity check failed" stays as a back-compat passthrough for any unsplit/older reason.
  // A COLD-STORAGE-CLASS object (a bucket lifecycle rule silently transitioned the archive to GLACIER /
  // DEEP_ARCHIVE) reads back with a distinct `thaw-needed` fault (s3-read-ops.ts get() classifies the S3
  // InvalidObjectState code). It is NOT a tamper, a missing object, or a transient access error: the bytes
  // are present and recoverable but unreadable until restored/thawed. Map it to a distinct `thaw-needed`
  // reason (checked FIRST, before the generic access/object-missing buckets) so the seal-verification verdict
  // -- which already rides into the support pack via sealVerification.reason -- reads the actionable cause
  // (bucket-lifecycle-to-glacier) instead of an opaque "destination access error".
  if (/thaw-needed|InvalidObjectState|cold storage class/.test(m)) return "thaw-needed";
  if (/signature did not verify|key commitment/.test(m)) return "signature check failed";
  if (/failed its plaintext hash|Merkle root|terminates after|chunkRange/.test(m)) return "record integrity check failed";
  if (/hash does not match|the root declares|recovered \d+ records|disagree/.test(m)) return "completeness check failed";
  if (/integrity check failed/.test(m)) return "integrity check failed";
  // a MISSING/unreadable root manifest-or-signature is a missing-OBJECT problem, not authenticity, so it
  // re-seals on a re-run and the bytes are NOT intact (see tier0Attest's signatureValid:false branch).
  if (/is missing|status 404|object missing|manifest or signature missing/.test(m)) return REASON_OBJECT_MISSING;
  if (/status \d/.test(m)) return destAccessReason(m);
  if (/RUNLOG|freshness|latest run|stale|freshness check failed/.test(m)) return "freshness check failed";
  if (/missing required configuration|engine not fully configured/.test(m)) return "engine not fully configured";
  return "verification check failed";
}

// verifyAtSeal reads the just-written run BACK from the destination and verifies it, returning a
// redaction-safe SealVerification verdict. It is a BOUNDED read-after-write retry around
// verifyAtSealOnce (the single full verification): healthy runs cost ZERO extra (attempt 1 passes);
// only an attempt-1 failure -- the false-suspect population plus the rare real-tamper population --
// pays for up to SEAL_VERIFY_ATTEMPTS-1 re-reads, each gated on a consistency-curable reason and
// spaced by full-jitter backoff. It NEVER throws and NEVER mutates the destination (fail-open on the
// run); it fails CLOSED on the verdict (a persistent failure is never downgraded to verified -- it
// surfaces as a suspect after the final attempt, raising the posture finding + critical alert exactly
// as today). SEAL_VERIFY_ATTEMPTS=1 (or 0/absent->default; here forced to "no retry" only by =1) is
// the exact pre-retry rollback. See §2.1: this is monotone in the safe direction -- it converts
// transient false-negatives into true-positives and can NEVER turn a tamper into a pass.
export async function verifyAtSeal(env: Env, dest: Destination, runId: string, plaintextBytes: number, master?: Uint8Array): Promise<SealVerification> {
  // Math.max(1, …) makes both 0 and 1 mean "no retry" (single attempt = today's behaviour).
  const maxAttempts = Math.max(1, parseNonNegativeInt(env.SEAL_VERIFY_ATTEMPTS, SEAL_VERIFY_ATTEMPTS_DEFAULT, SEAL_VERIFY_ATTEMPTS_MAX));
  let last!: SealVerification;
  let ran = 0; // actual attempts run (NOT maxAttempts) -- reported honestly even on an early break
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    ran = attempt;
    last = await verifyAtSealOnce(env, dest, runId, plaintextBytes, master); // never throws (fail-open)
    if (last.status === "verified") {
      // Healthy first try: return unchanged (no attempts/recovered fields -> looks exactly like
      // today, so no console/posture coordination needed). Self-healed after a retry: mark it so the
      // SLO surface can distinguish "verified, needed k read-after-write retries" (observability, NOT
      // an alarm) from "verified first try", and emit ONE warn line so the self-heal is never silent.
      if (attempt > 1) {
        logSelfHeal(runId, attempt, last.reason);
        return { ...last, attempts: attempt, recovered: true };
      }
      return last;
    }
    // SUSPECT: retry only when the reason is consistency-curable AND attempts remain.
    if (attempt < maxAttempts && isRetryableVerifyReason(last.reason)) {
      await sealVerifyBackoff(attempt);
      continue;
    }
    break; // non-retryable reason (e.g. config error) or out of attempts -> surface the suspect
  }
  // FINAL suspect. Emit the SINGLE counted error line here (NOT per attempt), carrying the actual
  // attempt count, so the operator and the harness metric see "a real failure that survived N
  // read-after-write retries", never per-attempt transient noise.
  logFinalSuspect(runId, last, ran);
  return { ...last, attempts: ran };
}

// isRetryableVerifyReason reports whether a suspect reason is consistency-curable in expectation, so
// only those reasons spend a metered re-read. "engine not fully configured" never heals (a missing
// signer is a config fault, not a replica lag) -> surface immediately. EVERYTHING else is curable in
// expectation: "object missing" (read-after-write 404 on a just-written object), "freshness check
// failed" (RUNLOG body lag), "integrity check failed" (RUNLOG body/sig skew OR a real tamper, which
// is RE-VERIFIED each attempt and STILL surfaced if persistent -- §2.1), "verification check failed"
// (catch-all; covers a RUNLOG chain anomaly under lag), "destination access error" (transient
// 5xx/429/network). Retrying "integrity" is sound by the §2.1 theorem: a real corruption fails every
// re-verify and surfaces after N; only a consistency skew (or the legitimate bytes) can ever pass.
function isRetryableVerifyReason(reason?: string): boolean {
  if (!reason) return false; // fail-safe: no reason -> no retry
  // "engine not fully configured" is a config fault (a missing signer never heals on a replica-lag retry);
  // "thaw-needed" is a cold-storage-class object (GLACIER/DEEP_ARCHIVE) that needs an EXPLICIT restore -- a
  // read-after-write retry can never thaw it, so re-reading only spends metered reads without changing the
  // verdict. Surface both immediately rather than retrying. Everything else is consistency-curable (§2.1).
  // REASON_ENGINE_KEY_FAULT joins them: the engine opened the run from a master that did not match the
  // run key commitment. That is this engine's own bug, so a re-read changes nothing and the honest move
  // is to surface it once rather than paying for up to SEAL_VERIFY_ATTEMPTS full re-reads.
  return reason !== "engine not fully configured" && reason !== "thaw-needed" && reason !== REASON_ENGINE_KEY_FAULT;
}

// sealVerifyBackoff sleeps a full-CSPRNG-jittered exponential backoff between attempts, the same idiom
// as seal/retry.ts withRetry (GUARDRAILS §15: jitter drawn from crypto.getRandomValues, never
// Math.random, so no reviewer reasons about RNG near a boundary). Full jitter (delay in [0, expo))
// decorrelates a fleet of finalisers that all missed attempt 1 at the same instant.
async function sealVerifyBackoff(attempt: number): Promise<void> {
  const expo = Math.min(SEAL_VERIFY_RETRY_CAP_MS, SEAL_VERIFY_RETRY_BASE_MS * 2 ** (attempt - 1));
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  const delay = Math.floor(((buf[0] ?? 0) / 0x100000000) * expo);
  await new Promise((r) => setTimeout(r, delay));
}

// logSelfHeal emits ONE warn line on a run that recovered on a retry. It MUST NOT contain the
// substring the suspect metric greps ("<reason>-check-failed"): the reason is rendered as a WORD
// (e.g. "was freshness"), never the counted hyphenated token, so the self-heal is honest in the log
// (never silent) without tripping the suspect count.
function logSelfHeal(runId: string, attempt: number, reason?: string): void {
  const was = reason ? reason.split(" ")[0] : "transient";
  log("warn", `verify-at-seal transient-recovered ${runId} after ${attempt} reads (was ${was})`);
}

// logFinalSuspect emits the SINGLE counted error line on the final suspect, carrying the coarse,
// secret-free reason in the hyphenated form the harness metric counts plus the actual attempt count,
// so the operator and the metric see one real failure that survived N read-after-write retries.
function logFinalSuspect(runId: string, v: SealVerification, ran: number): void {
  const reason = (v.reason ?? "verification check failed").replace(/ /g, "-");
  log("error", `verify-at-seal SUSPECT ${runId} ${v.tier} [${reason}] attempts=${ran}`);
}

// verifyAtSealOnce is ONE full read-back verification (the pre-retry logic). It NEVER throws and
// NEVER mutates the destination (fail-open); it NEVER emits a terminal log line (the loop owns all
// logging, so a run that recovers on a later attempt does not spam the operator's error log nor the
// suspect metric -- see logSelfHeal/logFinalSuspect). plaintextBytes is the run's total plaintext size
// (from the RunSummary), used only to decide whether the run is large enough to skip the decrypt
// sample (Tier-0 only).
//
//  1) Tier-0 (ALWAYS): attestKeyless re-opens the run from the destination and verifies the hybrid
//     signature over the stored root (which covers the merkleRoot, every per-record recordHash, the
//     declared counts and the shard digests), confirms every signed shard is present and hashes to
//     the signed root (completeness), and runs the key-free RUNLOG anti-rollback freshness check. No
//     decryption key is needed. A failure of ANY of the three flags is a suspect verdict.
//  2) Sampled-decrypt (only with the operational key AND when the run is not over the size
//     threshold): the run is opened with the full KEYED structural chain (key-commitment recompute,
//     every record's recordHash, the Merkle root recompute), then a sample of records is decrypted and
//     each one's plaintext hash is re-checked by restoreRecord. With the operational key present the
//     open goes through openRun, so the recipient CAPSULE is unwrapped and that wrap is proven to open.
//     A break-glass-only downpipe has no such key, and instead reaches this tier from the per-run master
//     the seal path passes in; it only falls back to Tier-0 when no master was supplied either.
async function verifyAtSealOnce(env: Env, dest: Destination, runId: string, plaintextBytes: number, master?: Uint8Array): Promise<SealVerification> {
  const at = Date.now();
  const store = storeOver(dest);

  // Build the verifier from the signer; a missing signer means the engine cannot even attempt a
  // verdict, reported honestly as a suspect rather than a fabricated pass.
  let signer: Signer;
  let verifier: HybridVerifier;
  try {
    signer = await loadSigner(req(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
    verifier = verifierFrom(signer);
  } catch (e) {
    const reason = coarseVerifyReason((e as Error).message);
    return { status: "suspect", tier: "tier-0", sampled: 0, at, reason, causeDigest: causeDigest((e as Error).message) };
  }

  // Tier-0 (ALWAYS): keyless attestation of signature, completeness and anti-rollback freshness. Fix-A:
  // a run with more than SEAL_VERIFY_FULL_SHARDS shards re-reads only a strided SEAL_VERIFY_SHARD_SAMPLE of
  // its shards for the durability smoke test (the signature still authenticates the whole listing), so a
  // very large run's at-seal verify stays under the subrequest cap; a run at/under the threshold stays
  // FULL, byte-identical to today.
  const fullShards = parseNonNegativeInt(env.SEAL_VERIFY_FULL_SHARDS, SEAL_VERIFY_FULL_SHARDS_DEFAULT, SEAL_VERIFY_FULL_SHARDS_MAX);
  const shardSample = parseNonNegativeInt(env.SEAL_VERIFY_SHARD_SAMPLE, SEAL_VERIFY_SHARD_SAMPLE_DEFAULT, SEAL_VERIFY_SHARD_SAMPLE_MAX);
  const tier0 = await tier0Attest(store, runId, verifier, { sampleAbove: fullShards, sample: shardSample });
  if (tier0.fault !== null) {
    // G067: the coarse reason is unchanged; the DIGEST rides beside it so two recurring Tier-0 faults can be
    // correlated without the raw text (which can embed a shard id or an object key) ever leaving the engine.
    return { status: "suspect", tier: "tier-0", sampled: 0, at, reason: tier0.fault.reason, causeDigest: tier0.fault.digest };
  }

  // Decide whether to additionally run the keyed decrypt sample. It needs a way to reach the master:
  // either the in-account operational key or the per-run master handed in by the seal path. With
  // neither, this is honestly Tier-0. It is also skipped on a very large run (over the size threshold)
  // so verify-at-seal stays bounded on the metered account.
  const sampleN = parseNonNegativeInt(env.SEAL_VERIFY_SAMPLE, SEAL_VERIFY_SAMPLE_DEFAULT, SEAL_VERIFY_SAMPLE_MAX);
  const maxBytes = parseNonNegativeInt(env.SEAL_VERIFY_MAX_BYTES, SEAL_VERIFY_MAX_BYTES_DEFAULT, Number.MAX_SAFE_INTEGER);
  const fullBytes = parseNonNegativeInt(env.SEAL_VERIFY_FULL_BYTES, SEAL_VERIFY_FULL_BYTES_DEFAULT, Number.MAX_SAFE_INTEGER);
  const haveOperationalKey = typeof env.OPERATIONAL_PRIVATE === "string" && env.OPERATIONAL_PRIVATE.length > 0;
  // The PER-RUN master, passed in by the seal path that just finalised this run (it is already in scope
  // there and already zeroised by that path's own finally, so this widens no window). It opens THIS run
  // and nothing else, which is what lets a BREAK-GLASS-ONLY downpipe reach the keyed decrypt tier without
  // the engine holding any key that can read an archive at rest. When the operational key IS present the
  // decrypt step still opens the run through the CAPSULE (see decryptVerify): that recipient-wrap decap is
  // the only recurring proof that the wrap written into this root actually opens, and it is not given up.
  // Length-checked, not merely present: a wrong-length buffer would sail through the gate, fail the run
  // key commitment inside openRunWith, and surface as a SUSPECT verdict indistinguishable from tampering.
  const haveMaster = master !== undefined && master.length === MASTER_BYTES;
  const canDecrypt = haveOperationalKey || haveMaster;
  const tooLargeForSample = plaintextBytes > maxBytes;
  // The SUBREQUEST guard, distinct from the byte guard above it. Tier-0 has just walked the shard list, and
  // the decrypt tier's openRun walks it AGAIN with no sampling of its own, so the two together cost roughly
  // twice the shard count before a single record is read. The 900-shard Tier-0 figure was derived for ONE
  // walk against the ~1000 platform cap; the second was never in that arithmetic, so a run in the hundreds
  // of shards could trip the cap, fail open, and report SUSPECT with a critical alert on a perfectly good
  // archive. Skipping the decrypt tier there is not a lost check: past this point it could not have
  // completed anyway.
  const decryptMaxShards = parseNonNegativeInt(env.SEAL_VERIFY_DECRYPT_MAX_SHARDS, SEAL_VERIFY_DECRYPT_MAX_SHARDS_DEFAULT, SEAL_VERIFY_DECRYPT_MAX_SHARDS_MAX);
  // Unknown shard count (the attestation did not report one) is treated as WITHIN budget, so this guard can
  // only ever skip a run it positively knows is too big. It must not silently disable the decrypt tier.
  const tooManyShards = tier0.shardCount !== undefined && tier0.shardCount > decryptMaxShards;

  if (!canDecrypt || sampleN === 0 || tooLargeForSample || tooManyShards) {
    // Tier-0 passed and that is the verification in force (break-glass-only, sample disabled, or the
    // run is too large for a decrypt sample). This is an honest "verified at seal, Tier-0". Record WHY
    // the sample was skipped as a closed diagnostic enum (support-pack mode tier0-only-reason-unknown):
    // the precedence mirrors the guard's own || short-circuit -- no in-account read-back key ("break-glass")
    // is checked first (with no key there is no sample to run regardless of the other knobs), then an
    // operator-disabled sample ("sample-off"), then the run being over SEAL_VERIFY_MAX_BYTES ("too-large").
    // This is additive verdict metadata: the status/tier/sampled are unchanged, so no sealed byte, root,
    // signature or verdict semantic moves.
    const tier0Cause = !canDecrypt ? "break-glass" : sampleN === 0 ? "sample-off" : tooLargeForSample ? "too-large" : "too-many-shards";
    return { status: "verified", tier: "tier-0", sampled: 0, at, tier0Cause };
  }

  // Full coverage for a small run (INT-1): when the plaintext is within SEAL_VERIFY_FULL_BYTES the
  // decrypt step covers EVERY record, so a flipped byte anywhere in the run is caught at seal time
  // rather than only if it fell in the strided sample. A larger run keeps the bounded strided sample.
  const fullCoverage = plaintextBytes <= fullBytes;
  return decryptVerify(env, store, runId, verifier, fullCoverage ? Number.POSITIVE_INFINITY : sampleN, fullCoverage, at, master);
}

// tier0Attest runs the ALWAYS Tier-0 keyless attestation: attestKeyless re-opens the run and verifies
// the hybrid signature over the stored root, confirms every signed shard is present and hashes to the
// signed root (completeness), and runs the key-free RUNLOG anti-rollback freshness check. allowStale:true
// so a verify of the run we JUST wrote attests recoverability + freshness honestly even if a concurrent
// newer run exists. Returns null on a clean pass, otherwise a coarse, secret-free reason. Total: even an
// unexpected throw is mapped to a reason rather than escaping (fail-open).
async function tier0Attest(store: ObjectStore, runId: string, verifier: HybridVerifier, shardCheck: "full" | { sampleAbove: number; sample: number }): Promise<{ fault: { reason: string; digest: string } | null; shardCount?: number }> {
  // tag pairs a coarse reason with the G067 correlation digest of the RAW attestation text. The raw text is
  // consumed here and never leaves.
  const tag = (reason: string, raw: string): { reason: string; digest: string } => ({ reason, digest: causeDigest(raw) });
  try {
    const att = await attestKeyless(store, runId, verifier, { allowStale: true, shardCheck });
    if (att.signatureValid && att.complete && att.notRolledBack) return { fault: null, ...(att.shardCount !== undefined ? { shardCount: att.shardCount } : {}) };
    const raw = att.reason ?? "verification check failed";
    // A COLD-storage-class archive (bucket-lifecycle-to-glacier) reads back as a thaw-needed fault regardless of
    // WHICH check tripped (a cold root fails signatureValid; a cold shard fails completeness), and attestKeyless
    // preserves that classification in att.reason. Surface the actionable `thaw-needed` reason with precedence
    // over the generic signature/completeness/freshness sub-classing below, so the verdict names the real cause.
    if (coarseVerifyReason(raw) === "thaw-needed") return { fault: tag("thaw-needed", raw), ...(att.shardCount !== undefined ? { shardCount: att.shardCount } : {}) };
    // The three INDEPENDENTLY-computed booleans are the AUTHORITATIVE per-check signal: attestKeyless coarsens
    // att.reason to a generic "integrity check failed" for a content/shard fault, so the booleans (not the
    // reason string) drive the sub-class. Precedence: signature > completeness > freshness. Two refinements
    // from att.reason: (1) signatureValid:false is BOTH a true verify failure AND a MISSING/unreadable root
    // manifest, only the former is an authenticity/posture problem ("do NOT re-run"); a missing root is a
    // missing-OBJECT problem (re-running re-seals it, bytes NOT intact), so route it via coarseVerifyReason
    // (-> object-missing) rather than mislabelling it "signature check failed". (2) complete:false refines to
    // the more-specific object-missing when att.reason says so (a shard 404 vs a hash mismatch). Every value is
    // a fixed secret-free enum word; the raw message is never returned.
    if (!att.signatureValid) return { fault: tag(/signature did not verify|key commitment/.test(att.reason ?? "") ? "signature check failed" : coarseVerifyReason(raw), raw) };
    if (!att.complete) return { fault: tag(coarseVerifyReason(att.reason ?? "") === REASON_OBJECT_MISSING ? REASON_OBJECT_MISSING : "completeness check failed", raw) };
    return { fault: tag("freshness check failed", raw) }; // notRolledBack === false
  } catch (e) {
    return { fault: tag(coarseVerifyReason((e as Error).message), (e as Error).message) };
  }
}

// decryptVerify runs the keyed decrypt step: open the run with the operational key (the full keyed
// structural chain) and decrypt + hash-check records. With fullCoverage it decrypts EVERY record so a
// flipped byte ANYWHERE in a small run is caught at seal time (tier "full"); otherwise it decrypts an
// evenly-strided sample bounded by sampleN (tier "sampled-decrypt"), so a large run stays bounded on
// the metered account. A failure is a suspect verdict (the keyed structure or a record's plaintext did
// not hold), still fail-open (no throw, no mutation). The caller has already confirmed that ONE of the
// operational key or a supplied per-run master is present, and decided fullCoverage from the run's
// plaintext size.
async function decryptVerify(env: Env, store: ObjectStore, runId: string, verifier: HybridVerifier, sampleN: number, fullCoverage: boolean, at: number, master?: Uint8Array): Promise<SealVerification> {
  const tier: SealVerificationTier = fullCoverage ? "full" : "sampled-decrypt";
  // G067: `sampled` is ZEROED on a suspect verdict, so a 50,000-record run's failure could not say whether it
  // died on record 1 or record 49,999 -- which is exactly how support bounds WHICH shard is bad. Track both the
  // clean count and the ORDINAL the fault landed on, outside the try, so they survive the throw.
  let verifiedBeforeFail = 0;
  let failingOrdinal: number | undefined;
  // Which acquisition path opened the run, tracked OUTSIDE the try so the catch can tell an engine-side
  // key fault from a genuine authenticity failure. Defaults to "recipient": if the open threw before this
  // was assigned, no master was consulted, so the existing classification is the honest one.
  let openedVia: "recipient" | "master" = "recipient";
  try {
    // PRECEDENCE IS DELIBERATE. With the operational key present the run is opened through the CAPSULE,
    // exactly as before, so the recipient-wrap decapsulation stays exercised on every run. Preferring the
    // master here would have quietly deleted the only recurring proof that a run's recipient wrap opens:
    // openRunWithMaster is HANDED the master and never touches a wrap, so a corrupt or substituted wrap
    // would seal, verify at the full tier and attest clean while being permanently unrecoverable. The
    // master path is the FALLBACK, and it is what gives a break-glass-only downpipe (which has no
    // in-account read-back key at all) a keyed decrypt tier it has never had. Both paths run the same
    // structural chain and the same key-commitment check inside openRunWith, so the only difference is
    // how the master is acquired.
    const opts = { verifyFreshness: true, allowStale: true };
    openedVia = typeof env.OPERATIONAL_PRIVATE === "string" && env.OPERATIONAL_PRIVATE.length > 0 ? "recipient" : "master";
    const run =
      openedVia === "recipient"
        ? await openRun(store, runId, loadIdentity(env.OPERATIONAL_PRIVATE as string), verifier, opts)
        : await openRunWithMaster(store, runId, master as Uint8Array, verifier, opts); // the gate proved one of the two is present
    const total = run.records.length;
    let sampled = 0;
    if (fullCoverage) {
      // Decrypt and hash-check every record in order: full byte coverage of the just-written archive.
      for (let i = 0; i < run.records.length; i++) {
        failingOrdinal = i; // the record we are ABOUT to verify: if restoreRecord throws, this is the culprit
        await run.restoreRecord(run.records[i]!);
        sampled++;
        verifiedBeforeFail = sampled;
      }
      failingOrdinal = undefined; // every record verified clean
    } else {
      const want = Math.min(sampleN, total);
      // Sample EVENLY across the record list (stride) rather than only the first N, so a corruption in
      // a late shard is more likely to be caught than always reading the head. restoreRecord verifies
      // each sampled record's plaintext SHA-384 (and its per-segment chunkRange).
      if (want > 0) {
        const stride = Math.max(1, Math.floor(total / want));
        for (let i = 0; i < total && sampled < want; i += stride) {
          failingOrdinal = i;
          await run.restoreRecord(run.records[i]!);
          sampled++;
          verifiedBeforeFail = sampled;
        }
      }
      failingOrdinal = undefined;
    }
    return { status: "verified", tier, sampled, at, via: openedVia };
  } catch (e) {
    const raw = (e as Error).message;
    // A run opened from the SUPPLIED MASTER that fails the run key commitment is an ENGINE-SIDE key fault,
    // not authenticity. coarseVerifyReason maps "key commitment" to "signature check failed", the most
    // serious reason in the vocabulary, which is retryable and escalates to a critical tamper alert -- so
    // an ordering slip in the seal path (a master zeroised before the verification instead of after) would
    // spend up to SEAL_VERIFY_ATTEMPTS FULL re-reads on a metered destination and then tell the customer
    // their archive had been tampered with. The capsule path cannot reach here with a bad master (it
    // derives one), so this narrowing applies only to the master arm, and it is non-retryable because
    // re-reading cannot mend the engine's own buffer.
    const reason = openedVia === "master" && /key commitment/.test(raw) ? REASON_ENGINE_KEY_FAULT : coarseVerifyReason(raw);
    log("error", `verify-at-seal ${runId} ${tier} [${reason.replace(/ /g, "-")}]`);
    // G067: the ORDINAL (an integer index, never a key), the records that verified CLEAN first, and the
    // correlation digest of the raw text (which is never itself returned).
    return {
      status: "suspect",
      tier,
      sampled: 0,
      at,
      reason,
      // Carried on a suspect verdict too: which route was in use decides how to read the failure. A
      // master-sourced failure points at this engine; a recipient-sourced one points at the archive.
      via: openedVia,
      causeDigest: causeDigest(raw),
      ...(failingOrdinal !== undefined ? { failingOrdinal } : {}),
      ...(verifiedBeforeFail > 0 ? { verifiedBeforeFail } : {}),
    };
  }
}

function req(v: string | undefined, name: string): string {
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
}

// sealVerifyEmission builds the CRITICAL notification for a SUSPECT seal-verification. It reuses the
// existing closed event vocabulary: verify-at-seal IS a restore test on the just-written archive, so
// a failure maps to "restore-test-fail" (already critical in notify.ts severityOf). The detail is the
// downpipe name + the coarse, secret-free reason + the tier that ran; it carries NO key, value,
// shard id or object key (reason is one of the enumerated buckets). at is RFC-3339 of the verify.
export function sealVerifyEmission(downpipeId: string, downpipeName: string, v: SealVerification): NotifyEmission {
  const reason = v.reason ?? "verification check failed";
  return {
    event: "restore-test-fail",
    severity: "critical",
    downpipeId,
    downpipeName,
    detail: `Seal-verify failed for "${downpipeName}": ${reason} (${v.tier}). The just-written archive is suspect; the run was NOT failed and the archive was NOT deleted (fail-open). Run a drill/restore to confirm.`,
    at: new Date(v.at).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
  };
}

// routeSealVerifyAlert fires the critical seal-verification notification through the SAME two-phase
// DO + Worker split routeNotification uses (the DO resolves the immediate channels, this side delivers
// via the channel adapters which hold env, and posts the per-channel outcomes back so the DO records
// the redaction-safe history). It is FULLY FAIL-OPEN: deliverEmission never throws and the whole
// function is wrapped, so a routing/delivery hiccup degrades to "not delivered" rather than escaping
// into the seal path. It NEVER affects the run outcome (the run already completed). Kept here, beside
// the verify, rather than threading index.ts's routeNotification through the seal DO + run drivers.
export async function routeSealVerifyAlert(env: Env, scheduler: DurableObjectStub, emission: NotifyEmission): Promise<{ delivered: boolean; routingFailed?: boolean; historyWriteFailed?: boolean }> {
  return routeEngineNotification(env, scheduler, emission, "seal-verify");
}
