import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { type ObjectStore, openRun } from "../format/reader.ts";
import { loadIdentity, loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { classifyRestoreFailure, worseRestoreReason } from "../restore-reasons.ts";
import type { RestoreBindingName } from "./diag-records.ts";
import { errId } from "./passkey-types.ts";
import type { RestoreDestFallback } from "./restore-types.ts";

// The in-account restore drill: prove a run is recoverable without leaving the account.
// It uses the OPERATIONAL private key (the in-account read-back key, SPEC 12.6) to open
// the run, verify the chain and restore a sample record. In the break-glass-only posture
// there is no in-account read-back key, so the drill honestly reports that recovery must
// be exercised offline with the break-glass key. The break-glass private is never here.
// errId (the short, stable, opaque exception identifier for the log stream) is shared from
// passkey-types.ts so every log stream emits the identical code for the same exception.

export interface DrillResult {
  ok: boolean;
  runId: string;
  recordsVerified?: number;
  sampleRestored?: boolean;
  isLatest?: boolean;
  reason?: string;
  // destFallback: present only when the 3-2-1 walk had to fall past at least one destination to produce this
  // drill result. See RestoreDestFallback (restore-types.ts). A drill that PASSED from a replica after the
  // primary refused is not the same fact as a drill that passed from the primary, and a recency stamp that
  // cannot tell them apart says the wrong thing about the destination the customer thinks they are testing.
  destFallback?: RestoreDestFallback;
  // durationMs / bytesVerified are the MEASURED recovery-test cost (the RTO signal): the wall-clock the
  // drill took and the plaintext bytes it actually decrypted-and-verified. They feed the RTO estimate (an
  // honest recovery-time projection derived from observed drill throughput). Present only on a successful
  // drill that verified at least one record (a failed/break-glass drill measured no recoverable work);
  // honestly absent otherwise so no estimate is ever derived from a non-measurement.
  durationMs?: number;
  bytesVerified?: number;
  // downpipeId is the run's own downpipe id (from the verified root manifest), surfaced so the route can
  // stamp the per-downpipe "Last restore test" recency on a successful manual drill (the same recency the
  // scheduled restore test writes). Present only on a successful drill (the run was opened); absent on a
  // break-glass / failed drill that never read the manifest. The customer's own id, never a key or value.
  downpipeId?: string;
  // deepVerify is the windowed-cursor outcome, present ONLY when the caller ran in windowed mode
  // (the scheduled restore test). cursor is the NEXT record index to decrypt (advanced past this tick's
  // window, wrapped); records is the run's record count; wrapped is true when this tick's window reached
  // the end of the run (a full decrypt pass over every record completed). The caller persists this so the
  // next tick resumes where this one stopped, rotating full decrypt coverage across ticks.
  deepVerify?: { cursor: number; records: number; wrapped: boolean };
  // nothingToVerify: the run opened, its chain verified, and it holds ZERO records, so the drill
  // decrypted nothing and PROVED nothing about recoverability. It is set on exactly the state
  // restore-verify.ts:127 already refuses to call ok (`recordsVerified > 0`), and it exists so the caller can
  // tell this apart from a real failure: a rehearsal with nothing to rehearse is a DEFERRAL with a stated
  // cause, never a downpipe failure and never a pass. cron/restore-test-pass.ts routes on this field, and
  // getting it wrong in EITHER direction writes a false sentence into the customer's compliance evidence.
  nothingToVerify?: boolean;
  // oom (INFRA isolate-oom-restore) is the restore-subsystem OOM-risk marker: the largest single record this
  // drill buffered WHOLE (the drill has no streaming path -- every sampled record is materialised in memory to
  // hash-check it), the memory-safe single-record ceiling, and whether the largest buffered record crossed it.
  // overSafe true means a record big enough to risk an isolate OOM on restore was buffered -- the recurring,
  // pack-visible early warning that "restore OOMs on large objects" BEFORE a slightly-larger record kills the
  // isolate. Present ONLY when the drill buffered at least one record (honestly absent otherwise). A size + a flag.
  oom?: { maxRecordBytes: number; safeBytes: number; overSafe: boolean };
  // The DISCRIMINATING detail a failed drill used to throw away. "The restore test failed" is the same
  // sentence whether ONE record of 500 is corrupt or all 500 are, whether a bucket lifecycle rule expired the
  // archive object, or whether a deploy wiped SIGNER_PRIVATE and the archive is perfectly fine. These name it.
  //
  // failedRecordCount: how many records of this tick's window failed to decrypt-and-verify (1 vs 500).
  // firstFailedIndex: the index of the FIRST failing record, so support can say "0-400 verify, 401 does not"
  //                   (a lifecycle-expired chunk) rather than guessing at the blast radius.
  // missingObjectKey: the ENGINE-WRITTEN archive object key the destination could not produce (engine-generated,
  //                   never a customer record name -- the same redaction class the pack's incompleteIds ships).
  // missingBinding:   WHICH engine binding was absent. A wiped SIGNER_PRIVATE, a break-glass-only posture and a
  //                   deleted destination record are three different tickets that all read "restore test failed".
  failedRecordCount?: number;
  firstFailedIndex?: number;
  missingObjectKey?: string;
  missingBinding?: RestoreBindingName;
}

// DeepVerifyWindow is the windowed-cursor request: start at `cursor` (the persisted resume point) and
// decrypt up to `window` records, wrapping at the end of the run. The caller (the scheduled restore
// test) advances and persists the returned cursor so coverage rotates across ticks (INT-1).
export interface DeepVerifyWindow {
  cursor: number;
  window: number;
}

function req(v: string | undefined, name: string): string {
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
}

// DRILL_SAMPLE_MAX bounds how many records the drill blind-restores. A small run (<= this) is fully
// restored; a larger run restores this many at an even stride (always including index 0). The full keyed
// structural chain over EVERY record was already recomputed by openRun.
const DRILL_SAMPLE_MAX = 8;

// RESTORE_OOM_SAFE_BYTES is the memory-safe ceiling for buffering ONE restored record WHOLE on a 128 MB Worker
// isolate (INFRA isolate-oom-restore). The in-account restore drill has NO streaming path -- measureSample /
// measureWindow call run.restoreRecord, which materialises each sampled record's whole plaintext in memory to
// hash-check it -- so a record larger than this risks OOMing the isolate mid-restore (an uncatchable kill that
// wedges the recovery). It mirrors the restore APPLY path's buffered ceiling (restore-sinks.ts
// BUFFERED_RESTORE_MAX_BYTES, above which the apply STREAMS): 32 MiB leaves ~4x headroom on the dominant ~2x
// decode/concat peak. The drill emits an OBSERVE-side marker (DrillResult.oom) recording the largest record it
// buffered and whether it crossed this ceiling, so "my restore OOMs on large objects" is visible BEFORE a
// slightly-larger record actually kills the isolate. A size threshold + a flag; never a key, value or plaintext.
export const RESTORE_OOM_SAFE_BYTES = 32 * 1024 * 1024; // 32 MiB

// NOTHING_TO_VERIFY_REASON is the drill's sentence for a run that holds no records. It is a REASON rather
// than a failure message on purpose: it states what the rehearsal could not establish, and names the thing
// to look at (the source, not the archive), because an empty archive over an empty source is a capture-side
// question and telling the customer their backup "failed its restore test" would point them at the wrong end.
// Exported so the cron and the tests assert the same string rather than two copies of it.
export const NOTHING_TO_VERIFY_REASON = "the run holds no records, so nothing was decrypted and recoverability was not established; check whether the source is genuinely empty";

// SampleMeasure is the drill's RTO signal: the verified plaintext byte total, the wall-clock duration of
// the read-back, and whether any record was actually restored. maxRecordBytes is the OOM-risk observation
// (INFRA isolate-oom-restore): the largest SINGLE record this drill buffered whole via restoreRecord (0 when
// nothing was buffered), so the caller can flag a record big enough to risk an isolate OOM on restore.
interface SampleMeasure {
  bytesVerified: number;
  durationMs: number;
  sampleRestored: boolean;
  maxRecordBytes: number;
}

// WindowMeasure extends SampleMeasure with the windowed-cursor bookkeeping (INT-1): the advanced cursor,
// the run's record count, whether this window wrapped past the end (a full pass), how many records in the
// window failed to decrypt-and-verify, and the coarse reason of the first such failure (for the drill
// result). measureWindow DRAINS per-record failures rather than throwing, so one corrupted record does
// not wedge the cursor: the tick reports the failure AND still advances coverage past it.
interface WindowMeasure extends SampleMeasure {
  newCursor: number;
  records: number;
  wrapped: boolean;
  failures: number;
  // The WORST reason among the drained failures, not the first: worseRestoreReason (restore-reasons.ts) lets
  // a finding about the archive beat an availability fault on this destination. It is deliberately NOT paired
  // with firstFailedIndex below, which answers a different question. They can name different records, and the
  // pair is honest that way: "damage starts at index N" and "the worst thing found in this window was X".
  worstReason: string | null;
  firstFailedIndex: number | null; // G029: the index of the FIRST record that would not decrypt-and-verify
}

// measureSample stride-samples records SPREAD across the run (not only records[0]), so a ciphertext/AEAD
// corruption anywhere in the archive is exercised, while staying cost-bounded on the customer's metered
// account. It times the read-back-and-verify and sums the verified plaintext bytes: restoreRecord opens +
// decrypts + hash-checks each record, the same read-back a recovery does, so its aggregate throughput is the
// honest proxy for recovery time. performance.now() is monotonic.
async function measureSample(run: Awaited<ReturnType<typeof openRun>>): Promise<SampleMeasure> {
  const total = run.records.length;
  const want = Math.min(total, DRILL_SAMPLE_MAX);
  const stride = want > 0 ? Math.max(1, Math.floor(total / want)) : 1;
  const startedAt = performance.now();
  let bytesVerified = 0;
  let samplesRestored = 0;
  let maxRecordBytes = 0;
  for (let i = 0; i < total && samplesRestored < want; i += stride) {
    const rec = run.records[i];
    if (!rec) continue;
    const value = await run.restoreRecord(rec); // verifies the plaintext hash; throws on integrity failure
    bytesVerified += value.length;
    if (value.length > maxRecordBytes) maxRecordBytes = value.length; // OOM-risk observation (isolate-oom-restore)
    samplesRestored++;
  }
  return { bytesVerified, durationMs: Math.max(0, Math.round(performance.now() - startedAt)), sampleRestored: samplesRestored > 0, maxRecordBytes };
}

// measureWindow decrypts a WINDOW of records starting at `cursor` (the persisted resume point), wrapping
// at the end of the run, so successive scheduled ticks rotate FULL decrypt coverage across the whole run
// (INT-1) instead of re-sampling the same strided records forever. It DRAINS per-record failures (a
// corrupted record is counted, not thrown) so the cursor still advances past a bad record and coverage
// continues; the failure is surfaced via failures/worstReason and the caller raises the critical alert.
// Every drained failure is CLASSIFIED, and the window reports the WORST of them (worseRestoreReason), never
// the first in cursor order. Cursor order is arbitrary and rotates per tick, so first-wins made a window
// holding both a transient segment fetch fault and a genuine AEAD failure report whichever the cursor
// happened to reach first: on one ordering that is a replica-fallback-eligible availability reason, and
// withRunDestFallback (router-sources.ts) would then serve the run from a replica with the tamper on THIS
// destination never reported. Worst-wins is derived from isReplicaFallbackReason, so a finding always wins.
// It times the read-back and sums verified plaintext bytes exactly as measureSample does (the same RTO
// signal). The returned newCursor is the next index to decrypt; wrapped is true when this window reached
// the end of the run (a full pass completed).
async function measureWindow(run: Awaited<ReturnType<typeof openRun>>, cursor: number, window: number): Promise<WindowMeasure> {
  const total = run.records.length;
  const startedAt = performance.now();
  if (total === 0) {
    return { bytesVerified: 0, durationMs: 0, sampleRestored: false, maxRecordBytes: 0, newCursor: 0, records: 0, wrapped: true, failures: 0, worstReason: null, firstFailedIndex: null };
  }
  // Normalise the persisted cursor into range (a record-count change since the last tick, or a malformed
  // value, can never index out of bounds). Math handles a negative cursor too.
  const start = ((Math.trunc(cursor) % total) + total) % total;
  const count = Math.min(Math.max(1, Math.trunc(window)), total);
  let bytesVerified = 0;
  let restored = 0;
  let failures = 0;
  let worstReason: string | null = null;
  let firstFailedIndex: number | null = null; // G029
  let maxRecordBytes = 0;
  for (let k = 0; k < count; k++) {
    const i = (start + k) % total;
    try {
      const value = await run.restoreRecord(run.records[i]!); // decrypts + hash-checks; throws on integrity failure
      bytesVerified += value.length;
      if (value.length > maxRecordBytes) maxRecordBytes = value.length; // OOM-risk observation (isolate-oom-restore)
      restored++;
    } catch (e) {
      failures++;
      worstReason = worseRestoreReason(worstReason, classifyRestoreFailure(e));
      if (firstFailedIndex === null) firstFailedIndex = i; // G029: WHICH record, not merely that one failed
    }
  }
  return {
    bytesVerified,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    sampleRestored: restored > 0,
    maxRecordBytes,
    newCursor: (start + count) % total,
    records: total,
    wrapped: start + count >= total,
    failures,
    worstReason,
    firstFailedIndex,
  };
}

// classifyDrillError maps a raw exception to a coarse, enumerated reason so the response never discloses
// internals; operators get the detail from the engine logs. It delegates to the shared
// classifyRestoreFailure so the drill classifies by the reader's STRUCTURED failure category
// (RunIntegrityError): a completeness/structural/integrity failure is always the non-fallback "integrity
// check failed", never mis-routed by a message the old per-site regex did not match.
function classifyDrillError(e: unknown): string {
  return classifyRestoreFailure(e);
}

// oomMarker builds the DrillResult OOM-risk marker (INFRA isolate-oom-restore) from the largest single record
// the drill buffered WHOLE, or undefined when nothing was buffered (honestly absent, so no false marker rides).
// overSafe flags a record past the memory-safe single-record ceiling -- a buffer big enough to risk an isolate
// OOM on restore. A size + the ceiling + a flag; never a key, value or plaintext.
function oomMarker(maxRecordBytes: number): { maxRecordBytes: number; safeBytes: number; overSafe: boolean } | undefined {
  if (maxRecordBytes <= 0) return undefined;
  return { maxRecordBytes, safeBytes: RESTORE_OOM_SAFE_BYTES, overSafe: maxRecordBytes > RESTORE_OOM_SAFE_BYTES };
}

export async function runDrill(env: Env, runId: string, destOverride?: RuntimeDestConfig | null, deepVerify?: DeepVerifyWindow): Promise<DrillResult> {
  if (!env.OPERATIONAL_PRIVATE) {
    // G029: an HONEST refusal, not a failure. The closed reason classifies to `posture-unexercisable` (never
    // `not-configured`), and missingBinding names the absent key, so a fleet of amber "failed last test" rows
    // stops sending support after a fault that does not exist.
    // The "break-glass-only posture" PREFIX is load-bearing: classifyDiagFaultReason (diag-records.ts) keys the
    // posture-unexercisable class on exactly that prefix, so it may be extended but never reworded.
    // IT NAMES THE IN-PRODUCT ROUTES FIRST, and that is a correction rather than a flourish. This message used
    // to offer the offline CLI as the only way forward, which read as "there is nothing you can do from here"
    // and contradicts the product's own no-customer-CLI rule. Two in-product routes exist: an ATTENDED
    // verification proves recovery from the browser on exactly this posture (attended-cadence.ts is the whole
    // module for it), and POST /admin/keys/add-operational installs a fresh operational pair, which brings
    // unattended drills back for runs sealed after it. The offline route stays, last, because it is the only
    // one that reaches archives sealed before an operational key was ever present.
    return {
      ok: false,
      runId,
      reason:
        "break-glass-only posture: no in-account read-back key. Prove recovery in-product with an attended verification, or add an operational key to bring unattended drills back for future runs; recovery offline with the break-glass key and the downpipe CLI stays available for archives sealed before that.",
      missingBinding: "operational-private",
    };
  }
  // G029: the archive object key the destination could not produce. Captured AT THE THROW SITE (never parsed
  // back out of a message), so the recorded value is exactly the key the engine asked for and nothing else.
  let missingObjectKey: string | undefined;
  try {
    const signer = await loadSigner(req(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
    const verifier = verifierFrom(signer);
    const identity = loadIdentity(env.OPERATIONAL_PRIVATE);
    const dest = await buildDestination(env, undefined, destOverride ?? null);
    const store: ObjectStore = {
      get: async (k: string) => {
        const r = await dest.get(k);
        if (!r) {
          missingObjectKey = k; // G029: name the object, at the site that knows it
          throw new Error(`object ${k} is missing`);
        }
        return r.body;
      },
    };
    // allowStale so the drill reports recoverability + freshness rather than failing on
    // an older run; the result surfaces isLatest for the operator.
    const run = await openRun(store, runId, identity, verifier, { verifyFreshness: true, allowStale: true });
    // The Run owns the master until it is disposed, and every return below leaves this block, so the
    // finally is what guarantees the master does not outlive the drill on any of them.
    try {
      // Windowed mode (the scheduled restore test, INT-1): decrypt this tick's window and report the
      // advanced cursor so coverage rotates across ticks. measureWindow DRAINS per-record failures, so a
      // corrupted record is reported (ok:false) while the cursor still advances past it. Manual mode keeps
      // the strided sample unchanged.
      if (deepVerify) {
        const w = await measureWindow(run, deepVerify.cursor, deepVerify.window);
        const wOom = oomMarker(w.maxRecordBytes);
        // ZERO RECORDS IS NOT A PASS. This is the clause restore-verify.ts:127 has carried all
        // along -- `ok: failures.length === 0 && recordsVerified > 0` -- and the drill did not, so the two
        // routes answered the SAME question about the SAME run in the SAME minute with ok:false and ok:true.
        // The drill's verdict is the one that travels: it stamps lastRestoreTestOk, which posture-checks.ts
        // reads as "restore tested recently", and it writes the drill-evidence note. So an estate whose
        // source was empty accumulated evidence rows reading "scheduled restore test passed (records
        // verified: 0)" -- our own compliance artefact asserting a restore test passed over nothing.
        //
        // MEASURED LIVE (an internal chaos test suite): NINETEEN consecutive runs
        // sealed zero records, and the scheduled test over them stamped lastRestoreTestOk:true.
        //
        // The zero-record case was ALREADY recognised in this same return statement, and only where a NUMBER
        // is derived rather than where the VERDICT is: the RTO measurement is deliberately withheld because
        // "a zero-record run measured no recoverable work". It then called it a pass.
        const wNothing = run.records.length === 0;
        return {
          ok: w.failures === 0 && !wNothing,
          // The reason is stated FIRST so a genuine per-record failure below still overrides it: a run that
          // both held records and failed them is a failure, not a deferral.
          ...(wNothing ? { nothingToVerify: true, reason: NOTHING_TO_VERIFY_REASON } : {}),
          runId,
          recordsVerified: run.records.length,
          sampleRestored: w.sampleRestored,
          isLatest: run.freshness?.isLatestForDownpipe ?? false,
          ...(run.root.downpipeId ? { downpipeId: run.root.downpipeId } : {}),
          ...(w.sampleRestored ? { durationMs: w.durationMs, bytesVerified: w.bytesVerified } : {}),
          // The OOM-risk marker (isolate-oom-restore): present whenever a record was buffered this window, even on
          // a drained per-record failure, so the isolate-OOM early warning rides regardless of the pass/fail verdict.
          ...(wOom ? { oom: wOom } : {}),
          deepVerify: { cursor: w.newCursor, records: w.records, wrapped: w.wrapped },
          ...(w.failures > 0 ? { reason: w.worstReason ?? "recovery check failed" } : {}),
          // G029: the blast radius + the first failing index. A single corrupt record and a wholly-corrupt
          // archive produce the same reason today; these two ints are the difference.
          ...(w.failures > 0 ? { failedRecordCount: w.failures } : {}),
          ...(w.firstFailedIndex !== null ? { firstFailedIndex: w.firstFailedIndex } : {}),
        };
      }
      const { bytesVerified, durationMs, sampleRestored, maxRecordBytes } = await measureSample(run);
      const sOom = oomMarker(maxRecordBytes);
      // ZERO RECORDS IS NOT A PASS, the MANUAL-mode half of the same clause. `ok: true` here was
      // unconditional: it did not read the sample it had just measured, so a run holding no records returned
      // ok:true with recordsVerified:0 and sampleRestored:false. router-restore.ts and router-pipelines.ts
      // both stamp lastRestoreTestOk from this field, so the manual route wrote the same false pass the
      // scheduled one did.
      const sNothing = run.records.length === 0;
      return {
        ok: !sNothing,
        ...(sNothing ? { nothingToVerify: true, reason: NOTHING_TO_VERIFY_REASON } : {}),
        runId,
        recordsVerified: run.records.length,
        sampleRestored,
        isLatest: run.freshness?.isLatestForDownpipe ?? false,
        // The run's own downpipe id (verified root manifest), so the route can stamp the "Last restore test"
        // recency for this downpipe on a successful manual drill, exactly as the scheduled test does.
        ...(run.root.downpipeId ? { downpipeId: run.root.downpipeId } : {}),
        // Only surface the RTO measurement when a record was actually verified (a zero-record run measured no
        // recoverable work, so it yields no throughput sample and no fabricated estimate downstream).
        ...(sampleRestored ? { durationMs, bytesVerified } : {}),
        // The OOM-risk marker (isolate-oom-restore): present whenever the drill buffered at least one record.
        ...(sOom ? { oom: sOom } : {}),
      };
    } finally {
      run.dispose();
    }
  } catch (e) {
    const reason = classifyDrillError(e);
    log("error", `drill ${runId} [err:${errId(e)} ${reason.replace(/ /g, "-")}]`);
    // G029: which ENGINE BINDING was absent, when that is what refused. req() names the env var it is missing;
    // the destination build names itself. Both are closed members of RESTORE_BINDING_NAMES -- never a value, a
    // key, an endpoint or a bucket -- so "a deploy wiped SIGNER_PRIVATE" stops reading as "your archive is bad".
    const msg = e instanceof Error ? e.message : "";
    const missingBinding: RestoreBindingName | undefined = msg.includes("missing required configuration: SIGNER_PRIVATE")
      ? "signer-private"
      : msg.startsWith("missing required configuration") || msg.includes("destination configuration") || msg.includes("is not configured")
        ? "dest-config"
        : undefined;
    return {
      ok: false,
      runId,
      reason,
      ...(missingObjectKey !== undefined ? { missingObjectKey } : {}),
      ...(missingBinding !== undefined ? { missingBinding } : {}),
    };
  }
}
