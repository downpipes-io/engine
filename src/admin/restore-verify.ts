import { concat, hexDecode, hexEncode, u32be, utf8 } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import type { ShardRecord } from "../format/manifest.ts";
import { attestKeyless, type ObjectStore } from "../format/reader.ts";
import { VERSION } from "../format/version.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { classifyRestoreFailure } from "../restore-reasons.ts";
import { inScope } from "../sources/selector.ts";
import { NOTHING_TO_VERIFY_REASON } from "./drill.ts";
import { openVerifiedRun, reqEnv } from "./restore-open.ts";
import { BREAK_GLASS_REASON, bufferedRestoreMaxBytes, errId, shouldStream, verifyRecordStreamingDiscard } from "./restore-sinks.ts";
import type { BlindRestoreTest, KeylessAttestationResult, RestoreFailure, RestoreRequest } from "./restore-types.ts";
import { doURL } from "../do-url.ts";

// foldDigestLeaf folds one verified record into the running restore digest. The accumulator is
// SHA-384(prevAcc || u32be(len(recordId)) || recordIdBytes || verifiedPlaintextSha384Bytes): the
// per-record input is the recordId and the plaintext SHA-384 that restoreRecord PROVED equals the actual
// decrypted plaintext, so the digest is genuinely a function OF the verified-restored plaintext WITHOUT
// the plaintext itself ever entering the hash input (it folds recordId + plaintextSha384, never a
// plaintext byte, so the digest cannot be a confirmation oracle for a guessed value). Records are folded
// in recordId order (sorted by the caller) so the digest is a stable function of the data set, not the
// iteration order, and the SAME archive restoring yields the SAME restoreDigest. It binds no key and
// discloses no value.
//
// This is NOT byte-identical to the Go offline reader's "discard" restore digest, by design. Both fold a
// per-record plaintext SHA-384 (never the plaintext) and are deterministic and content-sensitive, but the
// constructions differ: here we CHAIN a re-hash over (recordId, plaintextSha384) in recordId-sorted order;
// the Go discard target STREAMS (destinationKey, plaintextSha384) through one running SHA-384 in iteration
// order. They are two independent recoverability proofs of the same data, not a shared value to compare.
async function foldDigestLeaf(acc: Uint8Array, rec: ShardRecord): Promise<Uint8Array> {
  const recordIdBytes = utf8(rec.recordId);
  const plaintextHashBytes = hexDecode(rec.plaintextSha384);
  return sha384(concat(acc, u32be(recordIdBytes.length), recordIdBytes, plaintextHashBytes));
}

// runBlindRestoreTest is the BLIND restore test (restorability assurance, keyed Tier). It opens and
// verifies the run with the in-account read-back key (the same openVerifiedRun the restore dry-run uses),
// then decrypts EVERY in-scope record to a DISCARD sink: restoreRecord materialises the plaintext, checks
// its SHA-384 against the signed recordHash, and the bytes are summed for the throughput figure and then
// DROPPED (the local `value` falls out of scope each iteration; it is never returned, never logged, never
// written). A large R2 record instead takes the constant-memory shouldStream/verifyRecordStreamingDiscard
// path -- the SAME guard restore-plan.ts's dry-run and restore-apply.ts's verify phase apply to this
// identical record set -- so a multi-GB value is fully decrypted-and-verified without ever being held
// whole; either way bytesVerified counts the record's proven plaintext size. It returns an attestation
// { runId, recordsVerified, bytesVerified, failures, restoreDigest }:
// restoreDigest folds each verified record's (recordId, plaintextSha384) so a repeat test proves the SAME
// data restores, computed WITHOUT exposing plaintext. Like the drill/restore it is break-glass-aware: with
// no in-account read-back key it honestly reports ok:false with the break-glass reason rather than erroring.
// It is on the recovery path, so it NEVER consults the licence. A per-record decryption/verification
// failure is drained into failures (the archive is partially unrecoverable) without aborting the rest, so
// the operator sees EVERY bad record in one pass. selectors/maxRecords scope the test the same way the
// dry-run scopes its plan. CRITICALLY this function and its callers log only counts and coarse reasons;
// no branch here ever emits a record value.
// scheduler is OPTIONAL (HI-05): when supplied (the real router-restore.ts /restore/verify caller always has
// one in scope, exactly like its sibling /restore/attest), its live runlogCounter pins minRunlogIndex on the
// underlying openVerifiedRun so a whole-document RUNLOG replay is caught even when the replayed snapshot is
// itself internally consistent -- this endpoint persists the SAME stampRestoreProven compliance stamp on a
// pass that /restore/attest does, so it needs the identical protection; omitted (as every existing test
// call is), behaviour is byte-for-byte unchanged from before this pin existed.
export async function runBlindRestoreTest(env: Env, body: RestoreRequest, destOverride?: RuntimeDestConfig | null, scheduler?: DurableObjectStub): Promise<BlindRestoreTest> {
  const runId = body.runId;
  if (!env.OPERATIONAL_PRIVATE) {
    return { ok: false, runId, recordsVerified: 0, bytesVerified: 0, failures: [], restoreDigest: null, isLatest: false, reason: BREAK_GLASS_REASON };
  }
  try {
    const minRunlogIndex = await fetchMinRunlogIndex(scheduler);
    const run = await openVerifiedRun(env, runId, destOverride ?? null, minRunlogIndex);
    try {
      // Resolved once per call: RESTORE_BUFFERED_MAX_BYTES only ever LOWERS this (a test forcing the
      // streaming path), matching restore-plan.ts/restore-apply.ts's identical resolution.
      const bufferedMaxBytes = bufferedRestoreMaxBytes(env);
      const isLatest = run.freshness?.isLatestForDownpipe ?? false;
      // recordName scopes a single-record verify EXACTLY (the same first-class granular intent the restore
      // path honours): when set, only the record whose name equals it is tested, superseding the prefix
      // selector. Otherwise the prefix include/exclude selector applies unchanged.
      const recordName = typeof body.recordName === "string" && body.recordName.length > 0 ? body.recordName : null;
      const selector = { include: body.include ?? [], exclude: body.exclude ?? [] };
      // The in-scope set, capped by maxRecords (a large run can be tested in bounded windows). Sort by
      // recordId so the restoreDigest is a stable function of the verified data set, independent of the
      // manifest's record order, so the same archive always yields the same digest.
      const inScopeRecords = run.records.filter((rec) => (recordName !== null ? rec.name === recordName : inScope(rec.name, selector)));
      inScopeRecords.sort((a, b) => (a.recordId < b.recordId ? -1 : a.recordId > b.recordId ? 1 : 0));
      const window = body.maxRecords && body.maxRecords >= 1 ? inScopeRecords.slice(0, body.maxRecords) : inScopeRecords;

      const failures: RestoreFailure[] = [];
      let recordsVerified = 0;
      let bytesVerified = 0;
      // The digest accumulator starts from a fixed domain-separation label so an empty set and a single
      // empty record do not collide, and the digest is bound to "this is a restore-verify digest".
      let acc: Uint8Array = await sha384(utf8(`${VERSION} restore-verify-digest`));
      for (const rec of window) {
        try {
          // A large R2 record takes the constant-memory streaming-discard path (mirrors restore-plan.ts's
          // dry-run and restore-apply.ts's verify phase over this SAME record set): buffering it whole here
          // risked exceeding the Worker isolate's memory ceiling on exactly the "prove recoverability" path
          // this function exists for. verifyRecordStreamingDiscard authenticates every chunk and checks the
          // final plaintext SHA-384 exactly as restoreRecord does below, so it throws on the identical
          // failures and the catch below needs no branch-specific handling.
          if (shouldStream(rec, bufferedMaxBytes)) {
            await verifyRecordStreamingDiscard(run, rec);
            bytesVerified += rec.plaintextSize;
          } else {
            // restoreRecord decrypts the record and verifies the plaintext SHA-384 against the signed
            // recordHash. We take ONLY value.length (the discard sink: bytes flow in, the count flows out,
            // the bytes are dropped at the end of the iteration). The value is never returned or logged.
            const value = await run.restoreRecord(rec);
            bytesVerified += value.length;
          }
        } catch (e) {
          // A record that does not decrypt-and-verify is a per-record failure (the archive is partially
          // unrecoverable here); record the coarse reason and continue so the operator sees every bad
          // record. The reason carries the source name (the customer's own key) and an opaque error id,
          // never a value or a stack.
          log("error", `restore-verify ${runId} record ${rec.name} [err:${errId(e)} record-verify-failed]`);
          failures.push({ name: rec.name, reason: "record failed its integrity check", cls: "integrity" });
          continue;
        }
        recordsVerified++;
        acc = await foldDigestLeaf(acc, rec);
        // the plaintext is discarded, never retained: the buffered `value` falls out of scope here, and
        // the streaming path never materialised it at all.
      }

      // WIRE-28: a run holding no records (an empty source, never a selector emptied by the guarded
      // empty-prefix check above) leaves recordsVerified at 0 and failures empty -- the SAME shape a caller
      // cannot distinguish from "the freshness check refused this run" or "every record failed", because
      // openVerifiedRun would have thrown for either of THOSE before this point was ever reached. So
      // recordsVerified===0 && failures.length===0, reached here, means exactly one thing: the run's own
      // record set was empty. ok stays false (drill.ts's "zero records is not a pass" clause, mirrored here
      // on purpose -- this line is the twin restore-verify.ts:127 the drill's own comment names), but the
      // caller now gets the same {nothingToVerify:true, reason} pair the scheduled/manual drill already
      // returns for the identical state, so a fresh seal against an as-yet-unseeded source reads as
      // "nothing to verify yet" rather than "verification failed".
      const nothingToVerify = recordsVerified === 0 && failures.length === 0 && run.records.length === 0;
      return {
        ok: failures.length === 0 && recordsVerified > 0,
        runId,
        downpipeId: run.root.downpipeId,
        recordsVerified,
        bytesVerified,
        failures,
        restoreDigest: recordsVerified > 0 ? `sha384:${hexEncode(acc)}` : null,
        isLatest,
        ...(nothingToVerify ? { nothingToVerify: true as const, reason: NOTHING_TO_VERIFY_REASON } : {}),
      };
    } finally {
      run.dispose();
    }
  } catch (e) {
    // Map the failure to the same coarse, enumerated reason runRestore uses (the shared
    // classifyRestoreFailure), so a tampered or truncated archive classifies as the non-fallback "integrity
    // check failed" by the reader's STRUCTURED category, never leaking the raw exception. Detail -> log.
    const reason = classifyRestoreFailure(e);
    log("error", `restore-verify ${runId} [err:${errId(e)} ${reason.replace(/ /g, "-")}]`);
    return { ok: false, runId, recordsVerified: 0, bytesVerified: 0, failures: [], restoreDigest: null, isLatest: false, reason };
  }
}

// fetchMinRunlogIndex reads the scheduler DO's own account-global runlogCounter (GET /scheduler-signals
// -> scheduler-do-scheduling.ts schedulerSignals) as the out-of-band anti-rollback pin (HI-05): it is
// allocated independently of the destination bucket a keyless attestation OR a blind restore test reads,
// so a bucket-write adversary who replays an older, whole, validly-signed RUNLOG snapshot cannot roll this
// number back too. Shared by both runKeylessAttest and runBlindRestoreTest below (their two callers gate
// the identical stampRestoreProven compliance stamp, so both need the identical protection). Best-effort
// and fail-open, matching this file's recovery-path discipline throughout: a missing scheduler, a
// fetch/parse hiccup, or a non-finite value leaves the pin undefined -- today's behaviour, never a reason
// the attestation/test itself fails.
async function fetchMinRunlogIndex(scheduler: DurableObjectStub | undefined): Promise<number | undefined> {
  if (!scheduler) return undefined;
  try {
    const r = await scheduler.fetch(doURL("/scheduler-signals"), { method: "GET" });
    const j = (await r.json()) as { runlog?: unknown };
    const rl = j.runlog && typeof j.runlog === "object" ? (j.runlog as Record<string, unknown>) : null;
    const counter = rl ? Number(rl.counter) : NaN;
    return Number.isFinite(counter) && counter >= 0 ? counter : undefined;
  } catch {
    return undefined;
  }
}

// runKeylessAttest is the Tier 0 keyless integrity attestation: it verifies the manifest signature, the
// shard-presence completeness, the per-record/Merkle commitment (via the signature that covers them) and
// the RUNLOG anti-rollback WITHOUT any decryption key and WITHOUT touching record plaintext. It needs only
// the PUBLIC verifier (derived from the signer the engine holds to sign runs) and the destination as a
// read-only ObjectStore, so it runs even in the break-glass-only posture where there is no in-account
// read-back key. attestKeyless (reader.ts) is total (never throws), so this wrapper only loads the verifier
// + destination and maps the reader result onto the wire type; a configuration error (no signer) is the one
// thing that can throw here and is mapped to a coarse ok:false. It NEVER consults the licence (recovery path).
// scheduler is OPTIONAL (HI-05): when supplied (the real router-restore.ts caller always has one in scope),
// its live runlogCounter pins minRunlogIndex so a whole-document RUNLOG replay is caught even when the
// replayed snapshot is itself internally consistent; omitted (as every existing test call is), behaviour is
// byte-identical to before this pin existed.
export async function runKeylessAttest(env: Env, body: RestoreRequest, destOverride?: RuntimeDestConfig | null, scheduler?: DurableObjectStub): Promise<KeylessAttestationResult> {
  const runId = body.runId;
  try {
    const signer = await loadSigner(reqEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
    const verifier = verifierFrom(signer);
    const dest = await buildDestination(env, undefined, destOverride ?? null);
    const store: ObjectStore = {
      get: async (k: string) => {
        const r = await dest.get(k);
        if (!r) throw new Error(`object ${k} is missing`);
        return r.body;
      },
    };
    const minRunlogIndex = await fetchMinRunlogIndex(scheduler);
    const att = await attestKeyless(store, runId, verifier, { allowStale: true, ...(minRunlogIndex !== undefined ? { minRunlogIndex } : {}) });
    const ok = att.signatureValid && att.complete && att.notRolledBack;
    return {
      ok,
      runId,
      ...(att.downpipeId !== null ? { downpipeId: att.downpipeId } : {}),
      signatureValid: att.signatureValid,
      complete: att.complete,
      notRolledBack: att.notRolledBack,
      ...(att.reason !== null ? { reason: att.reason } : {}),
    };
  } catch (e) {
    const m = (e as Error).message;
    const reason = /missing required configuration/.test(m) ? "engine not fully configured" : "attestation could not be run";
    log("error", `restore-attest ${runId} [err:${errId(e)} ${reason.replace(/ /g, "-")}]`);
    return { ok: false, runId, signatureValid: false, complete: false, notRolledBack: false, reason };
  }
}
