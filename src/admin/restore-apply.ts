import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { Env } from "../env.d.ts";
import type { ShardRecord } from "../format/manifest.ts";
import type { Run } from "../format/reader.ts";
import { type MediaFaultClass, type MediaUploader, mediaFaultOf } from "./media-restore.ts";

// MEDIA_CONFLICT_DIGESTS_MAX bounds the conflict-digest evidence carried on one apply: a handful of adjudicable
// disputes is the diagnostic value, and a restore of ten thousand conflicting images must not grow the record.
const MEDIA_CONFLICT_DIGESTS_MAX = 8;

import { type D1FaultEvidence, d1FaultEvidence, drainMetadataShed, sanitiseMetadataShed } from "../dest/restore-fault.ts";
import { putOptionsFromRecord, ReadbackNotSupportedError } from "../dest/restore-sink.ts";
import { log } from "../log.ts";
import { destAccessReason } from "../restore-reasons.ts";
import { cfSkipCounts } from "../sources/cf-config-fault.ts";
import type { CfApi } from "../sources/cf-config-surfaces.ts";
import { coarseCfReason, decodeConfigSnapshot } from "./restore-cfconfig.ts";
import { crossAccountRefusalReason, crossZoneConfirmed, crossZoneWarning, originZoneFrom, unconfirmedCrossAccountLegs } from "./restore-cross-account.ts";
import type { RestorePlanState } from "./restore-plan-types.ts";
import { makeRestoreReceipt } from "./restore-receipt.ts";
import {
  d1GroupOfDataRecord,
  errId,
  inAccountTooLargeReason,
  inAccountWindow,
  MAX_IN_ACCOUNT_RESTORE_RECORDS,
  type Resolved,
  shouldStream,
  verifyReadbackStreaming,
  verifyRecordStreamingDiscard,
  windowSkippedReason,
} from "./restore-sinks.ts";
import type { CfConfigSkipClass, RestoreDestFallback, RestoreFailure, RestoreReceiptRecord, RestoreRequest, RestoreResult, RestoreSinkType, RestoreSkipped } from "./restore-types.ts";

// CF_SKIP_REMEDY names, per closed cf-config skip class, what an operator does about an item the Cloudflare
// API refused. It is operator-facing prose on the LIVE response only; what is recorded (audit chain, receipt,
// support pack) is the CLASS, never this string and never the raw Cloudflare message it was classified from.
const CF_SKIP_REMEDY: Record<Exclude<CfConfigSkipClass, "entitlement">, string> = {
  auth: "the Cloudflare token supplied under Restore was rejected or lacks the edit scope for this surface, so nothing on it applied; widen the token's scope and re-run the restore",
  quota: "the account is at its plan limit for this resource, so there was no room for the item; free space or raise the plan, then re-run the restore",
  validation: "Cloudflare refused the snapshot item as invalid; raise this with support quoting the run id, and recover the surface from the verified snapshot out of band",
  conflict: "a live item already occupies the same key; remove or rename it in Cloudflare, then re-run the restore",
  "no-live-id": "the item differs from live but the live item carries no id to update in place, so there was nothing to write to; re-create it from the verified snapshot out of band",
  "no-live-phase": "no live ruleset exists for this phase, and creating a phase entrypoint is a reprovisioning step a restore does not take; provision it in Cloudflare, then re-run the restore",
  "live-only-rules": "the live ruleset holds rules the snapshot does not and a restore never deletes, so the ruleset was left as it is; the extra rules are named in the diff",
  "rate-limited": "Cloudflare rate-limited the write; re-run the restore",
  "api-unavailable": "Cloudflare returned a server-side fault; re-run the restore",
  other: "Cloudflare refused the item for a reason the engine does not recognise; its own message is in this response",
};

/**
 * unrestoredCfSkips returns the entries of a surface's skip tally that mean AN ITEM FROM THE VERIFIED ARCHIVE
 * IS NOT IN THE ACCOUNT.
 *
 * Every closed class means that except `entitlement`, which cf-config-fault.ts documents as benign and
 * permanent: the account's PLAN does not carry the surface or feature, so there is no item to restore, nothing
 * to fix, and the surface is as applied as it can be. Failing an apply on an entitlement refusal would redden
 * a restore that is complete with respect to the account, which trains an operator to stop reading `ok`.
 *
 * The line is drawn here rather than at `auth` alone on purpose. `auth` is the sharpest case, because
 * cf-config-fault.ts says it will have refused EVERY item on the surface and because it is caused by the
 * caller's own supplied token, which is exactly what the console restore form asks for. But a quota refusal, a
 * validation refusal and a rate-limited item leave the account equally short of the archive, and reporting
 * those as success is the same defect wearing a different class.
 *
 * @param counts - the surface's {class: count} skip tally.
 * @returns the [class, count] pairs that leave the surface unrestored (empty when the surface fully applied).
 */
function unrestoredCfSkips(counts: Partial<Record<CfConfigSkipClass, number>>): Array<[Exclude<CfConfigSkipClass, "entitlement">, number]> {
  const out: Array<[Exclude<CfConfigSkipClass, "entitlement">, number]> = [];
  for (const [cls, n] of Object.entries(counts)) {
    if (cls === "entitlement" || n === undefined || n <= 0) continue;
    out.push([cls as Exclude<CfConfigSkipClass, "entitlement">, n]);
  }
  return out;
}

/**
 * cfUnrestoredReason renders the operator-facing failure prose for a surface that did not fully apply: the
 * count per class, then the remedy for each class present. It names the count because "your restore skipped
 * some items" is not actionable, and the remedy because the class alone is engine vocabulary.
 *
 * @param unrestored - the [class, count] pairs from unrestoredCfSkips (never empty at the call site).
 * @returns the reason string for the RestoreFailure.
 */
function cfUnrestoredReason(unrestored: Array<[Exclude<CfConfigSkipClass, "entitlement">, number]>): string {
  const counted = unrestored.map(([cls, n]) => `${n} refused as ${cls}`).join("; ");
  const remedy = unrestored.map(([cls]) => CF_SKIP_REMEDY[cls]).join(" ");
  return `this Cloudflare config surface did not fully apply, so items from the verified archive are not in the account (${counted}). ${remedy}`;
}

// applyDataRecords runs the apply path's two write phases for the in-scope data records (KV/R2/D1): first
// verify EVERY record's plaintext hash (read-only, nothing written; a failure aborts with nothing landed),
// then write each back with a post-write readback proof per record. It MUTATES the failures + receiptRecords
// arrays the caller owns and returns the running counts, EXACTLY as the inline apply loops did. A whole-run
// integrity abort is signalled by returning aborted:true so the caller renders the "integrity check failed"
// result. cf-config and media applies run afterwards in runApply (the verify-all-before-write discipline).
async function applyDataRecords(run: Run, window: Array<{ rec: ShardRecord; resolved: Resolved }>, bufferedMaxBytes: number, runId: string, failures: RestoreFailure[], receiptRecords: RestoreReceiptRecord[], outOfBand: RestoreSkipped[]): Promise<{ recordsVerified: number; recordsRestored: number; bytesRestored: number; aborted: boolean; d1Fault?: D1FaultEvidence }> {
  // The FIRST D1 fault's closed evidence (class + the batch that broke + the batch total, or the
  // residual-table count of a refused fresh-target check). First, not last: the earliest fault is the one that
  // localises where the apply stopped, and a later record's fault cannot un-break the database.
  let d1Fault: D1FaultEvidence | undefined;
  // d1FaultedGroups: the D1 database names (d1GroupOfDataRecord) a write fault has already been recorded
  // for in THIS apply. A D1 record's own sink methods enforce the fresh-target guard only on the header
  // (the first record; restore-sink.ts requireFreshTarget), by design, on the assumption that the caller
  // stops sending that database's later records once the header refuses. This loop does not naturally stop
  // itself -- it is one flat pass over every record in the window, D1 and non-D1 interleaved -- so without
  // this set a header refusal (or any other D1 write fault) did not prevent that SAME database's later rows
  // and schema record from still being attempted. A rows record against tables the header never created
  // fails loudly (no such table), but the schema record (CREATE INDEX/TRIGGER/VIEW) has no such backstop:
  // on a target that already carries some of the archived tables (this run's own scenario) it can apply
  // real DDL against a live, non-fresh database the fresh-target guard had already refused, and the receipt
  // then counts it as a genuine restored record on an apply that was supposed to write nothing at all. Once
  // a database's first fault is seen, every later record for that SAME database is refused here, before the
  // record is even decoded, with the same reason a real write fault on it would carry.
  const d1FaultedGroups = new Set<string>();
  // Phase 1: verify every in-scope record's plaintext hash, bytes discarded (one record at a
  // time). A failure here means the archive is not trustworthy, so stop with nothing written. A
  // large R2 record is verified through the constant-memory streaming discard (per-chunk GCM auth +
  // per-segment terminate-exactly + final whole-record SHA-384), so even a multi-GB value is fully
  // verified WITHOUT being held whole; everything else takes the buffered restoreRecord.
  let recordsVerified = 0;
  for (const { rec } of window) {
    try {
      if (shouldStream(rec, bufferedMaxBytes)) await verifyRecordStreamingDiscard(run, rec);
      else await run.restoreRecord(rec);
      recordsVerified++;
    } catch (e) {
      log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} integrity-check-failed]`);
      return { recordsVerified, recordsRestored: 0, bytesRestored: 0, aborted: true };
    }
  }

  // Phase 2: every record verified, so write them back. INTEGRITY MODEL: "never write an
  // unverified byte" holds on both paths.
  //   - Buffered path (small / non-R2): restoreRecord is re-run per record, materialising and
  //     re-verifying the whole value (its plaintext SHA-384) immediately before the write, one
  //     value at a time, never the whole run at once.
  //   - Streaming path (large R2): restoreRecordStream is re-run per record and piped straight into
  //     the sink's single PUT. The value is NEVER materialised: each 64 KiB chunk is decrypted and
  //     AES-256-GCM-authenticated before it is emitted, each segment must terminate at exactly its
  //     signed chunkRange, and the whole-record SHA-384 is checked in the stream's flush before it
  //     closes; the sink commits the object only on a clean close, so a decrypt/auth/hash failure
  //     aborts the PUT with no (or no committed) bytes. This replaces "buffer the whole value,
  //     verify, then write" with "verify the assembly, stream authenticated chunks, then verify the
  //     final hash" -- the same integrity strength, with bounded memory.
  // A failure on either path can only mean the immutable archive changed under us mid-restore (or a
  // transport fault); a decrypt/verify failure surfaces as a write fault below.
  //
  // VERIFY-ON-READBACK + RECEIPT: for every record actually written we capture a verifiedSha384 and
  // whether it equals the signed rec.plaintextSha384, into a per-record receipt entry. A record on a
  // sink that can read its writes back (R2, whether streamed or small-buffered) is proven by a POST-WRITE
  // READBACK: re-read the persisted object and re-hash with bounded memory, so the write is proven against
  // what truly persisted rather than against the write path's own claim of success (via streamed-readback
  // / buffered-readback). A readback MISMATCH (or a missing object) is a FAILURE, NOT a success: the
  // record is marked not-restored / not-verified, the object is LEFT in place (the operator decides;
  // deleting could lose data), and the drain continues with the other records. A record on a sink with NO
  // readback API (KV/Secrets/D1) records the verified in-memory plaintext hash that the atomic put wrote
  // and is labelled buffered-no-readback, so the receipt never claims a readback those resources cannot do.
  let recordsRestored = 0;
  let bytesRestored = 0;
  for (const { rec, resolved } of window) {
    // A record for a D1 database whose fresh-target guard (or any other write fault) has already fired
    // this apply is refused here, unattempted: the sink's own per-record methods trust the caller to stop
    // after the header refuses, and this flat single-pass loop is that caller. See d1FaultedGroups above.
    if (rec.sourceType === "d1") {
      const group = d1GroupOfDataRecord({ rec });
      if (group !== null && d1FaultedGroups.has(group)) {
        failures.push({ name: rec.name, reason: "partial restore: the target D1 may be inconsistent; drop it and retry into a fresh database", cls: "sink-write" });
        continue;
      }
    }
    // Apply the per-source restore descriptors (KV expiration/metadata, R2 http/custom metadata)
    // captured on the record, so a restore reconstructs the source faithfully and not value-only.
    const putOpts = putOptionsFromRecord(rec);
    if (shouldStream(rec, bufferedMaxBytes)) {
      try {
        // Stream the verified value straight into one R2 PUT without ever holding it whole. The
        // stream re-verifies every chunk and the final hash; an error here aborts this record's
        // write only (it is drained into failures, like any other sink fault) without abandoning
        // the rest, since the verify-all phase above already proved the whole set decrypts.
        await resolved.sink.putStream(rec.name, run.restoreRecordStream(rec), rec.plaintextSize, putOpts);
      } catch (e) {
        log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} stream-write-fault]`);
        // The sink throws s3WriteFailure on a rejected write, carrying the real, sanitised S3 <Code>
        // ("...status 403 (AccessDenied)"); surface it via destAccessReason instead of discarding it to a
        // generic class, so a restore-target Object-Lock / access rejection names its actionable cause. The
        // enriched reason still classifies as a destination-access availability fault.
        failures.push({ name: rec.name, reason: destAccessReason((e as Error)?.message ?? ""), cls: "sink-write" });
        continue; // not written: no readback, no receipt entry, not counted as restored
      }
      // VERIFY-ON-READBACK: the bytes are written; now PROVE the landed object. Re-read it from the
      // same sink and re-hash with bounded memory, then assert it equals the signed manifest hash. A
      // missing object or a re-hash that does not match is a post-write verification FAILURE: the
      // object stays (the operator decides), the record is marked NOT restored / NOT verified, and the
      // drain continues. Only a clean readback that MATCHES counts the record as restored.
      let readbackSha: string;
      try {
        readbackSha = await verifyReadbackStreaming(resolved.sink, rec.name);
      } catch (e) {
        log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} readback-failed]`);
        failures.push({ name: rec.name, reason: "the object was written but could not be read back to verify; recover it offline with the downpipe CLI", cls: "readback-failed" });
        receiptRecords.push({ name: rec.name, sourceType: rec.sourceType as RestoreSinkType, expectedSha384: rec.plaintextSha384, verifiedSha384: null, verified: false, via: "streamed-readback" });
        continue;
      }
      const verified = readbackSha === rec.plaintextSha384;
      receiptRecords.push({ name: rec.name, sourceType: rec.sourceType as RestoreSinkType, expectedSha384: rec.plaintextSha384, verifiedSha384: readbackSha, verified, via: "streamed-readback" });
      if (!verified) {
        // The streamed object that LANDED does not hash to the signed plaintext: do NOT report it as a
        // successful restore. Leave the object (deleting could lose data); flag it for offline recovery.
        log("error", `restore ${runId} record ${rec.name} [err:readback-mismatch]`);
        failures.push({ name: rec.name, reason: "the object was written but failed post-write readback verification; recover it offline with the downpipe CLI", cls: "readback-failed" });
        continue;
      }
      recordsRestored++;
      bytesRestored += rec.plaintextSize;
      continue;
    }
    let value: Uint8Array;
    try {
      value = await run.restoreRecord(rec); // never write an unverified byte
    } catch (e) {
      log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} integrity-check-failed-write-phase]`);
      return { recordsVerified, recordsRestored, bytesRestored, aborted: true };
    }
    // RESTORE-SKIP: a KV/R2/D1 DATA record whose value is an incompleteness
    // MARKER -- a _vanished object that raced the crawl, or an over-ceiling _skipped object -- is a sentinel,
    // NOT the object's real bytes. Writing it back would RE-CREATE a deleted/uncaptured key with marker JSON as
    // its live value: silent data corruption. Skip it exactly as the media re-upload path skips a marker blob
    // (restore-apply.ts media loop): nothing is written, it is not counted restored / not receipted, and it is
    // surfaced out of band. This is the paired restore-side change the capture-side _vanished marker requires,
    // and it also fixes the pre-existing R2 over-ceiling _skipped marker (which was silently restored as garbage
    // content). The value is already verified (Phase 1 + the restoreRecord above), so the archive is intact; the
    // marker simply must not become a live value. Markers are always small buffered values, so the streamed
    // branch above (large R2 objects) never sees one -- this single check covers every data-record marker.
    // Gate on rec.incompleteMarker (the signed manifest field, stamped at seal time from the source
    // adapter's OWN markerKind assertion), never by re-parsing the freshly decrypted `value` -- a real
    // customer value that merely LOOKS marker-shaped (e.g. `{"_pending":false,"orderId":42}`) carries no
    // adapter assertion and now writes back like any other real record instead of being silently dropped.
    if (rec.incompleteMarker !== undefined) {
      outOfBand.push({ name: rec.name, reason: "the captured value is an incompleteness marker (the object vanished or was skipped at capture), not real bytes; nothing written" });
      continue;
    }
    try {
      await resolved.sink.put(rec.name, value, putOpts);
    } catch (e) {
      // A write that fails (a sink error) is recorded coarsely and the restore continues with
      // the next record. Secrets records are never in the plan window (they are routed to
      // outOfBand before this loop), so this catch handles only KV, R2 and D1 write faults.
      // A D1 record is a whole database written over several non-atomic batches, so a fault can
      // leave it partially loaded; its reason says so plainly (drop the target and retry into a
      // fresh database) rather than the generic access-error used for an idempotent KV/R2 key.
      log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} write-fault]`);
      // For a non-D1 sink, surface the real, sanitised S3 <Code> the put rejection carries (via
      // destAccessReason) instead of collapsing it to a bare generic class, so an Object-Lock / access
      // rejection on the restore target names its actionable cause; the enriched reason still classifies
      // as a destination-access availability fault. D1 keeps its specific partial-restore guidance.
      //
      // The D1 sink throws a TYPED D1RestoreError carrying the closed class + the clamped
      // magnitudes. Read it off the caught error (by TYPE, never by parsing the message) and keep the FIRST
      // one: that is the fault that localises where the apply stopped.
      const d1 = d1FaultEvidence(e);
      if (d1 !== null && d1Fault === undefined) d1Fault = d1;
      // Block every later record for this SAME D1 database (see d1FaultedGroups above); a D1RestoreError
      // only ever comes from a D1 sink, so rec.sourceType is "d1" here and the group is never null.
      if (d1 !== null) {
        const group = d1GroupOfDataRecord({ rec });
        if (group !== null) d1FaultedGroups.add(group);
      }
      // A fresh-target REFUSAL wrote NOTHING, and coarsening it into the generic partial-restore
      // sentence told the operator their database MAY BE INCONSISTENT when it is untouched -- and cost the
      // fault ring its d1-target-not-empty class (which keys on the sink's own literal). Carry the sink's
      // engine-owned refusal message for that one class; every other D1 fault keeps the partial-restore
      // guidance (drop the target and retry into a fresh database).
      const reason = rec.sourceType === "d1"
        ? d1?.d1ErrorClass === "target-not-empty"
          ? ((e as Error).message)
          : "partial restore: the target D1 may be inconsistent; drop it and retry into a fresh database"
        : destAccessReason((e as Error)?.message ?? "");
      failures.push({ name: rec.name, reason, cls: "sink-write" });
      continue; // not written: no readback, no receipt entry, not counted as restored
    }
    // VERIFY-ON-READBACK (buffered path). The bytes are written; now PROVE the landed object, the same
    // post-write guarantee the streamed path gives. For a SMALL R2 record the sink CAN re-read the
    // object, so re-read it and re-hash with bounded memory: a readback that mismatches (or a missing
    // object) is a FAILURE, never a success, exactly as for the streamed path. KV/Secrets/D1 expose no
    // readback API (getStreamForVerify throws ReadbackNotSupportedError); for those we record the
    // verified in-memory plaintext hash that was written by the atomic put and label it
    // buffered-no-readback, so the receipt states honestly that no post-write readback was performed
    // rather than claiming a readback the resource cannot do. D1 in particular writes over several
    // non-atomic batches, so the honest label matters most there.
    let readbackSha: string;
    try {
      readbackSha = await verifyReadbackStreaming(resolved.sink, rec.name);
    } catch (e) {
      if (e instanceof ReadbackNotSupportedError) {
        // No native readback: record the written (verified) bytes' hash, labelled as a non-readback proof.
        const writtenSha = hexEncode(await sha384(value));
        recordsRestored++;
        bytesRestored += rec.plaintextSize;
        receiptRecords.push({ name: rec.name, sourceType: rec.sourceType as RestoreSinkType, expectedSha384: rec.plaintextSha384, verifiedSha384: writtenSha, verified: writtenSha === rec.plaintextSha384, via: "buffered-no-readback" });
        continue;
      }
      // A sink that DOES read back (R2) but could not return the object: the bytes were written but
      // cannot be proven, so this is a post-write readback FAILURE. Leave the object (the operator
      // decides; deleting could lose data) and do not count it as restored.
      log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} buffered-readback-failed]`);
      failures.push({ name: rec.name, reason: "the object was written but could not be read back to verify; recover it offline with the downpipe CLI", cls: "readback-failed" });
      receiptRecords.push({ name: rec.name, sourceType: rec.sourceType as RestoreSinkType, expectedSha384: rec.plaintextSha384, verifiedSha384: null, verified: false, via: "buffered-readback" });
      continue;
    }
    const verified = readbackSha === rec.plaintextSha384;
    receiptRecords.push({ name: rec.name, sourceType: rec.sourceType as RestoreSinkType, expectedSha384: rec.plaintextSha384, verifiedSha384: readbackSha, verified, via: "buffered-readback" });
    if (!verified) {
      // The small R2 object that LANDED does not hash to the signed plaintext: do NOT report it as a
      // successful restore. Leave the object (deleting could lose data); flag it for offline recovery.
      log("error", `restore ${runId} record ${rec.name} [err:buffered-readback-mismatch]`);
      failures.push({ name: rec.name, reason: "the object was written but failed post-write readback verification; recover it offline with the downpipe CLI", cls: "readback-failed" });
      continue;
    }
    recordsRestored++;
    bytesRestored += rec.plaintextSize;
  }
  return { recordsVerified, recordsRestored, bytesRestored, aborted: false, ...(d1Fault !== undefined ? { d1Fault } : {}) };
}

// d1SchemaObjectsFiltered sums the non-table schema objects (indexes / triggers / views) the D1 sinks in this
// apply's window FILTERED OUT because they belonged to a table a table-SUBSET restore did not create.
// The sinks counted them at the filter site; this only reads the accessor. Zero on every full-schema restore
// (and on every restore with no D1 record), so it stays honestly absent from the receipt in the normal case.
function d1SchemaObjectsFiltered(window: Array<{ resolved: Resolved }>): number {
  let n = 0;
  const seen = new Set<Resolved["sink"]>();
  for (const { resolved } of window) {
    const sink = resolved.sink;
    if (seen.has(sink)) continue; // one sink serves many records; count its filtered objects once
    seen.add(sink);
    if (typeof sink.schemaFilteredCount === "function") n += sink.schemaFilteredCount();
  }
  return n;
}

// runApply performs the destructive write into live in-account resources. It verifies the WHOLE in-scope
// set first (read-only) and begins writing only once every record has verified (applyDataRecords), so an
// integrity failure on a tampered archive aborts BEFORE a single byte is written. cf-config and media
// applies run AFTER the data set is proven, then the signed restore receipt is built. This is the original
// apply branch lifted verbatim, with the per-record write/readback loops factored into applyDataRecords.
// destFallback (last parameter) is the 3-2-1 walk this apply is running under: absent on a first-choice
// restore, present when withRunDestFallback was already refused by at least one destination. It is threaded
// in rather than discovered here because the apply reads ONE destination and cannot know it is the second
// choice, and because the fact belongs INSIDE the signed receipt core rather than beside it.
export async function runApply(env: Env, body: RestoreRequest, run: Run, state: RestorePlanState, bufferedMaxBytes: number, runId: string, isLatest: boolean, cfApiFactory: (token: string) => CfApi, mediaUploaderFactory: (token: string) => MediaUploader, destFallback?: RestoreDestFallback): Promise<RestoreResult> {
  const { outOfBand, plan, configPlan, mediaPlan } = state;
  const failures: RestoreFailure[] = [];
  // Window the COMBINED in-account work (data records + cf-config surfaces + media re-uploads), spending a
  // single maxRecords budget in apply order. Every one of the three costs subrequests, so the ceiling and
  // the window must bound the COMBINED set: a restore with few data records but many media/cf-config
  // records is still capped, sliced and resumable, never half-completing past the platform cap.
  const { dataWindow: window, configWindow, mediaWindow, total: inAccountTotal, outOfWindow, d1OutOfWindow } = inAccountWindow(plan, configPlan, mediaPlan, body.maxRecords, d1GroupOfDataRecord);
  // Refuse an oversized in-account apply BEFORE any write. The engine restore is single-invocation
  // with no slicing/resume, so a combined window over the ceiling would trip the Worker subrequest/CPU cap
  // mid-apply and half-overwrite live resources with no clean resume; steer bulk recovery to the offline
  // downpipe CLI. The bound is on the COMBINED window (data + cf-config + media), so an unbounded oversized
  // run is refused AND an explicit maxRecords that would still admit more than the ceiling is refused; a
  // caller wanting a bounded in-account apply passes an explicit maxRecords <= the ceiling (the escape hatch).
  if (window.length + configWindow.length + mediaWindow.length > MAX_IN_ACCOUNT_RESTORE_RECORDS) {
    return { ok: false, runId, mode: "applied", recordsVerified: 0, recordsRestored: 0, bytesRestored: 0, isLatest, failures: [], reason: inAccountTooLargeReason(inAccountTotal) };
  }

  // CROSS-ACCOUNT GUARD (the confused-deputy guard, symmetric to the reserved-binding refusal
  // above). The cf-config and media legs re-apply to a CALLER-SUPPLIED accountId; before a single byte is
  // written, refuse any leg whose target account is not the archive's SIGNED origin (or is unverifiable) and
  // is not EXPLICITLY confirmed, so a config/media restore can never SILENTLY land in the wrong account. It
  // refuses the WHOLE restore before applyDataRecords, so nothing (data, config or media) is written on an
  // unconfirmed cross-account attempt. Same-account restore (the common case) has no cross-account leg and is
  // untouched; a deliberate different-account restore proceeds once the caller echoes the target account.
  const unconfirmed = unconfirmedCrossAccountLegs(body, state);
  if (unconfirmed.length > 0) {
    log("error", `restore ${runId} refused: cross-account restore not confirmed`);
    return { ok: false, runId, mode: "applied", recordsVerified: 0, recordsRestored: 0, bytesRestored: 0, isLatest, failures: [], reason: crossAccountRefusalReason(unconfirmed) };
  }

  // CROSS-ZONE REFUSAL, the zone twin of the guard above. It refuses BEFORE applyDataRecords for the
  // same reason: nothing at all should be written on an unconfirmed cross-zone attempt, not even the data
  // leg. Only a restore that would write a ZONE-SCOPED surface can be wrong this way, so an account-only
  // cf-config restore is untouched, as is a same-zone restore, which is the common case.
  if (body.cfConfig?.zoneId !== undefined && state.configPlan.length > 0) {
    let originZone: string | null = null;
    try {
      originZone = state.cfIdentityRec === undefined ? null : originZoneFrom(await run.restoreRecord(state.cfIdentityRec));
    } catch {
      originZone = null; // unreadable origin is unverifiable, which the guard treats as needing confirmation
    }
    const zoneWarn = crossZoneWarning(body, originZone, state.configPlan);
    // REFUSE ONLY ON A PROVEN MISMATCH, and this is deliberately weaker than the account guard beside it.
    //
    // There, a null origin means the archive recorded no account, which the current engine always does, so
    // null is a rare defensive branch and refusing is right. Here, a null origin usually just means the
    // identity record is not in this restore's window: it is emitted first in every cf-config crawl, so a
    // windowed or selector-limited restore routinely leaves it out, and an archive captured before the
    // record existed has none at all. Refusing those would break ordinary same-zone restores to guard
    // against a mismatch there is no evidence of, which is a bad trade in both directions.
    //
    // The dry run still WARNS on a null origin, so an operator sees that the zone could not be checked.
    if (zoneWarn !== null && zoneWarn.originZone !== null && !crossZoneConfirmed(zoneWarn, body)) {
      log("error", `restore ${runId} refused: cross-zone cf-config restore not confirmed`);
      return {
        ok: false,
        runId,
        mode: "applied",
        recordsVerified: 0,
        recordsRestored: 0,
        bytesRestored: 0,
        isLatest,
        failures: [],
        reason: `cf-config restore targets zone ${zoneWarn.targetZone} but the archive was captured from ${zoneWarn.originZone ?? "a zone the archive does not record"}, and ${zoneWarn.zoneSurfaces.length} zone-scoped surface(s) would be written there. Re-send with confirmDifferentZoneId set to the target zone id to proceed deliberately`,
      };
    }
  }

  const receiptRecords: RestoreReceiptRecord[] = [];
  // Clear any metadata-shed tally a PREVIOUS operation left in this warm isolate, so the shed counts
  // this apply reports are its own. (The drain is the reset; the value is deliberately discarded.)
  drainMetadataShed();
  // outOfBand also receives any data-record MARKER skips (a _vanished / _skipped sentinel must never be written
  // back as a live value); it is spread into result.skipped below alongside the windowed-restore marker.
  const dataResult = await applyDataRecords(run, window, bufferedMaxBytes, runId, failures, receiptRecords, outOfBand);
  // recordsRestored / bytesRestored start from the data records and grow as proven media re-uploads land
  // below, so the receipt summary and the result count the media records that genuinely restored (they now
  // appear in the signed receipt alongside the data records).
  const { recordsVerified } = dataResult;
  let recordsRestored = dataResult.recordsRestored;
  let bytesRestored = dataResult.bytesRestored;
  if (dataResult.aborted) {
    return { ok: false, runId, mode: "applied", recordsVerified, recordsRestored, bytesRestored, isLatest, failures, reason: "integrity check failed" };
  }
  // cf-config APPLY: re-apply each idempotent surface to live Cloudflare with the edit-scoped token, AFTER
  // every data record verified above (so a cf-config write never lands before the data set is proven).
  // restoreRecord re-verifies the snapshot's plaintext hash before it is parsed, so a tampered config
  // record is caught before any production write. A surface write that throws becomes a per-surface
  // failure (so ok reflects it), never a silent drop.
  //
  // A surface the API merely REFUSED also counts against ok/complete. The write path is fail-open per ITEM:
  // an item Cloudflare rejects skips itself and the rest of the surface still applies, and each refusal is
  // classified at the skip site (cf-config-write.ts, via classifyCfWriteSkip). A token that is valid but too
  // NARROW puts the surface in the plan, where every item is attempted and refused 401/403 -- unlike supplying
  // no token at all, which leaves the surface out of band (restore-plan.ts), reported and counted separately.
  //
  // The apply is not ABORTED on such a refusal: by the time it is known the other surfaces have already
  // applied, so the surfaces that applied keep their applied counts, the surface that did not is a named
  // failure carrying the class and the remedy, and ok and complete are false.
  const configApplied: NonNullable<RestoreResult["configApplied"]> = [];
  // configSkipTally sums every surface's per-item skip classes into ONE closed {class: count} map, which rides
  // on the SIGNED receipt so a reader holding only the receipt can tell a clean apply from a refused one.
  const configSkipTally: Partial<Record<CfConfigSkipClass, number>> = {};
  for (const { rec, surface } of configWindow) {
    try {
      const snapshot = decodeConfigSnapshot(await run.restoreRecord(rec));
      const api = cfApiFactory(body.cfConfig!.token);
      const ids = { accountId: body.cfConfig!.accountId, ...(body.cfConfig!.zoneId ? { zoneId: body.cfConfig!.zoneId } : {}) };
      const res = await surface.write!(api, ids, snapshot, { dryRun: false });
      // Carry the CLOSED skip-class counts, not just the integer. Without them a restore that skipped
      // 20 of 200 records leaves no durable trace of WHY any of them skipped.
      const skipCounts = cfSkipCounts(res.skipped);
      for (const [cls, n] of Object.entries(skipCounts)) {
        const k = cls as CfConfigSkipClass;
        configSkipTally[k] = (configSkipTally[k] ?? 0) + (n ?? 0);
      }
      configApplied.push({
        surface: rec.name,
        applied: res.applied,
        skipped: res.skipped.length,
        ...(Object.keys(skipCounts).length > 0 ? { skipReasonCounts: skipCounts } : {}),
      });
      // THE SURFACE GOES ON THE RECEIPT, applied or refused. verified is the unrestored-item predicate below,
      // so a surface the API refused carries verified:false and drags allVerified false with it.
      const unrestored = unrestoredCfSkips(skipCounts);
      receiptRecords.push({ name: rec.name, sourceType: "cf-config", expectedSha384: rec.plaintextSha384, verifiedSha384: null, verified: unrestored.length === 0, via: "cf-config-applied" });
      if (unrestored.length > 0) {
        // AND IT IS A FAILURE, so ok and complete are false. This is the apply's own stated contract, applied
        // to the cf-config leg for the first time: "any record that verified but could not be written leaves
        // ok false ... so a partial apply is never reported as success". Every one of these items verified
        // against the signed manifest and is still not in the account, so the apply IS partial.
        log("error", `restore ${runId} cf-config ${rec.name} [err:cf-config-items-refused]`);
        failures.push({ name: rec.name, reason: cfUnrestoredReason(unrestored), cls: "cf-config-surface" });
      }
    } catch (e) {
      log("error", `restore ${runId} cf-config ${rec.name} [err:${errId(e)} cf-config-write-failed]`);
      receiptRecords.push({ name: rec.name, sourceType: "cf-config", expectedSha384: rec.plaintextSha384, verifiedSha384: null, verified: false, via: "cf-config-applied" });
      failures.push({ name: rec.name, reason: `Cloudflare config write failed: ${coarseCfReason(e)}`, cls: "cf-config-surface" });
    }
  }
  // media APPLY: re-upload each captured media file to live Cloudflare with the edit-scoped token, AFTER
  // every data record verified above. restoreRecord re-verifies the plaintext hash before the bytes are
  // uploaded, so a tampered media record is caught before any upload. The re-upload is ADDITIVE (create
  // only): an image restores to its ORIGINAL id; a video gets a NEW uid (reported as remapped). A marker
  // record (capture had failed) is skipped out of band, never uploaded as a file. An upload that throws
  // becomes a per-record failure (so ok reflects it), never a silent drop.
  // VERIFY-ON-READBACK + RECEIPT for media: a media re-upload carries the SAME post-upload proof
  // and signed-receipt entry the KV/R2/D1 sinks do, within the platform's reality. An IMAGE keeps its
  // ORIGINAL id, so the uploader proves it by a DIRECT BYTE READBACK of the live /blob (via
  // media-image-readback, verifiedSha384 = the readback hash). A VIDEO is TRANSCODED to a NEW uid, so a
  // byte-for-byte readback is impossible; the uploader instead proves the new uid RESOLVES (via
  // media-stream-exists, verifiedSha384 = null). An upload that lands but FAILS its proof (res.verified
  // false: an image whose live /blob does not hash to the archived bytes, or a video uid that does not
  // resolve) is a FAILURE, never a silent success: the record goes to failures, its receipt entry is
  // verified:false, and it is NOT counted in mediaRestored. The marker records (capture had failed) stay out
  // of band, never uploaded as a file.
  const mediaRestored: NonNullable<RestoreResult["mediaRestored"]> = [];
  // The per-CLASS media fault tally (and, on a conflict, the archived/live digest pair) lets
  // "some videos restored, some failed" be diagnosed remotely: an over-the-cap video, a transient Cloudflare
  // blip and an id occupied by DIFFERENT live bytes are distinct classes. Counts
  // keyed by the closed MEDIA_FAULT_CLASSES; the digests are hashes of the customer's own bytes (the receipt's
  // existing join-key idiom), so a conflict dispute can be adjudicated. Never a media byte, an id or a CF body.
  const mediaFaults: Record<string, number> = {};
  const mediaConflictDigests: Array<{ archivedSha384: string; liveSha384: string }> = [];
  const bumpMediaFault = (cls: MediaFaultClass): void => {
    mediaFaults[cls] = Math.min(1_000_000, (mediaFaults[cls] ?? 0) + 1);
  };
  for (const { rec, type, id } of mediaWindow) {
    try {
      const bytes = await run.restoreRecord(rec); // re-verifies the plaintext SHA-384
      // Gate on rec.incompleteMarker (the signed, adapter-asserted manifest field), never by
      // re-parsing the decrypted `bytes` -- see the sibling data-record gate above.
      if (rec.incompleteMarker !== undefined) {
        outOfBand.push({ name: rec.name, reason: "media file, the captured value was a marker (capture had failed), not file bytes" });
        continue;
      }
      const uploader = mediaUploaderFactory(body.mediaRestore!.token);
      const res = type === "images"
        ? await uploader.uploadImage(body.mediaRestore!.accountId, id, bytes)
        : await uploader.uploadStreamVideo(body.mediaRestore!.accountId, id, bytes);
      // The receipt records the media re-upload's proof: expectedSha384 is the signed plaintext hash; for an
      // image verifiedSha384 is the live /blob readback hash, for a transcoded video it is null (no byte proof
      // possible, only the uid resolution that res.verified carries). via distinguishes the two.
      // The id map rides on the SIGNED receipt, not only on the ephemeral response the console renders. A
      // transcoded video lands on a new uid, and the receipt is what the customer keeps, so the artefact must
      // be able to say which archived uid became which live one. It is carried whether or not the proof
      // passed: an upload that landed and could not be CONFIRMED still created a live asset the operator has
      // to find, and that is the case where knowing its uid matters most.
      const remap = res.remapped ? { restoredId: res.restoredId, remapped: true as const } : {};
      receiptRecords.push({ name: rec.name, sourceType: type, expectedSha384: rec.plaintextSha384, verifiedSha384: res.verifiedSha384, verified: res.verified, via: res.via, ...remap });
      if (!res.verified) {
        // The bytes were uploaded but the proof FAILED (image readback mismatch / unreadable, or a video uid
        // that did not resolve): do not report it as a successful restore. Surface a per-record failure so ok
        // reflects it; the additive upload is left in place (the operator decides) and can be re-driven.
        log("error", `restore ${runId} media ${rec.name} [err:media-readback-mismatch]`);
        // Split the two, which need OPPOSITE answers. readbackReadable false means the live object could
        // not be READ at all (a transient 5xx / throttle / propagation lag) -- the bytes may be perfectly fine
        // and the answer is "retry". readbackReadable true means it WAS read and does not match -- a real,
        // durable restore failure.
        bumpMediaFault(res.readbackReadable ? "readback-mismatch" : "readback-unreadable");
        const reason = type === "images"
          ? "the image was uploaded but failed post-upload readback verification; recover it offline with the downpipe CLI"
          : "the video was uploaded but its restored uid could not be confirmed; verify it in Cloudflare Stream or recover it offline with the downpipe CLI";
        failures.push({ name: rec.name, reason, cls: "media-upload" });
        continue;
      }
      mediaRestored.push({ name: rec.name, restoredId: res.restoredId, remapped: res.remapped });
      recordsRestored++;
      bytesRestored += rec.plaintextSize;
    } catch (e) {
      log("error", `restore ${runId} media ${rec.name} [err:${errId(e)} media-upload-failed]`);
      // Read the CLOSED class the uploader tagged (over-size-cap / conflict-different-bytes /
      // conflict-unreadable), never the thrown message (a Cloudflare media error can embed an account id and an
      // asset id). An UNTAGGED throw is honestly counted as upload-failed rather than guessed at from its text.
      const tag = mediaFaultOf(e);
      bumpMediaFault(tag?.cls ?? "upload-failed");
      if (tag?.archivedSha384 !== undefined && tag.liveSha384 !== undefined && mediaConflictDigests.length < MEDIA_CONFLICT_DIGESTS_MAX) {
        mediaConflictDigests.push({ archivedSha384: tag.archivedSha384, liveSha384: tag.liveSha384 });
      }
      failures.push({ name: rec.name, reason: `media re-upload failed: ${coarseCfReason(e)}`, cls: "media-upload" });
    }
  }
  // ok reflects the writes: any record that verified but could not be written leaves ok false
  // with the per-record reasons in failures, so a partial apply is never reported as success.
  // Secrets records are in outOfBand (they could not be written for a known platform reason,
  // not a runtime fault) and do not contribute to failures or affect ok.
  // WINDOWED-RESTORE HONESTY: maxRecords may have capped the apply to fewer COMBINED records (data +
  // cf-config + media) than the selector matched. The records beyond the window were never restored, so the
  // result must not present as a whole-run success. ok keeps its meaning (failures.length === 0) so an
  // operator who pages on purpose is not regressed; complete:false plus the explicit "(window)" skipped
  // marker is the honest signal that records were left unrestored. outOfWindow is the combined count
  // inAccountWindow computed (so media/cf-config left beyond the window are counted too, not only data). The
  // reason steers an unrestored D1 OFFLINE (it is not resumable and was never partially applied), never the
  // impossible "re-run with a higher maxRecords" advice for it (windowSkippedReason branches on d1OutOfWindow).
  const windowSkipped: RestoreSkipped[] = outOfWindow > 0
    ? [{ name: "(window)", reason: windowSkippedReason(outOfWindow, d1OutOfWindow) }]
    : [];
  const result: RestoreResult = { ok: failures.length === 0, runId, mode: "applied", recordsVerified, recordsRestored, bytesRestored, isLatest, failures, outOfWindow, windowed: outOfWindow > 0, complete: failures.length === 0 && outOfWindow === 0 };
  const skippedAll = [...outOfBand, ...windowSkipped];
  if (skippedAll.length > 0) result.skipped = skippedAll;
  if (configApplied.length > 0) result.configApplied = configApplied;
  if (mediaRestored.length > 0) result.mediaRestored = mediaRestored;
  // Surface the closed-class media fault tally (and any conflict digest pairs) so the router can stamp
  // them onto the restore-receipt audit target. Honestly ABSENT when no media record failed.
  if (Object.keys(mediaFaults).length > 0) result.mediaFaults = mediaFaults;
  if (mediaConflictDigests.length > 0) result.mediaConflictDigests = mediaConflictDigests;
  // The D1 partial-apply evidence (closed class + the batch it stopped at + the batch total, or the
  // residual-table count of a refused fresh-target check) and the schema objects a table-SUBSET restore
  // filtered away. Both are ABSENT on a clean, full-schema restore, so the receipt is unchanged in the normal
  // case and carries the localisation exactly when a database may be half-loaded.
  if (dataResult.d1Fault !== undefined) result.d1Fault = dataResult.d1Fault;
  const schemaFiltered = d1SchemaObjectsFiltered(window);
  if (schemaFiltered > 0) result.d1SchemaObjectsFiltered = schemaFiltered;
  // The restore descriptor fields the sinks SHED (an unusable KV expiration, an unparseable R2
  // cacheExpiry). Drained here, after every write, and re-gated to the closed field vocabulary.
  const shed = sanitiseMetadataShed(drainMetadataShed());
  if (shed !== undefined) result.metadataFieldsDropped = shed;
  // RESTORE RECEIPT (auditable proof-of-correct-restore). Build it over the per-record entries gathered
  // above: each carries the expected (signed) hash, the verified hash (buffered = the verified-plaintext
  // hash equal to the landed bytes via atomic put; streamed = the post-write readback hash), the via and
  // whether they matched. allVerified is true ONLY when every restored record verified, so a streamed
  // readback mismatch (already drained to failures) makes allVerified false. The receipt is made
  // tamper-evident: signed with the engine's reachable signer key when present, and ALWAYS anchored to
  // the audit chain by the router via its SHA-384 (see makeRestoreReceipt + the router's anchor). The
  // receipt is redaction-safe (record names + hashes + counts only, no values/keys).
  // The skipped count rides on the receipt too. Without it the receipt states what LANDED and is silent on
  // what did not, so a reader auditing the recovery sees "restored 98, allVerified true" and cannot tell
  // that two records from the archive are still absent from the account.
  // configSkipTally rides on the receipt for the reason the whole cf-config half of this function exists: a
  // receipt that cannot distinguish "the surface applied" from "the token was too narrow and nothing applied"
  // is not evidence of a recovery. It is inside the hashed and signed core, so the digest moves when it is
  // present and a count cannot be stripped after the fact.
  // destFallback rides into the receipt on the same ground as configSkipTally, and for the sharper version of
  // the same reason: a receipt that cannot distinguish "this came from your primary" from "your primary
  // refused verification and this came from the third copy" is not evidence of what was recovered or from
  // where. It is inside the hashed and signed core, so a receipt served from a replica cannot be made to
  // hash like one served from the primary, and the walk cannot be stripped after the fact. Absent on a
  // first-choice restore, which is every restore whose primary answered, so those receipts are unchanged.
  result.receipt = await makeRestoreReceipt(env, runId, isLatest, receiptRecords, recordsRestored, bytesRestored, result.skipped?.length ?? 0, configSkipTally, destFallback, shed ?? {});
  // The same walk on the RESULT, so the caller sees it whether or not a receipt was built (a receipt needs a
  // reachable signer or the audit anchor; the operator's right to know which destination served them does
  // not). withRunDestFallback stamps the identical value on the way out, so this is the same fact written
  // twice with one source, never two.
  if (destFallback !== undefined) result.destFallback = destFallback;
  return result;
}
