import { kvExpirationLapsed } from "../dest/restore-sink.ts";
import type { Env } from "../env.d.ts";
import type { ShardRecord } from "../format/manifest.ts";
import type { Run } from "../format/reader.ts";
import { log } from "../log.ts";
import { CF_CONFIG_IDENTITY_ID, type CfApi, type CfConfigSurface, surfaceById } from "../sources/cf-config-surfaces.ts";
import { d1DatabaseNameFromRecordName, d1TableIndexFromRowRecordName } from "../sources/d1.ts";
import { d1DependencyWarnings } from "../sources/d1-fk.ts";
import { decodeD1Record } from "../sources/d1-format.ts";
import { APPROVAL_TTL_MS, RESTORE_APPLY_LEASE_MS, resolveCfConfigSurfaces, restoreApplyDeadlineMs } from "./approvals.ts";
import { imageIdFromRecordName, MEDIA_UPLOAD_MAX, streamUidFromRecordName } from "./media-restore.ts";
import { coarseCfReason, decodeConfigSnapshot, summariseDiff } from "./restore-cfconfig.ts";
import { crossAccountWarnings, crossZoneWarning, originZoneFrom } from "./restore-cross-account.ts";
import type { ReservedRefusal, RestorePlanState } from "./restore-plan-types.ts";
import {
  d1GroupOfDataRecord,
  errId,
  guardTarget,
  inAccountTooLargeReason,
  inAccountWindow,
  MAX_IN_ACCOUNT_RESTORE_RECORDS,
  MEDIA_MARKER_MAX,
  mediaRestoreGuidance,
  RESERVED_REASON,
  type Resolved,
  resolveSink,
  SECRETS_OUT_OF_BAND_REASON,
  shouldStream,
  verifyRecordStreamingDiscard,
  windowSkippedReason,
  workersRestoreGuidance,
} from "./restore-sinks.ts";
import type { CrossZoneWarning, D1DependencyWarning, RestoreFidelityWarning, RestorePlan, RestoreRequest, RestoreSampleItem, RestoreSkipped } from "./restore-types.ts";

// buildRestorePlan classifies every in-scope record up front into the four plan buckets (data writes,
// cf-config re-applies, media re-uploads, out-of-band) or skips it, EXACTLY as the inline loop did. It
// returns a ReservedRefusal the moment a reserved target binding is detected (in any record's resolved
// binding or a secrets target override) so a confirm run never writes a single byte when a reserved
// binding is in play. Otherwise it returns the populated plan state. No write happens here.
export function buildRestorePlan(env: Env, body: RestoreRequest, run: Run, inRecordScope: (name: string) => boolean, confirm: boolean, sourceBindings?: ReadonlyMap<string, string>, d1Restrict?: { database: string; tables: ReadonlySet<string> }): RestorePlanState | ReservedRefusal {
  const skipped: RestoreSkipped[] = [];
  // sinkUnresolved counts ONLY the records resolveSink REFUSED (a missing/misnamed target binding, or a
  // record type with no write sink), which is a different fact from the rest of `skipped` even though both
  // land in the same array. The other members are the operator's OWN narrowing ("not the selected record",
  // "excluded by selector"): a plan of one record out of three is exactly what a granular restore is FOR, so
  // counting those would make every deliberate single-record restore report itself incomplete. A resolution
  // refusal is nobody's intent -- it is a fixable misconfiguration -- and it is the one the plan's verdict
  // fields have to read. Kept as a COUNT beside the array rather than re-derived by matching on reason
  // strings later, so the two can never drift and no verdict ever depends on parsing an English sentence.
  let sinkUnresolved = 0;
  const outOfBand: RestoreSkipped[] = [];
  const plan: Array<{ rec: ShardRecord; resolved: Resolved }> = [];
  // cf-config records that CAN be re-applied in-console (an idempotent surface with a write() AND a
  // supplied cfConfig token+account). Collected here and processed READ-ONLY in the dry-run (diff) or
  // written in the apply phase AFTER the data records verify, so the verify-all-before-write discipline is
  // never broken by a cf-config write landing before a data record is checked.
  const configPlan: Array<{ rec: ShardRecord; surface: CfConfigSurface }> = [];
  // mediaPlan collects the media BLOB records an apply would re-upload (images to their original id,
  // stream as new uids), gated on a supplied mediaRestore edit-token + account. Processed AFTER the data
  // records verify (same discipline as cf-config). Marker/metadata records never enter the plan.
  const mediaPlan: Array<{ rec: ShardRecord; type: "images" | "stream"; id: string }> = [];
  // The cf-config identity record, kept for the zone guard. Metadata, never a restorable surface.
  let cfIdentityRec: ShardRecord | undefined;
  // The resolved cf-config surface allow-list, computed once. Same function the plan hash binds.
  const allowedSurfaces = new Set(resolveCfConfigSurfaces(body.cfConfig?.surfaces));
  for (const rec of run.records) {
    if (!inRecordScope(rec.name)) {
      // Honest skip reason: a recordName restore excludes everything that is not THE named record; a
      // prefix restore excludes everything the selector did not admit. Either way the record is not
      // written and the operator sees why.
      skipped.push({ name: rec.name, reason: typeof body.recordName === "string" && body.recordName.length > 0 ? "not the selected record" : "excluded by selector" });
      continue;
    }
    // Secrets Store bindings are read-only at runtime: no runtime write path exists. Route
    // the record to outOfBand immediately, before attempting to build any sink, so the
    // dry-run plannedWrites count never includes a secrets record and the apply phase never
    // attempts a write that will always fail.
    // Guard the target binding first: a reserved binding override poisons the whole restore
    // regardless of whether the record is a secrets record. The guard must be checked before
    // we skip off to outOfBand so a confused-deputy attack via a secrets target override is
    // still refused.
    if (rec.sourceType === "secrets") {
      const targetBinding = body.target?.binding ?? "SECRETS";
      try {
        guardTarget(targetBinding);
      } catch {
        return { reserved: true, recName: rec.name };
      }
      // The sentence names the CAUSE and the REMEDY, like every other out-of-band class. The remedy is real and is deliberately worded as what the operator does:
      // the archive holds the value (sealed, and recoverable through a restore to an offline target), and
      // the secret is re-created from it. The engine does NOT put a secret back, here or anywhere, so
      // nothing in this sentence may read as though it will.
      outOfBand.push({ name: rec.name, reason: SECRETS_OUT_OF_BAND_REASON });
      continue;
    }
    if (rec.sourceType === "cf-config") {
      // The self-identifying record is metadata (which account/zone this backup is for), NOT a writable
      // surface: surface it as informational out-of-band (so the operator SEES, in the restore preview, which
      // zone this backup belongs to) and never as a restorable-surface gap. The actual accountId/zoneId/
      // zoneName live in the record value, readable on restore; the plan only sees names, so it names it here.
      if (rec.name === CF_CONFIG_IDENTITY_ID) {
        // Keep it: the zone guard reads its value to learn the archive's origin zone. It stays out of band
        // as a restorable surface, which it is not.
        cfIdentityRec = rec;
        outOfBand.push({ name: rec.name, reason: "Cloudflare config backup identity (records which account/zone this backup is for); informational, not a restorable surface" });
        continue;
      }
      // Cloudflare config write-back. An IDEMPOTENT (T1) surface re-applies IN-CONSOLE when the caller
      // supplies a cfConfig edit-scoped token + account: the diff-driven write() reads live config, diffs
      // the verified snapshot, and writes ONLY the differing fields, additively, never a blind delete.
      // ordered / reprovision surfaces (Access dependency order, certificate private keys) stay OUT OF
      // BAND with tier guidance. Without a cfConfig context the record also stays out of band (no change).
      // The surface must ALSO be in the approved allow-list. `allowedSurfaces` is resolved by the
      // same function the plan hash binds, so the set an approver signed and the set this writes are the
      // same set by construction, not by two code paths agreeing. A surface outside the list falls
      // through to the out-of-band branch below and is reported, never silently dropped.
      const surface = surfaceById(rec.name);
      if (surface?.write && body.cfConfig && body.cfConfig.token !== "" && body.cfConfig.accountId !== "" && allowedSurfaces.has(rec.name)) {
        configPlan.push({ rec, surface });
        continue;
      }
      const tier = surface?.restoreTier;
      // Distinguish "you have not supplied a token" from "this surface is outside the approved
      // allow-list". Both land out of band, but telling an operator who DID supply a token to supply one
      // would be a false instruction, and the fix in the second case is to widen the request and get it
      // re-approved, not to hunt for a credential.
      const writableButNotAllowed = surface?.write !== undefined && body.cfConfig !== undefined && !allowedSurfaces.has(rec.name);
      const how = tier === "reprovision"
        ? "write-only values (secrets / certificate keys), re-provision them; the snapshot holds the rest"
        : tier === "ordered"
          ? "re-create in dependency order (Access / load balancers) from the snapshot"
          : writableButNotAllowed
            ? "this surface can re-apply in-console but is outside the approved surface list for this restore; widen the request and have it approved again, or replay it via the Cloudflare API from the verified snapshot"
            : surface?.write
              ? "supply an edit-scoped Cloudflare token under Restore to re-apply this surface in-console, or replay it via the Cloudflare API from the verified snapshot"
              : "replay via the Cloudflare API from the verified snapshot";
      outOfBand.push({ name: rec.name, reason: `Cloudflare config, ${how}` });
      continue;
    }
    if (rec.sourceType === "workers") {
      // Workers scripts restore is REPROVISION, never a blind write: the engine does NOT
      // re-deploy a customer's Worker from a backup (that could brick a live service). The
      // snapshot is VERIFIED recoverable here (the blind restore test decrypts and hash-checks
      // every record, the code, the settings, the versions inventory) and surfaced OUT OF BAND
      // with re-deploy guidance, so the operator re-deploys deliberately. A "/settings" record
      // carries a reprovision checklist of secret binding NAMES (never a value); the operator
      // re-creates those secrets at re-deploy. There is no destructive Workers restore path.
      outOfBand.push({ name: rec.name, reason: workersRestoreGuidance(rec.name) });
      continue;
    }
    if (rec.sourceType === "stream" || rec.sourceType === "images" || rec.sourceType === "artifacts") {
      // Media re-upload (the "next increment" over out-of-band, like cf-config). Only an UPLOADABLE blob
      // record qualifies: an image "<id>/blob" (restores to its original id) or a video "<uid>/video.mp4"
      // (re-uploaded as a new uid). Metadata/inventory records, captions, and artifact blobs (git re-push
      // is not a REST upload) stay out of band. Gated on a supplied mediaRestore edit-token + account; the
      // marker check (a "_skipped"/"_unavailable" blob is not real bytes) happens at verify time.
      const mediaOn = body.mediaRestore !== undefined && body.mediaRestore.token !== "" && body.mediaRestore.accountId !== "";
      const imageId = rec.sourceType === "images" ? imageIdFromRecordName(rec.name) : undefined;
      const streamUid = rec.sourceType === "stream" ? streamUidFromRecordName(rec.name) : undefined;
      const uploadId = imageId ?? streamUid;
      // A re-upload buffers the whole value (no streaming-multipart path), so a media file past the
      // upload cap stays out of band (surfaced for offline re-upload) rather than risking the Worker
      // memory limit. BACKUP captured it fine (chained); only the in-account RE-UPLOAD is size-bound.
      const tooLarge = rec.plaintextSize > MEDIA_UPLOAD_MAX;
      if (mediaOn && uploadId !== undefined && !tooLarge) {
        mediaPlan.push({ rec, type: imageId !== undefined ? "images" : "stream", id: uploadId });
      } else if (mediaOn && uploadId !== undefined && tooLarge) {
        outOfBand.push({ name: rec.name, reason: `${imageId !== undefined ? "Image" : "Video"} file exceeds the ${MEDIA_UPLOAD_MAX}-byte in-account re-upload limit; re-upload from the verified bytes (the backup captured it in full)` });
      } else {
        outOfBand.push({ name: rec.name, reason: mediaRestoreGuidance(rec.name, rec.sourceType, mediaOn) });
      }
      continue;
    }
    let resolved: Resolved;
    try {
      resolved = resolveSink(env, rec, body.target, confirm, sourceBindings, d1Restrict);
    } catch (e) {
      const m = (e as Error).message;
      if (m === RESERVED_REASON) {
        // A reserved binding poisons the whole restore: refuse it, write nothing.
        return { reserved: true, recName: rec.name };
      }
      // An unsupported/unresolvable sink is a per-record skip, not a whole-run failure.
      // Distinguish a missing/misnamed target binding from a genuinely unsupported record
      // type so the dry-run plan points the operator at the real, fixable misconfiguration.
      const reason = /is not present in the environment/.test(m) ? "target binding not present" : "unsupported sink for sourceType";
      skipped.push({ name: rec.name, reason });
      // Counted HERE, at the one site that knows this skip was a refusal rather than the operator's own
      // narrowing. See the declaration for why the plan's ok/complete must read this and not skipped.length.
      sinkUnresolved += 1;
      continue;
    }
    plan.push({ rec, resolved });
  }
  return { skipped, sinkUnresolved, outOfBand, plan, configPlan, mediaPlan, ...(cfIdentityRec !== undefined ? { cfIdentityRec } : {}) };
}

// computeD1DependencyWarnings is the READ-ONLY D1 table-subset lint (RestorePlan.dependencyWarnings).
// When a restore drops SOME of a database's tables' rows but keeps a child table that references a
// dropped, non-empty parent, it advises the operator (before they confirm) that the child's references
// will dangle. It writes nothing and never throws into the plan.
//
// Two refinements keep it from crying wolf on a correct restore:
//  - WHOLE-DATABASE SHORT-CIRCUIT: if every one of a database's row pages is in scope, no rows are
//    dropped, so no dependency can be missing -- skip (and never read the header). This is the common
//    case (a plain whole-DB restore) and it is where the empty-parent false positive lived: an empty
//    table emits no row page, so it is simply "not populated", never a dropped dependency.
//  - PARENT-HAS-DATA FILTER: a structural warning is kept only when the missing parent actually holds
//    rows in the backup; dropping an empty parent leaves nothing to dangle.
// "Selected" and "populated" are derived from row-page presence (an in-scope page => that table is
// populated in this restore; any page in the run => that table holds rows), mapped to table names via
// the header's declaration order (ti). A header that is absent (a legacy whole-dump body) or unreadable
// yields no warning for that database, never a plan failure. The header read (the only I/O) happens
// only for a genuine subset, past the short-circuit.
//
// Granularity is per-table: a table with ANY in-scope row page counts as selected/populated, so an
// intra-table partial row drop (some pages of one table excluded) is not itself flagged. The lint is
// about dropping a table's data relative to a child that references it, not about within-table row
// subsets.
/** The sentence for expirations that have ALREADY gone by at plan time. Internal: one caller, below. */
function lapsedAlreadySentence(n: number): string {
  return `${n} Workers KV ${n === 1 ? "key carries an expiration that has" : "keys carry an expiration that has"} already passed, because this backup is older than the namespace's TTLs. ${n === 1 ? "It restores" : "They restore"} with the value and metadata intact and WITHOUT the expiration, so ${n === 1 ? "it will" : "they will"} not expire until a new TTL is set.`;
}

/**
 * The dry run's lapsed-KV-expiration warning, over the two counts that matter: what has gone by ALREADY, and
 * what can additionally go by before the LAST instant an apply of this plan may still be writing.
 *
 * The second number exists because the plan and the apply read different clocks. Reporting only the first
 * would name fewer keys than the sink can drop, which is the silent drop this warning was added to end.
 * Reporting only the total would tell an operator that keys are already gone when applying now would still
 * save them.
 *
 * The window it names is RESTORE_APPLY_DEADLINE_MS, not the approval's TTL: an apply is reserved while the
 * approval is still valid and then keeps writing under that reservation for up to RESTORE_APPLY_LEASE_MS,
 * so a sentence that named only the 24 hours would describe as safe a key an apply starting one second
 * inside the window still drops.
 *
 * When nothing lapses during that window the sentence is exactly what it has always been, because in that
 * case the plan's count IS what the receipt will carry.
 *
 * @param lapsedNow - keys whose expiration has already passed at plan time.
 * @param lapsedByApplyDeadline - keys whose expiration has passed by the last instant this plan can be applied.
 * @returns the operator-facing reason.
 */
export function lapsedKvWarningReason(lapsedNow: number, lapsedByApplyDeadline: number): string {
  const during = lapsedByApplyDeadline - lapsedNow;
  const parts: string[] = [];
  if (lapsedNow > 0) parts.push(lapsedAlreadySentence(lapsedNow));
  if (during === 0) return `${parts.join(" ")} The receipt records the count.`;
  const hours = Math.round(APPROVAL_TTL_MS / 3_600_000);
  const leaseMinutes = Math.round(RESTORE_APPLY_LEASE_MS / 60_000);
  parts.push(
    `${during} further Workers KV ${during === 1 ? "key carries an expiration that passes" : "keys carry an expiration that passes"} within the ${hours} hours this plan's approval stays valid plus the ${leaseMinutes} minutes an apply may still be writing after it starts, so ${during === 1 ? "it is" : "they are"} counted here rather than dropped later with nothing in this plan naming ${during === 1 ? "it" : "them"}. Applying sooner keeps ${during === 1 ? "that expiration" : "those expirations"}.`,
  );
  parts.push("The receipt records what was actually dropped.");
  return parts.join(" ");
}

async function computeD1DependencyWarnings(run: Run, plan: Array<{ rec: ShardRecord; resolved: Resolved }>): Promise<D1DependencyWarning[]> {
  // In-scope row-page table indexes + count, grouped by database (from the plan). A table may span many
  // pages, so the count is of records (for the short-circuit), the Set is of distinct tis (for selection).
  const inScopeByDb = new Map<string, { tis: Set<number>; count: number }>();
  for (const { rec } of plan) {
    if (rec.sourceType !== "d1") continue;
    const db = d1DatabaseNameFromRecordName(rec.name);
    let g = inScopeByDb.get(db);
    if (g === undefined) { g = { tis: new Set(), count: 0 }; inScopeByDb.set(db, g); }
    const ti = d1TableIndexFromRowRecordName(rec.name);
    if (ti !== null) { g.tis.add(ti); g.count++; }
  }
  if (inScopeByDb.size === 0) return [];
  // Populated tis + total row-page count per database, across the WHOLE run (any scope) in one pass. An
  // empty table emits no row page, so it never appears here -- that is what makes it "not populated".
  const runByDb = new Map<string, { populated: Set<number>; total: number }>();
  for (const rec of run.records) {
    if (rec.sourceType !== "d1") continue;
    const ti = d1TableIndexFromRowRecordName(rec.name);
    if (ti === null) continue;
    const db = d1DatabaseNameFromRecordName(rec.name);
    let g = runByDb.get(db);
    if (g === undefined) { g = { populated: new Set(), total: 0 }; runByDb.set(db, g); }
    g.populated.add(ti);
    g.total++;
  }
  const out: D1DependencyWarning[] = [];
  for (const [db, inScope] of inScopeByDb) {
    const all = runByDb.get(db) ?? { populated: new Set<number>(), total: 0 };
    if (inScope.count === all.total) continue; // no row page dropped => no missing dependency possible
    const headerRec = run.records.find((r) => r.sourceType === "d1" && r.name === `${db}/00-header`);
    if (headerRec === undefined) continue;
    let tables: Array<{ name: string; sql: string }>;
    try {
      const decoded = decodeD1Record(await run.restoreRecord(headerRec));
      if (decoded.kind !== "header") continue;
      tables = decoded.tables.map((t) => ({ name: t.name, sql: t.sql }));
    } catch {
      continue; // an unreadable/foreign header yields no lint, never a plan failure
    }
    const tiName = (ti: number): string | null => (ti >= 0 && ti < tables.length ? tables[ti]!.name : null);
    const selected = new Set<string>();
    for (const ti of inScope.tis) { const n = tiName(ti); if (n !== null) selected.add(n); }
    const populatedLc = new Set<string>();
    for (const ti of all.populated) { const n = tiName(ti); if (n !== null) populatedLc.add(n.toLowerCase()); }
    // Structural warnings, refined by data presence: keep a warning only when the missing parent holds
    // rows in the backup (dropping an empty parent leaves nothing to dangle).
    for (const w of d1DependencyWarnings(tables, selected)) {
      if (populatedLc.has(w.missingParent.toLowerCase())) out.push({ database: db, table: w.table, missingParent: w.missingParent });
    }
  }
  return out;
}

// runDryRun verifies each in-scope record read-only (restoreRecord checks the plaintext hash) within the
// maxRecords window, summing bytes, then returns the plan. It writes NOTHING (the cf-config write() runs
// dryRun:true, the D1 sink decodes without batching, media is only previewed). This is the original
// dry-run branch lifted verbatim; the verify proves recoverability without writing anything.
export async function runDryRun(body: RestoreRequest, run: Run, state: RestorePlanState, bufferedMaxBytes: number, runId: string, isLatest: boolean, sampleCap: number, cfApiFactory: (token: string) => CfApi): Promise<RestorePlan> {
  const { skipped, sinkUnresolved, outOfBand, plan, configPlan, mediaPlan } = state;
  // plannedWrites counts only records with a runtime write path. Secrets records have already been
  // separated into outOfBand above and are excluded from plannedWrites; they appear in skipped alongside
  // selector-excluded records so the operator can see exactly which records require out-of-band handling.
  let recordsVerified = 0;
  let bytes = 0;
  const sample: RestoreSampleItem[] = [];
  const dryRunSkipped: RestoreSkipped[] = [];
  // Window the COMBINED in-account work (data + cf-config + media) so the dry-run reports the same ceiling
  // and the same windowed/outOfWindow honesty the apply enforces: a media/cf-config-heavy run is
  // counted, refused-when-oversized and sliced identically on both paths.
  const { dataWindow: window, configWindow, mediaWindow, total: inAccountTotal, outOfWindow, d1OutOfWindow } = inAccountWindow(plan, configPlan, mediaPlan, body.maxRecords, d1GroupOfDataRecord);
  // An oversized in-account restore cannot complete in one Worker invocation; report it honestly
  // (steer to the offline CLI) rather than dying at the subrequest cap mid-verify. The ceiling bounds the
  // COMBINED window (data + cf-config + media), so an unbounded oversized run is refused AND a windowed
  // restore whose combined window still exceeds the ceiling is refused too.
  if (window.length + configWindow.length + mediaWindow.length > MAX_IN_ACCOUNT_RESTORE_RECORDS) {
    return { ok: false, runId, mode: "dry-run", recordsVerified: 0, isLatest, plannedWrites: 0, bytes: 0, sample: [], skipped: [...skipped, ...outOfBand], reason: inAccountTooLargeReason(inAccountTotal) };
  }
  for (const { rec, resolved } of window) {
    // Verifying proves recoverability without writing. A large R2 record is verified through the
    // constant-memory STREAMING path (the same path apply will use), so a multi-GB value's dry-run
    // verify never materialises it whole. A D1 record cannot stream (it is verified whole and then
    // shape-checked); everything else takes the buffered restoreRecord.
    if (shouldStream(rec, bufferedMaxBytes)) {
      await verifyRecordStreamingDiscard(run, rec); // streams, authenticates, checks final SHA-384
    } else {
      // restoreRecord proves the archive plaintext SHA-384, but for a D1 record that only
      // proves the BYTES are intact, not that they decode into a replayable schema-plus-rows
      // dump (the body shape is interpreted by the D1 sink, not by the archive). resolveSink
      // built this sink in dryRun mode (!confirm), so its put() DECODES and shape-checks the
      // dump and writes nothing. Exercising it here means a malformed dump (E4) is caught at
      // dry-run with zero writes instead of passing "dry-run clean" and failing on apply. A
      // decode failure is a per-record skip (it would not replay), not a whole-run abort, and
      // it is excluded from plannedWrites so the plan never promises a write that cannot land.
      const value = await run.restoreRecord(rec); // verifies the plaintext SHA-384
      // RESTORE-SKIP: a data record whose value is an incompleteness MARKER
      // (_vanished / _skipped, not real bytes) is NOT a planned write -- writing it back would re-create a
      // deleted/uncaptured key with sentinel JSON. Surface it out of band (mirrors the media marker preview
      // below and the apply path's skip), never counting it toward plannedWrites. Its bytes verified fine
      // above, so the archive is intact; the marker simply must not become a live value.
      // Gate on rec.incompleteMarker (the signed manifest field, adapter-asserted at seal time),
      // never by re-parsing the decrypted `value` -- a real value that merely LOOKS marker-shaped carries
      // no adapter assertion and is planned as a normal write instead of being silently excluded.
      if (rec.incompleteMarker !== undefined) {
        outOfBand.push({ name: rec.name, reason: "the captured value is an incompleteness marker (the object vanished or was skipped at capture), not real bytes; nothing to restore" });
        continue;
      }
      if (rec.sourceType === "d1") {
        try {
          // dryRun sink: decodes + validates the body, writes nothing (no batch, no statement).
          await resolved.sink.put(rec.name, value);
        } catch (e) {
          log("error", `restore ${runId} record ${rec.name} [err:${errId(e)} d1-dryrun-decode-failed]`);
          dryRunSkipped.push({ name: rec.name, reason: "D1 dump would not replay: malformed backup body" });
          continue;
        }
      }
    }
    recordsVerified++;
    bytes += rec.plaintextSize;
    if (sample.length < sampleCap) sample.push(resolved.sample);
  }
  // cf-config DRY-RUN: compute the per-surface diff READ-ONLY (write(dryRun:true) reads live config and
  // diffs the verified snapshot; it writes nothing). A surface whose read or diff throws (a token-scope
  // error, an incomplete snapshot) is surfaced out of band with a coarse reason, never failing the plan.
  const configChanges: NonNullable<RestorePlan["configChanges"]> = [];
  for (const { rec, surface } of configWindow) {
    try {
      const snapshot = decodeConfigSnapshot(await run.restoreRecord(rec));
      const api = cfApiFactory(body.cfConfig!.token);
      const ids = { accountId: body.cfConfig!.accountId, ...(body.cfConfig!.zoneId ? { zoneId: body.cfConfig!.zoneId } : {}) };
      const res = await surface.write!(api, ids, snapshot, { dryRun: true });
      configChanges.push({ surface: rec.name, summary: summariseDiff(res), willApply: res.changes.some((c) => c.action !== "remove") });
    } catch (e) {
      outOfBand.push({ name: rec.name, reason: `Cloudflare config, ${coarseCfReason(e)}` });
    }
  }
  // media DRY-RUN: preview the captured media an apply would re-upload. A marker-sized record is still
  // decrypted here (proving it recovers cleanly); a larger record is real file bytes by construction and is
  // never decrypted just to check. Read-only; nothing uploads.
  const mediaPlanned: NonNullable<RestorePlan["mediaPlanned"]> = [];
  for (const { rec, type } of mediaWindow) {
    try {
      if (rec.plaintextSize <= MEDIA_MARKER_MAX) await run.restoreRecord(rec);
      // Whether this is a marker (not file bytes) comes from rec.incompleteMarker (the signed,
      // adapter-asserted manifest field), never from re-parsing the decrypted bytes above -- a real small
      // media file that happens to look marker-shaped carries no adapter assertion and is planned normally.
      if (rec.incompleteMarker !== undefined) {
        outOfBand.push({ name: rec.name, reason: "media file, the captured value was a marker (capture had failed), not file bytes" });
        continue;
      }
      mediaPlanned.push({ name: rec.name, type });
    } catch (e) {
      outOfBand.push({ name: rec.name, reason: `media file, ${coarseCfReason(e)}` });
    }
  }
  // WINDOWED-RESTORE HONESTY: maxRecords may have capped the plan to fewer COMBINED records (data +
  // cf-config + media) than the selector matched. The records beyond the window were never verified, so a
  // windowed preview must not present as a whole-run preview. ok keeps its meaning (dryRunSkipped.length
  // === 0) so an operator who pages on purpose is not regressed; complete:false plus the explicit
  // "(window)" marker is the honest signal that records were left out of scope. outOfWindow is the combined
  // count inAccountWindow computed, so media/cf-config left beyond the window are counted too, not only data.
  // The reason steers an unrestored (non-resumable) D1 OFFLINE rather than telling the operator to re-run
  // with a higher maxRecords to finish it (windowSkippedReason branches on d1OutOfWindow), matching the apply.
  const windowSkipped: RestoreSkipped[] = outOfWindow > 0
    ? [{ name: "(window)", reason: windowSkippedReason(outOfWindow, d1OutOfWindow) }]
    : [];
  // D1 DEPENDENCY LINT: advise if a chosen table subset omits a selected child's FK parent (read-only,
  // over the full in-scope plan, independent of the maxRecords window).
  const dependencyWarnings = await computeD1DependencyWarnings(run, plan);
  // LAPSED KV EXPIRATIONS: the fidelity loss this apply already knows it will take, said BEFORE the operator
  // confirms rather than only on the receipt afterwards. A KV expiration is captured as an ABSOLUTE instant,
  // so a backup older than the namespace's TTLs carries instants that have gone by; the sink restores those
  // keys without the expiration (see KVRestoreSink.put) and they then never expire until a TTL is re-set.
  //
  // It reads rec.kv off the SIGNED manifest, so it costs no read, no decrypt and no clock beyond one call,
  // and it uses the sink's own kvExpirationLapsed rather than a second copy of the arithmetic. It is computed
  // over the WINDOW (the records this apply would actually write), so a windowed preview never warns about
  // records it is not writing.
  //
  // ONE AGGREGATE ROW, not one per key: a TTL-bearing namespace can hold millions of them, the remedy is a
  // namespace-level decision rather than a per-key one, and an unbounded list on a preview screen is its own
  // defect. The count is the actionable part.
  //
  // AND IT IS ASKED ON THE APPLY'S CLOCK, NOT THIS ONE. A dry run is read, approved by a second person and
  // applied later, so "which expirations have lapsed" has a different answer here than it will have at the
  // sink, and it can only move one way: time passes, so the plan can only ever under-report. An expiration
  // sitting between the two instants can read not-lapsed here and lapsed there, which would drop it with no
  // row in the plan the operator approved. This warning exists to close that silent case.
  //
  // THE SHAPE OF THE ANSWER, and the obvious one is wrong. Carrying this instant forward into the apply
  // would make the two agree by making the SINK wrong: the binding refuses an expiration without
  // KV_EXPIRATION_MIN_LEAD_SECONDS of lead whatever the plan believed, so a key that really did lapse in the
  // meantime would be offered its stale expiration and fail the put under the generic destination reason.
  // That is the original defect, restored. The sink must keep the live clock.
  //
  // So the PLAN moves instead, to the latest instant at which an apply of THIS plan can still be writing.
  // That instant is restoreApplyDeadlineMs, and getting it right took two corrections that a first reading
  // misses, both of which left the plan able to under-warn:
  //
  //   (1) THE APPROVAL'S LIFE IS NOT THE WHOLE DISTANCE. An apply RESERVES the approval while it is still
  //       valid and then keeps writing under that reservation, which the DO honours for
  //       RESTORE_APPLY_LEASE_MS. An apply starting one second inside the approval window is still writing
  //       half an hour later, so the deadline is APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS.
  //   (2) THE CLOCK STARTS AT THE PLAN. Stamping expiresAt at REQUEST time would measure the deadline from
  //       an instant strictly later than this one, by however long the operator spent reading the plan --
  //       unbounded, and repeatable for ever because a plan hash carries no timestamp. The dry-run route
  //       instead records the plan anchor (PLAN_SEEN_PREFIX) and the DO stamps the TTL from it, so the
  //       deadline below is the deadline the approval will actually carry rather than an optimistic guess.
  //
  // Both sides call restoreApplyDeadlineMs, which is the point: a superset derived twice is a superset by
  // coincidence. The warned set is a SUPERSET of the dropped set rather than an equal one, which is the
  // right direction: it can over-warn by naming a key that a prompt apply still saves, and it can never
  // under-warn. Both counts are reported, because "8 already gone, 2 more if you take the day to approve it"
  // is a different decision from "10 gone".
  const plannedAtMs = Date.now();
  const applyDeadlineMs = restoreApplyDeadlineMs(plannedAtMs, plannedAtMs);
  const isKvWithLapsed = (nowMs: number) => ({ rec }: { rec: ShardRecord }): boolean => rec.sourceType === "kv" && kvExpirationLapsed(rec.kv?.expiration, nowMs);
  const lapsedKvCount = window.filter(isKvWithLapsed(plannedAtMs)).length;
  const lapsedKvByApplyDeadline = window.filter(isKvWithLapsed(applyDeadlineMs)).length;
  const fidelityWarnings: RestoreFidelityWarning[] = lapsedKvByApplyDeadline > 0
    ? [{ name: "(kv expirations)", reason: lapsedKvWarningReason(lapsedKvCount, lapsedKvByApplyDeadline) }]
    : [];
  // CROSS-ACCOUNT WARNING: surface any cf-config / media leg whose target account is not the
  // archive's signed origin, so the console SHOWS a cross-account restore (and drives the type-to-confirm the
  // apply requires) before it is confirmed. Read-only here; the apply is where the guard actually refuses.
  const crossAccount = crossAccountWarnings(body, state);
  // CROSS-ZONE WARNING: the account guard above does not cover the mistake that is far easier to
  // make. A customer with several zones in one account picks the wrong one, the account matches, nothing
  // gates, and every zone-scoped surface is written into the wrong zone. Read the origin zone off the
  // identity record (hash-verified by restoreRecord like any other record, so the request cannot spoof it)
  // and warn here; the apply is where this actually refuses.
  let crossZone: CrossZoneWarning | null = null;
  if (body.cfConfig?.zoneId !== undefined && state.cfIdentityRec !== undefined) {
    try {
      crossZone = crossZoneWarning(body, originZoneFrom(await run.restoreRecord(state.cfIdentityRec)), state.configPlan);
    } catch {
      // The identity record did not verify or decode. Treat the origin as unknown rather than absent: an
      // unreadable origin is exactly the unverifiable case the guard exists for, so it must still warn.
      crossZone = crossZoneWarning(body, null, state.configPlan);
    }
  }
  // A SINK-RESOLUTION REFUSAL IS A WAY A RECORD FALLS OUT OF A PLAN, so both verdict fields must read it.
  // Until they did, a plan that could write NOTHING AT ALL presented as `ok:true, plannedWrites:0, bytes:0,
  // sample:[], complete:true` with every record sitting in the `skipped` array neither field read -- on the
  // last screen an operator sees before authorising a write-back.
  //
  // sinkUnresolved, NOT skipped.length: see its declaration. `skipped` also carries the operator's own
  // narrowing, and counting that would make a deliberate one-of-three granular restore call itself
  // incomplete -- which is a false claim in the other direction, and the existing plan-accounting proofs
  // are what caught it.
  //
  // `complete` already means "every record is in this plan", and it was computed over only ONE of the two
  // ways a record can involuntarily fall out of one. The windowed case was graded correctly (complete:false,
  // outOfWindow, and a named remedy), which is what made this a hole rather than a design: five records left
  // out of scope was honestly incomplete while all eight unwritable was complete.
  return {
    ok: dryRunSkipped.length === 0 && sinkUnresolved === 0,
    runId,
    mode: "dry-run",
    recordsVerified,
    isLatest,
    plannedWrites: recordsVerified,
    bytes,
    sample,
    skipped: [...skipped, ...outOfBand, ...dryRunSkipped, ...windowSkipped],
    outOfWindow,
    windowed: outOfWindow > 0,
    complete: dryRunSkipped.length === 0 && outOfWindow === 0 && sinkUnresolved === 0,
    // THE PLAN'S OWN DEADLINE, stated rather than left implicit. plannedAt is the instant the disclosure
    // below was computed on; applyDeadline is the last instant an apply of an approval anchored to this plan
    // may still be writing, and it is the exact instant fidelityWarnings was computed against. Publishing it
    // is what makes the superset claim CHECKABLE from outside the engine: a reader can take the deadline,
    // ask the sink's own rule what it would drop then, and compare. Always present, because a plan whose
    // deadline is unstated is a plan whose warning cannot be audited.
    plannedAt: new Date(plannedAtMs).toISOString(),
    applyDeadline: new Date(applyDeadlineMs).toISOString(),
    ...(configChanges.length > 0 ? { configChanges } : {}),
    // The resolved allow-list, keyed off the SAME body.cfConfig the hash binds, so the console can compute
    // a matching plan hash without carrying its own copy of the proven set. Emitted whenever a cfConfig
    // context was supplied, including when the archive holds no config records to preview: the surface set
    // is bound into the hash regardless of what the plan found, so gating this on configChanges would leave
    // the console unable to match exactly when there is nothing on screen to explain the difference.
    // resolveCfConfigSurfaces is pure and is called with the same body.cfConfig?.surfaces buildRestorePlan
    // filtered on and restorePlanHash binds, so this is the same list by construction rather than a second
    // opinion about what it should be.
    ...(body.cfConfig !== undefined ? { cfConfigSurfaces: resolveCfConfigSurfaces(body.cfConfig.surfaces) } : {}),
    ...(mediaPlanned.length > 0 ? { mediaPlanned } : {}),
    ...(dependencyWarnings.length > 0 ? { dependencyWarnings } : {}),
    ...(fidelityWarnings.length > 0 ? { fidelityWarnings } : {}),
    ...(crossAccount.length > 0 ? { crossAccountWarnings: crossAccount } : {}),
    ...(crossZone !== null ? { crossZoneWarning: crossZone } : {}),
  };
}
