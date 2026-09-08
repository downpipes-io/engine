import { accountPacer } from "../cf-pace.ts";
import type { RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import type { Run } from "../format/reader.ts";
import { log } from "../log.ts";
import { classifyRestoreFailure } from "../restore-reasons.ts";
import { type CfApi, makeCfApi } from "../sources/cf-config-surfaces.ts";
import { d1DatabaseNameFromRecordName, d1TableIndexFromRowRecordName } from "../sources/d1.ts";
import { decodeD1Record } from "../sources/d1-format.ts";
import { inScope } from "../sources/selector.ts";
import { type MediaUploader, makeMediaUploader } from "./media-restore.ts";
import { runApply } from "./restore-apply.ts";
import { openRunFromMaster, openVerifiedRun } from "./restore-open.ts";
import { buildRestorePlan, runDryRun } from "./restore-plan.ts";
import { makeReservedRefusalResult } from "./restore-plan-types.ts";
import { BREAK_GLASS_REASON, bufferedRestoreMaxBytes, errId, SAMPLE_CAP } from "./restore-sinks.ts";
import type { RestoreDestFallback, RestorePlan, RestoreRequest, RestoreResult } from "./restore-types.ts";

export { restoreReceiptDigestHex, verifyRestoreReceiptSignature } from "./restore-receipt.ts";
// The public restore API is re-exported here so importers (the admin router, the validators) keep one
// stable module to import from while the implementation lives in cohesive sibling modules:
//   restore-sinks.ts     sink resolution, the reserved-binding guard, streaming verify/readback, guidance.
//   restore-cfconfig.ts  cf-config snapshot decode + diff summary + coarse reasons.
//   restore-receipt.ts   the signed / audit-anchored RestoreReceipt builder + verifier.
//   restore-open.ts      the keyed run-open closure shared by restore + the verify/attest path.
//   restore-plan-types.ts the plan-state shapes + the reserved-binding refusal renderer.
//   restore-plan.ts      record classification (buildRestorePlan) + the read-only dry-run pass.
//   restore-apply.ts     the destructive apply pass (verify-all-then-write + readback + receipt).
//   restore-verify.ts    the blind restore-test + keyless attestation (the read-only recovery proofs).
export { guardTarget, mediaRestoreGuidance, resolveSink, verifyReadbackStreaming, workersRestoreGuidance } from "./restore-sinks.ts";
export { runBlindRestoreTest, runKeylessAttest } from "./restore-verify.ts";
// readRestoreCapsule (008) serves a chosen run's non-secret master capsule + key commitment so the operator's
// browser can decap this one run's per-run master locally for an in-console break-glass restore. Re-exported
// here so the admin router imports every restore primitive from one module.
export { readRestoreCapsule } from "./restore-open.ts";

// In-account RESTORE: the write-back dual of the seal path. It opens a sealed run with the
// OPERATIONAL read-back key (SPEC 12.6), verifies the whole SPEC 8.3 chain against the
// operator-pinned signer, then for each in-scope record re-verifies the plaintext hash
// (restoreRecord) BEFORE writing a single byte back into a live in-account resource. Like
// the drill it requires env.OPERATIONAL_PRIVATE to read back in-account; without it, restore
// is a break-glass-only offline operation and the route honestly says so. Restore is on the
// recovery path, so it NEVER consults the licence and works at tier 'community'.
//
// Dry-run is the default: with confirm absent or false it writes NOTHING and returns a plan
// of what an apply would do. Only confirm:true writes. A reserved target binding is refused
// (the confused-deputy guard, symmetric to buildAdapter on the read side) so a restore can
// never overwrite the engine's own signer key or destination credentials.

// Test-injection seams for runRestore. Both default to the real Cloudflare factories; tests supply fakes so
// the cf-config and media re-upload paths can be exercised without a live account. Collapsed into one options
// object to keep runRestore within the 4-parameter limit.
export interface RestoreOptions {
  cfApiFactory?: (token: string) => CfApi;
  mediaUploaderFactory?: (token: string) => MediaUploader;
  // sourceBindings maps a backed-up resource's identity (`kv:<namespaceId>` / `r2:<bucketName>` /
  // `d1:<dbName>`) to the Worker binding the source was attached under, so a restore writes back to the
  // operator's ACTUAL binding rather than the KV_<id>/R2_<bucket>/D1_<name> convention (which the attach
  // never used). The router builds it from the live downpipe configs; absent here it falls back to the
  // convention, byte-for-byte as before.
  sourceBindings?: ReadonlyMap<string, string>;
  // master (008, in-console break-glass restore) is a BROWSER-SUPPLIED 32-byte per-run master. When present
  // the run is opened via openRunFromMaster (the console decapsulated THIS run's master capsule locally; the
  // break-glass PRIVATE never reaches the engine) instead of openVerifiedRun's held OPERATIONAL_PRIVATE, so a
  // break-glass-only estate with no operational key can still restore. It is used ONLY to open the run and is
  // NEVER stored, logged, folded into the plan hash, placed in a recordAudit target, or carried on the
  // RestorePlan/RestoreResult/receipt: the router reads it from a distinct transport header into this field
  // (never onto RestoreRequest) and discards it, and everything downstream of the open is master-source-
  // agnostic (buildRestorePlan / runDryRun / runApply consume an already-opened Run and the master lives only
  // inside that Run object). Absent => the run opens with the operational key exactly as before, byte-for-byte.
  master?: Uint8Array;
  // destFallback (3-2-1 walk) is the record of the destinations withRunDestFallback already tried and was
  // refused by before this attempt. It is threaded in rather than discovered here because the restore core
  // reads ONE destination and has no way to know it is the second choice, and because the fact has to reach
  // the SIGNED receipt core: a receipt is what a customer keeps to prove what they recovered and from where,
  // and a fallback recorded only beside the signature is a fallback a tamperer can strip. Absent on a
  // first-choice restore, which is every restore whose primary answered, so the receipt bytes are unchanged.
  // It never influences a verdict: the replica is opened and verified in full from its own bytes.
  destFallback?: RestoreDestFallback;
}

// restoreScopeError renders the honest "nothing written" refusal for a scope problem (an unknown D1 table,
// a bad d1Tables/recordName combination, or a recordName matching no record), in the applied or dry-run
// shape the caller expects. Nothing is written; the reason states why.
function restoreScopeError(confirm: boolean, runId: string, isLatest: boolean, reason: string): RestorePlan | RestoreResult {
  return confirm
    ? { ok: false, runId, mode: "applied", recordsVerified: 0, recordsRestored: 0, bytesRestored: 0, isLatest, failures: [], reason }
    : { ok: false, runId, mode: "dry-run", recordsVerified: 0, isLatest, plannedWrites: 0, bytes: 0, sample: [], skipped: [], reason };
}

// resolveD1TableScope turns a d1Tables selection into the exact set of record names to restore: the named
// database's header (which creates EVERY table, so a fresh target keeps its full schema) + the schema
// record + ONLY the chosen tables' row pages. Table names are matched case-insensitively against the
// header (the authoritative table list), so an EMPTY table (which emits no row page) is still selectable
// and a typo is refused loudly. Returns the allow set, or an error the caller maps to a refusal. It reads
// only (one small header record) and writes nothing.
async function resolveD1TableScope(run: Run, sel: { database: string; tables: string[] }): Promise<{ allow: Set<string>; selectedTablesLc: Set<string> } | { error: string }> {
  const db = sel.database;
  if (typeof db !== "string" || db.length === 0) return { error: "d1Tables.database is required" };
  if (!Array.isArray(sel.tables) || sel.tables.length === 0) return { error: "d1Tables.tables must be a non-empty list of table names" };
  const headerRec = run.records.find((r) => r.sourceType === "d1" && r.name === `${db}/00-header`);
  if (headerRec === undefined) return { error: `D1 database not found in this run (no per-table header): ${db}` };
  let headerTables: ReadonlyArray<{ name: string }>;
  try {
    const decoded = decodeD1Record(await run.restoreRecord(headerRec));
    if (decoded.kind !== "header") return { error: `D1 database ${db} is a legacy whole-dump backup; table-subset restore needs a per-table backup` };
    headerTables = decoded.tables;
  } catch {
    return { error: `D1 database ${db} header could not be read` };
  }
  const tiByNameLc = new Map<string, number>();
  headerTables.forEach((t, ti) => { tiByNameLc.set(t.name.toLowerCase(), ti); });
  const selectedTis = new Set<number>();
  for (const name of sel.tables) {
    const ti = tiByNameLc.get(String(name).toLowerCase());
    if (ti === undefined) return { error: `table not found in D1 database ${db}: ${String(name)}` };
    selectedTis.add(ti);
  }
  const allow = new Set<string>([`${db}/00-header`, `${db}/20-schema`]);
  for (const rec of run.records) {
    if (rec.sourceType !== "d1" || d1DatabaseNameFromRecordName(rec.name) !== db) continue;
    const ti = d1TableIndexFromRowRecordName(rec.name);
    if (ti !== null && selectedTis.has(ti)) allow.add(rec.name);
  }
  // The lower-cased selected table names, for the createOnly restriction (which tables the sink creates).
  const selectedTablesLc = new Set<string>();
  for (const ti of selectedTis) selectedTablesLc.add(headerTables[ti]!.name.toLowerCase());
  return { allow, selectedTablesLc };
}

export async function runRestore(env: Env, body: RestoreRequest, destOverride?: RuntimeDestConfig | null, options: RestoreOptions = {}): Promise<RestorePlan | RestoreResult> {
  // B4: PACE the restore's Cloudflare calls, exactly as the backup paces its crawl. Both legs were built
  // without a pacer while the seal path has had accountPacer(env) throughout, so a restore was the one
  // place in the product that could hammer the account API at whatever rate the loop managed.
  //
  // It matters most on the surfaces worth restoring. A cf-config apply is one call to read live plus one
  // per changed item per surface, and a media re-upload is one per object, so a restore of a real account
  // is comfortably into the thousands of calls against a 1200-per-5-minutes account limit. Without pacing
  // that arrives as a burst of 429s partway through, which fail-open turns into a scatter of skipped
  // surfaces and half-restored media rather than a clean refusal.
  //
  // accountPacer is the same shared constructor the seal path uses, so it honours the RATELIMIT_DO binding
  // when present and falls back to the per-isolate CfPacer when it is not. Tests that inject their own
  // factory are unaffected: the pacer only applies to the default one.
  const cfApiFactory = options.cfApiFactory ?? ((token: string) => makeCfApi(token, fetch, accountPacer(env)));
  const mediaUploaderFactory = options.mediaUploaderFactory ?? ((token: string) => makeMediaUploader(token, fetch, accountPacer(env)));
  const runId = body.runId;
  const confirm = body.confirm === true;
  // master (008): the browser-supplied per-run master, threaded here from a distinct transport header by the
  // router. It is never a field on RestoreRequest, and never reaches the plan hash / audit / receipt / DO
  // writes; it is used only to open the run below and then dropped when the request returns.
  const master = options.master;
  // The break-glass restore refusal, made CONDITIONAL (008). Restore needs a way to recover THIS run's master:
  // either the in-account OPERATIONAL_PRIVATE (the operational posture) OR a browser-supplied per-run master
  // (the in-console break-glass restore, where the break-glass private stays in the browser and only the
  // single-archive master crosses). Refuse ONLY when there is NEITHER: with no operational key AND no supplied
  // master, restore can be exercised only offline, so report it (never error), exactly as before and as the
  // drill does. When a master IS supplied it opens the run below (openRunFromMaster) and is validated against
  // the signed key commitment, so an absent OR a wrong/cross-run master on a break-glass-only estate still
  // fails closed (here, or at the commitment check) with nothing written. This is a SAFETY gate: it is widened
  // by exactly one case (a genuinely valid supplied master), never any other.
  if (!env.OPERATIONAL_PRIVATE && master === undefined) {
    return confirm
      ? { ok: false, runId, mode: "applied", recordsVerified: 0, recordsRestored: 0, bytesRestored: 0, isLatest: false, failures: [], reason: BREAK_GLASS_REASON }
      : { ok: false, runId, mode: "dry-run", recordsVerified: 0, isLatest: false, plannedWrites: 0, bytes: 0, sample: [], skipped: [], reason: BREAK_GLASS_REASON };
  }

  // The buffered ceiling for THIS restore (env-overridable, clamped). Computed once so the dry-run
  // verify pass, the apply verify pass and the apply write pass all make the identical buffered-vs-stream
  // decision for every record.
  const bufferedMaxBytes = bufferedRestoreMaxBytes(env);

  try {
    // Open the run: from the browser-supplied per-run master when one was provided (openRunFromMaster, the
    // in-console break-glass path, which needs no operational key), else from the held OPERATIONAL_PRIVATE
    // (openVerifiedRun, unchanged). Both build the identical read-only store + verifier and run the identical
    // verified open, so ONLY the source of the decrypt key differs; everything below this line is untouched and
    // stays master-source-agnostic (it consumes the opened Run object, which holds the master internally).
    const run = master !== undefined
      ? await openRunFromMaster(env, runId, master, destOverride ?? null)
      : await openVerifiedRun(env, runId, destOverride ?? null);
    const isLatest = run.freshness?.isLatestForDownpipe ?? false;
    // GRANULAR single-record restore (E4/C1): recordName is the first-class single-record intent. When
    // set it scopes the WHOLE restore to EXACTLY the one record whose source name equals it (an exact
    // match in recordScoped, NOT a prefix), so the plan reports "1 record" and an apply writes only that
    // record. It supersedes the prefix include/exclude (the more specific intent wins), and being an exact
    // single name it can never widen the scope. inRecordScope is the single scope predicate the plan loop
    // uses: exact-name when recordName is set, else the prefix selector unchanged. A recordName that
    // matches no record yields an empty plan and an honest "record not found in run" reason rather than a
    // silent whole-run or empty success.
    const recordName = typeof body.recordName === "string" && body.recordName.length > 0 ? body.recordName : null;
    const selector = { include: body.include ?? [], exclude: body.exclude ?? [] };
    // D1 TABLE-SUBSET (d1Tables): scope the restore to one database's chosen tables (header + schema + only
    // those tables' row pages, into a fresh database). It supersedes include/exclude and is MUTUALLY
    // EXCLUSIVE with recordName (they express different, non-composable intents). Resolved against the run's
    // header (the authoritative table list) into an exact allow-set of record names, so a typo'd table name
    // is refused loudly rather than silently restoring nothing.
    let d1Allow: Set<string> | null = null;
    let d1Restrict: { database: string; tables: ReadonlySet<string> } | undefined;
    if (body.d1Tables !== undefined) {
      if (recordName !== null) return restoreScopeError(confirm, runId, isLatest, "d1Tables and recordName cannot be combined in one restore");
      const resolved = await resolveD1TableScope(run, body.d1Tables);
      if ("error" in resolved) return restoreScopeError(confirm, runId, isLatest, resolved.error);
      d1Allow = resolved.allow;
      // createOnly: restrict the fresh DB to ONLY the selected tables (a minimal extract). Otherwise the
      // header creates every table (the full schema) and only the selected tables are populated.
      if (body.d1Tables.createOnly === true) d1Restrict = { database: body.d1Tables.database, tables: resolved.selectedTablesLc };
    }
    const inRecordScope = (name: string): boolean =>
      recordName !== null ? name === recordName : d1Allow !== null ? d1Allow.has(name) : inScope(name, selector);
    // When a recordName was asked for but the run holds no record with that EXACT name, the plan is empty
    // by construction; surface the honest miss (ok:false, nothing written) rather than a vacuous success.
    if (recordName !== null && !run.records.some((rec) => rec.name === recordName)) {
      return restoreScopeError(confirm, runId, isLatest, "record not found in run");
    }
    const sampleCap = body.maxRecords && body.maxRecords >= 1 ? body.maxRecords : SAMPLE_CAP;

    // Resolve every in-scope record up front. A reserved target binding (in the override or in any
    // record's resolved binding) refuses the WHOLE restore before any write, so a confirm run never writes
    // a single byte when a reserved binding is in play. Secrets records are separated into outOfBand here
    // (Secrets Store bindings are read-only at runtime, so a secrets record is NEVER a planned write).
    const state = buildRestorePlan(env, body, run, inRecordScope, confirm, options.sourceBindings, d1Restrict);
    if ("reserved" in state) {
      return makeReservedRefusalResult(confirm, runId, isLatest, state.recName);
    }

    // `return await` (not a bare `return`) is load-bearing: a record-phase failure thrown INSIDE runDryRun /
    // runApply (e.g. INT-3's missing-segment completeness shortfall surfaced by restoreRecord) must settle
    // inside THIS try so the catch below classifies it (classifyRestoreFailure -> a coarse, enumerated,
    // correctly fallback-vs-non-fallback reason) instead of rejecting un-classified to the caller. A bare
    // `return promise` would hand the pending promise back before the try could observe its rejection.
    if (!confirm) {
      return await runDryRun(body, run, state, bufferedMaxBytes, runId, isLatest, sampleCap, cfApiFactory);
    }

    return await runApply(env, body, run, state, bufferedMaxBytes, runId, isLatest, cfApiFactory, mediaUploaderFactory, options.destFallback);
  } catch (e) {
    // Map the failure to a coarse, enumerated reason rather than leaking the raw exception; the detail goes
    // to the engine logs, exactly as the drill does. classifyRestoreFailure classifies by the reader's
    // STRUCTURED failure category (RunIntegrityError), so a completeness/structural/integrity failure is
    // ALWAYS the non-fallback "integrity check failed" and can never be mis-routed to a fallback-eligible
    // reason by a message the old regex did not match.
    const reason = classifyRestoreFailure(e);
    log("error", `restore ${runId} [err:${errId(e)} ${reason.replace(/ /g, "-")}]`);
    return confirm
      ? { ok: false, runId, mode: "applied", recordsVerified: 0, recordsRestored: 0, bytesRestored: 0, isLatest: false, failures: [], reason }
      : { ok: false, runId, mode: "dry-run", recordsVerified: 0, isLatest: false, plannedWrites: 0, bytes: 0, sample: [], skipped: [], reason };
  }
}
