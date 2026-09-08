import { sha384 as nobleSha384 } from "@noble/hashes/sha2.js";
import { hexEncode } from "../crypto/bytes.ts";
import {
  type BoundSecretSink,
  D1RestoreSink,
  KVRestoreSink,
  R2RestoreSink,
  type RestoreSink,
  SecretsRestoreSink,
} from "../dest/restore-sink.ts";
import type { Env } from "../env.d.ts";
import type { ShardRecord } from "../format/manifest.ts";
import type { Run } from "../format/reader.ts";
import { RESERVED_BINDINGS } from "../sched/scheduler-do.ts";
import { d1DatabaseNameFromRecordName } from "../sources/d1.ts";
import type { RestoreRequest, RestoreSampleItem, RestoreSinkType } from "./restore-types.ts";
import { RESTORE_SINK_TYPES } from "./restore-types.ts";

// errId (the short, stable, opaque FNV-1a exception identifier for the operational log stream) is defined
// once in the dependency-free passkey-types.ts leaf and re-exported here so the restore modules that import
// it from this file keep working while every log stream emits the identical code for the same exception.
export { errId } from "./passkey-types.ts";

// BUFFERED_RESTORE_MAX_BYTES is the largest plaintext an R2 record may have and still take the
// BUFFERED restore path (restoreRecord -> atomic put). The buffered path has the STRONGEST integrity:
// the exact bytes that restoreRecord verified in memory (its whole-record SHA-384 checked against the
// signed manifest) are the bytes handed to R2 .put, which is ATOMIC (the object appears whole or not
// at all), so the landed object is provably the verified plaintext with no post-write readback needed.
// We keep that path for as much of the size range as is MEMORY-SAFE; only the genuinely-large tail
// streams (and the streamed tail is covered by the verify-on-readback below, so capability is the same
// across the whole range -- this constant only chooses WHICH path runs).
//
// MEMORY REASONING (a 128 MB Worker isolate). The buffered restoreRecord builds a per-segment parts[]
// list (sum = plaintextSize) and then concat()s them into one fresh buffer of plaintextSize while the
// parts are still live, so the decode peak is ~2x the value size; the value is then copied once more
// into a standalone ArrayBuffer for .put (toArrayBuffer). The dominant transient is therefore the ~2x
// concat peak. At 32 MiB that peak is ~64 MiB, leaving ~64 MiB of the 128 MB isolate for the runtime,
// the reader's working set and the put -- clear headroom. We deliberately do NOT push to ~100 MB
// (which at the 2x peak would be ~200 MB and OOM the isolate) or even to the top of the expected
// 32-48 MiB band (48 MiB -> ~96 MiB peak leaves only ~32 MiB, too tight). 32 MiB is the conservative
// choice with ~4x margin on the dominant peak; an R2 object past it streams + reads back, so nothing
// becomes unrecoverable, only the path changes. A sane production deployment leaves this at the 32 MiB
// default (below ~8 MiB every object buffers trivially, so there is no reason to lower it in production),
// but the value is overridable via RESTORE_BUFFERED_MAX_BYTES to any positive integer up to the 32 MiB
// CEILING. The override only ever LOWERS the ceiling (a test sets it small to force the always-safe
// streaming + readback path on a small object); the safety bound is the 32 MiB MAXIMUM (raising past it
// risks the 2x concat peak OOMing the isolate, which is why the clamp caps there). Lowering it is
// harmless because the streaming path it routes to is integrity-equivalent (verify-the-assembly +
// per-chunk auth + final hash, then the post-write readback), just less optimal for tiny objects.
const BUFFERED_RESTORE_MAX_BYTES_DEFAULT = 32 * 1024 * 1024; // 32 MiB
const BUFFERED_RESTORE_MAX_BYTES_CEILING = 32 * 1024 * 1024; // the hard safety cap; never buffer more

// bufferedRestoreMaxBytes resolves the live buffered ceiling from env. An absent value uses the 32 MiB
// default. A supplied value must be a positive integer and is clamped to the 32 MiB CEILING (the safety
// bound); an invalid/non-positive/over-ceiling value falls back to the default, mirroring the SCALE_* /
// SEAL_VERIFY_* knob discipline. The override is for LOWERING the ceiling (forcing the streaming path);
// it can never raise the buffered ceiling above the memory-safe maximum.
export function bufferedRestoreMaxBytes(env: Env): number {
  const raw = env.RESTORE_BUFFERED_MAX_BYTES;
  if (raw === undefined) return BUFFERED_RESTORE_MAX_BYTES_DEFAULT;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) return BUFFERED_RESTORE_MAX_BYTES_DEFAULT;
  if (n > BUFFERED_RESTORE_MAX_BYTES_CEILING) return BUFFERED_RESTORE_MAX_BYTES_DEFAULT;
  return n;
}

// bufferedRestoreMaxBytesInvalid reports whether the operator SET the knob and the engine could not use
// it, so the fall-back to the 32 MiB default is a SILENT override of an explicit instruction ("we set the knob
// and records still buffer"). It is the exact predicate the resolver falls back on, expressed once so the
// counter and the behaviour cannot drift, and it is deliberately a BOOLEAN over env: the unusable value itself
// is never carried anywhere. An ABSENT knob is the default, not a fault, and answers false.
//
// The over-ceiling case counts too, and it is the one worth stating: an operator RAISING the ceiling past the
// memory-safe maximum has their value discarded entirely, which is the opposite of what they intended.
export function bufferedRestoreMaxBytesInvalid(env: Env): boolean {
  const raw = env.RESTORE_BUFFERED_MAX_BYTES;
  if (raw === undefined) return false;
  const n = Number(raw);
  return !Number.isFinite(n) || !Number.isInteger(n) || n < 1 || n > BUFFERED_RESTORE_MAX_BYTES_CEILING;
}

// shouldStream decides whether a record takes the constant-memory streaming restore path: an R2
// record whose plaintext is larger than the buffered ceiling. Only R2 streams (KV is bounded; secrets
// and D1 are restored whole / out of band), and a packed record is single-segment and small so it
// never reaches the ceiling (restoreRecordStream refuses a packed shape as defence in depth).
// Centralised and given the ceiling so the verify pass and the write pass make the identical decision.
export function shouldStream(rec: ShardRecord, bufferedMaxBytes: number): boolean {
  return rec.sourceType === "r2" && rec.plaintextSize > bufferedMaxBytes;
}

// verifyRecordStreamingDiscard drives restoreRecordStream to a DISCARD sink: it pulls every
// decrypted, authenticated chunk and drops it, so the stream's full integrity chain runs (per-chunk
// AES-256-GCM auth, per-segment terminate-exactly, and the final whole-record SHA-384 checked in the
// stream's flush) WITHOUT ever holding the value in memory. It is the bounded-memory equivalent of
// the buffered "await run.restoreRecord(rec)" verify: it resolves only if every check passes and
// throws (the stream errors) on any failure. The bytes are never returned, logged or written.
export async function verifyRecordStreamingDiscard(run: Run, rec: ShardRecord): Promise<void> {
  const reader = run.restoreRecordStream(rec).getReader();
  try {
    for (;;) {
      const { done } = await reader.read();
      if (done) break;
      // value is intentionally dropped: this is a verify, not a materialise.
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

// verifyReadbackStreaming proves the bytes that actually LANDED in the live bucket. After the
// streamed apply writes a large R2 object, it reads the object BACK from the SAME sink (sink.
// getStreamForVerify -> the R2 binding's native streaming get), recomputes the whole-object SHA-384
// INCREMENTALLY (nobleSha384.create().update per chunk, never buffering the object), and returns the
// hex digest. This converts the guarantee from "we trusted the streamed write / FixedLengthStream /
// abort behaviour" to "the persisted object is byte-correct", a check that is independent of the write
// path. It is bounded-memory by construction (one chunk in flight + a 48-byte running digest). It does
// NOT compare here: the caller compares the returned hash to the signed rec.plaintextSha384 and decides
// pass/fail, so the comparison and the failure handling live in one place on the apply path. A missing
// object surfaces as a thrown error from getStreamForVerify (the caller treats it as a readback
// failure). Exported for the readback validator, which drives it against a real sink + fake binding.
export async function verifyReadbackStreaming(sink: RestoreSink, name: string): Promise<string> {
  const stream = await sink.getStreamForVerify(name);
  const digest = nobleSha384.create();
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.length > 0) digest.update(value); // incremental: the object is never held whole
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return hexEncode(digest.digest());
}

// SAMPLE_CAP bounds how many preview rows a dry-run returns when the caller gives no
// maxRecords, so a huge run does not return a huge plan.
export const SAMPLE_CAP = 50;

// MAX_IN_ACCOUNT_RESTORE_RECORDS bounds the in-account engine restore. The engine restore runs the
// WHOLE in-scope window synchronously in ONE Worker invocation with no slicing or resume, and each record
// costs ~3 subrequests on the apply path (verify, re-verify, write) plus the run-open overhead, so a large
// window trips the platform ~1000-subrequest / CPU cap mid-apply and half-overwrites live resources with
// no clean resume. The product stance is: bulk recovery runs OFFLINE via the downpipe CLI (no Worker
// limits); the in-account path is for small/targeted recoveries. This ceiling refuses an oversized restore
// BEFORE any write rather than failing partway. A caller wanting a bounded in-account apply passes an
// explicit maxRecords <= this.
export const MAX_IN_ACCOUNT_RESTORE_RECORDS = 200;
// MEDIA_MARKER_MAX bounds how large a media record can be and still POSSIBLY be a capture marker (a small
// JSON object). A media blob at or below it is decrypted to confirm it is real file bytes before a re-upload
// is planned; a larger one is real bytes by construction, so it is never decrypted just to check.
export const MEDIA_MARKER_MAX = 4096;

// inAccountTooLargeReason is the single honest message both the dry-run and the apply return when the
// in-scope window exceeds the in-account ceiling, so the two paths steer to the offline CLI with one voice.
export function inAccountTooLargeReason(n: number): string {
  return `this restore covers ${n} records, more than the in-account limit of ${MAX_IN_ACCOUNT_RESTORE_RECORDS}; recover the full run offline with the downpipe CLI (it runs on your machine with no Worker limits), or run a bounded in-account restore with maxRecords <= ${MAX_IN_ACCOUNT_RESTORE_RECORDS}`;
}

// d1GroupOfDataRecord is the d1GroupOf extractor the data callers hand inAccountWindow: a D1 data record's
// database NAME (its restore binding root, the all-or-nothing group key), or null for any non-D1 record
// (KV/R2/secrets, which window per-record and stay idempotent). Shared by the dry-run and the apply so both
// group D1 records identically. A D1 database is configured one-source-per-database, so its records share a
// single dbName and are contiguous in the plan.
export function d1GroupOfDataRecord(d: { rec: ShardRecord }): string | null {
  return d.rec.sourceType === "d1" ? d1DatabaseNameFromRecordName(d.rec.name) : null;
}

// inAccountWindow is the SINGLE source of truth for which in-account records one Worker invocation may
// touch. The in-account apply does three kinds of bounded work in this fixed order -- DATA records (KV/R2/
// D1 sinks), then cf-config surface re-applies, then media re-uploads -- and EVERY one of them costs
// subrequests on the live account (a data record ~3, a media re-upload ~2-3 upload+readback, a cf-config
// surface a live read+write). So the platform ~1000-subrequest/CPU cap is a budget over the COMBINED set,
// not over the data records alone: a restore with few/zero data records but many media or cf-config
// records would otherwise trip the cap mid-apply and half-complete with no clean resume.
//
// maxRecords is therefore a budget over the COMBINED total, spent in apply order: data first, then
// cf-config, then media. Each bucket gets the records the running budget can still afford, so a windowed
// restore proceeds in BOUNDED, RESUMABLE batches (re-run with the next window to continue) rather than
// half-completing. With no maxRecords the window is the whole set (the caller has already been refused if
// total > MAX_IN_ACCOUNT_RESTORE_RECORDS). total is the combined in-scope count (the number the ceiling
// check and the too-large reason use); outOfWindow is how many combined records the window left unrestored
// (drives windowed / complete:false / the "(window)" marker). The dry-run and the apply both call this so
// the verify pass, the write pass and the honesty signals all window the IDENTICAL combined set.
//
// ALL-OR-NOTHING D1 (windowed-d1-non-resumable-corruption): KV/R2/secrets writes are IDEMPOTENT, so a flat
// record-count window over them is safe to re-run from the start. A D1 database is NOT: it restores as a
// SEQUENCE (header with requireFreshTarget+CREATE, many row pages, schema) whose records must travel
// together, and RestoreRequest has only maxRecords (no offset/cursor), so a window that cut a D1 in half
// would write header+some rows, then on a re-run restart at record 0 and the header's requireFreshTarget
// would throw against the now-non-empty target (and the rows would double). The fix: never PARTIALLY apply
// a single D1 database in-account. The flat slice keeps KV/R2 windowing byte-for-byte unchanged; then any
// D1 database that is only PARTIALLY inside that flat slice is dropped from the applied dataWindow ENTIRELY
// (steered offline via the marker), so a re-run can never hit the non-empty-target throw. d1GroupOf returns
// the D1 database name for a non-resumable D1 data record (else null); the data callers pass it so the
// generic windower stays decoupled from ShardRecord. d1OutOfWindow is how many D1 records ended up outside
// the applied window (whether dropped here or simply beyond the flat budget); it drives the windowSkipped
// guidance so a D1 left unrestored is steered OFFLINE, never told to "re-run with a higher maxRecords".
export function inAccountWindow<D, C, M>(
  plan: D[],
  configPlan: C[],
  mediaPlan: M[],
  maxRecords: number | undefined,
  d1GroupOf?: (d: D) => string | null,
): { dataWindow: D[]; configWindow: C[]; mediaWindow: M[]; total: number; outOfWindow: number; d1OutOfWindow: number } {
  const total = plan.length + configPlan.length + mediaPlan.length;
  const budget = maxRecords && maxRecords >= 1 ? maxRecords : total;
  // The flat data slice: KV/R2 windowing is exactly as before. cf-config / media spend the budget LEFT by
  // the flat data slice (not by the post-drop applied window), so their windowing is also unchanged -- a
  // dropped partial D1 frees no budget for them, it is simply steered offline.
  const flatData = plan.slice(0, budget);
  const afterData = Math.max(0, budget - flatData.length);
  const configWindow = configPlan.slice(0, afterData);
  const afterConfig = Math.max(0, afterData - configWindow.length);
  const mediaWindow = mediaPlan.slice(0, afterConfig);

  let dataWindow = flatData;
  if (d1GroupOf) {
    // A D1 database's records are contiguous in the plan (archive order). Drop any D1 group that is only
    // partially inside the flat slice, by comparing its count in the whole plan to its count in the slice.
    const groupTotal = new Map<string, number>();
    for (const d of plan) {
      const g = d1GroupOf(d);
      if (g !== null) groupTotal.set(g, (groupTotal.get(g) ?? 0) + 1);
    }
    const groupInWindow = new Map<string, number>();
    for (const d of flatData) {
      const g = d1GroupOf(d);
      if (g !== null) groupInWindow.set(g, (groupInWindow.get(g) ?? 0) + 1);
    }
    const partial = new Set<string>();
    for (const [g, n] of groupInWindow) {
      if (n < (groupTotal.get(g) ?? 0)) partial.add(g);
    }
    if (partial.size > 0) {
      dataWindow = flatData.filter((d) => {
        const g = d1GroupOf(d);
        return g === null || !partial.has(g);
      });
    }
  }
  const windowed = dataWindow.length + configWindow.length + mediaWindow.length;
  // D1 records outside the APPLIED window: the whole-plan D1 count minus the D1 count actually applied. This
  // counts both a partial D1 dropped above AND any D1 wholly beyond the flat budget, so the guidance steers
  // every unrestored D1 offline.
  let d1OutOfWindow = 0;
  if (d1GroupOf) {
    const d1InPlan = plan.reduce((n, d) => n + (d1GroupOf(d) !== null ? 1 : 0), 0);
    const d1Applied = dataWindow.reduce((n, d) => n + (d1GroupOf(d) !== null ? 1 : 0), 0);
    d1OutOfWindow = d1InPlan - d1Applied;
  }
  return { dataWindow, configWindow, mediaWindow, total, outOfWindow: total - windowed, d1OutOfWindow };
}

// windowSkippedReason is the SINGLE honest message both the dry-run and the apply put in the "(window)"
// skipped marker when maxRecords left records unrestored. The default (idempotent KV/R2/cf-config/media
// remainder) can be continued by re-running with a higher maxRecords. But when a D1 database was left
// unrestored (d1OutOfWindow > 0), re-running with a higher maxRecords is NOT a safe instruction for it: an
// in-account D1 restore is NOT resumable (RestoreRequest has no cursor) and a large D1 may not even fit the
// in-account ceiling, so such a D1 was deliberately NOT partially applied and must be recovered offline.
// The message then names the offline path for the D1 and keeps the re-run option only for the idempotent
// remainder, so it never gives the impossible "re-run to finish the D1" advice the old single message did.
export function windowSkippedReason(outOfWindow: number, d1OutOfWindow: number): string {
  if (d1OutOfWindow > 0) {
    return `windowed restore: ${outOfWindow} record(s) beyond maxRecords were not restored. A D1 database that did not fully fit the window was NOT partially applied (an in-account D1 restore is not resumable); recover the full run offline with the downpipe CLI. Any remaining idempotent records (KV/R2/cf-config/media) can instead be continued by re-running with a higher maxRecords.`;
  }
  return `windowed restore: ${outOfWindow} record(s) beyond maxRecords were not restored; re-run with a higher maxRecords or recover the full run offline`;
}

// The verbatim break-glass message the drill returns, reused so the two recovery routes
// speak with one voice when there is no in-account read-back key.
export const BREAK_GLASS_REASON =
  "break-glass-only posture: no in-account read-back key. Exercise recovery offline with the break-glass key and the downpipe CLI.";

export const RESERVED_REASON = "target binding is reserved";

export interface Resolved {
  sink: RestoreSink;
  sample: RestoreSampleItem;
}

// guardTarget is the single reserved-binding choke point: every resolved write binding
// passes through it before a sink is constructed, mirroring buildAdapter's guard on the read
// side. It throws RESERVED_REASON so the caller maps it to the coarse client reason.
export function guardTarget(binding: string): string {
  if (RESERVED_BINDINGS.has(binding)) throw new Error(RESERVED_REASON);
  return binding;
}

// SECRETS_OUT_OF_BAND_REASON is the OUT-OF-BAND guidance for a Secrets Store record: the one class that
// used to carry the bare label "restore out of band" and so named neither its cause nor its remedy, while
// three documentation pages told customers it named both.
//
// Every clause is checked against what the engine and the offline reader actually do:
//   - "the binding is read-only at runtime" is the CAUSE, and it is a platform property, not a fault of this
//     restore. That is why an out-of-band secret never makes a run not-ok.
//   - "recover the value ... with the offline reader" is the only true answer to "where do I get the value",
//     and it is named rather than left implicit because an operator reading this is mid-recovery. The console
//     never displays a secret value, and the offline reader's file and env sinks are the one path that puts a
//     recovered value in front of a person. It does NOT say anything writes the secret back, and it must not:
//     there is no runtime write path, and the offline reader has no Secrets Store target either.
//   - "re-create the secret through the Cloudflare API or wrangler" is the REMEDY, and it is the operator's
//     deliberate action with the value they recovered, which is exactly how the docs describe it.
// It is a constant rather than a literal at the push site so the validators, the console fixtures and the API
// reference quote one string instead of four copies of it.
export const SECRETS_OUT_OF_BAND_REASON =
  "Secrets Store value, restore out of band: the binding is read-only at runtime, so there is no in-account write path; recover the value from this archive with the offline reader and your break-glass key, then re-create the secret through the Cloudflare API or wrangler";

// workersRestoreGuidance is the OUT-OF-BAND re-deploy guidance for a Workers script record (the
// reprovision honesty contract, a Worker is NEVER blind-redeployed from a backup, which could
// brick a live service). It is a pure function of the record NAME so the restore route and the
// validator share one source of truth; it returns text only, never reaches a resource, and (like
// the cf-config guidance) makes the snapshot's recoverability explicit while keeping restore
// operator-driven. A "/settings" record's secret VALUES were never captured, only a checklist of
// names/types, so the guidance says to re-provision them, never that the backup holds them.
export function workersRestoreGuidance(name: string): string {
  const how = name.endsWith("/settings")
    ? "re-create the bindings + secrets from the verified settings snapshot (secret VALUES were never captured, the checklist lists their names/types to re-provision)"
    : name.endsWith("/versions")
      ? "a version inventory only, informational; re-deploy from the script content record"
      : name.endsWith("/schedules")
        ? "re-create the cron triggers from the verified schedules snapshot (each entry's cron expression), so the re-deployed Worker keeps its schedule"
        : "re-deploy the script code from the verified content snapshot (wrangler deploy / the Workers API), then apply its settings record";
  return `Workers script, ${how}`;
}

// mediaRestoreGuidance explains why a media record is out of band. An uploadable blob with no edit-token
// context says how to enable the in-account re-upload; a metadata/caption/artifact record says it is
// inventory or (for artifact blobs) re-pushed via git, which is not a REST upload.
export function mediaRestoreGuidance(name: string, sourceType: string, mediaOn: boolean): string {
  if (sourceType === "artifacts") {
    return name.includes("/blob/")
      ? "Artifact Registry blob, re-push the repository via git (the verified blob is surfaced); a git push is not a REST upload, so it is not auto-restored"
      : "Artifact Registry inventory, re-create the namespace/repository from the verified snapshot, then git push";
  }
  const isImageBlob = sourceType === "images" && name.endsWith("/blob");
  const isVideo = sourceType === "stream" && name.endsWith("/video.mp4");
  if (isImageBlob || isVideo) {
    return mediaOn
      ? "media file, captured but not re-uploaded (the value was a capture marker, not file bytes)"
      : `${sourceType === "images" ? "Image" : "Video"} file, supply an edit-scoped Cloudflare token under Restore to re-upload it in-account (images keep their id; a video gets a new uid), or re-upload from the verified bytes`;
  }
  // metadata inventory, variant definitions, captions, truncation markers
  return `${sourceType} inventory/metadata, informational; re-create from the verified snapshot${sourceType === "stream" && name.includes("/captions/") ? " (re-attach the caption track after the video re-uploads)" : ""}`;
}

// resolveSink picks the live destination for one record, preferring in order: (1) the operator's
// explicit target override binding/name; (2) the actual attached SOURCE binding from sourceBindings
// (a `kv:<namespaceId>` / `r2:<bucketName>` / `d1:<dbName>` -> binding map built from the live downpipe
// configs) -- the attach binding name is operator-chosen (e.g. SRC_KV_uploads) and need NOT equal the
// convention, so without this a "restore to original bindings" looks for a binding that does not exist
// and every record skips with "target binding not present"; (3) the binding convention dual to
// buildAdapter (KV_<namespace> / R2_<bucket> / D1_<name>) as a last resort, against the recorded manifest
// names. It guards the binding and constructs the typed sink. It throws a coarse Error for an unsupported
// sink so the caller can record a skipped/failure reason. confirm is threaded to the D1 sink so a dry run
// constructs a sink that decodes and validates the backup body without writing. Exported so the
// workers-source validator can prove there is NO write sink for a "workers" record (it throws
// "unsupported sink for sourceType").
export function resolveSink(env: Env, rec: ShardRecord, target: RestoreRequest["target"], confirm: boolean, sourceBindings?: ReadonlyMap<string, string>, d1Restrict?: { database: string; tables: ReadonlySet<string> }): Resolved {
  if (!RESTORE_SINK_TYPES.has(rec.sourceType)) {
    throw new Error(`unsupported sink for sourceType ${rec.sourceType}`);
  }
  const sourceType = rec.sourceType as RestoreSinkType;
  if (sourceType === "kv") {
    const namespace = target?.namespaceId ?? rec.namespace ?? "";
    const binding = guardTarget(target?.binding ?? sourceBindings?.get(`kv:${namespace}`) ?? `KV_${namespace}`);
    const store = env[binding];
    if (!store) throw new Error(`source binding ${binding} is not present in the environment`);
    return {
      sink: new KVRestoreSink(store as KVNamespace, namespace),
      sample: { name: rec.name, sourceType, binding, ...(namespace ? { namespace } : {}), plaintextSize: rec.plaintextSize },
    };
  }
  if (sourceType === "r2") {
    const bucket = target?.bucketName ?? rec.bucket ?? "";
    const binding = guardTarget(target?.binding ?? sourceBindings?.get(`r2:${bucket}`) ?? `R2_${bucket}`);
    const store = env[binding];
    if (!store) throw new Error(`source binding ${binding} is not present in the environment`);
    return {
      sink: new R2RestoreSink(store as R2Bucket, bucket),
      sample: { name: rec.name, sourceType, binding, ...(bucket ? { bucket } : {}), plaintextSize: rec.plaintextSize },
    };
  }
  if (sourceType === "secrets") {
    // Secrets Store bindings are read-only at runtime, so a restore needs an explicitly
    // wired write path. None is wired here, so the sink refuses on put; the binding shown is
    // the override if the operator named one (still guarded), else the logical store.
    const binding = guardTarget(target?.binding ?? "SECRETS");
    const bound: BoundSecretSink[] = [{ name: rec.name, bindingVar: binding }];
    return {
      sink: new SecretsRestoreSink(bound),
      sample: { name: rec.name, sourceType, binding, plaintextSize: rec.plaintextSize },
    };
  }
  if (sourceType === "d1") {
    // D1 restore writes back through the live database binding (schema re-created, rows re-inserted
    // parameterised), so resolve and guard the binding exactly as KV/R2 do rather than handing bytes
    // to an out-of-band loader. A D1 database now backs up as a SEQUENCE of records (header, row
    // pages, schema) whose names are "<dbName>/..."; the binding is per DATABASE, so derive the
    // database name from the record name's first element (the legacy whole-dump record name is the
    // bare database name with no slash, so this is unchanged for it) and route every record of one
    // database to the same D1_<dbName> binding. The sink dispatches on the decoded body kind, not the
    // name, so all three kinds reconstruct the one database.
    const dbName = d1DatabaseNameFromRecordName(rec.name);
    const binding = guardTarget(target?.binding ?? sourceBindings?.get(`d1:${dbName}`) ?? `D1_${dbName}`);
    const store = env[binding];
    if (!store) throw new Error(`source binding ${binding} is not present in the environment`);
    // createOnly (D1 table-subset): restrict which tables the header creates for THIS database. The
    // restriction is per database, so it only binds when the record's database matches the selection.
    const restrict = d1Restrict !== undefined && d1Restrict.database === dbName ? d1Restrict.tables : undefined;
    return {
      sink: new D1RestoreSink(store as D1Database, dbName, !confirm, restrict),
      sample: { name: rec.name, sourceType, binding, plaintextSize: rec.plaintextSize },
    };
  }
  throw new Error(`unsupported sink for sourceType`);
}
