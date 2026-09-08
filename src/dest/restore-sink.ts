import type { RestoreSinkType } from "../admin/restore-types.ts";
import type { ShardRecord } from "../format/manifest.ts";
import { d1SchemaTargetTable } from "../sources/d1-fk.ts";
import { cellToBind, type D1Backup, type D1Cell, type D1TableDDL, decodeD1Record, quoteIdent } from "../sources/d1-format.ts";
import { toArrayBuffer } from "./buffer-utils.ts";
import { classifyD1Error, D1RestoreError, noteMetadataShed } from "./restore-fault.ts";
import { R2_MAX_SINGLE_PUT } from "./types.ts";

// isBigIntCell reports whether a decoded D1 cell is a tagged out-of-range integer ($int). Such a cell
// holds an int64 that real D1's bind() rejects as a JS bigint, so the D1 restore binds it as a decimal
// string under a CAST(? AS INTEGER) placeholder rather than handing cellToBind's bigint to bind().
function isBigIntCell(c: D1Cell): c is { $int: string } {
  return typeof c === "object" && c !== null && "$int" in c;
}

/**
 * The per-source restore descriptors a sink applies alongside the value (SPEC 6.2, 12.3): the KV
 * metadata and expiration, and the R2 HTTP and custom metadata, so a sink reconstructs a record at
 * full fidelity rather than value-only. Both fields are optional, so a caller with no descriptor is
 * unaffected.
 */
export interface RestorePutOptions {
  kv?: ShardRecord["kv"];
  r2?: ShardRecord["r2"];
}

/**
 * Thrown by a sink whose backing resource has NO native readback API, so the apply path can tell a
 * "this sink cannot read its writes back" case apart from a genuine readback FAILURE (a missing or
 * wrong object on a sink that DOES read back, i.e. R2). KV/Secrets/D1 throw this from
 * getStreamForVerify; the apply path catches it and labels the receipt buffered-no-readback (an
 * honest "no post-write readback was performed") rather than claiming a readback it could not do.
 * Any other error from getStreamForVerify (only R2 reaches that) is a real readback failure.
 */
export class ReadbackNotSupportedError extends Error {
  constructor(sourceType: RestoreSinkType) {
    super(`readback not supported for ${sourceType}; only the streamed R2 restore path reads back`);
    this.name = "ReadbackNotSupportedError";
  }
}

/**
 * Lifts the restore descriptors off a verified ShardRecord into the options a sink applies, so the
 * orchestrator can pass them to put() without reaching into the sink.
 *
 * @param rec - the verified shard record.
 * @returns the restore options carrying the record's kv and r2 descriptors, or undefined when it
 *   carries neither.
 */
export function putOptionsFromRecord(rec: ShardRecord): RestorePutOptions | undefined {
  if (!rec.kv && !rec.r2) return undefined;
  return { ...(rec.kv ? { kv: rec.kv } : {}), ...(rec.r2 ? { r2: rec.r2 } : {}) };
}

/**
 * The lead a live Workers KV binding requires on an ABSOLUTE expiration. KV rejects a put whose
 * expiration is not at least this many seconds ahead of the current epoch second, so an expiration
 * inside the window is not a value the binding will take, whatever the archive holds.
 */
export const KV_EXPIRATION_MIN_LEAD_SECONDS = 60;

/**
 * Reports whether a captured KV expiration is a real instant that the live binding will NO LONGER accept,
 * because it has passed (or is about to). This is the ordinary state of any backup older than the
 * namespace's TTLs, since a KV expiration is captured and reproduced as an absolute epoch second.
 *
 * It is the ONE definition of the rule: the sink calls it to decide what to drop, and the dry-run plan
 * calls it to warn about the same records BEFORE an operator confirms. A second copy of the arithmetic is
 * exactly how a preview and an apply come to disagree.
 *
 * A non-positive or non-numeric expiration is NOT lapsed by this test: that is the separate unusable case,
 * which the sink sheds under `kv-expiration`.
 *
 * @param expiration - the captured absolute expiration, in epoch seconds.
 * @param nowMs - the clock, injectable for a test.
 * @returns true when the value is a usable-shaped instant the binding would now refuse.
 */
export function kvExpirationLapsed(expiration: unknown, nowMs: number = Date.now()): boolean {
  if (typeof expiration !== "number" || !Number.isFinite(expiration) || expiration <= 0) return false;
  return expiration < Math.floor(nowMs / 1000) + KV_EXPIRATION_MIN_LEAD_SECONDS;
}

// A RestoreSink writes ONE recovered record back into a LIVE in-account resource. It is the
// write-back dual of SourceAdapter: a SourceAdapter reads records OUT of a live source; a
// RestoreSink writes a verified record back IN. A sink only ever writes. It never reads the
// archive, never holds a key, and for secrets never logs the plaintext, so the trust
// boundary stays in the verifying reader (restoreRecord checks the plaintext hash before a
// byte ever reaches a sink). Confused-deputy refusal of a reserved target binding is the
// orchestrator's job (one choke point), not the sink's, so a sink that exists is already
// pointed at an allowed binding.
/**
 * Writes one recovered record back into a live in-account resource, the write-back dual of a
 * SourceAdapter. A sink only ever writes; it never reads the archive, holds no key, and for secrets
 * never logs the plaintext, so the trust boundary stays in the verifying reader (the bytes have
 * already passed restoreRecord's plaintext-hash check). It exposes target() for the dry-run plan,
 * put() for a whole value, and putStream() for a large value (only R2 implements streaming).
 */
export interface RestoreSink {
  readonly sourceType: RestoreSinkType;
  // target() is the human-readable resolved write target (namespace id / bucket / store),
  // surfaced in the dry-run plan so an operator sees exactly where the bytes would land.
  target(): string;
  // put writes a whole value. The bytes have ALREADY passed restoreRecord's plaintext hash
  // check, so the sink does not re-verify; re-verifying here would only buy a second hash of
  // bytes the reader already vouched for. opts carries the record's restore descriptors so a
  // sink reconstructs the record at full fidelity (KV metadata + expiration, R2 HTTP + custom
  // metadata); it is optional, so a caller with no descriptor restores value-only as before.
  put(name: string, value: Uint8Array, opts?: RestorePutOptions): Promise<void>;
  // putStream writes a large value as a single streamed PUT. Only R2 implements it;
  // the others throw, because their values are bounded (KV) or restored whole (secrets, D1
  // dumps). opts carries the same restore descriptors as put(), so a streamed R2 object is
  // also restored at full fidelity. The R2 sink enforces R2's single-PUT ceiling
  // (R2_MAX_SINGLE_PUT) as defence in depth so a value too large for one PUT fails loudly
  // before a byte reaches the binding (the native R2 binding has no multipart API).
  // Note: with the constant-memory streaming restore (reader.restoreRecordStream), the body is a
  // ReadableStream that decrypts and authenticates the value chunk-by-chunk, so the whole value is
  // NEVER held in memory; this is what lifts the in-account restore ceiling from ~128 MB to R2's
  // single-PUT maximum.
  putStream(name: string, body: ReadableStream<Uint8Array>, size: number, opts?: RestorePutOptions): Promise<void>;
  // getStreamForVerify reads the JUST-WRITTEN object BACK as a ReadableStream, so the orchestrator
  // can re-hash the bytes that actually LANDED and prove them byte-correct against the signed manifest
  // hash (verify-on-readback), independent of how the streamed write behaved (FixedLengthStream /
  // abort). It is the readback dual of putStream and is implemented ONLY by the R2 sink: only the
  // large-R2 streamed path reads back. The other sinks (KV/secrets/D1) throw "readback not supported"
  // so a miswire is LOUD rather than a silent skip of the post-write check. A missing object throws,
  // which the caller treats as a readback failure (the object was expected to be present after the
  // write). The returned stream MUST be consumed and re-hashed incrementally; it is never buffered whole.
  getStreamForVerify(name: string): Promise<ReadableStream<Uint8Array>>;
  // schemaFilteredCount reports how many non-table schema objects (indexes / triggers / views) a table-SUBSET
  // D1 restore FILTERED OUT of the apply (G055). A subset restore silently drops the indexes and triggers of
  // the tables it did not create -- and an INSTEAD OF trigger with them -- so an app can break after a restore
  // that reported complete success. It is a DIAGNOSTIC accessor only (an integer, never DDL text or an object
  // name): the apply reads it after the write phase and carries the count on the restore receipt. OPTIONAL:
  // only the D1 sink implements it, and a full-schema restore always answers 0.
  schemaFilteredCount?(): number;
}

/**
 * Writes a recovered value back into a live Workers KV namespace, reconstructing the record's
 * metadata and expiration from its descriptor. It mirrors KVSource's constructor (the binding plus
 * the recorded namespace id). KV has no streamed-value API, so putStream throws.
 */
export class KVRestoreSink implements RestoreSink {
  readonly sourceType = "kv" as const;
  private kv: KVNamespace;
  private namespaceId: string;

  constructor(kv: KVNamespace, namespaceId: string) {
    this.kv = kv;
    this.namespaceId = namespaceId;
  }

  target(): string {
    return this.namespaceId;
  }

  async put(name: string, value: Uint8Array, opts?: RestorePutOptions): Promise<void> {
    // Reconstruct the metadata and expiration the record carried, so a restore is full-fidelity
    // rather than value-only (SPEC 6.2). Both are omitted when absent, so a put with no
    // descriptor is exactly the bare put it was before. The expiration is an absolute Unix
    // epoch second, matching what the source captured from the list key.
    const putOpts: KVNamespacePutOptions = {};
    if (opts?.kv?.metadata !== undefined) putOpts.metadata = opts.kv.metadata;
    const expiration = opts?.kv?.expiration;
    // A LAPSED expiration is checked FIRST, because it is a well-formed positive number and would otherwise
    // pass straight into the put and be refused by the binding. It is the ordinary state of a backup older
    // than the namespace's TTLs: the archived instant has simply gone by. The value, the metadata and the key
    // are all still wanted, so the key is restored WITHOUT the expiration rather than failed outright -- a
    // backup product that answers "restore my year-old backup" with a per-key destination error has lost the
    // customer's data on its most ordinary operation, and there is no in-product path for them to get it back.
    // Clamping the expiration forward instead would INVENT a TTL the customer never chose, so it is dropped
    // and counted. The key now never expires until a new TTL is set, which is a real loss of fidelity: it is
    // named on the receipt through the shed tally, and the dry-run plan warns about the same records before
    // the operator confirms (runDryRun's fidelityWarnings), so this is never learned after the fact.
    if (kvExpirationLapsed(expiration)) noteMetadataShed("kv-expiration-lapsed");
    else if (typeof expiration === "number" && expiration > 0) putOpts.expiration = expiration;
    // G348: the descriptor CARRIED an expiration and it is unusable (not a number, non-positive, NaN): the key
    // is restored with NO TTL and will never expire, and the receipt used to claim full fidelity anyway. Count
    // the shed at the drop site (a closed field kind; the unusable VALUE is never carried) so support can tell
    // the customer to re-set the TTLs on evidence rather than on a guess.
    else if (expiration !== undefined) noteMetadataShed("kv-expiration");
    // KV.put accepts an ArrayBuffer; hand it a standalone slice rather than a view over a
    // possibly-larger pooled buffer, so a subarray can never ship trailing bytes.
    if (Object.keys(putOpts).length > 0) await this.kv.put(name, toArrayBuffer(value), putOpts);
    else await this.kv.put(name, toArrayBuffer(value));
  }

  putStream(_name: string, _body: ReadableStream<Uint8Array>, _size: number, _opts?: RestorePutOptions): Promise<never> {
    // KV values are capped at 25 MiB, so a whole-buffer put always fits; there is no
    // streamed-value API to stream into.
    throw new Error("KV does not support streamed values; KV values are bounded");
  }

  getStreamForVerify(_name: string): Promise<never> {
    // KV has no native streaming get the apply path can re-hash, so it cannot read its own writes back.
    // Throw the typed not-supported error so the apply path labels the receipt buffered-no-readback (an
    // honest "no post-write readback") rather than claiming a readback it did not perform.
    throw new ReadbackNotSupportedError(this.sourceType);
  }
}

/**
 * Writes a recovered value back into a live R2 bucket, reconstructing the object's HTTP and custom
 * metadata from its descriptor. It mirrors R2Source's constructor (the binding plus the recorded
 * bucket name) and is the only sink with a real streamed-write path, since R2.put takes a
 * ReadableStream directly.
 */
export class R2RestoreSink implements RestoreSink {
  readonly sourceType = "r2" as const;
  private r2: R2Bucket;
  private bucketName: string;

  constructor(r2: R2Bucket, bucketName: string) {
    this.r2 = r2;
    this.bucketName = bucketName;
  }

  target(): string {
    return this.bucketName;
  }

  async put(name: string, value: Uint8Array, opts?: RestorePutOptions): Promise<void> {
    const putOpts = r2PutOptions(opts);
    if (putOpts) await this.r2.put(name, toArrayBuffer(value), putOpts);
    else await this.r2.put(name, toArrayBuffer(value));
  }

  async putStream(name: string, body: ReadableStream<Uint8Array>, size: number, opts?: RestorePutOptions): Promise<void> {
    // Defence in depth: the in-account streaming restore decrypts the value chunk-by-chunk and
    // streams it into a SINGLE R2 PUT, so the binding ceiling is R2's single-PUT maximum
    // (R2_MAX_SINGLE_PUT, ~4.995 GiB), NOT the 1 GiB per-segment plaintext ceiling: a value chained
    // across many >1 GiB segments still restores in one streamed PUT as long as the whole value fits
    // under this. The native R2Bucket binding has no multipart API (its only write is .put), so a
    // value past this ceiling cannot be split into a multi-part upload here. This guard makes such a
    // value fail loudly at the sink rather than streaming an unbounded body into a put that R2 will
    // reject.
    if (size > R2_MAX_SINGLE_PUT) {
      // A value larger than R2's single-PUT maximum was faithfully CHAINED across segments on backup and
      // IS fully recoverable -- OFFLINE, via the downpipe CLI (it runs on a real machine with no Worker
      // memory/put limits and can assemble an object of any size). The in-account engine path streams the
      // value into ONE R2 PUT, which R2 caps at ~4.995 GiB, so it cannot land an object past that ceiling;
      // steer the operator to the offline CLI rather than imply the object is unrecoverable.
      throw new Error(`restore of ${name} is too large for the in-account path; recover it offline with the downpipe CLI (it is chained across segments and fully recoverable there)`);
    }
    // R2 streams the body server-side from a single put. The descriptor restores the
    // object's metadata on the streamed path too, so a large object comes back with its
    // content type and custom metadata, not value-only.
    //
    // A live R2 binding accepts a ReadableStream body ONLY when its length is known. The restore
    // stream emits the object's PLAINTEXT, so the content length is exactly `size` (the value byte
    // count) -- NOT a sealed/framed length, since the sink stores the decrypted value, not a .seg
    // container. Pipe through a FixedLengthStream sized to `size` so the binding has the length up
    // front while the body stays a stream (never buffered whole). The in-memory test doubles do not
    // require a length, so a runtime without FixedLengthStream passes the stream through raw.
    const putOpts = r2PutOptions(opts);
    if (typeof FixedLengthStream === "function") {
      const fixed = new FixedLengthStream(size);
      // Pipe without awaiting before the put: the binding drains the readable side while the restore
      // stream fills the writable side; awaiting both completes the transfer. A decrypt/verify error
      // in the restore stream aborts the pipe, which aborts the put, so a failed verification never
      // commits a partial object.
      const pump = body.pipeTo(fixed.writable);
      const put = putOpts ? this.r2.put(name, fixed.readable, putOpts) : this.r2.put(name, fixed.readable);
      await Promise.all([put, pump]);
      return;
    }
    if (putOpts) await this.r2.put(name, body, putOpts);
    else await this.r2.put(name, body);
  }

  // getStreamForVerify reads the object BACK from the SAME live bucket as a body stream, so the
  // orchestrator can recompute its SHA-384 from the bytes that actually LANDED (verify-on-readback)
  // rather than trusting the streamed write/abort. It returns r2.get(name).body, the binding's native
  // streaming read, so the readback never materialises the object whole (the caller re-hashes it
  // chunk-by-chunk). A missing object (get returns null, or a null body) throws so the caller records
  // a post-write readback FAILURE for that record (it was written but cannot be read back / verified),
  // never a silent pass. This is the only readback path; KV/secrets/D1 do not stream and refuse it.
  async getStreamForVerify(name: string): Promise<ReadableStream<Uint8Array>> {
    const obj = await this.r2.get(name);
    // G086: these two cases used to coarsen into ONE reason, and they are not the same fault. An ABSENT object
    // means the bucket accepted the write and does not have it (the write was eaten); a present object with NO
    // BODY means a store or proxy is stripping the payload on reads. The engine's own literals below are what the
    // restore-fault ring's classifier (admin/diag-records.ts classifyRestoreFaultClass) keys the closed classes
    // readback-absent / readback-bodyless on, so the distinction survives the coarsening.
    if (obj === null) throw new Error(`restored object ${name} was absent on read-back (the bucket accepted the write and does not hold it)`);
    if (!obj.body) throw new Error(`restored object ${name} carried no body on read-back (the store returned a bodyless object)`);
    return obj.body;
  }
}

/**
 * A bound secret the engine can write at runtime: its name, an optional write path, and the
 * optional binding variable. Secrets Store bindings expose get() only, so the write path must be
 * supplied explicitly by the operator; with no put, restore of that secret is refused loudly rather
 * than silently skipped.
 */
export interface BoundSecretSink {
  name: string;
  put?: (value: string) => Promise<void>;
  bindingVar?: string;
}

/**
 * unwiredSecretSinks counts the bound secrets that have NO runtime write path (G208). Secrets Store bindings are
 * read-only at runtime, so a secret whose operator never wired a `put` CANNOT be restored in-account -- and today
 * that is discovered DURING the disaster, on the restore receipt, when it is far too late to do anything about it.
 *
 * PURE and DERIVABLE, exactly like dest/config-anomalies.ts classifyEnvDestAnomalies: the pack can call this at
 * build time from the same bound-secret list the restore path would use, so the posture needs no write, cannot be
 * dropped by an unavailable DO, and cannot drift from the refusal it describes.
 *
 * NO-CUSTODY: it returns COUNTS. A secret's NAME is a customer label and never rides in the standing posture.
 *
 * @param sinks - the bound secret sinks.
 * @returns {bound, unwired}: how many secrets are bound, and how many of them cannot be restored in-account.
 */
export function unwiredSecretSinks(sinks: readonly BoundSecretSink[]): { bound: number; unwired: number } {
  return { bound: sinks.length, unwired: sinks.filter((s) => typeof s.put !== "function").length };
}

/**
 * Writes recovered secrets back through their operator-supplied write paths. It looks up the bound
 * sink by name and refuses (rather than pretends) when no write path was wired. The plaintext lives
 * in isolate memory only for the put call and is never logged or persisted; putStream throws, as
 * secrets are restored whole.
 *
 * Secrets Store bindings are READ-ONLY at runtime, so the write path cannot come from the binding: it
 * is a put callback the operator wires per secret. A secret bound without one cannot be restored in
 * account at all, and put throws saying so rather than reporting a restore that did not happen.
 * unwiredSecretSinks counts that condition ahead of time, so it is known before the disaster.
 *
 * getStreamForVerify throws the typed not-supported error, since a written secret cannot be read back
 * to re-hash; the apply then labels the receipt buffered-no-readback rather than claiming a check it
 * could not perform.
 */
export class SecretsRestoreSink implements RestoreSink {
  readonly sourceType = "secrets" as const;
  private sinks: BoundSecretSink[];

  constructor(sinks: BoundSecretSink[]) {
    this.sinks = sinks;
  }

  target(): string {
    return `secrets(${this.sinks.length} bound)`;
  }

  // _opts is declared to match the RestoreSink interface but ignored: a secret has no r2/kv descriptor,
  // so RestorePutOptions never applies to this sink type. The underscore prefix signals the discard.
  async put(name: string, value: Uint8Array, _opts?: RestorePutOptions): Promise<void> {
    const s = this.sinks.find((x) => x.name === name);
    if (!s) throw new Error(`no restore sink bound for secret ${name}`);
    // No write path means the operator did not wire one; refuse rather than pretend.
    if (!s.put) {
      throw new Error(`secret ${name} has no runtime write path; restore it out of band (Secrets Store bindings are read-only at runtime)`);
    }
    // The plaintext lives in isolate memory only for this call and is never logged or
    // persisted, matching the source side's contract.
    await s.put(new TextDecoder().decode(value));
  }

  putStream(_name: string, _body: ReadableStream<Uint8Array>, _size: number, _opts?: RestorePutOptions): Promise<never> {
    throw new Error("secrets are restored whole, not streamed");
  }

  getStreamForVerify(_name: string): Promise<never> {
    // Secrets are written through an operator-supplied put path (Secrets Store bindings are read-only at
    // runtime), so there is no readback API to re-hash. Throw the typed not-supported error so the apply
    // path labels the receipt buffered-no-readback rather than claiming a readback it could not do.
    throw new ReadbackNotSupportedError(this.sourceType);
  }
}

// How many statements go into one db.batch() call. D1.batch() runs its statements as a single
// implicit transaction (atomic: all or nothing), so each batch is individually atomic. A whole
// table, or a whole schema, in one batch can blow the per-call statement/size limit, so a large
// set is split into bounded batches. Atomicity is therefore PER BATCH, not across the whole
// restore: a schema with more than D1_INSERT_BATCH tables, or a table larger than the batch
// size, spans several batches, so a fault part way leaves a partially-loaded database. That is
// why the contract is "restore into a fresh, empty database" and a failure is reported so the
// operator drops the target and retries.
const D1_INSERT_BATCH = 50;

// D1RestoreSink replays a D1 backup (d1-format.ts) back into a LIVE target D1 database binding: it
// re-creates the schema and re-inserts every row with PARAMETERISED statements (the row values are
// bound, never interpolated, so data can never be SQL), inside db.batch() transactions so each batch
// loads atomically. The engine performs the restore in account, because the body it stores is a
// schema-plus-rows document the binding can replay (a binary dump could not be).
//
// It accepts BOTH record shapes, dispatching on decodeD1Record(value).kind:
//   - "full"  (legacy whole-database body): the original apply -- fresh-target check, then create
//             every table, insert every table's rows, apply the non-table schema -- byte-unchanged,
//             so an archive written before resumability restores exactly as before.
//   - "header" (resumable, FIRST per-page record): the fresh-target check (the ONLY kind that runs
//             it, so the whole database's fresh-target guarantee rides the header) then CREATE every
//             table. A dirty retry fails here, before any row.
//   - "rows"  (resumable, MANY per-page records): INSERT the page's rows into the named table (which
//             the header already created), parameterised and batched. No fresh-check (the table
//             exists). A write fault here surfaces as the D1 partial-apply reason.
//   - "schema" (resumable, LAST per-page record): apply the CREATE INDEX/TRIGGER/VIEW objects.
// The resumable records arrive in archive order (header, rows..., schema), so the per-record
// dispatch reconstructs the database exactly as the whole-body apply does, one record at a time.
//
// dryRun makes the sink a no-op that still decodes and validates each body, so an operator can prove
// a D1 record would replay cleanly without writing. The orchestrator already withholds put() on a
// dry run; carrying the flag here is defence in depth and lets the round-trip validator assert "dry
// run wrote nothing" at the sink itself.
/**
 * Replays a D1 backup back into a live target D1 database. It accepts the legacy whole-database body
 * and the three resumable per-page record kinds (header, rows, schema), dispatching on the decoded
 * kind: it re-creates the schema and re-inserts every row with parameterised statements (row values
 * are bound, never interpolated) inside db.batch() transactions, so each batch is atomic. Atomicity
 * is per batch, not across the whole restore, so the contract is to restore into a fresh, empty
 * database and drop-and-retry on failure; the fresh-target check runs once, on the header (or the
 * whole-body apply). A dryRun sink decodes and validates but writes nothing; putStream throws, as D1
 * backups are restored whole.
 */
export class D1RestoreSink implements RestoreSink {
  readonly sourceType = "d1" as const;
  private db: D1Database;
  private name: string;
  private dryRun: boolean;
  // restrict is the createOnly (D1 table-subset) allow-list: the LOWER-CASED names of the only tables to
  // CREATE. When set, applyHeader creates just these tables (a minimal extract) and applySchema drops the
  // indexes/triggers of any other table (whose CREATE would error on the absent table); views are kept.
  // Undefined (the default) creates every table in the header -- the full-schema behaviour is unchanged.
  private restrict: ReadonlySet<string> | undefined;
  // G055: how many non-table schema objects (indexes / triggers / views) a table-SUBSET restore FILTERED OUT.
  // A subset restore silently drops the indexes and triggers of the tables it did not create, so an app can break
  // after a restore that reported complete success. A COUNT only: no DDL text, no object name.
  private schemaObjectsFiltered = 0;

  /** schemaFilteredCount is the standing count of schema objects this subset restore dropped (G055). Read by the
   * restore orchestrator for the receipt; a full-schema restore is always 0. */
  schemaFilteredCount(): number {
    return this.schemaObjectsFiltered;
  }

  constructor(db: D1Database, name: string, dryRun: boolean, restrict?: ReadonlySet<string>) {
    this.db = db;
    this.name = name;
    this.dryRun = dryRun;
    this.restrict = restrict;
  }

  target(): string {
    return `d1:${this.name}`;
  }

  // _opts is declared to match the RestoreSink interface but ignored: a D1 record carries no r2/kv
  // descriptor, so RestorePutOptions is always inapplicable here. The underscore prefix signals the discard.
  async put(_name: string, value: Uint8Array, _opts?: RestorePutOptions): Promise<void> {
    // Decode and shape-check first so a malformed/foreign body fails before any statement is built.
    // The bytes already passed the archive plaintext-hash check, so this is a shape guard, not a
    // trust boundary. Dispatch on the decoded kind (legacy whole-body, or one of the three
    // resumable per-page records).
    const record = decodeD1Record(value);
    switch (record.kind) {
      case "full":
        await this.applyFull(record.body);
        return;
      case "header":
        await this.applyHeader(record.tables);
        return;
      case "rows":
        await this.applyRows(record.table, record.columns, record.rows);
        return;
      case "schema":
        await this.applySchema(record.schema);
        return;
    }
  }

  // applyFull is the legacy whole-database apply, byte-behaviour unchanged: the fresh-target check,
  // then create every table, insert every table's rows, then the non-table schema.
  private async applyFull(backup: D1Backup): Promise<void> {
    if (this.dryRun) return; // verified replayable; write nothing
    await this.requireFreshTarget();
    // Phase 1: create the tables before any row (bounded batches, atomic per batch) so the rows that
    // follow always have a table to land in. CREATE TABLE errors on a name that already exists,
    // surfacing rather than silently doubling data. The createOnly `restrict` never reaches a legacy
    // whole-dump body -- resolveD1TableScope refuses table-subset restore without a per-table header, so a
    // restrict-bearing sink never receives a "full" record -- hence applyFull creates every table.
    await this.runBatches(backup.tables.map((t) => this.db.prepare(t.sql)));
    for (const table of backup.tables) {
      await this.insertRows(table.name, table.columns, table.rows);
    }
    // Phase 2: apply the non-table schema after every row is in, so a trigger never fires on a load
    // row and an index is built once over the final data rather than maintained row by row.
    await this.applySchema(backup.schema);
  }

  // applyHeader runs the fresh-target check ONCE (the only kind that does, so the whole database's
  // fresh-target guarantee rides this first record -- a dirty retry fails here, before any row) then
  // creates every table. The rows records that follow append into these tables.
  private async applyHeader(tables: D1TableDDL[]): Promise<void> {
    if (this.dryRun) return; // verified replayable; write nothing
    await this.requireFreshTarget();
    // createOnly: create ONLY the selected tables (a minimal extract). A selected table's FK to a
    // now-absent table stays a dangling FK -- SQLite accepts it with foreign_keys off (the restore never
    // enables it), and the Stage 1 dependency lint already warns the operator. Default: create every table.
    const create = this.restrict === undefined ? tables : tables.filter((t) => this.restrict!.has(t.name.toLowerCase()));
    await this.runBatches(create.map((t) => this.db.prepare(t.sql)));
  }

  // applyRows inserts one page's rows into the named table (the header already created it), so it
  // runs NO fresh-target check. A write fault propagates; the orchestrator maps a d1 write fault to
  // the partial-apply reason (drop the target and retry into a fresh database).
  private async applyRows(table: string, columns: string[], rows: D1Cell[][]): Promise<void> {
    if (this.dryRun) return; // verified replayable; write nothing
    await this.insertRows(table, columns, rows);
  }

  // applySchema applies the non-table schema (CREATE INDEX/TRIGGER/VIEW) in bounded batches. Shared
  // by the whole-body apply (its Phase 2) and the resumable schema record (the last per-page record).
  private async applySchema(schema: string[]): Promise<void> {
    if (this.dryRun) return; // verified replayable; write nothing
    // createOnly: drop the indexes/triggers of tables that were not created (their CREATE would error on
    // the absent table); keep views (SQLite resolves a view's tables lazily) and keep everything when no
    // restriction is set. Known fidelity limit: an INSTEAD OF trigger's target is a VIEW, never in the
    // table-only restrict set, so it is dropped -- a rare, SAFE loss (never an apply failure; the view
    // still applies, it just loses its write path), not worth threading a separate view-name set for.
    const keep = this.restrict === undefined
      ? schema
      : schema.filter((sql) => {
          const t = d1SchemaTargetTable(sql);
          return t === null || this.restrict!.has(t.toLowerCase());
        });
    // G055: a table-SUBSET restore silently DROPS the indexes and triggers of the tables it did not create (and,
    // as the note above records, a view's INSTEAD OF trigger with them) -- so an app can break after a restore
    // that reported complete success, with nothing anywhere saying anything was filtered. The filtering is
    // unchanged; the COUNT is now observable (schemaObjectsFiltered), and it carries no DDL text and no name.
    this.schemaObjectsFiltered += schema.length - keep.length;
    await this.runBatches(keep.map((sql) => this.db.prepare(sql)));
  }

  // requireFreshTarget enforces the fresh-database contract (restore-d1-partial-apply-corruption):
  // D1's only transaction primitive is the per-batch db.batch(), so a multi-batch load is NOT
  // globally atomic; replaying into a non-empty target would double rows or collide, and a fault
  // part way leaves a partially-loaded database. Refuse a target that already holds user tables with
  // a clear, structured reason PROACTIVELY -- before any CREATE -- instead of discovering it via a
  // mid-load CREATE error (which is exactly the partial-apply corruption). After a failed load the
  // operator drops the target; a fresh DB then passes this check and the retry is clean. With the
  // resumable records this runs ONCE, on the header (the first record), so a dirty retry fails before
  // any row is inserted, giving the whole database the same fresh-target guarantee the whole-body
  // apply had. sqlite_* and _cf_* are SQLite/D1 internals (mirrors d1.ts isInternalTable), never counted.
  private async requireFreshTarget(): Promise<void> {
    const tablesRes = await this.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all<{ name: string }>();
    const userTables = (tablesRes.results ?? []).filter((r) => typeof r.name === "string" && !r.name.startsWith("sqlite_") && !r.name.startsWith("_cf_"));
    if (userTables.length > 0) {
      // G055: "restore keeps refusing 'target not empty'" gave support NOTHING to act on -- not even how many
      // tables are in the way. The refusal is unchanged; it now carries the RESIDUAL TABLE COUNT (a clamped int),
      // so the operator can be told what they are about to drop. Table NAMES are the customer's own schema labels
      // (the incompleteIds redaction class) and are deliberately NOT carried here: the count is what the remedy
      // turns on, and a count cannot leak a schema.
      throw new D1RestoreError("target-not-empty", "D1 restore target is not empty; restore requires a fresh database (drop the target and retry into an empty database)", { residualTableCount: userTables.length });
    }
  }

  // insertRows writes one table's rows with a single prepared, parameterised INSERT reused per row
  // via bind(). The column names are quoted identifiers (they cannot be bound); the VALUES are all
  // placeholders, so no row value is ever part of the SQL text. Shared by the whole-body apply and
  // each resumable rows record.
  private async insertRows(table: string, columns: string[], rows: D1Cell[][]): Promise<void> {
    if (rows.length === 0) return;
    const cols = columns.map(quoteIdent).join(", ");
    // A tagged big-integer ($int) cell carries an int64 that real D1 will NOT accept as a bind value
    // (it throws "D1_TYPE_ERROR: Type 'bigint' not supported"). Bind it as its decimal STRING and wrap
    // THAT placeholder in CAST(? AS INTEGER), so SQLite stores it as an integer regardless of the column's
    // affinity (a bare string bound to a none or BLOB affinity column would otherwise be kept as TEXT,
    // changing the value's storage class). Which columns hold a $int can differ row to row (SQLite is
    // dynamically typed), so a prepared statement is cached per placeholder pattern; a row with no $int
    // reuses one all-placeholder statement (the original fast path), and row order is preserved so the
    // restored rowid sequence matches the source read order. Values are still only ever bound, never
    // interpolated into SQL text, so a cell can never be SQL.
    const stmtByPattern = new Map<string, D1PreparedStatement>();
    const bound = rows.map((row) => {
      const pattern = row.map((c) => (isBigIntCell(c) ? "CAST(? AS INTEGER)" : "?")).join(", ");
      let stmt = stmtByPattern.get(pattern);
      if (stmt === undefined) {
        stmt = this.db.prepare(`INSERT INTO ${quoteIdent(table)} (${cols}) VALUES (${pattern})`);
        stmtByPattern.set(pattern, stmt);
      }
      return stmt.bind(...row.map((c) => (isBigIntCell(c) ? c.$int : cellToBind(c))));
    });
    await this.runBatches(bound);
  }

  // runBatches submits prepared statements in bounded atomic batches. An empty list is a
  // no-op. D1.batch() applies each batch in one transaction, so a fault rolls that batch back
  // rather than leaving a half-applied table; the error then propagates to the orchestrator,
  // which records the record as a destination write failure.
  private async runBatches(stmts: D1PreparedStatement[]): Promise<void> {
    const total = Math.ceil(stmts.length / D1_INSERT_BATCH);
    for (let i = 0; i < stmts.length; i += D1_INSERT_BATCH) {
      const index = Math.floor(i / D1_INSERT_BATCH);
      try {
        await this.db.batch(stmts.slice(i, i + D1_INSERT_BATCH));
      } catch (e) {
        // G055: a D1 restore is applied over several NON-ATOMIC batches, so a mid-apply fault leaves a
        // PARTIALLY-LOADED database -- and the receipt said only "partial restore", never WHERE it stopped or
        // WHY. failedBatchIndex/batchTotal LOCALISE the fault (a fault at batch 0 of 900 is a schema/type
        // problem; at 899 of 900 it is a size or constraint problem), and d1ErrorClass names the fault in a
        // CLOSED vocabulary derived from D1's own error tokens. The SQLite message -- which embeds table names,
        // column names and, on a constraint violation, ROW VALUES -- is read ONLY to select the enum and is never
        // carried. The throw is otherwise unchanged: the orchestrator still records a partial apply.
        throw new D1RestoreError(classifyD1Error(e), `partial restore: the D1 apply failed at batch ${index + 1} of ${total}`, { failedBatchIndex: index, batchTotal: total });
      }
    }
  }

  putStream(_name: string, _body: ReadableStream<Uint8Array>, _size: number, _opts?: RestorePutOptions): Promise<never> {
    throw new Error("D1 backups are restored whole, not streamed");
  }

  getStreamForVerify(_name: string): Promise<never> {
    // A D1 restore replays a schema-plus-rows document over several NON-ATOMIC batches, not a single
    // opaque object, so there is nothing to re-read and re-hash. Throw the typed not-supported error so
    // the apply path labels the receipt buffered-no-readback rather than claiming a readback it cannot do.
    throw new ReadbackNotSupportedError(this.sourceType);
  }
}

// r2PutOptions rebuilds the R2PutOptions metadata an object was stored with from its restore
// descriptor (SPEC 6.2), so a restored object carries its content type, cache headers and
// custom metadata. The HTTP metadata was normalised to a string map on capture (a Date such
// as cacheExpiry was rendered to an ISO string so it could canonicalise); this converts
// cacheExpiry back to a Date, the type the binding's R2HTTPMetadata expects. It returns
// undefined when the record carried no R2 metadata, so the sink falls back to a bare put.
function r2PutOptions(opts?: RestorePutOptions): R2PutOptions | undefined {
  const r2 = opts?.r2;
  if (!r2) return undefined;
  const put: R2PutOptions = {};
  if (r2.httpMetadata && Object.keys(r2.httpMetadata).length > 0) {
    const h = r2.httpMetadata;
    const http: R2HTTPMetadata = {};
    if (typeof h.contentType === "string") http.contentType = h.contentType;
    if (typeof h.contentLanguage === "string") http.contentLanguage = h.contentLanguage;
    if (typeof h.contentDisposition === "string") http.contentDisposition = h.contentDisposition;
    if (typeof h.contentEncoding === "string") http.contentEncoding = h.contentEncoding;
    if (typeof h.cacheControl === "string") http.cacheControl = h.cacheControl;
    // cacheExpiry was stored as an ISO string; rebuild the Date the binding expects. A value
    // that does not parse is dropped rather than written as Invalid Date.
    if (typeof h.cacheExpiry === "string") {
      const when = new Date(h.cacheExpiry);
      if (!Number.isNaN(when.getTime())) http.cacheExpiry = when;
      // G348: the stored cacheExpiry did not parse, so the object is restored WITHOUT it and behaves
      // differently at the edge -- silently, behind a receipt that claims the record restored. Count the shed
      // (the closed field kind only; the unparseable value is never carried).
      else noteMetadataShed("r2-cache-expiry");
    }
    if (Object.keys(http).length > 0) put.httpMetadata = http;
  }
  if (r2.customMetadata && Object.keys(r2.customMetadata).length > 0) put.customMetadata = { ...r2.customMetadata };
  return Object.keys(put).length > 0 ? put : undefined;
}
