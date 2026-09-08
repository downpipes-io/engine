// Source adapter unit tests for R2Source, SecretsSource, and D1Source.
//
// Tests the real adapter code imported from src/sources/. All external I/O
// (R2 bucket, D1 database, secret get() calls) is replaced with in-memory doubles.
//
// Coverage:
//   R2Source   - small object (buffered path, size < STREAM_THRESHOLD)
//   R2Source   - large object crossing the streaming threshold (stream path, yields a ChunkSource)
//   R2Source   - list pagination via cursor (two pages, limit simulated)
//   R2Source   - selector include/exclude filtering
//   R2Source   - estimate() derives counts and bytes from list metadata only
//   SecretsSource - per-binding get: value round-trips correctly
//   SecretsSource - zero secrets: crawl yields nothing
//   SecretsSource - selector include/exclude scoping filters the secret list
//   SecretsSource - record carries name (never value): no plaintext leaks into SourceRecord fields
//   SecretsSource - estimate() returns bytes=-1 (never reads a value)
//   D1Source   - normal export yields header + rows-pages + schema (per-page resumable sequence)
//   D1Source   - a single page exceeding the per-page byte cap is rejected (page guard fires mid-stream)
//   D1Source   - the whole-dump cap (D1_EXPORT_SIZE_LIMIT) is range-checked only, not exercised end-to-end
//
// Run: node test/validate-sources.ts

import { R2Source, STREAM_THRESHOLD } from "../src/sources/r2.ts";
import { SecretsSource, type BoundSecret } from "../src/sources/secrets.ts";
import { D1Source, D1_EXPORT_SIZE_LIMIT, D1_PAGE_BYTE_LIMIT, D1_ROWS_PER_PAGE, d1DatabaseNameFromRecordName } from "../src/sources/d1.ts";
import {
  cellFromValue,
  decodeD1Record,
  D1_HEADER_FORMAT,
  D1_ROWS_FORMAT,
  D1_SCHEMA_FORMAT,
  type D1Cell,
} from "../src/sources/d1-format.ts";
import type { SourceRecord, CrawlEvent } from "../src/sources/types.ts";
import type { ChunkSource } from "../src/crypto/streamseal.ts";

// ---- helpers ----------------------------------------------------------------

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function fill(n: number, seed = 0x5a): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i + seed) & 0xff;
  return b;
}

async function collect(iter: AsyncIterable<SourceRecord>): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of iter) out.push(r);
  return out;
}

// Collect all bytes from a ChunkSource (exercises the real generator path).
async function collectChunks(src: ChunkSource): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const chunk of src.chunks()) parts.push(chunk);
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ---- in-memory R2 bucket double ---------------------------------------------
//
// Implements the subset of R2Bucket that R2Source calls:
//   list({ prefix?, cursor?, limit? }) -> R2Objects
//   get(key)                           -> R2ObjectBody | null
//
// list() supports cursor-based pagination: we internally paginate at pageSize
// objects per page, controlled per-instance so tests can force pagination.

interface MockEntry {
  key: string;
  body: Uint8Array;
}

// A minimal R2Object whose only required fields for the source are key and size.
function makeR2Object(key: string, size: number): R2Object {
  return {
    key,
    size,
    version: "1",
    etag: `etag-${key}`,
    httpEtag: `"etag-${key}"`,
    checksums: {} as R2Checksums,
    uploaded: new Date(0),
    storageClass: "Standard",
    writeHttpMetadata(_h: Headers) {},
  } as unknown as R2Object;
}

// A minimal R2ObjectBody wrapping a Uint8Array.
function makeR2ObjectBody(key: string, body: Uint8Array): R2ObjectBody {
  const size = body.length;
  const base = makeR2Object(key, size);
  return {
    ...base,
    get body(): ReadableStream<Uint8Array> {
      return new ReadableStream({
        start(controller) {
          controller.enqueue(body);
          controller.close();
        },
      });
    },
    get bodyUsed(): boolean { return false; },
    async arrayBuffer(): Promise<ArrayBuffer> { return body.buffer as ArrayBuffer; },
    async bytes(): Promise<Uint8Array> { return body.slice(); },
    async text(): Promise<string> { return new TextDecoder().decode(body); },
    async json<T>(): Promise<T> { return JSON.parse(new TextDecoder().decode(body)) as T; },
    async blob(): Promise<Blob> { return new Blob([new Uint8Array(body)]); },
  } as unknown as R2ObjectBody;
}

class MemR2Bucket {
  private entries: MockEntry[];
  readonly pageSize: number; // how many objects to return per list() call

  constructor(entries: MockEntry[], pageSize = 1000) {
    // Sort so list order is deterministic.
    this.entries = [...entries].sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
    this.pageSize = pageSize;
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    const e = this.entries.find((x) => x.key === key);
    if (!e) return null;
    return makeR2ObjectBody(key, e.body);
  }

  async list(options?: { prefix?: string; cursor?: string; limit?: number }): Promise<R2Objects> {
    const prefix = options?.prefix;
    const limit = options?.limit ?? this.pageSize;
    const cursor = options?.cursor;

    // Filter by prefix.
    let filtered = prefix === undefined
      ? this.entries
      : this.entries.filter((e) => e.key.startsWith(prefix));

    // Cursor is the key of the FIRST entry on the current page (we use it as an offset token).
    let startIdx = 0;
    if (cursor !== undefined) {
      const idx = filtered.findIndex((e) => e.key === cursor);
      startIdx = idx === -1 ? filtered.length : idx;
    }

    const page = filtered.slice(startIdx, startIdx + limit);
    const nextStart = startIdx + limit;
    const hasMore = nextStart < filtered.length;

    const objects: R2Object[] = page.map((e) => makeR2Object(e.key, e.body.length));

    if (hasMore) {
      const nextCursor = filtered[nextStart]!.key;
      return { objects, delimitedPrefixes: [], truncated: true, cursor: nextCursor } as R2Objects;
    }
    return { objects, delimitedPrefixes: [], truncated: false } as R2Objects;
  }

  // Unused by R2Source but required by the R2Bucket interface shape.
  head(_key: string): Promise<R2Object | null> { throw new Error("head not needed"); }
  put(): never { throw new Error("put not needed"); }
  delete(): never { throw new Error("delete not needed"); }
  createMultipartUpload(): never { throw new Error("not needed"); }
  resumeMultipartUpload(): never { throw new Error("not needed"); }
}

// ---- R2Source tests ---------------------------------------------------------


async function testR2Small(): Promise<void> {
  console.log("\nr2-small (buffered path):");
  const body = fill(1024);
  const bucket = new MemR2Bucket([{ key: "obj/small", body }]);
  const src = new R2Source(bucket as unknown as R2Bucket, "my-bucket");

  const records = await collect(src.crawl({ include: [], exclude: [] }));
  ok("yields exactly one record", records.length === 1);

  const r = records[0]!;
  ok("sourceType is r2", r.sourceType === "r2");
  ok("name is the object key", r.name === "obj/small");
  ok("bucket field is set", r.bucket === "my-bucket");
  ok("value is a Uint8Array", r.value instanceof Uint8Array);
  ok("stream field is absent (buffered)", r.stream === undefined);
  ok("value bytes match", r.value !== undefined && eqBytes(r.value, body));
}

async function testR2Large(): Promise<void> {
  console.log("\nr2-large (streaming path):");
  // Just over the 8 MiB threshold.
  const size = STREAM_THRESHOLD + 1;
  const body = fill(size, 0x33);
  const bucket = new MemR2Bucket([{ key: "obj/large", body }]);
  const src = new R2Source(bucket as unknown as R2Bucket, "bucket-b");

  const records = await collect(src.crawl({ include: [], exclude: [] }));
  ok("yields exactly one record", records.length === 1);

  const r = records[0]!;
  ok("sourceType is r2", r.sourceType === "r2");
  ok("name is the object key", r.name === "obj/large");
  ok("value field is absent (streaming)", r.value === undefined);
  ok("stream field is present", r.stream !== undefined);
  ok("stream.size equals object size", r.stream !== undefined && r.stream.size === size);

  // Open the ChunkSource and verify the bytes come back intact.
  const chunkSrc = r.stream!.open();
  const got = await collectChunks(chunkSrc);
  ok("streamed bytes match original", eqBytes(got, body));
}

async function testR2Pagination(): Promise<void> {
  console.log("\nr2-pagination (cursor path):");
  // Four small objects; page size of 2 forces two pages.
  const entries: MockEntry[] = [
    { key: "a", body: fill(10, 0x01) },
    { key: "b", body: fill(20, 0x02) },
    { key: "c", body: fill(30, 0x03) },
    { key: "d", body: fill(40, 0x04) },
  ];
  const bucket = new MemR2Bucket(entries, 2);
  const src = new R2Source(bucket as unknown as R2Bucket, "paged-bucket");

  const records = await collect(src.crawl({ include: [], exclude: [] }));
  ok("all four objects are yielded across pages", records.length === 4);
  ok("first object key", records[0]?.name === "a");
  ok("second object key", records[1]?.name === "b");
  ok("third object key", records[2]?.name === "c");
  ok("fourth object key", records[3]?.name === "d");

  // Verify bytes round-trip for each.
  for (const e of entries) {
    const r = records.find((x) => x.name === e.key);
    ok(`bytes match for key ${e.key}`, r !== undefined && r.value !== undefined && eqBytes(r.value, e.body));
  }
}

async function testR2Selector(): Promise<void> {
  console.log("\nr2-selector (include/exclude filtering):");
  const entries: MockEntry[] = [
    { key: "uploads/img.png", body: fill(5, 0x01) },
    { key: "uploads/tmp/draft.png", body: fill(5, 0x02) },
    { key: "media/video.mp4", body: fill(5, 0x03) },
  ];
  const bucket = new MemR2Bucket(entries);
  const src = new R2Source(bucket as unknown as R2Bucket, "sel-bucket");

  const includeOnly = await collect(src.crawl({ include: ["uploads/"], exclude: [] }));
  ok("include prefix narrows to 2 uploads entries", includeOnly.length === 2);

  const excluded = await collect(src.crawl({ include: ["uploads/"], exclude: ["uploads/tmp/"] }));
  ok("exclude removes tmp subpath, leaving 1", excluded.length === 1);
  ok("remaining entry is uploads/img.png", excluded[0]?.name === "uploads/img.png");

  const all = await collect(src.crawl({ include: [], exclude: [] }));
  ok("empty include matches all 3", all.length === 3);
}

async function testR2Estimate(): Promise<void> {
  console.log("\nr2-estimate:");
  const entries: MockEntry[] = [
    { key: "x", body: fill(100) },
    { key: "y", body: fill(200) },
    { key: "z/excluded", body: fill(50) },
  ];
  const bucket = new MemR2Bucket(entries);
  const src = new R2Source(bucket as unknown as R2Bucket, "est-bucket");

  const all = await src.estimate({ include: [], exclude: [] });
  ok("estimate: all 3 records counted", all.records === 3);
  ok("estimate: total bytes = 350", all.bytes === 350);

  const filtered = await src.estimate({ include: [], exclude: ["z/"] });
  ok("estimate: exclude reduces record count to 2", filtered.records === 2);
  ok("estimate: exclude reduces bytes to 300", filtered.bytes === 300);
}

// ---- SecretsSource tests ----------------------------------------------------

async function testSecretsGet(): Promise<void> {
  console.log("\nsecrets-get (per-binding value round-trip):");
  const secrets: BoundSecret[] = [
    { name: "API_KEY", bindingVar: "API_KEY", get: async () => "super-secret-value" },
    { name: "DB_PASS", bindingVar: "DB_PASS", get: async () => "hunter2" },
  ];
  const src = new SecretsSource(secrets);

  const records = await collect(src.crawl({ include: [], exclude: [] }));
  ok("two records yielded", records.length === 2);

  const apiKey = records.find((r) => r.name === "API_KEY");
  ok("API_KEY record present", apiKey !== undefined);
  ok("API_KEY sourceType is secrets", apiKey?.sourceType === "secrets");
  ok("API_KEY value decodes correctly", apiKey?.value !== undefined && new TextDecoder().decode(apiKey.value) === "super-secret-value");

  const dbPass = records.find((r) => r.name === "DB_PASS");
  ok("DB_PASS record present", dbPass !== undefined);
  ok("DB_PASS value decodes correctly", dbPass?.value !== undefined && new TextDecoder().decode(dbPass.value) === "hunter2");
}

async function testSecretsZero(): Promise<void> {
  console.log("\nsecrets-zero (no secrets configured):");
  const src = new SecretsSource([]);
  const records = await collect(src.crawl({ include: [], exclude: [] }));
  ok("zero records yielded when no secrets", records.length === 0);
}

async function testSecretsSelector(): Promise<void> {
  console.log("\nsecrets-selector (include/exclude scoping):");
  const secrets: BoundSecret[] = [
    { name: "PROD_API_KEY", get: async () => "prod-val" },
    { name: "PROD_DB_PASS", get: async () => "prod-db" },
    { name: "DEV_API_KEY", get: async () => "dev-val" },
  ];
  const src = new SecretsSource(secrets);

  const prodOnly = await collect(src.crawl({ include: ["PROD_"], exclude: [] }));
  ok("include PROD_ yields 2 records", prodOnly.length === 2);
  ok("all yielded names start with PROD_", prodOnly.every((r) => r.name.startsWith("PROD_")));

  const excluded = await collect(src.crawl({ include: [], exclude: ["DEV_"] }));
  ok("exclude DEV_ leaves 2 records", excluded.length === 2);
  ok("no DEV_ record in result", excluded.every((r) => !r.name.startsWith("DEV_")));
}

async function testSecretsNoValueLeak(): Promise<void> {
  console.log("\nsecrets-no-value-leak (only name/binding recorded, never plaintext):");
  const secretValue = "absolutely-secret-plaintext-12345";
  const secrets: BoundSecret[] = [
    { name: "SENSITIVE_KEY", bindingVar: "SENSITIVE_KEY", get: async () => secretValue },
  ];
  const src = new SecretsSource(secrets);

  const records = await collect(src.crawl({ include: [], exclude: [] }));
  ok("one record yielded", records.length === 1);

  const r = records[0]!;

  // The only record field permitted to contain the value bytes is r.value itself.
  // Check that r.name, r.bucket, r.namespace, and r.sourceType contain no trace of the plaintext.
  ok("name does not contain the secret value", !r.name.includes(secretValue));
  ok("bucket field is undefined (not a leak vector)", r.bucket === undefined);
  ok("namespace field is undefined (not a leak vector)", r.namespace === undefined);
  ok("sourceType does not contain the secret value", !String(r.sourceType).includes(secretValue));

  // The stream field must be absent for secrets (they are always buffered as a small value).
  ok("stream field is absent for secrets", r.stream === undefined);

  // Confirm the value field itself is the encoded secret (that is the intended write path).
  ok("value field holds the encoded secret bytes", r.value !== undefined && new TextDecoder().decode(r.value) === secretValue);
}

async function testSecretsEstimate(): Promise<void> {
  console.log("\nsecrets-estimate (never reads a value to estimate):");
  let getCallCount = 0;
  const secrets: BoundSecret[] = [
    { name: "A", get: async () => { getCallCount++; return "secret-a"; } },
    { name: "B", get: async () => { getCallCount++; return "secret-b"; } },
    { name: "C_EXCLUDE", get: async () => { getCallCount++; return "secret-c"; } },
  ];
  const src = new SecretsSource(secrets);

  const est = await src.estimate({ include: [], exclude: [] });
  ok("estimate: get() was never called (no value read)", getCallCount === 0);
  ok("estimate: 3 records counted", est.records === 3);
  ok("estimate: bytes is -1 (unknown without reading)", est.bytes === -1);

  const filtered = await src.estimate({ include: [], exclude: ["C_"] });
  ok("filtered estimate: get() still never called", getCallCount === 0);
  ok("filtered estimate: 2 records counted", filtered.records === 2);
  ok("filtered estimate: bytes is still -1", filtered.bytes === -1);
}

// ---- D1Source in-memory double ---------------------------------------------
//
// Implements the subset of D1Database that the STREAMED D1Source calls:
//   withSession("first-primary") -> a session whose prepare() answers the reads
//   prepare(sql).all()                                      sqlite_master read
//   prepare("SELECT * FROM t LIMIT 0").raw({columnNames})   column header
//   prepare("SELECT _rowid_ FROM t LIMIT 0").raw(...)       rowid probe (here: always rowid)
//   prepare(keyset).bind(afterRowid, limit).raw(...)        WHERE _rowid_ > ? ORDER BY _rowid_
//
// Rows are seeded with an explicit synthetic rowid per row so the keyset pager is exercised
// for real (pages of rowsPerPage rows advance the cursor). The double records how many keyset
// pages it served so a test can assert the dump was produced via the paged path, and the
// largest number of rows it ever held in one page so a test can assert peak buffered rows stay
// bounded (it never returns the whole table in one query when paged).

interface MemD1Table {
  name: string;
  sql: string;
  columns: string[];
  rows: unknown[][]; // declared-column cells, in rowid order
  rowids: bigint[]; // one synthetic rowid per row (strictly increasing)
}

// memTypedProjectionRow models SQLite's typeof(col) plus the integer-safe typed projection's CASE for one
// raw fixture row (values as D1 .raw() returns them): per column it emits the (typeof, value) PAIR the
// source's typed projection reads. An integer comes back as typeof 'integer' with the value as an EXACT
// decimal string (CAST col AS TEXT), a fractional as 'real', text as 'text', null as 'null', a BLOB
// (number[]/typed-array/ArrayBuffer) as 'blob' with the value unchanged. This is what lets an int64 past
// 2^53 survive capture without truncation (a plain read would return it as a truncated float64 number).
function memTypedProjectionRow(row: unknown[]): unknown[] {
  const out: unknown[] = [];
  for (const v of row) {
    if (v === null || v === undefined) out.push("null", null);
    else if (typeof v === "string") out.push("text", v);
    else if (typeof v === "bigint") out.push("integer", v.toString());
    else if (typeof v === "number") {
      if (Number.isInteger(v)) out.push("integer", String(v));
      else out.push("real", v);
    } else out.push("blob", v); // a BLOB (number[]/typed-array/ArrayBuffer); cellFromValue tags it downstream
  }
  return out;
}

class MemD1 {
  tables: MemD1Table[];
  sessions = 0; // how many withSession() calls (consistency proof)
  keysetPages = 0; // how many keyset (paged) queries were served
  maxPageRows = 0; // the largest single-query row count (bounded-memory proof)
  // openedWith records the constraint/bookmark each withSession() was opened with, so a resume
  // test can assert the second session re-opened at the SAME bookmark the first marks carried.
  openedWith: string[] = [];
  // BOOKMARK is the fixed snapshot bookmark this double's session reports from getBookmark(),
  // modelling D1 Sessions: the first read establishes it and every mark threads it.
  static readonly BOOKMARK = "0000000a-0000000b-00000000-0123456789abcdef";

  constructor(seed: Array<{ name: string; sql: string; columns: string[]; rows: unknown[][] }> = []) {
    this.tables = seed.map((t) => ({ ...t, rowids: t.rows.map((_, i) => BigInt(i + 1)) }));
  }

  // withSession returns a session whose reads hit the same backing store (one snapshot) and whose
  // getBookmark() returns the fixed snapshot bookmark, modelling a consistent-read D1 Session.
  withSession(constraint?: string): MemD1Session {
    this.sessions++;
    this.openedWith.push(constraint ?? "");
    return new MemD1Session(this);
  }

  prepare(query: string): MemD1Stmt {
    return new MemD1Stmt(this, query, []);
  }

  // --- internals the statement calls back into ---
  allMaster<T>(): { results: T[]; success: true; meta: Record<string, unknown> } {
    const results = this.tables.map((t) => ({ type: "table", name: t.name, tbl_name: t.name, sql: t.sql })) as T[];
    return { results, success: true as const, meta: {} };
  }
  tableFor(query: string): MemD1Table {
    const m = /FROM\s+"((?:[^"]|"")+)"/i.exec(query);
    if (!m) throw new Error(`MemD1: unrecognised query: ${query}`);
    const name = m[1]!.replace(/""/g, '"');
    const t = this.tables.find((x) => x.name === name);
    if (!t) throw new Error(`MemD1: no such table: ${name}`);
    return t;
  }
  noteKeysetPage(rows: number): void {
    this.keysetPages++;
    if (rows > this.maxPageRows) this.maxPageRows = rows;
  }
}

// MemD1Session is the consistent-read session withSession() returns: it answers reads against the
// parent's backing store (one snapshot) and reports the fixed snapshot bookmark, modelling the D1
// Session getBookmark() the source threads through every mark for cross-slice consistency.
class MemD1Session {
  private db: MemD1;
  constructor(db: MemD1) {
    this.db = db;
  }
  prepare(query: string): MemD1Stmt {
    return new MemD1Stmt(this.db, query, []);
  }
  getBookmark(): string {
    return MemD1.BOOKMARK;
  }
}

class MemD1Stmt {
  private db: MemD1;
  private query: string;
  private binds: unknown[];
  constructor(db: MemD1, query: string, binds: unknown[]) {
    this.db = db;
    this.query = query;
    this.binds = binds;
  }
  bind(...values: unknown[]): MemD1Stmt {
    return new MemD1Stmt(this.db, this.query, values);
  }
  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    if (/FROM sqlite_master/i.test(this.query)) return this.db.allMaster<T>();
    throw new Error(`MemD1.all: unhandled: ${this.query}`);
  }
  async raw<T>(_opts: { columnNames: true }): Promise<[string[], ...T[]]> {
    // Column header probe: SELECT * FROM t LIMIT 0
    if (/SELECT \* FROM .* LIMIT 0/i.test(this.query)) {
      const t = this.db.tableFor(this.query);
      return [t.columns] as unknown as [string[], ...T[]];
    }
    // rowid probe: SELECT _rowid_ FROM t LIMIT 0 -> this double's tables all have a rowid.
    if (/SELECT _rowid_ FROM .* LIMIT 0/i.test(this.query)) {
      return [["_rowid_"]] as unknown as [string[], ...T[]];
    }
    // Keyset page: SELECT <integer-safe typed projection>, CAST(_rowid_ AS TEXT) AS "__dp_rowid" FROM t
    // WHERE _rowid_ > CAST(?1 AS INTEGER) ... The source binds the int64 cursor as a decimal STRING (real
    // D1 rejects a bigint bind, D1_TYPE_ERROR) and casts it to INTEGER in SQL. Enforce the string bind here
    // so a regression to a bigint is caught. The row cells are returned as the typed projection's
    // (typeof, value) pairs (an integer as an exact decimal string), and the cursor as CAST(_rowid_ AS TEXT).
    if (/WHERE _rowid_ > CAST\(\?1 AS INTEGER\) ORDER BY _rowid_ LIMIT \?2/i.test(this.query)) {
      const t = this.db.tableFor(this.query);
      if (typeof this.binds[0] !== "string") throw new Error(`D1_TYPE_ERROR: Type '${typeof this.binds[0]}' not supported for value '${String(this.binds[0])}'`);
      const after = BigInt(this.binds[0]);
      const limit = Number(this.binds[1]);
      const out: unknown[][] = [];
      for (let i = 0; i < t.rows.length && out.length < limit; i++) {
        if (t.rowids[i]! > after) out.push([...memTypedProjectionRow(t.rows[i]!), t.rowids[i]!.toString()]);
      }
      this.db.noteKeysetPage(out.length);
      // The header includes the declared columns plus the synthetic cursor alias.
      return [[...t.columns, "__dp_rowid"], ...out] as unknown as [string[], ...T[]];
    }
    throw new Error(`MemD1.raw: unhandled: ${this.query}`);
  }
}

// MemD1NoRowid models a database whose tables are WITHOUT ROWID: the _rowid_ probe THROWS (as it
// does on a real WITHOUT ROWID table), so the source falls back to a single-pass SELECT *. It shares
// MemD1's table shape and session/bookmark behaviour. Such tables cannot resume mid-table by design.
class MemD1NoRowid {
  tables: MemD1Table[];
  sessions = 0;
  constructor(seed: Array<{ name: string; sql: string; columns: string[]; rows: unknown[][] }> = []) {
    this.tables = seed.map((t) => ({ ...t, rowids: t.rows.map((_, i) => BigInt(i + 1)) }));
  }
  withSession(_constraint?: string): { prepare(q: string): MemD1NoRowidStmt; getBookmark(): string } {
    this.sessions++;
    const self = this;
    return { prepare: (q: string) => new MemD1NoRowidStmt(self, q), getBookmark: () => MemD1.BOOKMARK };
  }
  prepare(query: string): MemD1NoRowidStmt {
    return new MemD1NoRowidStmt(this, query);
  }
  tableFor(query: string): MemD1Table {
    const m = /FROM\s+"((?:[^"]|"")+)"/i.exec(query);
    if (!m) throw new Error(`MemD1NoRowid: unrecognised query: ${query}`);
    const name = m[1]!.replace(/""/g, '"');
    const t = this.tables.find((x) => x.name === name);
    if (!t) throw new Error(`MemD1NoRowid: no such table: ${name}`);
    return t;
  }
}

class MemD1NoRowidStmt {
  private db: MemD1NoRowid;
  private query: string;
  constructor(db: MemD1NoRowid, query: string) {
    this.db = db;
    this.query = query;
  }
  bind(..._values: unknown[]): MemD1NoRowidStmt {
    return this;
  }
  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    if (/FROM sqlite_master/i.test(this.query)) {
      const results = this.db.tables.map((t) => ({ type: "table", name: t.name, tbl_name: t.name, sql: t.sql })) as T[];
      return { results, success: true as const, meta: {} };
    }
    throw new Error(`MemD1NoRowid.all: unhandled: ${this.query}`);
  }
  async raw<T>(_opts: { columnNames: true }): Promise<[string[], ...T[]]> {
    // Column header probe: SELECT * FROM t LIMIT 0
    if (/SELECT \* FROM .* LIMIT 0/i.test(this.query)) {
      return [this.db.tableFor(this.query).columns] as unknown as [string[], ...T[]];
    }
    // rowid probe THROWS: a WITHOUT ROWID table has no _rowid_, so the source falls back.
    if (/SELECT _rowid_ FROM .* LIMIT 0/i.test(this.query)) {
      throw new Error("no such column: _rowid_");
    }
    // Single-pass read: SELECT <integer-safe typed projection> FROM t (no LIMIT) -> all rows in declared-
    // column order, each as the typed projection's (typeof, value) pairs (an integer as an exact decimal
    // string), so pageWithoutRowid captures an int64 past 2^53 without truncation.
    if (/^SELECT .* FROM /i.test(this.query)) {
      const t = this.db.tableFor(this.query);
      return [t.columns, ...t.rows.map(memTypedProjectionRow)] as unknown as [string[], ...T[]];
    }
    throw new Error(`MemD1NoRowid.raw: unhandled: ${this.query}`);
  }
}

// ---- D1Source tests ---------------------------------------------------------
//
// A D1 database now backs up as a RESUMABLE SEQUENCE of buffered per-page records (header, row
// pages, schema), not one whole-database stream. crawl() yields the records (marks dropped) and
// crawlFrom() yields the records interleaved with resume marks the sliced seal checkpoints between.

// collectEvents drains crawlFrom into its records, its mark tokens, and the raw event list, so a
// test can assert both what was yielded and where the marks fell.
async function collectEvents(iter: AsyncIterable<CrawlEvent>): Promise<{ records: SourceRecord[]; marks: string[]; events: CrawlEvent[] }> {
  const records: SourceRecord[] = [];
  const marks: string[] = [];
  const events: CrawlEvent[] = [];
  for await (const ev of iter) {
    events.push(ev);
    if (ev.kind === "record") records.push(ev.record);
    else if (ev.kind === "mark") marks.push(ev.token); // a mid-crawl vanish (WS-P2) is a _vanished RECORD event now, not a mark
  }
  return { records, marks, events };
}

// ReconD1 is a table-name -> rows reconstruction the tests build by replaying the decoded per-page
// records (header creates the table with its columns, each rows record appends, schema is collected).
// It is the in-test dual of the restore sink, just enough to assert the rows came back intact.
interface ReconD1 {
  tables: Map<string, { columns: string[]; rows: D1Cell[][] }>;
  schema: string[];
  order: string[]; // the kinds, in record order, e.g. ["header","rows","rows","schema"]
}

function reconstructFromRecords(records: SourceRecord[]): ReconD1 {
  const recon: ReconD1 = { tables: new Map(), schema: [], order: [] };
  for (const r of records) {
    const dec = decodeD1Record(r.value!);
    recon.order.push(dec.kind);
    if (dec.kind === "header") {
      for (const t of dec.tables) recon.tables.set(t.name, { columns: t.columns, rows: [] });
    } else if (dec.kind === "rows") {
      const t = recon.tables.get(dec.table);
      if (!t) throw new Error(`rows record for ${dec.table} arrived before its header`);
      for (const row of dec.rows) t.rows.push(row);
    } else if (dec.kind === "schema") {
      recon.schema.push(...dec.schema);
    }
  }
  return recon;
}

function cellsEqual(a: D1Cell[][], b: D1Cell[][]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

async function testD1Normal(): Promise<void> {
  console.log("\nd1-normal (resumable per-page export under a consistent session):");
  const db = new MemD1([
    {
      name: "items",
      sql: 'CREATE TABLE "items" (id INTEGER PRIMARY KEY, label TEXT)',
      columns: ["id", "label"],
      rows: [[1, "alpha"], [2, "beta"]],
    },
  ]);
  const src = new D1Source(db as unknown as D1Database, "mydb", undefined, undefined, "db-uuid-abc123");
  const records = await collect(src.crawl({ include: [], exclude: [] }));
  // A one-table, two-row DB: header, one rows record (both rows fit one default page), schema.
  ok("d1-normal: yields header + rows + schema (3 records)", records.length === 3);
  ok("d1-normal: every record is a buffered value, not a stream", records.every((r) => r.value !== undefined && r.stream === undefined));
  ok("d1-normal: every record's sourceType is d1", records.every((r) => r.sourceType === "d1"));
  ok("d1-normal: every record routes to the same database binding", records.every((r) => d1DatabaseNameFromRecordName(r.name) === "mydb"));
  // Self-identification: every record carries the native database UUID (not just the binding name in the
  // record name), so the archive says WHICH database it is a backup of even if the binding was renamed.
  ok("d1-normal: every record carries the native database UUID annotation", records.every((r) => r.database === "db-uuid-abc123"));
  ok("d1-without-uuid: a D1Source with no databaseId omits the database annotation (back-compat)", (await collect(new D1Source(new MemD1([{ name: "t", sql: 'CREATE TABLE "t" (id INTEGER PRIMARY KEY)', columns: ["id"], rows: [[1]] }]) as unknown as D1Database, "b").crawl({ include: [], exclude: [] }))).every((r) => r.database === undefined));
  // exactly one consistent session opened for the whole crawl (a regression that opens redundant
  // sessions would break bookmark threading and waste round-trips)
  ok("d1-normal: exactly one consistent session was opened (withSession)", db.sessions === 1);

  const [header, rowsRec, schemaRec] = records;
  ok("d1-normal: the FIRST record is the header (d1.format)", header!.descriptor?.d1Format === D1_HEADER_FORMAT && decodeD1Record(header!.value!).kind === "header");
  ok("d1-normal: the MIDDLE record is a rows page (d1.format)", rowsRec!.descriptor?.d1Format === D1_ROWS_FORMAT && decodeD1Record(rowsRec!.value!).kind === "rows");
  ok("d1-normal: the LAST record is the schema (d1.format)", schemaRec!.descriptor?.d1Format === D1_SCHEMA_FORMAT && decodeD1Record(schemaRec!.value!).kind === "schema");

  const headerDec = decodeD1Record(header!.value!);
  ok("d1-normal: header carries the table DDL and column order", headerDec.kind === "header" && headerDec.tables.length === 1 && headerDec.tables[0]!.name === "items" && headerDec.tables[0]!.columns.join(",") === "id,label");
  const rowsDec = decodeD1Record(rowsRec!.value!);
  ok("d1-normal: rows record carries the table name + columns + rows", rowsDec.kind === "rows" && rowsDec.table === "items" && rowsDec.columns.join(",") === "id,label" && cellsEqual(rowsDec.rows, [[1, "alpha"], [2, "beta"]]));

  // Reconstruct the DB from the records and confirm it matches the source cell for cell.
  const recon = reconstructFromRecords(records);
  ok("d1-normal: reconstruction order is header -> rows -> schema", recon.order.join(",") === "header,rows,schema");
  ok("d1-normal: reconstructed items rows match the source", cellsEqual(recon.tables.get("items")!.rows, [[1, "alpha"], [2, "beta"]]));
}

async function testD1Paged(): Promise<void> {
  console.log("\nd1-paged (keyset paging emits multiple bounded rows records per table):");
  // 5 rows with a page size of 2 forces 3 keyset pages (2 + 2 + 1) -> 3 rows records for t1. The
  // double records the largest single-query row count, so a bounded page proves the whole table is
  // never read at once. A second table proves the sequence crosses a table boundary.
  const rows = Array.from({ length: 5 }, (_, i) => [i + 1, `row-${i}`] as D1Cell[]);
  const db = new MemD1([
    { name: "t1", sql: 'CREATE TABLE "t1" (id INTEGER PRIMARY KEY, v TEXT)', columns: ["id", "v"], rows },
    { name: "t2", sql: 'CREATE TABLE "t2" (id INTEGER PRIMARY KEY)', columns: ["id"], rows: [[1], [2], [3]] },
  ]);
  const ROWS_PER_PAGE = 2;
  const src = new D1Source(db as unknown as D1Database, "paged-db", D1_PAGE_BYTE_LIMIT, ROWS_PER_PAGE);
  const { records, marks } = await collectEvents(src.crawlFrom({ include: [], exclude: [] }, null));

  const rowsRecs = records.filter((r) => decodeD1Record(r.value!).kind === "rows");
  const t1Rows = rowsRecs.filter((r) => (decodeD1Record(r.value!) as { table: string }).table === "t1");
  const t2Rows = rowsRecs.filter((r) => (decodeD1Record(r.value!) as { table: string }).table === "t2");
  ok("d1-paged: t1 emitted 3 rows pages (2+2+1)", t1Rows.length === 3);
  ok("d1-paged: t2 emitted 2 rows pages (2+1)", t2Rows.length === 2);
  ok("d1-paged: header first, schema last", decodeD1Record(records[0]!.value!).kind === "header" && decodeD1Record(records[records.length - 1]!.value!).kind === "schema");

  // Peak buffered rows are bounded by the page size: no single query returned more than one page.
  ok("d1-paged: no single query returned more than one page of rows (bounded memory)", db.maxPageRows <= ROWS_PER_PAGE);

  // Reconstruct both tables from the records and confirm cell-for-cell, no loss, no duplication.
  const recon = reconstructFromRecords(records);
  ok("d1-paged: reconstructed t1 rows match the source (no loss/dup across pages)", cellsEqual(recon.tables.get("t1")!.rows, rows));
  ok("d1-paged: reconstructed t2 rows match the source", cellsEqual(recon.tables.get("t2")!.rows, [[1], [2], [3]]));

  // Every mark threads the session snapshot bookmark, so a resumed slice re-opens the same point.
  ok("d1-paged: every mark threads the session bookmark (cross-slice consistency)", marks.length > 0 && marks.every((m) => JSON.parse(m).bookmark === MemD1.BOOKMARK));
  // A mark follows every record (the slice can checkpoint after any record).
  ok("d1-paged: a mark follows every record", marks.length >= records.length);
}

async function testD1AdaptivePaging(): Promise<void> {
  console.log("\nd1-adaptive (wide rows page by BYTES, not a fixed row count -- the wide-row residual):");
  // Each row carries a ~1 KiB string. At a fixed 2000-rows-per-page these 12 rows would be ONE ~12 KiB page
  // that a small per-page cap REJECTS (the old wide-row failure); adaptive byte-bounded paging instead
  // splits them into multiple sub-cap pages. A small sizeLimit (4096 -> targetBytes 2048) forces ~1 wide row
  // per page even though rowsPerPage defaults to 2000, so BYTES, not the row count, bound the page.
  const WIDE = "x".repeat(1024);
  const rows: D1Cell[][] = Array.from({ length: 12 }, (_, i) => [i + 1, WIDE]);
  const db = new MemD1([{ name: "wide", sql: 'CREATE TABLE "wide" (id INTEGER, blob TEXT)', columns: ["id", "blob"], rows }]);
  const src = new D1Source(db as unknown as D1Database, "wide-db", 4096);
  let threw = "";
  let records: SourceRecord[] = [];
  try {
    records = (await collectEvents(src.crawlFrom({ include: [], exclude: [] }, null))).records;
  } catch (e) {
    threw = (e as Error).message;
  }
  ok("d1-adaptive: a wide-row table pages WITHOUT throwing (fixed-row paging would hit the cap)", threw === "");
  const rowsRecs = records.filter((r) => r.value !== undefined && decodeD1Record(r.value).kind === "rows");
  ok("d1-adaptive: the wide rows split into MULTIPLE row-page records (not one over-cap page)", rowsRecs.length > 1);
  ok("d1-adaptive: no single query held more than a few wide rows (bounded by BYTES, not 2000)", db.maxPageRows <= 4);
  const recon = reconstructFromRecords(records);
  ok("d1-adaptive: every wide row is present across the pages (no loss/dup), cell-for-cell", cellsEqual(recon.tables.get("wide")!.rows, rows));
}

async function testD1Resume(): Promise<void> {
  console.log("\nd1-resume (crawlFrom resumes mid-table: no duplication, no loss):");
  // 6 rows, page size 2: pages cover rowids (1,2)(3,4)(5,6). Resume from the mark after the FIRST
  // page (afterRowid=2) and confirm the resumed crawl yields rows 3..6 exactly once and nothing
  // before. A second table proves resume continues across the table boundary.
  const t1Rows = Array.from({ length: 6 }, (_, i) => [i + 1, `r${i + 1}`] as D1Cell[]);
  const t2Rows = [[100, "x"], [200, "y"]] as D1Cell[][];
  const seed = () => new MemD1([
    { name: "t1", sql: 'CREATE TABLE "t1" (id INTEGER PRIMARY KEY, v TEXT)', columns: ["id", "v"], rows: t1Rows.map((r) => [...r]) },
    { name: "t2", sql: 'CREATE TABLE "t2" (id INTEGER PRIMARY KEY, v TEXT)', columns: ["id", "v"], rows: t2Rows.map((r) => [...r]) },
  ]);
  const ROWS_PER_PAGE = 2;

  // First pass: collect the events and find the mark right after t1's first rows page.
  const db1 = seed();
  const first = await collectEvents(new D1Source(db1 as unknown as D1Database, "rdb", D1_PAGE_BYTE_LIMIT, ROWS_PER_PAGE).crawlFrom({ include: [], exclude: [] }, null));
  // Locate the first rows record's following mark (events: header, mark, rows-page-0, MARK<-here, ...).
  let resumeToken: string | null = null;
  for (let i = 0; i < first.events.length; i++) {
    const ev = first.events[i]!;
    if (ev.kind === "record" && decodeD1Record(ev.record.value!).kind === "rows") {
      const next = first.events[i + 1];
      if (next && next.kind === "mark") resumeToken = next.token;
      break;
    }
  }
  ok("d1-resume: found a mid-table resume mark after the first rows page", resumeToken !== null);
  const parsed = JSON.parse(resumeToken!);
  ok("d1-resume: the mark points mid-table (phase rows, ti 0, afterRowid 2)", parsed.phase === "rows" && parsed.ti === 0 && parsed.afterRowid === "2");
  ok("d1-resume: the mark threads the session bookmark", parsed.bookmark === MemD1.BOOKMARK);

  // Resume from that token on a fresh source over the same data.
  const db2 = seed();
  const resumed = await collectEvents(new D1Source(db2 as unknown as D1Database, "rdb", D1_PAGE_BYTE_LIMIT, ROWS_PER_PAGE).crawlFrom({ include: [], exclude: [] }, resumeToken));
  // The resume re-opened the session at the SAME bookmark the mark carried (cross-slice snapshot).
  ok("d1-resume: the resumed crawl re-opened the session at the carried bookmark", db2.openedWith.includes(MemD1.BOOKMARK));
  // The resumed crawl must NOT re-emit the header (it was sealed before the resume).
  ok("d1-resume: the resumed crawl does not re-emit the header", resumed.records.every((r) => decodeD1Record(r.value!).kind !== "header"));

  // Collect the resumed rows for t1 and t2 and confirm they are exactly the rows AFTER rowid 2,
  // once each, in order: t1 rows 3..6 then t2 rows.
  const resumedRecon = reconstructFromRecordsAllowingMissingHeader(resumed.records);
  ok("d1-resume: t1 resumed rows are exactly 3..6 (no loss, no duplication, no rows<=2)", cellsEqual(resumedRecon.get("t1") ?? [], t1Rows.slice(2)));
  ok("d1-resume: t2 resumed rows are the whole second table (resume crossed the table boundary)", cellsEqual(resumedRecon.get("t2") ?? [], t2Rows));

  // End-to-end no-loss: the first page's rows (1,2) PLUS the resumed rows reconstruct the full table.
  const firstRecon = reconstructFromRecords(first.records);
  const t1FirstPageThenResume = [...firstRecon.tables.get("t1")!.rows.slice(0, 2), ...(resumedRecon.get("t1") ?? [])];
  ok("d1-resume: first-page rows + resumed rows = the whole t1 (split is exact)", cellsEqual(t1FirstPageThenResume, t1Rows));
}

// reconstructFromRecordsAllowingMissingHeader replays a RESUMED record stream (which has no header,
// since the header was sealed before the resume) into a table-name -> rows map, so a resume test can
// assert exactly which rows came back. A rows record's table is taken from its body.
function reconstructFromRecordsAllowingMissingHeader(records: SourceRecord[]): Map<string, D1Cell[][]> {
  const out = new Map<string, D1Cell[][]>();
  for (const r of records) {
    const dec = decodeD1Record(r.value!);
    if (dec.kind !== "rows") continue;
    const cur = out.get(dec.table) ?? [];
    for (const row of dec.rows) cur.push(row);
    out.set(dec.table, cur);
  }
  return out;
}

async function testD1Guards(): Promise<void> {
  console.log("\nd1-guards (per-page byte guard fires honestly):");

  // PER-PAGE guard (guardPageBytes): a single row larger than the (here lowered) page bound is
  // pathological - it cannot be carried in one record - so it is refused naming the table. A 1 KiB
  // row against a 256-byte effective bound trips the page guard. (The whole-dump streamed-total cap
  // is gone with the stream; the per-page bound is the live guard.)
  const pageDb = new MemD1([
    { name: "fat", sql: 'CREATE TABLE "fat" (id INTEGER PRIMARY KEY, payload TEXT)', columns: ["id", "payload"], rows: [[1, "x".repeat(1024)]] },
  ]);
  const pageSrc = new D1Source(pageDb as unknown as D1Database, "page-db", 256);
  let pageThrew = false;
  let pageMsg = "";
  try {
    for await (const _ev of pageSrc.crawlFrom({ include: [], exclude: [] }, null)) { /* page guard throws */ }
  } catch (e) {
    pageThrew = true;
    pageMsg = (e as Error).message;
  }
  ok("d1-guards: a single oversize row page throws (cannot carry in one record)", pageThrew);
  ok("d1-guards: the page-guard error names the table", pageMsg.includes("fat"));
  ok("d1-guards: the page-guard error mentions the page limit", /page limit/.test(pageMsg));

  // The production constants are honest, finite bounds.
  ok("d1-guards: D1_EXPORT_SIZE_LIMIT is a raised nominal cap (>> 1 GiB)", D1_EXPORT_SIZE_LIMIT > 1024 * 1024 * 1024);
  ok("d1-guards: D1_PAGE_BYTE_LIMIT bounds one in-memory page (finite)", D1_PAGE_BYTE_LIMIT > 0 && D1_PAGE_BYTE_LIMIT < D1_EXPORT_SIZE_LIMIT);
  ok("d1-guards: D1_ROWS_PER_PAGE is a sane page size", D1_ROWS_PER_PAGE >= 1);
}

async function testD1WithoutRowid(): Promise<void> {
  console.log("\nd1-without-rowid (a WITHOUT ROWID table is read in one page, no mid-table resume):");
  // The double's keyset path requires a rowid; model a WITHOUT ROWID table by making the rowid probe
  // fail, so the source falls back to the single-pass SELECT *. A small lookup table by design.
  const db = new MemD1NoRowid([
    { name: "lookup", sql: 'CREATE TABLE "lookup" (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID', columns: ["k", "v"], rows: [["a", "1"], ["b", "2"]] },
  ]);
  const src = new D1Source(db as unknown as D1Database, "wdb", D1_PAGE_BYTE_LIMIT, 1);
  const { records, marks } = await collectEvents(src.crawlFrom({ include: [], exclude: [] }, null));
  const recon = reconstructFromRecords(records);
  ok("d1-without-rowid: the table round-trips in one page", cellsEqual(recon.tables.get("lookup")!.rows, [["a", "1"], ["b", "2"]]));
  // Its mark advances straight to the next table (afterRowid null), i.e. it cannot resume mid-table.
  const lookupMark = marks.map((m) => JSON.parse(m)).find((t) => t.phase === "rows" && t.afterRowid === null && t.ti === 1);
  ok("d1-without-rowid: the mark advances to the next table (no mid-table cursor)", lookupMark !== undefined);
}

// ---- main -------------------------------------------------------------------

async function main(): Promise<void> {
  await testR2Small();
  await testR2Large();
  await testR2Pagination();
  await testR2Selector();
  await testR2Estimate();

  await testSecretsGet();
  await testSecretsZero();
  await testSecretsSelector();
  await testSecretsNoValueLeak();
  await testSecretsEstimate();

  await testD1Normal();
  await testD1Paged();
  await testD1AdaptivePaging();
  await testD1Resume();
  await testD1WithoutRowid();
  await testD1Guards();
  await testD1CellCodec();

  console.log(failures === 0 ? "\nSOURCE ADAPTER TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// testD1CellCodec unit-tests cellFromValue for the two data-correctness bugs (P0): a BLOB read via
// .raw() arrives as a number[] of bytes (not an ArrayBuffer), and a non-finite REAL must fail closed
// rather than silently JSON-serialise to null.
async function testD1CellCodec(): Promise<void> {
  const blob = cellFromValue([104, 105, 0, 255]);
  ok("D1 BLOB read as number[] becomes a $blob cell", typeof blob === "object" && blob !== null && "$blob" in blob);
  const empty = cellFromValue([]);
  ok("D1 empty BLOB number[] is a $blob cell (not null)", typeof empty === "object" && empty !== null && "$blob" in empty);
  let threwArr = false;
  try { cellFromValue([1, 2, 999]); } catch { threwArr = true; }
  ok("D1 non-byte array fails closed", threwArr);
  for (const nf of [Infinity, -Infinity, NaN]) {
    let threw = false;
    try { cellFromValue(nf); } catch { threw = true; }
    ok(`D1 non-finite REAL (${String(nf)}) fails closed (not a silent null)`, threw);
  }
  ok("D1 finite number passes through", cellFromValue(42) === 42);
  ok("D1 string passes through", cellFromValue("hi") === "hi");
  ok("D1 null passes through", cellFromValue(null) === null);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
