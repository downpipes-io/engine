// Prove the full D1 restore round trip: read a fixture D1 database through the real D1Source
// (schema from sqlite_master + every table's rows), seal it into a downpipe archive, then
// drive the real runRestore handler through the verifying reader to re-create the schema and
// re-insert the rows into a SEPARATE target D1 database, with the restored data matching the
// original cell for cell. Also prove: a dry run writes nothing, every row value is BOUND (no
// data in SQL text), inserts run inside batch() transactions, a reserved D1 target binding is
// refused, and a foreign-format body is refused before any write. Run:
//   node test/validate-d1-restore.ts
// In-memory doubles only; no network, no deploy, no D1, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { runRestore } from "../src/admin/restore.ts";
import { restorePlanHash } from "../src/admin/approvals.ts";
import { D1Source, D1_PAGE_BYTE_LIMIT } from "../src/sources/d1.ts";
import { D1RestoreSink } from "../src/dest/restore-sink.ts";
import {
  D1_BACKUP_FORMAT,
  D1_HEADER_FORMAT,
  D1_ROWS_FORMAT,
  D1_SCHEMA_FORMAT,
  cellFromValue,
  cellToBind,
  decodeD1Backup,
  decodeD1Record,
  encodeD1Backup,
  encodeD1BackupStream,
  encodeD1Header,
  encodeD1RowsPage,
  encodeD1Schema,
  quoteIdent,
  type D1Backup,
  type D1Cell,
  type D1DumpPlan,
  type D1RowPage,
} from "../src/sources/d1-format.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import type { SourceRecord, CrawlEvent } from "../src/sources/types.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult, RestorePlan } from "../src/admin/restore-types.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const DB_NAME = "app_throwaway";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// ---- The fixture D1 schema and rows the round trip must reproduce exactly. ----
// users exercises every cell kind the body has to carry: TEXT, INTEGER, NULL, a BLOB, and an
// out-of-safe-range INTEGER (a bigint) that must survive without being narrowed.
const USERS_SQL = 'CREATE TABLE "users" (id INTEGER PRIMARY KEY, name TEXT, score INTEGER, avatar BLOB, big INTEGER)';
const NOTES_SQL = 'CREATE TABLE "notes" (id INTEGER PRIMARY KEY, body TEXT)';
const IDX_SQL = 'CREATE INDEX "idx_users_name" ON "users" (name)';
const IDX_LEGACY_SQL = 'CREATE INDEX "idx_legacy_v" ON "legacy" (v)';
const BIG_INT = 9007199254740993n; // 2^53 + 1, not representable as a JS number
const AVATAR = new Uint8Array([0x00, 0x01, 0xfe, 0xff, 0x42]);
// A name chosen to look like SQL injection: it must land verbatim as data, never execute.
const HOSTILE_NAME = "Robert'); DROP TABLE users;--";

interface FixtureTable {
  sql: string;
  columns: string[];
  rows: D1Cell[][]; // cells in the d1-format representation (BLOB/bigint tagged)
  rowids?: bigint[]; // one synthetic rowid per row (source side keyset cursor); set by seedTable
  withoutRowid?: boolean; // a WITHOUT ROWID table: the _rowid_ probe throws, forcing pageWithoutRowid
}

// A faithful-enough D1 double. On the SOURCE side it answers the sqlite_master query and the
// per-table SELECT * the source issues. On the SINK side it executes the CREATE/INSERT/CREATE
// INDEX statements into its own in-memory tables so the test can read the RESTORED data back
// and compare. It records bound values and batch grouping so the test can prove
// parameterisation and transactional batching.
class MockD1 {
  tables = new Map<string, FixtureTable>();
  schema: string[] = []; // CREATE INDEX/TRIGGER/VIEW text, in apply order
  declOrder: string[] = []; // table names in sqlite_master declaration order
  batches = 0; // number of db.batch() calls
  // capturedSql collects every SQL string prepared during a restore, so the test can assert no
  // row value ever appears in the SQL text (i.e. values were bound, not interpolated).
  capturedSql: string[] = [];
  // Source instrumentation: how many consistent-read sessions were opened, what
  // constraint/bookmark each was opened with (so a resume proof can assert the second session
  // re-anchored at the carried bookmark), and the largest single keyset query's row count (the
  // bounded-memory witness: the whole table is never read in one query when paged).
  sessions = 0;
  openedWith: string[] = [];
  maxPageRows = 0;
  // BOOKMARK is the fixed snapshot bookmark this double's session reports, modelling a D1 Session:
  // the first read establishes it and the source threads it through every mark for cross-slice
  // consistency.
  static readonly BOOKMARK = "00000001-00000002-00000000-fedcba9876543210";

  // seedTable installs a fixture table for the source side to read out. A synthetic rowid per
  // row (1-based, in seed order) backs the source's keyset pager. withoutRowid makes the _rowid_
  // probe throw, so the source falls back to pageWithoutRowid (the single-pass typed read).
  seedTable(name: string, sql: string, columns: string[], rows: D1Cell[][], withoutRowid = false): void {
    this.tables.set(name, { sql, columns, rows, rowids: rows.map((_, i) => BigInt(i + 1)), withoutRowid });
    this.declOrder.push(name);
  }
  seedSchema(sql: string): void {
    this.schema.push(sql);
  }

  // withSession anchors a consistent read for the whole export. The same backing store
  // answers the session's reads (one snapshot); getBookmark returns the fixed snapshot bookmark
  // the source threads through every mark.
  withSession(constraint?: string): MockD1 {
    this.sessions++;
    this.openedWith.push(constraint ?? "");
    return this;
  }
  getBookmark(): string {
    return MockD1.BOOKMARK;
  }

  prepare(query: string): MockStmt {
    this.capturedSql.push(query);
    return new MockStmt(this, query, []);
  }

  noteKeysetPage(rows: number): void {
    if (rows > this.maxPageRows) this.maxPageRows = rows;
  }

  async batch(statements: MockStmt[]): Promise<unknown[]> {
    this.batches++;
    // A real D1 batch is one transaction; the mock simply applies each in order. If any throws
    // the rest do not run, mirroring rollback closely enough for the test's purposes.
    const out: unknown[] = [];
    for (const s of statements) out.push(await s.run());
    return out;
  }

  async exec(_query: string): Promise<{ count: number; duration: number }> {
    return { count: 0, duration: 0 };
  }

  // applyStatement is the mock's tiny SQL interpreter for the statements the sink emits.
  applyStatement(query: string, binds: unknown[]): void {
    const create = /^CREATE TABLE\s+"((?:[^"]|"")+)"/i.exec(query);
    if (create) {
      const name = create[1]!.replace(/""/g, '"');
      if (this.tables.has(name)) throw new Error(`table ${name} already exists`);
      this.tables.set(name, { sql: query, columns: [], rows: [] });
      this.declOrder.push(name);
      return;
    }
    const insert = /^INSERT INTO\s+"((?:[^"]|"")+)"\s*\(([^)]*)\)\s+VALUES\s*\((.*)\)\s*;?\s*$/i.exec(query);
    if (insert) {
      const name = insert[1]!.replace(/""/g, '"');
      const t = this.tables.get(name);
      if (!t) throw new Error(`no such table: ${name}`);
      const cols = insert[2]!.split(",").map((c) => c.trim().replace(/^"|"$/g, "").replace(/""/g, '"'));
      if (t.columns.length === 0) t.columns = cols;
      // Store the bound values as cells (the sink binds ArrayBuffer for BLOB and bigint for a big integer;
      // convert back to the tagged cell form so comparison is apples to apples). A big integer is bound as a
      // decimal STRING under a CAST(? AS INTEGER) placeholder because real D1 rejects a bigint bind, so that
      // position's string is converted back to a bigint here, exactly as SQLite's CAST stores it.
      const slots = insert[3]!.split(",").map((s) => s.trim());
      t.rows.push(binds.map((v, i) => (/^CAST\(\? AS INTEGER\)$/i.test(slots[i] ?? "") ? bindToCell(BigInt(v as string)) : bindToCell(v))));
      return;
    }
    if (/^CREATE\s+(INDEX|TRIGGER|VIEW)/i.test(query)) {
      this.schema.push(query);
      return;
    }
    throw new Error(`MockD1 cannot apply: ${query.slice(0, 40)}`);
  }
}

class MockStmt {
  private db: MockD1;
  private query: string;
  private binds: unknown[];
  constructor(db: MockD1, query: string, binds: unknown[]) {
    this.db = db;
    this.query = query;
    this.binds = binds;
  }
  bind(...values: unknown[]): MockStmt {
    // Real D1 rejects a JS bigint bind (D1_TYPE_ERROR: "Type 'bigint' not supported"); the source pager
    // and the restore sink both bind int64s as decimal strings (cast back in SQL) for that reason. Enforce
    // it here so a regression to a bigint bind on EITHER path is caught, not hidden by a permissive double.
    for (const v of values) if (typeof v === "bigint") throw new Error(`D1_TYPE_ERROR: Type 'bigint' not supported for value '${String(v)}'`);
    return new MockStmt(this.db, this.query, values);
  }
  // all() answers the sqlite_master read on the source side.
  async all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    if (/FROM sqlite_master/i.test(this.query)) {
      const results: Record<string, unknown>[] = [];
      for (const name of this.db.declOrder) {
        const t = this.db.tables.get(name)!;
        results.push({ type: "table", name, tbl_name: name, sql: t.sql });
      }
      for (const s of this.db.schema) {
        const m = /ON\s+"((?:[^"]|"")+)"/i.exec(s);
        const tbl = m ? m[1]!.replace(/""/g, '"') : "";
        const nm = /CREATE\s+\w+\s+"((?:[^"]|"")+)"/i.exec(s);
        results.push({ type: /INDEX/i.test(s) ? "index" : /TRIGGER/i.test(s) ? "trigger" : "view", name: nm ? nm[1] : "", tbl_name: tbl, sql: s });
      }
      return { results: results as T[], success: true, meta: {} };
    }
    throw new Error(`MockStmt.all unhandled: ${this.query}`);
  }
  // raw({columnNames:true}) answers the streamed source side's reads. The source issues, in order: a
  // LIMIT 0 column-header probe, a _rowid_ existence probe (fails for a WITHOUT ROWID table), then either
  // keyset pages (rowid tables) or a single typed pass (WITHOUT ROWID). The keyset/single-pass reads now
  // use the INTEGER-SAFE TYPED PROJECTION: per column a typeof(col) + CASE-projected value PAIR, so an
  // int64 past 2^53 comes back as an EXACT decimal string, plus a trailing CAST(_rowid_ AS TEXT) cursor.
  async raw<T = unknown[]>(_opts: { columnNames: true }): Promise<[string[], ...T[]]> {
    const m = /FROM\s+"((?:[^"]|"")+)"/i.exec(this.query);
    if (!m) throw new Error(`MockStmt.raw unhandled: ${this.query}`);
    const name = m[1]!.replace(/""/g, '"');
    const t = this.db.tables.get(name)!;

    // Column-header probe: SELECT * FROM t LIMIT 0 -> just the header row (unchanged; readDumpPlan still
    // reads the column header via a plain SELECT * LIMIT 0).
    if (/SELECT \* FROM .* LIMIT 0/i.test(this.query)) {
      return [t.columns] as unknown as [string[], ...T[]];
    }
    // rowid existence probe: a rowid table succeeds; a WITHOUT ROWID table THROWS (as real D1 does), so
    // the source falls back to pageWithoutRowid.
    if (/SELECT _rowid_ FROM .* LIMIT 0/i.test(this.query)) {
      if (t.withoutRowid) throw new Error("no such column: _rowid_");
      return [["_rowid_"]] as unknown as [string[], ...T[]];
    }
    // typed reports whether THIS read uses the integer-safe typed projection (typeof(col) per column). The
    // REGRESSION TRAP: if the source stops using the typed projection, `typed` is false and the mock
    // returns raw values via cellToRawValue, which TRUNCATES a >2^53 integer to float64 exactly as real
    // D1 would -- so the D1-BIGINT round-trip assertions then fail, catching the revert.
    const typed = /typeof\(/i.test(this.query);
    // Keyset page: rows with _rowid_ > after, ordered, limited; append the rowid cursor column. The
    // source binds the int64 cursor as a decimal STRING and casts it to INTEGER in SQL because real D1
    // rejects a bigint bind (D1_TYPE_ERROR). Enforce the string bind here so a regression to a bigint
    // cursor is caught (real D1 would throw). The cursor is projected as CAST(_rowid_ AS TEXT), so it is
    // returned as a decimal STRING (a plain _rowid_ read, the reverted shape, is returned TRUNCATED).
    if (/WHERE _rowid_ > CAST\(\?1 AS INTEGER\) ORDER BY _rowid_ LIMIT \?2/i.test(this.query)) {
      if (typeof this.binds[0] !== "string") throw new Error(`D1_TYPE_ERROR: Type '${typeof this.binds[0]}' not supported for value '${String(this.binds[0])}'`);
      const after = BigInt(this.binds[0]);
      const limit = Number(this.binds[1]);
      const rowids = t.rowids ?? t.rows.map((_, i) => BigInt(i + 1));
      const cursorAsText = /CAST\(_rowid_ AS TEXT\)/i.test(this.query);
      const out: unknown[][] = [];
      for (let i = 0; i < t.rows.length && out.length < limit; i++) {
        if (rowids[i]! > after) {
          const cells = typed ? typedProjectionRow(t.rows[i]!) : t.rows[i]!.map(cellToRawValue);
          const cursor = cursorAsText ? rowids[i]!.toString() : Number(rowids[i]!);
          out.push([...cells, cursor]);
        }
      }
      this.db.noteKeysetPage(out.length);
      return [[...t.columns, "__dp_rowid"], ...out] as unknown as [string[], ...T[]];
    }
    // WITHOUT-ROWID single pass: SELECT <typed projection> FROM t (no WHERE/LIMIT). The typed path
    // returns every row as typeof/value pairs; a reverted plain SELECT * (no typeof) returns raw values
    // (the same regression trap covers this path).
    const dataRows = t.rows.map((r) => (typed ? typedProjectionRow(r) : r.map(cellToRawValue))) as T[];
    return [t.columns, ...dataRows];
  }
  // run() is the sink-side execution path (used directly or inside batch()).
  async run(): Promise<{ success: true; meta: Record<string, unknown>; results: unknown[] }> {
    this.db.applyStatement(this.query, this.binds);
    return { success: true, meta: {}, results: [] };
  }
}

// bindToCell turns a value the sink bound back into the tagged cell form, so a restored row
// compares equal to the original fixture row.
function bindToCell(v: unknown): D1Cell {
  if (v === null) return null;
  if (typeof v === "bigint") return { $int: v.toString() };
  if (v instanceof ArrayBuffer) return { $blob: b64urlEncode(new Uint8Array(v)) };
  if (typeof v === "string" || typeof v === "number") return v;
  throw new Error(`unexpected bound value type ${typeof v}`);
}

// b64urlToByteArray decodes a base64url BLOB string to the number[] of byte values (0-255) that real D1
// .raw() surfaces a BLOB column as, matching the byte-array BLOB shape cellFromValue tags.
function b64urlToByteArray(b64url: string): number[] {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out: number[] = [];
  for (let i = 0; i < bin.length; i++) out.push(bin.charCodeAt(i));
  return out;
}

// cellToRawValue models what a PLAIN (non-typed) SELECT would read from real D1 .raw() for a fixture
// cell: a BLOB as a number[] of bytes, and -- crucially -- an out-of-safe-range integer TRUNCATED to a
// float64 number, because D1's query API returns integers as float64 JSON and silently loses precision
// above 2^53. This is the REGRESSION TRAP: it is reached only when the source does NOT use the typed
// projection, so a revert of the D1-BIGINT fix decodes a >2^53 integer from this truncated number and
// the exact-decimal round-trip assertions fail. The typed path (typedProjectionRow) never routes here.
function cellToRawValue(c: D1Cell): unknown {
  if (c === null) return null;
  if (typeof c === "string" || typeof c === "number") return c;
  if ("$blob" in c) return b64urlToByteArray(c.$blob);
  return Number(BigInt(c.$int)); // TRUNCATED to float64, exactly as real D1's plain read would return it
}

// sqliteTypeofAndValue models SQLite's typeof(col) plus the typed projection's CASE for one fixture cell,
// returning the [typeof, projected-value] PAIR the source's typed projection reads. An integer (an
// in-range plain number OR a tagged {$int}) comes back as typeof 'integer' with the value CAST to an
// EXACT decimal string; a fractional number as 'real'; text as 'text'; null as 'null'; a BLOB as 'blob'
// with the number[] byte array. The exact decimal string for an integer is what lets a >2^53 value
// survive capture without truncation.
function sqliteTypeofAndValue(c: D1Cell): [string, unknown] {
  if (c === null) return ["null", null];
  if (typeof c === "string") return ["text", c];
  if (typeof c === "number") return Number.isInteger(c) ? ["integer", String(c)] : ["real", c];
  if ("$blob" in c) return ["blob", b64urlToByteArray(c.$blob)];
  return ["integer", c.$int]; // {$int}: typeof 'integer', CAST(col AS TEXT) -> the exact decimal string
}

// typedProjectionRow flattens a fixture row into the source's typed-projection result columns: per column
// the (typeof, value) pair, index-synchronised (column i -> result indices 2*i and 2*i+1).
function typedProjectionRow(row: D1Cell[]): unknown[] {
  const out: unknown[] = [];
  for (const c of row) {
    const [ty, v] = sqliteTypeofAndValue(c);
    out.push(ty, v);
  }
  return out;
}

function cellEq(a: D1Cell, b: D1Cell): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function rowsEq(a: D1Cell[][], b: D1Cell[][]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i]!.length !== b[i]!.length) return false;
    for (let j = 0; j < a[i]!.length; j++) if (!cellEq(a[i]![j]!, b[i]![j]!)) return false;
  }
  return true;
}

// collectCrawl drains a crawlFrom into its records, mark tokens, and the raw event list, so a
// proof can assert both what was yielded and where the marks fell (the resume points).
async function collectCrawl(iter: AsyncIterable<CrawlEvent>): Promise<{ records: SourceRecord[]; marks: string[]; events: CrawlEvent[] }> {
  const records: SourceRecord[] = [];
  const marks: string[] = [];
  const events: CrawlEvent[] = [];
  for await (const ev of iter) {
    events.push(ev);
    if (ev.kind === "record") records.push(ev.record);
    else if (ev.kind === "mark") marks.push(ev.token); // a mid-crawl vanish is a _vanished RECORD event now, not a mark
  }
  return { records, marks, events };
}

// sealAndStore seals a list of (buffered-value) D1 records into a full archive and returns a MockR2
// holding every object, so the verifying reader + restore path can open it. The per-page D1 records
// seal through the buffered put() path (each page is a bounded value), not putStream.
async function sealAndStore(records: SourceRecord[], signer: Signer, recipients: RecipientEntry[], runId: string, downpipeId: string): Promise<MockR2> {
  const archive = await buildArchive({
    downpipeId,
    downpipeName: "d1",
    cadence: "3600s",
    runId,
    master: rand(32),
    recipients,
    signer,
    records: records.map((r) => ({ sourceType: "d1" as const, name: r.name, value: r.value!, ...(r.descriptor ? { descriptor: r.descriptor } : {}) })),
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const r2 = new MockR2();
  for (const [k, b] of archive) r2.store.set(k, b);
  return r2;
}

// The shared restore context: the signer + recipients + the env factory that threads the signer/operational
// keys into a per-call Env, plus the sealed archive and the source's per-page record sequence. The PROOF
// clusters below take this so each runs as its own named function rather than one 190-line main().
interface D1RestoreCtx {
  signer: Signer;
  signerPrivateB64: string;
  operationalPrivateB64: string;
  recipients: RecipientEntry[];
  envWith: (db: MockD1, r2: MockR2) => Env;
  r2: MockR2;
  recs: SourceRecord[];
}

// ---- PROOF 1: the SOURCE emits a RESUMABLE SEQUENCE (header, row pages, schema) ----
// crawlFrom yields buffered per-page records interleaved with resume marks; the whole DB is never
// one value. The header is first, the schema last, and the rows records carry their table+columns.
async function proveSourceSequence(ctx: Omit<D1RestoreCtx, "recs">, usersRows: D1Cell[][], notesRows: D1Cell[][], rowsPerPage: number): Promise<SourceRecord[]> {
  const buildFixtureSource = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("users", USERS_SQL, ["id", "name", "score", "avatar", "big"], usersRows.map((r) => [...r]));
    db.seedTable("notes", NOTES_SQL, ["id", "body"], notesRows.map((r) => [...r]));
    db.seedTable("_cf_KV", 'CREATE TABLE "_cf_KV" (k TEXT)', ["k"], [["internal"]]);
    db.seedSchema(IDX_SQL);
    return db;
  };

  const sourceDb = buildFixtureSource();
  const { records: recs, marks } = await collectCrawl(new D1Source(sourceDb as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, rowsPerPage).crawlFrom({ include: [], exclude: [] }, null));
  ok("D1 source opened a consistent-read session", sourceDb.sessions >= 1);
  ok("every emitted record is a d1 buffered value (no stream, whole DB never materialised)", recs.every((r) => r.sourceType === "d1" && r.value !== undefined && r.stream === undefined));
  ok("every record routes to the same database binding (name root is the db)", recs.every((r) => r.name.split("/")[0] === DB_NAME));

  const kinds = recs.map((r) => decodeD1Record(r.value!).kind);
  ok("the FIRST record is the header", kinds[0] === "header" && recs[0]!.descriptor?.d1Format === D1_HEADER_FORMAT);
  ok("the LAST record is the schema", kinds[kinds.length - 1] === "schema" && recs[recs.length - 1]!.descriptor?.d1Format === D1_SCHEMA_FORMAT);
  ok("the middle records are rows pages", kinds.slice(1, -1).every((k) => k === "rows") && recs.slice(1, -1).every((r) => r.descriptor?.d1Format === D1_ROWS_FORMAT));
  // users: 5 rows / page 2 -> 3 rows records; notes: 3 rows / page 2 -> 2 rows records. 5 total.
  ok("users emitted 3 rows pages and notes 2 (tiny page size forced multiple pages)", kinds.filter((k) => k === "rows").length === 5);

  const headerDec = decodeD1Record(recs[0]!.value!);
  ok("header captured the two user tables and skipped the internal _cf_ table", headerDec.kind === "header" && headerDec.tables.length === 2 && headerDec.tables.map((t) => t.name).sort().join(",") === "notes,users");
  const usersDDL = headerDec.kind === "header" ? headerDec.tables.find((t) => t.name === "users")! : undefined;
  ok("header preserved the exact CREATE TABLE text and column order", usersDDL?.sql === USERS_SQL && usersDDL?.columns.join(",") === "id,name,score,avatar,big");
  // A rows record carries its table name + columns + the page's rows (self-contained INSERT).
  const firstUsersRows = recs.map((r) => decodeD1Record(r.value!)).find((d) => d.kind === "rows" && d.table === "users");
  ok("a rows record carries the table name + columns + rows", firstUsersRows?.kind === "rows" && firstUsersRows.table === "users" && firstUsersRows.columns.join(",") === "id,name,score,avatar,big" && firstUsersRows.rows.length === 2);
  ok("a rows record tagged the BLOB cell as bytes", firstUsersRows?.kind === "rows" && JSON.stringify(firstUsersRows.rows[0]![3]) === JSON.stringify({ $blob: b64urlEncode(AVATAR) }));
  ok("a rows record tagged the out-of-range integer rather than narrowing it", firstUsersRows?.kind === "rows" && JSON.stringify(firstUsersRows.rows[0]![4]) === JSON.stringify({ $int: BIG_INT.toString() }));
  ok("a rows record carried the hostile name verbatim as a value", recs.map((r) => decodeD1Record(r.value!)).some((d) => d.kind === "rows" && d.rows.some((row) => row[1] === HOSTILE_NAME)));
  const schemaDec = decodeD1Record(recs[recs.length - 1]!.value!);
  ok("the schema record carries the non-table schema (the index)", schemaDec.kind === "schema" && schemaDec.schema.length === 1 && schemaDec.schema[0] === IDX_SQL);

  // CONSISTENCY: every mark threads the session snapshot bookmark, so a resumed slice re-opens the
  // same point in time across slices. A mark follows every record (the slice may checkpoint
  // after any record).
  ok("every mark threads the session bookmark (cross-slice consistency)", marks.length > 0 && marks.every((m) => JSON.parse(m).bookmark === MockD1.BOOKMARK));
  ok("a mark follows every record (a slice can checkpoint after any record)", marks.length >= recs.length);
  return recs;
}

// ---- PROOF 2-4: restore reconstructs the DB cell-for-cell, parameterises every value, dry-run writes nothing ----
async function proveArchiveRestore(ctx: D1RestoreCtx, usersRows: D1Cell[][], notesRows: D1Cell[][]): Promise<void> {
  const { envWith, r2, recs } = ctx;
  // ---- PROOF 2: confirm restore reconstructs the DB cell-for-cell from the SEQUENCE ----
  const targetDb = new MockD1();
  const applied = (await runRestore(envWith(targetDb, r2), { runId: RUN_ID, confirm: true })) as RestoreResult;
  ok("applied mode restored every per-page record with no failure", applied.ok === true && applied.mode === "applied" && applied.recordsRestored === recs.length && applied.failures.length === 0);
  ok("restore re-created both tables (from the header record)", targetDb.tables.has("users") && targetDb.tables.has("notes"));
  ok("restore re-created the index after the data (from the schema record)", targetDb.schema.length === 1 && targetDb.schema[0] === IDX_SQL);
  ok("restored users rows match the source CELL-FOR-CELL across all pages", rowsEq(targetDb.tables.get("users")!.rows, usersRows));
  ok("restored notes rows match the source CELL-FOR-CELL across all pages", rowsEq(targetDb.tables.get("notes")!.rows, notesRows));
  ok("restore never touched an internal table", !targetDb.tables.has("_cf_KV"));
  ok("inserts ran inside batch() transactions", targetDb.batches >= 1);
  // The fresh-target check ran exactly ONCE (on the header), not per rows record.
  const freshChecks = targetDb.capturedSql.filter((q) => /FROM sqlite_master WHERE type='table'/.test(q)).length;
  ok("the fresh-target check ran ONCE (on the header), not per record", freshChecks === 1);

  // ---- PROOF 3: parameterisation - no row VALUE appears in any SQL text ----
  // CAST(? AS INTEGER) is a bound placeholder (the int64 value is still bound, never interpolated), so
  // normalise it to a bare ? before the no-data check and accept it in the placeholder-shape check.
  const anyDataInSql = targetDb.capturedSql.some((q) => q.includes("DROP TABLE") || q.includes("alice") || /VALUES\s*\([^?)]*[A-Za-z0-9][^?)]*\)/.test(q.replace(/CAST\(\? AS INTEGER\)/gi, "?").replace(/\?/g, "")));
  ok("no row value was interpolated into SQL (all bound)", !anyDataInSql);
  ok("every INSERT uses placeholder parameters", targetDb.capturedSql.filter((q) => /^INSERT INTO/i.test(q)).every((q) => /VALUES\s*\(((\?|CAST\(\? AS INTEGER\))(,\s*)?)+\)/i.test(q)));

  // ---- PROOF 4: DRY-RUN (default) writes nothing into the target D1 ----
  const dryDb = new MockD1();
  const plan = await runRestore(envWith(dryDb, r2), { runId: RUN_ID });
  ok("dry-run verified every record and planned the writes", plan.ok === true && plan.mode === "dry-run" && plan.plannedWrites === recs.length);
  ok("DRY-RUN WROTE NOTHING into the target D1", dryDb.tables.size === 0 && dryDb.schema.length === 0 && dryDb.batches === 0);
}

// ---- PROOF 5-7: the sink edge cases (dry/foreign/non-empty), the reserved-binding refusal, the empty table ----
async function proveSinkEdgeCases(ctx: D1RestoreCtx, rowsPerPage: number): Promise<void> {
  const { envWith, r2, recs } = ctx;
  // ---- PROOF 5: dispatch + dry-mode + foreign-body + NON-EMPTY-AT-HEADER at the sink ----
  const headerBytes = recs[0]!.value!;
  const aRowsBytes = recs.find((r) => decodeD1Record(r.value!).kind === "rows")!.value!;
  const schemaBytes = recs[recs.length - 1]!.value!;
  // Dry mode decodes every kind and writes nothing.
  const sinkDryDb = new MockD1();
  const drySink = new D1RestoreSink(sinkDryDb as unknown as D1Database, DB_NAME, true);
  await drySink.put(DB_NAME, headerBytes);
  await drySink.put(DB_NAME, aRowsBytes);
  await drySink.put(DB_NAME, schemaBytes);
  ok("D1 sink dry mode wrote nothing for header/rows/schema", sinkDryDb.tables.size === 0 && sinkDryDb.batches === 0 && sinkDryDb.schema.length === 0);
  // A foreign-format body is refused before any write.
  let foreignRefused = false;
  try {
    await new D1RestoreSink(new MockD1() as unknown as D1Database, DB_NAME, false).put(DB_NAME, encodeForeignBody());
  } catch (e) {
    foreignRefused = /unsupported D1 record format|unsupported D1 backup format/.test((e as Error).message);
  }
  ok("D1 sink refuses a foreign-format body before writing", foreignRefused);
  // A NON-EMPTY target is refused AT THE HEADER (the fresh-target guarantee for the whole DB rides
  // the header; a dirty retry fails on the first record, before any row).
  const nonEmptyTarget = new MockD1();
  nonEmptyTarget.seedTable("pre_existing", 'CREATE TABLE "pre_existing" (id INTEGER)', ["id"], []);
  let headerRefused = false;
  try {
    await new D1RestoreSink(nonEmptyTarget as unknown as D1Database, DB_NAME, false).put(DB_NAME, headerBytes);
  } catch (e) {
    headerRefused = /not empty|fresh database/.test((e as Error).message);
  }
  ok("D1 sink refuses a NON-EMPTY target AT THE HEADER, nothing newly written", headerRefused && nonEmptyTarget.batches === 0 && nonEmptyTarget.tables.size === 1);
  // A rows record does NOT run the fresh-target check (the table already exists by the time it lands):
  // applied against a target that already holds the table, it appends without a fresh-target refusal.
  const existingTableDb = new MockD1();
  existingTableDb.seedTable("users", USERS_SQL, ["id", "name", "score", "avatar", "big"], []);
  existingTableDb.capturedSql.length = 0;
  await new D1RestoreSink(existingTableDb as unknown as D1Database, DB_NAME, false).put(DB_NAME, aRowsBytes);
  ok("a rows record does NOT run the fresh-target check (header already did)", !existingTableDb.capturedSql.some((q) => /FROM sqlite_master WHERE type='table'/.test(q)));
  ok("a rows record appended its page into the existing table", existingTableDb.tables.get("users")!.rows.length === 2);

  // ---- PROOF 6: a reserved D1 target binding is refused (no write) ----
  const reservedDb = new MockD1();
  const reservedEnv = envWith(reservedDb, r2);
  (reservedEnv as Record<string, unknown>)["SIGNER_PRIVATE_TARGET"] = reservedDb as unknown as D1Database;
  const refused = (await runRestore(reservedEnv, { runId: RUN_ID, confirm: true, target: { binding: "SIGNER_PRIVATE" } })) as RestoreResult;
  ok("reserved D1 target refused, nothing written", refused.ok === false && refused.reason === "target binding is reserved" && reservedDb.tables.size === 0);

  // ---- PROOF 7: an empty table round-trips (header creates it, no rows record, schema empty) ----
  const emptySource = new MockD1();
  emptySource.seedTable("empty", 'CREATE TABLE "empty" (id INTEGER)', ["id"], []);
  const emptyCrawl = await collectCrawl(new D1Source(emptySource as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, rowsPerPage).crawlFrom({ include: [], exclude: [] }, null));
  ok("empty table emits a header and a schema but NO rows record", emptyCrawl.records.map((r) => decodeD1Record(r.value!).kind).filter((k) => k === "rows").length === 0);
  const emptyTargetDb = new MockD1();
  for (const r of emptyCrawl.records) await new D1RestoreSink(emptyTargetDb as unknown as D1Database, DB_NAME, false).put(r.name, r.value!);
  ok("empty table re-created with zero rows", emptyTargetDb.tables.has("empty") && emptyTargetDb.tables.get("empty")!.rows.length === 0);
}

// ---- PROOF 10: a malformed D1 body is rejected AT DRY-RUN, with zero writes ----
async function proveMalformedRejected(ctx: D1RestoreCtx): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  const malformedR2 = await sealAndStore(
    [{ sourceType: "d1", name: DB_NAME, value: encodeForeignBody() }],
    signer, recipients, RUN_ID, "dp_d1_bad",
  );
  const badDb = new MockD1();
  const badPlan = (await runRestore(envWith(badDb, malformedR2), { runId: RUN_ID })) as Awaited<ReturnType<typeof runRestore>> & {
    mode: string; ok: boolean; plannedWrites: number; recordsVerified: number; skipped: { name: string; reason: string }[];
  };
  ok("malformed D1 body: dry-run reports NOT-ok (the body would not replay)", badPlan.mode === "dry-run" && badPlan.ok === false);
  ok("malformed D1 body: dry-run plans NO write", badPlan.plannedWrites === 0 && badPlan.recordsVerified === 0);
  ok("malformed D1 body: dry-run names the unreplayable record in skipped", badPlan.skipped.some((s) => /would not replay|malformed/i.test(s.reason)));
  ok("malformed D1 body: DRY-RUN WROTE NOTHING into the target D1", badDb.tables.size === 0 && badDb.schema.length === 0 && badDb.batches === 0);
}

// ---- PROOF 12: windowed in-account D1 is ALL-OR-NOTHING ----
// A D1 database restores as header(requireFreshTarget+CREATE) + many row pages + schema, which must travel
// together. RestoreRequest has only maxRecords (no offset/cursor), so a window that CUT a D1 in half used to
// write header+some rows, mark the rest outOfWindow, and tell the operator to "re-run with a higher
// maxRecords" -- but a re-run restarts at record 0, the header's requireFreshTarget re-runs against the
// now-non-empty DB and throws, failing the whole D1 (and the rows would double). The fix: a single D1 that
// does not fully fit the window is NOT partially applied (steered offline), so a re-run can never hit the
// non-empty-target throw; and the guidance steers a D1 OFFLINE rather than giving the impossible re-run
// advice. KV/R2 windowing is unchanged (idempotent). The OLD code partially applied the header (tables
// created, batches > 0); this proves the target stays untouched and a later full restore still works.
async function proveWindowedD1AllOrNothing(ctx: Omit<D1RestoreCtx, "recs" | "r2">, rowsPerPage: number): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  // A D1 with several row pages so a small maxRecords cuts THROUGH it: 6 users / page 2 = 3 rows pages, so
  // the sequence is header + 3 rows + schema = 5 records.
  const buildSource = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("users", USERS_SQL, ["id", "name", "score", "avatar", "big"], [
      [1, "a", 1, null, 1], [2, "b", 2, null, 2], [3, "c", 3, null, 3],
      [4, "d", 4, null, 4], [5, "e", 5, null, 5], [6, "f", 6, null, 6],
    ]);
    db.seedSchema(IDX_SQL);
    return db;
  };
  const D1_RUN = "01ARZ3NDEKTSV4RRFFQ69G5D12";
  const { records: recs } = await collectCrawl(new D1Source(buildSource() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, rowsPerPage).crawlFrom({ include: [], exclude: [] }, null));
  ok("fixture: the D1 is a multi-record sequence (header + rows + schema)", recs.length >= 5 && decodeD1Record(recs[0]!.value!).kind === "header" && decodeD1Record(recs[recs.length - 1]!.value!).kind === "schema");
  const r2 = await sealAndStore(recs, signer, recipients, D1_RUN, "dp_d1_window");
  const CUT = 3; // 3 < recs.length, so the window CUTS the single D1 mid-sequence

  // APPLY with a window that cuts the D1: the D1 must NOT be partially applied. The target stays a fresh,
  // empty DB (no tables created, no batches run, no fresh-target check even reached), and the result is
  // honestly partial: windowed, complete:false, outOfWindow = every D1 record, with the OFFLINE guidance.
  const targetDb = new MockD1();
  const applied = (await runRestore(envWith(targetDb, r2), { runId: D1_RUN, confirm: true, maxRecords: CUT })) as RestoreResult;
  ok("a windowed cut leaves the D1 target UNTOUCHED (no header-only write: 0 tables, 0 batches)", targetDb.tables.size === 0 && targetDb.batches === 0 && !targetDb.capturedSql.some((q) => /CREATE TABLE/i.test(q)));
  ok("the cut D1 was NOT counted as restored (all-or-nothing, nothing applied)", applied.recordsRestored === 0 && applied.failures.length === 0);
  ok("the apply is honestly partial (windowed, complete:false, outOfWindow = the whole D1)", applied.windowed === true && applied.complete === false && applied.outOfWindow === recs.length);
  const appliedMarker = (applied.skipped ?? []).find((s) => s.name === "(window)");
  // The marker must carry the D1-specific honesty the OLD single message lacked: it names the D1 as NOT
  // partially applied + an in-account D1 restore as NOT resumable, and steers it to the offline CLI -- the
  // OLD message ("re-run with a higher maxRecords or recover the full run offline") said none of that.
  ok("the apply (window) marker steers the D1 OFFLINE with the not-resumable honesty (not the OLD generic message)", appliedMarker !== undefined && /not resumable/i.test(appliedMarker.reason) && /not partially applied/i.test(appliedMarker.reason) && /offline with the downpipe CLI/i.test(appliedMarker.reason));

  // THE CORRUPTION IS GONE: because the windowed cut wrote NOTHING, the target is still fresh, so a later
  // FULL restore (no maxRecords) into the SAME target succeeds end to end. The OLD code would have left a
  // header-only DB here, and this full restore's requireFreshTarget would throw "target is not empty".
  const full = (await runRestore(envWith(targetDb, r2), { runId: D1_RUN, confirm: true })) as RestoreResult;
  ok("a later FULL restore into the still-fresh target SUCCEEDS (no non-empty-target throw)", full.ok === true && full.recordsRestored === recs.length && full.complete === true && full.failures.length === 0);
  ok("the full restore created the table and all rows landed", targetDb.tables.has("users") && targetDb.tables.get("users")!.rows.length === 6);

  // A DRY-RUN with the same cut is equally honest: it previews the D1 as out of window with the offline
  // guidance and writes nothing (the OLD dry-run would have planned/decoded the header into the cut window).
  const dryDb = new MockD1();
  const dry = (await runRestore(envWith(dryDb, r2), { runId: D1_RUN, maxRecords: CUT })) as RestorePlan;
  const dryMarker = dry.skipped.find((s) => s.name === "(window)");
  ok("the DRY-RUN is honestly partial and steers the D1 offline with the not-resumable honesty", dry.windowed === true && dry.complete === false && dryMarker !== undefined && /not resumable/i.test(dryMarker.reason) && /offline with the downpipe CLI/i.test(dryMarker.reason));
  ok("the cut DRY-RUN decoded NOTHING into the target (no partial-D1 plan)", dryDb.tables.size === 0 && dryDb.batches === 0);

  // A window that FITS the whole D1 still applies it normally (the fix only changes the cut case). maxRecords
  // >= recs.length admits the entire sequence into a fresh target.
  const fitDb = new MockD1();
  const fit = (await runRestore(envWith(fitDb, r2), { runId: D1_RUN, confirm: true, maxRecords: recs.length })) as RestoreResult;
  ok("a window that FITS the whole D1 applies it normally (complete, all rows)", fit.ok === true && fit.complete === true && fit.recordsRestored === recs.length && fitDb.tables.get("users")!.rows.length === 6);
}

// ---- PROOF 13 (D1 table-subset FK lint): a dry-run whose scope drops a SELECTED child's FK parent
// surfaces RestorePlan.dependencyWarnings; a whole-DB restore surfaces none. The lint is a READ-ONLY
// advisory (D1 restores with FK enforcement off), so the subset restore is still a valid, ok dry-run. ----
async function proveDependencyLint(ctx: Omit<D1RestoreCtx, "recs" | "r2">): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  const PARENT_SQL = 'CREATE TABLE "users" (id INTEGER PRIMARY KEY, name TEXT)';
  const CHILD_SQL = 'CREATE TABLE "orders" (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id))';
  const buildSource = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("users", PARENT_SQL, ["id", "name"], [[1, "alice"], [2, "bob"]]); // ti=0 (parent)
    db.seedTable("orders", CHILD_SQL, ["id", "user_id"], [[10, 1], [11, 2]]); // ti=1 (child -> users)
    return db;
  };
  const FK_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FK1";
  const { records: recs } = await collectCrawl(new D1Source(buildSource() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));
  const r2 = await sealAndStore(recs, signer, recipients, FK_RUN, "dp_d1_fk");

  // Whole-DB dry-run: both tables in scope -> NO dependency warnings at all.
  const wholePlan = (await runRestore(envWith(new MockD1(), r2), { runId: FK_RUN })) as RestorePlan;
  ok("FK lint: a whole-DB restore surfaces NO dependency warnings", wholePlan.ok === true && wholePlan.dependencyWarnings === undefined);

  // Table-subset dry-run: EXCLUDE the parent (users, ti=0 -> "10-rows/000000-...") and keep the child.
  // The child is selected, its FK parent is not -> exactly one advisory warning; the restore is still a
  // valid ok dry-run because the header still creates the (empty) parent table and FK enforcement is off.
  const subsetPlan = (await runRestore(envWith(new MockD1(), r2), { runId: FK_RUN, exclude: [`${DB_NAME}/10-rows/000000-`] })) as RestorePlan;
  ok("FK lint: dropping the parent's rows still yields a valid (ok) dry-run", subsetPlan.ok === true);
  const w = subsetPlan.dependencyWarnings ?? [];
  ok("FK lint: the subset restore surfaces exactly one dependency warning (child -> missing parent)", w.length === 1 && w[0]!.database === DB_NAME && w[0]!.table === "orders" && w[0]!.missingParent === "users");
  ok("FK lint: the parent's row page was genuinely excluded from the plan (a real subset)", subsetPlan.skipped.some((s) => s.name.startsWith(`${DB_NAME}/10-rows/000000-`)));

  // Header OUT of scope (excluded) but the child's rows in scope: the lint still finds the header in the
  // run (run.records, any scope) and still warns -- it does not depend on the header being admitted.
  const hdrOut = (await runRestore(envWith(new MockD1(), r2), { runId: FK_RUN, exclude: [`${DB_NAME}/00-header`, `${DB_NAME}/10-rows/000000-`] })) as RestorePlan;
  const w2 = hdrOut.dependencyWarnings ?? [];
  ok("FK lint: warns even when the header itself is out of scope (found via run.records)", w2.length === 1 && w2[0]!.table === "orders" && w2[0]!.missingParent === "users");

  // REGRESSION (empty-parent false positive): an EMPTY FK parent has NO row pages, so a whole-DB restore
  // drops nothing and must surface NO warning -- the short-circuit + parent-has-data filter catch this.
  const buildEmptyParent = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("users", PARENT_SQL, ["id", "name"], []); // EMPTY parent, ti=0 (no row page emitted)
    db.seedTable("orders", CHILD_SQL, ["id", "user_id"], [[10, 1], [11, 2]]); // child WITH rows, ti=1
    return db;
  };
  const EMPTY_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FK2";
  const { records: emptyRecs } = await collectCrawl(new D1Source(buildEmptyParent() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));
  const emptyR2 = await sealAndStore(emptyRecs, signer, recipients, EMPTY_RUN, "dp_d1_fk_empty");
  const emptyPlan = (await runRestore(envWith(new MockD1(), emptyR2), { runId: EMPTY_RUN })) as RestorePlan;
  ok("FK lint: an EMPTY parent on a whole-DB restore surfaces NO warning (nothing dropped)", emptyPlan.ok === true && emptyPlan.dependencyWarnings === undefined);
}

// ---- PROOF 14 (D1 TABLE-SUBSET restore, Stage 2): d1Tables scopes a restore to chosen tables of one
// database (header + schema + only those tables' rows, into a fresh DB), reuses the Stage 1 FK lint,
// refuses unknown tables/db and a recordName combination, and binds the selection into the plan hash. ----
async function proveTableSubset(ctx: Omit<D1RestoreCtx, "recs" | "r2">): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  const U = 'CREATE TABLE "users" (id INTEGER PRIMARY KEY, name TEXT)';
  const O = 'CREATE TABLE "orders" (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id))';
  const P = 'CREATE TABLE "products" (id INTEGER PRIMARY KEY, title TEXT)';
  const build = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("users", U, ["id", "name"], [[1, "alice"], [2, "bob"]]); // ti=0 (parent)
    db.seedTable("orders", O, ["id", "user_id"], [[10, 1], [11, 2], [12, 1]]); // ti=1 (child -> users)
    db.seedTable("products", P, ["id", "title"], [[100, "widget"]]); // ti=2 (independent)
    return db;
  };
  const RUN = "01ARZ3NDEKTSV4RRFFQ69G5TS1";
  const { records: recs } = await collectCrawl(new D1Source(build() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));
  const r2 = await sealAndStore(recs, signer, recipients, RUN, "dp_d1_subset");

  // Dry-run: select ONLY orders. Header + schema + orders rows are in scope; users/products rows excluded.
  const dry = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: DB_NAME, tables: ["orders"] } })) as RestorePlan;
  ok("d1Tables dry-run: ok, planned exactly header + schema + the orders page", dry.ok === true && dry.plannedWrites === 3 && dry.sample.every((s) => s.name === `${DB_NAME}/00-header` || s.name === `${DB_NAME}/20-schema` || s.name.startsWith(`${DB_NAME}/10-rows/000001-orders/`)));
  ok("d1Tables dry-run: the unselected tables' rows were excluded", dry.skipped.some((s) => s.name.startsWith(`${DB_NAME}/10-rows/000000-users/`)) && dry.skipped.some((s) => s.name.startsWith(`${DB_NAME}/10-rows/000002-products/`)));
  ok("d1Tables dry-run: selecting a child without its parent reuses the Stage 1 FK lint", (dry.dependencyWarnings ?? []).some((w) => w.table === "orders" && w.missingParent === "users"));

  // Apply: select users + orders into a FRESH DB. The header creates ALL three tables (full schema);
  // users + orders are populated; products is created but empty.
  const target = new MockD1();
  const applied = (await runRestore(envWith(target, r2), { runId: RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["users", "orders"] } })) as RestoreResult;
  ok("d1Tables apply: ok, restored header + schema + users + orders (4 records)", applied.ok === true && applied.recordsRestored === 4 && applied.failures.length === 0);
  ok("d1Tables apply: the fresh DB created ALL tables (full schema from the header)", target.tables.has("users") && target.tables.has("orders") && target.tables.has("products"));
  ok("d1Tables apply: only the selected tables were populated (products left empty)", target.tables.get("users")!.rows.length === 2 && target.tables.get("orders")!.rows.length === 3 && target.tables.get("products")!.rows.length === 0);

  // Validation: an unknown table name is refused loudly (nothing written).
  const badTarget = new MockD1();
  const badTable = (await runRestore(envWith(badTarget, r2), { runId: RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["nope"] } })) as RestoreResult;
  ok("d1Tables: an unknown table name is refused, nothing written", badTable.ok === false && /table not found/.test(badTable.reason ?? "") && badTarget.tables.size === 0);
  // Validation: an unknown database is refused.
  const badDb = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: "no_such_db", tables: ["users"] } })) as RestorePlan;
  ok("d1Tables: an unknown database is refused", badDb.ok === false && /database not found/.test(badDb.reason ?? ""));
  // Validation: d1Tables + recordName is mutually exclusive.
  const both = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: DB_NAME, tables: ["users"] }, recordName: `${DB_NAME}/00-header` })) as RestorePlan;
  ok("d1Tables + recordName is refused as mutually exclusive", both.ok === false && /cannot be combined/.test(both.reason ?? ""));
  // Case-insensitive table matching against the header.
  const ci = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: DB_NAME, tables: ["USERS"] } })) as RestorePlan;
  ok("d1Tables: table names match case-insensitively", ci.ok === true && ci.sample.some((s) => s.name.startsWith(`${DB_NAME}/10-rows/000000-users/`)));

  // Plan-hash binding: d1Tables changes the approval hash, is order-independent, and distinguishes selections.
  const hWhole = await restorePlanHash({ runId: RUN });
  const hAB = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["users", "orders"] } });
  const hBA = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["orders", "users"] } });
  const hA = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["users"] } });
  ok("d1Tables plan hash: differs from a whole-DB restore (its own approval)", hAB !== hWhole);
  ok("d1Tables plan hash: order-independent (a set)", hAB === hBA);
  ok("d1Tables plan hash: a different table selection is a different hash", hA !== hAB);
  const hUsers = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["users"] } });
  const hUSERS = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["USERS"] } });
  ok("d1Tables plan hash: case-insensitive on table names (matches the resolution)", hUsers === hUSERS);

  // SECURITY (forged-benign cue class): d1Tables SUPERSEDES include/exclude, so a broad exclude cannot make
  // the plan look like "0 writes". This is the semantic the /restore/request cue recomputation relies on
  // (it now passes d1Tables into the recomputed dry-run, so the approver sees the true subset cues).
  const forged = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: DB_NAME, tables: ["orders"] }, exclude: [`${DB_NAME}/`] })) as RestorePlan;
  ok("d1Tables supersedes a broad exclude (cannot forge a 0-write plan)", forged.ok === true && forged.plannedWrites === 3);

  // d1Tables + a small maxRecords that CUTS the subset: a D1 subset is all-or-nothing, never partially
  // applied (header + selected rows + schema travel together, exactly like a whole-DB windowed cut).
  const cutTarget = new MockD1();
  const cut = (await runRestore(envWith(cutTarget, r2), { runId: RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["users", "orders"] }, maxRecords: 2 })) as RestoreResult;
  ok("d1Tables + small maxRecords: the subset is NOT partially applied (all-or-nothing)", cutTarget.tables.size === 0 && cutTarget.batches === 0 && cut.recordsRestored === 0 && cut.windowed === true && cut.complete === false);

  // Multi-page: a selected table that spans several row pages has ALL its pages restored (rowsPerPage=1).
  const { records: mpRecs } = await collectCrawl(new D1Source(build() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 1).crawlFrom({ include: [], exclude: [] }, null));
  const MP_RUN = "01ARZ3NDEKTSV4RRFFQ69G5TS2";
  const mpR2 = await sealAndStore(mpRecs, signer, recipients, MP_RUN, "dp_d1_mp");
  const mpTarget = new MockD1();
  await runRestore(envWith(mpTarget, mpR2), { runId: MP_RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["orders"] } });
  ok("d1Tables: a multi-page selected table has ALL its pages restored (others empty)", mpTarget.tables.get("orders")!.rows.length === 3 && mpTarget.tables.get("users")!.rows.length === 0 && mpTarget.tables.get("products")!.rows.length === 0);

  // Legacy whole-dump DB: table-subset restore is refused (there is no per-table header to resolve against).
  const legacyBody = encodeD1Backup({ format: D1_BACKUP_FORMAT, tables: [{ name: "users", sql: U, columns: ["id", "name"], rows: [[1, "a"]] }], schema: [] });
  const LEGACY_RUN = "01ARZ3NDEKTSV4RRFFQ69G5TS3";
  const legacyR2 = await sealAndStore([{ sourceType: "d1", name: "legacy_db", value: legacyBody }], signer, recipients, LEGACY_RUN, "dp_d1_legacy");
  const legacy = (await runRestore(envWith(new MockD1(), legacyR2), { runId: LEGACY_RUN, d1Tables: { database: "legacy_db", tables: ["users"] } })) as RestorePlan;
  ok("d1Tables: a legacy whole-dump DB is refused (no per-table header)", legacy.ok === false && /no per-table header|not found/.test(legacy.reason ?? ""));

  // Dirty target: a table-subset apply still runs the header's fresh-target check and refuses a non-empty DB.
  const dirty = new MockD1();
  dirty.seedTable("pre_existing", 'CREATE TABLE "pre_existing" (id INTEGER)', ["id"], []);
  const dirtyRes = (await runRestore(envWith(dirty, r2), { runId: RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["users"] } })) as RestoreResult;
  ok("d1Tables apply: a NON-EMPTY target is refused by the fresh-target check (nothing new written)", dirtyRes.ok === false && dirtyRes.failures.some((f) => /fresh database|partial restore/.test(f.reason)) && dirty.tables.size === 1);

  // Malformed selections are refused cleanly (empty list, or a non-array value from the wire).
  const emptyList = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: DB_NAME, tables: [] } })) as RestorePlan;
  ok("d1Tables: an empty tables list is refused", emptyList.ok === false && /non-empty list/.test(emptyList.reason ?? ""));
  const nonArray = (await runRestore(envWith(new MockD1(), r2), { runId: RUN, d1Tables: { database: DB_NAME, tables: "users" as unknown as string[] } })) as RestorePlan;
  ok("d1Tables: a non-array tables value is refused (defensive against a malformed body)", nonArray.ok === false && /non-empty list/.test(nonArray.reason ?? ""));
}

// ---- PROOF 15 (D1 table-subset createOnly, Stage 3): d1Tables.createOnly makes the fresh DB contain ONLY
// the selected tables (a minimal extract) -- their indexes/triggers kept, dropped tables' indexes dropped,
// bound distinctly into the plan hash -- while the default (no createOnly) keeps the full schema. ----
async function proveTableSubsetCreateOnly(ctx: Omit<D1RestoreCtx, "recs" | "r2">): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  const U = 'CREATE TABLE "users" (id INTEGER PRIMARY KEY, name TEXT)';
  const O = 'CREATE TABLE "orders" (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id))';
  const P = 'CREATE TABLE "products" (id INTEGER PRIMARY KEY, title TEXT)';
  const IDX_U = 'CREATE INDEX "idx_users_name" ON "users" (name)';
  const IDX_P = 'CREATE INDEX "idx_products_title" ON "products" (title)';
  // A kept-table index whose NAME contains the word "on" (a parser trap: it must resolve to users, not
  // the "on date" inside the name), so the createOnly keep-predicate keeps it.
  const IDX_ON = 'CREATE INDEX "sorted on date" ON "users" (name)';
  const build = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("users", U, ["id", "name"], [[1, "alice"]]); // ti=0
    db.seedTable("orders", O, ["id", "user_id"], [[10, 1]]); // ti=1 (FK -> users)
    db.seedTable("products", P, ["id", "title"], [[100, "widget"]]); // ti=2
    db.seedSchema(IDX_U);
    db.seedSchema(IDX_P);
    db.seedSchema(IDX_ON);
    return db;
  };
  const RUN = "01ARZ3NDEKTSV4RRFFQ69G5C01";
  const { records: recs } = await collectCrawl(new D1Source(build() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));
  const r2 = await sealAndStore(recs, signer, recipients, RUN, "dp_d1_createonly");

  // createOnly apply: the fresh DB has ONLY users + orders; the index on the kept users table is created,
  // the index on the dropped products table is not.
  const target = new MockD1();
  const applied = (await runRestore(envWith(target, r2), { runId: RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["users", "orders"], createOnly: true } })) as RestoreResult;
  ok("createOnly apply: ok, no failures", applied.ok === true && applied.failures.length === 0);
  ok("createOnly: ONLY the selected tables are created (products absent)", target.tables.has("users") && target.tables.has("orders") && !target.tables.has("products"));
  ok("createOnly: the selected tables are populated", target.tables.get("users")!.rows.length === 1 && target.tables.get("orders")!.rows.length === 1);
  ok("createOnly: a kept table's index is created; a dropped table's index is NOT", target.schema.includes(IDX_U) && !target.schema.includes(IDX_P));
  ok("createOnly: a kept table's index whose NAME contains 'on' is kept (parser is name-safe)", target.schema.includes(IDX_ON));

  // Contrast: WITHOUT createOnly the same selection creates ALL tables (full schema) incl. products + its index.
  const full = new MockD1();
  await runRestore(envWith(full, r2), { runId: RUN, confirm: true, d1Tables: { database: DB_NAME, tables: ["users", "orders"] } });
  ok("default (no createOnly): ALL tables + indexes created (products present but empty)", full.tables.has("products") && full.tables.get("products")!.rows.length === 0 && full.schema.includes(IDX_P));

  // Plan hash: createOnly is bound (a distinct approval from the full-schema restore of the same tables).
  const hCreateOnly = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["users"], createOnly: true } });
  const hFull = await restorePlanHash({ runId: RUN, d1Tables: { database: DB_NAME, tables: ["users"] } });
  ok("createOnly plan hash: distinct from the full-schema restore of the same tables", hCreateOnly !== hFull);
}

// ---- PROOF 17 (REGRESSION, rehearsal): a whole-DB restore whose header refuses a non-empty
// target must write NOTHING AT ALL, not just skip the header. Before this fix the apply loop kept
// attempting every LATER D1 record for that same database once the header's fresh-target guard had
// already refused it: a rows record then fails loudly on its own (no such table, or -- on a real D1, a
// PRIMARY KEY collision -- this mock does not enforce uniqueness, which is exactly why it would otherwise
// mask the bug), but the SCHEMA record (CREATE INDEX/TRIGGER/VIEW) carries no fresh-target check of its
// own, so it still ran -- against a table the target already held, never one this restore created -- and
// the apply counted it as a genuine restored record on a run whose own headline was "refused, target not
// empty". This reproduces the live rehearsal finding: two of three archived tables already exist (one was
// dropped and is being recovered), and the archive's schema carries an index on a SURVIVING table. ----
async function proveDirtyTargetBlocksAllLaterRecords(ctx: Omit<D1RestoreCtx, "recs" | "r2">): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  const CUSTOMERS = 'CREATE TABLE "customers" (id INTEGER PRIMARY KEY, name TEXT)';
  const ORDERS = 'CREATE TABLE "orders" (id INTEGER PRIMARY KEY, customer_id INTEGER)';
  const IDX_ORDERS = 'CREATE INDEX "idx_orders_customer" ON "orders" (customer_id)';
  const build = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("customers", CUSTOMERS, ["id", "name"], [[1, "alice"]]);
    db.seedTable("orders", ORDERS, ["id", "customer_id"], [[10, 1]]);
    db.seedSchema(IDX_ORDERS);
    return db;
  };
  const RUN = "01ARZ3NDEKTSV4RRFFQ69G5D01";
  const { records: recs } = await collectCrawl(new D1Source(build() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));
  const r2 = await sealAndStore(recs, signer, recipients, RUN, "dp_d1_dirty_schema");

  // The dirty target already has "customers" (a live database carrying SOME of its archived tables,
  // exactly the rehearsal shape) but not "orders", which is what this restore is trying to bring back.
  const dirty = new MockD1();
  dirty.seedTable("customers", CUSTOMERS, ["id", "name"], [[1, "alice"]]);
  const applied = (await runRestore(envWith(dirty, r2), { runId: RUN, confirm: true })) as RestoreResult;

  ok("dirty whole-DB restore: ok is false (header refused, target not empty)", applied.ok === false);
  ok("dirty whole-DB restore: NOTHING is counted as restored, not even the schema record", applied.recordsRestored === 0 && applied.bytesRestored === 0);
  ok("dirty whole-DB restore: every in-scope record is reported as a failure, none silently skipped", applied.failures.length === applied.recordsVerified);
  ok("dirty whole-DB restore: the orders table was never created", !dirty.tables.has("orders"));
  ok("dirty whole-DB restore: the archive's index was NEVER applied to the live customers table", dirty.schema.length === 0);
  ok("dirty whole-DB restore: the pre-existing customers table is untouched (still 1 row)", dirty.tables.get("customers")!.rows.length === 1);
}

// ---- PROOF 16 (D1-BIGINT): int64 values past 2^53 and large rowids survive capture EXACTLY through the
// typed projection, on BOTH the keyset (rowid) path and the WITHOUT-ROWID single-pass path. The mock's
// plain (non-typed) read TRUNCATES a >2^53 integer to float64 exactly as real D1 does, so this proof is a
// REGRESSION TRAP: reverting the typed projection makes the source decode the truncated number and the
// exact-decimal assertions below fail. It also proves the {$int} restore binds a decimal string under
// CAST(? AS INTEGER) (never a bigint bind, which real D1 rejects). ----
async function proveIntegerPrecisionRoundTrip(ctx: Omit<D1RestoreCtx, "recs" | "r2">): Promise<void> {
  const { signer, recipients, envWith } = ctx;
  const MAX_I64 = "9223372036854775807"; // 2^63 - 1, SQLite INTEGER max
  const P53 = "9007199254740993"; // 2^53 + 1, the first integer a float64 cannot represent
  const BIG_ROWID = 9007199254740993n; // a rowid past 2^53 (the cursor must not truncate it either)

  // A rowid table whose integer column holds boundary int64s, AND whose rowids exceed 2^53.
  const IT_SQL = 'CREATE TABLE "ints" (id INTEGER PRIMARY KEY, n INTEGER)';
  const intRows: D1Cell[][] = [
    [1, { $int: P53 }],
    [2, { $int: MAX_I64 }],
    [3, { $int: `-${MAX_I64}` }],
    [4, 42], // an in-range integer still round-trips as a plain number
  ];
  // A WITHOUT ROWID table carrying >2^53 integers, to exercise pageWithoutRowid's typed projection.
  const WR_SQL = 'CREATE TABLE "wr" (k TEXT PRIMARY KEY, n INTEGER) WITHOUT ROWID';
  const wrRows: D1Cell[][] = [["a", { $int: P53 }], ["b", { $int: MAX_I64 }]];

  const build = (): MockD1 => {
    const db = new MockD1();
    db.seedTable("ints", IT_SQL, ["id", "n"], intRows.map((r) => [...r]));
    // Rowids past 2^53 so the CAST(_rowid_ AS TEXT) cursor is exercised (a plain rowid read would
    // truncate these and corrupt the keyset cursor).
    db.tables.get("ints")!.rowids = [BIG_ROWID, BIG_ROWID + 1n, BIG_ROWID + 2n, BIG_ROWID + 3n];
    db.seedTable("wr", WR_SQL, ["k", "n"], wrRows.map((r) => [...r]), true); // WITHOUT ROWID
    return db;
  };

  // rowsPerPage 50 so each table is one page; the keyset cursor still advances past 2^53 rowids.
  const { records: recs } = await collectCrawl(new D1Source(build() as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));

  // CAPTURE: the rows records carry the boundary integers as EXACT {$int} decimal strings, not truncated.
  const intPage = recs.map((r) => decodeD1Record(r.value!)).find((d) => d.kind === "rows" && d.table === "ints");
  ok("D1-BIGINT: the rowid table's row page was captured", intPage?.kind === "rows" && intPage.rows.length === 4);
  ok("D1-BIGINT: 2^53+1 survives capture EXACTLY as {$int} (not truncated)", intPage?.kind === "rows" && JSON.stringify(intPage.rows[0]![1]) === JSON.stringify({ $int: P53 }));
  ok("D1-BIGINT: int64 max (9223372036854775807) survives capture EXACTLY", intPage?.kind === "rows" && JSON.stringify(intPage.rows[1]![1]) === JSON.stringify({ $int: MAX_I64 }));
  ok("D1-BIGINT: a negative near-int64-min survives capture EXACTLY", intPage?.kind === "rows" && JSON.stringify(intPage.rows[2]![1]) === JSON.stringify({ $int: `-${MAX_I64}` }));
  ok("D1-BIGINT: an in-range integer stays a plain number (not needlessly tagged)", intPage?.kind === "rows" && intPage.rows[3]![1] === 42);

  // WITHOUT-ROWID path: pageWithoutRowid's typed projection captures its >2^53 integers exactly too.
  const wrPage = recs.map((r) => decodeD1Record(r.value!)).find((d) => d.kind === "rows" && d.table === "wr");
  ok("D1-BIGINT: the WITHOUT-ROWID table was read via pageWithoutRowid (single page)", wrPage?.kind === "rows" && wrPage.rows.length === 2);
  ok("D1-BIGINT: a WITHOUT-ROWID table's 2^53+1 survives capture EXACTLY", wrPage?.kind === "rows" && JSON.stringify(wrPage.rows[0]![1]) === JSON.stringify({ $int: P53 }));
  ok("D1-BIGINT: a WITHOUT-ROWID table's int64 max survives capture EXACTLY", wrPage?.kind === "rows" && JSON.stringify(wrPage.rows[1]![1]) === JSON.stringify({ $int: MAX_I64 }));

  // RESTORE round-trip: seal + restore into a fresh DB, and confirm the boundary integers land cell-for-
  // cell (the {$int} restore binds a decimal string under CAST(? AS INTEGER), never a bigint bind).
  const PREC_RUN = "01ARZ3NDEKTSV4RRFFQ69G5B01";
  const r2 = await sealAndStore(recs, signer, recipients, PREC_RUN, "dp_d1_bigint");
  const target = new MockD1();
  const applied = (await runRestore(envWith(target, r2), { runId: PREC_RUN, confirm: true })) as RestoreResult;
  ok("D1-BIGINT: restore applied every record with no failure (no bigint bind rejected)", applied.ok === true && applied.failures.length === 0);
  ok("D1-BIGINT: the rowid table restored its boundary integers cell-for-cell", rowsEq(target.tables.get("ints")!.rows, intRows));
  ok("D1-BIGINT: the WITHOUT-ROWID table restored its boundary integers cell-for-cell", rowsEq(target.tables.get("wr")!.rows, wrRows));

  // WIDE-TABLE GUARD: the typed projection emits 2 result columns per declared column (+1 for the keyset
  // rowid cursor), so a table wide enough to exceed SQLite's 2000-column result-set limit must FAIL with a
  // NAMED, actionable error naming the table and its column count -- not a raw SQLite error, not a silent
  // skip. 1001 columns -> 2*1001+1 = 2003 result columns, over the bound.
  const WIDE_COLS = Array.from({ length: 1001 }, (_, i) => `c${i}`);
  const wideDb = new MockD1();
  wideDb.seedTable("wide", `CREATE TABLE "wide" (${WIDE_COLS.join(" INTEGER, ")} INTEGER)`, WIDE_COLS, [WIDE_COLS.map(() => 0)]);
  let wideErr = "";
  try {
    await collectCrawl(new D1Source(wideDb as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, 50).crawlFrom({ include: [], exclude: [] }, null));
  } catch (e) {
    wideErr = (e as Error).message;
  }
  ok("D1-BIGINT wide-table guard: a table too wide for the typed projection fails with a NAMED error (table + column count), not a raw SQLite error", /table wide has 1001 columns/.test(wideErr) && /2003 result columns/.test(wideErr) && /2000-column/.test(wideErr));
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  // The reader builds its own verifier from SIGNER_PRIVATE inside runRestore, so the restore proofs
  // exercise the full verify-then-restore chain end to end.

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // The fixture: two rowid tables (users exercises every cell kind: TEXT/INTEGER/NULL/BLOB/bigint;
  // notes is a second table so the sequence crosses a table boundary) plus an internal _cf_ table
  // the backup MUST skip, plus a non-table index. A tiny rowsPerPage forces MULTIPLE rows records
  // per table, so the per-page (resumable) path is exercised for real, not a single page.
  const ROWS_PER_PAGE = 2;
  const usersRows: D1Cell[][] = [
    [1, "alice", 100, { $blob: b64urlEncode(AVATAR) }, { $int: BIG_INT.toString() }],
    [2, HOSTILE_NAME, 0, null, 7],
    [3, null, -5, { $blob: b64urlEncode(new Uint8Array(0)) }, 0],
    [4, "dave", 42, { $blob: b64urlEncode(new Uint8Array([9, 9])) }, -1],
    [5, "erin", 7, null, 5],
  ];
  const notesRows: D1Cell[][] = [[1, "first note"], [2, "second"], [3, "third"]];

  // The env factory threads the signer/operational keys into a per-call Env (DEST_R2 filled per call).
  const baseEnv = (db: MockD1): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: undefined as unknown as R2Bucket, // filled per-call below
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
    [`D1_${DB_NAME}`]: db as unknown as D1Database,
  } as unknown as Env);
  const envWith = (db: MockD1, r2: MockR2): Env => ({ ...baseEnv(db), DEST_R2: r2 as unknown as R2Bucket } as unknown as Env);

  const recipients = [breakGlass.entry, op.entry];
  const ctxBase = { signer, signerPrivateB64, operationalPrivateB64, recipients, envWith };

  // PROOF 1: the source emits the resumable sequence.
  const recs = await proveSourceSequence(ctxBase as Omit<D1RestoreCtx, "recs">, usersRows, notesRows, ROWS_PER_PAGE);
  // Seal the per-page records into a real archive (each page seals through the buffered put path).
  const r2 = await sealAndStore(recs, signer, recipients, RUN_ID, "dp_d1");
  const ctx: D1RestoreCtx = { ...ctxBase, r2, recs };

  // PROOF 2-4: the archive restore proofs.
  await proveArchiveRestore(ctx, usersRows, notesRows);
  // PROOF 5-7: the sink edge cases, the reserved-binding refusal, the empty-table round-trip.
  await proveSinkEdgeCases(ctx, ROWS_PER_PAGE);
  // PROOF 8 (resume): crawlFrom from a mid-table token yields the remaining rows ONCE.
  await proveResumeRoundTrip(ROWS_PER_PAGE);
  // PROOF 9 (legacy): a whole-dump record (kind:"full") still restores unchanged.
  await proveLegacyFullRestore(signer, recipients, signerPrivateB64, operationalPrivateB64);
  // PROOF 10: a malformed D1 body is rejected AT DRY-RUN, with zero writes.
  await proveMalformedRejected(ctx);
  // PROOF 12: a windowed in-account D1 is ALL-OR-NOTHING (never partially applied) and its
  // guidance steers an unrestored D1 offline rather than the impossible "re-run with a higher maxRecords".
  await proveWindowedD1AllOrNothing(ctxBase as Omit<D1RestoreCtx, "recs" | "r2">, ROWS_PER_PAGE);
  // PROOF 13 (D1 table-subset FK lint): a subset restore that drops a selected child's FK parent surfaces
  // a read-only dependency warning; a whole-DB restore surfaces none.
  await proveDependencyLint(ctxBase as Omit<D1RestoreCtx, "recs" | "r2">);
  // PROOF 14 (D1 table-subset restore): d1Tables scopes to chosen tables, reuses the FK lint, validates.
  await proveTableSubset(ctxBase as Omit<D1RestoreCtx, "recs" | "r2">);
  // PROOF 15 (D1 table-subset createOnly): a minimal extract of only the selected tables + their indexes.
  await proveTableSubsetCreateOnly(ctxBase as Omit<D1RestoreCtx, "recs" | "r2">);
  // PROOF 16 (D1-BIGINT): int64 values past 2^53 and large rowids survive capture EXACTLY via the typed
  // projection (rowid and WITHOUT-ROWID paths); the mock's plain read truncates, so this traps a revert.
  await proveIntegerPrecisionRoundTrip(ctxBase as Omit<D1RestoreCtx, "recs" | "r2">);
  // PROOF 17 (REGRESSION): a dirty (non-empty) whole-DB restore target blocks EVERY later record for that
  // database once the header refuses it, including the schema record -- nothing is written, full stop.
  await proveDirtyTargetBlocksAllLaterRecords(ctxBase as Omit<D1RestoreCtx, "recs" | "r2">);

  // ---- PROOF 11 (format unit): the shape guards and cell helpers refuse every malformed body ----
  // These drive the d1-format decoders and cell coders directly so each guard rejects the exact
  // shape it defends against, and each cell helper round-trips or refuses the right values. The
  // bytes a decoder reads have already passed the archive plaintext hash, so this is a shape guard,
  // not a trust boundary: the point is a loud refusal of a foreign or future body, not security.
  proveDecodeD1BackupGuards();
  proveDecodeD1RecordGuards();
  // PROOF 13: the single-statement/quote-aware guard on every DDL/schema
  // decode entry point that D1RestoreSink replays into a live target (mirrors the Go downpipe CLI's
  // identical d1transcode.go fix).
  proveD1SingleStatementGuard();
  proveCellCoders();
  await proveStreamEncoderMatchesBuffered();

  console.log(failures === 0 ? "\nALL D1 RESTORE VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// The resume fixture: two PRIMARY-KEY tables so a mid-table resume token (afterRowid) and a
// table-boundary crossing are both exercised. proveResumeFirstPass / proveResumeSecondPass below split
// the multi-page crawl at the first/second-pass seam.
const RESUME_T1_SQL = 'CREATE TABLE "t1" (id INTEGER PRIMARY KEY, v TEXT)';
const RESUME_T2_SQL = 'CREATE TABLE "t2" (id INTEGER PRIMARY KEY, v TEXT)';
const RESUME_T1_ROWS: D1Cell[][] = Array.from({ length: 6 }, (_, i) => [i + 1, `r${i + 1}`]);
const RESUME_T2_ROWS: D1Cell[][] = [[100, "x"], [200, "y"]];

function seedResumeFixture(): MockD1 {
  const db = new MockD1();
  db.seedTable("t1", RESUME_T1_SQL, ["id", "v"], RESUME_T1_ROWS.map((r) => [...r]));
  db.seedTable("t2", RESUME_T2_SQL, ["id", "v"], RESUME_T2_ROWS.map((r) => [...r]));
  return db;
}

// The first pass: crawl from the start, find the mark right after t1's first rows page, and return the
// resume token plus the records the first slice would have sealed before checkpointing at that mark.
async function proveResumeFirstPass(rowsPerPage: number): Promise<{ resumeToken: string; firstSliceRecords: SourceRecord[] }> {
  const db1 = seedResumeFixture();
  const first = await collectCrawl(new D1Source(db1 as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, rowsPerPage).crawlFrom({ include: [], exclude: [] }, null));
  let resumeToken: string | null = null;
  for (let i = 0; i < first.events.length; i++) {
    const ev = first.events[i]!;
    if (ev.kind === "record" && decodeD1Record(ev.record.value!).kind === "rows") {
      const next = first.events[i + 1];
      if (next && next.kind === "mark") resumeToken = next.token;
      break;
    }
  }
  ok("resume: found a mid-table mark after the first rows page", resumeToken !== null && JSON.parse(resumeToken).phase === "rows" && JSON.parse(resumeToken).ti === 0 && JSON.parse(resumeToken).afterRowid === "2");
  ok("resume: the mark threads the session bookmark", JSON.parse(resumeToken!).bookmark === MockD1.BOOKMARK);

  // Records yielded up to and including the first rows page (header + page 0). These are the records
  // a first slice would have sealed before checkpointing at the resume mark.
  const firstSliceRecords: SourceRecord[] = [];
  for (const ev of first.events) {
    if (ev.kind === "record") firstSliceRecords.push(ev.record);
    if (ev.kind === "mark" && ev.token === resumeToken) break;
  }
  ok("resume: the first slice sealed the header + the first rows page", firstSliceRecords.length === 2 && decodeD1Record(firstSliceRecords[0]!.value!).kind === "header" && decodeD1Record(firstSliceRecords[1]!.value!).kind === "rows");
  return { resumeToken: resumeToken!, firstSliceRecords };
}

// The second pass: resume from the token, confirm the resumed rows are exactly the remainder (no loss,
// no duplication), then restore the first-slice + resumed records into one fresh DB cell-for-cell.
async function proveResumeSecondPass(rowsPerPage: number, resumeToken: string, firstSliceRecords: SourceRecord[]): Promise<void> {
  const db2 = seedResumeFixture();
  const resumed = await collectCrawl(new D1Source(db2 as unknown as D1Database, DB_NAME, D1_PAGE_BYTE_LIMIT, rowsPerPage).crawlFrom({ include: [], exclude: [] }, resumeToken));
  ok("resume: the resumed crawl re-opened the session at the carried bookmark (same snapshot)", db2.openedWith.includes(MockD1.BOOKMARK));
  ok("resume: the resumed crawl does NOT re-emit the header", resumed.records.every((r) => decodeD1Record(r.value!).kind !== "header"));

  // The resumed rows for t1 are exactly 3..6 (no rows <= 2, none duplicated), and t2 is whole.
  const resumedT1: D1Cell[][] = [];
  const resumedT2: D1Cell[][] = [];
  for (const r of resumed.records) {
    const d = decodeD1Record(r.value!);
    if (d.kind === "rows" && d.table === "t1") for (const row of d.rows) resumedT1.push(row);
    if (d.kind === "rows" && d.table === "t2") for (const row of d.rows) resumedT2.push(row);
  }
  ok("resume: t1 resumed rows are exactly 3..6 (no loss, no duplication, no rows<=2)", rowsEq(resumedT1, RESUME_T1_ROWS.slice(2)));
  ok("resume: t2 resumed rows are the whole second table (resume crossed the table boundary)", rowsEq(resumedT2, RESUME_T2_ROWS));

  // End-to-end: restore the FIRST-SLICE records THEN the RESUMED records into ONE fresh DB, in order,
  // and confirm the result is the source cell-for-cell -- the split-then-rejoin loses/duplicates nothing.
  const target = new MockD1();
  for (const r of [...firstSliceRecords, ...resumed.records]) {
    await new D1RestoreSink(target as unknown as D1Database, DB_NAME, false).put(r.name, r.value!);
  }
  ok("resume: first-slice + resumed records restore t1 cell-for-cell (exact split/rejoin)", rowsEq(target.tables.get("t1")!.rows, RESUME_T1_ROWS));
  ok("resume: first-slice + resumed records restore t2 cell-for-cell", rowsEq(target.tables.get("t2")!.rows, RESUME_T2_ROWS));
}

async function proveResumeRoundTrip(rowsPerPage: number): Promise<void> {
  // This proof exercises the source's resume seam and the sink directly (no seal/verify needed: the
  // round-trip through the archive is proven in PROOF 2; here the focus is the resume cursor).
  const { resumeToken, firstSliceRecords } = await proveResumeFirstPass(rowsPerPage);
  await proveResumeSecondPass(rowsPerPage, resumeToken, firstSliceRecords);
}

// proveLegacyFullRestore seals a LEGACY whole-database record (kind:"full", encodeD1Backup) and
// confirms it still restores unchanged through the dispatch, so an archive written before per-page
// resumability keeps restoring exactly as before.
async function proveLegacyFullRestore(
  signer: Signer,
  recipients: RecipientEntry[],
  signerPrivateB64: string,
  operationalPrivateB64: string,
): Promise<void> {
  const LEGACY_RUN = "01CXY2Z3ABCDEFGHJKMNPQRSTV";
  const legacyRows: D1Cell[][] = [[1, "one", { $blob: b64urlEncode(AVATAR) }], [2, "two", null]];
  const legacyBody = encodeD1Backup({
    format: D1_BACKUP_FORMAT,
    tables: [{ name: "legacy", sql: 'CREATE TABLE "legacy" (id INTEGER PRIMARY KEY, v TEXT, b BLOB)', columns: ["id", "v", "b"], rows: legacyRows }],
    schema: [IDX_LEGACY_SQL],
  });
  // Decode confirms the dispatch sees it as a whole-database body.
  ok("legacy: a whole-dump body decodes as kind:full", decodeD1Record(legacyBody).kind === "full");

  const r2 = await sealAndStore(
    [{ sourceType: "d1", name: "legacydb", value: legacyBody, descriptor: { d1Format: D1_BACKUP_FORMAT } }],
    signer, recipients, LEGACY_RUN, "dp_d1_legacy",
  );
  const targetDb = new MockD1();
  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
    ["D1_legacydb"]: targetDb as unknown as D1Database,
  } as unknown as Env;
  const applied = (await runRestore(env, { runId: LEGACY_RUN, confirm: true })) as RestoreResult;
  ok("legacy: the whole-dump record restored (kind:full path)", applied.ok === true && applied.recordsRestored === 1 && applied.failures.length === 0);
  ok("legacy: the table and its rows came back cell-for-cell", targetDb.tables.has("legacy") && rowsEq(targetDb.tables.get("legacy")!.rows, legacyRows));
  ok("legacy: the index applied after the rows", targetDb.schema.length === 1 && targetDb.schema[0] === IDX_LEGACY_SQL);
}

// encodeForeignBody builds a structurally valid JSON body that names a format this reader does
// not understand, to prove the sink refuses it rather than mis-replaying it.
function encodeForeignBody(): Uint8Array {
  return utf8(JSON.stringify({ format: "some-other-d1/9", tables: [], schema: [] }));
}

// bytesFor JSON-encodes an arbitrary value to the raw bytes a decoder reads (it does not go through
// the typed encoders, so a deliberately malformed body can be built that the encoders would reject).
function bytesFor(value: unknown): Uint8Array {
  return utf8(JSON.stringify(value));
}

// throwsWith runs decode over a body and reports whether it threw an Error whose message matches a
// pattern, so every guard is asserted by both REFUSING (it threw) and by NAMING the right reason
// (the message), not merely by not returning.
function throwsWith(run: () => unknown, pattern: RegExp): boolean {
  try {
    run();
    return false;
  } catch (e) {
    return e instanceof Error && pattern.test(e.message);
  }
}

// A minimal well-formed full-backup body, cloned and corrupted one field at a time below so each
// guard is exercised against an otherwise valid body (the failure is the field under test, nothing
// else). The base round-trips cleanly, which is asserted first.
function baseFullBody(): Record<string, unknown> {
  return {
    format: D1_BACKUP_FORMAT,
    tables: [{ name: "t", sql: 'CREATE TABLE "t" (id INTEGER, v TEXT)', columns: ["id", "v"], rows: [[1, "a"]] }],
    schema: ['CREATE INDEX "ix" ON "t" (v)'],
  };
}

// proveDecodeD1BackupGuards drives decodeD1Backup (and the validCell guard it calls per cell) over a
// clean body and then over every malformed shape, so each refusal branch and the per-cell guard are
// covered, with the message naming the field at fault.
function proveDecodeD1BackupGuards(): void {
  // A clean body decodes, including a tagged BLOB and a tagged big integer cell (so validCell's
  // object-cell legs run on a body that passes, not only on rejections).
  const cleanCells: D1Cell[][] = [[1, "a", { $blob: b64urlEncode(AVATAR) }, { $int: "9007199254740993" }]];
  const clean = decodeD1Backup(bytesFor({
    format: D1_BACKUP_FORMAT,
    tables: [{ name: "t", sql: 'CREATE TABLE "t" (id INTEGER, v TEXT, b BLOB, big INTEGER)', columns: ["id", "v", "b", "big"], rows: cleanCells }],
    schema: ['CREATE TRIGGER "tg" AFTER INSERT ON "t" BEGIN SELECT 1; END'],
  }));
  ok("decode: a clean full body decodes (tagged BLOB + tagged big integer cells pass validCell)", clean.tables.length === 1 && rowsEq(clean.tables[0]!.rows, cleanCells) && clean.schema.length === 1);

  // Body-level guards.
  ok("decode: non-JSON bytes are refused as not valid JSON", throwsWith(() => decodeD1Backup(utf8("{not json")), /not valid JSON/));
  ok("decode: a JSON primitive (a number) is refused as not an object", throwsWith(() => decodeD1Backup(bytesFor(5)), /not an object/));
  ok("decode: a JSON null is refused as not an object", throwsWith(() => decodeD1Backup(bytesFor(null)), /not an object/));
  ok("decode: a wrong format string is refused and names the supported format", throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), format: "downpipe-d1-json/9" })), /unsupported D1 backup format/));
  ok("decode: a body with no tables array is refused", throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), tables: "x" })), /no tables array/));
  ok("decode: a body with no schema array is refused", throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), schema: 7 })), /no schema array/));

  // Per-table guards (each replaces only the tables entry on an otherwise clean body).
  const withTable = (t: unknown): Record<string, unknown> => ({ ...baseFullBody(), tables: [t] });
  ok("decode: a non-object table entry is refused", throwsWith(() => decodeD1Backup(bytesFor(withTable(42))), /table entry is not an object/));
  ok("decode: a table with no name is refused", throwsWith(() => decodeD1Backup(bytesFor(withTable({ name: "", sql: 'CREATE TABLE "t" (id)', columns: [], rows: [] }))), /has no name/));
  ok("decode: a table with no CREATE statement is refused", throwsWith(() => decodeD1Backup(bytesFor(withTable({ name: "t", sql: "", columns: [], rows: [] }))), /has no CREATE statement/));
  ok("decode: a table whose sql is not a CREATE TABLE is refused (DDL-replay defence)", throwsWith(() => decodeD1Backup(bytesFor(withTable({ name: "t", sql: "DROP TABLE t", columns: [], rows: [] }))), /not a CREATE TABLE statement/));
  ok("decode: a table with a malformed column list is refused", throwsWith(() => decodeD1Backup(bytesFor(withTable({ name: "t", sql: 'CREATE TABLE "t" (id)', columns: [1, 2], rows: [] }))), /malformed column list/));
  ok("decode: a table with a non-array rows list is refused", throwsWith(() => decodeD1Backup(bytesFor(withTable({ name: "t", sql: 'CREATE TABLE "t" (id)', columns: ["id"], rows: {} }))), /malformed rows list/));
  ok("decode: a row whose cell count does not match the columns is refused", throwsWith(() => decodeD1Backup(bytesFor(withTable({ name: "t", sql: 'CREATE TABLE "t" (a, b)', columns: ["a", "b"], rows: [[1]] }))), /cell count does not match/));

  // Per-cell guards: each malformed cell shape validCell rejects (a row of the right arity carrying a
  // single bad cell), so the validCell false legs and final return-false are all driven.
  const oneCell = (cell: unknown): Record<string, unknown> => withTable({ name: "t", sql: 'CREATE TABLE "t" (a)', columns: ["a"], rows: [[cell]] });
  ok("decode: a boolean cell is refused (not a scalar/tagged form)", throwsWith(() => decodeD1Backup(bytesFor(oneCell(true))), /malformed cell/));
  ok("decode: an array-valued cell is refused (validCell rejects arrays)", throwsWith(() => decodeD1Backup(bytesFor(oneCell([1, 2]))), /malformed cell/));
  ok("decode: a two-key object cell is refused (validCell wants exactly one tag key)", throwsWith(() => decodeD1Backup(bytesFor(oneCell({ $blob: "AA", $int: "1" }))), /malformed cell/));
  ok("decode: a $blob cell with a non-string value is refused", throwsWith(() => decodeD1Backup(bytesFor(oneCell({ $blob: 5 }))), /malformed cell/));
  ok("decode: a $int cell with a non-decimal string is refused", throwsWith(() => decodeD1Backup(bytesFor(oneCell({ $int: "12x" }))), /malformed cell/));
  ok("decode: an unknown one-key object cell is refused (neither $blob nor $int)", throwsWith(() => decodeD1Backup(bytesFor(oneCell({ $other: "x" }))), /malformed cell/));

  // Per-schema guards.
  const withSchema = (s: unknown): Record<string, unknown> => ({ ...baseFullBody(), schema: [s] });
  ok("decode: a non-string schema entry is refused", throwsWith(() => decodeD1Backup(bytesFor(withSchema(9))), /schema entry is not a string/));
  ok("decode: a schema entry that is not CREATE INDEX/TRIGGER/VIEW is refused", throwsWith(() => decodeD1Backup(bytesFor(withSchema("DROP INDEX ix"))), /not a CREATE INDEX\/TRIGGER\/VIEW statement/));
  // A valid VIEW schema entry decodes (the accepted-kind leg of the schema regex, alongside INDEX
  // which the clean body already covered).
  const okView = decodeD1Backup(bytesFor(withSchema('CREATE VIEW "v" AS SELECT 1')));
  ok("decode: a CREATE VIEW schema entry is accepted", okView.schema.length === 1 && /CREATE VIEW/.test(okView.schema[0]!));
}

// proveDecodeD1RecordGuards drives decodeD1Record over the JSON/object guards and the header, rows,
// and schema record guards (which run decodeTableDDL, the rows validation, and decodeSchemaList), so
// every per-kind refusal branch and the default unsupported-format branch are covered. The clean
// header/rows/schema decode is already proven by PROOF 1; here the focus is the refusals.
function proveDecodeD1RecordGuards(): void {
  // Top-level guards shared by every kind.
  ok("record: non-JSON bytes are refused as not valid JSON", throwsWith(() => decodeD1Record(utf8("nope")), /not valid JSON/));
  ok("record: a JSON non-object is refused as not an object", throwsWith(() => decodeD1Record(bytesFor(7)), /record body is not an object/));
  ok("record: an unknown format is refused and names the four understood formats", throwsWith(() => decodeD1Record(bytesFor({ format: "downpipe-d1-mystery/1" })), /unsupported D1 record format/));

  // Header record (decodeTableDDL guards).
  ok("record(header): no tables array is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_HEADER_FORMAT, tables: "x" })), /header record has no tables array/));
  const hdrTable = (t: unknown): Uint8Array => bytesFor({ format: D1_HEADER_FORMAT, tables: [t] });
  ok("record(header): a non-object table entry is refused", throwsWith(() => decodeD1Record(hdrTable(1)), /header table entry is not an object/));
  ok("record(header): a table with no name is refused", throwsWith(() => decodeD1Record(hdrTable({ name: "", sql: 'CREATE TABLE "t" (id)', columns: [] })), /header table has no name/));
  ok("record(header): a table whose sql is not a CREATE TABLE is refused", throwsWith(() => decodeD1Record(hdrTable({ name: "t", sql: "SELECT 1", columns: [] })), /sql is not a CREATE TABLE statement/));
  ok("record(header): a table with a malformed column list is refused", throwsWith(() => decodeD1Record(hdrTable({ name: "t", sql: 'CREATE TABLE "t" (id)', columns: [{}] })), /malformed column list/));
  // A clean header with a tag-free DDL decodes through decodeTableDDL's success return.
  const okHdr = decodeD1Record(encodeD1Header([{ name: "t", sql: 'CREATE TABLE "t" (id INTEGER)', columns: ["id"] }]));
  ok("record(header): a clean header decodes via decodeTableDDL", okHdr.kind === "header" && okHdr.tables[0]!.name === "t");

  // Rows record guards.
  ok("record(rows): no table name is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_ROWS_FORMAT, table: "", columns: [], rows: [] })), /rows record has no table name/));
  ok("record(rows): a malformed column list is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_ROWS_FORMAT, table: "t", columns: [5], rows: [] })), /malformed column list/));
  ok("record(rows): a non-array rows list is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_ROWS_FORMAT, table: "t", columns: ["a"], rows: "x" })), /malformed rows list/));
  ok("record(rows): a row of the wrong arity is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_ROWS_FORMAT, table: "t", columns: ["a", "b"], rows: [[1]] })), /cell count does not match/));
  ok("record(rows): a malformed cell in a row is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_ROWS_FORMAT, table: "t", columns: ["a"], rows: [[true]] })), /malformed cell/));
  // A clean rows record decodes through the success return.
  const okRows = decodeD1Record(encodeD1RowsPage("t", ["a"], [[1], [2]]));
  ok("record(rows): a clean rows record decodes", okRows.kind === "rows" && okRows.table === "t" && okRows.rows.length === 2);

  // Schema record (decodeSchemaList guards).
  ok("record(schema): a non-array schema is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_SCHEMA_FORMAT, schema: 1 })), /schema record has no schema array/));
  ok("record(schema): a non-string schema entry is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_SCHEMA_FORMAT, schema: [1] })), /schema entry is not a string/));
  ok("record(schema): a non-CREATE-INDEX/TRIGGER/VIEW schema entry is refused", throwsWith(() => decodeD1Record(bytesFor({ format: D1_SCHEMA_FORMAT, schema: ["UPDATE t SET v=1"] })), /not a CREATE INDEX\/TRIGGER\/VIEW statement/));
  // A clean schema record decodes through decodeSchemaList's success return.
  const okSchema = decodeD1Record(encodeD1Schema(['CREATE TRIGGER "tg" AFTER INSERT ON "t" BEGIN SELECT 1; END']));
  ok("record(schema): a clean schema record decodes via decodeSchemaList", okSchema.kind === "schema" && okSchema.schema.length === 1);
}

// proveD1SingleStatementGuard proves the DDL/schema decoders reject more than one SQL statement per
// entry: the prefix-only CREATE TABLE/INDEX/TRIGGER/VIEW regexes only prove a DDL/schema string
// STARTS with the right keyword, not that nothing else follows, so "CREATE TABLE t(x); DROP TABLE
// other; --" would otherwise pass unchanged. A decoded entry is handed straight to db.prepare() and
// replayed via db.batch() against a LIVE target D1 binding with NO human review step
// (D1RestoreSink in restore-sink.ts), so this guard matters at full severity. Each case is driven
// through BOTH the legacy whole-body decoder (decodeD1Backup, which delegates table entries to
// validateTableEntry) and the resumable per-page decoders (decodeD1Record's header path via
// decodeTableDDL, schema path via decodeSchemaList), since all four are separate call sites the
// guard has to reach.
//
// The second group of cases further down closes a gap in the first: those only ever exercised
// CREATE TABLE/INDEX smuggles (allowTriggerBody=false, so the BEGIN/CASE/END tracking branch never
// actually ran), never a CREATE TRIGGER smuggle -- the one entry kind that turns that branch on and
// the one a bare "begin"/"case" alias could fool into hiding a smuggled statement behind a
// wrongly-still-open body.
function proveD1SingleStatementGuard(): void {
  // ---- bare-keyword smuggle: a bare "begin" column/expression name must not hide a smuggled
  // statement behind the BEGIN/CASE...END depth tracker. This passes the OLD prefix-only regex
  // unchanged (it does start with CREATE TABLE/INDEX), so it must fail before the fix and be
  // refused after it.
  const smuggledTable = "CREATE TABLE users(begin INTEGER); DROP TABLE payments; END";
  ok(
    "decodeD1Backup refuses a bare-keyword smuggle in a table's CREATE TABLE",
    throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), tables: [{ name: "users", sql: smuggledTable, columns: ["begin"], rows: [] }] })), /more than one statement/),
  );
  ok(
    "decodeD1Record(header) refuses the same bare-keyword smuggle via decodeTableDDL",
    throwsWith(() => decodeD1Record(encodeD1Header([{ name: "users", sql: smuggledTable, columns: ["begin"] }])), /more than one statement/),
  );
  const smuggledIndex = "CREATE INDEX idx ON users(begin) ; DROP TABLE payments; END";
  ok(
    "decodeD1Backup refuses a bare-keyword smuggle in a schema (CREATE INDEX) entry",
    throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [smuggledIndex] })), /more than one statement/),
  );
  ok(
    "decodeD1Record(schema) refuses the same smuggle via decodeSchemaList",
    throwsWith(() => decodeD1Record(encodeD1Schema([smuggledIndex])), /more than one statement/),
  );

  // ---- mirror-image regression: SQLite reserves neither "begin" nor "end", so a real single-
  // statement CREATE TABLE using either as an ordinary column name must still decode unchanged
  // rather than being mistaken for an unterminated BEGIN/CASE block.
  const beginCol = 'CREATE TABLE "shifts" (id INTEGER PRIMARY KEY, begin INTEGER, finish INTEGER)';
  const endCol = 'CREATE TABLE "shifts" (id INTEGER PRIMARY KEY, start INTEGER, end INTEGER)';
  const decBegin = decodeD1Backup(bytesFor({ ...baseFullBody(), tables: [{ name: "shifts", sql: beginCol, columns: ["id", "begin", "finish"], rows: [] }] }));
  ok("a legitimate 'begin' column name still decodes unchanged", decBegin.tables[0]!.sql === beginCol);
  const decEnd = decodeD1Backup(bytesFor({ ...baseFullBody(), tables: [{ name: "shifts", sql: endCol, columns: ["id", "start", "end"], rows: [] }] }));
  ok("a legitimate 'end' column name still decodes unchanged", decEnd.tables[0]!.sql === endCol);

  // ---- cross-entry literal splice: decodeD1Backup/decodeD1Record validate each DDL/schema array
  // entry in ISOLATION, so an entry that leaves a quote/bracket/comment span dangling open must be
  // refused ON ITS OWN -- it must never depend on what a sibling entry's text happens to contain.
  const spliceTable0 = "CREATE TABLE t1(x TEXT DEFAULT '"; // dangling, unterminated string literal
  const spliceTable1 = "CREATE TABLE ignoreme') ; DROP TABLE IF EXISTS payments; --"; // would "close" entry 0 if ever concatenated
  ok(
    "decodeD1Backup refuses a dangling-literal table entry on its own, before any sibling entry is considered",
    throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), tables: [{ name: "t1", sql: spliceTable0, columns: ["x"], rows: [] }, { name: "ignoreme", sql: spliceTable1, columns: ["y"], rows: [] }] })), /unterminated/),
  );
  ok(
    "decodeD1Record(header) refuses the same dangling-literal entry via decodeTableDDL",
    throwsWith(() => decodeD1Record(encodeD1Header([{ name: "t1", sql: spliceTable0, columns: ["x"] }, { name: "ignoreme", sql: spliceTable1, columns: ["y"] }])), /unterminated/),
  );
  const spliceSchema0 = "CREATE INDEX idx0 ON t(x) WHERE y='";
  const spliceSchema1 = "CREATE VIEW v AS SELECT '; DROP TABLE payments; --";
  ok(
    "decodeD1Backup refuses a dangling-literal schema entry on its own",
    throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [spliceSchema0, spliceSchema1] })), /unterminated/),
  );
  ok(
    "decodeD1Record(schema) refuses the same dangling-literal schema entry via decodeSchemaList",
    throwsWith(() => decodeD1Record(encodeD1Schema([spliceSchema0, spliceSchema1])), /unterminated/),
  );

  // ---- positive control: a real multi-line CREATE TRIGGER with an internal BEGIN...END body (a
  // nested CASE...END expression, and its own internal ';'-separated statements) must still decode
  // byte-for-byte unchanged -- the tightened check must not overcorrect into rejecting genuine
  // trigger DDL just because it is now so much stricter about CREATE TABLE/INDEX/VIEW.
  const trigger =
    "CREATE TRIGGER users_ai AFTER INSERT ON users\n" +
    "BEGIN\n" +
    "  UPDATE stats SET n = CASE WHEN n IS NULL THEN 1 ELSE n + 1 END;\n" +
    "  INSERT INTO audit(action, table_name) VALUES ('insert', 'users');\n" +
    "END";
  const decBackup = decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [trigger] }));
  ok("decodeD1Backup still decodes a real multi-line CREATE TRIGGER unchanged", decBackup.schema.length === 1 && decBackup.schema[0] === trigger);
  const decRecord = decodeD1Record(encodeD1Schema([trigger]));
  ok("decodeD1Record(schema) still decodes the same multi-line trigger unchanged via decodeSchemaList", decRecord.kind === "schema" && decRecord.schema[0] === trigger);

  // ---- round 2: the bare-keyword smuggle cases above (smuggledTable, smuggledIndex) never actually
  // exercised allowTriggerBody=true -- CREATE TABLE/INDEX never carry a trigger body, so the
  // BEGIN/CASE/END tracking branch never even ran for them, and it is ALWAYS the CREATE TRIGGER path
  // (the one that turns it on) that a bare "begin"/"case" alias could fool:
  const triggerSmuggleAlias = "CREATE TRIGGER evil AFTER INSERT ON t\nBEGIN\n  SELECT 1 AS begin;\nEND;\nDROP TABLE payments;\nSELECT 1 AS end;";
  ok(
    "decodeD1Backup refuses a bare 'AS begin'/'AS end' alias trick in a CREATE TRIGGER (live-confirmed prior bypass)",
    throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [triggerSmuggleAlias] })), /more than one statement/),
  );
  ok(
    "decodeD1Record(schema) refuses the same alias trick via decodeSchemaList",
    throwsWith(() => decodeD1Record(encodeD1Schema([triggerSmuggleAlias])), /more than one statement/),
  );
  // a decorative trailing bare END (rather than a 3rd aliased statement) must be refused too, for the
  // same reason.
  const triggerSmuggleDecorative = "CREATE TRIGGER evil2 AFTER INSERT ON t\nBEGIN\n  SELECT 1 AS begin;\nEND;\nDROP TABLE payments;\nEND";
  ok(
    "decodeD1Backup refuses the original finding's decorative-trailing-END shape",
    throwsWith(() => decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [triggerSmuggleDecorative] })), /more than one statement/),
  );

  // ---- regression: the shipped begin/end fixtures above only ever declared begin/end as CREATE
  // TABLE columns (allowTriggerBody=false there, so the tracking branch never ran). A real CREATE
  // TRIGGER body that references a column literally named begin/end via NEW. (the idiomatic way to
  // read the triggering row, e.g. a rostering/shift-scheduling domain) is a DIFFERENT case: the depth
  // tracker's bare "begin"/"end" detection must not wrongly reject it. Both trigger bodies below are
  // valid, single-statement DDL that fires correctly against real SQLite.
  const triggerNewBegin = "CREATE TRIGGER shifts_ai AFTER INSERT ON shifts\nBEGIN\n  INSERT INTO shift_log(shift_id, started) VALUES (NEW.id, NEW.begin);\nEND";
  const decNewBegin = decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [triggerNewBegin] }));
  ok("a legitimate NEW.begin reference in a trigger body still decodes unchanged", decNewBegin.schema[0] === triggerNewBegin);
  ok(
    "decodeD1Record(schema) still decodes the same NEW.begin trigger unchanged",
    (() => {
      const r = decodeD1Record(encodeD1Schema([triggerNewBegin]));
      return r.kind === "schema" && r.schema[0] === triggerNewBegin;
    })(),
  );
  const triggerNewEnd = "CREATE TRIGGER shifts_au AFTER UPDATE ON shifts\nBEGIN\n  INSERT INTO shift_log(shift_id, finished) VALUES (NEW.id, NEW.end);\nEND";
  const decNewEnd = decodeD1Backup(bytesFor({ ...baseFullBody(), schema: [triggerNewEnd] }));
  ok("a legitimate NEW.end reference in a trigger body still decodes unchanged", decNewEnd.schema[0] === triggerNewEnd);
}

// proveCellCoders drives cellToBind, cellFromValue, and quoteIdent over every cell kind and every
// refusal, so the BLOB and big-integer legs of both coders, the non-finite refusal, the byte-array
// BLOB path, and the unsupported-type/unsupported-shape refusals are all covered.
function proveCellCoders(): void {
  // cellToBind: each cell kind maps to the value handed to .bind().
  ok("cellToBind: null maps to null", cellToBind(null) === null);
  ok("cellToBind: a string passes through", cellToBind("hi") === "hi");
  ok("cellToBind: a number passes through", cellToBind(42) === 42);
  const ab = cellToBind({ $blob: b64urlEncode(AVATAR) });
  ok("cellToBind: a tagged BLOB becomes an ArrayBuffer of the same bytes", ab instanceof ArrayBuffer && new Uint8Array(ab).join(",") === AVATAR.join(","));
  ok("cellToBind: a tagged big integer becomes a bigint without narrowing", cellToBind({ $int: "9007199254740993" }) === 9007199254740993n);

  // cellFromValue: each value the source reads from D1 .all()/.raw() maps to a JSON-safe cell.
  ok("cellFromValue: null maps to null", cellFromValue(null) === null);
  ok("cellFromValue: undefined maps to null (D1 surfaces a missing value as null)", cellFromValue(undefined) === null);
  ok("cellFromValue: a string passes through", cellFromValue("x") === "x");
  ok("cellFromValue: an in-range bigint narrows to a plain number", cellFromValue(5n) === 5);
  ok("cellFromValue: an out-of-range bigint is tagged rather than narrowed", JSON.stringify(cellFromValue(9007199254740993n)) === JSON.stringify({ $int: "9007199254740993" }));
  ok("cellFromValue: a negative out-of-range bigint is tagged", JSON.stringify(cellFromValue(-9007199254740993n)) === JSON.stringify({ $int: "-9007199254740993" }));
  ok("cellFromValue: a finite number passes through", cellFromValue(3.5) === 3.5);
  ok("cellFromValue: a non-finite number (Infinity) is refused, not silently nulled", throwsWith(() => cellFromValue(Infinity), /unsupported non-finite numeric value/));
  ok("cellFromValue: NaN is refused too", throwsWith(() => cellFromValue(NaN), /unsupported non-finite numeric value/));
  ok("cellFromValue: an ArrayBuffer becomes a tagged BLOB", JSON.stringify(cellFromValue(toAB(AVATAR))) === JSON.stringify({ $blob: b64urlEncode(AVATAR) }));
  // A typed-array view (ArrayBuffer.isView) is read at its own offset/length, not the whole backing
  // buffer: a view over the middle of a larger buffer must tag only its window.
  const backing = new Uint8Array([0xaa, 0x00, 0x01, 0xfe, 0xff, 0x42, 0xbb]);
  const view = new Uint8Array(backing.buffer, 1, 5); // exactly AVATAR's bytes
  ok("cellFromValue: a typed-array view becomes a tagged BLOB of just its window", JSON.stringify(cellFromValue(view)) === JSON.stringify({ $blob: b64urlEncode(AVATAR) }));
  // D1 .raw() returns a BLOB as a plain number[] of byte values; that path must tag it as a BLOB.
  ok("cellFromValue: a byte number[] (D1 .raw() BLOB shape) becomes a tagged BLOB", JSON.stringify(cellFromValue([0, 1, 254, 255, 66])) === JSON.stringify({ $blob: b64urlEncode(AVATAR) }));
  ok("cellFromValue: an empty number[] becomes a tagged empty BLOB", JSON.stringify(cellFromValue([])) === JSON.stringify({ $blob: "" }));
  ok("cellFromValue: a number[] with an out-of-byte-range element is refused", throwsWith(() => cellFromValue([0, 256]), /unsupported array shape/));
  ok("cellFromValue: a number[] with a non-integer element is refused", throwsWith(() => cellFromValue([1.5]), /unsupported array shape/));
  ok("cellFromValue: a number[] with a non-number element is refused", throwsWith(() => cellFromValue(["x"]), /unsupported array shape/));
  ok("cellFromValue: an unsupported type (a plain object) is refused", throwsWith(() => cellFromValue({ a: 1 }), /unsupported type/));
  ok("cellFromValue: a boolean is refused as an unsupported type", throwsWith(() => cellFromValue(true), /unsupported type/));

  // quoteIdent: a plain name is wrapped; an embedded double quote is doubled so it cannot break out.
  ok("quoteIdent: a plain identifier is wrapped in double quotes", quoteIdent("users") === '"users"');
  ok("quoteIdent: an embedded double quote is doubled (cannot break out of the quotes)", quoteIdent('a"b') === '"a""b"');
}

// collectStream concatenates an async byte stream into one buffer, so the streamed encoding can be
// compared with the buffered one.
async function collectStream(iter: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const c of iter) chunks.push(c);
  return concat(...chunks);
}

// planFromBackup turns an in-memory D1Backup into a streamed D1DumpPlan whose pageRows yields the
// table's rows in fixed-size pages, so the streamer's multi-page boundary (the per-row comma and the
// page.last break) is driven for a table whose rows span more than one page.
function planFromBackup(b: D1Backup, rowsPerPage: number): D1DumpPlan {
  return {
    tables: b.tables.map((t) => ({ name: t.name, sql: t.sql, columns: t.columns })),
    schema: b.schema,
    pageRows(ti: number): AsyncIterable<D1RowPage> {
      const rows = b.tables[ti]!.rows;
      return (async function* (): AsyncIterable<D1RowPage> {
        // An empty table still yields one terminal empty page (last:true), so the streamer closes
        // its rows array without ever reading a row.
        if (rows.length === 0) {
          yield { rows: [], last: true };
          return;
        }
        for (let i = 0; i < rows.length; i += rowsPerPage) {
          const page = rows.slice(i, i + rowsPerPage);
          yield { rows: page, last: i + rowsPerPage >= rows.length };
        }
      })();
    },
  };
}

// proveStreamEncoderMatchesBuffered pins encodeD1BackupStream BYTE-FOR-BYTE against encodeD1Backup
// over the same content (the source comment names this validator as the place that pins the two), so
// the memory-bounded streaming encoder is proven to produce the exact stored dump bytes. The fixture
// is chosen to drive every comma-join branch: more than one table, more than one column, more than
// one row across more than one page, and more than one schema entry, plus an empty table and an
// empty-schema variant so the zero-length loops are exercised too.
async function proveStreamEncoderMatchesBuffered(): Promise<void> {
  const body: D1Backup = {
    format: D1_BACKUP_FORMAT,
    tables: [
      // Five rows over a page size of two forces three pages (the per-row comma spans a page seam).
      {
        name: 'wei"rd', // an embedded quote so JSON-escaping of the name is exercised in the stream
        sql: 'CREATE TABLE "wei""rd" (id INTEGER, name TEXT, avatar BLOB, big INTEGER)',
        columns: ["id", "name", "avatar", "big"],
        rows: [
          [1, "alice", { $blob: b64urlEncode(AVATAR) }, { $int: BIG_INT.toString() }],
          [2, HOSTILE_NAME, null, 7],
          [3, null, { $blob: b64urlEncode(new Uint8Array(0)) }, 0],
          [4, "dave", { $blob: b64urlEncode(new Uint8Array([9, 9])) }, -1],
          [5, "erin", null, 5],
        ],
      },
      // A single-row second table, so the table-join comma runs and the second table is one page.
      { name: "notes", sql: 'CREATE TABLE "notes" (id INTEGER, body TEXT)', columns: ["id", "body"], rows: [[1, "only"]] },
      // An empty table, so the streamer closes an empty rows array via the terminal empty page.
      { name: "empty", sql: 'CREATE TABLE "empty" (id INTEGER)', columns: ["id"], rows: [] },
    ],
    schema: ['CREATE INDEX "ix" ON "notes" (body)', 'CREATE VIEW "v" AS SELECT 1'],
  };

  const buffered = encodeD1Backup(body);
  const streamed = await collectStream(encodeD1BackupStream(planFromBackup(body, 2)));
  ok("stream: the streamed encoding is byte-for-byte identical to the buffered encoding", b64urlEncode(streamed) === b64urlEncode(buffered));
  // And the streamed bytes decode back to the same body (so the stream is not just equal bytes but a
  // valid dump): a sanity round-trip through decodeD1Backup.
  const round = decodeD1Backup(streamed);
  ok("stream: the streamed bytes decode back to the same tables and schema", round.tables.length === 3 && round.schema.length === 2 && rowsEq(round.tables[0]!.rows, body.tables[0]!.rows));

  // An empty plan (no tables, no schema) still matches the buffered empty body, so the zero-length
  // table and schema loops (the leading-comma guards never firing) are covered.
  const emptyBody: D1Backup = { format: D1_BACKUP_FORMAT, tables: [], schema: [] };
  const emptyStreamed = await collectStream(encodeD1BackupStream(planFromBackup(emptyBody, 2)));
  ok("stream: an empty body streams byte-for-byte identical to the buffered empty body", b64urlEncode(emptyStreamed) === b64urlEncode(encodeD1Backup(emptyBody)));
}

// MockR2 serves the sealed archive objects through the R2 destination surface the reader uses.
class MockR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
