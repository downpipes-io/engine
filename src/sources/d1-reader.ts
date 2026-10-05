import { cellFromTypedValue, cellToBind, D1DefectError, quoteIdent, type D1Cell } from "./d1-format.ts";
import { resumeTokenError } from "./d1-token.ts";
import { classifyD1Defect, faultItemId, recordD1Defect, recordRowidProbeFallback, recordSnapshotConsistency } from "./source-fault-ledger.ts";
import type { Meter } from "./types.ts";

// ---- sizing constants ---------------------------------------------------------------------------

// D1_PAGE_BYTE_LIMIT bounds the serialised size of ONE keyset row page held in memory. A page is at
// most D1_ROWS_PER_PAGE rows; a page whose JSON exceeds this is a pathological table (a single row
// larger than the bound cannot be split across records), refused with a clear error rather than
// ballooning the isolate. It is generous (rows are bounded by D1's own 1 MB row / 2 MB statement
// limits in practice) but finite, so peak memory stays bounded.
export const D1_PAGE_BYTE_LIMIT = 96 * 1024 * 1024; // 96 MiB per in-memory page

// D1_ROWS_PER_PAGE is the keyset page size for a rowid table: the source reads this many rows per
// query, emits them as one rows record, then advances its keyset cursor. Small enough that a page of
// typical rows stays well under D1_PAGE_BYTE_LIMIT, large enough to keep the subrequest count sane.
export const D1_ROWS_PER_PAGE = 2000;

// D1_PAGE_TARGET_BYTES is the target SERIALISED size of one row-page record. The keyset pager chooses each
// page's row LIMIT ADAPTIVELY from the observed row width so a page record lands near this size REGARDLESS
// of how wide the rows are: a narrow-row table ramps up to D1_ROWS_PER_PAGE (efficient, few subrequests),
// a wide-row table shrinks to a few rows per page (bounded memory, never near the hard D1_PAGE_BYTE_LIMIT
// cap). This is what makes a WIDE-ROW table resumable instead of failing the cap at a fixed 2000 rows.
export const D1_PAGE_TARGET_BYTES = 8 * 1024 * 1024; // 8 MiB target per row-page record (12x under the cap)
// D1_ASSUMED_MAX_ROW_BYTES is a conservative upper bound on one D1 row's serialised size (the platform caps
// a value at ~2 MiB). The FIRST page of a table uses it to pick a safe row LIMIT before any row width is
// known, so the first fetch cannot balloon the isolate; every later page adapts from the measured average.
const D1_ASSUMED_MAX_ROW_BYTES = 2 * 1024 * 1024;

// D1_KEY_CURSOR_MAX_BYTES bounds the encoded size of one PRIMARY KEY cursor (the JSON of the key cells). A
// key cursor rides in every mark token, and the seal keeps the latest token in the checkpoint document in
// Durable Object storage. A D1 key cell can be as large as a row, and a mark with a key that size would
// push the checkpoint past the DO value limit, so every later checkpoint write would fail. A page whose
// last key is larger than this bound gets no mark (see pageByPrimaryKey). The bound is 4 times the longest
// R2 object key, which the R2 cursor already carries, and far under the ~128 KiB value the seal budgets.
export const D1_KEY_CURSOR_MAX_BYTES = 4 * 1024;
const utf8Encoder = new TextEncoder();

// D1_ROWID_MIN is SQLite's INTEGER minimum (INT64_MIN), used as the initial keyset cursor for a fresh
// table: it is strictly below any possible rowid, so the first `_rowid_ > ?` page starts at the very
// first row and skips none. Naming it avoids an unexplained literal on the paging path.
const D1_ROWID_MIN = -9223372036854775808n;

// D1_EXPORT_SIZE_LIMIT is retained as a public constant for callers/tests that still import it. With
// per-page resumable records the whole-database in-memory ceiling no longer applies (peak memory is
// one keyset page); the streamed-total is bounded by the run's segment/subrequest budget like every
// other source. It is the per-page bound's far-larger sibling, kept so a test asserting a raised cap
// still has the symbol. It is no longer enforced as a single sizing pass (that pass is gone with the
// stream); D1_PAGE_BYTE_LIMIT is the live per-record bound.
export const D1_EXPORT_SIZE_LIMIT = 256 * 1024 * 1024 * 1024; // 256 GiB nominal cap (no longer a sizing gate)

// ---- reading D1 ---------------------------------------------------------------------------------

// D1Reader is the narrow read surface the export uses: a prepare() that returns a statement
// supporting all()/raw(). It is satisfied by both a D1DatabaseSession and a bare D1Database, so
// makeSession can fall back gracefully when withSession is absent.
export interface D1Reader {
  prepare(query: string): {
    bind(...values: unknown[]): {
      all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
      raw<T = unknown[]>(opts: { columnNames: true }): Promise<[string[], ...T[]]>;
    };
    all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
    raw<T = unknown[]>(opts: { columnNames: true }): Promise<[string[], ...T[]]>;
  };
}

// A D1Snapshot pairs the read surface with the session's bookmark accessor. makeSession anchors a
// consistent-read session when the binding supports withSession, else uses the bare database and a
// null bookmark (best-effort: reads are still ordered, only the cross-slice snapshot is not pinned).
export interface D1Snapshot {
  reader: D1Reader;
  getBookmark(): string | null;
}

// makeSession opens a D1 Session anchored at the given constraint or bookmark when the binding
// supports it. "first-primary" pins a fresh crawl to the primary's bookmark across all reads on the
// session (SRC-1); an explicit bookmark re-pins a resumed crawl to the same snapshot. A binding
// without withSession (an older/local double) degrades to the bare db with a null bookmark.
export function makeSession(db: D1Database, constraintOrBookmark: string): D1Snapshot {
  const ws = (db as { withSession?: (c?: string) => unknown }).withSession;
  if (typeof ws === "function") {
    const session = ws.call(db, constraintOrBookmark) as D1Reader & { getBookmark?: () => string | null };
    // A session WITHOUT a working getBookmark cannot prove it held one point in time across a resume,
    // so it is recorded as unpinned rather than assumed pinned. The bookmark VALUE is never recorded, only
    // whether the guarantee exists.
    const pinned = typeof session.getBookmark === "function";
    recordSnapshotConsistency(pinned ? "pinned" : "unpinned");
    return {
      reader: session,
      getBookmark: () => (typeof session.getBookmark === "function" ? session.getBookmark() : null),
    };
  }
  // The binding exposes no withSession(), so reads are NOT snapshot-isolated. The crawl still runs (a
  // torn archive beats no archive), but the run row must say the point-in-time guarantee was not held, or a
  // restore showing dangling references reads as an unexplained corruption.
  recordSnapshotConsistency("unpinned");
  return { reader: db as unknown as D1Reader, getBookmark: () => null };
}

// Tables SQLite or the D1 platform owns, never backed up. sqlite_* are SQLite internals
// (sqlite_sequence, sqlite_stat*, the schema table itself); _cf_* are D1's own bookkeeping.
// Re-creating or re-inserting these would either error or corrupt the managed database, so the
// backup excludes them and the restore therefore never touches them.
function isInternalTable(name: string): boolean {
  return name.startsWith("sqlite_") || name.startsWith("_cf_");
}

// A per-table read plan: the dumped CREATE text, the ordered column names rows align to, whether the
// CREATE text declares the table WITHOUT ROWID, whether the table can page by rowid, and, for a WITHOUT
// ROWID table, its PRIMARY KEY columns (so the export can keyset-page by that key). A WITHOUT ROWID table
// always has a PRIMARY KEY, so it pages and resumes mid-table like a rowid table. keyColumns is empty for
// a rowid table, and for a WITHOUT ROWID table whose key could not be read; that table is read in one
// page. hasRowid is false for a rowid table whose _rowid_ probe failed; that table is read in one page too.
export interface TablePlan {
  name: string;
  sql: string;
  columns: string[];
  withoutRowid: boolean;
  hasRowid: boolean;
  keyColumns: KeyColumn[];
}

// A KeyColumn is one PRIMARY KEY column of a WITHOUT ROWID table, in key order: its position in
// TablePlan.columns (so the cursor is read from the decoded cells) and the collation of the PRIMARY
// KEY index on that column. The keyset pager compares and orders under that collation. The key is
// unique under it, so the order is total and no row is skipped or repeated at a page boundary.
export interface KeyColumn {
  index: number;
  collation: string;
}

// DumpPlan is the schema-and-structure half of the export: the table list (with column names and
// rowid-ness) and the non-table schema (CREATE INDEX/TRIGGER/VIEW). It is read up front and small by
// construction (DDL only, never rows). The crawl pages each table's rows from this plan.
export interface DumpPlan {
  tables: TablePlan[];
  schema: string[];
}

// readDumpPlan reads sqlite_master and each table's columns + rowid-ness, returning the DumpPlan the
// crawl pages rows from. Every query is a platform subrequest the slice budget must see (a database
// with hundreds of tables spends hundreds). This is the FIRST query of a crawl, so it establishes
// (fresh) or confirms (resume) the session bookmark the marks thread.
export async function readDumpPlan(reader: D1Reader, meter?: Meter): Promise<DumpPlan> {
  meter?.spend(1, "d1Read");
  const master = await reader
    .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid")
    .all<{ type: string; name: string; tbl_name: string; sql: string }>();

  const tables: TablePlan[] = [];
  const schema: string[] = [];
  for (const row of master.results) {
    if (isInternalTable(row.name) || isInternalTable(row.tbl_name)) continue;
    if (row.type === "table") {
      tables.push({ name: row.name, sql: row.sql, columns: [], withoutRowid: declaresWithoutRowid(row.sql), hasRowid: false, keyColumns: [] });
    } else if (row.type === "index" || row.type === "trigger" || row.type === "view") {
      schema.push(row.sql);
    }
    // Any other object type is ignored; the supported set is the SQLite DDL objects above.
  }

  // Read each table's column names (and detect rowid-ness) without reading its rows. A LIMIT 0
  // SELECT * returns just the column header via raw({columnNames:true}), so the column order the
  // dump aligns rows to is established before any row is read.
  //
  // Only a table whose CREATE text declares WITHOUT ROWID pages by its PRIMARY KEY. The table kind comes
  // from the DDL, never from a failed _rowid_ probe. A probe can fail transiently on a rowid table, and a
  // rowid table's PRIMARY KEY can hold NULL (SQLite allows it), which a key cursor cannot carry. The DDL
  // is part of the pinned snapshot, so every slice of a run sees the same kind for the same table.
  for (const t of tables) {
    meter?.spend(1, "d1Read");
    const [header] = await reader.prepare(`SELECT * FROM ${quoteIdent(t.name)} LIMIT 0`).raw<unknown[]>({ columnNames: true });
    t.columns = header.map((c) => String(c));
    if (t.withoutRowid) t.keyColumns = await readPrimaryKey(reader, t, meter);
    else t.hasRowid = await tableHasRowid(reader, t.name, meter);
  }

  return { tables, schema };
}

// declaresWithoutRowid reports whether a CREATE TABLE text ends in the WITHOUT ROWID table option.
// sqlite_master keeps the text as written, so it can hold comments, string literals and quoted
// identifiers that contain the words WITHOUT ROWID or a ")". The scan blanks each of those first. The
// table options (WITHOUT ROWID, STRICT) then follow the last ")", which closes the column list.
// test/validate-d1-keyset.ts checks this against SQLite's own PRAGMA table_list for such tables.
export function declaresWithoutRowid(sql: string): boolean {
  let bare = "";
  let i = 0;
  while (i < sql.length) {
    const two = sql.slice(i, i + 2);
    if (two === "--" || two === "/*") {
      const end = two === "--" ? sql.indexOf("\n", i) : sql.indexOf("*/", i + 2);
      i = end < 0 ? sql.length : end + (two === "--" ? 0 : 2);
      bare += " ";
      continue;
    }
    const c = sql[i]!;
    const close = c === "'" || c === '"' || c === "`" ? c : c === "[" ? "]" : null;
    if (close === null) {
      bare += c;
      i++;
      continue;
    }
    // A quoted run ends at its closing quote. A doubled quote inside it is an escaped quote; a bracketed
    // identifier has no escape.
    let j = i + 1;
    for (;;) {
      const k = sql.indexOf(close, j);
      if (k < 0) {
        j = sql.length;
        break;
      }
      if (close !== "]" && sql[k + 1] === close) {
        j = k + 2;
        continue;
      }
      j = k + 1;
      break;
    }
    i = j;
    bare += " ";
  }
  const lastParen = bare.lastIndexOf(")");
  return lastParen >= 0 && /\bWITHOUT\s+ROWID\b/i.test(bare.slice(lastParen + 1));
}

// tableHasRowid reports whether a keyset-by-rowid paged read is possible for a table whose DDL does not
// declare WITHOUT ROWID. A SELECT of _rowid_ succeeds on such a table, so a failure here is a fault, and
// the table falls back to a single-pass read. (A LIMIT 0 keeps the probe free of data.)
async function tableHasRowid(reader: D1Reader, name: string, meter?: Meter): Promise<boolean> {
  try {
    meter?.spend(1, "d1Read");
    await reader.prepare(`SELECT _rowid_ FROM ${quoteIdent(name)} LIMIT 0`).raw<unknown[]>({ columnNames: true });
    return true;
  } catch {
    // A TRANSIENTLY failing probe on a rowid table lands here and degrades the table to an unbounded
    // single-pass read, which is what later OOMs "unrelatedly" and cannot be resumed mid-table. Count the
    // fallback so it is visible. A WITHOUT ROWID table never reaches the probe, so every count is a fault.
    // The probe's error is deliberately discarded: only the count is evidence, never the table name here.
    recordRowidProbeFallback();
    return false;
  }
}

// readPrimaryKey reads the PRIMARY KEY columns of a WITHOUT ROWID table, in key order, with the
// collation of the key's own index. PRAGMA index_list names the index whose origin is "pk". PRAGMA
// index_xinfo lists its key columns (key = 1) in seqno order, each with its collation. D1 supports
// both statements. table_info also gives the key columns, but not the collation of the key index.
// That collation matters: a column declared COLLATE NOCASE with PRIMARY KEY (col COLLATE BINARY)
// holds "a" and "A" as two keys, and a NOCASE comparison would skip one of them at a page boundary.
//
// An empty result means "no usable key": the table is then read in one page, as before. That covers a
// key column the column header does not name and a pragma the binding refuses. A refused pragma must
// not fail a table the single-page read can capture. readDumpPlan calls this only for a table whose DDL
// declares WITHOUT ROWID, so a rowid table never pages by a key that can hold NULL.
async function readPrimaryKey(reader: D1Reader, t: TablePlan, meter?: Meter): Promise<KeyColumn[]> {
  try {
    meter?.spend(1, "d1Read");
    const list = await reader.prepare(`PRAGMA index_list(${quoteIdent(t.name)})`).all<{ name: unknown; origin: unknown }>();
    const pk = list.results.find((r) => r.origin === "pk");
    if (pk === undefined || typeof pk.name !== "string") return [];
    meter?.spend(1, "d1Read");
    const info = await reader.prepare(`PRAGMA index_xinfo(${quoteIdent(pk.name)})`).all<{ seqno: unknown; name: unknown; coll: unknown; key: unknown }>();
    const keyRows = info.results.filter((r) => Number(r.key) === 1).sort((a, b) => Number(a.seqno) - Number(b.seqno));
    const keys: KeyColumn[] = [];
    for (const r of keyRows) {
      const index = typeof r.name === "string" ? t.columns.indexOf(r.name) : -1;
      if (index < 0) return [];
      keys.push({ index, collation: typeof r.coll === "string" && r.coll !== "" ? r.coll : "BINARY" });
    }
    return keys;
  } catch {
    return [];
  }
}

// A ResumableRowPage is one keyset page plus the cursor a mark needs, and a per-table page index used
// only to make each rows record's name unique and ordered. The cursor is the page's last rowid for a
// rowid table, or the page's last PRIMARY KEY tuple for a WITHOUT ROWID table. Both are null for a
// table read in one page (it cannot resume mid-table) and on the terminal empty page. lastKey is also
// null on a key page whose last key is over D1_KEY_CURSOR_MAX_BYTES. Unless that page is the table's
// last, it gets no mark, so a slice cannot stop after it.
export interface ResumableRowPage {
  rows: D1Cell[][];
  last: boolean;
  lastRowid: bigint | null;
  lastKey: D1Cell[] | null;
  pageIndex: number;
}

// A RowCursor is where pageTableRows starts in a table: after a rowid (a decimal string), after a
// PRIMARY KEY tuple (the key cells in key order), or at the start of the table (null).
export type RowCursor = { afterRowid: string } | { afterKey: D1Cell[] } | null;

// pageTableRows yields a table's rows as keyset-ordered pages, STARTING after a given cursor so a
// resumed crawl reads only the rows it has not already emitted. For a rowid table it pages with
// WHERE _rowid_ > ? ORDER BY _rowid_ LIMIT n, exposing each page's last rowid as the cursor, so
// memory holds at most one page. The selected row shape is the integer-safe typed projection over the
// table's own columns (typedProjection) PLUS a trailing CAST(_rowid_ AS TEXT) used only as the cursor
// and stripped from the emitted cells, so the dumped columns are exactly the table's declared columns.
// A WITHOUT ROWID table pages the same way by its PRIMARY KEY (pageByPrimaryKey), exposing each
// page's last key tuple as the cursor. Only a table with neither a rowid nor a readable key is read in
// one pass (pageWithoutRowid) and reports no cursor, so its mark advances straight to the next table.
//
// startAfter is the resume cursor: null starts the table. A rowid cursor reads strictly after that
// rowid, and a key cursor reads strictly after that key tuple. startPage is the page index the first
// page takes, so a resumed table continues the record names an earlier slice sealed.
//
// The cursor kind must match the table kind, which comes from the DDL of the pinned snapshot. A key
// cursor on a table not declared WITHOUT ROWID, or a rowid cursor on one that is, cannot come from a
// mark of this snapshot. It is refused under the closed bad-cursor class, as a corrupt token is, rather
// than guessed at (a guess re-emits or skips sealed rows). A rowid cursor on a rowid table pages by
// rowid even when this slice's _rowid_ probe failed: the cursor proves the table has a rowid.
export async function* pageTableRows(
  reader: D1Reader,
  t: TablePlan,
  rowsPerPage: number,
  sizeLimit: number,
  startAfter: RowCursor,
  startPage: number,
  meter?: Meter,
): AsyncIterable<ResumableRowPage> {
  if (startAfter !== null && "afterKey" in startAfter) {
    if (!t.withoutRowid || (t.keyColumns.length > 0 && startAfter.afterKey.length !== t.keyColumns.length)) throw resumeTokenError("bad-cursor");
    // The key of a WITHOUT ROWID table could not be read on this slice (a refused pragma). The table
    // cannot resume after its key without it, so the slice fails and the run retries it on its backoff.
    if (t.keyColumns.length === 0) throw new Error(`D1 export: the PRIMARY KEY of table ${t.name} could not be read, so the crawl cannot resume after its key cursor`);
    yield* pageByPrimaryKey(reader, t, rowsPerPage, sizeLimit, startAfter.afterKey, startPage, meter);
    return;
  }
  if (startAfter !== null) {
    if (t.withoutRowid) throw resumeTokenError("bad-cursor");
    yield* pageByRowidKeyset(reader, t, rowsPerPage, sizeLimit, startAfter.afterRowid, startPage, meter);
    return;
  }
  if (t.hasRowid) {
    yield* pageByRowidKeyset(reader, t, rowsPerPage, sizeLimit, null, 0, meter);
    return;
  }
  if (t.keyColumns.length > 0) {
    yield* pageByPrimaryKey(reader, t, rowsPerPage, sizeLimit, null, 0, meter);
    return;
  }
  yield* pageWithoutRowid(reader, t, sizeLimit, meter);
}

// noteD1CaptureDefect records a D1 CAPTURE-path decode defect and re-throws, so a single NaN
// cell, one giant row or a binding contract violation is attributed to its table and defect class rather
// than surfacing only as a generic "run failed" coarse class that leaves the customer to bisect their own
// schema to find the table.
//
// The table name is a CUSTOMER schema label, so it is reduced to a one-way HANDLE (the same rule every other
// customer-owned name in this ledger follows); the raw name, the cell value and the row position stay in the
// throw and never reach a record. A fault that is not a D1 defect is re-thrown untouched.
// D1_TABLE_SCOPE is the ENGINE-CHOSEN product token the table handle hangs off. It is deliberately colon-free
// and lower-case so the composed id ("d1-table/h:ab12cd34ef56") matches the DO boundary's narrow attribution-id
// shape gate; a scope with a colon in it would be REFUSED there, and the locus would be silently dropped.
const D1_TABLE_SCOPE = "d1-table";

async function noteD1CaptureDefect(e: unknown, tableName: string): Promise<never> {
  const defect = classifyD1Defect(e);
  if (defect !== null) recordD1Defect(defect, await faultItemId(D1_TABLE_SCOPE, tableName));
  throw e;
}

// SQLITE_MAX_RESULT_COLUMNS pins SQLite's default SQLITE_MAX_COLUMN (2000): the maximum number of
// result-set expressions one SELECT may carry. The integer-safe TYPED projection below emits TWO result
// expressions per declared column (typeof(col) and the CASE-projected value), plus, on the keyset path,
// one CAST(_rowid_ AS TEXT) cursor expression. A table wide enough that 2*ncols(+1) would exceed this
// would otherwise trip a raw, opaque SQLite "too many columns in result set" error PART WAY through a
// crawl; typedProjection FAILS FIRST with a named, actionable error naming the table and its column
// count instead of a silent skip or an opaque platform error.
const SQLITE_MAX_RESULT_COLUMNS = 2000;

// typedProjection builds the integer-safe SELECT list for a table. For each declared column i it emits
// the PAIR
//   typeof(col)                                                         AS "__t<i>"   (result index 2*i)
//   CASE WHEN typeof(col)='integer' THEN CAST(col AS TEXT) ELSE col END AS "__v<i>"   (result index 2*i+1)
// so an int64 column comes back as an EXACT decimal string rather than a truncated float64 (D1's query
// API returns integers as float64 JSON, losing precision above 2^53). withRowidCursor adds nothing to
// this list itself (the keyset caller appends CAST(_rowid_ AS TEXT) after it) but is COUNTED here so the
// wide-table guard accounts for that trailing cursor column too. typedCellsFromRow MUST decode the raw
// result index-synchronised with this ordering: the two are a matched pair, change one and change both.
function typedProjection(t: TablePlan, withRowidCursor: boolean): string {
  const resultColumns = t.columns.length * 2 + (withRowidCursor ? 1 : 0);
  if (resultColumns > SQLITE_MAX_RESULT_COLUMNS) {
    throw new Error(
      `D1 export: table ${t.name} has ${t.columns.length} columns; the integer-safe typed projection needs ` +
      `${resultColumns} result columns, over SQLite's ${SQLITE_MAX_RESULT_COLUMNS}-column result-set limit. ` +
      `Capture and recover this table offline with the downpipe CLI, which has no such per-query column bound.`,
    );
  }
  const parts: string[] = [];
  for (let i = 0; i < t.columns.length; i++) {
    const c = quoteIdent(t.columns[i]!);
    parts.push(`typeof(${c}) AS "__t${i}"`);
    parts.push(`CASE WHEN typeof(${c})='integer' THEN CAST(${c} AS TEXT) ELSE ${c} END AS "__v${i}"`);
  }
  return parts.join(", ");
}

// typedCellsFromRow decodes one raw result row from typedProjection into ncols D1 cells. COUPLING: the
// projection emits, per column i, the pair (typeof at result index 2*i, value at result index 2*i+1), so
// this reads them index-synchronised with that ordering. Any trailing result column past 2*ncols (the
// keyset path's CAST(_rowid_ AS TEXT) cursor) is not a cell and is ignored here (the caller reads it).
function typedCellsFromRow(raw: unknown[], ncols: number): D1Cell[] {
  const cells: D1Cell[] = new Array(ncols);
  for (let i = 0; i < ncols; i++) {
    // raw[2*i] = typeof(col_i); raw[2*i + 1] = the CASE-projected value of col_i (index-synchronised).
    cells[i] = cellFromTypedValue(raw[2 * i], raw[2 * i + 1]);
  }
  return cells;
}

// pageWithoutRowid reads a table that has neither a usable rowid nor a readable PRIMARY KEY in one pass
// (still consistent under the session). It is the fallback for a WITHOUT ROWID table whose key could not
// be read (see readPrimaryKey), and for a rowid table whose _rowid_ probe failed (see tableHasRowid).
// It reads via the integer-safe typed projection (typedProjection: typeof + CAST(int AS TEXT) per
// column) so an int64 past 2^53 is captured exactly
// rather than truncated by D1's float64 JSON number encoding. It reports no cursor, so its mark
// advances straight to the next table (it cannot resume mid-table). A resume into such a table carries
// no cursor, so the whole table is read from the start.
//
// The row decode (and guardPageBytes) is wrapped so a decode defect is recorded (noteD1CaptureDefect)
// before it re-throws: WHICH table and WHICH defect class, not just a generic "run failed".
async function* pageWithoutRowid(reader: D1Reader, t: TablePlan, sizeLimit: number, meter?: Meter): AsyncIterable<ResumableRowPage> {
  meter?.spend(1, "d1Read");
  const [, ...dataRows] = await reader.prepare(`SELECT ${typedProjection(t, false)} FROM ${quoteIdent(t.name)}`).raw<unknown[]>({ columnNames: true });
  let rows: D1Cell[][] = [];
  try {
    rows = dataRows.map((raw) => typedCellsFromRow(raw, t.columns.length));
    guardPageBytes(rows, t.name, sizeLimit);
  } catch (e) {
    await noteD1CaptureDefect(e, t.name); // WHICH table, and WHICH defect class (this always re-throws)
  }
  yield { rows, last: true, lastRowid: null, lastKey: null, pageIndex: 0 };
}

// pageByRowidKeyset pages a rowid table with WHERE _rowid_ > ? ORDER BY _rowid_ LIMIT n, exposing each
// page's last rowid as the cursor, so memory holds at most one page. The SELECT list is the integer-safe
// typed projection (typedProjection: typeof + CAST(int AS TEXT) per declared column) so an int64 column
// value past 2^53 is captured exactly, followed by a trailing CAST(_rowid_ AS TEXT) "__dp_rowid" cursor
// (also TEXT, so a rowid past 2^53 is not truncated by D1's float64 JSON number encoding, which would
// corrupt the WHERE _rowid_ > ? cursor and skip or repeat rows near the boundary). The cursor is the last
// result column, read separately and dropped from the cells. ORDER BY _rowid_ is the stable keyset order
// resume relies on. afterRowid starts below any possible rowid for a fresh table, or at the resume cursor.
//
// ADAPTIVE row LIMIT: the page size is chosen by BYTES, not a fixed row count, so a page record stays near
// D1_PAGE_TARGET_BYTES regardless of row width (a wide-row table that would blow the cap at a fixed 2000
// rows instead pages into many small, safe records, and stays resumable). targetBytes is bounded by the
// configured cap so a test lowering sizeLimit also shrinks the target. The FIRST page assumes the
// worst-case row size so the first fetch cannot balloon the isolate before any width is measured; every
// later page adapts from the previous page's average row size. The limit never exceeds rowsPerPage (so a
// narrow table is still capped at the configured page rows) and never drops below 1 (a single wide row is
// still emitted, and only a single row OVER the hard cap trips guardPageBytes, which D1's row limit
// prevents in practice).
async function* pageByRowidKeyset(reader: D1Reader, t: TablePlan, rowsPerPage: number, sizeLimit: number, startAfter: string | null, startPage: number, meter?: Meter): AsyncIterable<ResumableRowPage> {
  const targetBytes = pageTargetBytes(sizeLimit);
  let limit = firstPageLimit(rowsPerPage, targetBytes);
  let afterRowid = startAfter !== null ? BigInt(startAfter) : D1_ROWID_MIN;
  let pageIndex = startPage;
  // The integer-safe typed projection is constant per table, so build it (and run the wide-table guard)
  // ONCE, before the paging loop, rather than per page.
  const proj = typedProjection(t, true);
  for (;;) {
    meter?.spend(1, "d1Read");
    // D1's prepared-statement bind() REJECTS a JS bigint parameter (real D1 throws
    // "D1_TYPE_ERROR: Type 'bigint' not supported"), so the int64 keyset cursor is bound as a decimal
    // STRING and cast back to INTEGER in SQL. This keeps the full int64 range (a number bind would lose
    // precision above 2^53 and could skip or repeat a row near the boundary) and stays an exact
    // integer keyset comparison. The in-memory test D1 double accepts a bigint bind, which is why this
    // only ever surfaced against real D1; the live chaos harness caught it. The trailing
    // CAST(_rowid_ AS TEXT) cursor keeps the SAME precision on the way back out (see the doc comment).
    const q = `SELECT ${proj}, CAST(_rowid_ AS TEXT) AS "__dp_rowid" FROM ${quoteIdent(t.name)} WHERE _rowid_ > CAST(?1 AS INTEGER) ORDER BY _rowid_ LIMIT ?2`;
    const [, ...dataRows] = await reader
      .prepare(q)
      .bind(afterRowid.toString(), limit)
      .raw<unknown[]>({ columnNames: true });
    if (dataRows.length === 0) {
      yield { rows: [], last: true, lastRowid: null, lastKey: null, pageIndex };
      return;
    }
    const rows: D1Cell[][] = [];
    try {
      for (const raw of dataRows) {
        // The typed projection emits 2*ncols cell expressions; the trailing CAST(_rowid_ AS TEXT) is the
        // last result column (a decimal string cursor), read here and excluded from the decoded cells.
        const rowidVal = raw[raw.length - 1];
        afterRowid = toRowid(rowidVal);
        rows.push(typedCellsFromRow(raw, t.columns.length));
      }
      guardPageBytes(rows, t.name, sizeLimit);
    } catch (e) {
      await noteD1CaptureDefect(e, t.name); // WHICH table, and WHICH defect class
    }
    const last = dataRows.length < limit;
    yield { rows, last, lastRowid: afterRowid, lastKey: null, pageIndex };
    pageIndex++;
    if (last) return;
    limit = nextPageLimit(rows, rowsPerPage, targetBytes);
  }
}

// pageTargetBytes is the byte target of one row-page record, bounded by the configured cap so a test
// that lowers sizeLimit also shrinks the target. Both keyset pagers use it.
function pageTargetBytes(sizeLimit: number): number {
  return Math.max(1, Math.min(D1_PAGE_TARGET_BYTES, Math.floor(sizeLimit / 2)));
}

// firstPageLimit is the row LIMIT of a table's first page. No row width is known yet, so it assumes the
// worst-case row size and the first fetch cannot balloon the isolate.
function firstPageLimit(rowsPerPage: number, targetBytes: number): number {
  return Math.max(1, Math.min(rowsPerPage, Math.floor(targetBytes / D1_ASSUMED_MAX_ROW_BYTES)));
}

// nextPageLimit adapts the NEXT page's row limit from this page's average row size so the next record
// stays near targetBytes (clamped to [1, rowsPerPage]).
function nextPageLimit(rows: D1Cell[][], rowsPerPage: number, targetBytes: number): number {
  const avgRowBytes = Math.max(1, Math.ceil(pageByteEstimate(rows) / rows.length));
  return Math.max(1, Math.min(rowsPerPage, Math.floor(targetBytes / avgRowBytes)));
}

// pageByPrimaryKey pages a WITHOUT ROWID table by its PRIMARY KEY, the same way pageByRowidKeyset pages
// by rowid. Each query is
//   SELECT <typed projection> FROM t WHERE (k1, k2, ...) > (?1 COLLATE c1, ?2 COLLATE c2, ...)
//   ORDER BY k1 COLLATE c1, k2 COLLATE c2, ... LIMIT ?n
// The first page has no WHERE. The cursor is the last row's key tuple, read from the decoded cells, so
// no extra result column is needed. The row-value comparison and the ORDER BY use the collation of the
// key's own index (readPrimaryKey), so the order is total and SQLite seeks the key index. The COLLATE
// goes on the bound side: a COLLATE on the column side stops SQLite from using the index, and every
// page would then scan the table from its first row. The page LIMIT adapts to row width exactly as the
// rowid pager does. A key column declared DESC still pages correctly, but SQLite sorts each page.
//
// A page whose last key encodes to more than D1_KEY_CURSOR_MAX_BYTES reports no cursor. Unless it is the
// table's last page, the crawl emits no mark after it. The pager keeps that key in memory and reads on, so memory stays one
// page. The next page that ends on a smaller key gets a mark again. A table whose keys are all that large
// reads to its end with no mid-table mark, as the single-pass read did, but still in bounded pages.
//
// Each cursor cell is bound with its exact storage class (keyBind). A mismatch changes the comparison:
// SQLite orders values by class first (INTEGER and REAL, then TEXT, then BLOB), and an operand with
// numeric affinity converts a numeric-looking TEXT cell to a number before it compares.
async function* pageByPrimaryKey(reader: D1Reader, t: TablePlan, rowsPerPage: number, sizeLimit: number, startAfter: D1Cell[] | null, startPage: number, meter?: Meter): AsyncIterable<ResumableRowPage> {
  const targetBytes = pageTargetBytes(sizeLimit);
  let limit = firstPageLimit(rowsPerPage, targetBytes);
  let afterKey = startAfter;
  let pageIndex = startPage;
  const proj = typedProjection(t, false);
  const keyCols = t.keyColumns.map((k) => quoteIdent(t.columns[k.index]!));
  const colls = t.keyColumns.map((k) => quoteIdent(k.collation));
  const orderBy = keyCols.map((c, i) => `${c} COLLATE ${colls[i]}`).join(", ");
  for (;;) {
    meter?.spend(1, "d1Read");
    let where = "";
    const binds: unknown[] = [];
    if (afterKey !== null) {
      const rhs = afterKey.map((cell, i) => {
        const b = keyBind(cell, t.name);
        binds.push(b.value);
        return `${b.sql.replace("?", `?${i + 1}`)} COLLATE ${colls[i]}`;
      });
      where = ` WHERE (${keyCols.join(", ")}) > (${rhs.join(", ")})`;
    }
    binds.push(limit);
    const q = `SELECT ${proj} FROM ${quoteIdent(t.name)}${where} ORDER BY ${orderBy} LIMIT ?${binds.length}`;
    const [, ...dataRows] = await reader
      .prepare(q)
      .bind(...binds)
      .raw<unknown[]>({ columnNames: true });
    if (dataRows.length === 0) {
      yield { rows: [], last: true, lastRowid: null, lastKey: null, pageIndex };
      return;
    }
    const rows: D1Cell[][] = [];
    try {
      for (const raw of dataRows) rows.push(typedCellsFromRow(raw, t.columns.length));
      guardPageBytes(rows, t.name, sizeLimit);
    } catch (e) {
      await noteD1CaptureDefect(e, t.name); // WHICH table, and WHICH defect class
    }
    const lastRow = rows[rows.length - 1]!;
    afterKey = t.keyColumns.map((k) => lastRow[k.index]!);
    const last = dataRows.length < limit;
    const markable = utf8Encoder.encode(JSON.stringify(afterKey)).length <= D1_KEY_CURSOR_MAX_BYTES;
    yield { rows, last, lastRowid: null, lastKey: markable ? afterKey : null, pageIndex };
    pageIndex++;
    if (last) return;
    limit = nextPageLimit(rows, rowsPerPage, targetBytes);
  }
}

// keyBind maps one cursor cell to its placeholder and bound value, keeping the cell's storage class.
//   - An integer (a safe-integer number or a {$int}) binds as a decimal STRING under
//     (CAST(? AS INTEGER)+0). D1 rejects a bigint bind, and a number loses precision past 2^53. The +0
//     matters: a bare CAST carries INTEGER affinity, which converts a numeric-looking TEXT key such as
//     '2' to a number and skips it. The sum has no affinity.
//   - A REAL (any other number) binds as the number. An INTEGER and a REAL of the same value compare
//     equal, and a PRIMARY KEY cannot hold both, so the class of an integral number does not matter.
//   - TEXT binds as the string, and a BLOB binds as an ArrayBuffer (cellToBind).
//   - NULL cannot occur: a WITHOUT ROWID table refuses a NULL in any PRIMARY KEY column.
function keyBind(cell: D1Cell, tableName: string): { sql: string; value: unknown } {
  if (cell === null) throw new Error(`D1 export: a PRIMARY KEY cell of table ${tableName} is NULL; a WITHOUT ROWID key cannot hold NULL`);
  if (typeof cell === "number") {
    return Number.isSafeInteger(cell) ? { sql: "(CAST(? AS INTEGER)+0)", value: String(cell) } : { sql: "?", value: cell };
  }
  if (typeof cell === "object" && "$int" in cell) return { sql: "(CAST(? AS INTEGER)+0)", value: cell.$int };
  return { sql: "?", value: cellToBind(cell) };
}

// toRowid coerces the keyset cursor value into a bigint. The projection casts the cursor to TEXT
// (CAST(_rowid_ AS TEXT)), so it normally arrives as a decimal STRING, parsed here exactly so a rowid
// past 2^53 keeps every digit. A number or bigint (an older/local double that does not cast) is still
// accepted for back-compat. A rowid is always an integer; anything else is a binding contract violation.
function toRowid(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^-?\d+$/.test(v)) return BigInt(v);
  throw new D1DefectError("bad-rowid", `D1 export: unexpected non-integer rowid ${typeof v}`);
}

// pageByteEstimate is a cheap upper bound on a page's serialised JSON size without stringifying every cell
// twice: strings/$blob/$int carry their length, scalars are tiny. Used BOTH to adapt the next page's row
// limit (pageTableRows) and to enforce the hard cap (guardPageBytes), so the sizing and the guard agree.
function pageByteEstimate(rows: D1Cell[][]): number {
  let bytes = 0;
  for (const row of rows) {
    for (const cell of row) {
      if (typeof cell === "string") bytes += cell.length * 2 + 2;
      else if (cell !== null && typeof cell === "object") {
        const s = "$blob" in cell ? cell.$blob : cell.$int;
        bytes += s.length + 12;
      } else bytes += 24;
    }
  }
  return bytes;
}

// guardPageBytes refuses a page whose serialised size exceeds the per-page bound, keeping peak in-memory
// bytes bounded. With adaptive byte-bounded paging a page lands near D1_PAGE_TARGET_BYTES (well under the
// bound), so this now only ever fires on a SINGLE ROW larger than the bound, which is pathological (a row
// cannot be split across records) and D1's own row/statement limits keep it from happening; it is the
// loud backstop rather than the common path. Compared against the smaller of the per-page bound and the
// configured sizeLimit so a test that lowers sizeLimit still exercises the guard deterministically.
function guardPageBytes(rows: D1Cell[][], tableName: string, sizeLimit: number): void {
  const bound = Math.min(D1_PAGE_BYTE_LIMIT, sizeLimit);
  if (pageByteEstimate(rows) > bound) {
    throw new D1DefectError(
      "giant-row",
      `D1 export: a single row page of table ${tableName} exceeds the ${bound}-byte page limit; ` +
      `the row is too large to carry in one record (D1 row/statement limits should keep this from happening)`,
    );
  }
}
