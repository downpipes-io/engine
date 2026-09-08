import { cellFromTypedValue, quoteIdent, type D1Cell } from "./d1-format.ts";
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
    // G096: a session WITHOUT a working getBookmark cannot prove it held one point in time across a resume,
    // so it is recorded as unpinned rather than assumed pinned. The bookmark VALUE is never recorded, only
    // whether the guarantee exists.
    const pinned = typeof session.getBookmark === "function";
    recordSnapshotConsistency(pinned ? "pinned" : "unpinned");
    return {
      reader: session,
      getBookmark: () => (typeof session.getBookmark === "function" ? session.getBookmark() : null),
    };
  }
  // G096: the binding exposes no withSession(), so reads are NOT snapshot-isolated. The crawl still runs (a
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

// A per-table read plan: the dumped CREATE text, the ordered column names rows align to, and whether
// the table has a rowid (so the export can keyset-page by rowid). A WITHOUT ROWID table has no
// rowid, so it is read in one page (still under the session, still consistent); these are uncommon
// and small in practice (lookup/config tables) and cannot resume mid-table.
export interface TablePlan {
  name: string;
  sql: string;
  columns: string[];
  hasRowid: boolean;
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
      tables.push({ name: row.name, sql: row.sql, columns: [], hasRowid: false });
    } else if (row.type === "index" || row.type === "trigger" || row.type === "view") {
      schema.push(row.sql);
    }
    // Any other object type is ignored; the supported set is the SQLite DDL objects above.
  }

  // Read each table's column names (and detect rowid-ness) without reading its rows. A LIMIT 0
  // SELECT * returns just the column header via raw({columnNames:true}), so the column order the
  // dump aligns rows to is established before any row is read.
  for (const t of tables) {
    meter?.spend(1, "d1Read");
    const [header] = await reader.prepare(`SELECT * FROM ${quoteIdent(t.name)} LIMIT 0`).raw<unknown[]>({ columnNames: true });
    t.columns = header.map((c) => String(c));
    t.hasRowid = await tableHasRowid(reader, t.name, meter);
  }

  return { tables, schema };
}

// tableHasRowid reports whether a keyset-by-rowid paged read is possible for the table. A SELECT of
// _rowid_ succeeds on a rowid table and errors on a WITHOUT ROWID table; we treat any failure as "no
// rowid" and fall back to a single-pass read. (A LIMIT 0 keeps it free of data.)
async function tableHasRowid(reader: D1Reader, name: string, meter?: Meter): Promise<boolean> {
  try {
    meter?.spend(1, "d1Read");
    await reader.prepare(`SELECT _rowid_ FROM ${quoteIdent(name)} LIMIT 0`).raw<unknown[]>({ columnNames: true });
    return true;
  } catch {
    // G096: this catch is CORRECT for a genuine WITHOUT ROWID table, but a TRANSIENTLY failing probe on a
    // normal rowid table lands here too and degrades the table to an unbounded single-pass read with no
    // trace, which is what later OOMs "unrelatedly" and cannot be resumed mid-table. Count the fallback so
    // "two WITHOUT ROWID tables" is distinguishable from "the probe is failing across the whole database".
    // The probe's error is deliberately discarded: only the count is evidence, never the table name here.
    recordRowidProbeFallback();
    return false;
  }
}

// A ResumableRowPage is one keyset page plus the cursor a mark needs: the page's last rowid (null for
// a WITHOUT ROWID single-pass table, which cannot resume mid-table) and a per-table page index used
// only to make each rows record's name unique and ordered.
export interface ResumableRowPage {
  rows: D1Cell[][];
  last: boolean;
  lastRowid: bigint | null;
  pageIndex: number;
}

// pageTableRows yields a table's rows as keyset-ordered pages, STARTING after a given rowid so a
// resumed crawl reads only the rows it has not already emitted. For a rowid table it pages with
// WHERE _rowid_ > ? ORDER BY _rowid_ LIMIT n, exposing each page's last rowid as the cursor, so
// memory holds at most one page. The selected row shape is the integer-safe typed projection over the
// table's own columns (typedProjection) PLUS a trailing CAST(_rowid_ AS TEXT) used only as the cursor
// and stripped from the emitted cells, so the dumped columns are exactly the table's declared columns.
// A WITHOUT ROWID table (no _rowid_) is read in one pass over the same typed projection (still
// consistent under the session; uncommon and small in practice) and reports lastRowid null so its mark
// advances straight to the next table (it cannot resume mid-table).
//
// startAfter is the resume cursor: null (or for a WITHOUT ROWID table, ignored) starts the table; a
// bigint reads strictly after that rowid. A resume into a WITHOUT ROWID table with a non-null
// startAfter cannot happen (its mark always advances to the next table), so the single-pass branch
// reads the whole table from the start.
export async function* pageTableRows(
  reader: D1Reader,
  t: TablePlan,
  rowsPerPage: number,
  sizeLimit: number,
  startAfter: string | null,
  meter?: Meter,
): AsyncIterable<ResumableRowPage> {
  if (!t.hasRowid) {
    yield* pageWithoutRowid(reader, t, sizeLimit, meter);
    return;
  }
  yield* pageByRowidKeyset(reader, t, rowsPerPage, sizeLimit, startAfter, meter);
}

// noteD1CaptureDefect records a D1 CAPTURE-path decode defect (G069) and re-throws, so a single NaN cell,
// one giant row or a binding contract violation is attributable to a table rather than surfacing only as a
// generic "run failed" coarse class that leaves the customer to bisect their own schema to find it.
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

// pageWithoutRowid reads a WITHOUT ROWID table in one pass (still consistent under the session; uncommon
// and small in practice) via the integer-safe typed projection (typedProjection: typeof + CAST(int AS
// TEXT) per column) so an int64 past 2^53 is captured exactly rather than truncated by D1's float64 JSON
// number encoding. It reports lastRowid null so its mark advances straight to the next table (it cannot
// resume mid-table). A resume into such a table cannot carry a non-null startAfter (its mark always
// advances to the next table), so the whole table is read from the start.
//
// The row decode (and guardPageBytes) is wrapped so a decode defect is recorded (G069, noteD1CaptureDefect)
// before it re-throws: WHICH table and WHICH defect class, not just a generic "run failed".
async function* pageWithoutRowid(reader: D1Reader, t: TablePlan, sizeLimit: number, meter?: Meter): AsyncIterable<ResumableRowPage> {
  meter?.spend(1, "d1Read");
  const [, ...dataRows] = await reader.prepare(`SELECT ${typedProjection(t, false)} FROM ${quoteIdent(t.name)}`).raw<unknown[]>({ columnNames: true });
  let rows: D1Cell[][] = [];
  try {
    rows = dataRows.map((raw) => typedCellsFromRow(raw, t.columns.length));
    guardPageBytes(rows, t.name, sizeLimit);
  } catch (e) {
    await noteD1CaptureDefect(e, t.name); // G069: WHICH table, and WHICH defect class (this always re-throws)
  }
  yield { rows, last: true, lastRowid: null, pageIndex: 0 };
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
async function* pageByRowidKeyset(reader: D1Reader, t: TablePlan, rowsPerPage: number, sizeLimit: number, startAfter: string | null, meter?: Meter): AsyncIterable<ResumableRowPage> {
  const targetBytes = Math.max(1, Math.min(D1_PAGE_TARGET_BYTES, Math.floor(sizeLimit / 2)));
  let limit = Math.max(1, Math.min(rowsPerPage, Math.floor(targetBytes / D1_ASSUMED_MAX_ROW_BYTES)));
  let afterRowid = startAfter !== null ? BigInt(startAfter) : D1_ROWID_MIN;
  let pageIndex = 0;
  // The integer-safe typed projection is constant per table, so build it (and run the wide-table guard)
  // ONCE, before the paging loop, rather than per page.
  const proj = typedProjection(t, true);
  for (;;) {
    meter?.spend(1, "d1Read");
    // D1's prepared-statement bind() REJECTS a JS bigint parameter (real D1 throws
    // "D1_TYPE_ERROR: Type 'bigint' not supported"), so the int64 keyset cursor is bound as a decimal
    // STRING and cast back to INTEGER in SQL. This keeps the full int64 range (a number bind would lose
    // precision above 2^53 and could skip or repeat a row near the boundary) and stays an exact
    // integer keyset comparison. An in-memory test D1 double may accept a bigint bind even though real D1
    // does not, so this is verified against real D1 rather than a double. The trailing
    // CAST(_rowid_ AS TEXT) cursor keeps the SAME precision on the way back out (see the doc comment).
    const q = `SELECT ${proj}, CAST(_rowid_ AS TEXT) AS "__dp_rowid" FROM ${quoteIdent(t.name)} WHERE _rowid_ > CAST(?1 AS INTEGER) ORDER BY _rowid_ LIMIT ?2`;
    const [, ...dataRows] = await reader
      .prepare(q)
      .bind(afterRowid.toString(), limit)
      .raw<unknown[]>({ columnNames: true });
    if (dataRows.length === 0) {
      yield { rows: [], last: true, lastRowid: null, pageIndex };
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
      await noteD1CaptureDefect(e, t.name); // G069: WHICH table, and WHICH defect class
    }
    const last = dataRows.length < limit;
    yield { rows, last, lastRowid: afterRowid, pageIndex };
    pageIndex++;
    if (last) return;
    // Adapt the NEXT page's row limit from this page's average row size so the next record stays near
    // targetBytes (clamped to [1, rowsPerPage]).
    const avgRowBytes = Math.max(1, Math.ceil(pageByteEstimate(rows) / rows.length));
    limit = Math.max(1, Math.min(rowsPerPage, Math.floor(targetBytes / avgRowBytes)));
  }
}

// toRowid coerces the keyset cursor value into a bigint. The projection casts the cursor to TEXT
// (CAST(_rowid_ AS TEXT)), so it normally arrives as a decimal STRING, parsed here exactly so a rowid
// past 2^53 keeps every digit. A number or bigint (an older/local double that does not cast) is still
// accepted for back-compat. A rowid is always an integer; anything else is a binding contract violation.
function toRowid(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^-?\d+$/.test(v)) return BigInt(v);
  throw new Error(`D1 export: unexpected non-integer rowid ${typeof v}`);
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
    throw new Error(
      `D1 export: a single row page of table ${tableName} exceeds the ${bound}-byte page limit; ` +
      `the row is too large to carry in one record (D1 row/statement limits should keep this from happening)`,
    );
  }
}
