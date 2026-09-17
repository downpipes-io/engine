// The structured D1 backup record body. SPEC 12.1 carries a D1 database as one opaque blob
// with a `d1.format` hint and says "restore replays the dump". A binary SQLite file (the old
// D1Database.dump(), now deprecated) cannot be replayed: the runtime binding has no load()
// call, which is why the D1 restore was best-effort. A SQL-level export CAN be replayed
// through the binding, so the dump this engine carries is a structured schema-plus-rows
// document, not a binary file. The blob stays opaque to the FROZEN archive format (the record
// value is still verified by its plaintext SHA-384, unchanged); only the bytes INSIDE the
// blob are interpreted here, by the D1 source that writes them and the D1 sink that replays
// them. The format hint names which interpretation applies so an older reader can refuse a
// shape it does not understand rather than mis-replay it.

import { utf8 } from "../crypto/bytes.ts";

// The `d1.format` descriptor value for this body shape (SPEC 6.2 d1.format). Versioned on its
// own so a future row-encoding change is a body-format bump, not an archive major version.
export const D1_BACKUP_FORMAT = "downpipe-d1-json/1";

// A single cell value as D1 returns it from .all() and accepts it in .bind(). SQLite has five
// storage classes; over the D1 JS binding they surface as string, number, null and (for BLOB)
// bytes. JSON cannot hold bytes, so a BLOB is tagged and base64url-encoded on the way out and
// rebuilt into an ArrayBuffer on the way in. Numbers cover INTEGER and REAL; SQLite INTEGERs
// can exceed 2^53, so a large integer surfaced as a bigint is tagged too rather than lossily
// narrowed.
export type D1Cell =
  | string
  | number
  | null
  | { $blob: string } // base64url of the BLOB bytes
  | { $int: string }; // decimal string of an out-of-safe-range integer

// One table: its exact CREATE TABLE text (replayed verbatim so column types, constraints and
// without-rowid-ness survive), the ordered column names the rows align to, and the rows as
// arrays of cells in that column order.
export interface D1Table {
  name: string;
  sql: string; // the CREATE TABLE statement from sqlite_master
  columns: string[];
  rows: D1Cell[][];
}

// The whole database body. `schema` holds the non-table schema objects (indexes, triggers,
// views) as their CREATE text, applied AFTER the tables and their rows so a trigger or a
// covering index never fires or rebuilds mid-load. `tables` holds the user tables in
// dependency-tolerant declaration order (sqlite_master order, which lists a table before the
// objects defined on it).
export interface D1Backup {
  format: typeof D1_BACKUP_FORMAT;
  tables: D1Table[];
  schema: string[]; // CREATE INDEX/TRIGGER/VIEW statements, applied last
}

// encodeD1Backup serialises a backup body to the bytes carried as the record value. Canonical
// enough for a stable plaintext hash: JSON.stringify with a fixed key order via the typed
// shape. (The archive does not require this body to be canonical; it hashes whatever bytes it
// is given. A stable encoding only keeps intra-downpipe dedup meaningful run to run.)
//
// This is the REFERENCE form of the dump bytes. encodeD1BackupStream below produces the exact
// same byte sequence incrementally without ever holding the whole body, so a multi-GB D1 can
// be sealed without buffering it whole; validate-d1-restore pins the two byte-for-byte.
export function encodeD1Backup(b: D1Backup): Uint8Array {
  return utf8(JSON.stringify(b));
}

// A D1RowPage is one keyset-ordered batch of a table's rows as the source read them from D1,
// already in the tagged D1Cell form. last reports whether this is the final page (so the
// streamer can close the rows array), and the source pages until last is true.
export interface D1RowPage {
  rows: D1Cell[][];
  last: boolean;
}

// A D1DumpPlan is the schema-and-structure half of a streamed dump: the table list (name +
// CREATE text + ordered column names) and the non-table schema (CREATE INDEX/TRIGGER/VIEW),
// read up front and small by construction (DDL only, never rows). It is paired with a
// pageRows callback that yields each table's rows lazily, one bounded page at a time, so the
// whole row set is never materialised. The streamer drives pageRows once per table.
export interface D1DumpPlan {
  tables: { name: string; sql: string; columns: string[] }[];
  schema: string[];
  // pageRows yields successive keyset-ordered pages for the table at index ti. It is an async
  // iterable so the source controls page size and resumes its keyset cursor between pages. The
  // streamer consumes pages in order and stops when a page reports last:true.
  pageRows(ti: number): AsyncIterable<D1RowPage>;
}

// encodeD1BackupStream emits the dump body as a byte stream that is BYTE-IDENTICAL to
// encodeD1Backup over the same content, so the stored dump format (and therefore the in-account
// restore and the offline Go reader replay) is unchanged. It hand-serialises the same JSON
// shape JSON.stringify produces for { format, tables:[{name,sql,columns,rows}], schema } with
// the same key order, escaping each scalar/cell with JSON.stringify (which is context-free, so
// a value stringified alone is byte-identical to the same value inside the parent object). It
// holds at most one row page and one emitted chunk, never the whole body. Field key order
// (format, then tables, then schema; per table name, sql, columns, rows) mirrors the typed
// object literal exportDatabase builds, which is what keeps the bytes identical.
export async function* encodeD1BackupStream(plan: D1DumpPlan): AsyncIterable<Uint8Array> {
  // The encoder works in JS strings and flushes utf8 bytes at boundaries that never split a
  // surrogate pair (every yield is a whole JSON.stringify result or a fixed ASCII punctuator),
  // so a multibyte character is never cut across two chunks.
  yield utf8(`{"format":${JSON.stringify(D1_BACKUP_FORMAT)},"tables":[`);
  for (let ti = 0; ti < plan.tables.length; ti++) {
    const t = plan.tables[ti]!;
    if (ti > 0) yield utf8(",");
    // {"name":<>,"sql":<>,"columns":[<>,...],"rows":[
    let head = `{"name":${JSON.stringify(t.name)},"sql":${JSON.stringify(t.sql)},"columns":[`;
    for (let ci = 0; ci < t.columns.length; ci++) head += (ci > 0 ? "," : "") + JSON.stringify(t.columns[ci]);
    head += '],"rows":[';
    yield utf8(head);
    let rowsEmitted = 0;
    for await (const page of plan.pageRows(ti)) {
      for (const row of page.rows) {
        let s = rowsEmitted > 0 ? ",[" : "[";
        for (let j = 0; j < row.length; j++) s += (j > 0 ? "," : "") + JSON.stringify(row[j]);
        s += "]";
        yield utf8(s);
        rowsEmitted++;
      }
      if (page.last) break;
    }
    yield utf8("]}"); // close rows array, then the table object
  }
  // ],"schema":[<>,...]}
  let tail = '],"schema":[';
  for (let si = 0; si < plan.schema.length; si++) tail += (si > 0 ? "," : "") + JSON.stringify(plan.schema[si]);
  tail += "]}";
  yield utf8(tail);
}

// validCell shape-checks a decoded cell: a JSON scalar (null/string/number) or one of the two
// tagged forms, {$blob:string} or {$int:string} whose value is a decimal integer. A cell that
// is neither is refused at decode so cellToBind never throws mid-write on apply.
function validCell(c: unknown): c is D1Cell {
  if (c === null || typeof c === "string" || typeof c === "number") return true;
  if (typeof c === "object" && c !== null && !Array.isArray(c)) {
    const o = c as Record<string, unknown>;
    if (Object.keys(o).length !== 1) return false;
    if ("$blob" in o) return typeof o.$blob === "string";
    if ("$int" in o) return typeof o.$int === "string" && /^-?\d+$/.test(o.$int);
  }
  return false;
}

// CREATE_TRIGGER_RE picks out the one CREATE kind, of the three CREATE INDEX/TRIGGER/VIEW a schema
// entry accepts, that legitimately carries a BEGIN...END body. d1RequireSingleStatement only tracks
// BEGIN/CASE...END nesting for an entry that matches this -- see its doc comment for why. Mirrors
// the Go CLI transcoder's d1CreateTriggerRe (downpipe/internal/restore/d1transcode.go).
const CREATE_TRIGGER_RE = /^\s*CREATE\s+TRIGGER\b/i;

// d1RequireSingleStatement rejects a DDL/schema string that carries more than one top-level
// statement, closing the gap the CREATE TABLE/INDEX/TRIGGER/VIEW prefix regexes above leave open: a
// prefix match only proves the string STARTS with the right keyword, not that nothing else follows,
// so `CREATE TABLE t(x); DROP TABLE other; --` passes those regexes unchanged. Unlike the Go
// `downpipe` CLI (which only writes such a string into a .sql file a human reviews before running
// it), a decoded table/schema entry here is handed straight to `this.db.prepare()` and replayed via
// `db.batch()` against a LIVE target D1 binding with no human review step at all (D1RestoreSink in
// restore-sink.ts). Verified directly (not just by inspection) against a real local D1 binding
// (wrangler's `--local` D1, the same workerd SQLite engine that backs production D1) that
// `db.prepare("CREATE TABLE t(x); DROP TABLE IF EXISTS payments;").run()`, and the equivalent
// `db.batch([...])` call, BOTH silently execute every statement in the string, not only the first --
// unlike a bare `sqlite3_prepare_v2()` call, which compiles just the first statement and leaves the
// rest as an unexecuted "tail". So the prefix-only gap is confirmed live-execution injection here,
// not merely a shape defect.
//
// allowTriggerBody must be true only for a CREATE TRIGGER entry, the one DDL kind that legitimately
// carries a BEGIN...END body with its own internal ';'-separated statements and, inside that, a
// CASE...END expression (which can itself nest). CREATE TABLE/INDEX/VIEW are, by SQLite grammar,
// always exactly one statement with no legitimate semicolon at all other than an optional one right
// at the very end -- so for those this does not track BEGIN/CASE/END at all, and simply requires
// that the first ';' found outside a literal is the only content left, whitespace aside.
//
// A prior version of this function tracked BEGIN/CASE/END with one shared depth counter (BEGIN and
// CASE both incremented it, any END decremented it). That is unsound: SQLite trigger grammar never
// nests a second compound block inside a trigger body (there is exactly ONE real top-level
// BEGIN...END per CREATE TRIGGER statement), so treating a bare "begin" as if it could legitimately
// re-open a new nesting level is already wrong, and it is exploitable: a bare, unquoted column alias
// spelled "begin" (`SELECT 1 AS begin`, valid SQL, no quoting needed) bumps the shared counter
// exactly like the trigger's own real BEGIN, so the trigger's REAL closing END only brings the
// counter back to 1 instead of 0, hiding every ';' after it (including a smuggled statement's own
// terminator) behind depth>0 until something later rebalances the counter back to zero. Confirmed,
// both against this function directly and end to end against a live local D1 binding, that this
// shape passed the prior guard unmodified and achieved genuine live execution of a smuggled
// `DROP TABLE`:
//   CREATE TRIGGER evil AFTER INSERT ON t
//   BEGIN
//     SELECT 1 AS begin;
//   END;
//   DROP TABLE payments;
//   SELECT 1 AS end;
// A decorative trailing bare `END` statement (the shape used to demonstrate the original gap) is
// NOT required to rebalance the prior counter: the final `SELECT 1 AS end;` above does the same job,
// and unlike a bare `END`/`BEGIN`/`SAVEPOINT` used as its own top-level statement (which D1 happens
// to refuse, in favour of `state.storage.transaction()`, an unrelated safety rail against raw
// transaction control, not a security boundary), an aliased `AS end` inside an ordinary SELECT is not
// caught by that incidental guard.
//
// The fix models the grammar instead of patching the same lexical guess again: `bodyOpen` opens
// exactly once, on the first bare BEGIN, and a later bare "begin" cannot re-open it (there is no
// legitimate second body to open), so it is inert -- exactly like a real column reference such as
// `NEW.begin` used anywhere in the body. `caseDepth` is tracked separately because CASE...END is
// genuinely re-enterable (a CASE expression can nest inside another); a bare END closes the
// innermost open CASE first, and only closes the body itself once no CASE is open. On top of that, a
// bareword immediately preceded (skipping only whitespace) by "." or by the keyword "AS" is always
// treated as a plain identifier, never as BEGIN/CASE/END. That is not a heuristic: it is what SQL
// grammar requires. "x.begin" can only mean "column begin of x" and "AS begin" can only mean "alias
// named begin", in both cases regardless of "begin" being a keyword elsewhere (SQLite's own `nm`
// grammar production accepts keyword-shaped tokens as names in exactly these two positions). That
// closes the alias/reference trick above at its root: `SELECT 1 AS begin` and `NEW.begin` no longer
// read as anything other than what they are.
//
// Residual, deliberately not chased further: a BARE column reference spelled "begin"/"case"/"end",
// used mid-body with neither a preceding "." nor a preceding "AS" (e.g. `WHERE end < 5` against a
// real column literally named "end", referenced unqualified), can still desynchronise `bodyOpen` if
// it appears before the trigger's true closing END, because a lexical scanner with no real grammar
// cannot tell that occurrence apart from the genuine closing keyword without knowing whether more
// legitimate body content follows. Closing this fully needs a real SQL parser, not another lexical
// patch. This residual is materially narrower and harder to weaponise than the alias-based one above:
// unlike `AS begin` (always parses, no runtime resolution needed), a bare unqualified reference must
// ALSO resolve to a real column somewhere in scope, and D1 was observed (same local-binding test) to
// validate every statement in a multi-statement `prepare()`/`batch()` call before executing ANY of
// them -- an unresolvable bare identifier such as a stray `end` with no matching column anywhere in
// scope makes D1 itself refuse the whole call up front (`D1_ERROR: no such column: end`), which is
// incidental behaviour this code does not rely on, but means this residual is not a free
// live-execution primitive the way the alias trick was. It is also gated behind the same actor this
// function already assumes throughout: the honest data path (D1Source reading `sqlite_master.sql`)
// can never itself produce a multi-statement DDL string, so anything reaching this function already
// had to come from a forged/tampered archive, i.e. a party holding that downpipe's own AEAD/signing
// key material.
//
// Whichever mode applies, a quote/backtick/bracket identifier or line/block comment that never
// closes before the string ends is ALSO rejected (never silently scanned to end-of-string with no
// error). That matters because decodeD1Backup/decodeD1Record validate each DDL/schema array entry in
// ISOLATION, and D1RestoreSink later prepares every entry's SQL and runs them together inside one
// db.batch() call: an entry that left a literal dangling open must never be allowed through on the
// assumption that "something later" closes it, since a real single sqlite_master DDL statement is,
// by construction, already fully self-contained. Requiring every span to close within its own entry
// costs nothing for legitimate input and forecloses any future replay path that might concatenate
// entries' text (as the Go CLI's file-writing transcoder does) from ever splicing two entries into
// one attacker-shaped statement.
//
// Mirrors the Go transcoder's d1RequireSingleStatement (downpipe/internal/restore/d1transcode.go):
// that implementation needs the identical bodyOpen/caseDepth/qualified-identifier fix so the
// engine's live-apply decode path and the CLI's offline file-generation transcode keep enforcing the
// same grammar (tracked as a sibling fix; out of scope for this file).
function d1RequireSingleStatement(stmt: string, allowTriggerBody: boolean): void {
  const isIdentByte = (c: string): boolean => c === "_" || (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9");
  const isSpace = (c: string): boolean => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v";
  let bodyOpen = false; // the trigger's single real BEGIN...END body: opens once, closes once
  let caseDepth = 0; // CASE...END expression nesting: genuinely re-enterable, unlike the body
  let prevSignificant = ""; // "." or "AS" iff that was the last non-whitespace token seen
  let term = -1;
  const n = stmt.length;
  let i = 0;
  while (i < n) {
    const c = stmt[i]!;
    if (isSpace(c)) {
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      // String/identifier literal: SQLite treats ', ", and ` alike -- a doubled delimiter is an
      // escaped literal character, a lone one closes the span. It must close within this entry:
      // see the unterminated-span note above.
      const start = i;
      i++;
      let closed = false;
      while (i < n) {
        if (stmt[i] === c) {
          if (i + 1 < n && stmt[i + 1] === c) {
            i += 2;
            continue;
          }
          i++;
          closed = true;
          break;
        }
        i++;
      }
      if (!closed) throw new Error(`statement has an unterminated ${c}...${c} literal starting at position ${start}`);
      prevSignificant = "";
    } else if (c === "[") {
      // bracket identifier: no escaping, must close at a following ']'
      const j = stmt.indexOf("]", i + 1);
      if (j < 0) throw new Error("statement has an unterminated [...] identifier");
      i = j + 1;
      prevSignificant = "";
    } else if (c === "-" && i + 1 < n && stmt[i + 1] === "-") {
      // line comment, must end by end of line
      const j = stmt.indexOf("\n", i);
      if (j < 0) throw new Error("statement has an unterminated -- comment (no trailing newline)");
      i = j + 1;
      prevSignificant = "";
    } else if (c === "/" && i + 1 < n && stmt[i + 1] === "*") {
      // block comment
      const j = stmt.indexOf("*/", i + 2);
      if (j < 0) throw new Error("statement has an unterminated /* */ comment");
      i = j + 2;
      prevSignificant = "";
    } else if (c === ".") {
      // Dot/member access: whatever bareword immediately follows is a column/member name, never a
      // keyword (see doc comment above), so remember it for the identifier branch below.
      prevSignificant = ".";
      i++;
    } else if (c === ";") {
      if (!bodyOpen && caseDepth === 0) {
        term = i;
        break;
      }
      i++;
      prevSignificant = "";
    } else if (allowTriggerBody && isIdentByte(c)) {
      // Only a CREATE TRIGGER entry inspects bare identifiers for BEGIN/CASE/END: for every other
      // kind this branch never runs at all, so a bare "begin"/"case"/"end" column or identifier
      // name there is just skipped like any other token (see doc comment above).
      const start = i;
      while (i < n && isIdentByte(stmt[i]!)) i++;
      const word = stmt.slice(start, i).toUpperCase();
      const qualified = prevSignificant === "." || prevSignificant === "AS";
      if (word === "AS") {
        prevSignificant = "AS";
      } else {
        if (!qualified) {
          if (word === "BEGIN") {
            if (!bodyOpen) bodyOpen = true; // only the first bare BEGIN can be the real opener
          } else if (word === "CASE") {
            caseDepth++;
          } else if (word === "END") {
            if (caseDepth > 0) caseDepth--;
            else if (bodyOpen) bodyOpen = false;
          }
        }
        prevSignificant = "";
      }
    } else {
      i++;
      prevSignificant = "";
    }
  }
  if (bodyOpen || caseDepth !== 0) throw new Error("statement has an unterminated BEGIN or CASE block");
  const rest = term >= 0 ? stmt.slice(term + 1) : "";
  if (rest.trim() !== "") throw new Error("statement carries content after its terminating ';' (more than one statement)");
}

// validateTableEntry shape-checks one entry of the backup's tables array and returns the typed
// D1Table, mirroring how decodeTableDDL validates the DDL-only entries on the per-page path. It
// throws a plain Error (the sink maps it to a coarse reason) so a malformed table from an unknown
// or future writer is refused loudly at decode time rather than half-replayed on apply.
function validateTableEntry(t: unknown): D1Table {
  if (typeof t !== "object" || t === null) throw new Error("D1 backup table entry is not an object");
  const to = t as Record<string, unknown>;
  const name = to.name;
  const sql = to.sql;
  const columns = to.columns;
  const rows = to.rows;
  if (typeof name !== "string" || name.length === 0) throw new Error("D1 backup table has no name");
  if (typeof sql !== "string" || sql.length === 0) throw new Error(`D1 backup table ${name} has no CREATE statement`);
  // Defence in depth: the replayed DDL must be a CREATE TABLE, so a body cannot smuggle a
  // different statement into the schema-replay path (row VALUES are always bound, never text).
  if (!/^\s*CREATE\s+TABLE\b/i.test(sql)) throw new Error(`D1 backup table ${name} sql is not a CREATE TABLE statement`);
  // The prefix check above only proves the string STARTS with CREATE TABLE, not that nothing else
  // follows: this closes that gap (see d1RequireSingleStatement). CREATE TABLE never legitimately
  // carries a BEGIN...END body (only CREATE TRIGGER does), so no trigger-body allowance is passed.
  try {
    d1RequireSingleStatement(sql, false);
  } catch (e) {
    throw new Error(`D1 backup table ${name} sql: ${(e as Error).message}`);
  }
  if (!Array.isArray(columns) || !columns.every((c) => typeof c === "string")) throw new Error(`D1 backup table ${name} has a malformed column list`);
  if (!Array.isArray(rows)) throw new Error(`D1 backup table ${name} has a malformed rows list`);
  // Every row must have one cell per column (or a parameterised insert binds the wrong arity),
  // and every cell must be a well-formed D1Cell, so a malformed cell is refused at decode time
  // (in a dry run too) rather than throwing mid-write on apply.
  for (const r of rows as unknown[]) {
    if (!Array.isArray(r) || r.length !== columns.length) {
      throw new Error(`D1 backup table ${name} has a row whose cell count does not match its ${columns.length} columns`);
    }
    for (const cell of r as unknown[]) {
      if (!validCell(cell)) throw new Error(`D1 backup table ${name} has a malformed cell`);
    }
  }
  return { name, sql, columns: columns as string[], rows: rows as D1Cell[][] };
}

// decodeD1Backup parses and VALIDATES a backup body read back from a verified record. The
// bytes have already passed the archive's plaintext-hash check, so this is not a trust
// boundary; it is a shape guard so a body from an unknown/future writer is refused loudly
// rather than half-replayed. It throws a plain Error the sink maps to a coarse reason.
export function decodeD1Backup(bytes: Uint8Array): D1Backup {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("D1 backup body is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("D1 backup body is not an object");
  const o = parsed as Record<string, unknown>;
  if (o.format !== D1_BACKUP_FORMAT) {
    throw new Error(`unsupported D1 backup format ${String(o.format)}; this reader understands ${D1_BACKUP_FORMAT}`);
  }
  if (!Array.isArray(o.tables)) throw new Error("D1 backup body has no tables array");
  if (!Array.isArray(o.schema)) throw new Error("D1 backup body has no schema array");
  const tables: D1Table[] = [];
  for (const t of o.tables as unknown[]) {
    tables.push(validateTableEntry(t));
  }
  const schema: string[] = [];
  for (const s of o.schema as unknown[]) {
    if (typeof s !== "string") throw new Error("D1 backup schema entry is not a string");
    // The non-table replay accepts only CREATE INDEX/TRIGGER/VIEW, matching what the D1 source
    // exports, so an unexpected statement kind is refused before any write.
    if (!/^\s*CREATE\s+(INDEX|TRIGGER|VIEW)\b/i.test(s)) throw new Error("D1 backup schema entry is not a CREATE INDEX/TRIGGER/VIEW statement");
    // Same defence as the table DDL above: the prefix check alone lets a trailing statement through.
    // Only CREATE TRIGGER legitimately carries a BEGIN...END body, so the depth tracker runs ONLY
    // for a trigger entry -- a bare "begin"/"case"/"end" in a CREATE INDEX/VIEW can never hide a ';'
    // behind it (see d1RequireSingleStatement).
    try {
      d1RequireSingleStatement(s, CREATE_TRIGGER_RE.test(s));
    } catch (e) {
      throw new Error(`D1 backup schema entry: ${(e as Error).message}`);
    }
    schema.push(s);
  }
  return { format: D1_BACKUP_FORMAT, tables, schema };
}

// ---- Resumable per-page D1 record shapes (D1 resumability) ------------------------------------
// A large D1 is backed up as a SEQUENCE of bounded records the sliced seal can checkpoint BETWEEN
// (resumable across invocations), instead of one whole-database stream that must seal in a single
// invocation. The records are emitted, sealed, and restored in this strict order:
//   1. ONE header record (downpipe-d1-header/1): every table's CREATE + ordered column names, NO rows.
//      Small (DDL only). On restore it runs the fresh-target check ONCE and creates all tables.
//   2. MANY row-page records (downpipe-d1-rows/1): one keyset page of one table's rows, carrying the
//      table name + its columns so the INSERT is self-contained. Bounded by the page byte guard, so each
//      buffers safely. On restore each APPENDS its rows to the (already header-created) table.
//   3. ONE schema record (downpipe-d1-schema/1): the CREATE INDEX/TRIGGER/VIEW objects, applied LAST.
// The legacy whole-database downpipe-d1-json/1 record (encodeD1Backup) is still decoded on restore, so
// archives written before this keep restoring unchanged. The per-page records are the resumable path.
export const D1_HEADER_FORMAT = "downpipe-d1-header/1";
export const D1_ROWS_FORMAT = "downpipe-d1-rows/1";
export const D1_SCHEMA_FORMAT = "downpipe-d1-schema/1";

export interface D1TableDDL {
  name: string;
  sql: string;
  columns: string[];
}

export function encodeD1Header(tables: D1TableDDL[]): Uint8Array {
  return utf8(JSON.stringify({ format: D1_HEADER_FORMAT, tables }));
}
export function encodeD1RowsPage(table: string, columns: string[], rows: D1Cell[][]): Uint8Array {
  return utf8(JSON.stringify({ format: D1_ROWS_FORMAT, table, columns, rows }));
}
export function encodeD1Schema(schema: string[]): Uint8Array {
  return utf8(JSON.stringify({ format: D1_SCHEMA_FORMAT, schema }));
}

// D1Record is the discriminated result of decodeD1Record: the legacy whole-database body, or one of the
// three resumable record kinds. The restore sink dispatches on .kind.
export type D1Record =
  | { kind: "full"; body: D1Backup }
  | { kind: "header"; tables: D1TableDDL[] }
  | { kind: "rows"; table: string; columns: string[]; rows: D1Cell[][] }
  | { kind: "schema"; schema: string[] };

// decodeTableDDL validates one {name, sql, columns} entry (no rows): a non-empty name, a CREATE TABLE
// statement (so a body can never smuggle a different statement into the DDL-replay path), and a string
// column list. Shared by the header decoder.
function decodeTableDDL(t: unknown): D1TableDDL {
  if (typeof t !== "object" || t === null) throw new Error("D1 header table entry is not an object");
  const to = t as Record<string, unknown>;
  const name = to.name;
  const sql = to.sql;
  if (typeof name !== "string" || name.length === 0) throw new Error("D1 header table has no name");
  if (typeof sql !== "string" || !/^\s*CREATE\s+TABLE\b/i.test(sql)) throw new Error(`D1 header table ${name} sql is not a CREATE TABLE statement`);
  // Same defence as validateTableEntry: the prefix check alone only proves the string starts with
  // CREATE TABLE, not that nothing else follows. CREATE TABLE never carries a BEGIN...END body (only
  // CREATE TRIGGER does), so no trigger-body allowance is passed.
  try {
    d1RequireSingleStatement(sql, false);
  } catch (e) {
    throw new Error(`D1 header table ${name} sql: ${(e as Error).message}`);
  }
  if (!Array.isArray(to.columns) || !to.columns.every((c) => typeof c === "string")) throw new Error(`D1 header table ${name} has a malformed column list`);
  return { name, sql, columns: to.columns as string[] };
}

// decodeSchemaList validates a list of CREATE INDEX/TRIGGER/VIEW statements (the only non-table objects
// the D1 source exports), refusing any other statement kind before a write.
function decodeSchemaList(s: unknown): string[] {
  if (!Array.isArray(s)) throw new Error("D1 schema record has no schema array");
  const out: string[] = [];
  for (const e of s) {
    if (typeof e !== "string") throw new Error("D1 schema entry is not a string");
    if (!/^\s*CREATE\s+(INDEX|TRIGGER|VIEW)\b/i.test(e)) throw new Error("D1 schema entry is not a CREATE INDEX/TRIGGER/VIEW statement");
    // Same defence as decodeD1Backup's schema loop: only CREATE TRIGGER legitimately carries a
    // BEGIN...END body, so the depth tracker runs ONLY for a trigger entry (see d1RequireSingleStatement).
    try {
      d1RequireSingleStatement(e, CREATE_TRIGGER_RE.test(e));
    } catch (err) {
      throw new Error(`D1 schema entry: ${(err as Error).message}`);
    }
    out.push(e);
  }
  return out;
}

// decodeD1Record parses + VALIDATES any D1 record body (the bytes already passed the archive plaintext
// hash; this is a shape guard so a malformed/foreign body is refused loudly, in a dry run too, rather than
// half-replayed). It dispatches on the body's `format`, so a sink handles legacy and resumable bodies the
// same way: decode, then act on .kind.
export function decodeD1Record(bytes: Uint8Array): D1Record {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("D1 record body is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("D1 record body is not an object");
  const o = parsed as Record<string, unknown>;
  switch (o.format) {
    case D1_BACKUP_FORMAT:
      return { kind: "full", body: decodeD1Backup(bytes) };
    case D1_HEADER_FORMAT: {
      if (!Array.isArray(o.tables)) throw new Error("D1 header record has no tables array");
      return { kind: "header", tables: (o.tables as unknown[]).map(decodeTableDDL) };
    }
    case D1_ROWS_FORMAT: {
      if (typeof o.table !== "string" || o.table.length === 0) throw new Error("D1 rows record has no table name");
      if (!Array.isArray(o.columns) || !o.columns.every((c) => typeof c === "string")) throw new Error(`D1 rows record for ${o.table} has a malformed column list`);
      if (!Array.isArray(o.rows)) throw new Error(`D1 rows record for ${o.table} has a malformed rows list`);
      const columns = o.columns as string[];
      for (const r of o.rows as unknown[]) {
        if (!Array.isArray(r) || r.length !== columns.length) throw new Error(`D1 rows record for ${o.table} has a row whose cell count does not match its ${columns.length} columns`);
        for (const cell of r as unknown[]) if (!validCell(cell)) throw new Error(`D1 rows record for ${o.table} has a malformed cell`);
      }
      return { kind: "rows", table: o.table, columns, rows: o.rows as D1Cell[][] };
    }
    case D1_SCHEMA_FORMAT:
      return { kind: "schema", schema: decodeSchemaList(o.schema) };
    default:
      throw new Error(`unsupported D1 record format ${String(o.format)}; this reader understands ${D1_BACKUP_FORMAT}, ${D1_HEADER_FORMAT}, ${D1_ROWS_FORMAT}, ${D1_SCHEMA_FORMAT}`);
  }
}

// cellToBind converts a decoded cell into the value handed to D1PreparedStatement.bind(). A
// tagged BLOB becomes an ArrayBuffer (the binding's BLOB input) and a tagged big integer
// becomes a bigint; plain JSON scalars pass through. Bound values are NEVER interpolated into
// SQL text, so a value can never be SQL: this is the parameterisation that makes data
// injection-proof regardless of its contents.
export function cellToBind(c: D1Cell): string | number | bigint | null | ArrayBuffer {
  if (c === null) return null;
  if (typeof c === "string" || typeof c === "number") return c;
  if ("$blob" in c) {
    const bytes = b64urlToBytes(c.$blob);
    const out = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(out).set(bytes);
    return out;
  }
  // A tagged out-of-range integer round-trips through bigint so it is not narrowed.
  return BigInt(c.$int);
}

// cellFromValue converts a value read from D1 .all() into a JSON-safe cell for the backup
// body, tagging the two kinds JSON cannot represent directly (bytes and out-of-safe-range
// integers). Unknown shapes are refused so the backup never silently drops a cell type.
export function cellFromValue(v: unknown): D1Cell {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return v;
  if (typeof v === "bigint") {
    // Keep it a plain number when it fits the JSON-safe range; tag it otherwise.
    return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(v)
      : { $int: v.toString() };
  }
  if (typeof v === "number") {
    // A non-finite REAL (Infinity/-Infinity/NaN) has no JSON form: JSON.stringify emits `null`, which
    // would SILENTLY turn the value into NULL on backup and restore (data corruption with no signal).
    // Refuse it loudly (fail closed, like the unsupported-type throw below) rather than lose it silently.
    if (!Number.isFinite(v)) throw new Error(`D1 cell of unsupported non-finite numeric value ${String(v)}`);
    return v;
  }
  if (v instanceof ArrayBuffer) return { $blob: bytesToB64url(new Uint8Array(v)) };
  if (ArrayBuffer.isView(v)) return { $blob: bytesToB64url(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)) };
  // D1's .raw() returns a BLOB column as a plain number[] of byte values (0-255), NOT an ArrayBuffer. The
  // crawl reads rows via .raw() (d1.ts pageTableRows), so without this branch a real BLOB throws the
  // unsupported-type error below and fails the WHOLE D1 backup. Validate each element is a byte so a
  // non-byte array (a binding contract violation) fails closed rather than corrupting via truncation.
  if (Array.isArray(v)) {
    const bytes = new Uint8Array(v.length);
    for (let i = 0; i < v.length; i++) {
      const n = v[i];
      if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 255) {
        throw new Error("D1 cell of unsupported array shape (a BLOB must be a byte array)");
      }
      bytes[i] = n;
    }
    return { $blob: bytesToB64url(bytes) };
  }
  throw new Error(`D1 cell of unsupported type ${typeof v}`);
}

// The safe-integer boundary as bigints, computed once. Number.MAX_SAFE_INTEGER is 2^53-1; an integer
// strictly outside [MIN_SAFE_INTEGER, MAX_SAFE_INTEGER] cannot be held as an exact JS number, so it is
// carried as an {$int} decimal string rather than narrowed.
const MIN_SAFE_INT_BIG = BigInt(Number.MIN_SAFE_INTEGER);
const MAX_SAFE_INT_BIG = BigInt(Number.MAX_SAFE_INTEGER);

// cellFromTypedValue decodes ONE cell from the D1 reader's TYPED projection (d1-reader.ts): for each
// declared column the projection selects typeof(col) AND a value that, for an 'integer' column, is
// CAST(col AS TEXT) -- an EXACT decimal string -- and otherwise the bare column value. This is what
// makes an int64 past 2^53 survive capture: D1's query API returns a bare integer as a float64 JSON
// number, silently truncating a value above 2^53, so reading the value alone (cellFromValue over a
// plain SELECT) loses precision BEFORE this code ever sees it. Reading typeof + CAST(col AS TEXT)
// instead delivers the digits intact.
//
// typeofStr is SQLite's typeof() result ('null'|'integer'|'real'|'text'|'blob'); value is the paired
// projected value. Mapping:
//   'null'    -> null
//   'integer' -> the decimal string; Number(it) when within the safe range, else {$int: it}
//   'real'    -> the float64 number (a non-finite REAL is refused, matching cellFromValue)
//   'text'    -> the string
//   'blob'    -> reuse cellFromValue's byte-array BLOB decode (D1 .raw() surfaces a BLOB as a number[])
// A value whose runtime type does not match its typeof() class is a binding-contract violation, refused
// loudly rather than silently mis-tagged.
//
// Boundary note: an integer in [2^53, 2^54) that a plain read happened to represent exactly as a bare
// number now encodes as an {$int} decimal string instead. The VALUE is identical; only the encoding
// changes (this is not byte-identical output across that boundary, and is not claimed to be).
export function cellFromTypedValue(typeofStr: unknown, value: unknown): D1Cell {
  switch (typeofStr) {
    case "null":
      return null;
    case "integer": {
      if (typeof value !== "string" || !/^-?\d+$/.test(value)) {
        throw new Error(`D1 typed cell: an 'integer' column did not project as a decimal string (got ${typeof value}); the typed projection CASTs integer columns to TEXT`);
      }
      const big = BigInt(value);
      return big >= MIN_SAFE_INT_BIG && big <= MAX_SAFE_INT_BIG ? Number(big) : { $int: value };
    }
    case "real": {
      if (typeof value !== "number") throw new Error(`D1 typed cell: a 'real' column did not project as a number (got ${typeof value})`);
      if (!Number.isFinite(value)) throw new Error(`D1 cell of unsupported non-finite numeric value ${String(value)}`);
      return value;
    }
    case "text": {
      if (typeof value !== "string") throw new Error(`D1 typed cell: a 'text' column did not project as a string (got ${typeof value})`);
      return value;
    }
    case "blob":
      // The projection's CASE else-branch returns the BLOB unchanged; D1 .raw() surfaces it as a
      // number[] of byte values, which cellFromValue tags as {$blob}.
      return cellFromValue(value);
    default:
      throw new Error(`D1 typed cell: unexpected typeof() storage class ${JSON.stringify(typeofStr)}`);
  }
}

// quoteIdent wraps a SQLite identifier (a table or column name) for safe interpolation into
// the INSERT text the sink builds. Identifiers cannot be bound as parameters, so they are
// escaped the SQLite way: wrap in double quotes and double any embedded double quote. A name
// can then never break out of its quotes to inject SQL, even one chosen adversarially.
export function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

// The body uses base64url (no pad), matching the archive's binary-field convention, kept local
// so this module has no dependency beyond crypto/bytes for utf8. These two mirror
// b64urlEncode/Decode but operate without importing them to keep the cell helpers self
// contained for the validator that imports this module directly.
function bytesToB64url(b: Uint8Array): string {
  // latin1 maps each byte 1:1 to a code point, building the binary string in one pass rather than
  // an O(n) string concatenation per byte (which spikes CPU for large BLOB cells).
  const s = new TextDecoder("latin1").decode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
