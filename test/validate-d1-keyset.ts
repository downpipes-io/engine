// Keyset paging of a WITHOUT ROWID table by its PRIMARY KEY (src/sources/d1-reader.ts pageByPrimaryKey),
// run against a REAL SQLite engine (node:sqlite) behind a D1-shaped double. The row-value comparison, the
// key collation, the storage-class order and the affinity rules are SQLite's own here, not a regex model of
// them, so a cursor that binds a key cell with the wrong class or collation skips or repeats a real row.
//
// The proofs:
//   1. A composite-key WITHOUT ROWID table whose rows total more than the (lowered) page cap crawls to
//      completion over several row-page records. The old single-page read threw the page guard here.
//   2. A crawl resumed from the mark after a mid-table page reads exactly the remaining rows, and the first
//      slice plus the resumed records restore into a fresh database byte-identical to the source.
//   3. A key that mixes storage classes (int64 extremes, a REAL, numeric-looking TEXT, TEXT, BLOB) and a key
//      whose index collation differs from its column collation page one row at a time with no row lost,
//      duplicated or reordered. Every row's key is a cursor, so every bind shape is exercised.
//   4. The keyset query seeks the PRIMARY KEY index (EXPLAIN QUERY PLAN says SEARCH, with no temp sort).
//   5. The resume token carries a key cursor and refuses a malformed one.
//   6. Only a table whose DDL says WITHOUT ROWID pages by its key. A rowid table whose _rowid_ probe fails
//      (a transient fault) keeps the single-pass read, even with NULLs in a TEXT PRIMARY KEY. A probe that
//      fails on one slice and recovers on the next cannot wedge the run. A rowid cursor continues by rowid
//      when the probe fails on the resume. A key cursor on a table that is not WITHOUT ROWID is refused
//      with the closed bad-cursor class. The DDL test agrees with SQLite's own PRAGMA table_list.
//   7. A resumed crawl continues the page numbering, so no rows record name repeats one already sealed.
//   8. A key too large for the checkpoint gets no mark: the table still reads in bounded pages, and every
//      mark stays under the key cursor cap.
//   9. A BLOB may hold any byte. BLOBs covering every byte value 0x00 to 0xFF, in a rowid table and as the
//      key of a WITHOUT ROWID table, crawl without a refusal and restore byte-identical. The BLOB encoder
//      once built its binary string with TextDecoder("latin1"), which is windows-1252 under the WHATWG
//      Encoding standard, so any byte from 0x80 to 0x9F made btoa throw and failed the whole D1 backup.
// Run:
//   node test/validate-d1-keyset.ts

import { DatabaseSync } from "node:sqlite";
import { D1RestoreSink } from "../src/dest/restore-sink.ts";
import { decodeD1Record, type D1Cell } from "../src/sources/d1-format.ts";
import { D1_PAGE_BYTE_LIMIT, D1Source } from "../src/sources/d1.ts";
import { parseToken } from "../src/sources/d1-token.ts";
import * as reader from "../src/sources/d1-reader.ts";
import { drainSourceFaultLedger, resetSourceFaultLedger } from "../src/sources/source-fault-ledger.ts";
import type { CrawlEvent, SourceRecord } from "../src/sources/types.ts";
import { SqliteD1, toSqliteBind } from "./lib/sqlite-d1.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- helpers ------------------------------------------------------------------------------------------

async function collect(iter: AsyncIterable<CrawlEvent>): Promise<{ records: SourceRecord[]; events: CrawlEvent[] }> {
  const records: SourceRecord[] = [];
  const events: CrawlEvent[] = [];
  for await (const ev of iter) {
    events.push(ev);
    if (ev.kind === "record") records.push(ev.record);
  }
  return { records, events };
}

function rowsOf(records: SourceRecord[], table: string): D1Cell[][] {
  const out: D1Cell[][] = [];
  for (const r of records) {
    const d = decodeD1Record(r.value!);
    if (d.kind === "rows" && d.table === table) out.push(...d.rows);
  }
  return out;
}

function pageCount(records: SourceRecord[], table: string): number {
  return records.filter((r) => {
    const d = decodeD1Record(r.value!);
    return d.kind === "rows" && d.table === table;
  }).length;
}

const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

// dump reads a table back from SQLite with each cell's storage class and exact SQL literal, in key order.
// Two databases with equal dumps hold byte-identical rows.
function dump(d1: SqliteD1, table: string, columns: string[], orderBy: string): string[] {
  const proj = columns.map((c) => `typeof("${c}") || ':' || quote("${c}")`).join(` || '|' || `);
  return (d1.db.prepare(`SELECT ${proj} AS r FROM "${table}" ORDER BY ${orderBy}`).all() as Array<{ r: string }>).map((x) => x.r);
}

// sourceCells reads a table the way the typed projection would decode it, in key order, so a capture can
// be compared with the source cell for cell.
function sourceCells(d1: SqliteD1, table: string, columns: string[], orderBy: string): D1Cell[][] {
  const proj = columns.map((c) => `typeof("${c}") AS "t_${c}", CASE WHEN typeof("${c}")='integer' THEN CAST("${c}" AS TEXT) ELSE "${c}" END AS "v_${c}"`).join(", ");
  const rows = d1.db.prepare(`SELECT ${proj} FROM "${table}" ORDER BY ${orderBy}`).all() as Record<string, unknown>[];
  return rows.map((r) =>
    columns.map((c): D1Cell => {
      const t = r[`t_${c}`];
      const v = r[`v_${c}`];
      if (t === "null") return null;
      if (t === "integer") {
        const big = BigInt(v as string);
        return big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : { $int: v as string };
      }
      if (t === "blob") return { $blob: Buffer.from(v as Uint8Array).toString("base64url") };
      return v as D1Cell;
    }),
  );
}

// ---- fixtures -----------------------------------------------------------------------------------------

const EVENTS_SQL = 'CREATE TABLE "events" (tenant TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT, PRIMARY KEY (tenant, seq)) WITHOUT ROWID';
const EVENTS_COLS = ["tenant", "seq", "body"];
const EVENTS_ORDER = '"tenant", "seq"';
const MIXED_SQL = 'CREATE TABLE "mixed" (k, c TEXT COLLATE NOCASE, v, PRIMARY KEY (k, c COLLATE BINARY)) WITHOUT ROWID';
const MIXED_COLS = ["k", "c", "v"];
const MIXED_ORDER = '"k", "c" COLLATE BINARY';
const NOCASE_SQL = 'CREATE TABLE "names" (n TEXT COLLATE NOCASE PRIMARY KEY, v INTEGER) WITHOUT ROWID';

function seedEvents(d1: SqliteD1): void {
  d1.db.exec(EVENTS_SQL);
  const ins = d1.db.prepare('INSERT INTO "events" VALUES (?, ?, ?)');
  // 3 tenants x 20 rows, each row about 1.2 KB serialised. Some seq values pass 2^53, so the cursor must
  // keep every digit of an int64 key.
  for (const tenant of ["acme", "beta", "gamma"]) {
    for (let i = 1; i <= 20; i++) {
      const seq = i % 5 === 0 ? (1n << 60n) + BigInt(i) : BigInt(i);
      ins.run(tenant, seq, `${tenant}-${i}-`.padEnd(600, "x"));
    }
  }
}

function seedMixed(d1: SqliteD1): void {
  d1.db.exec(MIXED_SQL);
  d1.db.exec(`INSERT INTO "mixed" VALUES
    (9223372036854775807, 'm', 1), (-9223372036854775808, 'a', 2), (9007199254740993, 'x', 3),
    (2.5, 'r', 4), (3, 'X', 5), (3, 'x', 6), ('2', 'x', 7), ('abc', 'q', 8),
    (x'00ff', 'z', 9), (x'00', 'z', 10), (-0.5, 'n', 11), (1e300, 'e', 12)`);
  d1.db.exec(NOCASE_SQL);
  d1.db.exec(`INSERT INTO "names" VALUES ('a', 1), ('B', 2), ('c', 3), ('D', 4)`);
  // A key column with no affinity where an INTEGER key is followed by a numeric-looking TEXT key. A cursor
  // bound under a bare CAST(? AS INTEGER) carries INTEGER affinity, so SQLite compares '2' as the number 2,
  // plans a table scan, and skips the row.
  d1.db.exec(`CREATE TABLE "loose" (k PRIMARY KEY, v) WITHOUT ROWID`);
  d1.db.exec(`INSERT INTO "loose" VALUES (1, 1), (3, 2), ('2', 3), ('abc', 4)`);
}

// A page cap of 16 KiB gives an 8 KiB page target: the 60 events rows (about 72 KB) need many pages.
const LOW_CAP = 16 * 1024;

// ---- proofs -------------------------------------------------------------------------------------------

async function proveCompositeKeyPages(): Promise<void> {
  console.log("composite PRIMARY KEY, WITHOUT ROWID, larger than one page:");
  const d1 = new SqliteD1();
  seedEvents(d1);
  let threw = "";
  let records: SourceRecord[] = [];
  try {
    records = (await collect(new D1Source(d1 as unknown as D1Database, "kdb", LOW_CAP).crawlFrom({ include: [], exclude: [] }, null))).records;
  } catch (e) {
    threw = (e as Error).message;
  }
  ok(`the crawl completes without the page guard firing${threw ? ` (threw: ${threw.slice(0, 90)})` : ""}`, threw === "");
  ok("the table is split over several row-page records", pageCount(records, "events") > 5);
  ok("no single keyset query held more rows than fit the page target", d1.maxPageRows > 0 && d1.maxPageRows <= 7);
  ok("every row is captured once, in key order, cell for cell", same(rowsOf(records, "events"), sourceCells(d1, "events", EVENTS_COLS, EVENTS_ORDER)));

  // The keyset query seeks the key index instead of scanning and sorting the table on every page.
  const last = d1.keysetQueries.at(-1);
  ok("the crawl issued keyset queries with a row-value WHERE", last !== undefined);
  if (last) {
    const s = d1.db.prepare(`EXPLAIN QUERY PLAN ${last.sql}`);
    const plan = (s.all(...last.binds.map(toSqliteBind)) as Array<{ detail: string }>).map((r) => r.detail).join(" / ");
    ok(`the keyset query SEARCHes the PRIMARY KEY index (${plan})`, /SEARCH events USING PRIMARY KEY/.test(plan) && !/TEMP B-TREE/.test(plan));
  }
}

async function proveResumeMidTable(): Promise<void> {
  console.log("resume mid-table from a key cursor, then restore byte-identical:");
  const src = new SqliteD1();
  seedEvents(src);
  const first = await collect(new D1Source(src as unknown as D1Database, "kdb", LOW_CAP).crawlFrom({ include: [], exclude: [] }, null));

  // The mark after the THIRD rows page of events: a slice that stops there seals the header and 3 pages.
  let resumeToken: string | null = null;
  let seen = 0;
  for (let i = 0; i < first.events.length && resumeToken === null; i++) {
    const ev = first.events[i]!;
    if (ev.kind === "record" && decodeD1Record(ev.record.value!).kind === "rows" && ++seen === 3) {
      const next = first.events[i + 1];
      if (next?.kind === "mark") resumeToken = next.token;
    }
  }
  ok("found the mark after the third rows page", resumeToken !== null);
  const tok = resumeToken === null ? null : parseToken(resumeToken);
  ok(
    "the mark stays in the table and carries the last key tuple (tenant, seq)",
    tok !== null && tok.phase === "rows" && tok.ti === 0 && tok.afterRowid === null && Array.isArray(tok.afterKey) && tok.afterKey.length === 2 && typeof tok.afterKey[0] === "string",
  );
  if (resumeToken === null) return;

  const firstSlice: SourceRecord[] = [];
  for (const ev of first.events) {
    if (ev.kind === "record") firstSlice.push(ev.record);
    if (ev.kind === "mark" && ev.token === resumeToken) break;
  }

  const resumed = await collect(new D1Source(src as unknown as D1Database, "kdb", LOW_CAP).crawlFrom({ include: [], exclude: [] }, resumeToken));
  const all = sourceCells(src, "events", EVENTS_COLS, EVENTS_ORDER);
  const firstRows = rowsOf(firstSlice, "events");
  ok("the first slice sealed some rows but not all", firstRows.length > 0 && firstRows.length < all.length);
  ok("the resumed crawl reads exactly the rows after the cursor (no loss, no repeat)", same(rowsOf(resumed.records, "events"), all.slice(firstRows.length)));
  ok("the resumed crawl does not re-emit the header", resumed.records.every((r) => decodeD1Record(r.value!).kind !== "header"));

  // Restore the first slice, then the resumed records, into one fresh database.
  const target = new SqliteD1();
  const sink = new D1RestoreSink(target as unknown as D1Database, "kdb", false);
  for (const r of [...firstSlice, ...resumed.records]) await sink.put(r.name, r.value!);
  const before = dump(src, "events", EVENTS_COLS, EVENTS_ORDER);
  const after = dump(target, "events", EVENTS_COLS, EVENTS_ORDER);
  ok(`the restored table is byte-identical to the source (${after.length} of ${before.length} rows)`, before.length === 60 && same(before, after));
}

async function proveMixedKeyClasses(): Promise<void> {
  console.log("keys of every storage class, and an index collation unlike the column's:");
  const d1 = new SqliteD1();
  seedMixed(d1);
  // rowsPerPage 1: every row is its own page, so every row's key is bound back as a cursor.
  const { records } = await collect(new D1Source(d1 as unknown as D1Database, "mdb", D1_PAGE_BYTE_LIMIT, 1).crawlFrom({ include: [], exclude: [] }, null));
  const want = sourceCells(d1, "mixed", MIXED_COLS, MIXED_ORDER);
  ok("the mixed-class table pages one row per record", pageCount(records, "mixed") === want.length);
  ok("every mixed-class row comes back once, in SQLite key order, cell for cell", same(rowsOf(records, "mixed"), want));
  ok("both 'x' and 'X' under a BINARY key on a NOCASE column are kept", rowsOf(records, "mixed").filter((r) => r[0] === 3).length === 2);
  const names = rowsOf(records, "names").map((r) => r[0]);
  ok("a NOCASE key pages in NOCASE order with no row lost (a, B, c, D)", same(names, ["a", "B", "c", "D"]));
  ok("a numeric-looking TEXT key after an INTEGER key is not skipped (1, 3, '2', 'abc')", same(rowsOf(records, "loose").map((r) => r[0]), [1, 3, "2", "abc"]));
}

function proveTokenCodec(): void {
  console.log("resume token key cursor:");
  const good = parseToken(JSON.stringify({ bookmark: null, phase: "rows", ti: 2, afterRowid: null, afterKey: ["t", 3, { $int: "9223372036854775807" }, { $blob: "AP8" }, 2.5] }));
  ok("a key cursor parses with its cells intact", good.phase === "rows" && same(good.afterKey, ["t", 3, { $int: "9223372036854775807" }, { $blob: "AP8" }, 2.5]));
  const legacy = parseToken(JSON.stringify({ bookmark: null, phase: "rows", ti: 0, afterRowid: "7" }));
  ok("a rowid cursor still parses, with no key", legacy.phase === "rows" && legacy.afterRowid === "7" && legacy.afterKey === undefined);
  const bad: Array<[string, unknown]> = [
    ["a key cursor with a rowid cursor", { afterRowid: "7", afterKey: ["t"] }],
    ["an empty key", { afterRowid: null, afterKey: [] }],
    ["a NULL key cell", { afterRowid: null, afterKey: [null] }],
    ["a malformed key cell", { afterRowid: null, afterKey: [{ $int: "12x" }] }],
    ["a key that is not an array", { afterRowid: null, afterKey: "t" }],
  ];
  for (const [label, extra] of bad) {
    let msg = "";
    try {
      parseToken(JSON.stringify({ bookmark: null, phase: "rows", ti: 0, ...(extra as object) }));
    } catch (e) {
      msg = (e as Error).message;
    }
    ok(`refuses ${label} (bad-cursor)`, /malformed D1 resume token \(bad-cursor\)/.test(msg));
  }
}

// markAfterRowsPage returns the mark that follows the n-th rows record (1-based) of a crawl, or null.
function markAfterRowsPage(events: CrawlEvent[], n: number): string | null {
  let seen = 0;
  for (let i = 0; i < events.length; i++) {
    const ev = events[i]!;
    if (ev.kind === "record" && decodeD1Record(ev.record.value!).kind === "rows" && ++seen === n) {
      const next = events[i + 1];
      return next?.kind === "mark" ? next.token : null;
    }
  }
  return null;
}

// sliceBefore returns the records a slice sealed when it stopped at the given mark.
function sliceBefore(events: CrawlEvent[], token: string): SourceRecord[] {
  const out: SourceRecord[] = [];
  for (const ev of events) {
    if (ev.kind === "record") out.push(ev.record);
    if (ev.kind === "mark" && ev.token === token) break;
  }
  return out;
}

async function crawlOrError(d1: SqliteD1, token: string | null, rowsPerPage: number, cap = D1_PAGE_BYTE_LIMIT): Promise<{ records: SourceRecord[]; events: CrawlEvent[]; error: string }> {
  try {
    return { ...(await collect(new D1Source(d1 as unknown as D1Database, "fdb", cap, rowsPerPage).crawlFrom({ include: [], exclude: [] }, token))), error: "" };
  } catch (e) {
    return { records: [], events: [], error: (e as Error).message };
  }
}

async function proveOnlyDeclaredWithoutRowidPagesByKey(): Promise<void> {
  console.log("only a table declared WITHOUT ROWID pages by its key; a flaky _rowid_ probe cannot wedge a run:");

  // The DDL test agrees with SQLite's own record of the table kind (PRAGMA table_list, column wr). The
  // tables put the words WITHOUT ROWID in a comment, a string default and a quoted identifier, where they
  // do not make the table WITHOUT ROWID.
  const declares = (reader as Record<string, unknown>).declaresWithoutRowid as ((sql: string) => boolean) | undefined;
  ok("d1-reader exports declaresWithoutRowid", typeof declares === "function");
  const ddl = new DatabaseSync(":memory:");
  ddl.exec(`CREATE TABLE a (k TEXT PRIMARY KEY) /* c (x) */ WITHOUT ROWID -- trailing (y)
`);
  ddl.exec(`CREATE TABLE b (k TEXT PRIMARY KEY, "WITHOUT ROWID" TEXT DEFAULT ') WITHOUT ROWID') -- WITHOUT ROWID
`);
  ddl.exec("CREATE TABLE c (k INTEGER PRIMARY KEY) STRICT, WITHOUT ROWID");
  ddl.exec("create table d (k int primary key) without\n  rowid");
  ddl.exec("CREATE TABLE e (a TEXT, b TEXT, PRIMARY KEY(a,b)) /* WITHOUT ROWID */");
  ddl.exec("CREATE TABLE [f] (k TEXT PRIMARY KEY, `without rowid)` TEXT) WITHOUT ROWID");
  ddl.exec("CREATE TABLE g (k TEXT PRIMARY KEY CHECK (k <> ')'))");
  ddl.exec("CREATE TABLE h (k TEXT PRIMARY KEY) /* WITHOUT ROWID */ STRICT");
  const kinds = ddl.prepare("SELECT m.name AS name, m.sql AS sql, l.wr AS wr FROM sqlite_master m JOIN pragma_table_list l ON l.name = m.name AND l.schema = 'main' WHERE m.type = 'table' ORDER BY m.name").all() as Array<{ name: string; sql: string; wr: number | bigint }>;
  ok(`the DDL fixture covers 8 tables (${kinds.length})`, kinds.length === 8);
  for (const k of kinds) {
    const want = Number(k.wr) === 1;
    ok(`table ${k.name}: declaresWithoutRowid is ${want}, as PRAGMA table_list says`, typeof declares === "function" && declares(k.sql) === want);
  }

  // (a) A rowid table with a composite TEXT PRIMARY KEY that holds NULLs. Its _rowid_ probe fails. It must
  // keep the single-pass read, which captures every row, rather than page by a key that can hold NULL.
  const nulls = new SqliteD1();
  nulls.db.exec('CREATE TABLE "t" (a TEXT, b TEXT, PRIMARY KEY (a, b))');
  const insNull = nulls.db.prepare('INSERT INTO "t" VALUES (?, ?)');
  for (let i = 0; i < 18; i++) insNull.run(`k${String(i % 6).padStart(2, "0")}`, i % 3 === 0 ? null : `v${i}`);
  nulls.failRowidProbe = true;
  resetSourceFaultLedger();
  const a = await crawlOrError(nulls, null, 4);
  const fallbacks = drainSourceFaultLedger().rowidProbeFallbacks;
  ok(`a flaky probe on a rowid table with NULL key cells does not fail the run${a.error ? ` (threw: ${a.error.slice(0, 90)})` : ""}`, a.error === "");
  ok(`every row of that table is captured once (${rowsOf(a.records, "t").length} of 18)`, rowsOf(a.records, "t").length === 18);
  ok("no mark carries a key cursor for a table that is not WITHOUT ROWID", a.events.every((e) => e.kind !== "mark" || !e.token.includes("afterKey")));
  ok(`the failed probe is counted as a rowid probe fallback (${fallbacks})`, fallbacks === 1);

  // (b) The probe fails on slice 1 and recovers on slice 2. Slice 1 reads the rowid table in one pass and
  // its mark moves on to the next table, so slice 2 resumes cleanly and the run completes.
  const flaky = new SqliteD1();
  flaky.db.exec('CREATE TABLE "u" (k TEXT PRIMARY KEY, v TEXT)');
  flaky.db.exec('CREATE TABLE "w" (k TEXT PRIMARY KEY, v TEXT)');
  const insU = flaky.db.prepare('INSERT INTO "u" VALUES (?, ?)');
  const insW = flaky.db.prepare('INSERT INTO "w" VALUES (?, ?)');
  for (let i = 0; i < 12; i++) {
    insU.run(`k${String(i).padStart(3, "0")}`, `u${i}`);
    insW.run(`k${String(i).padStart(3, "0")}`, `w${i}`);
  }
  flaky.failRowidProbe = true;
  const slice1 = await crawlOrError(flaky, null, 4);
  const tok1 = markAfterRowsPage(slice1.events, 1);
  ok("slice 1 (probe failing) emitted a mark after its first rows page", tok1 !== null);
  flaky.failRowidProbe = false;
  const slice2 = tok1 === null ? { records: [], events: [], error: "no token" } : await crawlOrError(flaky, tok1, 4);
  ok(`slice 2 (probe recovered) resumes without a cursor-kind error${slice2.error ? ` (threw: ${slice2.error.slice(0, 90)})` : ""}`, slice2.error === "");
  if (tok1 !== null) {
    const both = [...sliceBefore(slice1.events, tok1), ...slice2.records];
    for (const t of ["u", "w"]) {
      const got = rowsOf(both, t).map((row) => JSON.stringify(row)).sort();
      const want = sourceCells(flaky, t, ["k", "v"], '"k"').map((row) => JSON.stringify(row)).sort();
      ok(`slices 1 and 2 together hold every row of ${t} once (${got.length} of ${want.length})`, same(got, want));
    }
  }

  // (c) A rowid cursor, then a probe that fails on the resume slice. The cursor proves the table has a
  // rowid, so the resume continues by rowid and reads exactly the remaining rows.
  flaky.failRowidProbe = false;
  const healthy = await crawlOrError(flaky, null, 4);
  const tokRowid = markAfterRowsPage(healthy.events, 1);
  ok("a healthy slice leaves a rowid cursor mid-table", tokRowid !== null && /"afterRowid":"\d+"/.test(tokRowid));
  flaky.failRowidProbe = true;
  const resumedRowid = tokRowid === null ? { records: [], events: [], error: "no token" } : await crawlOrError(flaky, tokRowid, 4);
  flaky.failRowidProbe = false;
  ok(`a rowid cursor resumes by rowid when the probe fails on the resume${resumedRowid.error ? ` (threw: ${resumedRowid.error.slice(0, 90)})` : ""}`, resumedRowid.error === "");
  if (tokRowid !== null) {
    const first = rowsOf(sliceBefore(healthy.events, tokRowid), "u");
    const rest = rowsOf(resumedRowid.records, "u");
    ok(`the resume reads exactly the rows after the cursor (${first.length} + ${rest.length} of 12)`, first.length + rest.length === 12 && same([...first, ...rest], rowsOf(healthy.records, "u")));
  }

  // (d) A key cursor on a table that is not WITHOUT ROWID is refused with the closed bad-cursor class, so
  // the wedge reads as a corrupt resume token in the support pack, not as a generic run failure.
  resetSourceFaultLedger();
  const wrongKind = await crawlOrError(flaky, JSON.stringify({ bookmark: SqliteD1.BOOKMARK, phase: "rows", ti: 0, afterRowid: null, afterKey: ["k003"] }), 4);
  const led = drainSourceFaultLedger();
  ok(`a key cursor on a rowid table is refused as bad-cursor (${wrongKind.error.slice(0, 60)})`, /malformed D1 resume token \(bad-cursor\)/.test(wrongKind.error));
  ok("the refusal is recorded under the closed bad-cursor class", (led.resumeTokenDefects["bad-cursor"] ?? 0) === 1);
  resetSourceFaultLedger();
  const wr = new SqliteD1();
  seedEvents(wr);
  const rowidOnKey = await crawlOrError(wr, JSON.stringify({ bookmark: SqliteD1.BOOKMARK, phase: "rows", ti: 0, afterRowid: "5" }), 4);
  ok(`a rowid cursor on a WITHOUT ROWID table is refused as bad-cursor (${rowidOnKey.error.slice(0, 60)})`, /malformed D1 resume token \(bad-cursor\)/.test(rowidOnKey.error));
  resetSourceFaultLedger();
}

async function proveResumeKeepsNamesUnique(): Promise<void> {
  console.log("a resumed crawl continues the page numbering:");
  for (const kind of ["WITHOUT ROWID", "rowid"] as const) {
    const d1 = new SqliteD1();
    if (kind === "rowid") {
      d1.db.exec('CREATE TABLE "events" (tenant TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT, PRIMARY KEY (tenant, seq))');
      const ins = d1.db.prepare('INSERT INTO "events" VALUES (?, ?, ?)');
      for (let i = 1; i <= 60; i++) ins.run("acme", i, "x".repeat(600));
    } else {
      seedEvents(d1);
    }
    const first = await collect(new D1Source(d1 as unknown as D1Database, "kdb", LOW_CAP).crawlFrom({ include: [], exclude: [] }, null));
    const tok = markAfterRowsPage(first.events, 3);
    if (tok === null) {
      ok(`${kind}: found the mark after the third rows page`, false);
      continue;
    }
    const resumed = await collect(new D1Source(d1 as unknown as D1Database, "kdb", LOW_CAP).crawlFrom({ include: [], exclude: [] }, tok));
    const names = [...sliceBefore(first.events, tok), ...resumed.records].map((r) => r.name);
    ok(`${kind}: every record name across the first and the resumed slice is unique (${names.length})`, new Set(names).size === names.length);
    // The first slice sealed pages 000000..000002, so the resumed table starts at page 000003.
    const resumedPages = resumed.records.map((r) => r.name).filter((n) => n.includes("/10-rows/")).map((n) => n.slice(-6));
    ok(`${kind}: the resumed pages continue the numbering at 000003 (${resumedPages[0]})`, resumedPages[0] === "000003");
  }
}

async function proveOversizedKeyGetsNoMark(): Promise<void> {
  console.log("a key too large for the checkpoint gets no mark:");
  const cap = (reader as Record<string, unknown>).D1_KEY_CURSOR_MAX_BYTES as number | undefined;
  ok("d1-reader exports D1_KEY_CURSOR_MAX_BYTES", typeof cap === "number" && cap > 0);
  const limit = typeof cap === "number" ? cap : 4096;
  const d1 = new SqliteD1();
  d1.db.exec('CREATE TABLE "big" (k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID');
  const ins = d1.db.prepare('INSERT INTO "big" VALUES (?, ?)');
  // Keys a, c, e, ... are small. Keys b, d, f, ... are larger than the cap.
  for (let i = 0; i < 12; i++) {
    const letter = String.fromCharCode(97 + i);
    ins.run(i % 2 === 0 ? letter : letter.padEnd(limit * 3, "z"), i);
  }
  const r = await crawlOrError(d1, null, 1);
  ok(`the crawl completes${r.error ? ` (threw: ${r.error.slice(0, 90)})` : ""}`, r.error === "");
  ok(`every row is captured once, one row per record (${rowsOf(r.records, "big").length} of 12)`, rowsOf(r.records, "big").length === 12 && pageCount(r.records, "big") === 12);
  const marks = r.events.filter((e): e is Extract<CrawlEvent, { kind: "mark" }> => e.kind === "mark");
  const longest = Math.max(...marks.map((m) => new TextEncoder().encode(m.token).length));
  ok(`no mark token carries an oversized key (longest ${longest} bytes)`, longest < limit + 512);
  const keyMarks = marks.filter((m) => m.token.includes("afterKey")).length;
  ok(`the pages that end on a small key still get a key mark (${keyMarks})`, keyMarks >= 5);
  // A resume from the mark after a small key reads the rest, including the large keys.
  const tok = marks.find((m) => m.token.includes('"afterKey":["c"]'))?.token ?? null;
  ok("found the mark after key c", tok !== null);
  if (tok !== null) {
    const rest = await crawlOrError(d1, tok, 1);
    ok(`a resume after key c reads the 9 rows after it (${rowsOf(rest.records, "big").length})`, rest.error === "" && rowsOf(rest.records, "big").length === 9);
  }
}

// everyByte returns the 256 byte values in order.
function everyByte(): Uint8Array {
  const b = new Uint8Array(256);
  for (let i = 0; i < 256; i++) b[i] = i;
  return b;
}

async function proveEveryByteValueRoundTrips(): Promise<void> {
  console.log("BLOBs holding every byte value 0x00 to 0xFF crawl and restore byte-identical:");
  const d1 = new SqliteD1();
  d1.db.exec('CREATE TABLE "blobs" (id INTEGER PRIMARY KEY, b BLOB)');
  const ins = d1.db.prepare('INSERT INTO "blobs" VALUES (?, ?)');
  // One BLOB of all 256 values, one BLOB per single value, the 32 bytes 0x80 to 0x9F alone, and a long
  // BLOB that crosses the encoder's chunk boundary several times.
  ins.run(1n, everyByte());
  for (let i = 0; i < 256; i++) ins.run(BigInt(i + 2), Uint8Array.of(i));
  ins.run(258n, everyByte().subarray(0x80, 0xa0));
  const long = new Uint8Array(3 * 8192 + 5);
  for (let i = 0; i < long.length; i++) long[i] = (i * 131 + 17) & 0xff;
  ins.run(259n, long);
  // A WITHOUT ROWID table keyed by a BLOB, paged two rows at a time, so every key byte also travels
  // through the keyset cursor bind (keyBind -> cellToBind) and back.
  d1.db.exec('CREATE TABLE "bkeys" (k BLOB PRIMARY KEY, v INTEGER) WITHOUT ROWID');
  const insKey = d1.db.prepare('INSERT INTO "bkeys" VALUES (?, ?)');
  for (let i = 0; i < 256; i++) insKey.run(Uint8Array.of(i, 0x80 + (i % 32)), BigInt(i));

  const { records, error } = await crawlOrError(d1, null, 2);
  ok(`the crawl completes with no refusal${error ? ` (threw: ${error.slice(0, 90)})` : ""}`, error === "");
  ok("every blobs row is captured once, cell for cell", same(rowsOf(records, "blobs"), sourceCells(d1, "blobs", ["id", "b"], '"id"')));
  ok("every bkeys row is captured once, in key order, cell for cell", same(rowsOf(records, "bkeys"), sourceCells(d1, "bkeys", ["k", "v"], '"k"')));
  const first = rowsOf(records, "blobs")[0]?.[1];
  ok(
    "the all-bytes BLOB is carried as the base64url of exactly those 256 bytes",
    typeof first === "object" && first !== null && "$blob" in first && first.$blob === Buffer.from(everyByte()).toString("base64url"),
  );
  if (error !== "") return; // nothing was captured, so there is nothing to restore; the refusal is already a FAIL

  const target = new SqliteD1();
  const sink = new D1RestoreSink(target as unknown as D1Database, "fdb", false);
  for (const r of records) await sink.put(r.name, r.value!);
  const blobsBefore = dump(d1, "blobs", ["id", "b"], '"id"');
  const blobsAfter = dump(target, "blobs", ["id", "b"], '"id"');
  ok(`the restored blobs table is byte-identical (${blobsAfter.length} of ${blobsBefore.length} rows)`, blobsBefore.length === 259 && same(blobsBefore, blobsAfter));
  const keysBefore = dump(d1, "bkeys", ["k", "v"], '"k"');
  const keysAfter = dump(target, "bkeys", ["k", "v"], '"k"');
  ok(`the restored bkeys table is byte-identical (${keysAfter.length} of ${keysBefore.length} rows)`, keysBefore.length === 256 && same(keysBefore, keysAfter));
}

async function main(): Promise<void> {
  await proveCompositeKeyPages();
  await proveResumeMidTable();
  await proveMixedKeyClasses();
  proveTokenCodec();
  await proveOnlyDeclaredWithoutRowidPagesByKey();
  await proveResumeKeepsNamesUnique();
  await proveOversizedKeyGetsNoMark();
  await proveEveryByteValueRoundTrips();
  console.log(failures === 0 ? "\nD1 KEYSET PAGING VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
