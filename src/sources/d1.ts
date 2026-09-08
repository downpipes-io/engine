import {
  D1_HEADER_FORMAT,
  D1_ROWS_FORMAT,
  D1_SCHEMA_FORMAT,
  encodeD1Header,
  encodeD1RowsPage,
  encodeD1Schema,
} from "./d1-format.ts";
import {
  D1_PAGE_BYTE_LIMIT,
  D1_ROWS_PER_PAGE,
  makeSession,
  pageTableRows,
  readDumpPlan,
} from "./d1-reader.ts";
import { encodeToken, parseToken, type TokenPhase } from "./d1-token.ts";
import { classifyLivenessFault, type LivenessProbe, SourceResourceMissingError } from "./source-errors.ts";
import { recordSnapshotConsistency } from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";

// The sizing constants and the resume-token codec used to live here; they moved to sibling modules
// (d1-reader.ts holds the byte/page bounds and the D1 read surface; d1-token.ts holds the resume
// token shape and codec). They are re-exported below so importers of d1.ts are unchanged.
export { D1_EXPORT_SIZE_LIMIT, D1_PAGE_BYTE_LIMIT, D1_PAGE_TARGET_BYTES, D1_ROWS_PER_PAGE } from "./d1-reader.ts";

// A D1 database is backed up as a RESUMABLE SEQUENCE of bounded records the sliced seal can
// checkpoint BETWEEN, not as one whole-database value sealed in a single invocation. The records
// are emitted, sealed and restored in this strict order (d1-format.ts names the three bodies):
//   1. ONE header record (downpipe-d1-header/1): every table's CREATE + ordered column names, NO
//      rows. Small (DDL only). On restore it runs the fresh-target check ONCE and creates all tables.
//   2. MANY row-page records (downpipe-d1-rows/1): one keyset page of one table's rows, carrying
//      the table name and its columns so the INSERT is self-contained. Bounded by the per-page byte
//      guard, so each buffers safely. On restore each APPENDS its rows to the header-created table.
//   3. ONE schema record (downpipe-d1-schema/1): the CREATE INDEX/TRIGGER/VIEW objects, applied LAST.
// A SINGLE giant TABLE row page is still one record (it can hit the per-page cap) -- the documented
// residual; per-page records handle the common rows-heavy database that overflowed one slice before.
//
// The legacy whole-database dump (encodeD1Backup / encodeD1BackupStream) is gone from THIS crawl
// path (per-page replaces it), but its encoder stays exported from d1-format.ts for the reference
// byte-pinning tests, and a legacy whole-dump record (kind:"full") still restores unchanged, so
// archives written before resumability keep restoring.

// D1 adapter (SPEC 12.1, "a single SQLite-compatible dump ... restore replays the dump"). The dump
// is a SQL-level export, not the deprecated binary D1Database.dump(): a binary file cannot be
// replayed through the runtime binding (there is no load() call), whereas a header + row-page +
// schema sequence can be re-created and re-inserted, which is what makes a real in-account restore
// possible. The body shapes live in d1-format.ts and are named by the d1.format hint.
//
// CONSISTENCY (SRC-1): the whole export must read ONE point-in-time snapshot ACROSS slices. D1
// Sessions provide this. A fresh crawl opens withSession("first-primary"): the first query goes to
// the primary (the newest committed state) and establishes a bookmark; every later read on the same
// session is constrained to a replica at-or-after that bookmark. The bookmark captured after the
// first read is THREADED through every mark token, so a resumed slice re-opens the SAME snapshot
// (withSession(bookmark)) and the schema read plus every table page across every slice see a single
// sequentially-consistent point in time. A binding WITHOUT withSession (an older/local double)
// degrades to the bare db: reads are still ordered keyset pages, only the cross-slice snapshot
// guarantee is then best-effort (getBookmark -> null), exactly as the former whole-crawl degraded.
//
// The selector does not apply within a single database; it selects which databases a downpipe
// covers, which is expressed by configuring one D1 source per database.
export class D1Source implements SourceAdapter, ResumableSource, LivenessProbe {
  readonly sourceType = "d1" as const;
  private db: D1Database;
  private name: string;
  // sizeLimit is the per-page byte bound the page guard compares against (production: the per-page
  // constant). It is exposed only so tests can lower it to exercise the page guard without producing
  // a gigantic page. Do not pass this parameter in production code.
  private sizeLimit: number;
  // rowsPerPage is the keyset page size, exposed for tests so a small fixture can be forced to cross
  // page boundaries without seeding thousands of rows. Production uses the default.
  private rowsPerPage: number;
  // databaseId is D1's native database UUID, recorded on every record's `database` annotation so the archive
  // self-identifies WHICH database it is a backup of (the record NAME carries only the binding name, which can
  // collide across accounts or after a rename). Optional: a config saved before databaseId existed omits it.
  private databaseId: string | undefined;

  constructor(db: D1Database, name: string, sizeLimit = D1_PAGE_BYTE_LIMIT, rowsPerPage = D1_ROWS_PER_PAGE, databaseId?: string) {
    this.db = db;
    this.name = name;
    this.sizeLimit = sizeLimit;
    this.rowsPerPage = Math.max(1, rowsPerPage);
    this.databaseId = databaseId;
  }

  // dbId spreads the database identity annotation onto a record when the native UUID is known (omitted
  // otherwise, keeping the omitempty record shape). Shared by all three emit phases.
  private dbId(): { database: string } | Record<string, never> {
    return this.databaseId !== undefined ? { database: this.databaseId } : {};
  }

  // probeLiveness (SRC-1) proves the bound database still EXISTS with a constant SELECT 1 (reads no table
  // data) before the crawl opens its consistent-read session. A truthy binding pointing at a deleted
  // database passes preflight's presence check but throws raw on the first real query; this names it.
  async probeLiveness(): Promise<void> {
    if (typeof this.db.prepare !== "function") {
      throw new SourceResourceMissingError("d1", this.name, "misconfigured", "the bound object is not a D1 database (no prepare())");
    }
    try {
      await this.db.prepare("SELECT 1").first();
    } catch (e) {
      throw classifyLivenessFault("d1", this.name, e);
    }
  }

  // crawl() is the simple whole-crawl form: it delegates to crawlFrom(selector, null, meter) and
  // drops the marks, keeping the same yield-records behaviour over a full pass. The sliced seal
  // uses crawlFrom directly (it needs the marks to checkpoint).
  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null, meter)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // crawlFrom is the resumable crawl. A null token starts a fresh export: open a primary-anchored
  // session, emit the header, then page each table, then emit the schema, with a mark after every
  // record so a slice can checkpoint between any two records. A token from a previous mark re-opens
  // the SAME snapshot (its bookmark) and continues at the recorded position, re-reading no row
  // already emitted and never re-emitting the header.
  async *crawlFrom(_selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const resume = token === null ? null : parseToken(token);

    // G096: a RESUME whose token carries no bookmark cannot re-open the snapshot the earlier slices read.
    // It falls through to "first-primary" below, which opens a BRAND NEW snapshot, and the records this
    // slice seals are then drawn from a different point in time to the ones already sealed. The run still
    // reports ok and the tear is invisible until a restore shows rows referencing rows that do not exist,
    // so the re-anchor is recorded here, at the only site that can still see both halves of the fact.
    if (resume !== null && resume.bookmark === null) recordSnapshotConsistency("re-anchored");

    // Open the consistent-read session. A fresh crawl anchors at the primary; a resume re-anchors at
    // the captured bookmark so it reads the same snapshot the first slice did. The session object is
    // held so getBookmark() can be read after the first query (the snapshot the marks thread).
    const session = makeSession(this.db, resume?.bookmark ?? "first-primary");

    // Read the schema (sqlite_master) and each table's columns + rowid-ness up front. This is small
    // by construction (DDL text and column names only, never rows) and is the FIRST query, so it is
    // the read that establishes (fresh) or confirms (resume) the session bookmark.
    const plan = await readDumpPlan(session.reader, meter);

    // The bookmark to thread through every mark: the snapshot this session reads. On a fresh crawl
    // getBookmark() returns the bookmark the first read established; on a resume it returns the same
    // (re-anchored) bookmark. A degraded double returns null -> best-effort, threaded as null.
    const bookmark = session.getBookmark() ?? resume?.bookmark ?? null;

    // Three phases run in strict order with a mark after every record. crawlFrom is a thin orchestrator:
    // the header runs only on a fresh crawl, the rows and schema phases each pick up at the recorded
    // position. "done" yields nothing (a resume from the final mark).
    let phase: TokenPhase = resume?.phase ?? "header";
    if (phase === "header") {
      yield* this.emitHeaderPhase(plan, bookmark);
      phase = "rows";
    }
    if (phase === "rows") {
      yield* this.emitRowsPhase(session.reader, plan, bookmark, resume, meter);
      phase = "schema";
    }
    if (phase === "schema") {
      yield* this.emitSchemaPhase(plan, bookmark);
    }
  }

  // emitHeaderPhase yields the single header record (every table's CREATE + ordered column names, no
  // rows), then a mark advancing the cursor to the first table's first row page. Emitted only on a
  // FRESH crawl (a resume already sealed it).
  private async *emitHeaderPhase(plan: Awaited<ReturnType<typeof readDumpPlan>>, bookmark: string | null): AsyncIterable<CrawlEvent> {
    yield {
      kind: "record",
      record: {
        sourceType: "d1",
        name: headerName(this.name),
        ...this.dbId(),
        value: encodeD1Header(plan.tables.map((t) => ({ name: t.name, sql: t.sql, columns: t.columns }))),
        descriptor: { d1Format: D1_HEADER_FORMAT },
      },
    };
    yield { kind: "mark", token: encodeToken({ bookmark, phase: "rows", ti: 0, afterRowid: null }) };
  }

  // emitRowsPhase yields the row pages, table by table in declaration order. On a resume into "rows" it
  // starts at the recorded table index and rowid; otherwise from table 0, row 0. Each non-empty page is
  // one rows record followed by a mark carrying the cursor (the table index + the page's last rowid) so a
  // slice can stop after any page and resume after exactly that row. The trailing mark advances to schema.
  private async *emitRowsPhase(reader: ReturnType<typeof makeSession>["reader"], plan: Awaited<ReturnType<typeof readDumpPlan>>, bookmark: string | null, resume: ReturnType<typeof parseToken> | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    const startTi = resume?.phase === "rows" ? resume.ti : 0;
    let startAfter = resume?.phase === "rows" ? resume.afterRowid : null;
    for (let ti = startTi; ti < plan.tables.length; ti++) {
      const table = plan.tables[ti]!;
      for await (const page of pageTableRows(reader, table, this.rowsPerPage, this.sizeLimit, startAfter, meter)) {
        if (page.rows.length > 0) {
          yield {
            kind: "record",
            record: {
              sourceType: "d1",
              name: rowsName(this.name, ti, table.name, page.pageIndex),
              ...this.dbId(),
              value: encodeD1RowsPage(table.name, table.columns, page.rows),
              descriptor: { d1Format: D1_ROWS_FORMAT },
            },
          };
          // The mark resumes THIS table after the page's last row (a WITHOUT ROWID table has no
          // keyset cursor, so it is read in one page and the mark advances straight to the next
          // table -- it cannot resume mid-table, which is fine: such tables are small lookups).
          const next = page.lastRowid === null
            ? { bookmark, phase: "rows" as const, ti: ti + 1, afterRowid: null }
            : { bookmark, phase: "rows" as const, ti, afterRowid: page.lastRowid.toString() };
          yield { kind: "mark", token: encodeToken(next) };
        }
      }
      // After a table is fully paged, advance the cursor to the next table from its start. (When
      // the table emitted at least one page the per-page mark already advanced; this mark is the
      // authoritative table boundary and is harmless to repeat -- it is idempotent.)
      startAfter = null;
      yield { kind: "mark", token: encodeToken({ bookmark, phase: "rows", ti: ti + 1, afterRowid: null }) };
    }
    // All tables paged: the cursor now points at the schema record.
    yield { kind: "mark", token: encodeToken({ bookmark, phase: "schema" }) };
  }

  // emitSchemaPhase yields the single schema record (CREATE INDEX/TRIGGER/VIEW, applied LAST on
  // restore), then a trailing "done" mark so the mark-after-every-record invariant holds and a slice
  // that stops exactly here resumes to nothing.
  private async *emitSchemaPhase(plan: Awaited<ReturnType<typeof readDumpPlan>>, bookmark: string | null): AsyncIterable<CrawlEvent> {
    yield {
      kind: "record",
      record: {
        sourceType: "d1",
        name: schemaName(this.name),
        ...this.dbId(),
        value: encodeD1Schema(plan.schema),
        descriptor: { d1Format: D1_SCHEMA_FORMAT },
      },
    };
    yield { kind: "mark", token: encodeToken({ bookmark, phase: "done" }) };
  }

  async estimate(_selector: Selector): Promise<{ records: number; bytes: number }> {
    // A dump must be produced to know its record count and size; the projection reports an unknown
    // shape rather than reading every table to size it (the cost note: estimate never reads values).
    return { records: -1, bytes: -1 };
  }
}

// ---- per-page record names ----------------------------------------------------------------------
// Every D1 record of one database shares the database name as its first path element, so the restore
// binding resolves to D1_<dbName> for the header, every row page and the schema alike (the binding
// resolver derives the database name from the first element; restore-sink dispatches on the decoded
// body kind, not the name). The remaining elements make each record name UNIQUE (so the offline Go
// reader writes each to its own file rather than colliding on one key) and ORDERED (so the files
// sort header -> rows -> schema, the operator's replay order). The numeric prefixes (00/10/20) and
// zero-padded page index give that lexicographic ordering; the table name is included for the
// operator's readability and the table index makes two same-named-after-cleanup tables distinct.
// The database name is a Cloudflare binding identifier ([A-Za-z_][A-Za-z0-9_]*) with no slash, so
// the first path element is unambiguously the database name.
function headerName(db: string): string {
  return `${db}/00-header`;
}
function rowsName(db: string, ti: number, table: string, pageIndex: number): string {
  return `${db}/10-rows/${pad6(ti)}-${table}/${pad6(pageIndex)}`;
}
function schemaName(db: string): string {
  return `${db}/20-schema`;
}
function pad6(n: number): string {
  return String(n).padStart(6, "0");
}

// d1DatabaseNameFromRecordName extracts the database name (the restore binding root) from any D1
// record name: the legacy whole-dump record name is the bare database name (no slash), and a
// per-page record name is "<db>/...". Taking the substring before the first slash yields the
// database name in both cases. Shared with the restore binding resolver so source and restore agree.
export function d1DatabaseNameFromRecordName(name: string): string {
  const slash = name.indexOf("/");
  return slash === -1 ? name : name.slice(0, slash);
}

// d1TableIndexFromRowRecordName extracts the table INDEX (ti) from a per-page ROW record name
// "<db>/10-rows/<pad6(ti)>-<table>/<pad6(page)>", or null for a name that is not a row record (the
// header, the schema, or a legacy whole-dump name). The index maps into the header's declaration-order
// table list, so a caller can tell which table a row page belongs to WITHOUT parsing the (possibly
// punctuated) table name out of the path. Shared with the restore-side table-subset lint so the source
// and the restore agree on the naming, exactly as d1DatabaseNameFromRecordName is.
export function d1TableIndexFromRowRecordName(name: string): number | null {
  const m = /^[^/]+\/10-rows\/(\d{6})-/.exec(name);
  return m === null ? null : Number(m[1]);
}
