// A D1-shaped double over a REAL SQLite engine (node:sqlite), shared by the D1 proofs that need SQLite's
// own storage classes, collations and affinity rather than a model of them: the keyset paging proofs
// (validate-d1-keyset.ts), the every-byte BLOB proofs, and the e2e writer (write-archive.ts), which crawls a
// real table through the engine's D1Source before it seals the records for the Go reader.

import { DatabaseSync, type StatementSync } from "node:sqlite";

// ---- a D1-shaped double over real SQLite ------------------------------------------------------------
//
// It mirrors the D1 behaviours the source and the sink depend on:
//   - bind() refuses a JS bigint (real D1 throws D1_TYPE_ERROR), takes an ArrayBuffer as a BLOB, and binds
//     a safe-integer number as INTEGER and any other number as REAL;
//   - a read returns an INTEGER as a float64 number (the precision loss the typed projection exists to
//     avoid) and a BLOB as a number[] of bytes;
//   - raw({columnNames:true}) returns the column names first, then each row as an array;
//   - batch() runs its statements in one transaction.
// It records every keyset query (a SELECT with a row-value WHERE) so a proof can inspect its plan.

export function toSqliteBind(v: unknown): null | number | bigint | string | Uint8Array {
  if (typeof v === "bigint") throw new Error(`D1_TYPE_ERROR: Type 'bigint' not supported for value '${String(v)}'`);
  if (v === null || v === undefined) return null;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (typeof v === "number") return Number.isSafeInteger(v) ? BigInt(v) : v;
  if (typeof v === "string") return v;
  throw new Error(`SqliteD1: unsupported bind type ${typeof v}`);
}

export function fromSqliteValue(v: unknown): unknown {
  if (typeof v === "bigint") return Number(v); // D1 returns INTEGER as a float64 JSON number
  if (v instanceof Uint8Array) return Array.from(v); // D1 .raw() returns a BLOB as number[]
  return v;
}

export class SqliteD1 {
  db = new DatabaseSync(":memory:");
  keysetQueries: Array<{ sql: string; binds: unknown[] }> = [];
  maxPageRows = 0;
  // failRowidProbe makes the _rowid_ probe throw, as a transient D1 fault would on a rowid table.
  failRowidProbe = false;
  // failKeyLookup makes the PRIMARY KEY pragmas throw, as a transient D1 fault would on a WITHOUT ROWID table.
  failKeyLookup = false;
  static readonly BOOKMARK = "00000003-00000004-00000000-0011223344556677";

  withSession(_constraint?: string): { prepare(q: string): SqliteStmt; getBookmark(): string } {
    return { prepare: (q: string) => this.prepare(q), getBookmark: () => SqliteD1.BOOKMARK };
  }
  prepare(query: string): SqliteStmt {
    return new SqliteStmt(this, query, []);
  }
  async batch(stmts: SqliteStmt[]): Promise<unknown[]> {
    this.db.exec("BEGIN");
    try {
      const out: unknown[] = [];
      for (const s of stmts) out.push(await s.run());
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  async exec(query: string): Promise<{ count: number; duration: number }> {
    this.db.exec(query);
    return { count: 0, duration: 0 };
  }
}

export class SqliteStmt {
  private d1: SqliteD1;
  private query: string;
  private binds: unknown[];
  constructor(d1: SqliteD1, query: string, binds: unknown[]) {
    this.d1 = d1;
    this.query = query;
    this.binds = binds;
  }
  bind(...values: unknown[]): SqliteStmt {
    values.forEach(toSqliteBind); // refuse a bigint at bind time, as D1 does
    return new SqliteStmt(this.d1, this.query, values);
  }
  private statement(): StatementSync {
    const s = this.d1.db.prepare(this.query);
    s.setReadBigInts(true);
    return s;
  }
  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    if (this.d1.failKeyLookup && /^PRAGMA index_(list|xinfo)\(/.test(this.query)) throw new Error("D1_ERROR: transient fault (test double)");
    const rows = this.statement().all(...this.binds.map(toSqliteBind)) as Record<string, unknown>[];
    const results = rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, fromSqliteValue(v)])));
    return { results: results as T[], success: true, meta: {} };
  }
  async raw<T>(_opts: { columnNames: true }): Promise<[string[], ...T[]]> {
    if (this.d1.failRowidProbe && /^SELECT _rowid_ FROM .* LIMIT 0$/.test(this.query)) throw new Error("D1_ERROR: transient fault (test double)");
    const s = this.statement();
    const names = s.columns().map((c) => c.name);
    const rows = (s.all(...this.binds.map(toSqliteBind)) as Record<string, unknown>[]).map((r) => Object.values(r).map(fromSqliteValue));
    if (/\bWHERE \(/.test(this.query)) this.d1.keysetQueries.push({ sql: this.query, binds: this.binds });
    if (/\bLIMIT \?/.test(this.query) && rows.length > this.d1.maxPageRows) this.d1.maxPageRows = rows.length;
    return [names, ...(rows as T[])];
  }
  async run(): Promise<{ success: true; meta: Record<string, unknown>; results: unknown[] }> {
    this.statement().run(...this.binds.map(toSqliteBind));
    return { success: true, meta: {}, results: [] };
  }
}
