// Source-side fault injector for the fault-injection test suite.
//
// The network-fault proxy can only fault DESTINATION writes; a source READ (a KV/R2/D1 list or
// get the crawl issues) had no injection point, so a whole class of failures -- a refused KV cursor, a
// key deleted mid-crawl, an R2 object changed behind its etag, a throttled list, a D1 page that errors
// mid-stream -- could not be exercised at all. This module supplies three in-memory Cloudflare binding
// doubles (KV / R2 / D1) that reproduce the REAL platform read semantics (opaque KV cursors, the R2
// etag pin, D1 keyset pages and result caps) and let a test inject those faults on configurable
// triggers, so a real seal run can be driven THROUGH the fault and its behaviour asserted.
//
// Design: each double is a faithful base (paginated, ordered, etagged) with a small mutable fault
// surface. Faults are either declared up front (a set of keys that vanish on get, a cursor mode) or
// ARMED at runtime (arm a throttle/transient on the next read, then it auto-disarms so the retry
// recovers) -- the latter mirrors how the existing slice tests delete a binding AFTER handoff to drive
// the Durable Object's resume path. Nothing here allocates large buffers: every fixture is a handful of
// tiny values, by deliberate safety discipline.
//
// The doubles are cast to the real KVNamespace/R2Bucket/D1Database at the call site (`as unknown as
// KVNamespace`), exactly as the existing source doubles in validate-sources.ts / validate-slice.ts are:
// they implement only the surface the adapters in src/sources/{kv,r2,d1}.ts actually call.

import { utf8 } from "../src/crypto/bytes.ts";

// ---- shared -----------------------------------------------------------------

// A LIST fault is a thrown error, optionally one-shot (auto-disarms after firing once, so a retry
// recovers -- a transient/throttle) or sticky (fires until cleared -- a persistent outage). It models a
// read the platform rejected: the message is what the adapter would see and re-throw, so a test can
// assert how coarseRunError classifies it. spend/meter is unaffected; a fault is a throw, not a budget.
interface ArmedFault {
  message: string;
  sticky: boolean;
}

// ---- KV ---------------------------------------------------------------------

// KVCursorMode controls how the double treats the opaque list cursor, the heart of the analyst-flagged
// "cursor-refusal wedge":
//   "ok"        - every cursor is honoured (the no-fault baseline).
//   "epoch"     - cursors are epoch-stamped; invalidateCursors() expires every cursor issued so far
//                 (the platform expiring a long-held cursor between slices) while a freshly issued one
//                 still works. This is the REALISTIC stale-resume-cursor case: a slice resumes with a
//                 cursor the platform no longer accepts, and the adapter must fall back to its watermark
//                 re-scan rather than lose keys.
//   "refuse-all"- EVERY list that carries a cursor is refused, even a freshly issued one. This is the
//                 DETERMINISTIC case a re-list cannot escape: forward pagination can never advance past
//                 the first page, so the crawl can never complete. It exercises whether the engine wedges
//                 forever or fails closed.
export type KVCursorMode = "ok" | "epoch" | "refuse-all";

export interface KVSeed {
  name: string;
  value: Uint8Array;
}

export interface InjectableKVOpts {
  pageSize: number;
  cursorMode?: KVCursorMode;
  // Keys that list() still returns but get() answers null for: a key DELETED between the list and the
  // value read (SPEC 12.5, "a key that vanishes mid-crawl is simply skipped").
  vanishOnGet?: Iterable<string>;
  // Keys whose value the double swaps the FIRST time it is read: a value that changed mid-crawl. KV has
  // no point-in-time snapshot, so the adapter seals whatever one atomic get returns; this proves that is
  // internally consistent (the sealed bytes hash to what was read), never a torn read.
  mutateOnGet?: Map<string, Uint8Array>;
  // After this many keys have been yielded across all list() calls, the NEXT page claims list_complete
  // and drops the rest: a source that UNDER-REPORTS yet says it is done. The engine has no count oracle
  // beyond the source's own enumeration, so this pins exactly what the completeness guarantee rests on.
  truncateAndClaimCompleteAfter?: number;
}

// InjectableKV is a paginated KV namespace double with REAL opaque-cursor semantics plus an injectable
// fault surface. It implements only list() and getWithMetadata() -- the two calls KVSource makes -- and
// counts them so a test can assert each value is read exactly once (no re-reads across a fallback).
export class InjectableKV {
  private seeds: KVSeed[];
  private pageSize: number;
  private cursorMode: KVCursorMode;
  private vanish: Set<string>;
  private mutate: Map<string, Uint8Array>;
  private mutated = new Set<string>();
  private truncateAfter: number | null;
  private epoch = 0;
  private armed: ArmedFault | null = null;
  private yielded = 0; // cumulative keys returned across all list() calls (for the truncate-and-lie fault)
  lists = 0;
  gets = 0;

  constructor(seeds: KVSeed[], opts: InjectableKVOpts) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = opts.pageSize;
    this.cursorMode = opts.cursorMode ?? "ok";
    this.vanish = new Set(opts.vanishOnGet ?? []);
    this.mutate = opts.mutateOnGet ?? new Map();
    this.truncateAfter = opts.truncateAndClaimCompleteAfter ?? null;
  }

  // invalidateCursors expires every cursor issued so far (epoch mode): a later list with one of them is
  // refused, while a freshly issued cursor still works. Call it between slices to force the resume
  // watermark fallback. A no-op outside epoch mode.
  invalidateCursors(): void {
    this.epoch++;
  }

  // armListFault makes the NEXT list() (sticky=false) -- or EVERY list() until clearListFault (sticky=true)
  // -- throw the given message. Use it to inject a throttle ("... status 429"), a transient 5xx, or a
  // persistent read outage AFTER a run has handed off, mirroring how the slice tests mutate the binding
  // post-handoff to drive the DO's resume path.
  armListFault(message: string, sticky = false): void {
    this.armed = { message, sticky };
  }
  clearListFault(): void {
    this.armed = null;
  }

  async list(options?: { prefix?: string; cursor?: string; limit?: number }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    this.lists++;
    // An armed fault fires on a CRAWL list (no limit) but never on the cheap liveness probe
    // (list({limit:1})), so a transient/throttle injected after handoff lands on the crawl the run
    // retries, not on the preflight probe (which swallows an "unavailable" blip by design).
    if (this.armed !== null && options?.limit === undefined) {
      const a = this.armed;
      if (!a.sticky) this.armed = null; // one-shot: the retry recovers
      throw new Error(a.message);
    }
    if (options?.cursor !== undefined) {
      if (this.cursorMode === "refuse-all") throw new Error("cursor: refused (opaque cursor not honoured)");
      if (this.cursorMode === "epoch") {
        const m = /^e(\d+)c(\d+)$/.exec(options.cursor);
        if (!m || Number(m[1]) !== this.epoch) throw new Error("cursor: invalid or expired");
      }
    }
    let start = 0;
    if (options?.cursor !== undefined) {
      const m = /^e\d+c(\d+)$/.exec(options.cursor);
      start = m ? Number(m[1]) : 0;
    }
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((s) => s.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    let complete = next >= all.length;
    // The under-report-but-claim-complete fault: once enough keys have been handed out, declare the
    // listing finished and drop the remainder, modelling a source that silently enumerates short.
    if (this.truncateAfter !== null && this.yielded + page.length >= this.truncateAfter) {
      complete = true;
    }
    this.yielded += page.length;
    return {
      keys: page.map((s) => ({ name: s.name })),
      list_complete: complete,
      ...(complete ? {} : { cursor: `e${this.epoch}c${next}` }),
      cacheStatus: null,
    };
  }

  async getWithMetadata(key: string, _type: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
    this.gets++;
    if (this.vanish.has(key)) return { value: null, metadata: null, cacheStatus: null }; // deleted between list and get
    const s = this.seeds.find((x) => x.name === key);
    if (!s) return { value: null, metadata: null, cacheStatus: null };
    let bytes = s.value;
    const swap = this.mutate.get(key);
    if (swap !== undefined && !this.mutated.has(key)) {
      this.mutated.add(key);
      bytes = swap; // value changed mid-crawl; one atomic read returns the new bytes
    }
    const out = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(out).set(bytes);
    return { value: out, metadata: null, cacheStatus: null };
  }
}

// ---- R2 ---------------------------------------------------------------------

export interface R2Seed {
  key: string;
  body: Uint8Array;
}

export interface InjectableR2Opts {
  pageSize: number;
  // Keys whose etag-pinned (streamed) re-open comes back WITHOUT a body: the object was replaced
  // mid-crawl, so the etag no longer matches. The adapter reads it as a short read and skips the record
  // (recordsSkippedChanged), never sealing bytes that disagree with the recorded address.
  etagChangeOnGet?: Iterable<string>;
  // Keys that vanish on get(): deleted between the list and the read (the small-object analogue of the
  // KV mid-crawl deletion).
  vanishOnGet?: Iterable<string>;
}

// InjectableR2 is a paginated R2 bucket double with etag pinning and an injectable fault surface. It
// implements list() and get() (plain and onlyIf/ranged) -- what R2Source calls -- with the etag/onlyIf
// semantics the streamed path relies on.
export class InjectableR2 {
  private entries: R2Seed[];
  private pageSize: number;
  private etagChange: Set<string>;
  private vanish: Set<string>;
  private armed: ArmedFault | null = null;
  lists = 0;
  gets = 0;

  constructor(entries: R2Seed[], opts: InjectableR2Opts) {
    this.entries = [...entries].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    this.pageSize = opts.pageSize;
    this.etagChange = new Set(opts.etagChangeOnGet ?? []);
    this.vanish = new Set(opts.vanishOnGet ?? []);
  }

  armListFault(message: string, sticky = false): void {
    this.armed = { message, sticky };
  }
  clearListFault(): void {
    this.armed = null;
  }

  private etagFor(key: string): string {
    return `etag-${key}`;
  }

  // get answers BOTH the buffered path (plain get) and the streamed path (get with onlyIf.etagMatches
  // and an optional range). A vanished key returns null; a changed key under an etag pin returns an
  // object WITHOUT a body (the real onlyIf-failed shape), which the adapter treats as changed-mid-crawl.
  async get(key: string, opts?: { onlyIf?: { etagMatches?: string }; range?: { offset: number; length: number } }): Promise<unknown> {
    this.gets++;
    if (this.vanish.has(key)) return null;
    const e = this.entries.find((x) => x.key === key);
    if (!e) return null;
    const etag = this.etagFor(key);
    const wantsEtag = opts?.onlyIf?.etagMatches;
    if (wantsEtag !== undefined && (this.etagChange.has(key) || wantsEtag !== etag)) {
      // Precondition failed: the object was replaced. Real R2 returns an R2Object with NO body.
      return this.objectNoBody(key, e.body.length, etag);
    }
    let body = e.body;
    if (opts?.range) body = e.body.subarray(opts.range.offset, opts.range.offset + opts.range.length);
    return this.objectWithBody(key, body, etag);
  }

  async list(options?: { prefix?: string; cursor?: string; limit?: number; include?: ("httpMetadata" | "customMetadata")[] }): Promise<unknown> {
    this.lists++;
    // Fire on a crawl list (limit 1000) but never on the liveness probe (limit 1).
    if (this.armed !== null && options?.limit !== 1) {
      const a = this.armed;
      if (!a.sticky) this.armed = null;
      throw new Error(a.message);
    }
    const prefix = options?.prefix;
    const filtered = prefix === undefined ? this.entries : this.entries.filter((e) => e.key.startsWith(prefix));
    let start = 0;
    if (options?.cursor !== undefined) {
      const idx = filtered.findIndex((e) => e.key === options.cursor);
      start = idx === -1 ? filtered.length : idx;
    }
    const page = filtered.slice(start, start + this.pageSize);
    const nextStart = start + this.pageSize;
    const hasMore = nextStart < filtered.length;
    const objects = page.map((e) => this.objectMeta(e.key, e.body.length, this.etagFor(e.key)));
    if (hasMore) {
      return { objects, delimitedPrefixes: [], truncated: true, cursor: filtered[nextStart]!.key };
    }
    return { objects, delimitedPrefixes: [], truncated: false };
  }

  private objectMeta(key: string, size: number, etag: string): unknown {
    return { key, size, etag, version: "1", httpEtag: `"${etag}"`, uploaded: new Date(0), checksums: {}, storageClass: "Standard", writeHttpMetadata(_h: unknown) {} };
  }
  private objectNoBody(key: string, size: number, etag: string): unknown {
    return this.objectMeta(key, size, etag); // no `body` property: the onlyIf precondition failed
  }
  private objectWithBody(key: string, body: Uint8Array, etag: string): unknown {
    const meta = this.objectMeta(key, body.length, etag) as Record<string, unknown>;
    return {
      ...meta,
      get body(): ReadableStream<Uint8Array> {
        return new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(body);
            c.close();
          },
        });
      },
      bodyUsed: false,
      async arrayBuffer(): Promise<ArrayBuffer> {
        const b = new ArrayBuffer(body.length);
        new Uint8Array(b).set(body);
        return b;
      },
      async bytes(): Promise<Uint8Array> {
        return body.slice();
      },
      async text(): Promise<string> {
        return new TextDecoder().decode(body);
      },
    };
  }
}

// ---- D1 ---------------------------------------------------------------------

export interface D1TableSeed {
  name: string;
  sql: string;
  columns: string[];
  rows: unknown[][];
}

// d1TypedProjectionRow models SQLite's typeof(col) plus the integer-safe typed projection's CASE (see
// src/sources/d1-reader.ts typedProjection) for one fixture row: per column it emits the (typeof, value)
// PAIR the reader's typed SELECT now actually returns -- typeof() as the SQLite storage-class STRING
// ('null'|'integer'|'real'|'text'|'blob'), an integer's value as an EXACT decimal string (CAST col AS
// TEXT), matching validate-sources.ts's memTypedProjectionRow. Before this, the double answered the OLD
// bare-column shape (one value per declared column, no typeof()), and cellFromTypedValue
// (src/sources/d1-format.ts) rejects a non-string typeof() outright -- "D1 typed cell: unexpected
// typeof() storage class 1" (the fixture's first cell, a plain number, misread as the typeof() slot).
// The guard is correct; this is what keeps the double honest against it.
function d1TypedProjectionRow(row: unknown[]): unknown[] {
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

// InjectableD1 is a compact D1 database double with consistent-read Sessions and keyset paging (the
// shape D1Source crawls), plus one fault: arm a thrown error on the Nth keyset page query (a row page
// that errors mid-stream). It is the D1 analogue of the KV/R2 list fault.
export class InjectableD1 {
  tables: { name: string; sql: string; columns: string[]; rows: unknown[][]; rowids: bigint[] }[];
  sessions = 0;
  keysetPages = 0;
  private faultOnKeysetPage: number | null = null;
  private faultMessage = "D1_ERROR: read failed mid-stream";
  static readonly BOOKMARK = "0000000a-0000000b-00000000-0123456789abcdef";

  constructor(seed: D1TableSeed[]) {
    this.tables = seed.map((t) => ({ ...t, rowids: t.rows.map((_, i) => BigInt(i + 1)) }));
  }

  // armKeysetFault makes the Nth keyset page query (1-based) throw. A page error mid-stream: D1 is a
  // resumable source, so the question is whether one bad page wedges the run or fails it closed.
  armKeysetFault(onPage: number, message = "D1_ERROR: read failed mid-stream"): void {
    this.faultOnKeysetPage = onPage;
    this.faultMessage = message;
  }

  withSession(_constraint?: string): { prepare(q: string): D1Stmt; getBookmark(): string } {
    this.sessions++;
    return { prepare: (q: string) => new D1Stmt(this, q, []), getBookmark: () => InjectableD1.BOOKMARK };
  }
  prepare(query: string): D1Stmt {
    return new D1Stmt(this, query, []);
  }
  tableFor(query: string): { name: string; sql: string; columns: string[]; rows: unknown[][]; rowids: bigint[] } {
    const m = /FROM\s+"((?:[^"]|"")+)"/i.exec(query);
    if (!m) throw new Error(`InjectableD1: unrecognised query: ${query}`);
    const name = m[1]!.replace(/""/g, '"');
    const t = this.tables.find((x) => x.name === name);
    if (!t) throw new Error(`InjectableD1: no such table: ${name}`);
    return t;
  }
  noteKeysetPage(): void {
    this.keysetPages++;
  }
  maybeFaultKeyset(): void {
    if (this.faultOnKeysetPage !== null && this.keysetPages + 1 === this.faultOnKeysetPage) {
      throw new Error(this.faultMessage);
    }
  }
}

class D1Stmt {
  private db: InjectableD1;
  private query: string;
  private binds: unknown[];
  constructor(db: InjectableD1, query: string, binds: unknown[]) {
    this.db = db;
    this.query = query;
    this.binds = binds;
  }
  bind(...values: unknown[]): D1Stmt {
    return new D1Stmt(this.db, this.query, values);
  }
  async first<T>(): Promise<T | null> {
    return null; // SELECT 1 liveness probe: a non-throwing answer is all the probe needs
  }
  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    if (/FROM sqlite_master/i.test(this.query)) {
      const results = this.db.tables.map((t) => ({ type: "table", name: t.name, tbl_name: t.name, sql: t.sql })) as T[];
      return { results, success: true as const, meta: {} };
    }
    throw new Error(`InjectableD1.all: unhandled: ${this.query}`);
  }
  async raw<T>(_opts: { columnNames: true }): Promise<[string[], ...T[]]> {
    if (/SELECT \* FROM .* LIMIT 0/i.test(this.query)) {
      return [this.db.tableFor(this.query).columns] as unknown as [string[], ...T[]];
    }
    if (/SELECT _rowid_ FROM .* LIMIT 0/i.test(this.query)) {
      return [["_rowid_"]] as unknown as [string[], ...T[]];
    }
    if (/WHERE _rowid_ > CAST\(\?1 AS INTEGER\) ORDER BY _rowid_ LIMIT \?2/i.test(this.query)) {
      this.db.maybeFaultKeyset(); // a row page that errors mid-stream fires HERE, before any rows return
      const t = this.db.tableFor(this.query);
      if (typeof this.binds[0] !== "string") throw new Error(`D1_TYPE_ERROR: rowid cursor must bind as a string, got ${typeof this.binds[0]}`);
      const after = BigInt(this.binds[0]);
      const limit = Number(this.binds[1]);
      const out: unknown[][] = [];
      for (let i = 0; i < t.rows.length && out.length < limit; i++) {
        // The typed projection's (typeof, value) pairs per declared column, then the cursor CAST to TEXT
        // (a decimal string, exactly as real D1's CAST(_rowid_ AS TEXT) returns it -- never a bare bigint).
        if (t.rowids[i]! > after) out.push([...d1TypedProjectionRow(t.rows[i]!), t.rowids[i]!.toString()]);
      }
      this.db.noteKeysetPage();
      return [[...t.columns, "__dp_rowid"], ...out] as unknown as [string[], ...T[]];
    }
    throw new Error(`InjectableD1.raw: unhandled: ${this.query}`);
  }
}

// ---- shared fixtures --------------------------------------------------------

// kvSeeds builds a tiny ordered KV fixture: n keys with distinct, short, varied values. Deliberately
// small (tens of keys) -- a fault-injection run proves behaviour, never scale, and never allocates large buffers.
export function kvSeeds(n: number): KVSeed[] {
  return Array.from({ length: n }, (_, i) => ({
    name: `key/${String(i).padStart(4, "0")}`,
    value: utf8(`v-${i}-${"x".repeat(i % 7)}`),
  }));
}
