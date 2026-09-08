// IDEM: in-account RESTORE point-in-time FIDELITY chaos validators.
//
// THE INVARIANT for an in-account restore (the apply path that writes records back into LIVE
// KV/R2/D1 via the engine, NOT the offline Go CLI): it must NOT silently CLOBBER newer live data
// without the operator's intent; it must REPRODUCE fidelity (KV TTL/metadata, R2 content-type /
// custom-metadata / storage-class) or LOUDLY flag what it cannot; and it must FAIL CLOSED on a
// schema-diverged target rather than corrupt or partially apply.
//
// These validators drive the REAL apply write path (KVRestoreSink / R2RestoreSink / D1RestoreSink,
// putOptionsFromRecord, restorePlanHash, isUsableApproval, the real R2Source descriptor capture, the
// real encodeD1Header/decodeD1Record), assert the invariant, and either confirm SAFE behaviour with a
// concrete observation or surface a REAL fidelity gap.
//
// WHAT THIS COVERS (and the verdict each reaches):
//   IDEM-01  a value changed between approval and apply -> SAFE-BY-DESIGN revert, gated by dual control.
//            restorePlanHash binds the PLAN (run + target + selector), never live store state, so the
//            approval cannot detect a between-approval-and-apply change; the sink applies an
//            UNCONDITIONAL overwrite (point-in-time revert). The safety is procedural (maker != checker
//            plan-bound approval + immutable archive plan + audited restore-apply), NOT a data-level
//            conditional write. Observed and refuted-with-caveat.
//   IDEM-02  a D1 restore into a SCHEMA-DIVERGED target -> FAILS CLOSED. requireFreshTarget refuses ANY
//            non-empty target at the header, before a single CREATE/INSERT, so a column-added/dropped/
//            retyped target can never be half-written. Refuted (fail-closed proven at the divergence case).
//   IDEM-03  KV TTL -> REPRODUCED, as an ABSOLUTE epoch second, passed through unclamped whenever the live
//            binding will still take it. A stale backup whose TTL has LAPSED cannot simply fail the write:
//            the customer has no in-product path back (they never run a terminal, and the offline reader
//            writes a recovered value to a file rather than putting a KV key back), so the key restores with
//            its value and metadata and WITHOUT the lapsed expiration, the drop is counted on the receipt
//            (kv-expiration-lapsed) and warned about in the dry run before the operator confirms. The
//            boundary is pinned in both directions: a still-valid future TTL must reach the binding untouched.
//   IDEM-04  R2 metadata -> content-type + EVERY modelled httpMetadata field + customMetadata are
//            reproduced. FINDING: the source object's STORAGE CLASS is SILENTLY DROPPED -- describeObject
//            never reads R2Object.storageClass, RestoreDescriptor / R2Descriptor carry no slot for it, and
//            r2PutOptions emits none, so an Infrequent-Access source object restores into the destination
//            bucket's DEFAULT tier with no marker/flag. The platform supports it (R2Object.storageClass is
//            readable, R2PutOptions.storageClass is settable), so this is a descriptor-model gap, not a
//            platform limit. LOW severity (a cost-tier attribute; bytes + content-type + custom metadata
//            all survive) but it violates "reproduce OR loudly flag" for that one field.
//
// Run: node test/validate-idem-restore-fidelity.ts
// In-memory doubles only. No network, no deploy, no cost.

import { KVRestoreSink, R2RestoreSink, D1RestoreSink, putOptionsFromRecord } from "../src/dest/restore-sink.ts";
import type { ShardRecord } from "../src/format/manifest.ts";
import { restorePlanHash, isUsableApproval } from "../src/admin/approvals.ts";
import type { RestoreApproval } from "../src/admin/approvals.ts";
import type { RestoreRequest } from "../src/admin/restore-types.ts";
import { R2Source } from "../src/sources/r2.ts";
import type { SourceRecord } from "../src/sources/types.ts";
import { encodeD1Header } from "../src/sources/d1-format.ts";
import type { D1TableDDL } from "../src/sources/d1-format.ts";
import { destAccessReason, REASON_DESTINATION_ACCESS } from "../src/restore-reasons.ts";
import { drainMetadataShed } from "../src/dest/restore-fault.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import { eqBytes } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

// mkRec builds a type-complete ShardRecord carrying ONLY the fields the apply write-options path reads
// (name / sourceType + the kv/r2 restore descriptors); the hash/segment fields are inert placeholders,
// because putOptionsFromRecord and the sinks never read them. exactOptionalPropertyTypes-safe: kv/r2 are
// present only when supplied.
function mkRec(p: { name: string; sourceType: string; kv?: ShardRecord["kv"]; r2?: ShardRecord["r2"] }): ShardRecord {
  return {
    kind: "record",
    sourceType: p.sourceType,
    name: p.name,
    keyNameHash: "",
    recordId: "",
    plaintextSize: 0,
    plaintextSha384: "",
    recordHash: "",
    codec: "raw",
    segments: [],
    ...(p.kv ? { kv: p.kv } : {}),
    ...(p.r2 ? { r2: p.r2 } : {}),
  };
}

// objMeta narrows R2PutOptions.httpMetadata (R2HTTPMetadata | Headers) to the object form the production
// R2RestoreSink always builds, so the field reads below are type-safe; a Headers (never produced here)
// reads as undefined and the assertion fails, which is correct.
function objMeta(options: R2PutOptions | undefined): R2HTTPMetadata | undefined {
  const meta = options?.httpMetadata;
  if (meta === undefined || meta instanceof Headers) return undefined;
  return meta;
}

// ---- KV doubles -------------------------------------------------------------

// ClobberKV records writes and serves a pre-seeded value, so an unconditional overwrite (the revert) is
// observable. Its put() mirrors the live binding signature KVRestoreSink calls.
class ClobberKV {
  store = new Map<string, Uint8Array>();
  puts: { key: string; options?: { expiration?: number; metadata?: unknown } }[] = [];
  async put(key: string, value: ArrayBuffer, options?: { expiration?: number; metadata?: unknown }): Promise<void> {
    this.store.set(key, new Uint8Array(value));
    this.puts.push({ key, ...(options ? { options } : {}) });
  }
}

// StrictKV is ClobberKV plus Cloudflare KV's documented contract: an absolute `expiration` must be at
// least 60s in the future, else the binding REJECTS the write (a real KV 400). This lets the stale-TTL
// behaviour be observed at the real sink without workerd.
class StrictKV {
  store = new Map<string, Uint8Array>();
  puts: { key: string; options?: { expiration?: number; metadata?: unknown } }[] = [];
  private nowSec: number;
  constructor(nowSec: number) {
    this.nowSec = nowSec;
  }
  async put(key: string, value: ArrayBuffer, options?: { expiration?: number; metadata?: unknown }): Promise<void> {
    if (typeof options?.expiration === "number" && options.expiration < this.nowSec + 60) {
      throw new Error(`KV PUT ${key} failed: Invalid expiration of ${options.expiration}. Expiration times must be more than 60 seconds in the future.`);
    }
    this.store.set(key, new Uint8Array(value));
    this.puts.push({ key, ...(options ? { options } : {}) });
  }
}

// ---- R2 doubles -------------------------------------------------------------

// MemR2Sink records the R2 put options the sink hands the binding (so the apply assertion can read them).
class MemR2Sink {
  puts: { key: string; options?: R2PutOptions }[] = [];
  async put(key: string, _value: ReadableStream<Uint8Array> | ArrayBuffer | ArrayBufferView | string | null | Blob, options?: R2PutOptions): Promise<{ etag: string }> {
    this.puts.push({ key, ...(options ? { options } : {}) });
    return { etag: `etag-${this.puts.length}` };
  }
}

interface R2SourceSeed {
  key: string;
  value: Uint8Array;
  httpMetadata?: { contentType?: string };
  customMetadata?: Record<string, string>;
  storageClass?: string;
}

// MemR2Source is the R2 binding surface the REAL R2Source.crawl reads: a list page (with the metadata
// include) and a per-object get whose body exposes httpMetadata/customMetadata/storageClass and the
// bytes. It seeds a non-default storageClass so the capture can be inspected for whether it lifts it.
class MemR2Source {
  private seeds: R2SourceSeed[];
  constructor(seeds: R2SourceSeed[]) {
    this.seeds = [...seeds].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  }
  async list(options?: { prefix?: string }): Promise<{ objects: unknown[]; delimitedPrefixes: []; truncated: false }> {
    const prefix = options?.prefix;
    const objects = this.seeds
      .filter((s) => prefix === undefined || s.key.startsWith(prefix))
      .map((s) => ({ key: s.key, size: s.value.length, ...(s.httpMetadata ? { httpMetadata: s.httpMetadata } : {}), ...(s.customMetadata ? { customMetadata: s.customMetadata } : {}), ...(s.storageClass ? { storageClass: s.storageClass } : {}) }));
    return { objects, delimitedPrefixes: [], truncated: false };
  }
  async get(key: string): Promise<unknown> {
    const s = this.seeds.find((x) => x.key === key);
    if (!s) return null;
    return {
      key,
      size: s.value.length,
      ...(s.httpMetadata ? { httpMetadata: s.httpMetadata } : {}),
      ...(s.customMetadata ? { customMetadata: s.customMetadata } : {}),
      ...(s.storageClass ? { storageClass: s.storageClass } : {}),
      async arrayBuffer(): Promise<ArrayBuffer> {
        return toAB(s.value);
      },
    };
  }
}

// ---- D1 double --------------------------------------------------------------

// FakeStmt is the slice of D1PreparedStatement the restore sink touches (bind/all/run), typed explicitly
// so the self-returning bind() does not need self-referential inference.
interface FakeStmt {
  bind(...v: unknown[]): FakeStmt;
  all<T>(): Promise<{ results: T[] }>;
  run(): Promise<{ success: boolean }>;
}

// TargetD1 is a minimal D1 restore TARGET: requireFreshTarget lists sqlite_master, and any CREATE/INSERT
// goes through prepare()/batch(), all recorded, so a partial apply would be visible. seedTable adds a row
// to the sqlite_master listing (the live target's existing schema).
class TargetD1 {
  private masterTables: { name: string }[] = [];
  capturedSql: string[] = [];
  batches = 0;
  seedTable(name: string): void {
    this.masterTables.push({ name });
  }
  prepare(sql: string): unknown {
    this.capturedSql.push(sql);
    const masterTables = this.masterTables;
    const stmt: FakeStmt = {
      bind(): FakeStmt {
        return stmt;
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (/sqlite_master/.test(sql)) return { results: masterTables as unknown as T[] };
        return { results: [] as T[] };
      },
      async run(): Promise<{ success: boolean }> {
        return { success: true };
      },
    };
    return stmt;
  }
  async batch(stmts: unknown[]): Promise<unknown[]> {
    this.batches++;
    return stmts.map(() => ({ success: true }));
  }
  wroteSchema(): boolean {
    return this.capturedSql.some((q) => /CREATE TABLE|INSERT INTO/i.test(q));
  }
}

// ---- IDEM-01 ----------------------------------------------------------------

async function idem01(): Promise<void> {
  console.log("\nIDEM-01: a value changed between approval and apply (plan-hash binds the plan, not live state):");

  // (A) The apply-time gate decision is computed from the REQUEST alone. restorePlanHash reads only
  // {runId, target, selector, maxRecords, recordName, cfConfig, mediaRestore}; it never reads live store
  // state, so a value that changes K=v1->v2 AFTER approval does not move the plan hash, and the SAME
  // approval the checker granted stays usable for the apply that will overwrite v2.
  const reqAtApproval: RestoreRequest = { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", target: { binding: "KV_NS", namespaceId: "ns-app" }, include: [], exclude: [] };
  const hApproval = await restorePlanHash(reqAtApproval);
  // The identical request re-evaluated at apply time (live K has since changed to v2) -> the same hash.
  const reqAtApply: RestoreRequest = { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", target: { binding: "KV_NS", namespaceId: "ns-app" }, include: [], exclude: [] };
  const hApply = await restorePlanHash(reqAtApply);
  ok("the plan hash is identical at approval-time and apply-time (a live-value change cannot move it)", hApproval === hApply);

  // A genuinely DIFFERENT plan (re-targeting to another binding) DOES change the hash, so re-targeting
  // re-arms approval: the binding/run is the plan, the live value is not an input.
  const reqRetarget: RestoreRequest = { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", target: { binding: "KV_OTHER", namespaceId: "ns-other" }, include: [], exclude: [] };
  ok("a re-targeted plan hashes differently (a different binding re-arms approval)", (await restorePlanHash(reqRetarget)) !== hApproval);

  // The approval the checker granted (maker != checker by subject) is keyed by hApproval, so it is found
  // and still usable when the apply re-derives the same hash -- EVEN THOUGH live K changed underneath it.
  const now = Date.now();
  const approved: RestoreApproval = {
    planHash: hApproval,
    runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    isLatest: true,
    plannedWrites: 1,
    bytes: 8,
    redirectBinding: null,
    requesterSubject: "subj-maker",
    requestedBy: "maker@example.test",
    requesterGroups: [],
    requestedAt: new Date(now - 1000).toISOString(),
    reason: "DR restore of the config namespace",
    status: "approved",
    approverSubject: "subj-checker",
    approvedBy: "checker@example.test",
    approvedAt: new Date(now - 500).toISOString(),
    expiresAt: new Date(now + 600000).toISOString(),
  };
  ok("the approval keyed to the plan hash is STILL usable at apply time (the gate cannot see the live change)", isUsableApproval(approved, now));

  // (B) The sink applies an UNCONDITIONAL overwrite (point-in-time revert): the live store already holds
  // the NEWER v2 (written after the plan was approved); the apply writes the backup's v1 over it.
  const kv = new ClobberKV();
  kv.store.set("config/flag", utf8("v2-newer-live"));
  const sink = new KVRestoreSink(kv as unknown as KVNamespace, "ns-app");
  const rec = mkRec({ name: "config/flag", sourceType: "kv" });
  await sink.put(rec.name, utf8("v1-from-backup"), putOptionsFromRecord(rec));
  ok("the apply reverted the live v2 to the backup v1 (point-in-time revert, by design)", eqBytes(kv.store.get("config/flag")!, utf8("v1-from-backup")));

  // The RestoreSink.put contract carries no if-match / precondition: putOptionsFromRecord only ever yields
  // kv/r2 descriptor keys, never a compare-and-swap guard, so the revert is unconditional by construction.
  const optsBare = putOptionsFromRecord(rec);
  ok("a value-only record yields NO put options at all (no precondition, no metadata)", optsBare === undefined);
  const optsDesc = putOptionsFromRecord(mkRec({ name: "x", sourceType: "kv", kv: { metadata: { a: 1 } } }));
  ok("a descriptor record's options carry ONLY kv/r2 keys (never an if-match / precondition)", optsDesc !== undefined && Object.keys(optsDesc).every((k) => k === "kv" || k === "r2"));
}

// ---- IDEM-02 ----------------------------------------------------------------

async function idem02(): Promise<void> {
  console.log("\nIDEM-02: a D1 restore into a SCHEMA-DIVERGED (non-fresh) target FAILS CLOSED before any write:");
  // The backup header would re-create users(id, name).
  const backupTables: D1TableDDL[] = [{ name: "users", sql: 'CREATE TABLE "users" (id INTEGER PRIMARY KEY, name TEXT)', columns: ["id", "name"] }];
  const headerBytes = encodeD1Header(backupTables);

  // (a) The live target holds a table of the SAME name but a DIVERGED schema (think users(id, email, blob
  // extra): a column added/retyped/dropped). requireFreshTarget refuses on the PRESENCE of any user table,
  // before it ever inspects columns, so a column-diverged target can never be half-written. The header
  // throws; nothing is created or inserted; the diverged target is untouched.
  const diverged = new TargetD1();
  diverged.seedTable("users");
  let refusedDiverged = false;
  try {
    await new D1RestoreSink(diverged as unknown as D1Database, "appdb", false).put("appdb", headerBytes);
  } catch (e) {
    refusedDiverged = /not empty|fresh database/.test((e as Error).message);
  }
  ok("a same-name schema-diverged target is REFUSED (fail-closed) at the header", refusedDiverged);
  ok("nothing was created or inserted into the diverged target (no partial/corrupt apply)", diverged.batches === 0 && !diverged.wroteSchema());

  // (b) A target whose tables DIFFER in name from the backup (a wholly different schema, no overlap) is
  // STILL refused: the contract is a fresh, empty database, so ANY user table fails closed -- a divergent
  // schema can never be partially overwritten regardless of name overlap.
  const otherSchema = new TargetD1();
  otherSchema.seedTable("legacy_audit");
  let refusedOther = false;
  try {
    await new D1RestoreSink(otherSchema as unknown as D1Database, "appdb", false).put("appdb", headerBytes);
  } catch (e) {
    refusedOther = /not empty|fresh database/.test((e as Error).message);
  }
  ok("a different-schema (non-overlapping) non-empty target is ALSO refused (any user table fails closed)", refusedOther);
  ok("nothing written into the different-schema target either", otherSchema.batches === 0 && !otherSchema.wroteSchema());

  // The fail-closed is PRECISE, not a blanket refusal: a target holding ONLY SQLite/D1 internals
  // (sqlite_*, _cf_*) is treated as fresh, so the header proceeds and CREATEs the tables.
  const fresh = new TargetD1();
  fresh.seedTable("sqlite_sequence");
  fresh.seedTable("_cf_KV");
  let freshThrew = false;
  try {
    await new D1RestoreSink(fresh as unknown as D1Database, "appdb", false).put("appdb", headerBytes);
  } catch {
    freshThrew = true;
  }
  ok("a target holding ONLY SQLite/D1 internals is treated as fresh (proceeds, no refusal)", !freshThrew);
  ok("the fresh target had its table CREATE applied (the header ran)", fresh.batches >= 1 && fresh.capturedSql.some((q) => /CREATE TABLE/i.test(q)));
}

// ---- IDEM-03 ----------------------------------------------------------------

async function idem03(): Promise<void> {
  console.log("\nIDEM-03: KV TTL reproduced as an ABSOLUTE expiration; a stale (lapsed) TTL is DROPPED and counted, never silently kept or silently lost:");
  const nowSec = Math.floor(Date.now() / 1000);
  const future = nowSec + 86400; // a TTL a day out
  const past = nowSec - 3600; // a TTL that LAPSED an hour ago (a stale backup)

  // (refute the core concern) a FUTURE TTL + metadata are BOTH reproduced on the put, and the expiration is
  // passed through as the ABSOLUTE epoch second the source captured -- not clamped, not relativised.
  const kv = new StrictKV(nowSec);
  const sink = new KVRestoreSink(kv as unknown as KVNamespace, "ns");
  const recFuture = mkRec({ name: "session/live", sourceType: "kv", kv: { expiration: future, metadata: { tier: "gold" } } });
  await sink.put(recFuture.name, utf8("a live value"), putOptionsFromRecord(recFuture));
  const putFuture = kv.puts.find((p) => p.key === "session/live")!;
  ok("a future KV TTL is reproduced on the put (captured + reproduced, not value-only)", putFuture.options?.expiration === future);
  ok("the KV metadata is reproduced alongside the TTL", JSON.stringify(putFuture.options?.metadata) === JSON.stringify({ tier: "gold" }));
  ok("the TTL is passed through as the ABSOLUTE epoch second, unclamped/unrelativised", putFuture.options?.expiration === future && future > nowSec);

  // (the boundary) a STALE backup carries a TTL that has since LAPSED. The DESCRIPTOR still carries the past
  // absolute time verbatim (nothing rewrites the archive's own record of what the key's expiration was), and
  // the SINK is where the decision is taken: it drops an expiration the binding will no longer accept, so the
  // value and the metadata land and the key simply has no TTL until one is set. The loss is counted, at the
  // drop site, on the receipt.
  drainMetadataShed(); // start from a clean tally so the count below is this put's, not a previous check's
  const recStale = mkRec({ name: "session/stale", sourceType: "kv", kv: { expiration: past } });
  const staleOpts = putOptionsFromRecord(recStale);
  ok("the stale (past) TTL is carried through the DESCRIPTOR verbatim, NOT clamped to a safe future time", staleOpts?.kv?.expiration === past);
  let staleErr: Error | null = null;
  try {
    await sink.put(recStale.name, utf8("a recoverable value"), staleOpts);
  } catch (e) {
    staleErr = e as Error;
  }
  ok("restoring a lapsed-TTL value does NOT throw at the sink (the customer's data is not lost to an expiry that has simply gone by)", staleErr === null);
  ok("the lapsed-TTL value LANDS, with its bytes intact", eqBytes(kv.store.get("session/stale") ?? new Uint8Array(), utf8("a recoverable value")));
  const stalePut = kv.puts.find((p) => p.key === "session/stale")!;
  ok("the binding was never OFFERED the lapsed expiration (it is dropped before the put, not rejected by it)", stalePut.options === undefined || stalePut.options.expiration === undefined);
  ok("the drop is COUNTED as kv-expiration-lapsed, so the receipt cannot claim full fidelity", (drainMetadataShed()["kv-expiration-lapsed"] ?? 0) === 1);
  // The generic destination-access classification is still the right answer for a genuine sink rejection
  // (as distinct from a lapsed expiration, which is handled separately), so the classifier itself is left
  // pinned.
  ok("a real sink rejection still classifies as a surfaced availability failure (the classifier is unchanged)", destAccessReason("KV PUT failed: 403 Forbidden") === REASON_DESTINATION_ACCESS);

  // (isolation) the stale record does not disturb a sibling: a record with NO TTL still restores cleanly.
  const recNoTtl = mkRec({ name: "config/plain", sourceType: "kv" });
  await sink.put(recNoTtl.name, utf8("plain value"), putOptionsFromRecord(recNoTtl));
  ok("a sibling record with no TTL still restores after the stale one failed (per-record isolation)", eqBytes(kv.store.get("config/plain")!, utf8("plain value")));

  // an expiration of 0 is the no-expiry sentinel: the sink's `> 0` guard drops it, so a 0 never becomes a
  // 1970 absolute TTL that would reject (or instantly expire) every restored key.
  const recZero = mkRec({ name: "config/zero", sourceType: "kv", kv: { expiration: 0 } });
  await sink.put(recZero.name, utf8("zero ttl"), putOptionsFromRecord(recZero));
  const putZero = kv.puts.find((p) => p.key === "config/zero")!;
  ok("an expiration of 0 is dropped (no-expiry sentinel, never a 1970 absolute TTL)", putZero.options === undefined || putZero.options.expiration === undefined);
}

// ---- IDEM-04 ----------------------------------------------------------------

async function idem04(): Promise<void> {
  console.log("\nIDEM-04: R2 metadata fidelity -- content-type + every httpMetadata field + customMetadata reproduced; storageClass SILENTLY DROPPED:");

  // (refute the bulk concern) drive the REAL R2RestoreSink: EVERY R2 HTTP metadata field r2PutOptions models
  // (contentType, contentLanguage, contentDisposition, contentEncoding, cacheControl, cacheExpiry) plus
  // customMetadata is reproduced on the put. validate-descriptors covers contentType/cacheControl/cacheExpiry;
  // this additionally pins contentLanguage/contentDisposition/contentEncoding so the whole modelled set is proven.
  const rec = mkRec({
    name: "media/report.pdf",
    sourceType: "r2",
    r2: {
      httpMetadata: { contentType: "application/pdf", contentLanguage: "en-AU", contentDisposition: 'attachment; filename="r.pdf"', contentEncoding: "gzip", cacheControl: "max-age=600", cacheExpiry: new Date("2031-01-01T00:00:00.000Z").toISOString() },
      customMetadata: { team: "ops", origin: "ingest" },
    },
  });
  const sinkBinding = new MemR2Sink();
  await new R2RestoreSink(sinkBinding as unknown as R2Bucket, "bucket").put(rec.name, utf8("pdf bytes"), putOptionsFromRecord(rec));
  const put = sinkBinding.puts.find((p) => p.key === "media/report.pdf")!;
  const http = objMeta(put.options);
  ok("R2 restore reproduces contentType", http?.contentType === "application/pdf");
  ok("R2 restore reproduces contentLanguage", http?.contentLanguage === "en-AU");
  ok("R2 restore reproduces contentDisposition", http?.contentDisposition === 'attachment; filename="r.pdf"');
  ok("R2 restore reproduces contentEncoding", http?.contentEncoding === "gzip");
  ok("R2 restore reproduces cacheControl", http?.cacheControl === "max-age=600");
  ok("R2 restore rebuilds cacheExpiry as a Date", http?.cacheExpiry instanceof Date && http.cacheExpiry.toISOString() === "2031-01-01T00:00:00.000Z");
  ok("R2 restore reproduces customMetadata", JSON.stringify(put.options?.customMetadata) === JSON.stringify({ team: "ops", origin: "ingest" }));

  // (the REAL fidelity finding) STORAGE CLASS. The source binding exposes R2Object.storageClass and the
  // restore put accepts R2PutOptions.storageClass (both in @cloudflare/workers-types), so the platform CAN
  // round-trip it -- but the engine's descriptor model does not.
  //
  // CAPTURE: the REAL R2Source over a source object IN the InfrequentAccess class lifts its content-type and
  // custom metadata into the descriptor but DROPS the storage class entirely (describeObject never reads it).
  const src = new R2Source(new MemR2Source([{ key: "cold/object.bin", value: utf8("cold bytes"), httpMetadata: { contentType: "application/octet-stream" }, customMetadata: { k: "v" }, storageClass: "InfrequentAccess" }]) as unknown as R2Bucket, "bucket");
  const captured: SourceRecord[] = [];
  for await (const r of src.crawl({ include: [], exclude: [] })) captured.push(r);
  const cold = captured.find((r) => r.name === "cold/object.bin")!;
  ok("R2 capture lifts contentType + customMetadata into the descriptor", cold.descriptor?.r2HttpMetadata?.["contentType"] === "application/octet-stream" && JSON.stringify(cold.descriptor?.r2CustomMetadata) === JSON.stringify({ k: "v" }));
  const descJson = JSON.stringify(cold.descriptor ?? {}).toLowerCase();
  ok("FINDING: the source object's storageClass (InfrequentAccess) is NOT captured anywhere in the descriptor", !descJson.includes("infrequentaccess") && !descJson.includes("storageclass"));

  // APPLY: the richest R2 descriptor the chain can carry (httpMetadata + customMetadata) still yields put
  // options with NO storageClass key -- there is no slot for one -- so the restored object cannot be placed
  // back in its source tier; it lands in the destination bucket's DEFAULT storage class, with no marker/flag.
  const r2rec = mkRec({ name: "cold/object.bin", sourceType: "r2", r2: { httpMetadata: { contentType: "application/octet-stream" }, customMetadata: { k: "v" } } });
  const sinkBinding2 = new MemR2Sink();
  await new R2RestoreSink(sinkBinding2 as unknown as R2Bucket, "bucket").put(r2rec.name, utf8("cold bytes"), putOptionsFromRecord(r2rec));
  const coldPut = sinkBinding2.puts.find((p) => p.key === "cold/object.bin")!;
  ok("FINDING: the R2 restore put carries NO storageClass (the object lands in the destination bucket default tier)", coldPut.options !== undefined && !("storageClass" in coldPut.options));
}

async function main(): Promise<void> {
  await idem01();
  await idem02();
  await idem03();
  await idem04();
  console.log(
    failures === 0
      ? "\nIDEM RESTORE-FIDELITY VALIDATORS PASS (IDEM-01 revert-by-design + dual-control; IDEM-02 fail-closed on schema divergence; IDEM-03 TTL reproduced, lapsed TTL dropped and counted; IDEM-04 metadata reproduced, storageClass DROPPED = documented finding)"
      : `\n${failures} FAILURE(S)`,
  );
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
