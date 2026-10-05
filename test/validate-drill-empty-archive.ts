// Validates that an HONEST EMPTY ARCHIVE is a drill DEFERRAL and never a restore FAULT, for every downpipe
// source type, and that a REAL open error on the same archive still is a fault.
//
// THE FINDING THIS GUARDS (support bundle, engine 0.3.5): 46 restoreFaults rows reading
// {op:"drill", phase:"open", cls:"other"}, two a day, from dp-src-kv-beacons (an empty KV namespace) and
// an empty R2 bucket. The drill's open phase did not fail on either. runDrill opened
// and verified the run, found zero records and returned the deliberate deferral {ok:false, nothingToVerify:true}
// (drill.ts NOTHING_TO_VERIFY_REASON). The fault projection, drillFaultRows, read ok:false alone, so the
// deferral reason classified to "other" and "other" maps to the "open" phase. The pack also carried
// lastRestoreTestOk:false without the deferral kind beside it, so the same state read as a failed test twice.
//
// THE CLASS GUARD: SOURCE_TYPE_ROWS is exhaustive over the downpipe source-type union (SourceSpec["type"])
// at type level, so a new source type fails typecheck here until it has a row. Each row seals a zero-record
// run through the SLICED finaliseRun path (the path every estate runs; the buffered writer refuses an empty
// run outright) with that source type in the checkpoint, then drives the manual and the windowed drill and
// the one-call recorder both drill routes use (recordDrillOutcome) against a capturing scheduler.
//
// THE CONTROL: the same archive with its root manifest deleted, and again with a signature byte flipped,
// must still produce exactly one open-phase fault row that is posted. Without the control a projection that
// recorded nothing at all would pass every row above.
//
// THE PROJECTION: the pack's downpipe row carries lastRestoreTestDeferred, gated on its closed vocabulary.
//
// In-memory doubles only; no network, no deploy. Run: node test/validate-drill-empty-archive.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { runDrill } from "../src/admin/drill.ts";
import { drillFaultRows, recordDrillOutcome } from "../src/admin/restore-faults.ts";
import { projectDownpipeRow, type ProjectRowOpts } from "../src/admin/support-sections-downpipes.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { wrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { finaliseRun, type SliceDeps } from "../src/seal/slice.ts";
import type { SourceSpec } from "../src/sched/types.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// Every downpipe source type. The satisfies clause is the type-level exhaustiveness check: a member added to
// SourceSpec["type"] without a row here is a typecheck error under tsconfig.test.json.
const SOURCE_TYPE_ROWS = {
  kv: true,
  r2: true,
  secrets: true,
  d1: true,
  "cf-config": true,
  workers: true,
  stream: true,
  images: true,
  artifacts: true,
} as const satisfies Record<SourceSpec["type"], true>;
const SOURCE_TYPES = Object.keys(SOURCE_TYPE_ROWS) as Array<SourceSpec["type"]>;

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

// MemDest is the Destination contract over a map (the sliced seal writes through it).
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    await this.put(key, concat(...parts));
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.tags.get(key);
    if (opts.ifNoneMatch === "*" && cur !== undefined) return { ok: false };
    if (opts.ifMatch !== undefined && cur !== opts.ifMatch) return { ok: false };
    await this.put(key, body);
    return { ok: true, etag: this.tags.get(key)! };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
    this.tags.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

// An R2Bucket-shaped read view, so buildDestination(env) picks R2Destination and the drill reads the archive.
function bucketOver(store: Map<string, Uint8Array>): R2Bucket {
  return {
    async get(key: string) {
      const v = store.get(key);
      if (!v) return null;
      return { arrayBuffer: async () => toAB(v), etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2ObjectBody;
    },
    async head(key: string) {
      const v = store.get(key);
      return v ? ({ etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2Object) : null;
    },
  } as unknown as R2Bucket;
}

// A capturing scheduler: records every restore-fault post recordDrillOutcome makes, and answers ok.
function capturingScheduler(): { stub: DurableObjectStub; posts: unknown[][] } {
  const posts: unknown[][] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/diag/restore-faults")) posts.push((JSON.parse(String(init?.body ?? "{}")) as { rows: unknown[] }).rows);
      return new Response("{}", { status: 200 });
    },
  } as unknown as DurableObjectStub;
  return { stub, posts };
}

// sealEmpty seals a zero-record run of the given source type through the sliced finaliseRun path.
async function sealEmpty(sourceType: SourceSpec["type"], runId: string, signer: Signer, signerPrivateB64: string, recipients: RecipientEntry[]): Promise<MemDest> {
  const dest = new MemDest();
  const master = rand(32);
  const cp: RunCheckpoint = {
    v: 1,
    downpipeId: `dp_empty_${sourceType}`,
    downpipeName: `empty ${sourceType}`,
    cadence: "3600s",
    sourceType,
    selector: { include: [], exclude: [] },
    runId,
    runlogIndex: 1,
    prevRunId: null,
    startedAt: "2026-09-26T00:00:00.000Z",
    wrappedMaster: await wrapMaster(signerPrivateB64, runId, master),
    cursor: null,
    sourceDone: true,
    nextRecordIndex: 0,
    nextShardIndex: 0,
    frontier: { count: 0, nodes: [] },
    counts: zeroCounts(),
    sliceCount: 1,
    partialRecord: null,
  };
  const deps: SliceDeps = {
    // finaliseRun never reads the source (sourceDone is true); the seal is source-agnostic past this point.
    source: {} as unknown as SliceDeps["source"],
    dest,
    signer,
    recipients,
    budget: new SliceBudget({ subrequests: 200, wallMs: 60_000 }),
  };
  await finaliseRun(deps, cp, master, [], []);
  return dest;
}

function envOver(store: Map<string, Uint8Array>, signerPrivateB64: string, operationalPrivateB64: string): Env {
  return {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: bucketOver(store),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;
}

async function main(): Promise<void> {
  const signerPrivateB64 = b64urlEncode(rand(64));
  const signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const recipients = [breakGlass.entry, op.entry];
  const operationalPrivateB64 = b64urlEncode(op.identity);

  console.log("-- 1. an honest empty archive is a deferral, never a fault, for every source type --");
  ok(`POPULATION: the table covers ${SOURCE_TYPES.length} source types`, SOURCE_TYPES.length >= 9);
  let sealedAny: { dest: MemDest; runId: string } | null = null;
  let i = 0;
  for (const sourceType of SOURCE_TYPES) {
    const runId = `01K6EMPTYAKCHVE000000000${String(i++).padStart(2, "0")}`;
    const dest = await sealEmpty(sourceType, runId, signer, signerPrivateB64, recipients);
    const env = envOver(dest.map, signerPrivateB64, operationalPrivateB64);
    for (const [mode, result] of [
      ["manual", await runDrill(env, runId)],
      ["windowed", await runDrill(env, runId, null, { cursor: 0, window: 8 })],
    ] as const) {
      ok(`${sourceType} ${mode}: the run opened and holds zero records`, result.recordsVerified === 0);
      ok(`${sourceType} ${mode}: it is the nothingToVerify deferral, not a pass`, result.ok === false && result.nothingToVerify === true);
      ok(`${sourceType} ${mode}: drillFaultRows records no fault row`, drillFaultRows(result).length === 0);
      const cap = capturingScheduler();
      await recordDrillOutcome(cap.stub, result);
      ok(`${sourceType} ${mode}: recordDrillOutcome posts nothing to the restoreFaults ring`, cap.posts.length === 0);
    }
    if (sealedAny === null) sealedAny = { dest, runId };
  }

  console.log("-- 2. CONTROL: a real open error on the same archive is still a fault --");
  if (sealedAny === null) throw new Error("no archive was sealed");
  const rootKey = [...sealedAny.dest.map.keys()].find((k) => k.includes(sealedAny!.runId) && /root/.test(k));
  ok("POPULATION: the sealed archive has a root manifest object to remove", rootKey !== undefined);
  {
    const store = new Map(sealedAny.dest.map);
    if (rootKey !== undefined) store.delete(rootKey);
    const result = await runDrill(envOver(store, signerPrivateB64, operationalPrivateB64), sealedAny.runId);
    const rows = drillFaultRows(result);
    ok("missing root manifest: the drill is NOT ok", result.ok === false);
    ok("missing root manifest: it is NOT a nothingToVerify deferral", result.nothingToVerify === undefined);
    ok("missing root manifest: exactly one fault row", rows.length === 1);
    ok("missing root manifest: the row is an open-phase drill fault naming the missing object", rows[0]?.op === "drill" && rows[0]?.phase === "open" && rows[0]?.cls === "object-missing");
    const cap = capturingScheduler();
    await recordDrillOutcome(cap.stub, result);
    ok("missing root manifest: recordDrillOutcome posts the row", cap.posts.length === 1 && cap.posts[0]?.length === 1);
  }
  {
    const store = new Map(sealedAny.dest.map);
    const sigKey = rootKey !== undefined ? [...store.keys()].find((k) => k !== rootKey && k.startsWith(rootKey) && /sig/.test(k)) ?? rootKey : undefined;
    ok("POPULATION: there is a signed object to damage", sigKey !== undefined);
    if (sigKey !== undefined) {
      const b = new Uint8Array(store.get(sigKey)!);
      const mid = b.length >> 1;
      b[mid] = (b[mid] ?? 0) ^ 0xff;
      store.set(sigKey, b);
    }
    const result = await runDrill(envOver(store, signerPrivateB64, operationalPrivateB64), sealedAny.runId);
    const rows = drillFaultRows(result);
    ok("damaged signature: the drill is NOT ok and NOT a deferral", result.ok === false && result.nothingToVerify === undefined);
    ok("damaged signature: exactly one fault row, and it is not the empty-run 'other'", rows.length === 1 && rows[0]?.cls !== "other");
    const cap = capturingScheduler();
    await recordDrillOutcome(cap.stub, result);
    ok("damaged signature: recordDrillOutcome posts the row", cap.posts.length === 1);
  }

  console.log("-- 3. the pack carries the deferral kind beside lastRestoreTestOk --");
  const opts: ProjectRowOpts = { replication: null, destIdSet: null, sealErrors: {}, freshnessIndex: new Map(), freshnessTruncation: { named: new Set<string>(), incomplete: false }, refusalIndex: new Map() };
  const base = { config: { id: "dp1", name: "beacons", enabled: true, cadenceSeconds: 86400, source: { type: "kv" } }, lastRunId: "01RUN", inFlight: false, lastRestoreTestAt: 1_790_212_535_988, lastRestoreTestOk: false };
  const deferredRow = projectDownpipeRow({ ...base, lastRestoreTestDeferred: "no-records" } as never, opts) as Record<string, unknown>;
  ok("a no-records deferral rides as lastRestoreTestDeferred:no-records", deferredRow["lastRestoreTestDeferred"] === "no-records" && deferredRow["lastRestoreTestOk"] === false);
  const driftRow = projectDownpipeRow({ ...base, lastRestoreTestDeferred: "s3cr3t-raw-value" } as never, opts) as Record<string, unknown>;
  ok("an out-of-vocabulary kind rides as the drift placeholder, never raw", driftRow["lastRestoreTestDeferred"] !== undefined && !JSON.stringify(driftRow).includes("s3cr3t"));
  const plainRow = projectDownpipeRow(base as never, opts) as Record<string, unknown>;
  ok("CONTROL: a real failure (no kind) carries no deferral field", !("lastRestoreTestDeferred" in plainRow));

  console.log(failures === 0 ? "\nDRILL EMPTY ARCHIVE PASS\n" : `\nDRILL EMPTY ARCHIVE FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
