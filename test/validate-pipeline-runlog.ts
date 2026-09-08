// Exercise the live RUNLOG accumulation path through runBackup: two runs of one downpipe
// against an in-memory destination, asserting the account-wide RUNLOG ends with both
// entries (read-append-sign-conditional-write), then flush to <outdir> so a Go
// cross-check can prove anti-rollback.
//
// TC-12: when no outdir argument is given the test defaults to a unique directory under
// os.tmpdir() and removes it on exit so it can run hands-free (no argument required).
// When an explicit outdir is supplied the caller owns it; no cleanup is performed.
//
// Run: node test/validate-pipeline-runlog.ts [outdir]

import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { runBackup, appendRunlog, type RunConfig, type RunClock } from "../src/seal/pipeline.ts";
import { parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { SourceAdapter, SourceRecord, Selector } from "../src/sources/types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";

const explicitOutDir = process.argv[2] ?? null;
const cleanupOnExit = explicitOutDir === null;
const outDir = explicitOutDir ?? join(tmpdir(), `dp-runlog-validate-${crypto.randomUUID()}`);
const R1 = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const R2 = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const DP = "dp_pipeline";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// An in-memory Destination with ETag-based optimistic concurrency.
class MemoryDestination implements Destination {
  private store = new Map<string, { body: Uint8Array; etag: string }>();
  private counter = 0;
  private nextEtag(): string {
    return `"${++this.counter}"`;
  }
  async get(key: string): Promise<GetResult | null> {
    const v = this.store.get(key);
    return v ? { body: v.body, etag: v.etag } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.store.set(key, { body, etag: this.nextEtag() });
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    let n = 0;
    for (const p of parts) n += p.length;
    const merged = new Uint8Array(n);
    let off = 0;
    for (const p of parts) {
      merged.set(p, off);
      off += p.length;
    }
    this.store.set(key, { body: merged, etag: this.nextEtag() });
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.store.get(key);
    if (opts.ifNoneMatch === "*" && cur) return { ok: false };
    if (opts.ifMatch && (!cur || cur.etag !== opts.ifMatch)) return { ok: false };
    const etag = this.nextEtag();
    this.store.set(key, { body, etag });
    return { ok: true, etag };
  }
  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix));
  }
  entries(): Map<string, Uint8Array> {
    return new Map([...this.store].map(([k, v]) => [k, v.body]));
  }
}

class FakeSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private value: string;
  constructor(value: string) {
    this.value = value;
  }
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: "k", value: utf8(this.value), namespace: "ns" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}

// IdentitySource carries an accountId (like the API sources) and yields a record with a `database` UUID
// (like D1): it lets the round-trip prove the BUFFERED seal path (runBackup) stamps `account` from the
// adapter and carries `database` from the record all the way into the signed, decoded manifest line. This
// is the regression guard for the buffered-path parity bug (makeLine had dropped both).
class IdentitySource implements SourceAdapter {
  readonly sourceType = "d1" as const;
  readonly accountId = "acct-roundtrip-Y";
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "d1", name: "appdb/00-header", value: utf8("hdr"), database: "db-uuid-roundtrip-X" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const recipients = [breakGlass.entry, op.entry];

  const dest = new MemoryDestination();
  const cfg: RunConfig = { downpipeId: DP, downpipeName: "pipeline", cadence: "3600s", selector: { include: [], exclude: [] }, recipients };
  const clockBase = { randomNonce: () => rand(16), randomSalt: () => rand(16) };

  // A best-effort in-memory RUNLOG lock; the second run takes it to prove the lock path
  // (acquire -> write -> release) works end to end.
  let held = false;
  let acquires = 0;
  const lock = {
    acquire: async () => {
      if (held) return null;
      held = true;
      acquires++;
      return "tok";
    },
    release: async (_t: string) => {
      held = false;
    },
  };

  await runBackup([new FakeSource("run one value")], cfg, signer, dest, { ...clockBase, runId: R1, runlogIndex: 1, prevRunId: null, now: "2026-06-07T00:00:01.000Z", master: rand(32) } as RunClock);
  await runBackup([new FakeSource("run two value")], cfg, signer, dest, { ...clockBase, runId: R2, runlogIndex: 2, prevRunId: R1, now: "2026-06-07T01:00:01.000Z", master: rand(32) } as RunClock, lock);

  ok("RUNLOG write took the lock and released it", acquires === 1 && held === false);
  const log = await dest.get("_RECOVERY/RUNLOG");
  ok("RUNLOG present after two runs", log !== null);
  const entries = log ? parseRunlog(log.body) : [];
  ok("RUNLOG accumulated both entries", entries.length === 2);
  ok("entry 1 is run 1 with index 1, no prev", entries[0]?.runId === R1 && entries[0]?.index === 1 && entries[0]?.prevRunId === null);
  ok("entry 2 is run 2 with index 2, chained to run 1", entries[1]?.runId === R2 && entries[1]?.index === 2 && entries[1]?.prevRunId === R1);

  // The lock MUST be released even when the RUNLOG write throws; otherwise the next run cannot take the
  // lock and the account-wide RUNLOG silently stalls. Drive appendRunlog with a destination that throws on
  // the RUNLOG read (the work happens inside appendRunlog's try) and assert the lock is back to free.
  {
    let throwHeld = false;
    let throwAcquires = 0;
    const throwLock = {
      acquire: async () => {
        if (throwHeld) return null;
        throwHeld = true;
        throwAcquires++;
        return "tok";
      },
      release: async (_t: string) => {
        throwHeld = false;
      },
    };
    const throwingDest: Destination = {
      get: async (_k: string): Promise<GetResult | null> => {
        throw new Error("destination read failure");
      },
      put: (k, b) => dest.put(k, b),
      putStream: (k, b) => dest.putStream(k, b),
      putConditional: (k, b, o) => dest.putConditional(k, b, o),
      exists: (k) => dest.exists(k),
      delete: (k) => dest.delete(k),
      list: (p) => dest.list(p),
    };
    const entry: RunlogEntry = { index: 3, runId: R2, downpipeId: DP, time: "2026-06-07T02:00:01.000Z", recordCount: 1, prevRunId: R1, status: "active" };
    let threw = false;
    try {
      await appendRunlog(throwingDest, signer, entry, throwLock, { relinkLocalPrev: true });
    } catch {
      threw = true;
    }
    ok("RUNLOG write that throws still propagates the error", threw);
    ok("RUNLOG lock is released after a thrown write (held === false)", throwAcquires === 1 && throwHeld === false);
  }

  // The TS reader's freshness check must agree with Go: latest run fresh, older stale.
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`missing ${k}`);
      return r.body;
    },
  };
  const identity = parseIdentity(breakGlass.identity);
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };
  const r2run = await openRun(store, R2, identity, verifier, { verifyFreshness: true });
  ok("TS reader: latest run R2 is fresh", r2run.freshness?.isLatestForDownpipe === true);
  let r1Rejected = false;
  try {
    await openRun(store, R1, identity, verifier, { verifyFreshness: true });
  } catch {
    r1Rejected = true;
  }
  ok("TS reader: older run R1 rejected as stale", r1Rejected);
  const r1stale = await openRun(store, R1, identity, verifier, { verifyFreshness: true, allowStale: true });
  ok("TS reader: older run R1 opens with allowStale, marked not-latest", r1stale.freshness?.isLatestForDownpipe === false);

  // ---- RUNLOG-1: a rapid re-trigger / crashed-run RECLAIM must not sign a null-prev root ----
  // Reproduce the churn window on a fresh destination: run A seals + appends (idx 1). Run B is then
  // triggered with clock.prevRunId=null — exactly what the scheduler DO hands a reclaim, since
  // lastRunId only advances on a SUCCESSFUL completion and run A's completion has not landed — but at
  // idx 2. The signed root must be seeded from the destination-local RUNLOG (the same source the relink
  // uses), so the root and the relinked RUNLOG entry agree on run A's prevRunId and run B opens fresh
  // WITHOUT allowStale, rather than the strict reader rejecting the intact run B as a rollback.
  {
    const dest2 = new MemoryDestination();
    const cfg2: RunConfig = { downpipeId: "dp_churn", downpipeName: "churn", cadence: "3600s", selector: { include: [], exclude: [] }, recipients };
    const A = "01ARZ3NDEKTSV4RRFFQ69G5FE3";
    const B = "01ARZ3NDEKTSV4RRFFQ69G5FF4";
    await runBackup([new FakeSource("a")], cfg2, signer, dest2, { ...clockBase, runId: A, runlogIndex: 1, prevRunId: null, now: "2026-06-07T03:00:01.000Z", master: rand(32) } as RunClock);
    // The BUG input: prevRunId=null at idx 2 (reclaim before lastRunId advanced).
    await runBackup([new FakeSource("b")], cfg2, signer, dest2, { ...clockBase, runId: B, runlogIndex: 2, prevRunId: null, now: "2026-06-07T04:00:01.000Z", master: rand(32) } as RunClock);
    const log2 = await dest2.get("_RECOVERY/RUNLOG");
    const e2 = log2 ? parseRunlog(log2.body) : [];
    const eB = e2.find((e) => e.runId === B);
    ok("churn reclaim: run B's RUNLOG entry links run A (not null)", eB?.prevRunId === A);

    // The signed root must carry the SAME prev (A); proven by the reader accepting run B as fresh
    // WITHOUT allowStale (the run-vs-root prevRunId equality is exactly what would otherwise throw rc=5).
    const store2: ObjectStore = {
      get: async (k: string) => {
        const r = await dest2.get(k);
        if (!r) throw new Error(`missing ${k}`);
        return r.body;
      },
    };
    let bFreshNoStale = false;
    try {
      const bRun = await openRun(store2, B, identity, verifier, { verifyFreshness: true });
      bFreshNoStale = bRun.freshness?.isLatestForDownpipe === true;
    } catch {
      bFreshNoStale = false;
    }
    ok("churn reclaim: run B opens fresh WITHOUT allowStale (root agrees with the RUNLOG)", bFreshNoStale);
  }

  // Flush to disk for the Go cross-check.
  for (const [key, body] of dest.entries()) {
    const path = join(outDir, "archive", key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, body);
  }
  await writeFile(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(breakGlass.identity)}\n`);
  await writeFile(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(concat(edPublic, mldsa.publicKey))}\n`);

  // ---- IDENTITY ROUND-TRIP: the BUFFERED seal path carries `database` + `account` to the SIGNED line ----
  // Regression guard for the buffered-path parity bug: pipeline.ts computed the identity fields but
  // writer.ts makeLine rebuilt the record meta and dropped them, so a SLICED_RUNS_DISABLED run (and the
  // canary) sealed D1/API-source records with no database UUID / account. Seal a real adapter through
  // runBackup, decode the signed manifest, and prove both fields are present.
  {
    const idest = new MemoryDestination();
    const idcfg: RunConfig = { downpipeId: "dp_identity", downpipeName: "identity", cadence: "3600s", selector: { include: [], exclude: [] }, recipients };
    const IR = "01ARZ3NDEKTSV4RRFFQ69G5FC0";
    await runBackup([new IdentitySource()], idcfg, signer, idest, { ...clockBase, runId: IR, runlogIndex: 1, prevRunId: null, now: "2026-06-07T05:00:01.000Z", master: rand(32) } as RunClock);
    const istore: ObjectStore = { get: async (k: string) => { const r = await idest.get(k); if (!r) throw new Error(`missing ${k}`); return r.body; } };
    const irun = await openRun(istore, IR, identity, verifier, {});
    const rec = irun.records.find((r) => r.name === "appdb/00-header");
    ok("buffered round-trip: the sealed record decodes", rec !== undefined);
    ok("buffered round-trip: `database` UUID reaches the SIGNED manifest line (makeLine parity)", rec?.database === "db-uuid-roundtrip-X");
    ok("buffered round-trip: `account` (stamped from the adapter) reaches the SIGNED manifest line", rec?.account === "acct-roundtrip-Y");
  }

  console.log(failures === 0 ? "\nPIPELINE RUNLOG ACCUMULATION PASSES" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exitCode = 1;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

(async () => {
  try {
    await main();
  } catch (e) {
    console.error(e);
    process.exitCode = 1;
  } finally {
    if (cleanupOnExit) {
      await rm(outDir, { recursive: true, force: true });
    }
  }
})();
