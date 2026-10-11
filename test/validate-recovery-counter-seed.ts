// Proves the recovery-path counter reseed: a rebuilt SchedulerDO's runlogCounter starts at zero against a
// surviving destination bucket, so without a seed the recovery path's own first trigger() would fork the
// customer's signed RUNLOG. readVerifiedRunlogSeed (format/freshness.ts) reads the bucket's own RUNLOG,
// verified under the operator's pinned signer, and setControlPlaneRecoveryRequired
// (scheduler-do-control-plane.ts) anchors the DO's runlogCounter to it, monotonically, before the latch is
// set -- so the next real trigger() allocates the index the log actually expects, through the REAL routed
// HTTP surface (stubFetch), not a hand-fed index.
//
// Cell A is the reader in isolation, with its own negative controls (wrong verifier, absent document,
// corrupt signature) so the seed can be shown to withhold an answer, not merely to produce one.
// Cell B drives the full recovery path through a real SchedulerDO: unseeded (the baseline case) vs
// seeded, reading the ALLOCATED index off trigger()'s own response, never off a source variable.
// Cell C closes the loop against the real writer: the seeded index is used to seal an actual run into the
// bucket that already holds the three pre-loss entries, and the resulting document is asserted clean AND
// the pre-loss run stays attestable, as validate-runlog-fork-on-recovery.ts's cell A requires.
//
// Cells D-I grade every way the recovery path's RUNLOG read can end, through the real cron health pass (see
// the block above seedOutcomeCells).
//
// Run: node test/validate-recovery-counter-seed.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { runControlPlaneHealthPass } from "../src/cron/control-plane-pass.ts";
import { advanceAfterIndexHeld, pinnedVerifier, reseedAfterIndexHeld, seedAcrossArchives, type RunlogReader } from "../src/cron/runlog-index-advance.ts";
import { fetchSiteFaults } from "../src/admin/site-faults.ts";
import { fetchRunHistory } from "../src/admin/support-sections-runs.ts";
import { runlogLockVia } from "../src/seal/runstate-helpers.ts";
import { coarseRunError } from "../src/seal/slice.ts";
import { fetchIntegrityFaults } from "../src/admin/support-sections-faults.ts";
import type { Env } from "../src/env.d.ts";
import { readVerifiedRunlogSeed } from "../src/format/freshness.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import { parseRunlog, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { signRunlog } from "../src/format/writer-runlog.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { budgetFromEnv } from "../src/seal/budget.ts";
import { type RunClock, type RunConfig, runBackup } from "../src/seal/pipeline.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";
import { MockStorage } from "./mock-storage.ts";
import { makeConfig, makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";

const A1 = "01ARZ3NDEKTSV4RRFFQ69G5FA1";
const A2 = "01ARZ3NDEKTSV4RRFFQ69G5FA2";
const A3 = "01ARZ3NDEKTSV4RRFFQ69G5FA3";
const B_SEEDED = "01ARZ3NDEKTSV4RRFFQ69G5FB4"; // the post-recovery run, sealed at the SEEDED index.
const DP = "dp_recovered";

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

class FakeSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private readonly value: string;
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

function makeRecipient(role: string): RecipientEntry {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } };
}

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function storeOf(dest: MemoryDestination): ObjectStore {
  return {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`missing ${k}`);
      return r.body;
    },
  };
}

// cloneDest copies every object into a fresh MemoryDestination, so cells run against independent copies of
// the same surviving state (memdest.ts carries no snapshot() of its own).
async function cloneDest(src: MemoryDestination): Promise<MemoryDestination> {
  const copy = new MemoryDestination();
  for (const [k, v] of src.entries()) await copy.put(k, v);
  return copy;
}

// okd is ok() with the observed value printed on a failure.
function okd(label: string, cond: boolean, detail?: unknown): void {
  ok(label, cond);
  if (!cond && detail !== undefined) console.log(`         ${JSON.stringify(detail)}`);
}
const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const DP_B = "dp_recovered_b";
const RUN = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FC${n}`;

// Faults planted at the binding, below the production R2 adapter: a get that throws, or a get that reads
// absent while head still reads present (the object went between the existence probe and the read).
interface Faults {
  throwOnGet: Set<string>;
  nullOnGet: Set<string>;
}
function r2For(dest: MemoryDestination, faults: Faults): R2Bucket {
  return {
    get: async (key: string) => {
      if (faults.throwOnGet.has(key)) throw new Error("R2 get failed: 503 SlowDown (planted)");
      if (faults.nullOnGet.has(key)) return null;
      const v = await dest.get(key);
      if (!v) return null;
      return {
        arrayBuffer: async () => {
          const ab = new ArrayBuffer(v.body.byteLength);
          new Uint8Array(ab).set(v.body);
          return ab;
        },
        etag: v.etag,
      };
    },
    head: async (key: string) => ((await dest.get(key)) ? { etag: "x" } : null),
    list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] }),
  } as unknown as R2Bucket;
}

interface Rig {
  storage: MockStorage;
  dobj: SchedulerDO;
  stub: DurableObjectStub;
}
function makeRig(): Rig {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)),
  } as unknown as DurableObjectStub;
  return { storage, dobj, stub };
}
async function doCall(rig: Rig, method: string, path: string, body?: unknown): Promise<Response> {
  return rig.dobj.fetch(new Request(`https://scheduler.internal${path}`, { method, headers: body !== undefined ? { "content-type": "application/json" } : {}, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
}
// addDownpipe restores a downpipe the way the resume slice or a reconcile does, through the real route.
async function addDownpipe(rig: Rig, id: string): Promise<void> {
  const r = await doCall(rig, "POST", "/downpipes", { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_ns", namespaceId: "ns", include: [], exclude: [] } });
  if (!r.ok) throw new Error(`downpipe add failed: ${r.status} ${await r.text()}`);
}
type Trig = { runId: string; index: number } | { skipped: string };
async function trigger(rig: Rig, id: string): Promise<Trig> {
  return (await (await doCall(rig, "POST", "/trigger", { id })).json()) as Trig;
}
type PackSeed = { seed?: number; noSeed?: string; firstNoSeed?: string; allocatedBeforeSeed?: number; allocationHeld?: boolean; reads?: number; heldAllocations?: number };
async function packSeed(rig: Rig): Promise<PackSeed | undefined> {
  return ((await fetchRecoveryStatus(rig.stub, {})) as { runlogSeed?: PackSeed }).runlogSeed;
}


// ---- CELLS D-I: the recovery path's RUNLOG seed OUTCOME, through the real cron health pass -----------------
// Cells A-C grade the seed when the read succeeds. These grade every way the read can END, through the real
// health pass (cron/control-plane-pass.ts runControlPlaneHealthPass), a real SchedulerDO over MockStorage, the
// production R2 destination adapter over an in-memory bucket, the real writer and the real support-pack
// recovery section (admin/support-sections-recovery.ts fetchRecoveryStatus). Before the closed outcome, any
// failed read returned null through a bare catch: the latch recorded nothing, the next trigger allocated index
// 1 into a document that already held it, and every later freshness check of that destination reported
// "runlog index 1 appears twice", with nothing in the pack.
//   D. Each outcome, planted in a real bucket, is named in the pack: seed 3, absent, unreadable, sig-absent,
//      sig-invalid (a corrupt signature and a rotated signer), unparsable, no-signer (unset and malformed).
//   E. unreadable holds allocation with a named reason; once the bucket reads again, the next tick seeds the
//      counter and the next run gets index 4 in a clean RUNLOG.
//   F. no-signer holds the same way, released once a signer is configured.
//   G. sig-absent does not hold (no retry clears it): the first run allocates index 1, the writer refuses it
//      because the RUNLOG holds it, and the pack says so; once the signature reads, the next tick seeds past
//      the document, so the next run gets index 4.
//   H. A fresh bucket with no RUNLOG keeps working: no latch, no seed record, index 1.
//   I. The DO's seed route refuses an outcome outside the closed shape.
//   J. A run refused for an index another archive's RUNLOG holds holds allocation; the next pass reads every
//      archive, sets the counter past the HIGHEST index any of them holds (not only the refusing one), and the
//      pack names where it moved from, to, and the archive that held the maximum.
//   L. A failed advance, a failed archive listing, an unreadable archive and an unusable signer each count into
//      a pack row (siteFaults); a clean advance counts nothing.
//   M. The refused run reads as an integrity refusal naming index-held in the run record the console reads
//      (GET /history) and in the pack's run rows.
//   N. After a recovery whose default RUNLOG has no signature, exactly one run is refused for its index; the
//      next two passes and their runs succeed.
//   K. A recovery whose default archive reads sig-absent seeds from the highest index across every other
//      archive, so the first run succeeds in all of them; an unreadable default still holds.
async function seedOutcomeCells(): Promise<void> {
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);
  const otherSignerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const cfgFor = (id: string): RunConfig => ({ downpipeId: id, downpipeName: id, cadence: "3600s", selector: { include: [], exclude: [] }, recipients: [makeRecipient("break-glass"), makeRecipient("operational")] });
  const clockAt = (runId: string, index: number, day: number): RunClock => ({ runId, runlogIndex: index, prevRunId: null, now: `2026-08-0${day}T00:00:00.000Z`, master: rand(32), randomNonce: () => rand(16), randomSalt: () => rand(16) });

  // The customer's surviving bucket: three runs of one downpipe, sealed and appended by the production writer.
  async function survivingBucket(): Promise<MemoryDestination> {
    const d = new MemoryDestination();
    for (const n of [1, 2, 3]) await runBackup([new FakeSource(`v${n}`)], cfgFor(DP), signer, d, clockAt(RUN(n), n, n));
    return d;
  }
  const noFaults = (): Faults => ({ throwOnGet: new Set(), nullOnGet: new Set() });
  // signerPrivate null configures no signer at all.
  function envFor(rig: Rig, dest: MemoryDestination, faults: Faults, signerPrivate: string | null = signerB64): Env {
    return {
      SCHEDULER: { idFromName: () => ({}) as DurableObjectId, get: () => rig.stub } as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: r2For(dest, faults),
      ...(signerPrivate !== null ? { SIGNER_PRIVATE: signerPrivate } : {}),
    } as unknown as Env;
  }
  const tick = (env: Env, rig: Rig): Promise<void> => runControlPlaneHealthPass(env, rig.stub as never, budgetFromEnv({}));

  // ---- D: each outcome, planted in a real bucket, reaches the pack ------------------------------------------
  console.log("\nD -- each RUNLOG read outcome is named in the pack's recovery section");
  {
    const cases: Array<{ label: string; plant: (d: MemoryDestination, f: Faults) => Promise<void>; signer?: string | null; want: PackSeed }> = [
      { label: "intact RUNLOG", plant: async () => {}, want: { seed: 3, allocationHeld: false } },
      { label: "RUNLOG gone between the probe and the read", plant: async (_d, f) => void f.nullOnGet.add(RUNLOG), want: { noSeed: "absent", allocationHeld: false } },
      { label: "RUNLOG read throws", plant: async (_d, f) => void f.throwOnGet.add(RUNLOG), want: { noSeed: "unreadable", allocationHeld: true } },
      { label: "RUNLOG.sig read throws", plant: async (_d, f) => void f.throwOnGet.add(RUNLOG_SIG), want: { noSeed: "unreadable", allocationHeld: true } },
      { label: "RUNLOG.sig removed", plant: async (d) => d.delete(RUNLOG_SIG), want: { noSeed: "sig-absent", allocationHeld: false } },
      {
        label: "RUNLOG.sig corrupted",
        plant: async (d) => {
          const s = (await d.get(RUNLOG_SIG))!.body.slice();
          s[5] = s[5] === 65 ? 66 : 65;
          await d.put(RUNLOG_SIG, s);
        },
        want: { noSeed: "sig-invalid", allocationHeld: false },
      },
      { label: "a rotated signer", plant: async () => {}, signer: otherSignerB64, want: { noSeed: "sig-invalid", allocationHeld: false } },
      {
        label: "a validly signed RUNLOG that does not parse",
        plant: async (d) => {
          const bad = [{ index: 1, runId: "", downpipeId: DP, time: "2026-08-01T00:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" }] as unknown as Parameters<typeof signRunlog>[0];
          const { runlog, sig } = await signRunlog(bad, signer.edPrivate, signer.mldsaSecret);
          await d.put(RUNLOG, runlog);
          await d.put(RUNLOG_SIG, utf8(b64urlEncode(sig)));
        },
        want: { noSeed: "unparsable", allocationHeld: false },
      },
      { label: "no SIGNER_PRIVATE", plant: async () => {}, signer: null, want: { noSeed: "no-signer", allocationHeld: true } },
      { label: "a malformed SIGNER_PRIVATE", plant: async () => {}, signer: "not-a-key", want: { noSeed: "no-signer", allocationHeld: true } },
    ];
    for (const c of cases) {
      const d = await survivingBucket();
      const f = noFaults();
      await c.plant(d, f);
      const rig = makeRig();
      await tick(envFor(rig, d, f, c.signer === undefined ? signerB64 : c.signer), rig);
      const status = (await (await doCall(rig, "GET", "/control-plane/recovery-status")).json()) as { recoveryRequired?: boolean };
      okd(`D ${c.label}: recovery latched`, status.recoveryRequired === true);
      const got = await packSeed(rig);
      const match = got !== undefined && got.seed === c.want.seed && got.noSeed === c.want.noSeed && got.allocationHeld === c.want.allocationHeld && got.reads === 1;
      okd(`D ${c.label}: the pack says ${JSON.stringify(c.want)}`, match, got);
      const counter = await rig.storage.get<number>("runlogCounter");
      okd(`D ${c.label}: runlogCounter is ${c.want.seed ?? "unset"}`, counter === c.want.seed, counter);
    }
  }

  // ---- E: unreadable holds allocation, and the next tick's re-read releases it ------------------------------
  console.log("\nE -- a failed read holds allocation until a later tick reads the RUNLOG");
  {
    const d = await survivingBucket();
    const f = noFaults();
    f.throwOnGet.add(RUNLOG);
    const rig = makeRig();
    const env = envFor(rig, d, f);
    await tick(env, rig);
    await addDownpipe(rig, DP);
    const t1 = await trigger(rig, DP);
    okd("E: the post-recovery trigger is refused with a named reason", "skipped" in t1 && /held until the recovery path reads the destination RUNLOG \(unreadable\)/.test(t1.skipped), t1);
    okd("E: and the counter did not move", (await rig.storage.get<number>("runlogCounter")) === undefined);
    okd("E: the pack counts the refused allocation", (await packSeed(rig))?.heldAllocations === 1);
    // The bucket reads again. The next tick re-reads, verifies and seeds.
    f.throwOnGet.clear();
    await tick(env, rig);
    const after = await packSeed(rig);
    okd("E: the next tick establishes seed 3 and releases the hold", after?.seed === 3 && after.allocationHeld === false && after.reads === 2 && after.firstNoSeed === "unreadable", after);
    okd("E: nothing was allocated before the seed", after?.allocatedBeforeSeed === undefined, after);
    const t2 = await trigger(rig, DP);
    okd("E: the next trigger allocates index 4", "index" in t2 && t2.index === 4, t2);
    if ("index" in t2) {
      await runBackup([new FakeSource("post")], cfgFor(DP), signer, d, clockAt(t2.runId, t2.index, 5));
      const idx = parseRunlog((await d.get(RUNLOG))!.body).map((e) => e.index);
      okd("E: the RUNLOG holds 1,2,3,4 with no repeated index", idx.length === 4 && new Set(idx).size === 4 && Math.max(...idx) === 4, idx);
      const att = await attestKeyless(storeOf(d), t2.runId, verifier, { allowStale: false });
      okd("E: the post-recovery run attests clean", att.notRolledBack === true && att.signatureValid === true, att.reason);
    }
  }

  // ---- F: no-signer holds allocation until a signer is configured -------------------------------------------
  console.log("\nF -- no signer holds allocation until a signer is set");
  {
    const d = await survivingBucket();
    const rig = makeRig();
    await tick(envFor(rig, d, noFaults(), null), rig);
    await addDownpipe(rig, DP);
    const t1 = await trigger(rig, DP);
    okd("F: the trigger is refused, naming no-signer", "skipped" in t1 && /\(no-signer\)/.test(t1.skipped), t1);
    await tick(envFor(rig, d, noFaults(), signerB64), rig);
    const after = await packSeed(rig);
    okd("F: once a signer is set, the next tick seeds 3", after?.seed === 3 && after.allocationHeld === false && after.firstNoSeed === "no-signer", after);
    const t2 = await trigger(rig, DP);
    okd("F: and the next trigger allocates index 4", "index" in t2 && t2.index === 4, t2);
  }

  // ---- G: sig-absent does not hold; the writer refuses the repeated index ----------------------------------
  console.log("\nG -- a missing signature does not hold, the writer refuses the repeated index, and the pack says what happened");
  {
    const d = await survivingBucket();
    const sigBytes = (await d.get(RUNLOG_SIG))!.body;
    await d.delete(RUNLOG_SIG);
    const rig = makeRig();
    const env = envFor(rig, d, noFaults());
    await tick(env, rig);
    await addDownpipe(rig, DP);
    await addDownpipe(rig, DP_B);
    const t1 = await trigger(rig, DP);
    okd("G: the first trigger is not held, and allocates index 1 (the counter is unanchored)", "index" in t1 && t1.index === 1, t1);
    let refused = "no throw";
    if ("index" in t1) {
      try {
        await runBackup([new FakeSource("post")], cfgFor(DP), signer, d, clockAt(t1.runId, t1.index, 5));
      } catch (e) {
        refused = e instanceof Error ? ((e as { reason?: string }).reason ?? e.message) : String(e);
      }
    }
    okd("G: the writer refuses index 1, which the RUNLOG already holds", refused === "index-held", refused);
    const idx = parseRunlog((await d.get(RUNLOG))!.body).map((e) => e.index);
    okd("G: the RUNLOG holds each index once", idx.length === 3 && new Set(idx).size === 3, idx);
    const before = await packSeed(rig);
    okd("G: the pack names sig-absent with no hold", before?.noSeed === "sig-absent" && before.allocationHeld === false, before);
    await d.put(RUNLOG_SIG, sigBytes);
    await tick(env, rig);
    const after = await packSeed(rig);
    okd("G: once the signature is back, the next tick seeds 3", after?.seed === 3 && after.firstNoSeed === "sig-absent", after);
    okd("G: and records that 1 index was allocated before the seed", after?.allocatedBeforeSeed === 1, after);
    const t2 = await trigger(rig, DP_B);
    okd("G: the next trigger allocates index 4, past the document", "index" in t2 && t2.index === 4, t2);
  }

  // ---- J, K: the counter follows the highest index across every archive --------------------------------------
  const readerOf = (id: string, d: MemoryDestination): RunlogReader => ({ id, get: async (k) => (await d.get(k))?.body ?? null });
  // A bucket holding indices 1..top for one downpipe, sealed by the production writer.
  async function bucketTo(top: number, dp: string): Promise<MemoryDestination> {
    const d = new MemoryDestination();
    for (let n = 1; n <= top; n++) await runBackup([new FakeSource(`w${n}`)], cfgFor(dp), signer, d, clockAt(RUN(n), n, n));
    return d;
  }
  console.log("\nJ -- an index-held refusal advances the counter past the highest index in every archive");
  {
    const a = await survivingBucket(); // archive-a: indices 1..3
    const b = await bucketTo(9, DP_B); // archive-b: indices 1..9
    const rig = makeRig();
    await addDownpipe(rig, DP);
    await addDownpipe(rig, DP_B);
    const t1 = await trigger(rig, DP);
    okd("J: the first trigger allocates index 1", "index" in t1 && t1.index === 1, t1);
    // The run refused at archive-a (index 1 is held there): the writer reports it through the lock.
    const post = await doCall(rig, "POST", "/runlog-index-held", { index: 1, downpipeId: DP });
    okd("J: the DO takes the report", post.ok, post.status);
    const held = await trigger(rig, DP_B);
    okd("J: allocation is held until the pass reads the archives", "skipped" in held && /index/.test(held.skipped) && /held/.test(held.skipped), held);
    await reseedAfterIndexHeld(rig.stub, [readerOf("archive-a", a), readerOf("archive-b", b)], verifier, { index: 1, downpipeId: DP });
    const counter = await rig.storage.get<number>("runlogCounter");
    okd("J: the counter is past archive-b's 9, not only archive-a's 3", counter === 9, counter);
    const t2 = await trigger(rig, DP_B);
    okd("J: the next trigger allocates index 10", "index" in t2 && t2.index === 10, t2);
    if ("index" in t2) {
      let refused = "none";
      try {
        await runBackup([new FakeSource("after")], cfgFor(DP_B), signer, a, clockAt(t2.runId, t2.index, 7));
        await runBackup([new FakeSource("after")], cfgFor(DP_B), signer, b, clockAt(t2.runId, t2.index, 7));
      } catch (e) {
        refused = e instanceof Error ? e.message : String(e);
      }
      okd("J: index 10 appends to both archives with no second refusal", refused === "none", refused);
      const ia = parseRunlog((await a.get(RUNLOG))!.body).map((e) => e.index);
      const ib = parseRunlog((await b.get(RUNLOG))!.body).map((e) => e.index);
      okd("J: neither RUNLOG repeats an index", new Set(ia).size === ia.length && new Set(ib).size === ib.length, { ia, ib });
    }
    const faults = (await fetchIntegrityFaults(rig.stub)) as Record<string, { runlogAnomalies?: Array<{ kind: string; indexA?: number; indexB?: number; archiveId?: string }> }>;
    const row = faults[DP]?.runlogAnomalies?.find((r) => r.kind === "counter-advanced-after-recovery");
    okd("J: the pack names counter-advanced-after-recovery with from 1, to 9 and archive-b", row?.indexA === 1 && row.indexB === 9 && row.archiveId === "archive-b", faults);
    const after = await trigger(rig, DP);
    okd("J: the hold is released (a later trigger is not refused for it)", !("skipped" in after && /index/.test(after.skipped) && /held/.test(after.skipped)), after);
    const status = (await (await doCall(rig, "GET", "/control-plane/recovery-status")).json()) as { runlogIndexHeld?: unknown };
    okd("J: and the recovery status carries no pending report", status.runlogIndexHeld === null || status.runlogIndexHeld === undefined, status);
  }
  console.log("\nJ2 -- a report whose archives read lower than the refused index still moves the counter past it");
  {
    const rig = makeRig();
    await addDownpipe(rig, DP);
    await doCall(rig, "POST", "/runlog-index-held", { index: 5, downpipeId: DP });
    await reseedAfterIndexHeld(rig.stub, [readerOf("archive-a", await survivingBucket())], verifier, { index: 5, downpipeId: DP });
    const counter = await rig.storage.get<number>("runlogCounter");
    okd("J2: the counter is 5, so the next run is past the refused index", counter === 5, counter);
  }

  console.log("\nJ3 -- the cron pass itself answers a pending report from the archives it can build");
  {
    const d = await survivingBucket(); // the default archive: indices 1..3
    const rig = makeRig();
    await addDownpipe(rig, DP);
    await doCall(rig, "POST", "/runlog-index-held", { index: 1, downpipeId: DP });
    await tick(envFor(rig, d, noFaults()), rig);
    const counter = await rig.storage.get<number>("runlogCounter");
    okd("J3: the pass moved the counter to the default archive's 3", counter === 3, counter);
    const faults = (await fetchIntegrityFaults(rig.stub)) as Record<string, { runlogAnomalies?: Array<{ kind: string; indexA?: number; indexB?: number; archiveId?: string }> }>;
    const row = faults[DP]?.runlogAnomalies?.find((r) => r.kind === "counter-advanced-after-recovery");
    okd("J3: the pack row names from 0, to 3 and the default archive", row?.indexA === 0 && row.indexB === 3 && row.archiveId === "default", faults);
  }

  // ---- L: a failed advance is visible in the pack -------------------------------------------------------------
  // The scheduler DO drains this isolate's ledger into its storage when a fetch ends, so one read here can miss a
  // row the same read just caused. The first read drains, the second reads what was stored (the pack build drains first).
  const siteRow = async (rig: Rig, id: string) => {
    await fetchSiteFaults(rig.stub);
    return (await fetchSiteFaults(rig.stub)).find((r) => (r.id as string) === id);
  };
  const failingOn = (rig: Rig, path: string): DurableObjectStub =>
    ({
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes(path)) return Promise.reject(new Error("planted scheduler fault"));
        return rig.stub.fetch(input, init);
      },
    }) as unknown as DurableObjectStub;
  console.log("\nL -- a failed advance, an unlistable archive set, an unreadable archive and a bad signer reach the pack");
  {
    const d = await survivingBucket();
    const rig = makeRig();
    await addDownpipe(rig, DP);
    await doCall(rig, "POST", "/runlog-index-held", { index: 1, downpipeId: DP });
    const before = await siteRow(rig, "runlog.advance-failed");
    await advanceAfterIndexHeld(envFor(rig, d, noFaults()), failingOn(rig, "/control-plane/runlog-advance"), { index: 1, downpipeId: DP });
    const after = await siteRow(rig, "runlog.advance-failed");
    okd("L: a failed advance counts one runlog.advance-failed row in the pack", (after?.count ?? 0) === (before?.count ?? 0) + 1, after);
    okd("L: the report still stands, so the hold stays and the next pass tries again", (await rig.storage.get<number>("runlogCounter")) === undefined && "skipped" in (await trigger(rig, DP)));
    const okBefore = (await siteRow(rig, "runlog.advance-failed"))?.count ?? 0;
    await advanceAfterIndexHeld(envFor(rig, d, noFaults()), rig.stub, { index: 1, downpipeId: DP });
    okd("L: control, a clean advance counts nothing and moves the counter to 3", ((await siteRow(rig, "runlog.advance-failed"))?.count ?? 0) === okBefore && (await rig.storage.get<number>("runlogCounter")) === 3);

    const list0 = (await siteRow(rig, "runlog.advance-archive-list"))?.count ?? 0;
    await doCall(rig, "POST", "/runlog-index-held", { index: 1, downpipeId: DP });
    await advanceAfterIndexHeld(envFor(rig, d, noFaults()), failingOn(rig, "/control-plane/export"), { index: 1, downpipeId: DP });
    okd("L: an archive list that cannot be read counts a runlog.advance-archive-list row", ((await siteRow(rig, "runlog.advance-archive-list"))?.count ?? 0) === list0 + 1);

    const f = noFaults();
    f.throwOnGet.add(RUNLOG);
    const read0 = (await siteRow(rig, "runlog.advance-archive-read"))?.count ?? 0;
    await doCall(rig, "POST", "/runlog-index-held", { index: 1, downpipeId: DP });
    await reseedAfterIndexHeld(rig.stub, [{ id: "archive-x", get: async () => { throw new Error("503"); } }], verifier, { index: 1, downpipeId: DP });
    okd("L: an archive that cannot be read counts a runlog.advance-archive-read row", ((await siteRow(rig, "runlog.advance-archive-read"))?.count ?? 0) === read0 + 1);

    const sig0 = (await siteRow(rig, "runlog.advance-signer"))?.count ?? 0;
    const none = await pinnedVerifier({} as Env);
    okd("L: control, no signer at all is not a fault (null, nothing counted)", none === null && ((await siteRow(rig, "runlog.advance-signer"))?.count ?? 0) === sig0);
    const bad = await pinnedVerifier({ SIGNER_PRIVATE: "not-a-key" } as unknown as Env);
    okd("L: an unusable signer counts a runlog.advance-signer row", bad === null && ((await siteRow(rig, "runlog.advance-signer"))?.count ?? 0) === sig0 + 1);
  }

  // ---- M: the refused run reads as an integrity refusal naming index-held --------------------------------------
  console.log("\nM -- the refused run is an integrity refusal naming index-held, in the console's run record and the pack");
  {
    const d = await survivingBucket();
    const rig = makeRig();
    await addDownpipe(rig, DP);
    const t = await trigger(rig, DP);
    let message = "";
    if ("index" in t) {
      try {
        await runBackup([new FakeSource("refused")], cfgFor(DP), signer, d, clockAt(t.runId, t.index, 6), runlogLockVia(rig.stub));
      } catch (e) {
        message = e instanceof Error ? e.message : String(e);
      }
    }
    const coarse = coarseRunError(message);
    okd("M: the coarse class names an integrity refusal and index-held", /^runlog integrity refused/.test(coarse) && /index-held/.test(coarse), coarse);
    okd("M: and differs from the generic integrity class an Owner review follows", coarse !== coarseRunError("RUNLOG integrity: the RUNLOG has no signature; the engine will not modify or re-sign it"));
    if ("index" in t) {
      await doCall(rig, "POST", "/complete", { id: DP, runId: t.runId, index: t.index, status: "failed", error: coarse });
      const hist = (await (await doCall(rig, "GET", `/history?id=${DP}`)).json()) as { entries?: Array<{ status: string; error?: string }> };
      const row = hist.entries?.find((e) => e.status === "failed");
      okd("M: the run record the console reads carries that error", row?.error === coarse, hist);
      const pack = (await fetchRunHistory(rig.stub)) as Record<string, Array<{ status: string; error?: string }>>;
      okd("M: the pack's run row carries it too", pack[DP]?.find((r) => r.status === "failed")?.error === coarse, pack);
    }
  }

  // ---- N: after a recovery, one refused run, then success -----------------------------------------------------
  console.log("\nN -- after a recovery with an unsigned default RUNLOG: one refused run, then the next two passes succeed");
  {
    const d = await survivingBucket(); // indices 1..3, signature removed below; the pending signature stays
    await d.delete(RUNLOG_SIG);
    const rig = makeRig();
    const env = envFor(rig, d, noFaults());
    await addDownpipe(rig, DP);
    await addDownpipe(rig, DP_B);
    await tick(env, rig); // pass 0: the recovery latch reads sig-absent and seeds nothing
    const lock = runlogLockVia(rig.stub);
    let refused = 0;
    let succeeded = 0;
    const attempt = async (dp: string, day: number): Promise<string> => {
      const t = await trigger(rig, dp);
      if (!("index" in t)) return `skipped: ${t.skipped}`;
      try {
        await runBackup([new FakeSource(`n${t.index}`)], cfgFor(dp), signer, d, clockAt(t.runId, t.index, day), lock);
        await doCall(rig, "POST", "/complete", { id: dp, runId: t.runId, index: t.index, status: "ok" });
        succeeded++;
        return `ok ${t.index}`;
      } catch (e) {
        refused++;
        await doCall(rig, "POST", "/complete", { id: dp, runId: t.runId, index: t.index, status: "failed", error: coarseRunError(e instanceof Error ? e.message : String(e)) });
        return `refused ${t.index}`;
      }
    };
    const r1 = await attempt(DP, 4);
    okd("N: the first run after the recovery is refused for its index", r1 === "refused 1", r1);
    const held = await attempt(DP_B, 4);
    okd("N: a trigger before the next pass is held, not run", /^skipped: .*held/.test(held), held);
    await tick(env, rig); // pass 1
    const r2 = await attempt(DP, 5);
    okd("N: after pass 1 the next run succeeds past the document", r2 === "ok 4", r2);
    await tick(env, rig); // pass 2
    const r3 = await attempt(DP_B, 6);
    okd("N: after pass 2 the next run succeeds", r3 === "ok 5", r3);
    okd("N: exactly one run was refused, and two succeeded", refused === 1 && succeeded === 2, { refused, succeeded });
    const idx = parseRunlog((await d.get(RUNLOG))!.body).map((e) => e.index);
    okd("N: the RUNLOG holds each index once", new Set(idx).size === idx.length, idx);
  }

  console.log("\nK -- a sig-absent default archive seeds from the other archives");
  {
    const a = await survivingBucket(); // default archive: 1..3, signature removed below
    const b = await bucketTo(9, DP_B);
    await a.delete(RUNLOG_SIG);
    const readers = [readerOf("archive-b", b)];
    const primary = { noSeed: "sig-absent" } as const;
    const got = await seedAcrossArchives(primary, readers, verifier);
    okd("K: sig-absent default plus archive-b at 9 gives seed 9", "seed" in got && got.seed === 9, got);
    const higher = await seedAcrossArchives({ seed: 12 }, readers, verifier);
    okd("K: a default seed above every other archive stays 12", "seed" in higher && higher.seed === 12, higher);
    const lower = await seedAcrossArchives({ seed: 3 }, readers, verifier);
    okd("K: a default seed below archive-b's 9 rises to 9", "seed" in lower && lower.seed === 9, lower);
    const held = await seedAcrossArchives({ noSeed: "unreadable" }, readers, verifier);
    okd("K: an unreadable default stays unreadable, so allocation still holds", "noSeed" in held && held.noSeed === "unreadable", held);
    const bad = await seedAcrossArchives(primary, [{ id: "archive-x", get: async () => { throw new Error("503"); } }], verifier);
    okd("K: an unreadable other archive does not invent a seed", "noSeed" in bad, bad);
    const rig = makeRig();
    await addDownpipe(rig, DP);
    const post = await doCall(rig, "POST", "/control-plane/runlog-seed", { runlogSeed: got });
    okd("K: the DO takes the seed", post.ok, post.status);
    const t = await trigger(rig, DP);
    okd("K: the first trigger allocates index 10", "index" in t && t.index === 10, t);
    if ("index" in t) {
      let refused = "none";
      try {
        await runBackup([new FakeSource("first")], cfgFor(DP), signer, b, clockAt(t.runId, t.index, 8));
      } catch (e) {
        refused = e instanceof Error ? e.message : String(e);
      }
      okd("K: the first run succeeds with no refusal", refused === "none", refused);
    }
  }

  // ---- H: a fresh bucket keeps working ----------------------------------------------------------------------
  console.log("\nH -- a bucket with no RUNLOG is a new account: no latch, no seed, index 1");
  {
    const d = new MemoryDestination();
    const rig = makeRig();
    await tick(envFor(rig, d, noFaults()), rig);
    const status = (await (await doCall(rig, "GET", "/control-plane/recovery-status")).json()) as { recoveryRequired?: boolean; amnesiaProbe?: { probe?: string }; runlogSeed?: unknown };
    okd("H: no latch, and the probe says runlog-absent", status.recoveryRequired === false && status.amnesiaProbe?.probe === "runlog-absent", status);
    okd("H: no seed record, so the pack carries no runlogSeed", status.runlogSeed === null && (await packSeed(rig)) === undefined);
    await addDownpipe(rig, DP);
    const t = await trigger(rig, DP);
    okd("H: the first trigger allocates index 1", "index" in t && t.index === 1, t);
  }

  // ---- I: the seed route takes only the closed shape --------------------------------------------------------
  console.log("\nI -- the DO seed route refuses anything outside the closed shape");
  {
    const rig = makeRig();
    for (const bad of [undefined, 3, { seed: -1 }, { seed: 1.5 }, { noSeed: "because" }, { seed: 3, noSeed: "absent" }]) {
      const r = await doCall(rig, "POST", "/control-plane/runlog-seed", { runlogSeed: bad });
      okd(`I: ${JSON.stringify(bad)} is refused with 400 and records nothing`, r.status === 400 && (await rig.storage.get("controlPlaneRunlogSeed")) === undefined);
    }
    const good = await doCall(rig, "POST", "/control-plane/runlog-seed", { runlogSeed: { seed: 7 } });
    okd("I: positive control: a seed is accepted and raises the counter", good.status === 200 && (await rig.storage.get<number>("runlogCounter")) === 7);
    await doCall(rig, "POST", "/control-plane/runlog-seed", { runlogSeed: { noSeed: "unreadable" } });
    okd("I: a later no-seed outcome never replaces an established seed", (await packSeed(rig))?.seed === 7);
  }

}

async function main(): Promise<void> {
  const recipients = [makeRecipient("break-glass"), makeRecipient("operational")];
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };
  const cfg: RunConfig = { downpipeId: DP, downpipeName: "recovered", cadence: "3600s", selector: { include: [], exclude: [] }, recipients };
  const clockBase = { randomNonce: () => rand(16), randomSalt: () => rand(16) };

  // The customer's surviving bucket: three ordinary pre-loss runs, exactly as the fork validator builds it.
  const original = new MemoryDestination();
  await runBackup([new FakeSource("one")], cfg, signer, original, { ...clockBase, runId: A1, runlogIndex: 1, prevRunId: null, now: "2026-08-01T00:00:00.000Z", master: rand(32) } as RunClock);
  await runBackup([new FakeSource("two")], cfg, signer, original, { ...clockBase, runId: A2, runlogIndex: 2, prevRunId: A1, now: "2026-08-02T00:00:00.000Z", master: rand(32) } as RunClock);
  await runBackup([new FakeSource("three")], cfg, signer, original, { ...clockBase, runId: A3, runlogIndex: 3, prevRunId: A2, now: "2026-08-03T00:00:00.000Z", master: rand(32) } as RunClock);

  // ---- CELL A: readVerifiedRunlogSeed in isolation, with negative controls. ----------------------
  {
    const getObject = (key: string): Promise<Uint8Array | null> => original.get(key).then((r) => r?.body ?? null);
    const seed = await readVerifiedRunlogSeed(getObject, verifier);
    ok("A: the verified reader returns the document's true high-water mark (3)", "seed" in seed && seed.seed === 3);

    const wrongVerifier = { ed: new Uint8Array(edPublic.length), mldsa: mldsa.publicKey };
    const underWrongKey = await readVerifiedRunlogSeed(getObject, wrongVerifier);
    ok("A: a verifier that does not match the signer yields NO seed (sig-invalid, never 0)", "noSeed" in underWrongKey && underWrongKey.noSeed === "sig-invalid");

    const emptyBucket = new MemoryDestination();
    const overEmpty = await readVerifiedRunlogSeed((k) => emptyBucket.get(k).then((r) => r?.body ?? null), verifier);
    ok("A: an absent RUNLOG yields NO seed (absent)", "noSeed" in overEmpty && overEmpty.noSeed === "absent");

    const tampered = new MemoryDestination();
    for (const [k, v] of [["_RECOVERY/RUNLOG", await original.get("_RECOVERY/RUNLOG")], ["_RECOVERY/RUNLOG.sig", await original.get("_RECOVERY/RUNLOG.sig")]] as const) {
      if (v) await tampered.put(k, v.body);
    }
    const runlogRaw = await tampered.get("_RECOVERY/RUNLOG");
    if (runlogRaw) {
      const mutated = new Uint8Array(runlogRaw.body);
      mutated[0] = (mutated[0] ?? 0) ^ 0xff;
      await tampered.put("_RECOVERY/RUNLOG", mutated);
    }
    const overTampered = await readVerifiedRunlogSeed((k) => tampered.get(k).then((r) => r?.body ?? null), verifier);
    ok("A: a tampered document (signature no longer verifies) yields NO seed (sig-invalid)", "noSeed" in overTampered && overTampered.noSeed === "sig-invalid");
  }

  // ---- CELL B: the real recovery path, through the routed SchedulerDO HTTP surface. ----------------
  {
    // B1: a latch that carries no seed outcome at all leaves the counter alone and holds nothing. The
    // outcomes the health pass does carry, and which of them hold allocation, are graded by
    // validate-recovery-seed-outcome.ts through the real health pass.
    const { stub: unseeded } = makeScheduler();
    await stubFetch(unseeded, "POST", "/downpipes", makeConfig("dp-unseeded"));
    await stubFetch(unseeded, "POST", "/control-plane/recovery-required", { reason: "amnesia, no seed established" });
    const t0 = (await (await stubFetch(unseeded, "POST", "/trigger", { id: "dp-unseeded" })).json()) as { index: number };
    ok("B1: with no seed outcome, the recovered DO allocates index 1", t0.index === 1);

    // B2: SEEDED with the reader's own verified answer from Cell A (3), carried exactly as
    // runControlPlaneHealthPass now carries it in the POST body.
    const { stub: seeded } = makeScheduler();
    await stubFetch(seeded, "POST", "/downpipes", makeConfig(DP));
    const getObject = (key: string): Promise<Uint8Array | null> => original.get(key).then((r) => r?.body ?? null);
    const runlogSeed = await readVerifiedRunlogSeed(getObject, verifier);
    ok("B2: precondition -- the seed computed from the bucket is 3", "seed" in runlogSeed && runlogSeed.seed === 3);
    await stubFetch(seeded, "POST", "/control-plane/recovery-required", { reason: "amnesia, seed established", runlogSeed });
    const t1 = (await (await stubFetch(seeded, "POST", "/trigger", { id: DP })).json()) as { index: number };
    ok("B2: a recovered DO seeded from the verified RUNLOG allocates index 4, NOT 1", t1.index === 4);

    // B3: idempotence / monotonicity -- a second recovery-required call with a LOWER seed never regresses
    // an already-anchored counter (setControlPlaneRecoveryRequired's monotonic-max write). A SECOND
    // downpipe is used because the runlogCounter is account-global, not per-downpipe, and the first is
    // still in flight (trigger() coalesces a repeat call on the same downpipe rather than allocating).
    await stubFetch(seeded, "POST", "/downpipes", makeConfig("dp-seeded-second"));
    await stubFetch(seeded, "POST", "/control-plane/recovery-required", { reason: "re-latched", runlogSeed: { seed: 1 } });
    const t2 = (await (await stubFetch(seeded, "POST", "/trigger", { id: "dp-seeded-second" })).json()) as { index: number };
    ok("B3: a later, LOWER seed does not regress the counter (still past 4)", t2.index === 5);
  }

  // ---- CELL C: close the loop against the real writer -- the seeded index actually seals cleanly. ------
  {
    const dest = await cloneDest(original);
    await runBackup([new FakeSource("post-recovery-seeded")], cfg, signer, dest, { ...clockBase, runId: B_SEEDED, runlogIndex: 4, prevRunId: A3, now: "2026-08-04T00:00:00.000Z", master: rand(32) } as RunClock);
    const log = await dest.get("_RECOVERY/RUNLOG");
    const entries = log ? parseRunlog(log.body) : [];
    ok("C: four entries, four distinct indices -- no fork", entries.length === 4 && new Set(entries.map((e) => e.index)).size === 4);

    const attNew = await attestKeyless(storeOf(dest), B_SEEDED, verifier, { allowStale: false });
    ok("C: the post-recovery run attests CLEAN", attNew.signatureValid === true && attNew.complete === true && attNew.notRolledBack === true);
    ok("C: and carries no reason", attNew.reason === undefined || attNew.reason === null || attNew.reason === "");

    // A3 stops being the LATEST run for its downpipe once B_SEEDED exists (index 4), and attestKeyless's
    // notRolledBack REQUIRES latest-ness unconditionally (keyless.ts: `freshness.ok &&
    // freshness.isLatestForDownpipe && !freshness.rollbackDetected`) -- so A3 legitimately refuses under
    // BOTH allowStale settings, and that is correct, ordinary product behaviour present on every multi-run
    // downpipe, fork or no fork. A3 must never instead refuse under a SEPARATE, unconditional,
    // allowStale-proof refusal class (a chain anomaly: "log corrupted or rewritten" / "prevRunId disagrees
    // with the signed root") driven by a false rollbackDetected, which allowStale can never clear. A
    // non-latest run must never become attestable, and the anomaly must never fire here, so the ONLY
    // reason A3 refuses is the ordinary one, under either allowStale setting.
    const attOldStrict = await attestKeyless(storeOf(dest), A3, verifier, { allowStale: false });
    ok(
      "C: A3 refuses under allowStale:false for ORDINARY staleness, not a chain anomaly",
      attOldStrict.notRolledBack === false && attOldStrict.signatureValid === true && attOldStrict.reason !== "runlog index 3 appears twice (log corrupted or rewritten)" && !/prevRunId disagrees with the signed root/.test(attOldStrict.reason ?? ""),
    );
    const attOldStale = await attestKeyless(storeOf(dest), A3, verifier, { allowStale: true });
    ok(
      "C: A3 refuses under allowStale:true too (still not latest), but STILL never the fork's chain-anomaly reason",
      attOldStale.notRolledBack === false && attOldStale.signatureValid === true && attOldStale.reason !== "runlog index 3 appears twice (log corrupted or rewritten)" && !/prevRunId disagrees with the signed root/.test(attOldStale.reason ?? ""),
    );
  }

  await seedOutcomeCells();

  console.log(failures === 0 ? "\nPASS: the recovery-path seed anchors the counter, each read outcome is recorded, and a fork does not occur where a retry can prevent it." : `\nFAIL: ${failures} assertion(s)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

await main();
