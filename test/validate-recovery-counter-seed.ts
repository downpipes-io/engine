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
  return ((await fetchRecoveryStatus(rig.stub)) as { runlogSeed?: PackSeed }).runlogSeed;
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
//   G. sig-absent does not hold (no retry clears it): the first run re-uses index 1, and the pack says so; the
//      next tick's re-read seeds past the document, so the next run gets index 4.
//   H. A fresh bucket with no RUNLOG keeps working: no latch, no seed record, index 1.
//   I. The DO's seed route refuses an outcome outside the closed shape.
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

  // ---- G: sig-absent does not hold; the re-read limits the collision to the indices already allocated -------
  console.log("\nG -- a missing signature does not hold, and the pack says what happened");
  {
    const d = await survivingBucket();
    await d.delete(RUNLOG_SIG);
    const rig = makeRig();
    const env = envFor(rig, d, noFaults());
    await tick(env, rig);
    await addDownpipe(rig, DP);
    await addDownpipe(rig, DP_B);
    const t1 = await trigger(rig, DP);
    okd("G: the first trigger is not held, and re-uses index 1 (the documented residual)", "index" in t1 && t1.index === 1, t1);
    if ("index" in t1) {
      await runBackup([new FakeSource("post")], cfgFor(DP), signer, d, clockAt(t1.runId, t1.index, 5));
      await doCall(rig, "POST", "/complete", { id: DP, runId: t1.runId, index: t1.index, status: "ok" });
    }
    const idx = parseRunlog((await d.get(RUNLOG))!.body).map((e) => e.index);
    okd("G: the writer appended a repeated index 1 and re-signed", idx.filter((i) => i === 1).length === 2, idx);
    const before = await packSeed(rig);
    okd("G: the pack names sig-absent with no hold", before?.noSeed === "sig-absent" && before.allocationHeld === false, before);
    await tick(env, rig);
    const after = await packSeed(rig);
    okd("G: the next tick reads the re-signed RUNLOG and seeds 3", after?.seed === 3 && after.firstNoSeed === "sig-absent", after);
    okd("G: and records that 1 index was allocated before the seed", after?.allocatedBeforeSeed === 1, after);
    const t2 = await trigger(rig, DP_B);
    okd("G: the next trigger allocates index 4, past the document", "index" in t2 && t2.index === 4, t2);
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
