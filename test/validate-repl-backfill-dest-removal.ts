// validate-repl-backfill-dest-removal: a destination added to a downpipe receives the older runs, within a
// stated number of ticks, and the old destination can then be removed WITHOUT force.
//
// THE DEFECT (customer-path check on the released engine, two downpipes, six sealed runs on destination A,
// destination B added to both). Removing A was refused "in use ... Reassign them first". With both
// destinations on the downpipes for 48 minutes (three cron ticks), B received the run-tree of ONE run and no
// RUNLOG entry, so B's proven copy count stayed at none (holdsIndex -1) and the second downpipe was never
// reached. After the operator took A off the downpipes, the orphan guard asked for a second destination, the
// state the operator had just left. Only force ended it, and runs 1 to 6 became unrestorable.
//
// THE CAUSE. runReplications ran on the cron tick's shared SliceBudget, whose 20-second wall clock starts
// before the seal loop. Six passes run before replication, each with its own scheduler round trips (about
// 200 ms each on the live account, whose 08:15 tick ran about two minutes). Replication started with the
// wall allowance spent: it returned "budget-exhausted", or it got as far as one segment and a run-tree copy
// (the run-tree copy has no yield check) with no done-marker, and it did the same at every tick.
//
// THE FIX, and what this file proves against the real code path (the real SchedulerDO over in-memory
// storage as the scheduler, real sealed archives with real signatures, and a stateful S3 wire for both
// buckets, with a clock that charges 150 ms for each destination request):
//   1. Replication runs on SliceBudget.passWindow(): the tick's subrequest tally, its own wall window. With
//      the tick's wall allowance already spent before the pass, all 6 runs are on B after TICKS_BOUND ticks.
//   2. Then A comes off the downpipes and removing A succeeds without force.
//   3. While the backfill runs, the in-use refusal says to keep A on the downpipes, with a count that falls.
//   4. The loop is closed: with A already taken off, the orphan refusal names the step that makes
//      replication run (this destination and one other) and what force costs.
//   5. A seal completion no longer raises holdsIndex across a gap, so a part-way backfill followed by a run
//      on B cannot make the guard allow removing A while runs are only on A.
//   6. Runs outside the history ring are never copied: the refusal and the removal notice state the count.
//   4c. A run whose origin is removed is copied from another destination of its downpipe that holds it.
//      A run that no destination can source no longer holds its downpipe's newer runs in the count: the
//      pass records the runs a destination holds above its window (holdsAbove).
//   4d. With three destinations, the one that replaced a removed origin receives the runs from the one
//      that still holds them.
//
// Sections 1, 2 and 5 FAIL on the code before this fix; sections 3, 4 and 6 fail on its refusal texts.
// Run: node test/validate-repl-backfill-dest-removal.ts

import { x25519 } from "@noble/curves/ed25519.js";
import type { AuthMethod } from "../src/admin/identity.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { classifyDestProbeRefusal } from "../src/sched/sched-fault-ledger.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DestReplState } from "../src/sched/scheduler-do-base.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { runReplications } from "../src/seal/replicate.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The stated bound: with the tick's wall allowance spent before the pass, and 150 ms per destination
// request, the replication pass has copied all six runs to B after this many cron ticks (30 minutes).
const TICKS_BOUND = 2;
const LATENCY_MS = 150;
// The wall time the passes before replication took on the live tick (08:15 ran about two minutes); any
// value past the 20-second allowance puts the pass in the state the live account was in.
const PRIOR_PASSES_MS = 25_000;

// ---- the clock: real time plus the latency each destination request is charged -----------------------
const realNow = Date.now.bind(Date);
let skew = 0;
Date.now = () => realNow() + skew;

// ---- a stateful path-style S3 wire for every bucket on one endpoint ------------------------------------
const ENDPOINT = "https://s3.example.test";
class S3Wire {
  buckets = new Map<string, Map<string, { bytes: Uint8Array; etag: string }>>();
  requests = 0;
  private seq = 0;
  private realFetch = globalThis.fetch;
  install(): void {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.origin !== ENDPOINT) return this.realFetch(input as RequestInfo, init);
      this.requests++;
      skew += LATENCY_MS;
      return this.handle(u, init ?? {});
    }) as typeof fetch;
  }
  uninstall(): void {
    globalThis.fetch = this.realFetch;
  }
  bucket(name: string): Map<string, { bytes: Uint8Array; etag: string }> {
    let b = this.buckets.get(name);
    if (!b) {
      b = new Map();
      this.buckets.set(name, b);
    }
    return b;
  }
  private async handle(u: URL, init: RequestInit): Promise<Response> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    const parts = u.pathname.split("/");
    const store = this.bucket(parts[1] ?? "");
    const path = parts.slice(2).map(decodeURIComponent).join("/");
    if (method === "GET" && u.searchParams.get("list-type") === "2") {
      const prefix = u.searchParams.get("prefix") ?? "";
      const keys = [...store.keys()].filter((k) => k.startsWith(prefix)).sort();
      const xml = `<ListBucketResult>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("")}<IsTruncated>false</IsTruncated></ListBucketResult>`;
      return new Response(xml, { status: 200 });
    }
    if (method === "PUT") {
      const existing = store.get(path);
      if (headers.get("if-none-match") === "*" && existing) return new Response("", { status: 412 });
      const im = headers.get("if-match");
      if (im !== null && (!existing || existing.etag !== im)) return new Response("", { status: 412 });
      const body = new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer());
      const etag = `"s3-${++this.seq}"`;
      store.set(path, { bytes: body, etag });
      return new Response("", { status: 200, headers: { etag } });
    }
    if (method === "GET" || method === "HEAD") {
      const r = store.get(path);
      if (!r) return new Response(method === "HEAD" ? null : "<Error><Code>NoSuchKey</Code></Error>", { status: 404 });
      return new Response(method === "HEAD" ? null : r.bytes.slice(), { status: 200, headers: { etag: r.etag, "content-length": String(r.bytes.length) } });
    }
    if (method === "DELETE") {
      store.delete(path);
      return new Response(null, { status: 204 });
    }
    return new Response("", { status: 400 });
  }
}

// ---- the estate: destinations A (default) and B, downpipes d1 and r2 ------------------------------------
type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[] };
const OWNER: Caller = { method: "token", email: null, subject: null, groups: [] };
const A = "dest-a";
const B = "dest-b";
const C = "dest-c";
const BUCKET: Record<string, string> = { [A]: "archive", [B]: "archive2", [C]: "archive3" };
const D1 = "dp-d1";
const R2 = "dp-r2";
const NAME: Record<string, string> = { [D1]: "src-d1", [R2]: "src-r2" };

function storedDest(id: string): Record<string, unknown> {
  return { id, label: id, endpoint: ENDPOINT, bucket: BUCKET[id], region: "auto", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "not-a-real-secret", addressing: "path", setAt: 1, setBy: "owner@acme.example", verifiedAt: 1, deleteProbe: "ok" };
}
function downpipe(id: string, destinationIds: string[], lastRunId: string, sealedRuns: number): Record<string, unknown> {
  return { config: { id, name: NAME[id], cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds }, nextRunAt: Date.now() + 86_400_000, lastRunId, inFlight: false, sealedRuns };
}
function runId(i: number): string {
  return `01K5ZZKBKACTAV9WEVGEMMVR${String(i).padStart(2, "0")}`;
}

interface Estate {
  dobj: SchedulerDO;
  storage: MockStorage;
  scheduler: DurableObjectStub;
  env: Env;
  wire: S3Wire;
  signer: Signer;
}

// makeEstate seals runs 1..6 to A (d1 takes the odd indices, r2 the even, as on the live account), writes
// the matching history rings, and seeds the DO. `destinationIds` is what both downpipes are configured with.
async function makeEstate(wire: S3Wire, destinationIds: string[], opts: { sealedRuns?: number } = {}): Promise<Estate> {
  const signerPrivateB64 = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));
  const signer = await loadSigner(signerPrivateB64);
  const recipients: RecipientEntry[] = ["break-glass", "operational"].map((role) => ({ role, pub: { x25519: x25519.keygen().publicKey, mlkemEk: mlkemKeygen(crypto.getRandomValues(new Uint8Array(64))).encapKey } }));
  wire.buckets.clear();
  const a = new S3Destination(ENDPOINT, BUCKET[A]!, "auto", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
  const hist: Record<string, Array<Record<string, unknown>>> = { [D1]: [], [R2]: [] };
  const prev: Record<string, string | null> = { [D1]: null, [R2]: null };
  for (let i = 1; i <= 6; i++) {
    const dp = i % 2 === 1 ? D1 : R2;
    const id = runId(i);
    const archive = await buildArchive({
      downpipeId: dp, downpipeName: NAME[dp]!, cadence: "86400s", runId: id, master: crypto.getRandomValues(new Uint8Array(32)), recipients, signer,
      records: Array.from({ length: 7 }, (_, r) => ({ sourceType: "kv" as const, name: `rec-${r}`, namespace: "ns", value: utf8(`value-${i}-${r}-${"x".repeat(200)}`) })),
      windowStart: "2026-09-27T08:00:00.000Z", windowEnd: "2026-09-27T08:00:01.000Z", createdAt: "2026-09-27T08:00:01.000Z",
      runlogIndex: i, prevRunId: prev[dp]!, skipRunlog: true, randomNonce: () => crypto.getRandomValues(new Uint8Array(16)), randomSalt: () => crypto.getRandomValues(new Uint8Array(16)),
    });
    for (const [k, v] of archive) await a.put(k, v);
    const entry: RunlogEntry = { index: i, runId: id, downpipeId: dp, time: `2026-09-27T08:0${i}:00.000Z`, recordCount: 7, prevRunId: prev[dp]!, status: "active" };
    await appendRunlog(a, signer, entry, undefined, { relinkLocalPrev: true });
    hist[dp]!.push({ runId: id, index: i, startedAt: entry.time, status: "ok", destinationId: A, prevRunId: prev[dp] });
    prev[dp] = id;
  }
  const storage = new MockStorage();
  storage.seed("destinations", { list: [storedDest(A), storedDest(B)], defaultId: A });
  storage.seed(`dp:${D1}`, downpipe(D1, destinationIds, prev[D1]!, opts.sealedRuns ?? 3));
  storage.seed(`dp:${R2}`, downpipe(R2, destinationIds, prev[R2]!, opts.sealedRuns ?? 3));
  storage.seed(`hist:${D1}`, hist[D1]);
  storage.seed(`hist:${R2}`, hist[R2]);
  // A's own proof, as the seal completions recorded it.
  storage.seed(`repl:${D1}`, { [A]: { holdsRunId: runId(5), holdsIndex: 5, lastOk: true, lastAttemptAt: 1 } });
  storage.seed(`repl:${R2}`, { [A]: { holdsRunId: runId(6), holdsIndex: 6, lastOk: true, lastAttemptAt: 1 } });
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  const env = { SIGNER_PRIVATE: signerPrivateB64 } as unknown as Env;
  return { dobj, storage, scheduler, env, wire, signer };
}

// tick runs the replication pass the way drive() does at a tick whose earlier passes used the whole wall
// allowance: the tick budget is built, the overhead lump is spent, and PRIOR_PASSES_MS go by first.
async function tick(e: Estate): Promise<void> {
  const tickBudget = new SliceBudget();
  tickBudget.spend(30); // DRIVE_OVERHEAD_SUBREQUESTS
  skew += PRIOR_PASSES_MS;
  await runReplications(e.env, e.scheduler, tickBudget);
}

function runlogIndexes(e: Estate, dest: string): number[] {
  const rl = e.wire.bucket(BUCKET[dest]!).get("_RECOVERY/RUNLOG");
  return rl ? parseRunlog(rl.bytes).map((x) => x.index).sort((p, q) => p - q) : [];
}

async function repl(e: Estate, dp: string): Promise<Record<string, DestReplState>> {
  return ((await e.storage.get<Record<string, DestReplState>>(`repl:${dp}`)) ?? {}) as Record<string, DestReplState>;
}

async function reassign(e: Estate, destinationIds: string[]): Promise<void> {
  for (const dp of [D1, R2]) {
    const st = (await e.storage.get<Record<string, unknown>>(`dp:${dp}`)) as { config: Record<string, unknown> };
    st.config.destinationIds = destinationIds;
    await e.storage.put(`dp:${dp}`, st);
  }
}

async function caught(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (err) {
    return err as Error;
  }
}

const sentences: Record<string, string> = {};

async function main(): Promise<void> {
  const wire = new S3Wire();
  wire.install();
  try {
    // ==========================================================================================
    // 0. NEGATIVE CONTROL: the harness can see a pass that copies nothing.
    // ==========================================================================================
    console.log("-- 0. control: a tick with no subrequests left copies nothing, and the harness sees that --");
    {
      const e = await makeEstate(wire, [A, B]);
      const spent = new SliceBudget();
      spent.spend(spent.subrequestBudget);
      skew += PRIOR_PASSES_MS;
      await runReplications(e.env, e.scheduler, spent);
      ok("with the subrequest tally spent, B's RUNLOG holds no run", runlogIndexes(e, B).length === 0);
      ok("and the removal of A is still refused", (await caught(() => e.dobj.removeDest(A, false, OWNER))) !== null);
    }

    // ==========================================================================================
    // 1-3. THE CUSTOMER PATH: both destinations ticked, wait, take A off, remove A without force.
    // ==========================================================================================
    console.log(`-- 1. backfill: 6 runs on A, B added to both downpipes, the tick's wall spent before the pass --`);
    {
      const e = await makeEstate(wire, [A, B]);
      const before = await caught(() => e.dobj.removeDest(A, false, OWNER));
      sentences.inUseBeforeBackfill = before?.message ?? "";
      ok("3. before any tick: the in-use refusal says to keep A on, and counts 6 runs held only on A", before !== null && /in use by 2 downpipe\(s\)/.test(before.message) && /Keep it on them for now: it holds 6 backed-up run\(s\) that no other destination holds yet/.test(before.message));
      ok("3. it names the wait and the step after it, and never the orphan guard's phrase", before !== null && /at each 15-minute tick, oldest first within each downpipe\. This can take hours\./.test(before.message) && /take this destination off those downpipes and remove it/.test(before.message) && !/only proven copy/i.test(before.message));
      ok("3. the refusal classifies as in-use, not orphan-guard", classifyDestProbeRefusal(before) === "in-use");

      await tick(e);
      const afterOne = runlogIndexes(e, B);
      const mid = await caught(() => e.dobj.removeDest(A, false, OWNER));
      const midCount = Number(/it holds (\d+) backed-up run/.exec(mid?.message ?? "")?.[1] ?? "-1");
      ok(`1. after tick 1 B holds a run proven in its RUNLOG (holds [${afterOne}])`, afterOne.length > 0);
      ok(`3. the in-use count falls as replication copies (6 -> ${midCount})`, midCount >= 0 && midCount < 6 && midCount === 6 - afterOne.length);
      for (let t = 2; t <= TICKS_BOUND; t++) await tick(e);
      const onB = runlogIndexes(e, B);
      ok(`1. after ${TICKS_BOUND} ticks all 6 runs are in B's RUNLOG (holds [${onB}])`, JSON.stringify(onB) === JSON.stringify([1, 2, 3, 4, 5, 6]));
      const rd1 = (await repl(e, D1))[B];
      const rr2 = (await repl(e, R2))[B];
      ok("1. B's proven window covers d1's runs [1, 5]", rd1 !== undefined && rd1.holdsFrom === 1 && rd1.holdsIndex === 5);
      ok("1. B's proven window covers r2's runs [2, 6]", rr2 !== undefined && rr2.holdsFrom === 2 && rr2.holdsIndex === 6);
      const inUse = await caught(() => e.dobj.removeDest(A, false, OWNER));
      sentences.inUseAfterBackfill = inUse?.message ?? "";
      ok("3. with the backfill done the in-use refusal is the plain one", inUse !== null && inUse.message === "destination is in use by 2 downpipe(s): src-d1, src-r2. Reassign them first.");

      await reassign(e, [B]);
      const removed = await caught(() => e.dobj.removeDest(A, false, OWNER));
      ok("2. with A taken off the downpipes, removing A succeeds WITHOUT force", removed === null);
      const coll = (await e.storage.get<{ list: Array<{ id: string }>; defaultId: string }>("destinations"))!;
      ok("2. A is gone and B is the default", !coll.list.some((d) => d.id === A) && coll.defaultId === B);
    }

    // ==========================================================================================
    // 4. THE LOOP IS CLOSED: A taken off first, so replication cannot run.
    // ==========================================================================================
    console.log("-- 4. A taken off before the backfill: the refusal names the step that makes replication run --");
    {
      const e = await makeEstate(wire, [B]);
      const refusal = await caught(() => e.dobj.removeDest(A, false, OWNER));
      sentences.orphanUnreplicable = refusal?.message ?? "";
      const m = refusal?.message ?? "";
      ok("the orphan guard refuses with the count", /^destination is the only proven copy of 6 backed-up run\(s\) \(src-d1, src-r2\)\./.test(m));
      ok("it says plainly that waiting does not clear them", /which replication does not copy, so waiting does not clear them/.test(m));
      ok("it names the step that makes replication run: this destination and one other, then take it off", /give each of those downpipes this destination and one other, wait for replication to copy the runs \(this can take hours\), then take this destination off them and remove it/.test(m));
      ok("it states what force costs, after the step that keeps the runs", /Or remove it with force: downpipes then cannot restore those 6 run\(s\)\./.test(m) && m.indexOf("give each of those") < m.indexOf("with force"));
      ok("it does not promise a wait for these runs", !/Replication copies/.test(m));
      // Follow the step: A back on next to B. Replication runs, then A comes off and goes.
      await reassign(e, [B, A]);
      for (let t = 1; t <= TICKS_BOUND; t++) await tick(e);
      ok(`following the step, all 6 runs are on B after ${TICKS_BOUND} ticks`, JSON.stringify(runlogIndexes(e, B)) === JSON.stringify([1, 2, 3, 4, 5, 6]));
      await reassign(e, [B]);
      ok("then removing A succeeds without force", (await caught(() => e.dobj.removeDest(A, false, OWNER))) === null);
    }

    // The wait arm of the orphan guard: A is on no downpipe, but the downpipes fan out to two others.
    console.log("-- 4b. A on no downpipe, downpipes fan out to B and C: the refusal names a wait that ends --");
    {
      const e = await makeEstate(wire, [B, "dest-c"]);
      const refusal = await caught(() => e.dobj.removeDest(A, false, OWNER));
      sentences.orphanWait = refusal?.message ?? "";
      ok("the orphan refusal names the wait, and that the count falls", refusal !== null && /Replication copies them to another destination of their downpipes at each 15-minute tick, oldest first within each downpipe\. This count falls as replication copies runs\. It can stay the same for several ticks while replication copies shared data, and the wait can take hours\./.test(refusal.message));
      ok("it states the case where the count does not fall", refusal !== null && /If replication cannot copy a run \(for example, no destination holds it\), its downpipe's newer runs stay in this count until that run leaves the downpipe's newest 50 runs\./.test(refusal.message));
      ok("it classifies as orphan-guard", classifyDestProbeRefusal(refusal) === "orphan-guard");
    }

    // A run whose origin is removed is copied from a destination that holds it. d1's run 1 records an origin
    // destination that is removed, but A holds the run, and A is on the downpipe, so B copies run 1 from A and
    // its proven window for d1 covers [1, 5].
    console.log("-- 4c. a run whose origin is removed: copied from the destination that holds it --");
    {
      const e = await makeEstate(wire, [A, B]);
      const h1 = (await e.storage.get<Array<Record<string, unknown>>>(`hist:${D1}`))!;
      h1[0]!.destinationId = "dest-removed";
      await e.storage.put(`hist:${D1}`, h1);
      const heldOnlyOnA = async (): Promise<number> => Number(/it holds (\d+) backed-up run/.exec((await caught(() => e.dobj.removeDest(A, false, OWNER)))?.message ?? "")?.[1] ?? "0");
      ok("before any tick, A holds 5 runs held nowhere else (run 1 no longer counts as sealed on A)", (await heldOnlyOnA()) === 5);
      for (let t = 1; t <= TICKS_BOUND + 1; t++) await tick(e);
      ok(`B's RUNLOG holds all 6 runs, run 1 copied from A (holds [${runlogIndexes(e, B)}])`, JSON.stringify(runlogIndexes(e, B)) === JSON.stringify([1, 2, 3, 4, 5, 6]));
      const b1 = (await repl(e, D1))[B];
      ok(`B's proven window for d1 is [1, 5] (holdsFrom ${b1?.holdsFrom}, holdsIndex ${b1?.holdsIndex})`, b1?.lastOk === true && b1.holdsFrom === 1 && b1.holdsIndex === 5);
      ok("so the count is 0", (await heldOnlyOnA()) === 0);
    }

    // A run that no destination can source does not hold the count. As 4c, and A's RUNLOG no longer lists run
    // 1, so neither its origin nor any destination of the downpipe holds it. B receives d1's runs 3 and 5. Its
    // proven window for d1 stops below run 1, and the pass records runs 3 and 5 in holdsAbove, so they leave
    // the count at once, not when run 1 leaves the run history, which can be up to
    // 50 runs later. r2 is the control: its runs are copied and leave the count through the window. When run
    // 1 leaves the run history, one more tick moves d1's runs into the window.
    console.log("-- 4c control. a run that no destination can source: its downpipe's newer runs leave the count --");
    {
      const e = await makeEstate(wire, [A, B]);
      const h1 = (await e.storage.get<Array<Record<string, unknown>>>(`hist:${D1}`))!;
      h1[0]!.destinationId = "dest-removed";
      await e.storage.put(`hist:${D1}`, h1);
      const bucketA = e.wire.bucket(BUCKET[A]!);
      const kept = parseRunlog(bucketA.get("_RECOVERY/RUNLOG")!.bytes).filter((x) => x.index !== 1);
      bucketA.delete("_RECOVERY/RUNLOG");
      bucketA.delete("_RECOVERY/RUNLOG.sig");
      const a = new S3Destination(ENDPOINT, BUCKET[A]!, "auto", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
      for (const x of kept) await appendRunlog(a, e.signer, x, undefined, { relinkLocalPrev: true });
      ok("control setup: A's RUNLOG no longer lists run 1", !runlogIndexes(e, A).includes(1) && runlogIndexes(e, A).length === 5);
      const heldOnlyOnA = async (): Promise<number> => Number(/it holds (\d+) backed-up run/.exec((await caught(() => e.dobj.removeDest(A, false, OWNER)))?.message ?? "")?.[1] ?? "0");
      for (let t = 1; t <= TICKS_BOUND + 1; t++) await tick(e);
      ok(`B's RUNLOG holds d1's runs 3 and 5 and all of r2's runs (holds [${runlogIndexes(e, B)}])`, JSON.stringify(runlogIndexes(e, B)) === JSON.stringify([2, 3, 4, 5, 6]));
      const b1 = (await repl(e, D1))[B];
      ok(`B's proven window for d1 holds nothing, as run 1 is below runs 3 and 5 (holdsIndex ${b1?.holdsIndex})`, b1?.lastOk === true && b1.holdsIndex === -1 && b1.holdsFrom === undefined);
      ok("control: B's proven window covers r2's runs [2, 6]", (await repl(e, R2))[B]?.holdsFrom === 2 && (await repl(e, R2))[B]?.holdsIndex === 6);
      ok(`B records d1's runs 3 and 5 above its window (holdsAbove ${JSON.stringify(b1?.holdsAbove)})`, JSON.stringify(b1?.holdsAbove) === "[3,5]");
      ok("so the count is 0 while run 1 is still in the run history", (await heldOnlyOnA()) === 0);
      await e.storage.put(`hist:${D1}`, h1.slice(1));
      await tick(e);
      ok("when run 1 leaves the run history, one tick moves d1's runs 3 and 5 into the window and the count stays 0", (await heldOnlyOnA()) === 0 && (await repl(e, D1))[B]?.holdsFrom === 3 && (await repl(e, D1))[B]?.holdsIndex === 5 && (await repl(e, D1))[B]?.holdsAbove === undefined);
    }

    // Three destinations: A, the origin of every run, is replaced by C after B holds the runs. A is removed, so
    // C can copy the runs only from B.
    console.log("-- 4d. A replaced by C after B holds the runs: C copies them from B --");
    {
      const e = await makeEstate(wire, [A, B]);
      for (let t = 1; t <= TICKS_BOUND; t++) await tick(e);
      ok(`setup: B holds all 6 runs (holds [${runlogIndexes(e, B)}])`, JSON.stringify(runlogIndexes(e, B)) === JSON.stringify([1, 2, 3, 4, 5, 6]));
      const coll = (await e.storage.get<{ list: Array<Record<string, unknown>>; defaultId: string }>("destinations"))!;
      coll.list.push(storedDest(C));
      await e.storage.put("destinations", coll);
      await reassign(e, [B, C]);
      ok("setup: removing A succeeds without force, as B holds every run", (await caught(() => e.dobj.removeDest(A, false, OWNER))) === null);
      for (let t = 1; t <= TICKS_BOUND + 1; t++) await tick(e);
      ok(`C's RUNLOG holds all 6 runs, copied from B (holds [${runlogIndexes(e, C)}])`, JSON.stringify(runlogIndexes(e, C)) === JSON.stringify([1, 2, 3, 4, 5, 6]));
      const cd1 = (await repl(e, D1))[C];
      const cr2 = (await repl(e, R2))[C];
      ok(`C's proven windows are d1 [1, 5] and r2 [2, 6] (d1 ${cd1?.holdsFrom}..${cd1?.holdsIndex}, r2 ${cr2?.holdsFrom}..${cr2?.holdsIndex})`, cd1?.holdsFrom === 1 && cd1.holdsIndex === 5 && cr2?.holdsFrom === 2 && cr2.holdsIndex === 6);
    }

    // ==========================================================================================
    // 5. NO OVER-CLAIM ACROSS A GAP: B held run 1, the downpipe moved to B, run 7 sealed to B.
    // ==========================================================================================
    console.log("-- 5. a seal completion on B does not claim runs 3 and 5, which only A holds --");
    {
      const e = await makeEstate(wire, [B]);
      // B proved run 1 of d1 (a part-way backfill), as the replicate pass records it.
      await e.storage.put(`repl:${D1}`, { [A]: { holdsRunId: runId(5), holdsIndex: 5, lastOk: true, lastAttemptAt: 1 }, [B]: { holdsRunId: runId(1), holdsIndex: 1, holdsFrom: 1, lastOk: true, lastAttemptAt: 1 } });
      // Run 7 of d1 is in flight and seals to B.
      const ring = (await e.storage.get<Array<Record<string, unknown>>>(`hist:${D1}`))!;
      ring.push({ runId: runId(7), index: 7, startedAt: "2026-09-27T09:14:00.000Z", status: "in-flight", prevRunId: runId(5) });
      await e.storage.put(`hist:${D1}`, ring);
      const st = (await e.storage.get<Record<string, unknown>>(`dp:${D1}`))!;
      st.inFlight = true;
      await e.storage.put(`dp:${D1}`, st);
      await e.dobj.completeRun({ id: D1, runId: runId(7), index: 7, status: "ok", destinationId: B, recordCount: 7 });
      const rb = (await repl(e, D1))[B];
      ok("B's holdsIndex stays at 1: runs 3 and 5 sealed to A and were not copied", rb !== undefined && rb.holdsIndex === 1 && rb.lastOk === true);
      const refusal = await caught(() => e.dobj.removeDest(A, false, OWNER));
      sentences.gapRefusal = refusal?.message ?? "(removal allowed)";
      console.log(`  B's holdsIndex for d1 after run 7 sealed to B: ${rb?.holdsIndex}`);
      ok("removing A is refused: d1's runs 3 and 5 and r2's runs 2, 4, 6 are only on A (5 runs)", refusal !== null && /only proven copy of 5 backed-up run\(s\)/.test(refusal.message));
      // Control: with no gap (B already proved [1, 5]) the same completion does advance holdsIndex.
      await e.storage.put(`repl:${R2}`, { [B]: { holdsRunId: runId(6), holdsIndex: 6, holdsFrom: 2, lastOk: true, lastAttemptAt: 1 } });
      const ring2 = (await e.storage.get<Array<Record<string, unknown>>>(`hist:${R2}`))!;
      ring2.push({ runId: runId(8), index: 8, startedAt: "2026-09-27T09:14:30.000Z", status: "in-flight", prevRunId: runId(6) });
      await e.storage.put(`hist:${R2}`, ring2);
      const st2 = (await e.storage.get<Record<string, unknown>>(`dp:${R2}`))!;
      st2.inFlight = true;
      await e.storage.put(`dp:${R2}`, st2);
      await e.dobj.completeRun({ id: R2, runId: runId(8), index: 8, status: "ok", destinationId: B, recordCount: 7 });
      ok("control: with no gap below it the completion raises B's holdsIndex to 8", (await repl(e, R2))[B]?.holdsIndex === 8);
    }

    // ==========================================================================================
    // 6. GENUINELY UNCOPYABLE: runs that have left the history ring.
    // ==========================================================================================
    console.log("-- 6. runs outside the history ring: the refusal and the removal notice state the count --");
    {
      // Each downpipe sealed 5 runs, 3 are still in the ring: 2 older runs each have left it.
      const e = await makeEstate(wire, [B], { sealedRuns: 5 });
      const refusal = await caught(() => e.dobj.removeDest(A, false, OWNER));
      sentences.orphanWithOlder = refusal?.message ?? "";
      ok("the refusal states the 4 older runs outside the run history and that nothing copies them", refusal !== null && /4 older run\(s\) of the downpipes that sealed runs here are no longer in the run history, which keeps the newest 50 runs of each downpipe\. Replication does not copy those, so downpipes cannot restore any of them held only here once this destination is removed, with or without force\./.test(refusal.message));
      const forced = ((await e.dobj.removeDest(A, true, OWNER).catch(() => ({}))) as { notice?: string });
      sentences.forceNotice = forced.notice ?? "";
      ok("a force removal returns a notice naming the 6 runs it dropped and the 4 older ones", forced.notice === "Destination removed with force. Downpipes cannot restore the 6 backed-up run(s) that were only here. 4 older run(s) of the downpipes that sealed runs here are outside the run history, which keeps the newest 50 runs of each downpipe, and replication does not copy runs outside it. Downpipes cannot restore any of them that were only here.");
    }
    {
      // Backfill done, older runs outside the ring: the removal succeeds without force and says what it cost.
      const e = await makeEstate(wire, [A, B], { sealedRuns: 5 });
      for (let t = 1; t <= TICKS_BOUND; t++) await tick(e);
      await reassign(e, [B]);
      const res = ((await e.dobj.removeDest(A, false, OWNER).catch((err: Error) => ({ refused: err.message }))) as { notice?: string });
      sentences.removedNotice = res.notice ?? "";
      ok("a removal with no ring run at risk still states the older runs outside the history", res.notice?.startsWith("Destination removed. 4 older run(s)") === true);
      const clean = await makeEstate(wire, [A, B]);
      for (let t = 1; t <= TICKS_BOUND; t++) await tick(clean);
      await reassign(clean, [B]);
      const cleanRes = (await clean.dobj.removeDest(A, false, OWNER).catch(() => null)) as { notice?: string } | null;
      ok("control: with every run in the ring copied, the removal succeeds and returns no notice", cleanRes !== null && cleanRes.notice === undefined);
    }
  } finally {
    wire.uninstall();
    Date.now = realNow;
  }

  console.log("\n-- the texts the console shows verbatim --");
  for (const [k, v] of Object.entries(sentences)) console.log(`  ${k}: ${v}`);
  console.log(failures === 0 ? "\nREPL BACKFILL DEST REMOVAL PASS\n" : `\nREPL BACKFILL DEST REMOVAL FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
