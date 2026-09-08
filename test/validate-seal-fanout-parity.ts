// Prove the SUPPORT-PACK evidence the SLICED / FAN-OUT seal paths now record, and prove it is REDACTION-SAFE
// (NO-CUSTODY: a closed enum, a count, a clamped int, a boolean or a coarse class -- never a raw message, a
// key, an object name, a bucket or a customer value). No network, no deploy, no real DO.
//   node test/validate-seal-fanout-parity.ts
//
// The three gaps this closes:
//   The fan-out / sliced population -- the BIGGEST customers -- produced structurally poorer rows than
//         inline runs: fan-out failure completions carried NO causeDigest (so a customer's Logpush export could
//         not be joined to the failed row), ok fan-out rows omitted recordsVanished / incompleteByMarker /
//         incompleteIds / multipartAbortFailed (a fanned-out archive looked WHOLE while the same shortfall was
//         reported honestly inline), a sole-destination outage never lit the down-destination marker on a DO
//         failure, a "worker stalled" row never said WHICH range, and the coordinator's lease-loss never posted
//         the lease-lost-abandon ring entry a serial resume does.
//         -> the seal DO's completion bodies now go through ONE rule set (multipartAbortFlag /
//            downDestinationFlag, shared with the inline path); the worker digests its own raw fault at the
//            detection point and reports the 12-hex digest; and the coordinator observes lease-lost-abandon,
//            fanout-range-stalled (with the range index) and fanout-report-discarded into the seal-fault ring.
//   The seal-fault ring's OWN ingestion dropped observations silently: a failed fire-and-forget POST
//         during a scheduler-DO outage, a kind added engine-side but never added to SEAL_FAULT_KINDS, and a
//         malformed count that read back as an honest 0 (the input a false severe-truncation escalation needs).
//         -> postSealFault is the one send-side chokepoint: it tallies drops by CLOSED class and flushes them
//            into the ring as "observe-dropped" records; sanitiseSealFault stamps countsMalformed on a record
//            whose count was clamped from a malformed value.
//   Every knob resolver outside the slice family was fail-soft and SILENT: a typo'd
//         SCALE_SEGMENT_TARGET_BYTES / DEST_THROTTLE_ATTEMPTS / SEAL_VERIFY_SAMPLE / REPL_VERIFY_SEGMENTS /
//         SCALE_FANOUT_RANGES resolved to the default with no marker, so set-but-invalid was indistinguishable
//         from never-set. -> sealKnobSources reports {source: default|env|clamped|invalid} for every family.
//
// PART B: a fan-out WORKER strike-out digests its own raw fault, and the COORDINATOR forwards the coarse
//         class + causeDigest + down-destination + stranded-parts flag onto the failed run row.
// PART C: the merge fault's own terminal completions carry the digest + destination attribution.
// PART D: the ok fan-out completion carries the summed incompleteness fields the counts already held.
// PART E: the SLICED (serial DO) failure row names the down destination + the stranded-parts flag.
// PART F: the ring gains lease-lost-abandon (coordinator), fanout-range-stalled (which range) and
//         fanout-report-discarded (why a worker report was dropped).
// PART G: REDACTION -- a secret + a customer object key planted in the raw fault reach NO recorded byte.
// PART H: dropped observations are counted by closed class and self-reported into the ring.
// PART I: every knob family reports its source; the rejected raw string is never carried.

import { RunSealDO } from "../src/seal/runstate.ts";
import type { CoordinatorDoc } from "../src/seal/runseal-do.ts";
import { zeroCounts, type CheckpointCounts } from "../src/seal/checkpoint.ts";
import { coarseRunError, causeDigest } from "../src/seal/slice.ts";
import { REASON_DESTINATION_ACCESS } from "../src/restore-reasons.ts";
import { MAX_SLICE_FAILURES } from "../src/seal/runstate-helpers.ts";
import { sanitiseSealFault, SEAL_FAULT_KINDS, SEAL_FAULT_DROP_CLASSES, FANOUT_DISCARD_CLASSES } from "../src/seal/seal-faults.ts";
import { postSealFault, resetSealFaultDropTally, sealFaultDropTally } from "../src/seal/seal-fault-post.ts";
import { sealKnobSources } from "../src/seal/knob-sources.ts";
import { KNOB_SOURCES } from "../src/seal/budget.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DP = "dp_big";
const RUN = "01BX5ZZKBKACTAV9WEVGEMMVRY";

// The two customer-owned values planted INSIDE every raw fault this test throws: exactly where a raw message
// would leak into the pack if a recording site failed to coarsen. Neither may reach a recorded byte.
const SECRET = "sk-live-CUSTOMER-TOKEN-abc123";
const CUSTOMER_KEY = "kv/tenants/acme/billing-2026.json";
// A DESTINATION-class fault (coarseRunError maps a bare status to "destination access error"), carrying both.
const DEST_FAULT = `PUT https://acct.r2.cloudflarestorage.com/prod-bucket/${CUSTOMER_KEY} failed: status 500 token=${SECRET}`;

// ---- doubles ------------------------------------------------------------------------------------

// makeDOState: a Map-backed DurableObjectState (the fan-out validator's harness, trimmed to what these paths
// touch: get/put/delete/deleteAll/list/setAlarm/deleteAlarm).
function makeDOState(): { state: DurableObjectState; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const state = {
    storage: {
      async get(key: string): Promise<unknown> {
        return storage.get(key);
      },
      async put(a: string | Record<string, unknown>, b?: unknown): Promise<void> {
        if (typeof a === "string") storage.set(a, b);
        else for (const [k, v] of Object.entries(a)) storage.set(k, v);
      },
      async delete(key: string | string[]): Promise<boolean | number> {
        if (Array.isArray(key)) {
          let n = 0;
          for (const k of key) if (storage.delete(k)) n += 1;
          return n;
        }
        return storage.delete(key);
      },
      async deleteAll(): Promise<void> {
        storage.clear();
      },
      async list<T>(opts?: { prefix?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
        const prefix = opts?.prefix ?? "";
        let keys = [...storage.keys()].filter((k) => k.startsWith(prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        const out = new Map<string, T>();
        for (const k of keys.slice(0, opts?.limit ?? keys.length)) out.set(k, storage.get(k) as T);
        return out;
      },
      async setAlarm(): Promise<void> {},
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, storage };
}

interface Call {
  path: string;
  body?: Record<string, unknown>;
}

// makeScheduler: a scheduler-DO stub that RECORDS every call. `owned` drives the lease heartbeat (false = a
// newer run reclaimed the downpipe: the lease-lost-abandon path). `refuse` makes every POST fail, which is the
// scheduler-DO outage the seal-fault transport-drop class exists to count.
function makeScheduler(opts?: { owned?: boolean; refuse?: boolean }): { stub: DurableObjectStub; calls: Call[] } {
  const calls: Call[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (opts?.refuse === true) return new Response("nope", { status: 503 });
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: opts?.owned !== false }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls };
}

// strandedDest: a Destination double whose ONLY behaviour under test is the stranded-multipart-parts accessor
// (the signal multipartAbortFlag reads). Every other member is unreachable on these fault paths.
function strandedDest(n: number): Destination {
  return { multipartAbortFailures: () => n } as unknown as Destination;
}

// makeEnv wires a RunSealDO fleet double: SCHEDULER -> the recording scheduler, RUNSEAL -> per-name instances
// (so a WORKER's /range-failed reaches a REAL coordinator DO, and a coordinator's worker poll reaches a real or
// absent worker). `pollOk:false` makes every worker /status unreachable, which is the wedged-worker case.
function makeEnv(sched: DurableObjectStub, opts?: { pollOk?: boolean; knobs?: Record<string, string> }): { env: Env; instFor: (name: string) => { obj: RunSealDO; storage: Map<string, unknown> } } {
  const instances = new Map<string, { obj: RunSealDO; storage: Map<string, unknown> }>();
  let env!: Env;
  const instFor = (name: string): { obj: RunSealDO; storage: Map<string, unknown> } => {
    let inst = instances.get(name);
    if (!inst) {
      const { state, storage } = makeDOState();
      inst = { obj: new RunSealDO(state, env), storage };
      instances.set(name, inst);
    }
    return inst;
  };
  const runseal = {
    idFromName: (name: string) => ({ name }),
    get: (id: { name: string }) => ({
      async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const req = input instanceof Request ? input : new Request(String(input), init);
        if (new URL(req.url).pathname === "/status" && opts?.pollOk !== true) return new Response("gone", { status: 404 });
        return instFor(id.name).obj.fetch(req);
      },
    }),
  } as unknown as DurableObjectNamespace;
  env = {
    SCHEDULER: { idFromName: () => ({}), get: () => sched } as unknown as DurableObjectNamespace,
    RUNSEAL: runseal,
    ...(opts?.knobs ?? {}),
  } as unknown as Env;
  return { env, instFor };
}

// A worker RunDoc whose strike ladder is ONE strike from terminal (so a single fault strikes it out) and whose
// checkpoint is the stored identity shape the fault paths read (they never unwrap the cursor).
function workerDoc(rangeIndex: number, destinationId?: string): Record<string, unknown> {
  return {
    config: { id: DP, name: "big" },
    checkpoint: { downpipeId: DP, runId: RUN, runlogIndex: 7, rangeIndex, counts: zeroCounts() },
    attempt: MAX_SLICE_FAILURES - 1,
    coordinatorId: DP,
    ...(destinationId !== undefined ? { destinationId } : {}),
  };
}

// A coordinator doc in the AWAIT phase with `ranges` ranges, none reported done.
function coordDoc(ranges: number, opts?: { destinationId?: string; counts?: CheckpointCounts; phase?: string; strikes?: number[] }): CoordinatorDoc {
  return {
    kind: "coordinator",
    config: { id: DP, name: "big" },
    base: { runId: RUN, runlogIndex: 7, prevRunId: null, downpipeId: DP, downpipeName: "big", cadence: "daily", sourceType: "kv", startedAt: "2026-07-01T00:00:00.000Z" },
    selector: { include: [], exclude: [] },
    wrappedMaster: { iv: "i", ct: "c" },
    ranges: Array.from({ length: ranges }, () => ({})),
    doneRanges: Array.from({ length: ranges }, () => null),
    counts: opts?.counts ?? zeroCounts(),
    phase: opts?.phase ?? "await",
    attempt: MAX_SLICE_FAILURES - 1,
    progress: Array.from({ length: ranges }, () => null),
    rangeStrikes: opts?.strikes ?? Array.from({ length: ranges }, () => 0),
    destConfig: null,
    ...(opts?.destinationId !== undefined ? { destinationId: opts.destinationId } : {}),
  } as unknown as CoordinatorDoc;
}

// completes / sealFaults project the recorded scheduler calls.
const completes = (calls: Call[]): Record<string, unknown>[] => calls.filter((c) => c.path === "/complete").map((c) => c.body ?? {});
const sealFaults = (calls: Call[]): Record<string, unknown>[] => calls.filter((c) => c.path === "/seal-fault").map((c) => c.body ?? {});

// ---- PART B: the coordinator forwards the worker's evidence onto the failed run row --------------
async function partB(): Promise<void> {
  console.log("\nPART B: the COORDINATOR stamps causeDigest + downDestinationIds + multipartAbortFailed:");
  const { stub, calls } = makeScheduler();
  const { env, instFor } = makeEnv(stub);
  const coord = instFor(DP);
  coord.storage.set("doc", coordDoc(2, { destinationId: "dest_primary" }));

  const { state } = makeDOState();
  const worker = new RunSealDO(state, env);
  await (worker as unknown as { workerFault(d: unknown, m: string, dest?: Destination): Promise<void> }).workerFault(workerDoc(1), DEST_FAULT, strandedDest(2));

  const rows = completes(calls);
  ok("the run row is completed FAILED exactly once", rows.length === 1 && rows[0]!.status === "failed");
  const row = rows[0]!;
  const coarse = coarseRunError(DEST_FAULT);
  ok("the raw fault classifies as a DESTINATION-access error", coarse === REASON_DESTINATION_ACCESS);
  ok("the failed row carries the coarse class (never the message)", row.error === coarse);
  // The join key: byte-identical to the `[cause <hex>]` the worker's redacted log line carries.
  ok("the failed row carries the worker's 12-hex causeDigest", row.causeDigest === (await causeDigest(DEST_FAULT)));
  ok("the digest is a bare 12-hex string (a one-way prefix, never the fault)", /^[0-9a-f]{12}$/.test(String(row.causeDigest)));
  // DEST-1: the sole destination is named DOWN, so the map's per-destination indicator lights up.
  ok("the failed row names the destination proven down", JSON.stringify(row.downDestinationIds) === JSON.stringify(["dest_primary"]));
  ok("the failed row flags the stranded multipart parts", row.multipartAbortFailed === true);

  // A SOURCE-class fault must NEVER blame the bucket (the fail-closed half of the DEST-1 rule).
  const { stub: s2, calls: c2 } = makeScheduler();
  const { env: e2, instFor: i2 } = makeEnv(s2);
  i2(DP).storage.set("doc", coordDoc(2, { destinationId: "dest_primary" }));
  const w2 = new RunSealDO(makeDOState().state, e2);
  await (w2 as unknown as { workerFault(d: unknown, m: string, dest?: Destination): Promise<void> }).workerFault(workerDoc(0), "KV namespace not found", strandedDest(0));
  const row2 = completes(c2)[0]!;
  ok("a SOURCE-class failure names NO destination down", !("downDestinationIds" in row2));
  ok("a run that stranded nothing carries NO multipart flag", !("multipartAbortFailed" in row2));

  // A hostile/drifted worker cannot smuggle free text onto the row through causeDigest (the coordinator re-gates).
  const { stub: s3, calls: c3 } = makeScheduler();
  const { env: e3, instFor: i3 } = makeEnv(s3);
  const c3o = i3(DP);
  c3o.storage.set("doc", coordDoc(1, { destinationId: "dest_primary" }));
  await c3o.obj.fetch(new Request("https://runseal.internal/range-failed", { method: "POST", body: JSON.stringify({ rangeIndex: 0, reason: "run failed", causeDigest: `leak ${SECRET}` }), headers: { "content-type": "application/json" } }));
  const row3 = completes(c3)[0]!;
  ok("a non-hex causeDigest from a worker is DROPPED at the coordinator", !("causeDigest" in row3));
  ok("no secret reaches the run row", !JSON.stringify(row3).includes(SECRET));
}

// ---- PART C: the merge fault's own terminal completions ------------------------------------------
async function partC(): Promise<void> {
  console.log("\nPART C: a COORDINATOR MERGE fault completes with the digest + destination attribution:");
  const { stub, calls } = makeScheduler();
  const { env } = makeEnv(stub);
  const coord = new RunSealDO(makeDOState().state, env);
  const doc = coordDoc(2, { destinationId: "dest_primary" });
  await (coord as unknown as { coordinatorFault(s: DurableObjectStub, d: CoordinatorDoc, m: string, dest?: Destination): Promise<void> }).coordinatorFault(stub, doc, DEST_FAULT, strandedDest(1));
  const row = completes(calls)[0]!;
  ok("the merge strike-out row carries the coarse class", row.error === REASON_DESTINATION_ACCESS);
  ok("the merge strike-out row carries the causeDigest", row.causeDigest === (await causeDigest(DEST_FAULT)));
  ok("the merge strike-out row names the destination down", JSON.stringify(row.downDestinationIds) === JSON.stringify(["dest_primary"]));
  ok("the merge strike-out row flags stranded parts", row.multipartAbortFailed === true);
  ok("the merge strike-out row carries NO raw text", !JSON.stringify(row).includes(SECRET) && !JSON.stringify(row).includes(CUSTOMER_KEY));

  // The sustained-throttle terminal arm (a merge parked for the whole window) also carries the digest.
  const { stub: s2, calls: c2 } = makeScheduler();
  const { env: e2 } = makeEnv(s2, { knobs: { DEST_THROTTLE_MAX_YIELDS: "1" } });
  const c2o = new RunSealDO(makeDOState().state, e2);
  const throttle = `PUT ${CUSTOMER_KEY} failed: status 503 SlowDown ${SECRET}`;
  await (c2o as unknown as { coordinatorFault(s: DurableObjectStub, d: CoordinatorDoc, m: string, dest?: Destination): Promise<void> }).coordinatorFault(s2, coordDoc(2, { destinationId: "dest_primary" }), throttle, strandedDest(0));
  const trow = completes(c2)[0]!;
  ok("the sustained-throttle merge row carries the causeDigest", trow.causeDigest === (await causeDigest(throttle)));
  ok("the sustained-throttle merge row carries NO raw text", !JSON.stringify(trow).includes(SECRET) && !JSON.stringify(trow).includes("503"));
}

// ---- PART D: the ok fan-out completion's incompleteness parity -----------------------------------
async function partD(): Promise<void> {
  console.log("\nPART D: the ok FAN-OUT completion carries the summed incompleteness fields:");
  const { stub, calls } = makeScheduler();
  const { env } = makeEnv(stub);
  const coord = new RunSealDO(makeDOState().state, env);
  // The counts the coordinator has ALREADY summed across its workers (addCheckpointCounts folds all of these);
  // before this fix the completion body simply did not send them, so a fanned-out archive looked whole.
  const counts: CheckpointCounts = {
    ...zeroCounts(),
    records: 900,
    bytes: 4096,
    recordsVanished: 3,
    recordsIncomplete: 2,
    incompleteByMarker: { _truncated: 2 } as CheckpointCounts["incompleteByMarker"],
    incompleteIds: { _truncated: ["zones.settings"] } as unknown as CheckpointCounts["incompleteIds"],
  };
  await (coord as unknown as { completeFanout(s: DurableObjectStub, d: CoordinatorDoc, dest: Destination | undefined): Promise<void> }).completeFanout(stub, coordDoc(3, { counts, destinationId: "dest_primary" }), strandedDest(1));
  const row = completes(calls)[0]!;
  ok("the ok row is a fan-out completion", row.status === "ok" && row.recordCount === 900);
  ok("recordsVanished (objects deleted mid-crawl) now rides the fan-out row", row.recordsVanished === 3);
  ok("incompleteByMarker (WHICH incompleteness kinds) now rides", JSON.stringify(row.incompleteByMarker) === JSON.stringify({ _truncated: 2 }));
  ok("incompleteIds (WHICH surface was short) now rides", JSON.stringify(row.incompleteIds) === JSON.stringify({ _truncated: ["zones.settings"] }));
  ok("multipartAbortFailed rides an ok fan-out row too", row.multipartAbortFailed === true);

  // A clean run carries none of them (the fields are only present when non-zero / non-empty, byte-for-byte the
  // inline body's rule -- a clean fan-out row must not grow noise).
  const { stub: s2, calls: c2 } = makeScheduler();
  const { env: e2 } = makeEnv(s2);
  const c2o = new RunSealDO(makeDOState().state, e2);
  await (c2o as unknown as { completeFanout(s: DurableObjectStub, d: CoordinatorDoc, dest: Destination | undefined): Promise<void> }).completeFanout(s2, coordDoc(3), strandedDest(0));
  const clean = completes(c2)[0]!;
  ok("a clean fan-out row omits recordsVanished / incompleteByMarker / incompleteIds", !("recordsVanished" in clean) && !("incompleteByMarker" in clean) && !("incompleteIds" in clean));
  ok("a clean fan-out row omits multipartAbortFailed", !("multipartAbortFailed" in clean));
}

// ---- PART E: the SLICED (serial DO) failure row --------------------------------------------------
async function partE(): Promise<void> {
  console.log("\nPART E: the SLICED seal-DO failure row names the down destination + stranded parts:");
  const { stub, calls } = makeScheduler();
  const { env } = makeEnv(stub);
  const seal = new RunSealDO(makeDOState().state, env);
  const doc = { config: { id: DP, name: "big" }, checkpoint: { downpipeId: DP, runId: RUN, runlogIndex: 7, counts: zeroCounts() }, attempt: MAX_SLICE_FAILURES - 1, destinationId: "dest_primary" };
  await (seal as unknown as { handleHardFault(s: DurableObjectStub, d: unknown, m: string, dest?: Destination): Promise<void> }).handleHardFault(stub, doc, DEST_FAULT, strandedDest(4));
  const row = completes(calls)[0]!;
  ok("the sliced strike-out row carries the coarse class + digest", row.error === REASON_DESTINATION_ACCESS && row.causeDigest === (await causeDigest(DEST_FAULT)));
  ok("the sliced strike-out row names the destination proven down", JSON.stringify(row.downDestinationIds) === JSON.stringify(["dest_primary"]));
  ok("the sliced strike-out row flags stranded multipart parts", row.multipartAbortFailed === true);
  ok("the sliced strike-out row carries NO raw text", !JSON.stringify(row).includes(SECRET) && !JSON.stringify(row).includes(CUSTOMER_KEY));
}

// ---- PART F: the fan-out seal-fault ring entries --------------------------------------------------
async function partF(): Promise<void> {
  console.log("\nPART F: the ring gains lease-lost-abandon, fanout-range-stalled and fanout-report-discarded:");
  // (1) COORDINATOR lease loss: a newer run owns the downpipe. The serial resume has always posted this; the
  //     coordinator abandoned silently, so the fan-out population's reclaim events were invisible.
  {
    const { stub, calls } = makeScheduler({ owned: false });
    const { env, instFor } = makeEnv(stub);
    const inst = instFor(DP);
    inst.storage.set("doc", coordDoc(2));
    await inst.obj.alarm();
    const faults = sealFaults(calls);
    ok("the coordinator posts a lease-lost-abandon observation", faults.length === 1 && faults[0]!.kind === "lease-lost-abandon");
    ok("it carries the customer's own downpipe + run ids only", faults[0]!.downpipeId === DP && faults[0]!.runId === RUN);
    ok("the abandon is still clean (no completion posted)", completes(calls).length === 0);
  }
  // (2) The AWAIT ladder strikes out a WEDGED range. The completion can only say "stalled" (there is no raw
  //     fault to digest -- the worker threw nothing), so the RANGE INDEX in the ring is the only handle support
  //     has on the run. Range 1 is one strike from the ladder; its worker /status is unreachable.
  {
    const { stub, calls } = makeScheduler();
    const { env, instFor } = makeEnv(stub, { pollOk: false });
    const inst = instFor(DP);
    const doc = coordDoc(3, { strikes: [0, MAX_SLICE_FAILURES - 1, 0] });
    inst.storage.set("doc", doc);
    await (inst.obj as unknown as { awaitTick(s: DurableObjectStub, d: CoordinatorDoc): Promise<void> }).awaitTick(stub, doc);
    const stalls = sealFaults(calls).filter((f) => f.kind === "fanout-range-stalled");
    ok("the strike-out posts a fanout-range-stalled observation", stalls.length === 1);
    ok("it names WHICH range wedged (a small integer)", stalls[0]!.rangeIndex === 1);
    ok("the run is still failed closed (the lease is released)", completes(calls).some((r) => r.status === "failed"));
  }
  // (3) A DISCARDED worker report. Each discard is correct (idempotence), but a run whose reports were being
  //     dropped previously left no trace at all.
  {
    const { stub, calls } = makeScheduler();
    const { env, instFor } = makeEnv(stub);
    const inst = instFor(DP);
    const doc = coordDoc(2);
    (doc as unknown as { doneRanges: unknown[] }).doneRanges[0] = { rangeIndex: 0, shards: [], recordCount: 1, counts: zeroCounts() };
    inst.storage.set("doc", doc);
    // A DUPLICATE report for a range already recorded.
    await inst.obj.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 0, shards: [], recordCount: 1, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    // A STALE report arriving after the merge began.
    inst.storage.set("doc", coordDoc(2, { phase: "merge" }));
    await inst.obj.fetch(new Request("https://runseal.internal/range-done", { method: "POST", body: JSON.stringify({ rangeIndex: 1, shards: [], recordCount: 1, counts: zeroCounts() }), headers: { "content-type": "application/json" } }));
    const drops = sealFaults(calls).filter((f) => f.kind === "fanout-report-discarded");
    ok("a duplicate range report is observed", drops.some((d) => d.discardClass === "duplicate-range" && d.rangeIndex === 0));
    ok("a stale (post-merge) report is observed", drops.some((d) => d.discardClass === "stale-phase" && d.rangeIndex === 1));
    ok("the discard classes are the closed vocabulary", drops.every((d) => (FANOUT_DISCARD_CLASSES as readonly string[]).includes(String(d.discardClass))));
  }
}

// ---- PART G: REDACTION across every recorded byte -------------------------------------------------
async function partG(): Promise<void> {
  console.log("\nPART G: REDACTION -- no recorded byte carries the secret, the key, the bucket or the message:");
  const { stub, calls } = makeScheduler();
  const { env, instFor } = makeEnv(stub, { pollOk: false });
  const coord = instFor(DP);
  coord.storage.set("doc", coordDoc(2, { destinationId: "dest_primary" }));
  const worker = new RunSealDO(makeDOState().state, env);
  await (worker as unknown as { workerFault(d: unknown, m: string, dest?: Destination): Promise<void> }).workerFault(workerDoc(1), DEST_FAULT, strandedDest(1));

  const bytes = JSON.stringify(calls);
  ok("no recorded byte carries the secret", !bytes.includes(SECRET) && !bytes.includes("sk-live"));
  ok("no recorded byte carries the customer object key", !bytes.includes(CUSTOMER_KEY) && !bytes.includes("billing-2026"));
  ok("no recorded byte carries the endpoint / bucket", !bytes.includes("cloudflarestorage") && !bytes.includes("prod-bucket"));
  ok("no recorded byte carries the raw message or its status", !bytes.includes("status 500") && !bytes.includes("PUT https"));
  // Everything that DID ride is a closed class, a hex digest, an opaque id or a boolean.
  const row = completes(calls)[0]!;
  ok("only the coarse class rides as the reason", row.error === REASON_DESTINATION_ACCESS);
  ok("the sanitiser drops every fan-out observation field that is not in the vocabulary", sanitiseSealFault({ kind: "fanout-report-discarded", discardClass: `hostile ${SECRET}`, rangeIndex: 2 }, 1)?.discardClass === undefined);
}

// ---- PART H: the ring's own dropped observations ------------------------------------------
async function partH(): Promise<void> {
  console.log("\nPART H: the seal-fault ring self-reports its OWN dropped observations:");
  // The drop classes are the TWO ways an observation never reaches the ring, and only those two. `malformed-count`
  // was a third member and is gone: a malformed count does not DROP the observation, it clamps it and
  // stamps countsMalformed:true on the record that lands, which is a different fact carried in a different field.
  // A drop class that cannot be a drop is a promise the pack cannot keep, so the assertion pins the two.
  ok("the drop classes are the closed two, and both are genuine drops", SEAL_FAULT_DROP_CLASSES.length === 2 && (SEAL_FAULT_DROP_CLASSES as readonly string[]).includes("transport") && (SEAL_FAULT_DROP_CLASSES as readonly string[]).includes("unknown-kind"));
  ok("a malformed count is NOT a drop: the record lands, clamped, carrying the countsMalformed sentinel", ((r) => r !== null && r.countsMalformed === true && r.reclaimed === 0)(sanitiseSealFault({ kind: "orphan-root-reclaim", reclaimed: Number.NaN }, 1)));
  ok("observe-dropped is a member kind", (SEAL_FAULT_KINDS as readonly string[]).includes("observe-dropped"));

  // (1) TRANSPORT: a scheduler-DO outage refuses every POST. The observation is gone (fail-open, as designed),
  //     but it is now COUNTED -- and flushed into the ring as soon as an observation lands again, so the pack
  //     shows "N observations were dropped" instead of a clean ring that reads as a healthy engine.
  resetSealFaultDropTally();
  {
    const { stub: down } = makeScheduler({ refuse: true });
    await postSealFault(down, { kind: "shard-list-truncated", at: 1, downpipeId: DP, runId: RUN, found: 900, expected: 970 });
    await postSealFault(down, { kind: "lease-lost-abandon", at: 2, downpipeId: DP, runId: RUN });
    ok("a refused POST is tallied as a transport drop", sealFaultDropTally().transport === 2);
    const { stub: up, calls } = makeScheduler();
    await postSealFault(up, { kind: "lease-lost-abandon", at: 3, downpipeId: DP, runId: RUN });
    const posted = sealFaults(calls);
    ok("the recovered observation lands", posted.some((f) => f.kind === "lease-lost-abandon"));
    const dropped = posted.find((f) => f.kind === "observe-dropped");
    ok("the pending drops are FLUSHED into the ring", dropped !== undefined && dropped.dropClass === "transport" && dropped.dropped === 2);
    ok("the tally is cleared once flushed", sealFaultDropTally().transport === undefined);
    ok("the drop record carries counters only (no message, no kind string)", JSON.stringify(dropped).includes('"dropped":2') && !JSON.stringify(dropped).includes("shard-list-truncated"));
  }

  // (2) UNKNOWN KIND: a kind added engine-side but never added to SEAL_FAULT_KINDS was dropped by the DO's
  //     defensive sanitiser and nothing anywhere said so (the "silent for months" case). It is now pre-gated at
  //     the SEND side and converted into a valid observe-dropped record; the drifted kind's STRING never rides.
  resetSealFaultDropTally();
  {
    const { stub, calls } = makeScheduler();
    await postSealFault(stub, { kind: "some-new-kind-nobody-registered", at: 4, downpipeId: DP });
    const posted = sealFaults(calls);
    ok("a drifted kind is NOT posted as itself", !posted.some((f) => f.kind === "some-new-kind-nobody-registered"));
    ok("it is reported as an observe-dropped / unknown-kind record", posted.length === 1 && posted[0]!.kind === "observe-dropped" && posted[0]!.dropClass === "unknown-kind");
    ok("the drifted kind's string never rides", !JSON.stringify(posted).includes("nobody-registered"));
    ok("the DO sanitiser accepts the record it produced", sanitiseSealFault(posted[0]!, 4) !== null);
  }

  // (3) MALFORMED COUNT: a NaN `found` used to read back as an honest found:0 -- exactly the input a severe-
  //     truncation escalation fires on. The clamp is unchanged (fail-closed) but the record now says so.
  {
    const f = sanitiseSealFault({ kind: "shard-list-truncated", at: 5, downpipeId: DP, found: Number.NaN, expected: 970 }, 5);
    ok("a malformed count still clamps to a bounded 0 (fail-closed)", f?.found === 0);
    ok("the record is STAMPED countsMalformed, so the 0 is not read as a measurement", f?.countsMalformed === true);
    const g = sanitiseSealFault({ kind: "shard-list-truncated", at: 5, downpipeId: DP, found: 900, expected: 970 }, 5);
    ok("a real measurement is NOT stamped", g?.found === 900 && !("countsMalformed" in (g ?? {})));
  }

  // (4) A hostile drop class cannot invent a class the diagnosis reasons over.
  const hostile = sanitiseSealFault({ kind: "observe-dropped", at: 6, dropClass: `transport ${SECRET}`, dropped: 3 }, 6);
  ok("an out-of-vocabulary dropClass is DROPPED (never carried as text)", hostile !== null && !("dropClass" in hostile));
  ok("no secret survives the sanitiser", !JSON.stringify(hostile).includes(SECRET));
  resetSealFaultDropTally();
}

// ---- PART I: every knob family reports its source -----------------------------------------
function partI(): void {
  console.log("\nPART I: every knob resolver reports {resolved, source}:");
  ok("the source vocabulary is the closed four", KNOB_SOURCES.length === 4 && (KNOB_SOURCES as readonly string[]).includes("invalid"));

  // Nothing set: every knob is an honest DEFAULT.
  const unset = sealKnobSources({} as unknown as Env);
  const families = ["sliceSubrequests", "sliceWallMs", "shardMaxRecords", "segmentTargetBytes", "slicedRunsDisabled", "destThrottleAttempts", "destThrottleBaseMs", "destThrottleMaxYields", "fanoutRanges", "fanoutMinRecords", "fanoutSampleCap", "verifyAtSeal", "sealVerifySample", "sealVerifyMaxBytes", "sealVerifyFullBytes", "sealVerifyAttempts", "sealVerifyFullShards", "sealVerifyShardSample", "replVerifySegments"];
  for (const k of families) ok(`${k} is reported`, unset[k] !== undefined);
  ok("every unset knob reports source `default`", families.every((k) => unset[k]!.source === "default"));

  // The six families the gap names, each SET but INVALID: the pack now says the value was REJECTED. This is the
  // whole ticket -- "I tuned it and nothing changed" -- and it was previously indistinguishable from never-set.
  const invalid = sealKnobSources({ SCALE_SEGMENT_TARGET_BYTES: "8MB", DEST_THROTTLE_ATTEMPTS: `${SECRET}`, DEST_THROTTLE_MAX_YIELDS: "-1", SEAL_VERIFY_SAMPLE: "lots", REPL_VERIFY_SEGMENTS: "off", SCALE_FANOUT_RANGES: "many" } as unknown as Env);
  ok("an invalid SCALE_SEGMENT_TARGET_BYTES reports source `invalid`", invalid.segmentTargetBytes!.source === "invalid");
  ok("an invalid DEST_THROTTLE_ATTEMPTS reports source `invalid`", invalid.destThrottleAttempts!.source === "invalid");
  ok("a negative DEST_THROTTLE_MAX_YIELDS reports source `invalid`", invalid.destThrottleMaxYields!.source === "invalid");
  ok("an invalid SEAL_VERIFY_SAMPLE reports source `invalid`", invalid.sealVerifySample!.source === "invalid");
  ok("an invalid SCALE_FANOUT_RANGES reports source `invalid`", invalid.fanoutRanges!.source === "invalid");
  ok("an explicitly-set REPL_VERIFY_SEGMENTS reports source `env`", invalid.replVerifySegments!.source === "env");
  ok("an invalid knob still reports the DEFAULT that is actually running", invalid.destThrottleMaxYields!.resolved === 60 && invalid.fanoutRanges!.resolved === 1);
  // REDACTION: the rejected string could be anything at all, including a pasted secret. It must never ride.
  ok("the rejected raw string is NEVER carried", !JSON.stringify(invalid).includes(SECRET) && !JSON.stringify(invalid).includes("8MB") && !JSON.stringify(invalid).includes("lots"));

  // Valid + over-ceiling values.
  const set = sealKnobSources({ SCALE_FANOUT_RANGES: "4096", SEAL_VERIFY_SAMPLE: "7", DEST_THROTTLE_ATTEMPTS: "9" } as unknown as Env);
  ok("an over-ceiling SCALE_FANOUT_RANGES reports source `clamped` at the ceiling", set.fanoutRanges!.source === "clamped" && set.fanoutRanges!.resolved === 256);
  ok("a valid SEAL_VERIFY_SAMPLE reports source `env` with the value in force", set.sealVerifySample!.source === "env" && set.sealVerifySample!.resolved === 7);
  ok("a valid DEST_THROTTLE_ATTEMPTS reports source `env`", set.destThrottleAttempts!.source === "env" && set.destThrottleAttempts!.resolved === 9);
  // SEAL_VERIFY_SAMPLE=0 is MEANINGFUL (no decrypt sample), not a typo: it must read as `env`, not `invalid`.
  const zero = sealKnobSources({ SEAL_VERIFY_SAMPLE: "0" } as unknown as Env);
  ok("SEAL_VERIFY_SAMPLE=0 is an operator value, not a typo", zero.sealVerifySample!.source === "env" && zero.sealVerifySample!.resolved === 0);
  ok("every reported value is an enum + bounded ints (no strings)", Object.values(sealKnobSources({ SCALE_SLICE_WALL_MS: "99" } as unknown as Env)).every((r) => (KNOB_SOURCES as readonly string[]).includes(r.source) && (r.resolved === undefined || Number.isInteger(r.resolved))));
}

async function main(): Promise<void> {
  await partB();
  await partC();
  await partD();
  await partE();
  await partF();
  await partG();
  await partH();
  partI();
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
