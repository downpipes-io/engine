// Validates three pieces of support-bundle evidence an operator needed, and did not have, to diagnose the
// deploy-time destination fault from the bundle alone:
//   4. SPANS: first-seen and last-seen per seal or replication fault reason (and per replica target), kept
//      beside the 64-row ring, which a replication pass fills within a day and so loses the START of a fault;
//   5. RUN DESTINATION: every run row names the destination it sealed to, or says explicitly why it names none
//      (destinationBasis), and a default-routed run records the default it sealed to;
//   6. STRANDS: which runs are stranded on a replica target, the origin each sealed to, the cause, and whether
//      the origin still holds it.
// Each piece is driven through its real recording site (the SchedulerDO over MockStorage, replicateBacklog over
// an R2 double and a stubbed S3 wire, selectSealDestination), then through the pack projection, and checked for
// redaction: a posted value outside a closed vocabulary never reaches the pack.
//
// Run: node test/validate-bundle-fault-evidence.ts

import { fetchSealFaults, fetchSealFaultSpans } from "../src/admin/support-sections-seal.ts";
import { fetchRunHistory, RUN_DESTINATION_BASES } from "../src/admin/support-sections-runs.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { selectSealDestination } from "../src/cron/seal-dispatch.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState, RunHistoryEntry } from "../src/sched/types.ts";
import { SEAL_FAULT_SPAN_MAX } from "../src/seal/seal-fault-spans.ts";
import { sanitiseSealFault } from "../src/seal/seal-faults.ts";
import { replicateBacklog } from "../src/seal/replicate.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const S3_ENDPOINT = "https://s3.example.test";
const SENTINEL = "acme-payroll-bucket";

function makeDO(seed: Record<string, unknown> = {}): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(seed)) storage.seed(k, v);
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  return { storage, scheduler };
}
async function post(s: DurableObjectStub, path: string, body: unknown): Promise<Response> {
  return s.fetch(`https://scheduler.internal${path}`, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
}

// ---------------------------------------------------------------------------------------------------------
// 4. SPANS
// ---------------------------------------------------------------------------------------------------------
async function spans(): Promise<void> {
  console.log("-- 4. first and last seen per fault reason survive a full ring --");
  const { scheduler } = makeDO();
  const t0 = Date.parse("2026-09-24T05:40:00.000Z");
  const dps = ["dp-a", "dp-b", "dp-c", "dp-d", "dp-e", "dp-f", "dp-g"];
  // Two days of a replication pass: every tick, every downpipe, both faults (well past the 64-row ring).
  let at = t0;
  for (let tick = 0; tick < 12; tick++) {
    for (const dp of dps) {
      at += 60_000;
      await post(scheduler, "/seal-fault", { kind: "replica-target-fault", at, downpipeId: dp, destinationId: "deploy", replicaReason: "not-configured" });
      await post(scheduler, "/seal-fault", { kind: "replica-target-fault", at, downpipeId: dp, destinationId: "dest-s3", replicaReason: "origin-dest-unconfigured", strandedRuns: 20 + tick });
    }
  }
  const ring = await fetchSealFaults(scheduler);
  ok("POPULATION: the ring is full (64 rows) and has lost the earliest observations", ring.length === 64 && !ring.some((r) => (r as { at?: number }).at === t0 + 60_000));
  const pack = (await fetchSealFaultSpans(scheduler)) as { spans?: Array<Record<string, unknown>>; overflow?: number };
  const notCfg = pack.spans?.find((s) => s.reason === "not-configured" && s.destinationId === "deploy");
  const strand = pack.spans?.find((s) => s.reason === "origin-dest-unconfigured" && s.destinationId === "dest-s3");
  ok("sealFaultSpans carries a span for (deploy, not-configured)", notCfg !== undefined);
  ok("its firstSeenAt is the FIRST observation, which the ring no longer holds", notCfg?.firstSeenAt === t0 + 60_000);
  ok("its lastSeenAt is the latest observation", notCfg?.lastSeenAt === at);
  ok("its count is every observation (84), not the ring's share", notCfg?.count === 84);
  ok("it names the seven downpipes that posted it", Array.isArray(notCfg?.downpipeIds) && (notCfg?.downpipeIds as string[]).length === 7);
  ok("the (dest-s3, origin-dest-unconfigured) span carries the most runs ever stranded in one pass", strand?.maxStrandedRuns === 31);
  ok("the span names its reason field, a closed member", notCfg?.reasonField === "replicaReason");

  // Redaction and bounds.
  const { scheduler: s2 } = makeDO();
  await post(s2, "/seal-fault", { kind: "replica-target-fault", at: t0, destinationId: "d1", replicaReason: SENTINEL });
  await post(s2, "/seal-fault", { kind: SENTINEL, at: t0 });
  for (let i = 0; i < SEAL_FAULT_SPAN_MAX + 5; i++) await post(s2, "/seal-fault", { kind: "replica-target-fault", at: t0 + i, destinationId: `dest-${i}`, replicaReason: "unreachable" });
  const p2 = (await fetchSealFaultSpans(s2)) as { spans?: Array<Record<string, unknown>>; overflow?: number };
  ok("no byte of the spans carries an out-of-vocabulary value", !JSON.stringify(p2).includes(SENTINEL));
  ok(`the spans are capped at ${SEAL_FAULT_SPAN_MAX}`, (p2.spans?.length ?? 0) === SEAL_FAULT_SPAN_MAX);
  ok("a new key past the cap is COUNTED in overflow, never evicting an older span", (p2.overflow ?? 0) >= 5 && p2.spans?.some((s) => s.destinationId === "d1") === true);
  const { scheduler: s3 } = makeDO();
  ok("a DO with no faults carries no spans (honest absence)", Object.keys(await fetchSealFaultSpans(s3)).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// 5. RUN DESTINATION
// ---------------------------------------------------------------------------------------------------------
function stubDestConfig(list: Array<Record<string, unknown>>, defaultId: string): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.pathname === "/dest-config") {
        const id = u.searchParams.get("id");
        if (list.length === 0) return Response.json({ config: null });
        return Response.json({ config: id ? (list.find((d) => d.id === id) ?? null) : (list.find((d) => d.id === defaultId) ?? null) });
      }
      return Response.json({ ok: true });
    },
  } as unknown as DurableObjectStub;
}
const DEPLOY_ROW = { id: "deploy", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "" };
const S3_ROW = { id: "dest-s3", endpoint: S3_ENDPOINT, bucket: "b", region: "us-east-1", accessKeyId: "AKID", secretAccessKey: "not-a-real-secret", addressing: "path" };
const UNPINNED = { config: { id: "dp-u", name: "u", enabled: true, cadenceSeconds: 3600, source: { type: "kv", namespaceId: "ns" } } } as unknown as DownpipeState;

async function runDestination(): Promise<void> {
  console.log("-- 5. every run names its destination, or says why it names none --");
  const env = { DEST_R2: {} } as unknown as Env;
  const a = await selectSealDestination(env, stubDestConfig([DEPLOY_ROW, S3_ROW], "deploy"), UNPINNED);
  ok("a default-routed run whose default is the deploy-time row records \"deploy\"", !("allDown" in a) && a.destinationId === "deploy");
  const b = await selectSealDestination(env, stubDestConfig([DEPLOY_ROW, S3_ROW], "dest-s3"), UNPINNED);
  ok("a default-routed run whose default is a console destination records that id", !("allDown" in b) && b.destinationId === "dest-s3");
  const c = await selectSealDestination(env, stubDestConfig([], ""), UNPINNED);
  ok("an env-only estate (no stored destinations) records no id", !("allDown" in c) && c.destinationId === undefined);

  // The DO records the id on the row and seeds no replication state for a downpipe that does not fan out.
  const { scheduler, storage } = makeDO({ "dp:dp-u": { ...UNPINNED, nextRunAt: 0, lastRunId: null, inFlight: false } });
  const t = (await (await post(scheduler, "/trigger", { id: "dp-u" })).json()) as { runId: string; index: number };
  await post(scheduler, "/complete", { id: "dp-u", runId: t.runId, index: t.index, status: "ok", destinationId: "deploy", recordCount: 1, bytes: 1 });
  const hist = storage.rawGet<RunHistoryEntry[]>("hist:dp-u") ?? [];
  ok("the DO row of a default-routed run carries the destination it sealed to", hist.some((r) => r.runId === t.runId && r.destinationId === "deploy"));
  ok("no replication state is seeded for a downpipe that does not fan out", storage.rawGet("repl:dp-u") === undefined);

  // The pack: a row with no id carries a closed basis instead of a silent absence.
  const rows = [
    { runId: "r1", index: 1, startedAt: "2026-09-25T09:30:00.000Z", status: "ok" },
    { runId: "r2", index: 2, startedAt: "2026-09-25T10:30:00.000Z", status: "failed", error: "x" },
    { runId: "r3", index: 3, startedAt: "2026-09-25T11:30:00.000Z", status: "ok", destinationId: "dest-s3" },
  ];
  const histStub = { fetch: async () => Response.json({ byDownpipe: { "dp-u": rows } }) } as unknown as DurableObjectStub;
  const basisOf = async (set: ReadonlySet<string> | null): Promise<Array<Record<string, unknown>>> => ((await fetchRunHistory(histStub, set))["dp-u"] ?? []) as Array<Record<string, unknown>>;
  const envOnly = await basisOf(new Set());
  ok("env-only estate: an ok row with no id reads destinationBasis env-default", envOnly[0]?.destinationBasis === "env-default");
  ok("a failed row reads not-sealed", envOnly[1]?.destinationBasis === "not-sealed");
  ok("a row with an id carries the id and no basis", envOnly[2]?.destinationId === "dest-s3" && envOnly[2]?.destinationBasis === undefined);
  ok("an estate with stored destinations: an ok row with no id reads unrecorded", (await basisOf(new Set(["deploy"])))[0]?.destinationBasis === "unrecorded");
  ok("an unreadable roster reads unknown, never a guess", (await basisOf(null))[0]?.destinationBasis === "unknown");
  ok("every row carries a destinationId or a closed basis", envOnly.every((r) => typeof r.destinationId === "string" || (RUN_DESTINATION_BASES as readonly unknown[]).includes(r.destinationBasis)));
}

// ---------------------------------------------------------------------------------------------------------
// 6. STRANDS
// ---------------------------------------------------------------------------------------------------------
function installEmptyS3(): () => void {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    if (u.origin !== S3_ENDPOINT) return real(input as RequestInfo, init);
    return new Response("<Error><Code>NoSuchKey</Code></Error>", { status: 404 });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}
function emptyR2(): R2Bucket {
  return { get: async () => null, head: async () => null, put: async () => ({ etag: "e" }), delete: async () => undefined, list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] }) } as unknown as R2Bucket;
}
function replStub(): { stub: DurableObjectStub; posts: Array<Record<string, unknown>> } {
  const list = [DEPLOY_ROW, S3_ROW];
  const posts: Array<Record<string, unknown>> = [];
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (u.pathname === "/dest-config") return Response.json({ config: list.find((d) => d.id === u.searchParams.get("id")) ?? null });
      if (u.pathname === "/seal-fault") posts.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
      return Response.json({ ok: true, acquired: true, token: "t" });
    },
  } as unknown as DurableObjectStub;
  return { stub, posts };
}
const RUN = (runId: string, index: number, destinationId: string): RunHistoryEntry => ({ runId, index, startedAt: "2026-09-24T01:00:00.000Z", status: "ok", destinationId }) as RunHistoryEntry;
const SIGNER = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));

async function strands(): Promise<void> {
  console.log("-- 6. which runs are stranded, and whether the origin still holds each --");
  const restore = installEmptyS3();
  try {
    const cfg = { id: "dp-s", destinationIds: ["dest-s3", "deploy", "gone"] } as unknown as DownpipeState["config"];
    const history = [RUN("run-1", 1, "deploy"), RUN("run-2", 2, "gone"), RUN("run-3", 3, "dest-s3")];
    const { stub, posts } = replStub();
    await replicateBacklog({ SIGNER_PRIVATE: SIGNER, DEST_R2: emptyR2() } as unknown as Env, stub, cfg, history);
    const toS3 = posts.find((p) => p.kind === "replica-target-fault" && p.destinationId === "dest-s3" && Array.isArray(p.strands));
    const list = (toS3?.strands ?? []) as Array<Record<string, unknown>>;
    const by = (id: string): Record<string, unknown> | undefined => list.find((s) => s.runId === id);
    ok("the S3 target's fault lists its stranded runs", list.length === 3 && toS3?.strandedRuns === 3);
    ok("run-1: origin \"deploy\", absent from the deploy RUNLOG, so the origin does not hold it", by("run-1")?.originId === "deploy" && by("run-1")?.cause === "origin-run-missing" && by("run-1")?.originHolds === false);
    ok("run-2: origin \"gone\" (removed), so whether it holds the run is unknown", by("run-2")?.cause === "origin-dest-unconfigured" && by("run-2")?.originHolds === "unknown");
    ok("run-3: the target is its own origin and its RUNLOG lacks it: not held", by("run-3")?.originId === "dest-s3" && by("run-3")?.cause === "origin-run-missing" && by("run-3")?.originHolds === false);

    const { stub: stub2, posts: posts2 } = replStub();
    await replicateBacklog({ SIGNER_PRIVATE: SIGNER } as unknown as Env, stub2, { id: "dp-t", destinationIds: ["dest-s3", "deploy"] } as unknown as DownpipeState["config"], [RUN("run-1", 1, "deploy")]);
    const s1 = ((posts2.find((p) => p.destinationId === "dest-s3" && Array.isArray(p.strands))?.strands ?? []) as Array<Record<string, unknown>>)[0];
    ok("an origin \"deploy\" with no env binding: cause deploy-binding-missing, holding unknown", s1?.cause === "deploy-binding-missing" && s1?.originHolds === "unknown");

    // Through the DO sanitiser and the pack projection, with planted values outside the vocabulary.
    const planted = { ...toS3, strands: [...list, { runId: "run-9", originId: "x", cause: SENTINEL, originHolds: false }, { runId: "run-8", cause: "origin-run-missing", originHolds: SENTINEL }] };
    const clean = sanitiseSealFault(planted as Record<string, unknown>, Date.now());
    const cleanStrands = (clean as { strands?: Array<Record<string, unknown>> } | null)?.strands ?? [];
    ok("the DO sanitiser keeps the three real strands and drops a strand with an unknown cause", cleanStrands.length === 4 && !cleanStrands.some((s) => s.runId === "run-9"));
    ok("an out-of-vocabulary originHolds is coerced to unknown, never carried", cleanStrands.find((s) => s.runId === "run-8")?.originHolds === "unknown");
    const packStub = { fetch: async () => Response.json({ faults: [clean] }) } as unknown as DurableObjectStub;
    const pack = (await fetchSealFaults(packStub)) as Array<Record<string, unknown>>;
    ok("the pack's sealFaults row carries the strands", Array.isArray(pack[0]?.strands) && (pack[0]?.strands as unknown[]).length === 4);
    ok("no byte of the pack row carries a planted value", !JSON.stringify(pack).includes(SENTINEL));
  } finally {
    restore();
  }
}

async function main(): Promise<void> {
  await spans();
  await runDestination();
  await strands();
  console.log(failures === 0 ? "\nBUNDLE FAULT EVIDENCE PASS\n" : `\nBUNDLE FAULT EVIDENCE FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
