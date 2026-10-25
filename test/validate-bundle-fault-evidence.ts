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

import { fetchReplication, fetchSealFaults, fetchSealFaultSpans } from "../src/admin/support-sections-seal.ts";
import { fetchRunHistory, RUN_DESTINATION_BASES } from "../src/admin/support-sections-runs.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { selectSealDestination } from "../src/cron/seal-dispatch.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState, RunHistoryEntry } from "../src/sched/types.ts";
import { SEAL_FAULT_SPAN_MAX } from "../src/seal/seal-fault-spans.ts";
import { joinDestResolution } from "../src/admin/support-dest-join.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
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
// 4b. VERSION STAMP AND STALE MARK
// ---------------------------------------------------------------------------------------------------------
async function stamps(): Promise<void> {
  console.log("-- 4b. each row names the engine version that wrote it, and a row from another version reads stale --");
  const at = Date.parse("2026-10-01T00:00:00.000Z");
  const { scheduler } = makeDO();
  await post(scheduler, "/seal-fault", { kind: "replica-target-fault", at, downpipeId: "dp-a", destinationId: "deploy", replicaReason: "not-configured", engineVersion: "9.9.9" });
  await post(scheduler, "/replication/record", { id: "dp-a", destinationId: "deploy", ok: false, reason: "not-configured" });
  const row = (await fetchSealFaults(scheduler))[0] as Record<string, unknown>;
  const span = ((await fetchSealFaultSpans(scheduler)) as { spans: Array<Record<string, unknown>> }).spans[0]!;
  const repl = (await fetchReplication(scheduler))!["dp-a"]![0]!;
  ok("a ring row written by the real writer carries the running version and no stale", row.engineVersion === ENGINE_VERSION && !("stale" in row));
  ok("a span carries the running version as lastEngineVersion and no stale", span.lastEngineVersion === ENGINE_VERSION && !("stale" in span));
  ok("a replication row carries the running version and no stale", repl.engineVersion === ENGINE_VERSION && !("stale" in repl));
  const { engineVersion: _a, ...rowRest } = row;
  ok("control: the fault row is otherwise unchanged", JSON.stringify(rowRest) === JSON.stringify({ kind: "replica-target-fault", at, downpipeId: "dp-a", destinationId: "deploy", replicaReason: "not-configured", nextStep: (rowRest as { nextStep?: string }).nextStep }));

  // A record written before the stamp existed has none of the fields. It loads, and projects stale.
  const ringRow = { kind: "replica-target-fault", at, downpipeId: "dp-a", destinationId: "deploy", replicaReason: "not-configured" };
  const spanRow = { kind: "replica-target-fault", reasonField: "replicaReason", reason: "not-configured", destinationId: "deploy", count: 3, firstSeenAt: at, lastSeenAt: at + 5 };
  const replRow = { holdsRunId: null, holdsIndex: -1, lastOk: false, lastAttemptAt: at, reason: "not-configured" };
  const { scheduler: old } = makeDO({ "signal:seal-faults": [ringRow], "signal:seal-fault-spans": { spans: [spanRow], overflow: 0 }, "repl:dp-a": { deploy: replRow } });
  const oRow = (await fetchSealFaults(old))[0] as Record<string, unknown>;
  const oSpan = ((await fetchSealFaultSpans(old)) as { spans: Array<Record<string, unknown>> }).spans[0]!;
  const oRepl = (await fetchReplication(old))!["dp-a"]![0]!;
  ok("a pre-stamp ring row projects with stale true and no version", oRow.stale === true && !("engineVersion" in oRow));
  ok("a pre-stamp span projects with stale true and no version", oSpan.stale === true && !("lastEngineVersion" in oSpan) && oSpan.count === 3);
  ok("a pre-stamp replication row projects with stale true and no version", oRepl.stale === true && !("engineVersion" in oRepl) && oRepl.ok === false);

  // A row stamped by another version is stale and keeps its version; a malformed version is dropped and the row is stale.
  const other = "0.3.7";
  const bad = ["0.3.7-rc1", "v0.3.7", "0.3", "1".repeat(40), "0.3.7 ", 7];
  const { scheduler: mixed } = makeDO({ "signal:seal-faults": [{ ...ringRow, engineVersion: other }, ...bad.map((v, i) => ({ ...ringRow, at: at + 1 + i, engineVersion: v }))], "signal:seal-fault-spans": { spans: [{ ...spanRow, lastEngineVersion: other }, ...bad.map((v, i) => ({ ...spanRow, destinationId: `d${i}`, lastEngineVersion: v }))], overflow: 0 }, "repl:dp-a": { other: { ...replRow, engineVersion: other }, ...Object.fromEntries(bad.map((v, i) => [`bad${i}`, { ...replRow, engineVersion: v }])) } });
  const mRows = (await fetchSealFaults(mixed)) as Array<Record<string, unknown>>;
  const mSpans = ((await fetchSealFaultSpans(mixed)) as { spans: Array<Record<string, unknown>> }).spans;
  const mRepl = (await fetchReplication(mixed))!["dp-a"]!;
  ok("a row stamped by another version keeps that version and reads stale", mRows.some((r) => r.engineVersion === other && r.stale === true));
  ok("a malformed ring version is dropped and the row reads stale", mRows.filter((r) => r.engineVersion !== other).length === bad.length && mRows.filter((r) => r.engineVersion !== other).every((r) => !("engineVersion" in r) && r.stale === true));
  ok("a span stamped by another version keeps it and reads stale", mSpans.some((r) => r.lastEngineVersion === other && r.stale === true));
  ok("a malformed span version is dropped and the span reads stale", mSpans.filter((r) => r.lastEngineVersion !== other).length === bad.length && mSpans.filter((r) => r.lastEngineVersion !== other).every((r) => !("lastEngineVersion" in r) && r.stale === true));
  ok("a replication row stamped by another version keeps it and reads stale", mRepl.some((r) => r.engineVersion === other && r.stale === true));
  ok("a malformed replication version is dropped and the row reads stale", mRepl.filter((r) => r.engineVersion !== other).length === bad.length && mRepl.filter((r) => r.engineVersion !== other).every((r) => !("engineVersion" in r) && r.stale === true));
  ok("stale is never false anywhere in the projected rows", ![...mRows, ...mSpans, ...mRepl].some((r) => r.stale === false) && !JSON.stringify([row, span, repl]).includes("\"stale\""));

  // The next fault on a pre-stamp store folds into its span without error and stamps the span.
  await post(old, "/seal-fault", { kind: "replica-target-fault", at: at + 10, downpipeId: "dp-a", destinationId: "deploy", replicaReason: "not-configured" });
  const folded = ((await fetchSealFaultSpans(old)) as { spans: Array<Record<string, unknown>> }).spans[0]!;
  ok("a new fault folds into a pre-stamp span, keeps its count history and stamps it", folded.count === 4 && folded.firstSeenAt === at && folded.lastEngineVersion === ENGINE_VERSION && !("stale" in folded));
}

// ---------------------------------------------------------------------------------------------------------
// 4c. THE CURRENT RESOLUTION BESIDE A RED DESTINATION
// ---------------------------------------------------------------------------------------------------------
async function joined(): Promise<void> {
  console.log("-- 4c. a red destination shows what its resolution is now --");
  const at = Date.parse("2026-10-01T00:00:00.000Z");
  const { scheduler } = makeDO();
  await post(scheduler, "/seal-fault", { kind: "replica-target-fault", at, downpipeId: "dp-a", destinationId: "deploy", replicaReason: "not-configured" });
  await post(scheduler, "/seal-fault", { kind: "replica-target-fault", at: at + 1, downpipeId: "dp-a", destinationId: "other", replicaReason: "unreachable" });
  await post(scheduler, "/seal-fault", { kind: "lease-lost-abandon", at: at + 2, downpipeId: "dp-a", runId: "01R" });
  await post(scheduler, "/replication/record", { id: "dp-a", destinationId: "deploy", ok: false, reason: "not-configured" });
  await post(scheduler, "/replication/record", { id: "dp-a", destinationId: "origin", ok: true, runId: "01R", index: 1 });
  const repl = (await fetchReplication(scheduler))!;
  const out = joinDestResolution(
    { resolution: [{ id: "deploy", stored: true, namedBy: 1, branch: "deploy-env-binding", ok: true }] },
    { downpipes: [{ id: "dp-a", replication: { destinations: repl["dp-a"] } }], sealFaults: await fetchSealFaults(scheduler), sealFaultSpans: await fetchSealFaultSpans(scheduler) },
  );
  const dests = (out.downpipes[0] as { replication: { destinations: Array<Record<string, unknown>> } }).replication.destinations;
  const want = JSON.stringify({ branch: "deploy-env-binding", ok: true });
  ok("the red deploy row reads not-configured and carries the ok resolution", dests.find((d) => d.id === "deploy")?.reason === "not-configured" && JSON.stringify(dests.find((d) => d.id === "deploy")?.resolution) === want);
  ok("the green origin row carries none", !("resolution" in dests.find((d) => d.id === "origin")!));
  const faults = out.sealFaults as Array<Record<string, unknown>>;
  ok("the replica fault for deploy carries the resolution, and the one for an unlisted id reads not-listed", JSON.stringify(faults.find((f) => f.destinationId === "deploy")?.resolution) === want && faults.find((f) => f.destinationId === "other")?.resolution === "not-listed");
  ok("the non-replica fault carries none", !("resolution" in faults.find((f) => f.kind === "lease-lost-abandon")!));
  const sp = (out.sealFaultSpans as { spans: Array<Record<string, unknown>> }).spans;
  ok("the span for deploy carries the resolution; the span with no destination carries none", JSON.stringify(sp.find((x) => x.destinationId === "deploy")?.resolution) === want && !("resolution" in sp.find((x) => x.kind === "lease-lost-abandon")!));
}

// ---------------------------------------------------------------------------------------------------------
// 4d. A SPAN CLOSES WHEN THE DESTINATION RETURNS TO OK; THE RING SHOWS ITS LOWER BOUND
// ---------------------------------------------------------------------------------------------------------
async function closing(): Promise<void> {
  console.log("-- 4d. clearedAt closes a span, a recurrence reopens it, ringOldestAt bounds the ring --");
  type Span = Record<string, unknown>;
  const spansOf = async (s: DurableObjectStub): Promise<Span[]> => ((await fetchSealFaultSpans(s)) as { spans?: Span[] }).spans ?? [];
  const spanFor = async (s: DurableObjectStub, dest: string): Promise<Span | undefined> => (await spansOf(s)).find((x) => x.destinationId === dest);
  const fault = (s: DurableObjectStub, dest: string, at: number): Promise<Response> => post(s, "/seal-fault", { kind: "replica-target-fault", at, downpipeId: "dp-a", destinationId: dest, replicaReason: "not-configured" });
  const okRec = (s: DurableObjectStub, dest: string): Promise<Response> => post(s, "/replication/record", { id: "dp-a", destinationId: dest, ok: true, runId: "01R", index: 1 });
  const badRec = (s: DurableObjectStub, dest: string): Promise<Response> => post(s, "/replication/record", { id: "dp-a", destinationId: dest, ok: false, reason: "not-configured" });
  const t0 = Date.now() - 3_600_000;

  const { scheduler } = makeDO();
  await fault(scheduler, "deploy", t0);
  await fault(scheduler, "other", t0 + 1);
  await badRec(scheduler, "deploy");
  ok("a failed state does not close the span", (await spanFor(scheduler, "deploy"))?.clearedAt === undefined);
  await okRec(scheduler, "deploy");
  const closed = await spanFor(scheduler, "deploy");
  ok("fault then ok sets clearedAt at or after lastSeenAt", typeof closed?.clearedAt === "number" && (closed.clearedAt as number) >= (closed.lastSeenAt as number));
  ok("an ok for another destination does not touch the other span", (await spanFor(scheduler, "other"))?.clearedAt === undefined);
  const firstSeen = closed?.firstSeenAt;
  await fault(scheduler, "deploy", Date.now() + 5_000);
  const reopened = await spanFor(scheduler, "deploy");
  ok("fault, ok, fault removes clearedAt and keeps firstSeenAt", reopened !== undefined && !("clearedAt" in reopened) && reopened.firstSeenAt === firstSeen && reopened.count === 2);
  await okRec(scheduler, "other");
  ok("a later ok closes only the span of its own destination", typeof (await spanFor(scheduler, "other"))?.clearedAt === "number" && !("clearedAt" in ((await spanFor(scheduler, "deploy")) as Span)));

  // A span covers every downpipe that posted it. Two downpipes fail on one destination: the first to replicate
  // ok does not close the span, because the other still records a failed attempt there. The second one does.
  {
    const { scheduler: two } = makeDO();
    const faultBy = (dp: string, at: number): Promise<Response> => post(two, "/seal-fault", { kind: "replica-target-fault", at, downpipeId: dp, destinationId: "deploy", replicaReason: "not-configured" });
    const rec = (dp: string, okNow: boolean): Promise<Response> => post(two, "/replication/record", okNow ? { id: dp, destinationId: "deploy", ok: true, runId: "01R", index: 1 } : { id: dp, destinationId: "deploy", ok: false, reason: "not-configured" });
    await faultBy("dp-a", t0);
    await faultBy("dp-b", t0 + 1);
    await rec("dp-a", false);
    await rec("dp-b", false);
    await rec("dp-a", true);
    ok("one downpipe replicating ok does not close a span another downpipe still fails on", (await spanFor(two, "deploy"))?.clearedAt === undefined);
    await rec("dp-b", true);
    ok("the span closes when the last failing downpipe replicates ok", typeof (await spanFor(two, "deploy"))?.clearedAt === "number");
  }
  // A span whose downpipe list is truncated cannot be checked, so it stays open.
  {
    const truncated = { kind: "replica-target-fault", reasonField: "replicaReason", reason: "not-configured", destinationId: "deploy", count: 40, firstSeenAt: t0, lastSeenAt: t0 + 5, downpipeIds: ["dp-a"], downpipesTruncated: true };
    const { scheduler: tr } = makeDO({ "signal:seal-fault-spans": { spans: [truncated], overflow: 0 } });
    await okRec(tr, "deploy");
    ok("a span with a truncated downpipe list stays open on an ok record", (await spanFor(tr, "deploy"))?.clearedAt === undefined);
  }

  // A span written by 0.3.8 has no clearedAt. It loads, projects unchanged, and an ok record closes it.
  const old = { kind: "replica-target-fault", reasonField: "replicaReason", reason: "not-configured", destinationId: "deploy", count: 3, firstSeenAt: t0, lastSeenAt: t0 + 5 };
  const { scheduler: s38 } = makeDO({ "signal:seal-fault-spans": { spans: [old], overflow: 0 } });
  const loaded = await spanFor(s38, "deploy");
  ok("a 0.3.8-shaped span with no clearedAt loads and projects without it", loaded !== undefined && !("clearedAt" in loaded) && loaded.count === 3 && loaded.firstSeenAt === t0 && loaded.lastSeenAt === t0 + 5);
  await okRec(s38, "deploy");
  ok("an ok record closes a 0.3.8-shaped span", typeof (await spanFor(s38, "deploy"))?.clearedAt === "number");

  // ringOldestAt is the oldest row's at, absent for an empty ring, and present when no span covers the ring.
  const { scheduler: empty } = makeDO();
  ok("an empty ring carries no ringOldestAt", !("ringOldestAt" in ((await fetchSealFaultSpans(empty)) as Span)));
  const { scheduler: r } = makeDO();
  await post(r, "/seal-fault", { kind: "lease-lost-abandon", at: t0 + 30, runId: "r2" });
  await post(r, "/seal-fault", { kind: "lease-lost-abandon", at: t0 + 10, runId: "r1" });
  await post(r, "/seal-fault", { kind: "lease-lost-abandon", at: t0 + 20, runId: "r3" });
  const ringRows = (await fetchSealFaults(r)) as Array<{ at: number }>;
  const section = (await fetchSealFaultSpans(r)) as Span;
  ok("ringOldestAt equals the at of the oldest row in the ring", section.ringOldestAt === Math.min(...ringRows.map((x) => x.at)) && section.ringOldestAt === t0 + 10);
  const { scheduler: ringOnly } = makeDO({ "signal:seal-faults": [{ kind: "lease-lost-abandon", at: t0 }] });
  const ro = (await fetchSealFaultSpans(ringOnly)) as Span;
  ok("a ring with rows and no spans still carries ringOldestAt and seeds no span", ro.ringOldestAt === t0 && !("spans" in ro));
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
  await stamps();
  await joined();
  await closing();
  await runDestination();
  await strands();
  console.log(failures === 0 ? "\nBUNDLE FAULT EVIDENCE PASS\n" : `\nBUNDLE FAULT EVIDENCE FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
