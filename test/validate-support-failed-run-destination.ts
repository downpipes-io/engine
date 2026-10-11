// Validates that a FAILED run names the destination it was writing to, and that a destination fault names
// the destination that produced it, in the support pack:
//   A. a failed completion that carries the destination it attempted is recorded on the run row, and the pack
//      projects it as destinationId with a closed destinationIdBasis (attempted | pinned | default | unknown);
//   B. a failed completion posted before any destination was resolved carries the downpipe's pinned id with
//      basis "pinned", or no id and basis "unknown";
//   C. an ok row still reads exactly as before, and a failed row with no attribution reads basis "unknown";
//   D. destFaults entries name the destination id the faulting run wrote to;
//   E. REDACTION: a value outside the closed vocabulary or the id shape never reaches the pack.
//
// It drives the real SchedulerDO over an in-memory storage double. No network.
// Run: node test/validate-support-failed-run-destination.ts

import { fetchRunHistory } from "../src/admin/support-sections-runs.ts";
import { fetchDestFaults } from "../src/admin/support-sections-diag.ts";
import { postFailedCompletion } from "../src/index.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { reportRunFaults } from "../src/seal/run-fault-report.ts";
import type { Destination } from "../src/dest/types.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const SENTINEL = "acme-payroll-bucket";
const DP: DownpipeState = { config: { id: "dp-u", name: "u", enabled: true, cadenceSeconds: 3600, source: { type: "kv", namespaceId: "ns" } }, nextRunAt: 0, lastRunId: null, inFlight: false } as unknown as DownpipeState;

function makeDO(): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  storage.seed("dp:dp-u", DP);
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  return { storage, scheduler };
}
async function post(s: DurableObjectStub, path: string, body: unknown): Promise<Response> {
  return s.fetch(`https://scheduler.internal${path}`, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
}
async function failedRun(s: DurableObjectStub, extra: Record<string, unknown>): Promise<void> {
  const t = (await (await post(s, "/trigger", { id: "dp-u" })).json()) as { index: number };
  await post(s, "/complete", { id: "dp-u", runId: "", index: t.index, status: "failed", error: "destination rejected the write (Unauthorized)", ...extra });
}
async function rows(s: DurableObjectStub): Promise<Array<Record<string, unknown>>> {
  return ((await fetchRunHistory(s, new Set(["deploy", "dest-81ddfcc4"])))["dp-u"] ?? []) as Array<Record<string, unknown>>;
}

async function runRows(): Promise<void> {
  console.log("-- A. a failed run names the destination it attempted --");
  const a = makeDO();
  await failedRun(a.scheduler, { attemptedDestinationId: "dest-81ddfcc4", attemptedDestinationBasis: "attempted" });
  const r = (await rows(a.scheduler))[0] ?? {};
  ok("the failed row carries destinationId", r.destinationId === "dest-81ddfcc4");
  ok("the failed row carries destinationIdBasis attempted", r.destinationIdBasis === "attempted");
  ok("the failed row still reads not-sealed (it sealed nowhere)", r.destinationBasis === "not-sealed");

  console.log("-- B. a failure before any destination resolved --");
  const stub = (posts: Array<Record<string, unknown>>): DurableObjectStub => ({ fetch: async (_u: unknown, init?: RequestInit) => { posts.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>); return Response.json({ ok: true }); } }) as unknown as DurableObjectStub;
  const p1: Array<Record<string, unknown>> = [];
  await postFailedCompletion(stub(p1), { id: "dp-u", index: 1, error: "destination configuration unreadable", destinationId: "dest-81ddfcc4", destinationIdBasis: "pinned" } as never);
  ok("the pre-resolution completion posts the pinned id", p1[0]?.attemptedDestinationId === "dest-81ddfcc4" && p1[0]?.attemptedDestinationBasis === "pinned");
  const p2: Array<Record<string, unknown>> = [];
  await postFailedCompletion(stub(p2), { id: "dp-u", index: 1, error: "destination configuration unreadable", destinationIdBasis: "unknown" } as never);
  ok("with no pin it posts no id and basis unknown", p2[0]?.attemptedDestinationId === undefined && p2[0]?.attemptedDestinationBasis === "unknown");
  const b = makeDO();
  await failedRun(b.scheduler, { attemptedDestinationId: "dest-81ddfcc4", attemptedDestinationBasis: "pinned" });
  const rb = (await rows(b.scheduler))[0] ?? {};
  ok("the pack shows pinned", rb.destinationId === "dest-81ddfcc4" && rb.destinationIdBasis === "pinned");
  const bd = makeDO();
  await failedRun(bd.scheduler, { attemptedDestinationId: "deploy", attemptedDestinationBasis: "default" });
  ok("the pack shows default", (await rows(bd.scheduler))[0]?.destinationIdBasis === "default");

  console.log("-- C. unattributed and ok rows --");
  const c = makeDO();
  await failedRun(c.scheduler, {});
  const rc = (await rows(c.scheduler))[0] ?? {};
  ok("a failed row with no attribution reads basis unknown and no id", rc.destinationId === undefined && rc.destinationIdBasis === "unknown");
  const t = (await (await post(c.scheduler, "/trigger", { id: "dp-u" })).json()) as { runId: string; index: number };
  await post(c.scheduler, "/complete", { id: "dp-u", runId: t.runId, index: t.index, status: "ok", destinationId: "dest-81ddfcc4", recordCount: 1, bytes: 1 });
  const okRow = (await rows(c.scheduler)).find((x) => x.status === "ok") ?? {};
  ok("an ok row carries its id and no destinationIdBasis", okRow.destinationId === "dest-81ddfcc4" && okRow.destinationIdBasis === undefined);

  console.log("-- E. redaction --");
  const e = makeDO();
  await failedRun(e.scheduler, { attemptedDestinationId: `https://${SENTINEL}.example/x y`, attemptedDestinationBasis: SENTINEL });
  const re = await rows(e.scheduler);
  ok("a non-id value and an out-of-vocabulary basis reach no byte of the pack", !JSON.stringify(re).includes(SENTINEL));
  ok("such a row reads basis unknown", re[0]?.destinationIdBasis === "unknown" && re[0]?.destinationId === undefined);
}

async function destFaults(): Promise<void> {
  console.log("-- D. destFaults names the destination --");
  const { scheduler } = makeDO();
  const dest = {
    destFaults: () => ({ total: 1, overflow: 0, faults: [{ op: "put", httpStatus: 401, s3Code: "AccessDenied", fault: "auth", arm: "matched-status", requestIdPresent: true, wormChecksumComplaint: false, count: 1 }] }),
    destIo: () => ({}),
  } as unknown as Destination;
  await (reportRunFaults as (s: DurableObjectStub, id: string, d?: Destination, destinationId?: string) => Promise<void>)(scheduler, "dp-u", dest, "dest-81ddfcc4");
  const f = (await fetchDestFaults(scheduler)) as Record<string, Record<string, unknown>>;
  ok("POPULATION: the downpipe has a destFaults entry", f["dp-u"] !== undefined && Array.isArray(f["dp-u"]?.faults));
  ok("the entry names the destination id", f["dp-u"]?.destinationId === "dest-81ddfcc4");
  const { scheduler: s2 } = makeDO();
  await (reportRunFaults as (s: DurableObjectStub, id: string, d?: Destination, destinationId?: string) => Promise<void>)(s2, "dp-u", dest, `${SENTINEL}/ x`);
  const f2 = await fetchDestFaults(s2);
  ok("a value that is not an id shape never reaches the pack", !JSON.stringify(f2).includes(SENTINEL) && (f2["dp-u"] as Record<string, unknown> | undefined)?.destinationId === undefined);
  const { scheduler: s3 } = makeDO();
  await reportRunFaults(s3, "dp-u", dest);
  ok("an unattributed fault carries no destinationId", ((await fetchDestFaults(s3))["dp-u"] as Record<string, unknown> | undefined)?.destinationId === undefined);
}

async function main(): Promise<void> {
  await runRows();
  await destFaults();
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
