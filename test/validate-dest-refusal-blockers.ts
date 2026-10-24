// validate-dest-refusal-blockers: a REFUSED clear of the default destination, and a REFUSED plural remove, leave a
// row in the support pack's configEvents that says what blocked them.
//
// The engine refuses to clear the default or to remove a destination while downpipes name it (in use) or while it
// holds the only proven copy of some runs (orphan guard). The refusal was a 400 and a counter: a pack could not say
// which destination, which downpipes pinned it, or how many runs were at risk. Each refusal now writes ONE failed
// dest-config-cleared row carrying the destination id, the count and ids of the pinned downpipes, the count of runs
// that would lose their only proven copy, and the closed refusal class. The plural remove also records forced.
//
// This drives the PRODUCTION handleAdmin over an in-memory SchedulerDO and reads the pack's own configEvents
// projection (fetchConfigEvents). It checks the row's fields, that a refused clear writes one row and not two, and
// that no downpipe name, bucket, endpoint or sentence rides.
//
// Run: node test/validate-dest-refusal-blockers.ts

import { handleAdmin } from "../src/admin/router.ts";
import { fetchConfigEvents } from "../src/admin/support-sections-audit.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 600)}`);
  }
}

const TOKEN = "bg-token-dest-blockers";
const A = "dest-aaaaaaa1";
const B = "dest-bbbbbbb2";
const C = "dest-ccccccc3";
const BUCKET_PREFIX = "customer-private-bucket";
const NAME_ONE = "Payroll Archive One";
const NAME_TWO = "Payroll Archive Two";

function storedDest(id: string): Record<string, unknown> {
  return { id, label: id, endpoint: "https://acct.r2.cloudflarestorage.com", bucket: `${BUCKET_PREFIX}-${id}`, region: "auto", accessKeyId: "AK", secretAccessKey: "SK", setAt: 1, setBy: "owner@acme.example", verifiedAt: 1, deleteProbe: "ok" };
}
function downpipe(id: string, name: string, destinationIds: string[] | undefined, sealedRuns: number): Record<string, unknown> {
  return { config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, ...(destinationIds !== undefined ? { destinationIds } : {}) }, nextRunAt: 0, lastRunId: "r5", inFlight: false, sealedRuns };
}
function row(index: number, origin: string): Record<string, unknown> {
  return { runId: `r${index}`, index, startedAt: "2026-09-27T08:00:00.000Z", status: "ok", destinationId: origin };
}

interface Rig {
  env: Env;
  storage: MockStorage;
  stub: DurableObjectStub;
}
function makeRig(setup: (s: MockStorage) => void): Rig {
  const storage = new MockStorage();
  setup(storage);
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { env: { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN } as unknown as Env, storage, stub };
}

async function call(env: Env, path: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const resp = await handleAdmin(new Request(`https://engine.example${path}`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body) }), env);
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (await resp.json()) as Record<string, unknown>;
  } catch {
    /* a body that is not JSON stays empty */
  }
  return { status: resp.status, body: parsed };
}

type Ev = Record<string, unknown>;
async function refusalRows(stub: DurableObjectStub): Promise<Ev[]> {
  const { events } = await fetchConfigEvents(stub);
  return (events as Ev[]).filter((e) => e.action === "dest-config-cleared" && e.refusal !== undefined);
}

async function main(): Promise<void> {
  console.log("validate-dest-refusal-blockers\n");

  console.log("-- a refused clear: two downpipes pin the default --");
  {
    const r = makeRig((s) => {
      s.seed("destinations", { list: [storedDest(A), storedDest(B)], defaultId: A });
      s.seed("dp:p2", downpipe("p2", NAME_TWO, [A], 0));
      s.seed("dp:p1", downpipe("p1", NAME_ONE, [A, B], 0));
    });
    const res = await call(r.env, "/admin/destination", { config: null });
    ok("the clear is refused 400", res.status === 400, res);
    const rows = await refusalRows(r.stub);
    ok("exactly one refusal row is written", rows.length === 1, rows);
    const c = rows[0];
    ok("the row is failed, with class clear-in-use", c?.outcome === "failed" && c?.refusal === "clear-in-use", c);
    ok("the row names the destination id", c?.id === A, c);
    ok("the row counts the pinned downpipes: 2", c?.pinnedDownpipeCount === 2, c);
    ok("the row lists the pinned downpipe ids", JSON.stringify(c?.pinnedDownpipeIds) === JSON.stringify(["p1", "p2"]), c);
    ok("the row counts the runs at risk: 0", c?.atRiskRunCount === 0, c);
    const all = JSON.stringify(rows);
    ok("no downpipe name, bucket or endpoint rides", !all.includes(NAME_ONE) && !all.includes(NAME_TWO) && !all.includes(BUCKET_PREFIX) && !all.includes("r2.cloudflarestorage.com"), all.slice(0, 300));
  }

  console.log("-- a refused clear: the default holds the only proven copy --");
  {
    const r = makeRig((s) => {
      s.seed("destinations", { list: [storedDest(A), storedDest(B)], defaultId: A });
      s.seed("dp:p1", downpipe("p1", NAME_ONE, undefined, 3));
      s.seed("hist:p1", [row(1, A), row(2, A), row(3, A)]);
    });
    const res = await call(r.env, "/admin/destination", { config: null });
    ok("the clear is refused 400", res.status === 400, res);
    const rows = await refusalRows(r.stub);
    const c = rows[0];
    ok("exactly one row, class clear-orphan-guard", rows.length === 1 && c?.refusal === "clear-orphan-guard", rows);
    ok("the row names the destination id and counts 3 runs at risk", c?.id === A && c?.atRiskRunCount === 3, c);
    ok("no downpipe pins it: count 0, no ids", c?.pinnedDownpipeCount === 0 && (c?.pinnedDownpipeIds === undefined || (c.pinnedDownpipeIds as unknown[]).length === 0), c);
  }

  console.log("-- a refused plural remove: two downpipes pin the destination --");
  {
    const r = makeRig((s) => {
      s.seed("destinations", { list: [storedDest(A), storedDest(B)], defaultId: B });
      s.seed("dp:p1", downpipe("p1", NAME_ONE, [A], 0));
      s.seed("dp:p2", downpipe("p2", NAME_TWO, [A, B], 0));
    });
    const res = await call(r.env, "/admin/destinations/remove", { id: A });
    ok("the remove is refused 400", res.status === 400, res);
    const rows = await refusalRows(r.stub);
    ok("exactly one refusal row is written", rows.length === 1, rows);
    const c = rows[0];
    ok("the row is failed, op remove, class remove-in-use", c?.outcome === "failed" && c?.op === "remove" && c?.refusal === "remove-in-use", c);
    ok("the row names the destination id", c?.id === A, c);
    ok("the row counts 2 pinned downpipes and lists their ids", c?.pinnedDownpipeCount === 2 && JSON.stringify(c?.pinnedDownpipeIds) === JSON.stringify(["p1", "p2"]), c);
    ok("the row says the remove was not forced", c?.force === false, c);
    ok("the row counts the runs at risk: 0", c?.atRiskRunCount === 0, c);
    const all = JSON.stringify(rows);
    ok("no downpipe name or bucket rides", !all.includes(NAME_ONE) && !all.includes(NAME_TWO) && !all.includes(BUCKET_PREFIX), all.slice(0, 300));
    const forced = await call(r.env, "/admin/destinations/remove", { id: A, force: true });
    ok("force does not override the in-use guard", forced.status === 400, forced);
  }

  console.log("-- a refused plural remove: the destination holds the only proven copy --");
  {
    const r = makeRig((s) => {
      s.seed("destinations", { list: [storedDest(B), storedDest(C)], defaultId: C });
      s.seed("dp:p1", downpipe("p1", NAME_ONE, [C], 3));
      s.seed("hist:p1", [row(1, B), row(3, B), row(5, B)]);
    });
    const res = await call(r.env, "/admin/destinations/remove", { id: B });
    ok("the remove is refused 400", res.status === 400, res);
    const rows = await refusalRows(r.stub);
    const c = rows[0];
    ok("exactly one row, op remove, class remove-orphan-guard", rows.length === 1 && c?.op === "remove" && c?.refusal === "remove-orphan-guard", rows);
    ok("the row names the destination id and counts 3 runs at risk", c?.id === B && c?.atRiskRunCount === 3, c);
    ok("nothing pins it: count 0", c?.pinnedDownpipeCount === 0, c);
    ok("the row says the remove was not forced", c?.force === false, c);
  }

  console.log("-- an action page that cannot be read is a fetch failure, not an excerpt with no events --");
  {
    const auditStub = (actionPage: (action: string) => Response): DurableObjectStub =>
      ({
        async fetch(input: RequestInfo | URL): Promise<Response> {
          const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
          const action = url.searchParams.get("action");
          if (action !== null) return actionPage(action);
          return Response.json({ headSeq: 0, events: [] });
        },
      }) as unknown as DurableObjectStub;
    const outcome = async (stub: DurableObjectStub): Promise<{ threw: boolean; fetched: boolean | null }> => {
      try {
        return { threw: false, fetched: (await fetchConfigEvents(stub)).fetched };
      } catch {
        return { threw: true, fetched: null };
      }
    };
    const healthy = await outcome(auditStub(() => Response.json({ events: [] })));
    ok("control, readable action pages give a fetched excerpt", !healthy.threw && healthy.fetched === true, healthy);
    const http500 = await outcome(auditStub(() => new Response("upstream fault", { status: 500 })));
    ok("an action page answering 500 throws, so the section reads error", http500.threw, http500);
    const notJson = await outcome(auditStub(() => new Response("<html>", { status: 200 })));
    ok("an action page that is not JSON throws, so the section reads error", notJson.threw, notJson);
    const rejects = await outcome({ fetch: async (input: RequestInfo | URL) => (String(input).includes("action=") ? Promise.reject(new Error("DO unreachable")) : Response.json({ headSeq: 0, events: [] })) } as unknown as DurableObjectStub);
    ok("an action page whose fetch rejects throws, so the section reads error", rejects.threw, rejects);
  }

  console.log(failures === 0 ? `\nvalidate-dest-refusal-blockers: ${checks} checks passed` : `\nvalidate-dest-refusal-blockers: ${failures} of ${checks} checks FAILED`);
  verdictReached(failures, checks);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
