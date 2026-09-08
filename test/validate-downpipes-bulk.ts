// Prove POST /admin/downpipes/bulk (the many-at-once downpipe create) end to end: the REAL handleAdmin
// against a REAL SchedulerDO over in-memory storage, authenticated with the ADMIN_TOKEN break-glass
// (the token caller resolves to owner, so the downpipe.write gate passes and the route bodies are
// exercised). Covered:
//   1. a clean batch applies every item (per-item "applied", the downpipes are stored and scheduled);
//   2. continue-on-error: an invalid item (bad cadence), an unknown pinned destination and an intra-batch
//      duplicate id each fail as per-item errors WITHOUT voiding their valid siblings;
//   3. an oversized batch is refused WHOLE (400) with the cap echoed as maxBatch, nothing stored;
//   4. the batch cap drops to the gated cap while config approval is ON, and a break-glass (bare-token)
//      caller's items are refused per item (dual control needs an attributable proposer), nothing stored;
//   5. per-item downpipe-create audit rows land for applied and failed items (the DO appends them);
//   6. a non-array / empty body is a 400; the single-create route is untouched by the bulk addition.
// No network, no deploy, no cost. Run:
//   node test/validate-downpipes-bulk.ts

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { BULK_DOWNPIPES_MAX, BULK_DOWNPIPES_MAX_GATED } from "../src/sched/config-validate.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const TOKEN = "bulk-test-admin-token";

function makeEnv(): Env {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN } as unknown as Env;
}

async function call(env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return handleAdmin(new Request(`https://engine.example${path}`, init), env);
}

interface BulkItemResult {
  id: string;
  status: "applied" | "pending" | "error";
  changeId?: string;
  error?: string;
}
interface BulkBody {
  results: BulkItemResult[];
  applied: number;
  pending: number;
  failed: number;
}

function dp(id: string, over?: Record<string, unknown>): Record<string, unknown> {
  return {
    id,
    name: `bulk ${id}`,
    cadenceSeconds: 3600,
    enabled: true,
    // A binding name allows [A-Za-z0-9_] only, so the id's hyphens are folded to underscores.
    source: { type: "kv", binding: `SRC_KV_${id.replace(/-/g, "_")}`, include: [], exclude: [] },
    ...over,
  };
}

async function main(): Promise<void> {
  // ---- 1. clean batch: every item applies, the downpipes are stored ---------------------------
  {
    const env = makeEnv();
    const r = await call(env, "POST", "/admin/downpipes/bulk", { downpipes: [dp("a"), dp("b"), dp("c")] });
    ok("clean batch is 200", r.status === 200);
    const body = (await r.json()) as BulkBody;
    ok("clean batch applies all three", body.applied === 3 && body.pending === 0 && body.failed === 0);
    ok("clean batch results are index-aligned applied", body.results.length === 3 && body.results.every((x, i) => x.status === "applied" && x.id === ["a", "b", "c"][i]));
    const list = (await (await call(env, "GET", "/admin/downpipes")).json()) as DownpipeState[];
    ok("all three downpipes are stored and scheduled", list.length === 3 && list.every((d) => d.nextRunAt > 0));
    // Per-item audit rows: the DO appends one downpipe-create success per applied item.
    const audit = (await (await call(env, "GET", "/admin/audit")).json()) as { events: Array<{ action: string; outcome: string }> };
    const created = audit.events.filter((e) => e.action === "downpipe-create" && e.outcome === "success");
    ok("a downpipe-create success audit row landed per applied item", created.length === 3);
  }

  // ---- 2. continue-on-error: invalid cadence, unknown destination, duplicate id ---------------
  {
    const env = makeEnv();
    const r = await call(env, "POST", "/admin/downpipes/bulk", {
      downpipes: [
        dp("good-one"),
        dp("bad-cadence", { cadenceSeconds: 30 }),
        dp("bad-dest", { destinationIds: ["nope"] }),
        dp("good-one"), // duplicate id within the batch: refused per item, the first wins
        dp("good-two"),
      ],
    });
    ok("mixed batch is 200 (per-item outcomes, not a whole-request failure)", r.status === 200);
    const body = (await r.json()) as BulkBody;
    ok("mixed batch applied exactly the two valid distinct items", body.applied === 2 && body.failed === 3);
    ok("bad cadence fails per item with the validation reason", body.results[1]?.status === "error" && /cadenceSeconds/.test(body.results[1]?.error ?? ""));
    ok("unknown pinned destination fails per item", body.results[2]?.status === "error" && /not a known destination/.test(body.results[2]?.error ?? ""));
    ok("intra-batch duplicate id fails per item", body.results[3]?.status === "error" && /duplicate id/.test(body.results[3]?.error ?? ""));
    const list = (await (await call(env, "GET", "/admin/downpipes")).json()) as DownpipeState[];
    ok("only the valid items were stored", list.length === 2 && list.every((d) => ["good-one", "good-two"].includes(d.config.id)));
    const audit = (await (await call(env, "GET", "/admin/audit")).json()) as { events: Array<{ action: string; outcome: string }> };
    const failed = audit.events.filter((e) => e.action === "downpipe-create" && e.outcome === "failed");
    ok("a downpipe-create failed audit row landed per failed item", failed.length === 3);
  }

  // ---- 3. oversized batch: refused whole with the cap echoed, nothing stored ------------------
  {
    const env = makeEnv();
    const items = Array.from({ length: BULK_DOWNPIPES_MAX + 1 }, (_v, i) => dp(`over-${i}`));
    const r = await call(env, "POST", "/admin/downpipes/bulk", { downpipes: items });
    ok("oversized batch is a 400", r.status === 400);
    const body = (await r.json()) as { error?: string; maxBatch?: number };
    ok("oversized batch echoes the cap as maxBatch", body.maxBatch === BULK_DOWNPIPES_MAX);
    const list = (await (await call(env, "GET", "/admin/downpipes")).json()) as DownpipeState[];
    ok("an oversized batch stores nothing", list.length === 0);
  }

  // ---- 4. gate ON: the cap drops, and break-glass items are refused per item ------------------
  {
    const env = makeEnv();
    const arm = await call(env, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("arming config approval succeeds (owner immediate)", arm.status === 200);
    const over = await call(env, "POST", "/admin/downpipes/bulk", {
      downpipes: Array.from({ length: BULK_DOWNPIPES_MAX_GATED + 1 }, (_v, i) => dp(`g-${i}`)),
    });
    const overBody = (await over.json()) as { maxBatch?: number };
    ok("gated oversize is a 400 echoing the gated cap", over.status === 400 && overBody.maxBatch === BULK_DOWNPIPES_MAX_GATED);
    const r = await call(env, "POST", "/admin/downpipes/bulk", { downpipes: [dp("g-a"), dp("g-b")] });
    ok("gated break-glass batch is 200 with per-item refusals", r.status === 200);
    const body = (await r.json()) as BulkBody;
    ok("gated break-glass items each refuse (dual control needs an attributable proposer)", body.failed === 2 && body.results.every((x) => x.status === "error" && /attributable identity/.test(x.error ?? "")));
    const list = (await (await call(env, "GET", "/admin/downpipes")).json()) as DownpipeState[];
    ok("nothing was stored under the gate", list.length === 0);
  }

  // ---- 5. malformed bodies + the single route is untouched ------------------------------------
  {
    const env = makeEnv();
    const empty = await call(env, "POST", "/admin/downpipes/bulk", { downpipes: [] });
    ok("an empty array is a 400", empty.status === 400);
    const notArray = await call(env, "POST", "/admin/downpipes/bulk", { downpipes: "nope" });
    ok("a non-array is a 400", notArray.status === 400);
    const single = await call(env, "POST", "/admin/downpipes", dp("solo"));
    ok("the single-create route still applies", single.status === 200);
    const list = (await (await call(env, "GET", "/admin/downpipes")).json()) as DownpipeState[];
    ok("the single create stored its downpipe", list.length === 1 && list[0]?.config.id === "solo");
  }

  console.log(failures === 0 ? "validate-downpipes-bulk: ALL OK" : `validate-downpipes-bulk: ${failures} FAILURES`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

void main();
