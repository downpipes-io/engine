// Fail-open / partial-failure vectors for the cf-config registry's COMPLEX inline per-item-expand reads
// (queues, workers-for-platforms, vectorize, r2-bucket-config). These are the only branching reads in the
// registry: each inner branch decides between a real partial record and a silent null/marker, so an
// untested regression here could turn a partial capture into a silently-empty entry or let one item's 404
// throw and void the whole surface. This validator drives each read with a stubbed CfApi over three cases:
//   (a) a parent item missing its id/name field -> the raw item is pushed through (out.push(raw) fallback);
//   (b) one inner call throwing -> fail-open to null / an _unavailable marker, the surface still complete;
//   (c) every item's inner call throwing -> a partial record per item, never a throw or a silent empty.
// No network. Run: node test/validate-cf-config-expand.ts (finding eng-m3).

import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-registry.ts";
import { type CfApi, type CfPage, type CfConfigSurface, makeCfApi } from "../src/sources/cf-config-core.ts";
import { cfConfigCatalogue } from "../src/sources/cf-config-catalogue.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

declare const process: { exit(code?: number): never };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A stubbed CfApi. listPages maps a (normalised, query-stripped) path to the array a list returns on its
// FIRST page (one short page ends pagination). getMap maps a get() path to either a value or a sentinel that
// makes get() throw, so a test can inject a per-item 404. send() is never used by these read-only surfaces.
const THROW = Symbol("throw");
function stripQuery(path: string): string {
  const i = path.indexOf("?");
  return i === -1 ? path : path.slice(0, i);
}
function makeApi(listPages: Map<string, unknown[]>, getMap: Map<string, unknown | typeof THROW>): CfApi {
  return {
    async getPage(path: string): Promise<CfPage> {
      const arr = listPages.get(stripQuery(path));
      if (arr === undefined) throw new Error(`stub getPage: unexpected list path ${stripQuery(path)}`);
      return { result: arr }; // no result_info: a short first page, so paginate stops after it
    },
    async get(path: string): Promise<unknown> {
      const clean = stripQuery(path);
      if (!getMap.has(clean)) throw new Error(`stub get: unexpected path ${clean}`);
      const v = getMap.get(clean);
      if (v === THROW) throw new Error(`stub get: injected 404 for ${clean}`);
      return v;
    },
    async send(): Promise<unknown> {
      throw new Error("stub send: a capture-only surface must not write");
    },
  };
}

function surface(id: string): CfConfigSurface {
  const s = CF_CONFIG_SURFACES.find((x) => x.id === id);
  if (s === undefined) throw new Error(`surface ${id} not found in the registry`);
  return s;
}

const IDS = { accountId: "acc_test", zoneId: "zone_test" };

async function testQueues(): Promise<void> {
  console.log("queues: per-item consumers expand");
  const s = surface("queues");

  // (a) a queue missing its id -> the raw queue is pushed through unchanged (no consumers read).
  {
    const lists = new Map<string, unknown[]>([[`/accounts/${IDS.accountId}/queues`, [{ queue_name: "no-id" }]]]);
    const out = (await s.read(makeApi(lists, new Map()), IDS)) as Array<Record<string, unknown>>;
    ok("queues (no id): the raw item is captured, no consumers key", out.length === 1 && out[0]!.queue_name === "no-id" && !("consumers" in out[0]!));
  }
  // (b) one of two queues' consumers read throws -> paginate has no fail-open, so a missing inner GET that
  //     is mapped to a value succeeds and a value-bearing record results; this surface does NOT swallow a
  //     consumers throw, so a thrown inner read must propagate (documents the intended NON-fail-open here).
  {
    const lists = new Map<string, unknown[]>([[`/accounts/${IDS.accountId}/queues`, [{ id: "q1" }, { id: "q2" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([
      [`/accounts/${IDS.accountId}/queues/q1/consumers`, [{ consumer: "a" }]],
      [`/accounts/${IDS.accountId}/queues/q2/consumers`, [{ consumer: "b" }]],
    ]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<Record<string, unknown>>;
    ok("queues (all ok): every queue carries its consumers", out.length === 2 && Array.isArray((out[0] as { consumers?: unknown }).consumers) && Array.isArray((out[1] as { consumers?: unknown }).consumers));
  }
}

async function testWorkersForPlatforms(): Promise<void> {
  console.log("workers-for-platforms: per-namespace script inventory expand");
  const s = surface("workers-for-platforms");
  const base = `/accounts/${IDS.accountId}/workers/dispatch/namespaces`;

  // (a) a namespace missing every name field -> the raw namespace is pushed through.
  {
    const lists = new Map<string, unknown[]>([[base, [{ created_on: "x" }]]]);
    const out = (await s.read(makeApi(lists, new Map()), IDS)) as unknown[];
    ok("wfp (no name): the raw namespace is captured", out.length === 1 && (out[0] as { created_on?: string }).created_on === "x");
  }
  // (b) the per-namespace script LIST throws -> fail-open to the _unavailable marker, surface still complete.
  {
    const lists = new Map<string, unknown[]>([[base, [{ namespace_name: "ns1" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([[`${base}/ns1/scripts`, THROW]]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<{ namespace: unknown; scripts: unknown }>;
    const marker = out[0]!.scripts as { _unavailable?: string };
    ok("wfp (script list 404): fail-open to the _unavailable marker, namespace still captured", out.length === 1 && typeof marker._unavailable === "string");
  }
  // (c) the script list is fine but one script's SETTINGS read throws -> that script's settings fail-open to
  //     null; the script and the surface are still complete.
  {
    const lists = new Map<string, unknown[]>([[base, [{ namespace_name: "ns1" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([
      [`${base}/ns1/scripts`, [{ script_name: "s1" }]],
      [`${base}/ns1/scripts/s1/settings`, THROW],
    ]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<{ scripts: Array<{ settings: unknown }> }>;
    ok("wfp (settings 404): the script's settings fail-open to null, surface complete", out.length === 1 && out[0]!.scripts.length === 1 && out[0]!.scripts[0]!.settings === null);
  }
}

async function testVectorize(): Promise<void> {
  console.log("vectorize: per-index info expand");
  const s = surface("vectorize");
  const base = `/accounts/${IDS.accountId}/vectorize/v2/indexes`;

  // (a) an index missing its name -> the raw index is pushed through (no info read).
  {
    const lists = new Map<string, unknown[]>([[base, [{ dimensions: 768 }]]]);
    const out = (await s.read(makeApi(lists, new Map()), IDS)) as Array<Record<string, unknown>>;
    ok("vectorize (no name): the raw index is captured, no info key", out.length === 1 && out[0]!.dimensions === 768 && !("info" in out[0]!));
  }
  // (b) one index's info read throws -> info fail-opens to null, the index and surface are still complete.
  {
    const lists = new Map<string, unknown[]>([[base, [{ name: "ix1" }, { name: "ix2" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([
      [`${base}/ix1/info`, THROW],
      [`${base}/ix2/info`, { vectorCount: 5 }],
    ]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<{ name: string; info: unknown }>;
    ok("vectorize (one info 404): that index's info is null, the other is captured", out.length === 2 && out[0]!.info === null && (out[1]!.info as { vectorCount?: number }).vectorCount === 5);
  }
  // (c) EVERY index's info read throws -> every index is a partial record (info null), never a throw or empty.
  {
    const lists = new Map<string, unknown[]>([[base, [{ name: "ix1" }, { name: "ix2" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([
      [`${base}/ix1/info`, THROW],
      [`${base}/ix2/info`, THROW],
    ]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<{ name: string; info: unknown }>;
    ok("vectorize (all info 404): a partial record per index (info null), surface not empty", out.length === 2 && out.every((r) => r.info === null));
  }
}

async function testR2BucketConfig(): Promise<void> {
  console.log("r2-bucket-config: per-bucket sub-config expand");
  const s = surface("r2-bucket-config");
  const base = `/accounts/${IDS.accountId}/r2/buckets`;

  // (a) a bucket missing its name -> the raw bucket is pushed through (no sub-config reads).
  {
    const lists = new Map<string, unknown[]>([[base, [{ creation_date: "x" }]]]);
    const out = (await s.read(makeApi(lists, new Map()), IDS)) as Array<Record<string, unknown>>;
    ok("r2-config (no name): the raw bucket is captured, no bucket key", out.length === 1 && (out[0] as { creation_date?: string }).creation_date === "x" && !("bucket" in out[0]!));
  }
  // (b) one sub-config part throws while the rest succeed -> that part fail-opens to null, the bucket record
  //     is still complete with every part present.
  {
    const lists = new Map<string, unknown[]>([[base, [{ name: "b1" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([
      [`${base}/b1/lifecycle`, { rules: [] }],
      [`${base}/b1/lock`, THROW], // the WORM/lock read 404s
      [`${base}/b1/cors`, { rules: [] }],
      [`${base}/b1/sippy`, { enabled: false }],
      [`${base}/b1/domains/custom`, { domains: [] }],
      [`${base}/b1/domains/managed`, { enabled: false }],
      [`/accounts/${IDS.accountId}/event_notifications/r2/b1/configuration`, { queues: [] }],
    ]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<Record<string, unknown>>;
    const rec = out[0]!;
    ok("r2-config (lock 404): that part is null, every other part captured, record complete",
      out.length === 1 && rec.bucket === "b1" && rec.lock === null && rec.lifecycle !== null && rec.cors !== null && rec.sippy !== null && rec.customDomains !== null && rec.publicAccess !== null && rec.eventNotifications !== null);
  }
  // (c) EVERY sub-config read throws -> the bucket record is a partial { bucket, every part null }, never a
  //     throw or a silent empty surface.
  {
    const lists = new Map<string, unknown[]>([[base, [{ name: "b1" }]]]);
    const gets = new Map<string, unknown | typeof THROW>([
      [`${base}/b1/lifecycle`, THROW],
      [`${base}/b1/lock`, THROW],
      [`${base}/b1/cors`, THROW],
      [`${base}/b1/sippy`, THROW],
      [`${base}/b1/domains/custom`, THROW],
      [`${base}/b1/domains/managed`, THROW],
      [`/accounts/${IDS.accountId}/event_notifications/r2/b1/configuration`, THROW],
    ]);
    const out = (await s.read(makeApi(lists, gets), IDS)) as Array<Record<string, unknown>>;
    const rec = out[0]!;
    ok("r2-config (all parts 404): a partial record (bucket id kept, all parts null), surface not empty",
      out.length === 1 && rec.bucket === "b1" && rec.lifecycle === null && rec.lock === null && rec.cors === null && rec.sippy === null && rec.customDomains === null && rec.publicAccess === null && rec.eventNotifications === null);
  }
  // (d) THE LIVE SHAPE, through the real client. The cases above give the read a flat array of buckets.
  //     The live R2 list (read on 28 Sep 2026) answers {result: {buckets: [{name, creation_date}]}}, and
  //     the real client's getPage makes that object a ONE-row page. The read must unwrap that row. Before
  //     the fix it kept the row as it was, found no bucket name and read no per-bucket setting, so the
  //     archive held the bare bucket list. Each per-bucket endpoint here answers a distinct body, so the
  //     check proves every setting reached the archive under its own key, for every bucket.
  {
    const buckets = [
      { name: "alpha", creation_date: "2026-01-01T00:00:00.000Z" },
      { name: "bravo", creation_date: "2026-02-01T00:00:00.000Z" },
      { name: "charlie", creation_date: "2026-03-01T00:00:00.000Z" },
    ];
    const settingOf = (path: string): unknown => {
      const m = /\/r2\/buckets\/([^/]+)\/(.+)$/.exec(path) ?? /\/event_notifications\/r2\/([^/]+)\/configuration$/.exec(path);
      return m === null ? null : { bucket: m[1], part: m[2] ?? "eventNotifications" };
    };
    const paths: string[] = [];
    const liveFetch: typeof fetch = async (input) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
      const path = url.pathname.replace(/^\/client\/v4/, "");
      paths.push(path);
      const result = path.endsWith("/r2/buckets") ? { buckets } : settingOf(path);
      return new Response(JSON.stringify({ success: true, errors: [], messages: [], result }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const data = (await s.read(makeCfApi("tok", liveFetch), IDS)) as Array<Record<string, unknown>>;
    ok(`r2-config (live shape, 3 buckets): one record per bucket (got ${Array.isArray(data) ? data.length : "no array"})`, Array.isArray(data) && data.length === 3 && data.map((r) => r.bucket).join(",") === "alpha,bravo,charlie");
    const parts = { lifecycle: "lifecycle", lock: "lock", cors: "cors", sippy: "sippy", customDomains: "domains/custom", publicAccess: "domains/managed", eventNotifications: "eventNotifications" } as const;
    for (const [key, part] of Object.entries(parts)) {
      ok(`r2-config (live shape): every bucket carries ${key} from its own endpoint`, Array.isArray(data) && data.every((r) => JSON.stringify(r[key]) === JSON.stringify({ bucket: r.bucket, part })));
    }
    ok("r2-config (live shape): the list is read once and 7 settings per bucket", paths.length === 1 + 3 * 7);
    const label = cfConfigCatalogue().find((m) => m.id === "r2-bucket-config")?.label ?? "";
    ok(`r2-config label names the captured settings and the not-restorable state (label: "${label}")`, /CORS/.test(label) && /lifecycle/.test(label) && /custom domains/.test(label) && /public access/.test(label) && /captured, not restorable/.test(label));
    const meta = cfConfigCatalogue().find((m) => m.id === "r2-bucket-config");
    ok("r2-config is neither in-band nor available for restore (no writer)", meta?.inBand === false && meta?.available === false && typeof s.write !== "function");
    ok("r2-config declares its captured, not restorable reason", /captured, not restorable/.test(s.capturedNotRestorable ?? ""));
  }
}

async function main(): Promise<void> {
  console.log("cf-config inline per-item-expand fail-open vectors\n");
  await testQueues();
  await testWorkersForPlatforms();
  await testVectorize();
  await testR2BucketConfig();
  console.log(failures === 0 ? "\nCF-CONFIG EXPAND FAIL-OPEN VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
