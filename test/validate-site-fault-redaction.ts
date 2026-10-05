// Site faults must never carry a secret, a token, a key or customer content into the support pack.
//
// One world fires every site-fault path at once, and each path is handed all four kinds of sensitive value:
//   - SECRET:   the ADMIN_TOKEN binding, and the thrown error's message;
//   - TOKEN:    the SCIM_BEARER_TOKEN binding, the error's cause and name, and a forged merge batch;
//   - KEY:      a private key block in the error's stack, an own property, and the BEACON_INGEST_KEY binding;
//   - CUSTOMER: a customer's KV record name and value, which the source adapter lists, the error's message,
//               and a forged merge batch that uses the record name as a site id.
// The paths are the three converted catches (the replica floor write, the rate limiter's health read, the
// KV resume cursor), the drains at their entry points (scheduler fetch, rate limiter fetch, RunSealDO alarm),
// the merge route with a forged batch and with a body that is not JSON, and the pack build.
//
// The pack must carry the evidence (each site row) and none of the four values. DO storage must not hold them
// either, because a later pack reads it.
//
// Run: node test/validate-site-fault-redaction.ts

import type { Env } from "../src/env.d.ts";
import { RateLimitDO } from "../src/sched/ratelimit-do.ts";
import { RunSealDO } from "../src/seal/runseal-do.ts";
import { KVSource } from "../src/sources/kv.ts";
import { namespaceOver, ok, packOver, siteFaultRows, storageText, stubOver, tally } from "./lib/site-fault-proof.ts";
import { makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const SECRET = "u6plant-secret-5b1e0c9a-admin-bearer";
const TOKEN = "u6plant-token-cfat_Zq8rX2pLw9vB4nTkY7mD";
const KEY = "u6plant-key-MC4CAQAwBQYDK2VwBCIEIHh1c2VyLXByaXZhdGUta2V5";
const CUSTOMER = "u6plant-customer-acme-payroll-2026-q3.csv";
const PEM = `-----BEGIN PRIVATE KEY-----\n${KEY}\n-----END PRIVATE KEY-----`;
const PLANTS = { SECRET, TOKEN, KEY, CUSTOMER } as const;

// plantedError carries all four values wherever a careless recorder might read: message, name, stack, cause
// and own properties.
function plantedError(name = "Error"): Error {
  const e = new Error(`write failed for ${CUSTOMER} with bearer ${SECRET}`, { cause: new Error(`token ${TOKEN}`) });
  e.name = name;
  e.stack = `${name}: ${SECRET}\n${PEM}\n    at read (file:///${CUSTOMER}.ts:1:1)`;
  Object.assign(e, { token: TOKEN, key: PEM, record: { name: CUSTOMER, value: `salary for ${CUSTOMER}` } });
  return e;
}

const DESTS = { list: [{ id: "d1", name: "Primary", provider: "r2", bucket: "b1" }, { id: "d2", name: "Replica", provider: "r2", bucket: "b2" }], defaultId: "d1" };

async function main(): Promise<void> {
  const { storage, stub: dobj } = makeScheduler();
  const scheduler = stubOver(dobj);
  await storage.put("destinations", DESTS);

  console.log("site 1: the replica floor write throws (scheduler DO, drained into its own storage):");
  const put = storage.put.bind(storage);
  storage.put = (async (key: unknown, value: unknown) => {
    if (key === "runlogFloor") throw plantedError();
    return put(key as string, value);
  }) as typeof storage.put;
  const rec = await stubFetch(dobj, "POST", "/replication/record", { id: "p1", destinationId: "d2", ok: true, runId: "01JAAAAAAAAAAAAAAAAAAAAAAA", index: 7 });
  ok("the replication record still answers 200", rec.status === 200);

  console.log("site 2: the rate limiter's health read throws (other DO, drained by POST):");
  const rl = new RateLimitDO(
    {
      storage: {
        async get(): Promise<unknown> {
          throw plantedError();
        },
        async put(): Promise<void> {},
      },
    } as unknown as DurableObjectState,
    { CF_API_RATE_PER_SEC: "10", SCHEDULER: namespaceOver(scheduler) } as unknown as { CF_API_RATE_PER_SEC?: unknown },
  );
  await rl.fetch(new Request("https://ratelimit.internal/health"));

  console.log("site 3: KV refuses the resume cursor while it lists a customer's records (drained by the RunSealDO alarm):");
  const kv = {
    async list(opts: { cursor?: string }): Promise<unknown> {
      if (opts.cursor !== undefined) throw plantedError(TOKEN);
      return { keys: [{ name: "k1" }, { name: CUSTOMER, metadata: { note: SECRET } }], list_complete: true };
    },
  } as unknown as KVNamespace;
  const keys: string[] = [];
  for await (const ev of new KVSource(kv, "ns-1").listKeysFrom({ include: [], exclude: [] }, JSON.stringify({ cursor: "c-saved", after: "k1" }))) keys.push(...ev.keys);
  ok("control: the customer's record name really flowed through the source adapter in this isolate", keys.includes(CUSTOMER));
  await new RunSealDO({ storage: { get: async () => undefined } } as unknown as DurableObjectState, { SCHEDULER: namespaceOver(scheduler) } as unknown as Env).alarm();

  console.log("the merge route: a forged batch, and a body that is not JSON:");
  const now = Date.now();
  const forged = await stubFetch(dobj, "POST", "/diag/site-faults", {
    faults: {
      [CUSTOMER]: { count: 1, firstAt: now, lastAt: now, lastCls: "error" },
      "ratelimit.health-read": { count: 1, firstAt: now, lastAt: now, lastCls: TOKEN, note: SECRET },
      "source.kv-resume-cursor": { count: 1, firstAt: 0, lastAt: 0, lastCls: "error", key: PEM, record: CUSTOMER },
    },
    extra: { token: TOKEN, secret: SECRET },
  });
  ok("the forged batch is accepted as a request (the merge filters it; it does not fail)", forged.status === 200);
  await dobj.fetch(new Request("https://scheduler.internal/diag/site-faults", { method: "POST", headers: { "content-type": "application/json" }, body: `{"faults":${JSON.stringify(SECRET)},${TOKEN}` }));

  const env = { ADMIN_TOKEN: SECRET, SCIM_BEARER_TOKEN: TOKEN, BEACON_INGEST_KEY: PEM, RATELIMIT_DO: namespaceOver(stubOver(rl)) } as unknown as Partial<Env>;
  const pack = await packOver(env, scheduler);
  const packText = JSON.stringify(pack);
  const stored = storageText(storage);

  console.log("the evidence is in the pack:");
  const rows = siteFaultRows(pack);
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const id of ["sched.replica-floor-write", "ratelimit.health-read", "source.kv-resume-cursor", "diag.site-fault-post-body"]) ok(`siteFaults names ${id}`, byId.has(id));
  ok("the forged row whose site id is customer content is dropped", !byId.has(CUSTOMER) && rows.every((r) => typeof r.id === "string" && !(r.id as string).startsWith("u6plant")));
  ok("the forged row with a class outside the closed list is dropped (the limiter row counts its two real reads only)", byId.get("ratelimit.health-read")?.count === 2);
  ok("an error whose name is a token is recorded as class other", byId.get("source.kv-resume-cursor")?.cls === "other");
  ok("a forged row with valid fields merges its count only; its extra fields do not ride", byId.get("source.kv-resume-cursor")?.count === 2);
  ok("every row carries only the fixed fields", rows.every((r) => Object.keys(r).sort().join(",") === "cls,count,firstAt,fixClass,id,lastAt,subsystem,what"));

  console.log("none of the planted values is in the pack or in DO storage:");
  for (const [label, value] of Object.entries(PLANTS)) {
    ok(`${label} is not in the pack`, !packText.includes(value));
    ok(`${label} is not in any value the scheduler DO stored`, !stored.includes(value));
  }

  const { failures, checks } = tally();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-site-fault-redaction (${failures} failure(s) of ${checks})`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
