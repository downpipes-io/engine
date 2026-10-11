// validate-support-dest-save-refusal: a REFUSED destination save, and a refused clear of the default
// destination, leave a row in the support pack's configEvents.
//
// POST /admin/destinations (add or edit) and POST /admin/destination (the singular set, and {config:null}
// the singular clear) answer 400 at many points: an endpoint that is not https, a private address, missing
// fields, an unsupported storage class, a provider field the store cannot honour, the live write probe
// failing, a misconfigured CONFIG_WRAP_KEY, a WORM policy the bucket cannot enforce, and (on the clear) a
// default that downpipes still name. Each one used to be a 400 into a browser and nothing else, so a pack
// from a customer who had tried three times showed no attempt at all.
//
// This drives the PRODUCTION handleAdmin over an in-memory SchedulerDO with a stub for the S3 endpoint, then
// reads the pack's own configEvents projection (fetchConfigEvents). It checks:
//   - each refusal writes ONE failed dest-config-set / dest-config-cleared row carrying a CLOSED refusal
//     class, the provider when the endpoint names one, the destination id on an edit, the probe's closed
//     failure class and HTTP status on a probe failure, and the time;
//   - the row carries no endpoint, bucket, key, secret or message text;
//   - a retry loop writes one row per class per window, and the rows in an hour are capped.
//
// Run: node test/validate-support-dest-save-refusal.ts

import { handleAdmin } from "../src/admin/router.ts";
import { fetchConfigEvents } from "../src/admin/support-sections-audit.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 500)}`);
  }
}

const TOKEN = "bg-token-dest-refusal";
const R2_HOST = "acct.r2.cloudflarestorage.com";
const GOOD_ENDPOINT = `https://${R2_HOST}`;
const SECRET = "SKEY-must-never-ride";
const BUCKET = "customer-private-bucket-name";
let probeMode: "ok" | "deny" = "ok";

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const host = new URL(url).host;
  if (host === R2_HOST || host.endsWith(`.${R2_HOST}`)) {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "HEAD") return new Response(null, { status: 404 });
    if (method === "PUT") return probeMode === "deny" ? new Response("AccessDenied", { status: 403 }) : new Response(null, { status: 200, headers: { etag: '"p"' } });
    if (method === "DELETE") return new Response(null, { status: 204 });
    if (method === "GET") return url.includes("object-lock") ? new Response("<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>", { status: 200 }) : new Response("", { status: 200, headers: { etag: '"x"' } });
    return new Response(null, { status: 200 });
  }
  throw new Error(`unexpected network fetch in test: ${url}`);
}) as typeof fetch;

function makeScheduler(): { env: Env; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
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
  return (events as Ev[]).filter((e) => (e.action === "dest-config-set" || e.action === "dest-config-cleared") && e.refusal !== undefined);
}
const cfg = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({ endpoint: GOOD_ENDPOINT, bucket: BUCKET, region: "auto", accessKeyId: "AKID", secretAccessKey: SECRET, ...extra });

async function main(): Promise<void> {
  console.log("validate-support-dest-save-refusal\n");
  const s = makeScheduler();
  const { env, stub } = s;

  console.log("-- an add refused before the probe --");
  const r1 = await call(env, "/admin/destinations", { label: "Offsite", config: cfg({ endpoint: "http://insecure.example.com" }) });
  ok("an http endpoint is refused 400", r1.status === 400);
  let rows = await refusalRows(stub);
  const a = rows.find((e) => e.refusal === "endpoint-not-https");
  ok("the pack shows a failed dest-config-set row with refusal endpoint-not-https", a !== undefined && a.action === "dest-config-set" && a.outcome === "failed", rows);
  ok("an add carries no destination id", a !== undefined && a.id === undefined);
  ok("the row carries its time", typeof a?.at === "string" && !Number.isNaN(Date.parse(a.at as string)));

  const r2 = await call(env, "/admin/destinations", { label: "Offsite", config: cfg({ endpoint: "https://169.254.169.254" }) });
  ok("a private address is refused 400", r2.status === 400);
  rows = await refusalRows(stub);
  ok("the refusal class is endpoint-private", rows.some((e) => e.refusal === "endpoint-private"), rows);

  const r3 = await call(env, "/admin/destinations", { label: "Offsite", config: cfg({ accessKeyId: "" }) });
  ok("missing credentials are refused 400", r3.status === 400);
  rows = await refusalRows(stub);
  ok("the refusal class is missing-fields", rows.some((e) => e.refusal === "missing-fields"), rows);

  const r4 = await call(env, "/admin/destinations", { label: "Offsite", config: cfg({ storageClass: "GLACIER" }) });
  ok("an unsupported storage class is refused 400", r4.status === 400);
  rows = await refusalRows(stub);
  ok("the refusal class is storage-class-unsupported", rows.some((e) => e.refusal === "storage-class-unsupported"), rows);

  const r5 = await call(env, "/admin/destinations", { label: "GCS", config: cfg({ endpoint: "https://storage.googleapis.com", storageClass: "STANDARD" }) });
  ok("a storage class on a Google Cloud Storage endpoint is refused 400", r5.status === 400);
  rows = await refusalRows(stub);
  const g = rows.find((e) => e.refusal === "provider-field-refused");
  ok("the refusal class is provider-field-refused and names the provider gcs", g !== undefined && g.provider === "gcs", rows);

  console.log("-- an edit refused by the live write probe --");
  probeMode = "deny";
  const r6 = await call(env, "/admin/destinations", { id: "dest-0123abcd", label: "Offsite", config: cfg() });
  ok("a destination whose write probe fails is refused 400", r6.status === 400);
  rows = await refusalRows(stub);
  const p = rows.find((e) => e.refusal === "probe-failed");
  ok("the pack shows refusal probe-failed", p !== undefined, rows);
  ok("the edit carries the destination id", p?.id === "dest-0123abcd", p);
  ok("the probe's closed failure class and HTTP status ride", p?.probeClass === "auth-refused" && p?.probeStatus === 403, p);
  ok("the provider r2 rides", p?.provider === "r2", p);
  probeMode = "ok";

  console.log("-- the singular set --");
  const r7 = await call(env, "/admin/destination", { config: cfg({ endpoint: "http://insecure.example.com" }) });
  ok("the singular set with an http endpoint is refused 400", r7.status === 400);

  console.log("-- a refused clear of the default --");
  await s.storage.put("destinations", { list: [{ id: "deploy", label: "Deploy", source: "deploy", endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }], defaultId: "deploy" });
  await s.storage.put("dp:pinned", { config: { id: "pinned", name: "Pinned", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_X", include: [], exclude: [] }, destinationId: "deploy" }, nextRunAt: 0, lastRunId: null, inFlight: false });
  const r8 = await call(env, "/admin/destination", { config: null });
  ok("a clear of a default that a downpipe names is refused 400", r8.status === 400);
  rows = await refusalRows(stub);
  const c = rows.find((e) => e.action === "dest-config-cleared");
  ok("the pack shows a failed dest-config-cleared row", c !== undefined && c.outcome === "failed", rows);
  ok("its refusal class is clear-in-use", c?.refusal === "clear-in-use", c);

  console.log("-- no secret, name or message rides --");
  const all = JSON.stringify(rows);
  ok("no secret, bucket, endpoint host or message text in any refusal row", !all.includes(SECRET) && !all.includes(BUCKET) && !all.includes("insecure.example.com") && !all.includes("169.254") && !all.includes("storage.googleapis.com") && !all.includes("AccessDenied"), all.slice(0, 300));

  console.log("-- a retry loop is capped --");
  const before = (await refusalRows(stub)).filter((e) => e.refusal === "endpoint-not-https").length;
  for (let i = 0; i < 12; i++) await call(env, "/admin/destinations", { label: "Offsite", config: cfg({ endpoint: "http://insecure.example.com" }) });
  const after = (await refusalRows(stub)).filter((e) => e.refusal === "endpoint-not-https").length;
  ok("the first refusal of that class had written exactly one row", before === 1, { before });
  ok("twelve more identical refusals in the same minute add no further row", after === before, { before, after });

  console.log("-- the hourly ceiling --");
  const gate = await import("../src/sched/dest-refusal-gate.ts").catch(() => null);
  ok("the refusal-row gate module exists", gate !== null);
  if (gate !== null) {
    let state = gate.emptyDestRefusalGate();
    let admitted = 0;
    for (let i = 0; i < 100; i++) {
      const v = gate.admitDestRefusalRow(state, `class-${i}`, 1_000_000 + i * 1000);
      state = v.state;
      if (v.admit) admitted++;
    }
    ok("a hundred distinct-class refusals inside one hour admit at most the hourly ceiling", admitted === gate.DEST_REFUSAL_ROWS_PER_HOUR && admitted > 0, { admitted });
    const later = gate.admitDestRefusalRow(state, "class-0", 1_000_000 + 3_700_000 * 2);
    ok("the ceiling reopens in the next hour", later.admit === true);
  }

  console.log(failures === 0 ? `\nvalidate-support-dest-save-refusal: ${checks} checks passed` : `\nvalidate-support-dest-save-refusal: ${failures} of ${checks} checks FAILED`);
  verdictReached(failures, checks);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
