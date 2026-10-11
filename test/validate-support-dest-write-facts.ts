// Validates three destination write facts the support pack must carry:
//
//   A. A refused write on a native R2 destination (an ObjectLocked row) says which CLASS of object the engine
//      was writing: recovery-marker, runlog, segment, manifest or other. The class is derived from the key and
//      the key itself never enters the pack.
//   B. The destination `lock` facts show checksumRequired when the probe learnt that the bucket refuses a write
//      with no checksum.
//   C. A refused save whose write probe was redirected to another region carries the closed regionHint (the AWS
//      region token the engine already reads from a wrong-region redirect), never the Location URL.
//
// No network. The R2 binding, the S3 wire and the scheduler DO are in-memory doubles.
// Run: node test/validate-support-dest-write-facts.ts

import { callerHeaders } from "../src/admin/router-audit.ts";
import type { AuthMethod, Role } from "../src/admin/identity.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { probeDestination } from "../src/admin/router-posture.ts";
import { sanitiseDestFaults } from "../src/admin/run-fault-records.ts";
import { fetchConfigEvents } from "../src/admin/support-sections-audit.ts";
import { fetchDestResolution } from "../src/admin/support-sections-config.ts";
import { fetchDestFaults } from "../src/admin/support-sections-diag.ts";
import { R2Destination } from "../src/dest/r2.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

const SENTINEL_KEY = "seg/acme-payroll-CONFIDENTIAL/ab/abcdef";
const SENTINEL_BUCKET = "acme-payroll-archive-bucket";
const SENTINEL_SECRET = "example-secret-ACMEpayrollSECRET";

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; role: Role };
const OWNER: Caller = { method: "token", email: "owner@acme.example", subject: null, groups: [], role: "owner" };

function makeDO(): { stub: DurableObjectStub; env: Env } {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { stub, env: { SCHEDULER: namespace, ADMIN_TOKEN: "bg-token-write-facts" } as unknown as Env };
}

// ---- A. the key class on an R2 refusal row ----------------------------------------------------------------------

function lockedBucket(): R2Bucket {
  const boom = async (): Promise<never> => {
    throw new Error("put: The object is locked by the bucket policy. (10069)");
  };
  return { put: boom, get: boom, head: boom, delete: boom, list: boom } as unknown as R2Bucket;
}

async function refusedClass(key: string): Promise<{ keyClass?: unknown; s3Code?: unknown; op?: unknown; snap: unknown }> {
  const d = new R2Destination(lockedBucket());
  await d.put(key, new Uint8Array([1])).catch(() => undefined);
  const snap = d.destFaults();
  const row = snap.faults[0] as unknown as Record<string, unknown> | undefined;
  return { keyClass: row?.keyClass, s3Code: row?.s3Code, op: row?.op, snap };
}

async function partA(): Promise<void> {
  console.log("-- A. the key class on an R2 refusal --");
  const cases: Array<[string, string]> = [
    ["_RECOVERY/RUNLOG", "runlog"],
    ["_RECOVERY/RUNLOG.sig", "runlog"],
    ["_RECOVERY/CONTROL-PLANE/000000000007-2026-10-01T00:00:00Z.json", "recovery-marker"],
    ["_RECOVERY/.write-probe", "recovery-marker"],
    [SENTINEL_KEY, "segment"],
    ["run/r-1/manifest/shard-0001.json", "manifest"],
    ["run/r-1/root.manifest.json", "manifest"],
    ["something/else.bin", "other"],
  ];
  for (const [key, want] of cases) {
    const got = await refusedClass(key);
    ok(`a refused put of a ${want} key is one row {put, ObjectLocked, ${want}}`, got.op === "put" && got.s3Code === "ObjectLocked" && got.keyClass === want, got);
  }
  const first = await refusedClass(SENTINEL_KEY);
  ok("the key itself is nowhere in the snapshot", !JSON.stringify(first.snap).includes("payroll") && !JSON.stringify(first.snap).includes("CONFIDENTIAL"));

  const d = new R2Destination(lockedBucket());
  await d.put("_RECOVERY/RUNLOG", new Uint8Array([1])).catch(() => undefined);
  await d.put("_RECOVERY/RUNLOG", new Uint8Array([1])).catch(() => undefined);
  await d.put(SENTINEL_KEY, new Uint8Array([1])).catch(() => undefined);
  const faults = d.destFaults().faults as unknown as Array<Record<string, unknown>>;
  ok("the same op on a different key class is a separate row; a repeat folds into count", faults.length === 2 && faults.find((f) => f.keyClass === "runlog")?.count === 2 && faults.find((f) => f.keyClass === "segment")?.count === 1, faults);

  const gated = sanitiseDestFaults(d.destFaults(), undefined, 1);
  ok("the DO re-gate keeps the key class", (gated?.faults as unknown as Array<Record<string, unknown>> | undefined)?.some((f) => f.keyClass === "runlog") === true);
  const forged = sanitiseDestFaults({ total: 1, faults: [{ op: "put", httpStatus: 0, s3Code: "ObjectLocked", fault: "permanent", arm: "default-permanent", requestIdPresent: false, wormChecksumComplaint: false, keyClass: SENTINEL_KEY, count: 1 }] }, undefined, 1);
  const fr = (forged?.faults as unknown as Array<Record<string, unknown>> | undefined)?.[0];
  ok("a key class outside the closed set is dropped, and the row stays", fr?.s3Code === "ObjectLocked" && fr?.keyClass === undefined, fr);

  const stored = { dp1: { at: 5, total: 2, faults: faults.map((f) => ({ ...f })) } };
  const stub = { fetch: async () => new Response(JSON.stringify(stored)) } as unknown as DurableObjectStub;
  const pack = (await fetchDestFaults(stub)) as Record<string, { faults?: Array<Record<string, unknown>> }>;
  ok("the pack's destFaults row carries keyClass", pack.dp1?.faults?.some((f) => f.keyClass === "runlog") === true, pack);
  ok("no key, bucket or secret in any byte of the pack section", !JSON.stringify(pack).includes("payroll"));
}

// ---- B. checksumRequired on the lock facts ----------------------------------------------------------------------

async function addDest(scheduler: DurableObjectStub, label: string, config: Record<string, unknown>): Promise<string> {
  const resp = await scheduler.fetch("https://scheduler.internal/destinations", {
    method: "POST",
    headers: callerHeaders(OWNER),
    body: JSON.stringify({ label, config: { endpoint: "https://s3.example.com", bucket: SENTINEL_BUCKET, region: "us-east-1", accessKeyId: "AKIDACME", secretAccessKey: SENTINEL_SECRET, deleteProbe: "ok", ...config }, envDestConfigured: true }),
  });
  const body = (await resp.json()) as { destinations: Array<{ id: string; label?: string }> };
  return body.destinations.find((d) => d.label === label)?.id ?? "";
}

async function partB(): Promise<void> {
  console.log("-- B. checksumRequired on the lock facts --");
  const { stub } = makeDO();
  const needs = await addDest(stub, "needs", { objectLock: "enforced", defaultRetention: true, lockMode: "COMPLIANCE", lockRetentionDays: 30, checksumRequired: true });
  const plain = await addDest(stub, "plain", { objectLock: "enforced", defaultRetention: true, lockMode: "COMPLIANCE", lockRetentionDays: 30 });
  const bogus = await addDest(stub, "bogus", { objectLock: "enforced", checksumRequired: "yes" });
  const dr = (await fetchDestResolution({ DEST_R2: {} } as unknown as Env, stub, [])) as { destinations?: Array<Record<string, unknown>> };
  const lock = (id: string) => dr.destinations?.find((d) => d.id === id)?.lock as Record<string, unknown> | undefined;
  ok("POPULATION: three stored rows reach the pack", [needs, plain, bogus].every((i) => i !== "") && lock(needs) !== undefined);
  ok("a row that learnt checksumRequired shows lock.checksumRequired true", lock(needs)?.checksumRequired === true, lock(needs));
  ok("the other lock facts still ride beside it", lock(needs)?.enabled === "yes" && lock(needs)?.defaultMode === "COMPLIANCE" && lock(needs)?.defaultRetentionDays === 30);
  ok("a row that has not learnt it omits the field", lock(plain) !== undefined && !("checksumRequired" in (lock(plain) ?? {})), lock(plain));
  ok("a non-boolean stored value is not carried", !("checksumRequired" in (lock(bogus) ?? {})), lock(bogus));
}

// ---- C. the region hint on a refused save ---------------------------------------------------------------------------

async function partC(): Promise<void> {
  console.log("-- C. the region hint on a refused save --");
  const LOC = `https://${SENTINEL_BUCKET}.s3.ap-southeast-2.amazonaws.com/_RECOVERY/.write-probe`;
  let location: string | null = LOC;
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const doh = dohReply(input);
    if (doh !== null) return doh;
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "HEAD") return new Response("", { status: 404 });
    if (method === "PUT") return new Response("", { status: 301, headers: location !== null ? { location, "x-amz-bucket-region": "ap-southeast-2" } : { "x-amz-bucket-region": "ap-southeast-2" } });
    return new Response("", { status: 500 });
  }) as typeof fetch;
  try {
    const cfg = { endpoint: "https://s3.example.com", bucket: SENTINEL_BUCKET, region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: SENTINEL_SECRET };
    const probe = (await probeDestination({} as Env, cfg)) as { ok: boolean; failClass?: string; status?: number; regionHint?: unknown };
    ok("POPULATION: the probe was redirected", probe.ok === false && probe.failClass === "redirect" && probe.status === 301, probe);
    ok("the failed probe carries the region token", probe.regionHint === "ap-southeast-2", probe);

    const { stub, env } = makeDO();
    const resp = await handleAdmin(new Request("https://engine.example/admin/destinations", { method: "POST", headers: { authorization: "Bearer bg-token-write-facts", "content-type": "application/json" }, body: JSON.stringify({ label: "Offsite", config: cfg }) }), env);
    ok("the save is refused 400", resp.status === 400);
    const { events } = await fetchConfigEvents(stub);
    const row = (events as Array<Record<string, unknown>>).find((e) => e.refusal === "probe-failed");
    ok("the refused-save row keeps provider, class and status", row?.provider === "s3" && row?.probeClass === "redirect" && row?.probeStatus === 301, row);
    ok("the refused-save row carries regionHint ap-southeast-2", row?.regionHint === "ap-southeast-2", row);
    ok("no Location URL, bucket or secret in the row", !JSON.stringify(row).includes("amazonaws.com") && !JSON.stringify(row).includes("payroll"), row);

    location = "https://proxy.internal.example/some/path";
    const noHint = (await probeDestination({} as Env, cfg)) as { regionHint?: unknown };
    ok("a redirect to a target that names no AWS region carries no hint", noHint.regionHint === undefined, noHint);
  } finally {
    globalThis.fetch = real;
  }
}

async function main(): Promise<void> {
  console.log("validate-support-dest-write-facts\n");
  await partA();
  await partB();
  await partC();
  console.log(failures === 0 ? `\nvalidate-support-dest-write-facts: ${checks} checks passed` : `\nvalidate-support-dest-write-facts: ${failures} of ${checks} checks FAILED`);
  verdictReached(failures, checks);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
