// Validates three support-pack facts a reader needs when a destination or a source stops answering:
//
//   A. DESTINATION ACCESS FAULTS. A native R2 destination that refuses an op (a bucket lock rule, a deleted
//      bucket, a refused read) records a destFaults row with the op, the closed fault class and a closed
//      code, exactly as the S3 driver already does. The pack's destFaults section also carries the redirect
//      anomaly, the region token and the other closed fields the DO stores beside the rows.
//   B. BUCKET LOCK FACTS. The save-time probe learns the default retention mode and period, the destination
//      row stores them beside the live verdict, and destResolution.destinations[].lock carries the closed
//      facts: enabled yes/no/unknown, default mode, period in days and when it was learnt.
//   C. A DELETED D1 DATABASE. The D1 "database not found" answer is classified as a proven absence (kind
//      "deleted", preflight class "not-found", source fault class "404"), not as a passing outage. A vague
//      answer and a timeout stay "unavailable".
//
// No network. The R2 binding, the S3 wire and the scheduler DO are in-memory doubles.
// Run: node test/validate-support-dest-access-source-class.ts

import { callerHeaders } from "../src/admin/router-audit.ts";
import type { AuthMethod, Role } from "../src/admin/identity.ts";
import { probeDestination } from "../src/admin/router-posture.ts";
import { fetchDestResolution } from "../src/admin/support-sections-config.ts";
import { fetchDestFaults } from "../src/admin/support-sections-diag.ts";
import { sanitiseDestFaults } from "../src/admin/run-fault-records.ts";
import { R2Destination } from "../src/dest/r2.ts";
import { segmentObjectKey } from "../src/format/writer-record.ts";
import { CONTROL_PLANE_PREFIX } from "../src/admin/control-plane.ts";
import { RUNLOG_SIG_PENDING_KEY as PIPELINE_PENDING_KEY } from "../src/seal/pipeline.ts";
import { D1Source } from "../src/sources/d1.ts";
import { resetSourceFaultLedger, readSourceFaultLedger } from "../src/sources/source-fault-ledger.ts";
import { sourceLivenessClass } from "../src/admin/preflight-probes.ts";
import { SourceResourceMissingError } from "../src/sources/source-errors.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { dohReply } from "./lib/doh-stub.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

// Key shapes for the key-class cases, read from the pipeline's exported pending-signature key. The manifest
// key follows the run layout run/<runId>/root.manifest.json, which the engine builds inline.
const RUNLOG_SIG_KEY = PIPELINE_PENDING_KEY.replace(/\.pending$/, "");
const RUNLOG_KEY = RUNLOG_SIG_KEY.replace(/\.sig$/, "");
const RECOVERY_PREFIX = RUNLOG_KEY.slice(0, RUNLOG_KEY.indexOf("/") + 1);
const rootManifestKey = (runId: string): string => `run/${runId}/root.manifest.json`;

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const SENTINEL_KEY = "seg/acme-payroll-CONFIDENTIAL/ab/abcdef";
const SENTINEL_HOST = "acme-payroll-host.example.test";
const SENTINEL_BUCKET = "acme-payroll-archive-bucket";
function noSentinel(label: string, v: unknown): void {
  const hay = JSON.stringify(v ?? null).toLowerCase();
  const hit = [SENTINEL_KEY, SENTINEL_HOST, SENTINEL_BUCKET, "payroll"].find((s) => hay.includes(s.toLowerCase()));
  ok(`${label}: no key, host or bucket in any byte${hit ? ` (LEAKED ${hit})` : ""}`, hit === undefined);
}

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; role: Role };
const OWNER: Caller = { method: "token", email: "owner@acme.example", subject: null, groups: [], role: "owner" };

// ---- A. destination access faults ------------------------------------------------------------------------

// The binding's own refusal text, measured on a live estate with the native R2 binding: a plain Error with no
// code field; the code 10069 exists only inside the message.
const BINDING_LOCK_PUT = "put: The object is locked by the bucket policy. (10069)";
const BINDING_LOCK_DELETE = "delete: The object is locked by the bucket policy. (10069)";
const LOCK_SENTENCE = "The object is locked by the bucket policy.";

function refusingBucket(message: string): R2Bucket {
  const boom = async (): Promise<never> => {
    throw new Error(message);
  };
  return { put: boom, get: boom, head: boom, delete: boom, list: boom } as unknown as R2Bucket;
}

async function partA(): Promise<void> {
  console.log("-- A. destination access faults --");
  const locked = new R2Destination(refusingBucket(BINDING_LOCK_PUT));
  let threw = false;
  try {
    await locked.put(SENTINEL_KEY, new Uint8Array([1]));
  } catch {
    threw = true;
  }
  ok("POPULATION: the refused R2 put threw", threw);
  const snap = locked.destFaults();
  ok("the refused put leaves a destFaults row", snap.total === 1 && snap.faults.length === 1);
  const row = snap.faults[0];
  ok("the row names the op", row?.op === "put");
  ok("the row carries the closed class permanent (a locked object is refused every time)", row?.fault === "permanent");
  ok("the row carries the closed code ObjectLocked", row?.s3Code === "ObjectLocked");
  noSentinel("the R2 fault snapshot", snap);

  await keyClassCases();

  const gone = new R2Destination(refusingBucket("list: The specified bucket does not exist. (10006)"));
  await gone.list("run/").catch(() => undefined);
  ok("a deleted bucket on a list is a list row with the closed code NoSuchBucket", gone.destFaults().faults[0]?.op === "list" && gone.destFaults().faults[0]?.s3Code === "NoSuchBucket");

  const opaque = new R2Destination(refusingBucket("something the runtime made up"));
  await opaque.get("_RECOVERY/RUNLOG").catch(() => undefined);
  ok("an unreadable refusal is still a get row, code none, never the text", opaque.destFaults().faults[0]?.op === "get" && opaque.destFaults().faults[0]?.s3Code === "none");

  const cond = new R2Destination(refusingBucket("denied"));
  await cond.putConditional("_RECOVERY/RUNLOG", new Uint8Array([1]), { ifNoneMatch: "*" }).catch(() => undefined);
  ok("a refused conditional put is a put-conditional row", cond.destFaults().faults[0]?.op === "put-conditional");

  const gated = sanitiseDestFaults(snap, undefined, 1);
  ok("the DO re-gate keeps the ObjectLocked row", gated?.faults?.[0]?.s3Code === "ObjectLocked" && gated?.faults?.[0]?.op === "put");

  // The pack projection forwards the redirect anomaly and region token the DO stores beside the rows.
  const stored = { dp1: { at: 5, total: 1, faults: [{ op: "put", httpStatus: 301, s3Code: "PermanentRedirect", fault: "permanent", arm: "matched-status", requestIdPresent: true, wormChecksumComplaint: false, count: 1 }], anomalies: { "redirect-wrong-region": 1 }, redirectRegionHint: "eu-central-1", overBoundBytes: 7, listPagesReached: 2 } };
  const stub = { fetch: async () => new Response(JSON.stringify(stored)) } as unknown as DurableObjectStub;
  const pack = (await fetchDestFaults(stub)) as Record<string, { faults?: Array<{ s3Code?: string }>; anomalies?: Record<string, number>; redirectRegionHint?: string; overBoundBytes?: number; listPagesReached?: number }>;
  ok("the pack carries the PermanentRedirect row", pack.dp1?.faults?.[0]?.s3Code === "PermanentRedirect");
  ok("the pack carries the redirect-wrong-region anomaly", pack.dp1?.anomalies?.["redirect-wrong-region"] === 1);
  ok("the pack carries the region token", pack.dp1?.redirectRegionHint === "eu-central-1");
  ok("the pack carries the guard magnitude and the pages reached", pack.dp1?.overBoundBytes === 7 && pack.dp1?.listPagesReached === 2);
}

// The row's key class is derived from the key by the engine's own key constants and is a closed word.
async function lockRowOf(message: string, op: "put" | "delete", key: string): Promise<Array<Record<string, unknown>>> {
  const dest = new R2Destination(refusingBucket(message));
  if (op === "put") await dest.put(key, new Uint8Array([1])).catch(() => undefined);
  else await dest.delete(key).catch(() => undefined);
  const snap = dest.destFaults();
  noSentinel(`the ${op} fault snapshot`, snap);
  return snap.faults as unknown as Array<Record<string, unknown>>;
}

async function keyClassCases(): Promise<void> {
  ok("the run log keys read from the pipeline are _RECOVERY/RUNLOG and its signature", RUNLOG_KEY === "_RECOVERY/RUNLOG" && RUNLOG_SIG_KEY === `${RUNLOG_KEY}.sig`);
  const segKey = segmentObjectKey(new Uint8Array(48).fill(7));
  const cases: Array<[string, string, string]> = [
    ["runlog", RUNLOG_KEY, "runlog"],
    ["recovery marker", `${CONTROL_PLANE_PREFIX}marker`, "recovery-marker"],
    ["segment", segKey, "segment"],
    ["manifest", rootManifestKey("01HZZZZZZZZZZZZZZZZZZZZZZZ"), "manifest"],
    ["unrelated", "other/thing.bin", "other"],
  ];
  for (const op of ["put", "delete"] as const) {
    const msg = op === "put" ? BINDING_LOCK_PUT : BINDING_LOCK_DELETE;
    for (const [label, key, want] of cases) {
      const rows = await lockRowOf(msg, op, key);
      const r = rows[0];
      ok(`the binding's ${op} lock text on a ${label} key leaves exactly one row`, rows.length === 1);
      ok(`  ... op ${op}, s3Code ObjectLocked, keyClass ${want}`, r?.op === op && r?.s3Code === "ObjectLocked" && r?.keyClass === want);
    }
  }
  ok("the recovery prefix constant is the one the markers share", `${CONTROL_PLANE_PREFIX}x`.startsWith(RECOVERY_PREFIX));

  // Negative controls: other refusals keep their class and are never ObjectLocked.
  const notLocked: Array<[string, string]> = [
    ["a network error", "put: Network connection lost."],
    ["a 5xx-style message", "put: Internal error; reference = abc123. (10001)"],
    ["a missing bucket (10006)", "put: The specified bucket does not exist. (10006)"],
    ["the lock sentence without the code", `put: ${LOCK_SENTENCE}`],
    ["the lock sentence with a different code", `put: ${LOCK_SENTENCE} (10099)`],
    ["10069 alone inside a longer number", "put: request id 100690 failed"],
    ["10069 alone with no lock wording", "put: something failed (10069)"],
  ];
  for (const [label, msg] of notLocked) {
    const rows = await lockRowOf(msg, "put", RUNLOG_KEY);
    ok(`${label} is not ObjectLocked`, rows.length === 1 && rows[0]?.s3Code !== "ObjectLocked");
  }
  const miss = await lockRowOf("put: The specified bucket does not exist. (10006)", "put", RUNLOG_KEY);
  ok("a missing bucket keeps the code NoSuchBucket", miss[0]?.s3Code === "NoSuchBucket");
  const net = await lockRowOf("put: Network connection lost.", "put", RUNLOG_KEY);
  ok("a network error keeps its code none", net[0]?.s3Code === "none");
  const sanitised = sanitiseDestFaults({ total: 1, faults: [{ op: "put", httpStatus: 0, s3Code: "ObjectLocked", fault: "permanent", arm: "default-permanent", requestIdPresent: false, wormChecksumComplaint: false, keyClass: "runlog", count: 1 }] }, undefined, 1);
  ok("the DO re-gate keeps a closed keyClass", (sanitised?.faults?.[0] as unknown as Record<string, unknown>)?.keyClass === "runlog");
  const hostile = sanitiseDestFaults({ total: 1, faults: [{ op: "put", httpStatus: 0, s3Code: "ObjectLocked", fault: "permanent", arm: "default-permanent", requestIdPresent: false, wormChecksumComplaint: false, keyClass: SENTINEL_KEY, count: 1 }] }, undefined, 1);
  ok("the DO re-gate drops an out-of-vocabulary keyClass and keeps the row", hostile?.faults?.length === 1 && (hostile.faults[0] as unknown as Record<string, unknown>)?.keyClass === undefined);
}

// ---- B. bucket lock facts -----------------------------------------------------------------------------------

const ENDPOINT = "https://s3.example.com";
async function probeWith(lockXml: string | null): Promise<Awaited<ReturnType<typeof probeDestination>>> {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const doh = dohReply(input);
    if (doh !== null) return doh;
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "HEAD") return new Response("", { status: 404 });
    if (method === "PUT") return new Response("", { status: 200 });
    if (method === "DELETE") return new Response("", { status: 204 });
    if (method === "GET" && url.includes("object-lock")) return lockXml === null ? new Response("", { status: 404 }) : new Response(lockXml, { status: 200 });
    return new Response("", { status: 500 });
  }) as typeof fetch;
  try {
    return await probeDestination({} as Env, { endpoint: ENDPOINT, bucket: "archive-bucket", region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "secret" });
  } finally {
    globalThis.fetch = real;
  }
}

function makeDO(): { scheduler: DurableObjectStub } {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  return { scheduler: { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub };
}

async function addDest(scheduler: DurableObjectStub, label: string, config: Record<string, unknown>): Promise<string> {
  const resp = await scheduler.fetch("https://scheduler.internal/destinations", {
    method: "POST",
    headers: callerHeaders(OWNER),
    body: JSON.stringify({ label, config: { endpoint: `https://${SENTINEL_HOST}`, bucket: SENTINEL_BUCKET, region: "us-east-1", accessKeyId: "AKIDACME", secretAccessKey: "example-secret", deleteProbe: "ok", ...config }, envDestConfigured: true }),
  });
  const body = (await resp.json()) as { destinations: Array<{ id: string; label?: string; source?: string }> };
  return body.destinations.find((d) => d.label === label)?.id ?? "";
}

async function partB(): Promise<void> {
  console.log("-- B. bucket lock facts --");
  const gov = await probeWith("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>7</Days></DefaultRetention></Rule></ObjectLockConfiguration>");
  ok("POPULATION: the probe passed against a locked bucket", gov.ok === true && gov.objectLock === "enforced");
  const g = gov as { lockMode?: string; lockRetentionDays?: number };
  ok("the probe learns the default mode GOVERNANCE", g.lockMode === "GOVERNANCE");
  ok("the probe learns the retention period in days as a number", g.lockRetentionDays === 7);
  const yrs = (await probeWith("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>")) as { lockMode?: string; lockRetentionDays?: number };
  ok("a period in years is carried as days", yrs.lockMode === "COMPLIANCE" && yrs.lockRetentionDays === 730);
  const norule = (await probeWith("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>")) as { lockMode?: string; lockRetentionDays?: number };
  ok("a lock with no default rule is mode none, no period", norule.lockMode === "none" && norule.lockRetentionDays === undefined);

  const { scheduler } = makeDO();
  const lockedId = await addDest(scheduler, "locked", { objectLock: "enforced", defaultRetention: true, lockMode: "COMPLIANCE", lockRetentionDays: 30, verifiedAt: 1_790_000_000_000 });
  const openId = await addDest(scheduler, "open", { objectLock: "not-enforced" });
  const unkId = await addDest(scheduler, "unk", { objectLock: "unknown" });
  const bogusId = await addDest(scheduler, "bogus", { objectLock: "enforced", defaultRetention: true, lockMode: `evil ${SENTINEL_KEY}`, lockRetentionDays: -4 });
  const dr = (await fetchDestResolution({ DEST_R2: {} } as unknown as Env, scheduler, [])) as { destinations?: Array<Record<string, unknown>> };
  const lock = (id: string) => dr.destinations?.find((d) => d.id === id)?.lock as Record<string, unknown> | undefined;
  ok("POPULATION: four stored rows reach the pack", [lockedId, openId, unkId, bogusId].every((i) => i !== ""));
  ok("a locked bucket: enabled yes, mode COMPLIANCE, 30 days", lock(lockedId)?.enabled === "yes" && lock(lockedId)?.defaultMode === "COMPLIANCE" && lock(lockedId)?.defaultRetentionDays === 30);
  ok("it says when the facts were learnt", lock(lockedId)?.learnedAt === 1_790_000_000_000);
  ok("a bucket with no lock: enabled no, mode none", lock(openId)?.enabled === "no" && lock(openId)?.defaultMode === "none");
  ok("an unread bucket: enabled unknown, mode unknown", lock(unkId)?.enabled === "unknown" && lock(unkId)?.defaultMode === "unknown");
  ok("an out-of-vocabulary mode and a negative period are dropped, not carried", lock(bogusId)?.defaultMode === "unknown" && lock(bogusId)?.defaultRetentionDays === undefined);
  noSentinel("destResolution lock facts", dr);
}

// ---- C. a deleted D1 database -----------------------------------------------------------------------------

function d1Throwing(message: string): D1Database {
  return { prepare: () => ({ first: async () => { throw new Error(message); } }) } as unknown as D1Database;
}

async function partC(): Promise<void> {
  console.log("-- C. a deleted D1 database --");
  const kindOf = async (message: string): Promise<SourceResourceMissingError | undefined> => {
    try {
      await new D1Source(d1Throwing(message), "SRC_D1_orders").probeLiveness();
    } catch (e) {
      return e instanceof SourceResourceMissingError ? e : undefined;
    }
    return undefined;
  };
  resetSourceFaultLedger();
  const gone = await kindOf("D1_ERROR: D1 database not found");
  ok("POPULATION: the probe threw a named source error", gone !== undefined);
  ok("a D1 'database not found' answer is a proven absence: kind deleted", gone?.kind === "deleted");
  ok("preflight reads it as class not-found, not other", gone !== undefined && sourceLivenessClass(gone) === "not-found");
  ok("the failed run's source fault carries the 404 class at the probe stage", readSourceFaultLedger().fatal?.statusClass === "404" && readSourceFaultLedger().fatal?.stage === "probe");
  const alt = await kindOf("D1_ERROR: no such database: harness-orders");
  ok("the D1_ERROR 'no such database' wording is also a proven absence", alt?.kind === "deleted");
  const vague = await kindOf("no such database");
  ok("a vague message with no D1 error prefix stays unavailable", vague?.kind === "unavailable");
  const slow = await kindOf("D1_ERROR: D1 DB storage operation exceeded timeout which caused object to be reset.");
  ok("a D1 timeout stays unavailable", slow?.kind === "unavailable" && sourceLivenessClass(slow) === "timeout");
  const net = await kindOf("D1_ERROR: Network connection lost");
  ok("a dropped connection stays unavailable", net?.kind === "unavailable");
}

async function main(): Promise<void> {
  await partA();
  await partB();
  await partC();
  console.log(failures === 0 ? "\nSUPPORT DEST ACCESS SOURCE CLASS PASS\n" : `\nSUPPORT DEST ACCESS SOURCE CLASS FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
