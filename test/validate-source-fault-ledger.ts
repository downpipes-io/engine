// SOURCE FAULT LEDGER validator.
//
// The source adapters absorb faults by design (a fail-open marker, a null sub-part, a tolerant parse), and
// every WHY behind those faults would otherwise exist ONLY inside the end-to-end-encrypted archive at the
// customer's own destination. This validator drives each fault path with in-memory stubs (no network) and
// proves TWO things at once:
//
//   (a) RECORDED: the fault path writes coarse, diagnosable evidence into the source fault ledger -- the
//       closed reason class, the shortfall magnitude, the failing item's attribution, the shape-drift count,
//       the run-fatal status class and stage.
//   (b) REDACTION-SAFE (binding, NO-CUSTODY): a CUSTOMER VALUE and a RAW ERROR planted at every one of those
//       sites NEVER appears anywhere in the recorded evidence. Each case plants a poison string (a secret
//       value, a bucket name, a script name, a Cloudflare error body naming a token) and the final sweep
//       asserts the serialised ledger contains none of them, and that every enum member it carries is drawn
//       from the closed vocabularies.
//
// Run: node test/validate-source-fault-ledger.ts

import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-registry.ts";
import { CF_CONFIG_IDENTITY_ID } from "../src/sources/cf-config-surfaces.ts";
import { CfApiError, CfPaginationTruncated, type CfApi, type CfConfigSurface, type CfPage } from "../src/sources/cf-config-core.ts";
import { WorkersSource, type WorkersCfApi } from "../src/sources/workers.ts";
import { ImagesSource } from "../src/sources/images.ts";
import { SecretsSource } from "../src/sources/secrets.ts";
import { SourceResourceMissingError } from "../src/sources/source-errors.ts";
import {
  SOURCE_FAULT_REASONS,
  SOURCE_FAULT_STAGES,
  SOURCE_FAULT_STATUS_CLASSES,
  drainSourceFaultLedger,
  faultHandle,
  isEmptyFaultLedger,
  mergeSourceFaultLedgers,
  readSourceFaultLedger,
  resetSourceFaultLedger,
  type SourceFaultLedger,
} from "../src/sources/source-fault-ledger.ts";
import type { Selector, SourceRecord } from "../src/sources/types.ts";

declare const process: { exit(code?: number): never; exitCode?: number };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ALL: Selector = { include: [], exclude: [] };

// POISON is the set of values planted at the fault sites. Every one is something the ledger must NEVER carry:
// a live secret value, a customer bucket/script/video name, and a raw Cloudflare error body naming a token.
const POISON = {
  secretValue: "s3cr3t-live-value-DO-NOT-LEAK",
  secretName: "PROD_STRIPE_KEY",
  bucketName: "acme-prod-customer-bucket",
  scriptName: "acme-checkout-worker",
  imageId: "img-acme-customer-0001",
  errorBody: "Cloudflare API GET /accounts/acct/x: token 9f3a-DEADBEEF is not authorised for zone acme.example",
} as const;

// cfErr builds a CfApiError exactly as makeCfApi does at a real throw site: the raw CF message rides on the
// error (as it does in production), so a leak of the message into the ledger would be caught by the sweep.
function cfErr(status: number, gated = false): CfApiError {
  return new CfApiError(POISON.errorBody, status, [10000], gated);
}

// A drained snapshot per case, kept for the final redaction sweep over EVERYTHING recorded in this run.
const drained: Array<{ label: string; ledger: SourceFaultLedger }> = [];
function drain(label: string): SourceFaultLedger {
  const l = drainSourceFaultLedger();
  drained.push({ label, ledger: l });
  return l;
}

// ---------------------------------------------------------------------------------------------------
// The marker's REASON and MAGNITUDE reach the run row, not just the archive.
// ---------------------------------------------------------------------------------------------------
async function cfConfigMarkerReasons(): Promise<void> {
  console.log("cf-config marker reason + truncation magnitude");
  resetSourceFaultLedger();

  // Three surfaces: one 403 scope gap, one plan-entitlement gate, one page-cap truncation, one healthy read.
  const surfaces: CfConfigSurface[] = [
    { id: "dns_records", scope: "account", restoreTier: "idempotent", read: () => Promise.reject(cfErr(403)) },
    { id: "logpush", scope: "account", restoreTier: "idempotent", read: () => Promise.reject(cfErr(403, true)) },
    { id: "rulesets", scope: "account", restoreTier: "idempotent", read: () => Promise.reject(new CfPaginationTruncated(1000, 47_000)) },
    { id: "zone-settings", scope: "account", restoreTier: "idempotent", read: () => Promise.resolve({ ok: true }) },
  ];
  const src = new CloudflareConfigSource("tok", "acct-1", undefined, surfaces, (() => Promise.reject(new Error("no network"))) as unknown as typeof fetch);

  const records: SourceRecord[] = [];
  for await (const ev of src.crawlFrom(ALL, JSON.stringify({ after: CF_CONFIG_IDENTITY_ID }))) {
    if (ev.kind === "record") records.push(ev.record);
  }
  const l = drain("cf-config-marker-reasons");

  const byName = new Map(records.map((r) => [r.name, r]));
  ok("the 403 surface's record carries markerReason=auth", byName.get("dns_records")?.markerReason === "auth");
  ok("the entitlement-gated surface's record carries markerReason=entitlement", byName.get("logpush")?.markerReason === "entitlement");
  ok("the truncated surface's record carries markerReason=page-cap", byName.get("rulesets")?.markerReason === "page-cap");
  ok("the healthy surface's record carries NO markerReason", byName.get("zone-settings")?.markerReason === undefined);

  ok("ledger: _unavailable.auth counted", l.incompleteReasons._unavailable?.auth === 1);
  ok("ledger: _unavailable.entitlement counted", l.incompleteReasons._unavailable?.entitlement === 1);
  ok("ledger: _truncated['page-cap'] counted", l.incompleteReasons._truncated?.["page-cap"] === 1);
  ok("ledger: the truncation MAGNITUDE is carried (1000 pages / 47000 records)", l.truncation?.pagesRead === 1000 && l.truncation?.recordsAccumulated === 47_000);
  ok("ledger: the failing surface ids are attributed (closed-registry tokens, raw)", (l.incompleteIds._unavailable ?? []).includes("dns_records"));
}

// ---------------------------------------------------------------------------------------------------
// A failed SUB-PART read is not indistinguishable from "not configured".
// ---------------------------------------------------------------------------------------------------
async function subPartFaults(): Promise<void> {
  console.log("r2-bucket-config sub-part read failure (the WORM/object-lock case)");
  resetSourceFaultLedger();

  const surface = CF_CONFIG_SURFACES.find((s) => s.id === "r2-bucket-config");
  if (surface === undefined) {
    ok("the r2-bucket-config surface exists in the registry", false);
    return;
  }
  // The bucket list succeeds; the object-LOCK read (the retention posture) fails; everything else succeeds.
  const api: CfApi = {
    get: (path) => {
      if (path.endsWith("/lock")) return Promise.reject(cfErr(500));
      return Promise.resolve({ configured: true });
    },
    getPage: (path) => (path.includes("/r2/buckets") ? Promise.resolve({ result: [{ name: POISON.bucketName }] } as CfPage) : Promise.resolve({ result: [] } as CfPage)),
    send: () => Promise.reject(new Error("read-only")),
  };
  const out = (await surface.read(api, { accountId: "acct-1" })) as Array<Record<string, unknown>>;
  const l = drain("subpart-faults");

  ok("the surface still archives (fail-open per part is unchanged)", Array.isArray(out) && out.length === 1);
  ok("the failed lock read still degrades to null in the archive (behaviour unchanged)", out[0]?.lock === null);
  ok("ledger: the sub-part fault is recorded with reason=server-error", l.incompleteReasons._unavailable?.["server-error"] === 1);
  const ids = l.incompleteIds._unavailable ?? [];
  ok("ledger: it is attributed to the '<surface>:<part>' scope", ids.some((i) => i.startsWith("cf-config/r2-bucket-config:lock/")));
  const bucketHandle = await faultHandle(POISON.bucketName);
  ok("ledger: the BUCKET is attributed by one-way handle, never by name", ids.includes(`cf-config/r2-bucket-config:lock/${bucketHandle}`));
}

// ---------------------------------------------------------------------------------------------------
// One bad item does not sink a surface (or the secrets run) anonymously.
// ---------------------------------------------------------------------------------------------------
async function itemAttribution(): Promise<void> {
  console.log("the failing ITEM is attributed, not just the surface");
  resetSourceFaultLedger();

  const surface = CF_CONFIG_SURFACES.find((s) => s.id === "queues");
  if (surface === undefined) {
    ok("the queues surface exists in the registry", false);
    return;
  }
  const queueId = "q-acme-orders";
  const api: CfApi = {
    get: () => Promise.reject(cfErr(403)), // one queue's consumers read: a 403 that voids the whole surface today
    getPage: () => Promise.resolve({ result: [{ queue_id: queueId }] } as CfPage),
    send: () => Promise.reject(new Error("read-only")),
  };
  let threw = false;
  try {
    await surface.read(api, { accountId: "acct-1" });
  } catch {
    threw = true;
  }
  const l = drain("item-attribution-queues");
  ok("the per-item throw still propagates (behaviour unchanged; evidence closes independently)", threw);
  const ids = l.incompleteIds._unavailable ?? [];
  const queueHandle = await faultHandle(queueId);
  ok("ledger: the failing queue is attributed under a compound '<surface>:<part>/<handle>' id", ids.includes(`cf-config/queues:consumers/${queueHandle}`));
  ok("ledger: the reason class is auth (a 403 scope gap, not an outage)", l.incompleteReasons._unavailable?.auth === 1);

  // The secrets source: one of N bound secrets is deleted, and the whole run dies with no identity today.
  resetSourceFaultLedger();
  const secrets = new SecretsSource([
    { name: "OK_SECRET", get: () => Promise.resolve("fine") },
    { name: POISON.secretName, get: () => Promise.reject(new Error(`secret ${POISON.secretName} not found (value was ${POISON.secretValue})`)) },
  ]);
  let secretsThrew = false;
  const got: string[] = [];
  try {
    for await (const rec of secrets.crawl(ALL)) got.push(rec.name);
  } catch {
    secretsThrew = true;
  }
  const sl = drain("item-attribution-secrets");
  ok("secrets: the healthy secret still yields before the failure", got.includes("OK_SECRET"));
  ok("secrets: the deleted secret still fails the run (behaviour unchanged)", secretsThrew);
  const secretHandle = await faultHandle(POISON.secretName);
  ok("secrets: the failing secret is attributed by one-way handle", (sl.incompleteIds._unavailable ?? []).includes(`secrets:get/${secretHandle}`));
  ok("secrets: the run-fatal fault is recorded with stage=item-read", sl.fatal?.stage === "item-read" && sl.fatal?.sourceType === "secrets");
}

// ---------------------------------------------------------------------------------------------------
// A tolerant parse does not drop items silently.
// ---------------------------------------------------------------------------------------------------
async function shapeDrift(): Promise<void> {
  console.log("API shape drift is counted instead of voiding coverage silently");
  resetSourceFaultLedger();

  // Images: the v2 list answers with an object whose `images` is NOT an array (a response-shape change). The
  // adapter coerces to an empty page today: zero images captured, run reports ok, pack shows nothing.
  const imagesApi: CfApi = {
    get: () => Promise.resolve({ images: { "0": { id: POISON.imageId } }, continuation_token: "" }),
    getPage: () => Promise.resolve({ result: [] } as CfPage),
    send: () => Promise.reject(new Error("read-only")),
  };
  const images = new ImagesSource("acct-1", imagesApi);
  const names: string[] = [];
  for await (const ev of images.crawlFrom(ALL, null)) if (ev.kind === "record") names.push(ev.record.name);
  const il = drain("shape-drift-images");
  ok("images: the run still 'succeeds' having captured NO image (the silent-coverage bug is real)", !names.includes(POISON.imageId));
  ok("images: the shape drift is COUNTED", il.shapeAnomalies >= 1);
  ok("images: the drift is located by product token", il.shapeAnomalyIds.includes("images:list"));

  // Workers: a script's /versions and /schedules answer in an unrecognised shape. Today both coerce to an
  // empty inventory, so a restore silently loses the Worker's cron schedule with a clean run row.
  resetSourceFaultLedger();
  const workersApi: WorkersCfApi = {
    get: (path) => {
      if (path.endsWith("/versions")) return Promise.resolve({ result_items: [] }); // renamed field
      if (path.endsWith("/schedules")) return Promise.resolve({ crons: [{ cron: "*/5 * * * *" }] }); // renamed field
      return Promise.resolve({ bindings: [] });
    },
    getPage: () => Promise.resolve({ result: [{ id: POISON.scriptName }] } as CfPage),
    getRaw: () => Promise.resolve({ bytes: new Uint8Array([1, 2, 3]), contentType: "application/javascript" }),
  };
  const workers = new WorkersSource("acct-1", workersApi);
  for await (const ev of workers.crawlFrom(ALL, null)) void ev;
  const wl = drain("shape-drift-workers");
  ok("workers: the versions drift is counted", wl.shapeAnomalyIds.includes("workers:versions"));
  ok("workers: the schedules drift is counted (a restore would lose the cron schedule)", wl.shapeAnomalyIds.includes("workers:schedules"));
  ok("workers: both drifts bump the clamped counter", wl.shapeAnomalies >= 2);
}

// ---------------------------------------------------------------------------------------------------
// A run-fatal source failure carries its transport class and stage.
// ---------------------------------------------------------------------------------------------------
async function fatalClass(): Promise<void> {
  console.log("G144: run-fatal failures carry a status class + a stage");

  // The classic ticket: the token was rotated and the Workers LIST now 401s. The adapter rewraps the throw as
  // a 160-char hint string, so without this the run row could not tell 401 from 403 from a 5xx.
  resetSourceFaultLedger();
  const api401: WorkersCfApi = {
    get: () => Promise.reject(cfErr(401)),
    getPage: () => Promise.reject(cfErr(401)),
    getRaw: () => Promise.reject(cfErr(401)),
  };
  let threw = false;
  try {
    for await (const ev of new WorkersSource("acct-1", api401).crawlFrom(ALL, null)) void ev;
  } catch {
    threw = true;
  }
  const l1 = drain("fatal-class-workers-list");
  ok("workers: the list failure still throws (behaviour unchanged)", threw);
  ok("workers: fatal recorded as 401 at stage=list", l1.fatal?.statusClass === "401" && l1.fatal?.stage === "list" && l1.fatal?.sourceType === "workers");

  // The list SUCCEEDS but every aspect read 403s: a different fix (a narrower scope), and today an identical
  // run row. The attempted/succeeded magnitude proves the list worked.
  resetSourceFaultLedger();
  const api403: WorkersCfApi = {
    get: () => Promise.reject(cfErr(403)),
    getPage: () => Promise.resolve({ result: [{ id: POISON.scriptName }] } as CfPage),
    getRaw: () => Promise.reject(cfErr(403)),
  };
  let threw2 = false;
  try {
    for await (const ev of new WorkersSource("acct-1", api403).crawlFrom(ALL, null)) void ev;
  } catch {
    threw2 = true;
  }
  const l2 = drain("fatal-class-workers-aspects");
  ok("workers: the all-aspects-failed guard still throws", threw2);
  ok("workers: fatal recorded as 403 at stage=item-read", l2.fatal?.statusClass === "403" && l2.fatal?.stage === "item-read");
  ok("workers: the attempted/succeeded magnitude proves the LIST worked", (l2.fatal?.attempted ?? 0) > 0 && l2.fatal?.succeeded === 0);
  ok("workers: the failing aspects are attributed by handle, never by script name", (l2.incompleteIds._unavailable ?? []).some((i) => i.startsWith("workers:settings/h:")));

  // cf-config: every surface fails -> the all-failed guard. Stage item-read, class from the real fault.
  resetSourceFaultLedger();
  const surfaces: CfConfigSurface[] = [
    { id: "dns_records", scope: "account", restoreTier: "idempotent", read: () => Promise.reject(cfErr(500)) },
    { id: "zone-settings", scope: "account", restoreTier: "idempotent", read: () => Promise.reject(cfErr(500)) },
  ];
  const stubFetch = (() => Promise.reject(new Error("no network"))) as unknown as typeof fetch;
  let threw3 = false;
  try {
    for await (const ev of new CloudflareConfigSource("tok", "acct-1", undefined, surfaces, stubFetch).crawlFrom(ALL, null)) void ev;
  } catch {
    threw3 = true;
  }
  const l3 = drain("fatal-class-cfconfig-allfailed");
  ok("cf-config: the all-failed guard still throws", threw3);
  ok("cf-config: fatal recorded as 5xx (an outage, not a token problem)", l3.fatal?.statusClass === "5xx" && l3.fatal?.sourceType === "cf-config");
  ok("cf-config: attempted=2 succeeded=0", l3.fatal?.attempted === 2 && l3.fatal?.succeeded === 0);

  // The liveness probe: a deleted resource vs a transient outage, which the classifier could previously
  // mislabel with no way to check. The error now carries the transport class beside the engine's verdict.
  resetSourceFaultLedger();
  const missing = new SourceResourceMissingError("r2", POISON.bucketName, "deleted");
  ok("SourceResourceMissingError carries a faultClass", missing.faultClass === "other" || missing.faultClass === "404");
  const l4 = drain("fatal-class-probe");
  ok("the liveness throw records a fatal at stage=probe", l4.fatal?.stage === "probe" && l4.fatal?.sourceType === "r2");
}

// ---------------------------------------------------------------------------------------------------
// Ledger discipline: bounds, merge, reset.
// ---------------------------------------------------------------------------------------------------
async function ledgerDiscipline(): Promise<void> {
  console.log("ledger discipline: bounds, merge, reset");
  resetSourceFaultLedger();
  ok("a fresh ledger is empty", isEmptyFaultLedger(readSourceFaultLedger()));

  // 200 distinct failing items must not grow the id list past the cap; the COUNT stays exact.
  const surface = CF_CONFIG_SURFACES.find((s) => s.id === "snippets");
  if (surface !== undefined) {
    const api: CfApi = {
      get: () => Promise.reject(cfErr(404)),
      getPage: (path) => (path.includes("/snippets") ? Promise.resolve({ result: Array.from({ length: 200 }, (_, i) => ({ snippet_name: `snip-${i}` })) } as CfPage) : Promise.resolve({ result: [] } as CfPage)),
      send: () => Promise.reject(new Error("read-only")),
    };
    await surface.read(api, { accountId: "a", zoneId: "z" });
    const l = drain("bounds-snippets");
    ok("200 failing sub-reads cap the id list at 25", (l.incompleteIds._unavailable ?? []).length === 25);
    ok("...while the per-reason COUNT stays exact (200)", l.incompleteReasons._unavailable?.["not-found"] === 200);
  }

  // merge folds two slices' ledgers the way the seal folds checkpoint counts. Each slice is built on a DRAINED
  // (empty) ledger rather than a hand-written literal, so it carries every required counter the type has grown
  // since -- rowidProbeFallbacks, resumeTokenDefects, d1Defects, throttle429Count and the rest -- at its zero
  // value, and cannot drift from SourceFaultLedger again. A fresh drain per slice keeps the two fixtures'
  // nested containers separate objects, so neither can see the other's state.
  resetSourceFaultLedger();
  const emptySlice = (): SourceFaultLedger => drainSourceFaultLedger();
  const a: SourceFaultLedger = { ...emptySlice(), incompleteReasons: { _unavailable: { auth: 2 } }, incompleteIds: { _unavailable: ["x"] }, shapeAnomalies: 1, shapeAnomalyIds: ["images:list"] };
  const b: SourceFaultLedger = { ...emptySlice(), incompleteReasons: { _unavailable: { auth: 3, shape: 1 } }, incompleteIds: { _unavailable: ["y"] }, shapeAnomalies: 2, shapeAnomalyIds: ["stream:list"], truncation: { pagesRead: 4, recordsAccumulated: 9 } };
  const m = mergeSourceFaultLedgers(a, b);
  ok("merge sums the per-reason counts", m.incompleteReasons._unavailable?.auth === 5 && m.incompleteReasons._unavailable?.shape === 1);
  ok("merge unions the attribution ids", (m.incompleteIds._unavailable ?? []).length === 2);
  ok("merge sums shapeAnomalies and carries the truncation magnitude", m.shapeAnomalies === 3 && m.truncation?.recordsAccumulated === 9);

  resetSourceFaultLedger();
  ok("reset clears the accumulator (a warm isolate never attributes a previous run's faults to this one)", isEmptyFaultLedger(readSourceFaultLedger()));
}

// ---------------------------------------------------------------------------------------------------
// THE REDACTION SWEEP: nothing recorded above may carry a customer value or a raw error, and every enum
// member must come from a closed vocabulary. This is the binding NO-CUSTODY check.
// ---------------------------------------------------------------------------------------------------
function redactionSweep(): void {
  console.log("redaction sweep (NO-CUSTODY): no customer value, no raw error, closed enums only");
  const all = JSON.stringify(drained);

  for (const [k, v] of Object.entries(POISON)) {
    ok(`the recorded evidence never carries the planted ${k}`, !all.includes(v));
  }
  // The raw CF error body is also checked piecewise: no token fragment, no zone name, no request path.
  for (const frag of ["9f3a-DEADBEEF", "acme.example", "/accounts/acct/x", "not authorised"]) {
    ok(`no fragment of the raw Cloudflare error survives ("${frag}")`, !all.includes(frag));
  }
  ok("no bearer/authorization material anywhere in the evidence", !/bearer|authorization|Bearer/i.test(all));

  let sawSomething = false;
  for (const { label, ledger } of drained) {
    if (!isEmptyFaultLedger(ledger)) sawSomething = true;
    for (const kind of Object.keys(ledger.incompleteReasons)) {
      for (const reason of Object.keys(ledger.incompleteReasons[kind as keyof typeof ledger.incompleteReasons] ?? {})) {
        ok(`${label}: reason "${reason}" is in the closed vocabulary`, (SOURCE_FAULT_REASONS as readonly string[]).includes(reason));
      }
    }
    for (const ids of Object.values(ledger.incompleteIds)) {
      for (const id of ids ?? []) {
        ok(`${label}: attribution id "${id}" is within the 128-char clamp`, id.length <= 128);
      }
    }
    if (ledger.fatal !== undefined) {
      ok(`${label}: fatal statusClass is in the closed vocabulary`, (SOURCE_FAULT_STATUS_CLASSES as readonly string[]).includes(ledger.fatal.statusClass));
      ok(`${label}: fatal stage is in the closed vocabulary`, (SOURCE_FAULT_STAGES as readonly string[]).includes(ledger.fatal.stage));
    }
    ok(`${label}: shapeAnomalies is a bounded non-negative int`, Number.isInteger(ledger.shapeAnomalies) && ledger.shapeAnomalies >= 0 && ledger.shapeAnomalies <= 1_000_000);
  }
  ok("the sweep actually saw recorded evidence (the test is not vacuous)", sawSomething);
}

async function main(): Promise<void> {
  await cfConfigMarkerReasons();
  await subPartFaults();
  await itemAttribution();
  await shapeDrift();
  await fatalClass();
  await ledgerDiscipline();
  redactionSweep();
  console.log(failures === 0 ? "\nvalidate-source-fault-ledger: PASS" : `\nvalidate-source-fault-ledger: ${failures} FAILURES`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

await main();
