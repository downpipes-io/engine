// Validates the destination-id evidence the support pack carries from engine 0.3.7: the evidence a reader
// with only the pack needed to see that the deploy-time destination was being read as "not configured".
//
//   A. destResolution.resolution / defaultResolution: every configured id (each stored row and every id a
//      downpipe names, a removed one included) resolved through the real resolveDestination, with its branch
//      and closed refusal; a config-plane throw is branch "error" with the closed build cause.
//   B. destResolution.collection: each stored row's source, kind, default flag, which fields are set, and the
//      basis of its deleteProbe verdict (the deploy-time row is seeded "other" and never probed; a probed
//      "other" carries the status class the store answered with).
//   C. configEvents: each dest change carries the destination ids and default before and after it.
//   D. destResolution.danglingRefs: each refused (downpipe, destination id) pair, and why.
//   E. destResolution.ioTimeouts: which destination id each request timeout hit.
//   F. replication rows: the replicate-pass site behind a failed row's reason.
//   G. REDACTION: an endpoint, a bucket and a secret planted in the stored rows reach no byte of any of it.
//
// It drives the real SchedulerDO through its own HTTP routes over an in-memory storage double. No network.
// Run: node test/validate-support-dest-evidence.ts

import { callerHeaders } from "../src/admin/router-audit.ts";
import type { AuthMethod, Role } from "../src/admin/identity.ts";
import { fetchConfigEvents } from "../src/admin/support-sections-audit.ts";
import { fetchDestResolution } from "../src/admin/support-sections-config.ts";
import { fetchReplication } from "../src/admin/support-sections-seal.ts";
import { joinDestResolution } from "../src/admin/support-dest-join.ts";
import { applyDestIoTimeouts, projectDestIoTimeouts } from "../src/dest/dest-io-attribution.ts";
import { DestIo, flushDestIo, pendingDestIoTimeouts, resetPendingDestIo } from "../src/dest/dest-io.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; role: Role };
const OWNER: Caller = { method: "token", email: "owner@acme.example", subject: null, groups: [], role: "owner" };

// The customer SENTINELS planted in the stored console row. None may reach any byte of the evidence.
const SENTINEL_HOST = "acme-payroll-host.example.test";
const SENTINEL_BUCKET = "acme-payroll-archive-bucket";
const SENTINEL_SECRET = "example-secret-ACMEpayrollSECRET";
const SENTINEL_KEY_ID = "AKIDACMEPAYROLL";
const SENTINELS = [SENTINEL_HOST, SENTINEL_BUCKET, SENTINEL_SECRET, SENTINEL_KEY_ID, "payroll"];
function noSentinel(label: string, v: unknown): void {
  const hay = JSON.stringify(v ?? null).toLowerCase();
  const hit = SENTINELS.find((s) => hay.includes(s.toLowerCase()));
  ok(`${label}: no endpoint, bucket, key id or secret in any byte${hit ? ` (LEAKED ${hit})` : ""}`, hit === undefined);
}

function makeDO(): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
  return { storage, scheduler };
}

async function addConsoleDestination(scheduler: DurableObjectStub): Promise<string> {
  const resp = await scheduler.fetch("https://scheduler.internal/destinations", {
    method: "POST",
    headers: callerHeaders(OWNER),
    body: JSON.stringify({
      label: "offsite",
      // The probe the router ran said the cleanup DELETE failed with a verdict of "other", the store having
      // answered a 5xx. From engine 0.3.7 the status class is stored beside the row.
      config: { endpoint: `https://${SENTINEL_HOST}`, bucket: SENTINEL_BUCKET, region: "us-east-1", accessKeyId: SENTINEL_KEY_ID, secretAccessKey: SENTINEL_SECRET, deleteProbe: "other", deleteStatusClass: "5xx", addressing: "path" },
      envDestConfigured: true,
    }),
  });
  const body = (await resp.json()) as { destinations: Array<{ id: string; source?: string }> };
  return body.destinations.find((d) => d.source !== "deploy")?.id ?? "";
}

async function main(): Promise<void> {
  const { storage, scheduler } = makeDO();
  const s3Id = await addConsoleDestination(scheduler);
  ok("POPULATION: the console add seeded the deploy-time row and added the console row", s3Id.startsWith("dest-"));
  const downpipes = [
    { config: { id: "dp-fanout", destinationIds: ["deploy", s3Id] } },
    { config: { id: "dp-removed", destinationIds: ["gone", s3Id] } },
    { config: { id: "dp-default" } },
  ];
  const R2_ENV = { DEST_R2: {} } as unknown as Env;

  console.log("-- A. per-id resolution --");
  const dr = (await fetchDestResolution(R2_ENV, scheduler, downpipes)) as Record<string, unknown>;
  const resolution = (dr.resolution ?? []) as Array<Record<string, unknown>>;
  const row = (id: string) => resolution.find((r) => r.id === id);
  ok("POPULATION: every configured id has a row (two stored, one named with no row)", resolution.length === 3);
  ok("\"deploy\" resolves through the deploy-env-binding branch, ok", row("deploy")?.branch === "deploy-env-binding" && row("deploy")?.ok === true && row("deploy")?.stored === true);
  ok("the console id resolves through console-stored, ok", row(s3Id)?.branch === "console-stored" && row(s3Id)?.ok === true);
  ok("a named id with no row is missing / not-configured, and says who names it", row("gone")?.branch === "missing" && row("gone")?.reason === "not-configured" && row("gone")?.stored === false && row("gone")?.namedBy === 1);
  ok("the default resolves to the deploy-time destination", (dr.defaultResolution as Record<string, unknown>)?.branch === "deploy-env-binding");
  const noEnv = (await fetchDestResolution({} as unknown as Env, scheduler, downpipes)) as Record<string, unknown>;
  const deployNoEnv = ((noEnv.resolution ?? []) as Array<Record<string, unknown>>).find((r) => r.id === "deploy");
  ok("with no env destination, \"deploy\" is refused as deploy-binding-missing (never not-configured)", deployNoEnv?.branch === "deploy-binding-missing" && deployNoEnv?.reason === "deploy-binding-missing");

  // A config-plane throw is an "error" row with the closed build cause: a stored row missing its bucket.
  const broken = makeDO();
  broken.storage.seed("destinations", { list: [{ id: "dest-broken", label: "b", endpoint: `https://${SENTINEL_HOST}`, bucket: "", region: "r", accessKeyId: "k", secretAccessKey: SENTINEL_SECRET, setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }], defaultId: "dest-broken" });
  const brokenDr = (await fetchDestResolution(R2_ENV, broken.scheduler, [])) as Record<string, unknown>;
  const brokenRow = ((brokenDr.resolution ?? []) as Array<Record<string, unknown>>)[0];
  ok("an incomplete stored row resolves to branch error with the closed cause config-incomplete", brokenRow?.branch === "error" && brokenRow?.cause === "config-incomplete" && brokenRow?.ok === false);
  noSentinel("the error row", brokenDr);

  console.log("-- B. the redacted collection --");
  const collection = (dr.collection ?? []) as Array<Record<string, unknown>>;
  const deployRow = collection.find((r) => r.id === "deploy");
  const s3Row = collection.find((r) => r.id === s3Id);
  ok("the deploy-time row: source deploy, kind r2 (the env binding), the default", deployRow?.source === "deploy" && deployRow?.kind === "r2" && deployRow?.isDefault === true);
  ok("the deploy-time row's deleteProbe \"other\" is seeded-unprobed, not a measured verdict", deployRow?.deleteProbe === "other" && deployRow?.deleteProbeBasis === "seeded-unprobed");
  const fs = (s3Row?.fieldsSet ?? {}) as Record<string, unknown>;
  ok("the console row: source console, kind s3, not the default", s3Row?.source === "console" && s3Row?.kind === "s3" && s3Row?.isDefault === false);
  ok("the console row says which fields are set, as booleans only", fs.endpoint === true && fs.bucket === true && fs.region === true && fs.accessKeyId === true && fs.secret === true && fs.addressing === true && fs.worm === false && fs.assumeRole === false && fs.azureEntra === false && fs.storageClass === false && fs.pricing === false);
  ok("the console row's probed \"other\" carries the status class the store answered with", s3Row?.deleteProbe === "other" && s3Row?.deleteProbeBasis === "probed" && s3Row?.deleteStatusClass === "5xx");
  const deployFields = (deployRow?.fieldsSet ?? {}) as Record<string, unknown>;
  ok("the deploy-time row sets no field (every value is a blank placeholder)", Object.values(deployFields).length === 11 && Object.values(deployFields).every((v) => v === false));

  console.log("-- C. config events carry before/after destination ids --");
  const { events } = await fetchConfigEvents(scheduler);
  const destEvents = (events as Array<Record<string, unknown>>).filter((e) => e.action === "dest-config-set");
  ok("POPULATION: the seed and the add each wrote a dest-change event", destEvents.length === 2);
  const seed = destEvents[0];
  const add = destEvents[1];
  ok("the seed event: ids [] -> [deploy], default -> deploy", JSON.stringify(seed?.idsBefore) === "[]" && JSON.stringify(seed?.idsAfter) === '["deploy"]' && seed?.defaultAfter === "deploy" && seed?.id === "deploy");
  ok("the add event: ids [deploy] -> [deploy, console], default unchanged", JSON.stringify(add?.idsBefore) === '["deploy"]' && JSON.stringify(add?.idsAfter) === JSON.stringify(["deploy", s3Id]) && add?.defaultBefore === "deploy" && add?.defaultAfter === "deploy");
  // A REJECTED set saved nothing, so its before and after agree.
  await scheduler.fetch("https://scheduler.internal/destinations", { method: "POST", headers: callerHeaders(OWNER), body: JSON.stringify({ label: "bad", config: { endpoint: "http://insecure.example.test", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s" }, envDestConfigured: true }) });
  const after = ((await fetchConfigEvents(scheduler)).events as Array<Record<string, unknown>>).filter((e) => e.action === "dest-config-set");
  const rejected = after.find((e) => e.outcome === "failed");
  ok("a rejected set's before and after are the same collection", rejected !== undefined && JSON.stringify(rejected.idsBefore) === JSON.stringify(rejected.idsAfter));
  noSentinel("configEvents", after);
  // An id that is not engine-minted (an imported or hand-seeded row) is replaced, never carried: the excerpt
  // keeps operator text out while the list keeps its length.
  const legacy = makeDO();
  legacy.storage.seed("destinations", { list: [{ id: "acme-payroll-slug", label: "l", endpoint: "https://x.example.test", bucket: "b", region: "r", accessKeyId: "k", secretAccessKey: "s", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }], defaultId: "acme-payroll-slug" });
  await addConsoleDestination(legacy.scheduler);
  const legacyEvents = ((await fetchConfigEvents(legacy.scheduler)).events as Array<Record<string, unknown>>).filter((e) => e.action === "dest-config-set");
  const legacyAdd = legacyEvents.at(-1);
  ok("a non-minted id rides as \"unminted\" in the before/after lists and the defaults", JSON.stringify(legacyAdd?.idsBefore) === '["unminted"]' && (legacyAdd?.idsAfter as string[] | undefined)?.[0] === "unminted" && legacyAdd?.defaultBefore === "unminted");
  noSentinel("configEvents over a non-minted id", legacyEvents);

  console.log("-- D. what each dangling reference points at --");
  const dangling = (dr.danglingRefs ?? []) as Array<Record<string, unknown>>;
  ok("one refused reference: dp-removed -> gone, not-configured", dangling.length === 1 && dangling[0]?.downpipeId === "dp-removed" && dangling[0]?.destinationId === "gone" && dangling[0]?.reason === "not-configured");
  const danglingNoEnv = (noEnv.danglingRefs ?? []) as Array<Record<string, unknown>>;
  ok("with no env destination, dp-fanout -> deploy is refused as deploy-binding-missing", danglingNoEnv.some((d) => d.downpipeId === "dp-fanout" && d.destinationId === "deploy" && d.reason === "deploy-binding-missing"));

  console.log("-- E. which destination each timeout hit --");
  resetPendingDestIo();
  const labelled = new DestIo();
  labelled.setLabel(s3Id);
  labelled.note("timeouts");
  labelled.note("timeouts");
  new DestIo().note("timeouts"); // an instance built with no id: unattributed, never guessed
  const tally = pendingDestIoTimeouts();
  ok("the isolate tally attributes 2 timeouts to the labelled id and 1 as unattributed", tally.byId[s3Id] === 2 && tally.unattributed === 1);
  await flushDestIo(scheduler);
  const dr2 = (await fetchDestResolution(R2_ENV, scheduler, downpipes)) as Record<string, unknown>;
  const io = dr2.ioTimeouts as { byDestination?: Record<string, { count: number }>; unattributed?: { count: number } } | undefined;
  ok("the flush lands in the DO and the pack carries it per destination", io?.byDestination?.[s3Id]?.count === 2 && io?.unattributed?.count === 1);
  const counters = JSON.stringify(await (await scheduler.fetch("https://scheduler.internal/admin-counters")).json());
  ok("CONTROL: the fleet-wide dest-io-timeout counter still counts all three", /"dest-io-timeout":\{"count":3\b/.test(counters));
  const capped = applyDestIoTimeouts(undefined, { byId: Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`d${i}`, 1])), unattributed: 0 }, 5);
  ok("the DO record refuses ids past its cap of 64 and counts them", Object.keys(capped.byDestination).length === 64 && capped.refused === 6);
  const hostile = projectDestIoTimeouts({ byDestination: { "a\u0000b": { count: -3, lastAt: 1 }, ok: { count: "9" }, x: { count: 2, lastAt: 7, endpoint: SENTINEL_HOST } }, unattributed: "lots", refused: 1.5 });
  ok("the pack gate drops a non-positive or non-numeric count, and every field it does not know", JSON.stringify(hostile) === JSON.stringify({ byDestination: { x: { count: 2, lastAt: 7 } }, refused: 1 }));

  console.log("-- F. the site behind a failed replication row --");
  await scheduler.fetch("https://scheduler.internal/replication/record", { method: "POST", body: JSON.stringify({ id: "dp-removed", destinationId: "gone", ok: false, reason: "not-configured", reasonSite: "target-resolution" }) });
  await scheduler.fetch("https://scheduler.internal/replication/record", { method: "POST", body: JSON.stringify({ id: "dp-removed", destinationId: s3Id, ok: false, reason: "unreachable", reasonSite: "somewhere-else" }) });
  const repl = await fetchReplication(scheduler);
  const rows = repl?.["dp-removed"] ?? [];
  ok("a not-configured row names target-resolution as its site", rows.find((r) => r.id === "gone")?.reasonSite === "target-resolution");
  ok("an out-of-vocabulary site is dropped at the DO", rows.find((r) => r.id === s3Id)?.reason === "unreachable" && rows.find((r) => r.id === s3Id)?.reasonSite === undefined);

  console.log("-- F2. a stored row that cannot be projected is counted, and an HTTP error reply is a read fault --");
  const destStub = (status: number, body: unknown): DurableObjectStub => ({ fetch: async () => new Response(JSON.stringify(body), { status }) }) as unknown as DurableObjectStub;
  const goodRow = { id: "good", endpointHost: "s3.example.com", bucket: "b1", addressing: "path" };
  const badRow = { id: "bad", endpointHost: "s3.example.com", bucket: "a/b", addressing: "vhost" };
  const healthyDr = (await fetchDestResolution(R2_ENV, destStub(200, { destinations: [goodRow] }))) as Record<string, unknown>;
  ok("control, every row projects: no destinationRowsDropped and no destinationsUnavailable", healthyDr.destinationRowsDropped === undefined && healthyDr.destinationsUnavailable === undefined);
  const droppedDr = (await fetchDestResolution(R2_ENV, destStub(200, { destinations: [goodRow, badRow] }))) as Record<string, unknown>;
  ok("one row that cannot be projected is counted: destinationRowsDropped is 1", droppedDr.destinationRowsDropped === 1);
  ok("the count carries no bucket name, and the projected list holds only the row that projects", !JSON.stringify(droppedDr).includes("a/b") && (droppedDr.destinations as unknown[]).length === 1);
  const faultDr = (await fetchDestResolution(R2_ENV, destStub(500, { error: "internal error", errorId: "e1" }))) as Record<string, unknown>;
  ok("a JSON 500 from the roster read is destinationsUnavailable, not an empty roster", faultDr.destinationsUnavailable === true);

  console.log("-- H. the current resolution is joined onto each red row, replica fault and span --");
  {
    // The recorded case: destination "deploy" is red and faulting as not-configured while its current resolution is ok.
    const resolution = [
      { id: "deploy", stored: true, namedBy: 1, branch: "deploy-env-binding", ok: true },
      { id: "gone", stored: false, namedBy: 1, branch: "missing", ok: false, reason: "not-configured", cause: "build-threw" },
    ];
    const parts = {
      downpipes: [{ id: "dp1", replication: { destinations: [
        { id: "deploy", ok: false, reason: "not-configured" },
        { id: "gone", ok: false, reason: "not-configured" },
        { id: "unlisted", ok: false, reason: "unreachable" },
        { id: "origin", ok: true },
      ] } }, { id: "dp2" }],
      sealFaults: [
        { kind: "replica-target-fault", destinationId: "deploy", replicaReason: "not-configured" },
        { kind: "replica-target-fault", destinationId: "unlisted", replicaReason: "unreachable" },
        { kind: "replica-target-fault", replicaReason: "unreachable" },
        { kind: "lease-lost-abandon", destinationId: "deploy" },
      ],
      sealFaultSpans: { spans: [
        { kind: "replica-target-fault", destinationId: "deploy", reason: "not-configured", count: 2 },
        { kind: "replica-target-fault", destinationId: "unlisted", reason: "unreachable", count: 1 },
        { kind: "lease-lost-abandon", count: 1 },
      ], overflow: 0 },
    };
    const before = JSON.stringify(parts);
    const out = joinDestResolution({ resolution }, parts);
    const dests = (out.downpipes[0] as { replication: { destinations: Array<Record<string, unknown>> } }).replication.destinations;
    const sf = out.sealFaults as Array<Record<string, unknown>>;
    const sp = (out.sealFaultSpans as { spans: Array<Record<string, unknown>> }).spans;
    const want = { branch: "deploy-env-binding", ok: true };
    ok("the red replication row for deploy carries the ok resolution beside it", JSON.stringify(dests[0]!.resolution) === JSON.stringify(want));
    ok("the replica-target-fault row for deploy carries the same resolution", JSON.stringify(sf[0]!.resolution) === JSON.stringify(want));
    ok("the span for deploy carries the same resolution", JSON.stringify(sp[0]!.resolution) === JSON.stringify(want));
    ok("a refused resolution carries its closed reason and no cause", JSON.stringify(dests[1]!.resolution) === JSON.stringify({ branch: "missing", ok: false, reason: "not-configured" }));
    ok("an id absent from the list reads not-listed on a row, a fault and a span", dests[2]!.resolution === "not-listed" && sf[1]!.resolution === "not-listed" && sp[1]!.resolution === "not-listed");
    ok("a replica fault with no destination id reads not-listed", sf[2]!.resolution === "not-listed");
    ok("a green replication row gets no resolution", !("resolution" in dests[3]!));
    ok("a non-replica fault row gets none, and a span with no destination id gets none", !("resolution" in sf[3]!) && !("resolution" in sp[2]!));
    ok("a downpipe with no replication block is unchanged", JSON.stringify(out.downpipes[1]) === JSON.stringify({ id: "dp2" }));
    ok("the join leaves its input untouched", JSON.stringify(parts) === before);
    const none = joinDestResolution({}, parts);
    ok("with no resolution list (the section faulted) no row gets a claim", JSON.stringify(none) === before);
  }

  console.log("-- G. redaction over the whole section --");
  noSentinel("destResolution", dr2);
  noSentinel("destResolution without an env destination", noEnv);
  void storage;

  console.log(failures === 0 ? "\nSUPPORT DEST EVIDENCE PASS\n" : `\nSUPPORT DEST EVIDENCE FAIL (${failures})\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
