// SRC-1: source-resource liveness probe + the named "source resource missing" failure class.
//
// Proves the GRACEFUL fix for the silent trap where a KV/R2/D1 binding stays truthy after its
// underlying resource was deleted at Cloudflare: preflight's presence check is green, yet the next
// backup dies deep in the crawl on a raw platform throw the run path can only call "run failed".
//
// Coverage:
//   KVSource.probeLiveness   - live namespace resolves; deleted (not-found throw) -> "deleted";
//                              transient throw -> "unavailable"; wrong-shape binding -> "misconfigured"
//   R2Source.probeLiveness   - live bucket resolves; deleted -> "deleted"
//   D1Source.probeLiveness   - live db (SELECT 1) resolves; deleted -> "deleted"; SELECT 1 reads no data
//   coarseRunError           - a SourceResourceMissingError message maps to "source resource missing",
//                              classified AHEAD of the generic source-binding / destination catch-alls
//   probeSourceLiveness      - structured live / missing / unprobeable result (detect-and-alert form)
//   preflight source-liveness - a deleted resource raises a named, actionable FAILED item naming the
//                              source/binding/kind; a live one VERIFIES; a minimal binding is unproven,
//                              not a false alarm; never auto-creates a resource
//
// Run: node test/validate-source-liveness.ts

import { KVSource } from "../src/sources/kv.ts";
import { R2Source } from "../src/sources/r2.ts";
import { D1Source } from "../src/sources/d1.ts";
import {
  SourceResourceMissingError,
  classifyLivenessFault,
  hasLivenessProbe,
  probeSourceLiveness,
} from "../src/sources/source-errors.ts";
import { coarseRunError } from "../src/seal/slice.ts";
import { runPreflight } from "../src/admin/preflight.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function expectMissing(label: string, fn: () => Promise<unknown>, kind: SourceResourceMissingError["kind"]): Promise<void> {
  try {
    await fn();
    ok(`${label} (expected throw)`, false);
  } catch (e) {
    const named = e instanceof SourceResourceMissingError;
    ok(label, named && (e as SourceResourceMissingError).kind === kind);
  }
}

// ---- doubles ----------------------------------------------------------------

// A KV namespace double whose list() either resolves (live) or throws a chosen error (dead).
function kvDouble(onList: () => unknown): KVNamespace {
  return { list: async () => onList() } as unknown as KVNamespace;
}
function r2Double(onList: () => unknown): R2Bucket {
  return { list: async () => onList() } as unknown as R2Bucket;
}
function d1Double(onSelect: () => unknown): D1Database {
  return {
    prepare: (_q: string) => ({ first: async () => onSelect() }),
  } as unknown as D1Database;
}

// ---- KV liveness ------------------------------------------------------------

async function kvTests(): Promise<void> {
  console.log("\nKVSource.probeLiveness:");
  const live = new KVSource(kvDouble(() => ({ keys: [], list_complete: true })), "ns-uploads");
  let lived = true;
  try {
    await live.probeLiveness();
  } catch {
    lived = false;
  }
  ok("a live KV namespace passes the liveness probe", lived);
  ok("KVSource advertises the liveness capability", hasLivenessProbe(live));

  await expectMissing(
    "a deleted KV namespace (error 10041, 'No KV namespace found with ID') -> kind 'deleted'",
    () => new KVSource(kvDouble(() => { throw new Error("list: No KV namespace found with ID 0f2ac74b498b48028cb68387c421e279 (10041)"); }), "ns-gone").probeLiveness(),
    "deleted",
  );
  await expectMissing(
    "a KV answer that only says 'not found' proves nothing -> kind 'unavailable'",
    () => new KVSource(kvDouble(() => { throw new Error("KV namespace not found"); }), "ns-vague").probeLiveness(),
    "unavailable",
  );
  await expectMissing(
    "a transient KV fault (500) -> kind 'unavailable'",
    () => new KVSource(kvDouble(() => { throw new Error("internal error 500"); }), "ns-blip").probeLiveness(),
    "unavailable",
  );
  await expectMissing(
    "a wrong-shape KV binding (no list()) -> kind 'misconfigured'",
    () => new KVSource({} as unknown as KVNamespace, "ns-wrong").probeLiveness(),
    "misconfigured",
  );

  // The probe reads NO value: a list() that records calls proves only list was issued.
  let getCalls = 0;
  const counting = { list: async () => ({ keys: [], list_complete: true }), get: async () => { getCalls++; return null; } } as unknown as KVNamespace;
  await new KVSource(counting, "ns").probeLiveness();
  ok("the KV liveness probe reads no value (get() never called)", getCalls === 0);
}

// ---- R2 / D1 liveness -------------------------------------------------------

async function r2d1Tests(): Promise<void> {
  console.log("\nR2Source / D1Source.probeLiveness:");
  let r2live = true;
  try {
    await new R2Source(r2Double(() => ({ objects: [], truncated: false })), "media").probeLiveness();
  } catch {
    r2live = false;
  }
  ok("a live R2 bucket passes the liveness probe", r2live);
  await expectMissing(
    "a deleted R2 bucket (the live answer, error 10006) -> kind 'deleted'",
    () => new R2Source(r2Double(() => { throw new Error("list: The specified bucket does not exist. (10006)"); }), "media-gone").probeLiveness(),
    "deleted",
  );
  // TRANSIENT R2 answers (R2 error codes 10001 InternalError, 10043 ServiceUnavailable, 10058 TooManyRequests),
  // a timeout and a network fault: the bucket may exist, so the kind is 'unavailable', never 'deleted'.
  for (const [label, msg] of [
    ["a 500 (10001 InternalError)", "list: We encountered an internal error. Please try again. (10001)"],
    ["a 503 (10043 ServiceUnavailable)", "list: Service is temporarily unavailable (10043)"],
    ["a 429 (10058 TooManyRequests)", "list: Rate limit exceeded (10058)"],
    ["a timeout", "list: The operation was aborted due to timeout"],
    ["a network fault", "Network connection lost."],
    ["a 404 status with no R2 code", "list: status 404"],
  ] as const) {
    await expectMissing(`an R2 probe fault that is ${label} -> kind 'unavailable'`, () => new R2Source(r2Double(() => { throw new Error(msg); }), "media-blip").probeLiveness(), "unavailable");
  }

  let d1live = true;
  let selectSql = "";
  const d1 = { prepare: (q: string) => { selectSql = q; return { first: async () => ({ "1": 1 }) }; } } as unknown as D1Database;
  try {
    await new D1Source(d1, "app").probeLiveness();
  } catch {
    d1live = false;
  }
  ok("a live D1 database passes the liveness probe", d1live);
  ok("the D1 liveness probe is a constant SELECT 1 (reads no table data)", /^SELECT 1$/i.test(selectSql.trim()));
  await expectMissing(
    "a deleted D1 database (error 7404, 'the database cannot be found') -> kind 'deleted'",
    () => new D1Source(d1Double(() => { throw new Error("D1_ERROR: the database cannot be found (7404)"); }), "app-gone").probeLiveness(),
    "deleted",
  );
  await expectMissing(
    "a D1 UUID not found (error 10181) -> kind 'deleted'",
    () => new D1Source(d1Double(() => { throw new Error("D1_ERROR: the D1 database UUID could not be found (10181)"); }), "app-gone2").probeLiveness(),
    "deleted",
  );
  await expectMissing(
    "a D1 storage timeout -> kind 'unavailable'",
    () => new D1Source(d1Double(() => { throw new Error("D1_ERROR: D1 DB storage operation exceeded timeout which caused object to be reset."); }), "app-slow").probeLiveness(),
    "unavailable",
  );
  await expectMissing(
    "a D1 'no such database' proves nothing -> kind 'unavailable'",
    () => new D1Source(d1Double(() => { throw new Error("no such database"); }), "app-vague").probeLiveness(),
    "unavailable",
  );
  // The binding's own throw for a deleted database, measured on a live estate: an Error whose message
  // carries the "D1_ERROR: " prefix and whose string cause is the same text without it.
  const gone = "D1 database 404223c8-fb1d-4712-b315-13be2abe1967 has been deleted.";
  const measured = (message: string): D1Database => d1Double(() => { throw new Error(message, { cause: gone }); });
  await expectMissing("a deleted D1 database, measured binding text with prefix -> kind 'deleted'", () => new D1Source(measured(`D1_ERROR: ${gone}`), "app-del1").probeLiveness(), "deleted");
  await expectMissing("a deleted D1 database, measured binding text without prefix -> kind 'deleted'", () => new D1Source(measured(gone), "app-del2").probeLiveness(), "deleted");
  ok("classifyLivenessFault: measured deleted-D1 text with prefix is 'deleted' (404 class)", (() => { const r = classifyLivenessFault("d1", "x", new Error(`D1_ERROR: ${gone}`)); return r.kind === "deleted" && r.faultClass === "404"; })());
  ok("classifyLivenessFault: measured deleted-D1 text without prefix is 'deleted'", classifyLivenessFault("d1", "x", new Error(gone)).kind === "deleted");
  // Negative controls: outages stay "unavailable"; a different deleted thing is not a deleted database.
  for (const [label, text] of [
    ["a network fault", "D1_ERROR: Network connection lost."],
    ["a timeout", "D1_ERROR: D1 DB storage operation exceeded timeout which caused object to be reset."],
    ["a 5xx-shaped D1 error", "D1_ERROR: D1 database is overloaded. Too many requests queued. (500)"],
    ["a deleted table", "D1_ERROR: table users has been deleted"],
    ["a deleted row set", "D1_ERROR: rows in the database have been deleted"],
  ] as const) {
    await expectMissing(`${label} -> kind 'unavailable'`, () => new D1Source(measured(text), "app-neg").probeLiveness(), "unavailable");
  }
}

// ---- error classification ---------------------------------------------------

function classifyTests(): void {
  console.log("\nclassification:");
  ok("classifyLivenessFault passes through an already-named error", classifyLivenessFault("kv", "x", new SourceResourceMissingError("kv", "x", "deleted")).kind === "deleted");
  const err = new SourceResourceMissingError("kv", "ns-gone", "deleted");
  ok("coarseRunError maps a missing-resource message to 'source resource missing'", coarseRunError(err.message) === "source resource missing");
  // It must NOT be misclassified as a generic source-binding or destination error.
  ok("a missing-resource message is not a generic 'source binding error'", coarseRunError(err.message) !== "source binding error");
  // A probe that failed WITHOUT proof of absence is the transient source class, never "source resource missing".
  const blip = classifyLivenessFault("r2", "media", new Error("list: We encountered an internal error. Please try again. (10001)"));
  ok("an unproven probe fault reads 'source read error' in the run row", coarseRunError(blip.message) === "source read error");
  ok("an unproven probe fault never reads 'source resource missing'", !/source resource missing/.test(blip.message));
  const proven = classifyLivenessFault("r2", "media", new Error("list: The specified bucket does not exist. (10006)"));
  ok("a proven absence reads 'source resource missing' in the run row", coarseRunError(proven.message) === "source resource missing");
  ok("a source type with no absence proof is never 'deleted'", classifyLivenessFault("unknown", "x", new Error("The specified bucket does not exist. (10006)")).kind === "unavailable");
  // A truly generic message stays generic (the classifier did not over-match).
  ok("an unrelated failure stays generic", coarseRunError("something else entirely") === "run failed");
}

// ---- detect-and-alert structured form ---------------------------------------

async function structuredTests(): Promise<void> {
  console.log("\nprobeSourceLiveness (detect-and-alert):");
  ok("a live source -> { status: 'live' }", (await probeSourceLiveness(new KVSource(kvDouble(() => ({ keys: [], list_complete: true })), "ns"))).status === "live");
  const miss = await probeSourceLiveness(new KVSource(kvDouble(() => { throw new Error("list: No KV namespace found with ID 0f2ac74b498b48028cb68387c421e279 (10041)"); }), "ns-gone"));
  ok("a dead source -> { status: 'missing' } with the named error", miss.status === "missing" && (miss as { error: SourceResourceMissingError }).error.kind === "deleted");
  ok("a non-probeable source -> { status: 'unprobeable' }", (await probeSourceLiveness({} as unknown)).status === "unprobeable");
}

// ---- preflight surface ------------------------------------------------------

function schedulerWithDownpipes(downpipes: unknown[]): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/tick-info") return new Response(JSON.stringify({ lastTickAt: Date.now() - 60_000 }));
      if (url.pathname === "/downpipes") return new Response(JSON.stringify(downpipes));
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
}

function item(report: Awaited<ReturnType<typeof runPreflight>>, id: string): { status: string; evidence: string; remediation?: string; required: boolean } {
  return report.items.find((i) => i.id === id) as { status: string; evidence: string; remediation?: string; required: boolean };
}

async function preflightTests(): Promise<void> {
  console.log("\npreflight source-liveness probe:");
  const downpipes = [
    { config: { id: "dp-live", name: "uploads", enabled: true, source: { type: "kv", binding: "SRC_KV_uploads", include: [], exclude: [] } } },
    { config: { id: "dp-gone", name: "archive", enabled: true, source: { type: "r2", binding: "SRC_R2_archive", include: [], exclude: [] } } },
  ];

  // A live KV binding and a DELETED R2 binding (its list throws not-found).
  const envMixed = {
    SCHEDULER: {} as DurableObjectNamespace,
    SRC_KV_uploads: kvDouble(() => ({ keys: [], list_complete: true })),
    SRC_R2_archive: r2Double(() => { throw new Error("bucket does not exist"); }),
  } as unknown as Env;
  const mixed = await runPreflight(envMixed, schedulerWithDownpipes(downpipes));
  const sl = item(mixed, "source-liveness");
  ok("a deleted source resource FAILS the source-liveness item", sl.status === "failed");
  ok("the failure names the broken binding and downpipe", sl.evidence.includes("SRC_R2_archive") && sl.evidence.includes("archive"));
  ok("the failure does not name the live binding", !sl.evidence.includes("SRC_KV_uploads"));
  ok("the remediation tells the operator to re-create/re-point (and never auto-creates)", /re-create|re-point/i.test(sl.remediation ?? "") && /never auto-creates/i.test(sl.remediation ?? ""));

  // THE ITEM'S CAUSE CLASS. "not-found" only when a probe answer PROVED the resource gone (R2 error 10006). A
  // timeout, a 5xx, a 429, a network fault, a bare 404 or a vague "does not exist" is not proof, so the item
  // and the binding carry that fault's own class and never "not-found".
  type SlItem = { status: string; probeErrorClass?: string; missingResources?: Array<{ binding: string; kind: string; probeErrorClass?: string }> };
  const r2Only = [downpipes[1]];
  const classOf = async (msg: string): Promise<SlItem> => {
    const env = { SCHEDULER: {} as DurableObjectNamespace, SRC_R2_archive: r2Double(() => { throw new Error(msg); }) } as unknown as Env;
    return (await runPreflight(env, schedulerWithDownpipes(r2Only))).items.find((i) => i.id === "source-liveness") as SlItem;
  };
  const proven = await classOf("list: The specified bucket does not exist. (10006)");
  ok("a PROVEN absence (R2 10006): the item's probeErrorClass is 'not-found'", proven.status === "failed" && proven.probeErrorClass === "not-found");
  ok("a PROVEN absence: the binding's kind is 'deleted' and its class 'not-found'", proven.missingResources?.[0]?.kind === "deleted" && proven.missingResources[0].probeErrorClass === "not-found");
  for (const [label, msg, want] of [
    ["a timeout", "list: The operation was aborted due to timeout", "timeout"],
    ["a network fault", "Network connection lost.", "transport"],
    ["a 5xx status", "list: status 503 Service Unavailable", "unavailable"],
    ["a 429 status", "list: status 429 Too Many Requests", "rate-limited"],
    ["an R2 500 code with no status (10001)", "list: We encountered an internal error. Please try again. (10001)", "other"],
    ["a bare 404 status", "list: status 404", "other"],
    ["a vague 'does not exist'", "bucket does not exist", "other"],
  ] as const) {
    const it = await classOf(msg);
    ok(`${label}: the item fails and is NOT 'not-found' (${it.probeErrorClass})`, it.status === "failed" && it.probeErrorClass === want);
    ok(`${label}: the binding reads kind 'unavailable' with class '${want}'`, it.missingResources?.[0]?.kind === "unavailable" && it.missingResources[0].probeErrorClass === want);
  }
  // Two bindings that disagree: one proven gone, one timing out. The item leads with the proven absence.
  const both = [
    downpipes[1],
    { config: { id: "dp-slow", name: "slow", enabled: true, source: { type: "r2", binding: "SRC_R2_slow", include: [], exclude: [] } } },
  ];
  const envBoth = {
    SCHEDULER: {} as DurableObjectNamespace,
    SRC_R2_archive: r2Double(() => { throw new Error("list: The specified bucket does not exist. (10006)"); }),
    SRC_R2_slow: r2Double(() => { throw new Error("list: The operation was aborted due to timeout"); }),
  } as unknown as Env;
  const mixedItem = (await runPreflight(envBoth, schedulerWithDownpipes(both))).items.find((i) => i.id === "source-liveness") as SlItem;
  ok("a proven absence beside a timeout: the item reads 'not-found' and each binding keeps its own class",
    mixedItem.probeErrorClass === "not-found" &&
    mixedItem.missingResources?.find((m) => m.binding === "SRC_R2_archive")?.probeErrorClass === "not-found" &&
    mixedItem.missingResources?.find((m) => m.binding === "SRC_R2_slow")?.probeErrorClass === "timeout");
  // The probe's own throw rides as the non-enumerable Error cause: a JSON dump of the error never carries it.
  const withCause = classifyLivenessFault("r2", "archive", new Error("list: status 503 raw platform text"));
  ok("the probe's throw is kept only as the non-enumerable cause (not in a JSON dump)", withCause.cause instanceof Error && !JSON.stringify(withCause).includes("raw platform text"));

  // All resources live -> verified.
  const envLive = {
    SCHEDULER: {} as DurableObjectNamespace,
    SRC_KV_uploads: kvDouble(() => ({ keys: [], list_complete: true })),
    SRC_R2_archive: r2Double(() => ({ objects: [], truncated: false })),
  } as unknown as Env;
  ok("all-live source resources VERIFY", item(await runPreflight(envLive, schedulerWithDownpipes(downpipes)), "source-liveness").status === "verified");

  // Minimal bindings (present but no list/prepare) -> present-but-unproven, NOT a false alarm.
  const envMinimal = { SCHEDULER: {} as DurableObjectNamespace, SRC_KV_uploads: {}, SRC_R2_archive: {} } as unknown as Env;
  ok("minimal/unprobeable bindings are present-but-unproven, not failed", item(await runPreflight(envMinimal, schedulerWithDownpipes(downpipes)), "source-liveness").status === "configured");

  // No binding-backed sources -> unconfigured.
  const cfOnly = [{ config: { id: "dp-cf", name: "cf", source: { type: "cf-config", accountId: "a", include: [], exclude: [] } } }];
  ok("a cf-config-only fleet is unconfigured for liveness", item(await runPreflight({ SCHEDULER: {} as DurableObjectNamespace } as unknown as Env, schedulerWithDownpipes(cfOnly)), "source-liveness").status === "unconfigured");
}

async function main(): Promise<void> {
  await kvTests();
  await r2d1Tests();
  classifyTests();
  await structuredTests();
  await preflightTests();
  console.log("");
  verdictReached(failures);
  if (failures > 0) {
    console.log(`SOURCE LIVENESS (SRC-1) TESTS FAILED: ${failures}`);
    process.exit(1);
  }
  console.log("SOURCE LIVENESS (SRC-1) TESTS PASS");
}

void main();
