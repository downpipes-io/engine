// Source-resource liveness probe + the named "source resource missing" failure class.
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
    "a deleted KV namespace (not-found throw) -> kind 'deleted'",
    () => new KVSource(kvDouble(() => { throw new Error("KV namespace not found"); }), "ns-gone").probeLiveness(),
    "deleted",
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
    "a deleted R2 bucket -> kind 'deleted'",
    () => new R2Source(r2Double(() => { throw new Error("The specified bucket does not exist"); }), "media-gone").probeLiveness(),
    "deleted",
  );

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
    "a deleted D1 database -> kind 'deleted'",
    () => new D1Source(d1Double(() => { throw new Error("no such database"); }), "app-gone").probeLiveness(),
    "deleted",
  );
}

// ---- error classification ---------------------------------------------------

function classifyTests(): void {
  console.log("\nclassification:");
  ok("classifyLivenessFault passes through an already-named error", classifyLivenessFault("kv", "x", new SourceResourceMissingError("kv", "x", "deleted")).kind === "deleted");
  const err = new SourceResourceMissingError("kv", "ns-gone", "deleted");
  ok("coarseRunError maps a missing-resource message to 'source resource missing'", coarseRunError(err.message) === "source resource missing");
  // It must NOT be misclassified as a generic source-binding or destination error.
  ok("a missing-resource message is not a generic 'source binding error'", coarseRunError(err.message) !== "source binding error");
  // A truly generic message stays generic (the classifier did not over-match).
  ok("an unrelated failure stays generic", coarseRunError("something else entirely") === "run failed");
}

// ---- detect-and-alert structured form ---------------------------------------

async function structuredTests(): Promise<void> {
  console.log("\nprobeSourceLiveness (detect-and-alert):");
  ok("a live source -> { status: 'live' }", (await probeSourceLiveness(new KVSource(kvDouble(() => ({ keys: [], list_complete: true })), "ns"))).status === "live");
  const miss = await probeSourceLiveness(new KVSource(kvDouble(() => { throw new Error("namespace not found"); }), "ns-gone"));
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
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`SOURCE LIVENESS TESTS FAILED: ${failures}`);
    process.exit(1);
  }
  console.log("SOURCE LIVENESS TESTS PASS");
}

void main();
