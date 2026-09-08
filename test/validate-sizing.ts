// Validate the cost SIZING probe and its Cloudflare Analytics client (src/cost/cf-analytics.ts,
// src/cost/sizing-probe.ts): the analytics-first onboarding size estimate. No network and no live
// Cloudflare: a fake fetch returns fixture GraphQL bodies, so the parsing, the graceful-null failure
// paths and the probe's analytics-first/unavailable logic are all exercised deterministically.
// Run: node test/validate-sizing.ts
//
// The client is BEST-EFFORT: any HTTP error, GraphQL errors array, unparseable body or unexpected shape
// must yield null (never a throw, never a wrong number), so the probe degrades to "unavailable" and the
// estimate stays honest. The fixtures cover each of those failure shapes.

import { isCfSize, makeCfAnalytics } from "../src/cost/cf-analytics.ts";
import { estimateSourceSize, estimateEstateSize } from "../src/cost/sizing-probe.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

// A fetch stub returning one fixed body (ok by default). Shaped just enough for the client (resp.ok +
// resp.json()).
function fetchReturning(body: unknown, ok2 = true, status = ok2 ? 200 : 500): typeof fetch {
  return (async () => ({ ok: ok2, status, json: async () => body })) as unknown as typeof fetch;
}
// A fetch stub returning successive bodies, one per call (for the multi-source estate roll-up).
function fetchQueue(bodies: unknown[]): typeof fetch {
  let i = 0;
  return (async () => {
    const b = i < bodies.length ? bodies[i] : null;
    i += 1;
    return { ok: true, status: 200, json: async () => b };
  }) as unknown as typeof fetch;
}

const KV_FIXTURE = { data: { viewer: { accounts: [{ kvStorageAdaptiveGroups: [{ max: { byteCount: 1_048_576, keyCount: 1000 } }] }] } } };
const R2_FIXTURE = { data: { viewer: { accounts: [{ r2StorageAdaptiveGroups: [{ max: { payloadSize: 2_000_000, metadataSize: 4000, objectCount: 50 } }] }] } } };
const GQL_ERRORS = { errors: [{ message: "no analytics scope on this token" }] };
const EMPTY_ACCOUNTS = { data: { viewer: { accounts: [] } } };
const NO_GROUP = { data: { viewer: { accounts: [{ kvStorageAdaptiveGroups: [] }] } } };
const NO_MAX = { data: { viewer: { accounts: [{ kvStorageAdaptiveGroups: [{}] }] } } };

async function main(): Promise<void> {
  // --- client parsing (the happy paths) ---
  // isCfSize, not `!== null`: an unmeasurable size answers with a fault CLASS STRING rather than a bare
  // null, so `!== null` would let "schema-drift" through the guard and only the field comparisons would
  // catch it. The engine's own narrowing predicate is the honest gate, and it asserts strictly more.
  const kv = await makeCfAnalytics("tok", fetchReturning(KV_FIXTURE)).kvNamespaceSize("acct", "ns1");
  ok("kv size parses byteCount and keyCount", isCfSize(kv) && kv.bytes === 1_048_576 && kv.count === 1000);
  const r2 = await makeCfAnalytics("tok", fetchReturning(R2_FIXTURE)).r2BucketSize("acct", "bucket");
  ok("r2 size sums payload + metadata and reads objectCount", isCfSize(r2) && r2.bytes === 2_004_000 && r2.count === 50);

  // --- client graceful failure -------------------------------------------------------------------------
  // No shape may throw, and none may yield a WRONG NUMBER -- the probe still degrades to "unavailable". The
  // failure is never a bare null: distinguishing the fault classes is the whole point, since an auth/scope
  // fault is a token the operator must widen (permanent, actionable), a SCHEMA DRIFT is a Cloudflare-side
  // dataset change no customer action can fix, and a network fault heals itself. A single collapsed answer
  // would make an analytics response the engine could not read indistinguishable from a source that
  // genuinely holds nothing -- showing the customer an EMPTY ACCOUNT and inviting them to conclude they had
  // nothing to back up.
  ok("graphql errors array -> schema-drift (the dataset stopped answering; NOT the customer's fault)", (await makeCfAnalytics("t", fetchReturning(GQL_ERRORS)).kvNamespaceSize("a", "n")) === "schema-drift");
  ok("http 401 -> auth-or-scope (a token to widen: permanent and actionable)", (await makeCfAnalytics("t", fetchReturning(KV_FIXTURE, false, 401)).kvNamespaceSize("a", "n")) === "auth-or-scope");
  ok("http 403 -> auth-or-scope (not a blip to wait out)", (await makeCfAnalytics("t", fetchReturning(KV_FIXTURE, false, 403)).kvNamespaceSize("a", "n")) === "auth-or-scope");
  ok("http 5xx -> network (a blip, distinct from a scope gap)", (await makeCfAnalytics("t", fetchReturning(KV_FIXTURE, false, 503)).kvNamespaceSize("a", "n")) === "network");
  ok("empty accounts -> schema-drift", (await makeCfAnalytics("t", fetchReturning(EMPTY_ACCOUNTS)).kvNamespaceSize("a", "n")) === "schema-drift");
  ok("empty group list -> schema-drift", (await makeCfAnalytics("t", fetchReturning(NO_GROUP)).kvNamespaceSize("a", "n")) === "schema-drift");
  ok("group without max -> schema-drift (no wrong number)", (await makeCfAnalytics("t", fetchReturning(NO_MAX)).kvNamespaceSize("a", "n")) === "schema-drift");
  const nullBody = fetchReturning(null);
  const throwing = (async () => { throw new Error("network down"); }) as unknown as typeof fetch;
  ok("a null json body -> schema-drift", (await makeCfAnalytics("t", nullBody).kvNamespaceSize("a", "n")) === "schema-drift");
  ok("a thrown fetch (network fault) -> network", (await makeCfAnalytics("t", throwing).kvNamespaceSize("a", "n")) === "network");

  // --- the probe: analytics-first, unavailable otherwise ---
  const kvDeps = { analytics: makeCfAnalytics("t", fetchReturning(KV_FIXTURE)), accountId: "acct" };
  const kvEst = await estimateSourceSize({ type: "kv", namespaceId: "ns1" }, kvDeps);
  ok("probe sizes a kv source from analytics", kvEst.basis === "analytics" && kvEst.bytes === 1_048_576 && kvEst.count === 1000);
  const r2Deps = { analytics: makeCfAnalytics("t", fetchReturning(R2_FIXTURE)), accountId: "acct" };
  ok("probe sizes an r2 source from analytics", (await estimateSourceSize({ type: "r2", bucketName: "b" }, r2Deps)).basis === "analytics");
  ok("probe reports d1 as unavailable (not yet analytics-sized)", (await estimateSourceSize({ type: "d1" }, kvDeps)).basis === "unavailable");
  ok("probe reports kv without a namespace id as unavailable", (await estimateSourceSize({ type: "kv" }, kvDeps)).basis === "unavailable");
  ok("an unavailable estimate is zero, never a guess", (await estimateSourceSize({ type: "d1" }, kvDeps)).bytes === 0);

  // --- estate roll-up: totals + sized-source count, unavailable contributes zero ---
  const estate = await estimateEstateSize(
    [{ type: "kv", namespaceId: "ns1" }, { type: "r2", bucketName: "b" }, { type: "d1" }],
    { analytics: makeCfAnalytics("t", fetchQueue([KV_FIXTURE, R2_FIXTURE])), accountId: "acct" },
  );
  ok("estate totals sum only the sized sources", estate.totalBytes === 1_048_576 + 2_004_000 && estate.totalCount === 1050);
  ok("estate counts how many sources were sized (2 of 3)", estate.sizedSources === 2 && estate.perSource.length === 3);

  console.log(failures === 0 ? "\nALL SIZING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
