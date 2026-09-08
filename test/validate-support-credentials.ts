// Prove the support pack carries the metrics-feed grant state and the full credential-expiry registry.
//
// The pack must carry more than two expiry COUNTS (status.expiryWarnings / cleanupPending) and the
// audit-feed grant: the metrics-scope ingest credential and the per-row expiry registry must ride too, so
// "our metrics scraper stopped collecting" and "which credential is expiring / needs cleanup" are
// diagnosable. fetchMetricsFeed mirrors the audit-feed grant for the metrics scope; fetchExpiryRegistry
// projects the whole registry (worst-state-first, capped, redaction-safe). This drives both real gatherers
// through DO doubles and asserts the projection and, load-bearing, that no free-text label/purpose/note and
// no token value ever appear.
//
// Run:  node test/validate-support-credentials.ts

import { fetchMetricsFeed } from "../src/admin/support-sections-audit.ts";
import { fetchExpiryRegistry } from "../src/admin/support-sections-config.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function scheduler(routes: Record<string, unknown>): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const key = url.pathname + url.search;
      if (key in routes) return new Response(JSON.stringify(routes[key]));
      if (url.pathname in routes) return new Response(JSON.stringify(routes[url.pathname]));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("validate-support-credentials\n");

  // ---- metricsFeed ----
  const granted = scheduler({ "/ingest-credential?scope=metrics": { grant: { grantedAt: "2026-01-01T00:00:00Z", expiresAt: "2026-06-01T00:00:00Z", pulls: [{ at: "2026-05-30T00:00:00Z" }, { at: "2026-05-31T00:00:00Z" }] } } });
  const mf = (await fetchMetricsFeed(granted)) as Record<string, unknown>;
  ok("metricsFeed carries configured + pullCount + last-pull recency", mf.configured === true && mf.pullCount === 2 && mf.lastPullAt === "2026-05-31T00:00:00Z");
  ok("metricsFeed marks an elapsed grant expired", mf.expired === true);
  const ungranted = (await fetchMetricsFeed(scheduler({ "/ingest-credential?scope=metrics": { grant: null } }))) as Record<string, unknown>;
  ok("an ungranted metrics scope reads configured:false (section() marks it empty)", ungranted.configured === false);

  // ---- expiryRegistry ----
  const expiryRows = [
    { id: "s3-access-key", label: "S3 destination access key", kind: "credential", lifecycleClass: "functional", state: "ok", purpose: "SECRET PURPOSE TEXT" },
    { id: "attach-token-1", label: "one-shot attach token", kind: "token", lifecycleClass: "ephemeral", state: "expired", tokenRef: "cf-token-abc", usedAt: "2026-05-01T00:00:00Z" },
    { id: "saml-cert", kind: "certificate", state: "approaching" },
    { id: "junk", kind: "not-a-kind", state: "not-a-state" },
  ];
  const reg = (await fetchExpiryRegistry(scheduler({ "/expiry": expiryRows }))) as { rows: Array<Record<string, unknown>> };

  ok("expiryRegistry carries a row per registry item", Array.isArray(reg.rows) && reg.rows.length === 4);
  // The head row is pulled out once. The length check above does not narrow the index, so `worst` is read
  // optionally: a projection that returned NO rows leaves it undefined, which fails both checks below rather
  // than throwing before the redaction assertion at the end of the cell gets to run.
  const worst = reg.rows[0];
  ok("rows are ordered worst-state-first (expired before approaching before ok)", worst?.id === "attach-token-1" && worst?.state === "expired");
  ok("an ephemeral token row carries hasTokenRef:true + usedAt (actionable)", worst?.hasTokenRef === true && worst?.usedAt === "2026-05-01T00:00:00Z");
  ok("a row without a token ref carries hasTokenRef:false", reg.rows.find((r) => r.id === "s3-access-key")?.hasTokenRef === false);
  ok("out-of-vocab kind/state are dropped, not echoed", (() => { const j = reg.rows.find((r) => r.id === "junk"); return j !== undefined && j.kind === undefined && j.state === undefined; })());
  // Load-bearing redaction: NO free-text label / purpose, and NO token value, anywhere.
  const regStr = JSON.stringify(reg);
  ok("expiryRegistry NEVER carries a free-text label/purpose or the token value (redaction)", !regStr.includes("S3 destination access key") && !regStr.includes("SECRET PURPOSE TEXT") && !regStr.includes("cf-token-abc"));

  console.log(failures === 0 ? "\nALL SUPPORT-CREDENTIALS VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
