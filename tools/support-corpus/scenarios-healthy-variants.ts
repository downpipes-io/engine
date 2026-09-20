// HEALTHY-VARIANT corpus scenarios: legitimately-fine deployments in many shapes, hunting bot
// FALSE POSITIVES. Every world here is a realistic, correctly-operated fleet that comes CLOSE to a
// signal's firing condition without meeting it (a stale failure, an intentional knob, an optional
// subsystem configured and healthy). A variant that cannot read HEALTHY under the bot's DESIGNED
// behaviour is labelled truthfully and flagged as a FINDING (see below) — never patched around.
//
// ## FINDINGS (designed behaviour that mis-serves a legitimately-healthy customer)
//
// FINDING F-HV1 (healthy.fresh-install) — PARTIALLY FIXED 2026-07-02: plan-ceiling-exceeded now fires
//   only when some recorded tick has dispatched>0 (the fleet actually works), so a pristine day-one
//   engine no longer gets the scary platform warning during the golden first-touch window. The
//   remaining half stands by design: diagnose() still requires anyRun===true to reach HEALTHY, so a
//   no-runs-yet fresh install reads INDETERMINATE + escalate (a human confirms "setup verified,
//   awaiting first run") — the candidate NO-RUNS-YET/SETUP-OK reading remains future work.
//
// FINDING F-HV2 (healthy.recent-redeploy) — FIXED 2026-07-02: deploy-identity-changed is now a
//   CORRELATOR — it fires only when the recent deploy coincides with something OFF (a not-verified
//   source-bindings probe, a failed/stalled run, records incomplete/skipped, or a sources-detached
//   event). A routine same-config redeploy with bindings verified and runs green reads HEALTHY and
//   auto-posts. The owner-#1 chain is unaffected (roster-dropped-across-version-change + the
//   bindings-probe-failed branch route it independently).
//
// FINDING F-HV3 (healthy.tier0-verify) — FIXED 2026-07-02: tier0-verify-only no longer fires on
//   tier0Cause="sample-off" (an INTENTIONAL operator knob; the pack's sealKnobs still show it for a
//   human reviewer). break-glass / too-large still fire (states the operator may not have intended);
//   see seal.tier0-only-break-glass.

import { DEST_HOST, liveKvNamespace, type Scenario, type World } from "./harness.ts";
import { loadSigner } from "../../src/keys-env.ts";
import { hybridSign } from "../../src/crypto/sign.ts";
import { canonicalJSON } from "../../src/format/canonjson.ts";
import { b64urlEncode, concat } from "../../src/crypto/bytes.ts";

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const iso = (t: number): string => new Date(t).toISOString();

type Dict = Record<string, unknown>;

function dp1(w: World): Dict {
  return (w.routes["/downpipes"] as Dict[])[0]!;
}
function runs(w: World): Dict[] {
  return ((w.routes["/history"] as Dict).byDownpipe as Record<string, Dict[]>)["dp1"]!;
}
function bundleText(b: Dict): string {
  return JSON.stringify(b);
}
function expectInBundle(b: Dict, needle: string, what: string): string[] {
  return bundleText(b).includes(needle) ? [] : [`bundle does not carry ${what} (expected substring ${JSON.stringify(needle)})`];
}
function preflightItem(b: Dict, id: string): Dict | undefined {
  const items = ((b["preflight"] as Dict)?.["items"] ?? []) as Dict[];
  return items.find((i) => i["id"] === id);
}

/** A healthy ok run row in the exact shape the baseline history rows use. */
function okRun(runId: string, index: number, startedAt: number, recordCount: number, bytes: number): Dict {
  return {
    runId,
    index,
    startedAt: iso(startedAt),
    status: "ok",
    recordCount,
    bytes,
    durationMs: 700 + (recordCount % 900),
    recordsSkipped: 0,
    recordsIncomplete: 0,
    destinationId: "d-primary",
    sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: Math.min(8, recordCount), at: startedAt + MIN },
  };
}

// ---------------------------------------------------------------------------
// A REAL vendor-signed enterprise licence, minted once per emit with the same claim shape the
// control plane mints (canonical-JSON body, hybrid Ed25519+ML-DSA signature, b64url(body).b64url(sig)).
// The engine pins LICENCE_SIGNER_PUBLIC and verifies for real — no hand-shaped licence block.
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
const LICENCE_NOT_AFTER = new Date(Date.now() + 365 * DAY).toISOString();
const licenceVendor = await loadSigner(b64urlEncode(concat(rand(32), rand(32))));
const LICENCE_SIGNER_PIN = b64urlEncode(concat(licenceVendor.edPublic, licenceVendor.mldsaPublic));
const licenceBody = canonicalJSON({ account: "acct-corpus-lab", features: ["dashboard", "managed-drill", "priority-support"], notAfter: LICENCE_NOT_AFTER, tier: "enterprise" });
const LICENCE_TOKEN = `${b64urlEncode(licenceBody)}.${b64urlEncode(await hybridSign(licenceVendor.edPrivate, licenceVendor.mldsaSecret, licenceBody))}`;

// A bucket that REALLY enforces Object-Lock: the exact GetObjectLockConfiguration 200 body S3 returns
// (parseObjectLockConfig requires <ObjectLockConfiguration ...> + <ObjectLockEnabled>Enabled</...>).
const OBJECT_LOCK_ENFORCED_XML =
  '<?xml version="1.0" encoding="UTF-8"?>' +
  '<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
  "<ObjectLockEnabled>Enabled</ObjectLockEnabled>" +
  "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule>" +
  "</ObjectLockConfiguration>";

export const HEALTHY_VARIANT_SCENARIOS: Scenario[] = [
  // F-HV1 (partially fixed 2026-07-02): plan-ceiling-exceeded no longer cries wolf on a fleet that has
  // never dispatched (its ticks show dispatched 0), so the fresh install keeps only the by-design
  // INDETERMINATE no-runs-yet reading (a human confirms "setup verified, awaiting first run").
  {
    id: "healthy.fresh-install",
    title: "day-one engine: keys ceremony done, dest console-set + live-verified, no downpipes, no runs",
    domain: "healthy-variant",
    trueClass: "INDETERMINATE",
    isFault: false,
    expectEscalate: true,
    expectSignals: [],
    expectAbsentSignals: ["plan-ceiling-exceeded", "backup-overdue", "posture-failed", "bindings-probe-failed", "deploy-identity-changed", "recovery-required", "dest-auth-failed"],
    mutate: (w) => {
      const now = Date.now();
      // Deployed this morning; nothing attached yet. The DO answers honestly-empty everywhere.
      w.routes["/downpipes"] = [];
      w.routes["/history"] = { byDownpipe: {} };
      w.routes["/replication"] = { byDownpipe: {} };
      w.routes["/notify/history"] = [];
      w.routes["/scheduler-signals"] = {
        ticks: [
          { at: now - 8 * MIN, intervalMs: 300_000, due: 0, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 9, budgetRemaining: 691, overBudget: false },
          { at: now - 3 * MIN, intervalMs: 300_000, due: 0, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 7, budgetRemaining: 693, overBudget: false },
        ],
        dueIndex: { at: now - 3 * MIN, indexEntriesBeforeRebuild: 0, indexEntriesRequired: 0, dpTotal: 0, matched: true },
        runlog: { counter: 0, maxHistoryIndex: 0 },
        storageFaults: { total: 0, valueTooLarge: 0, putFailed: 0 },
      };
      // First deploy TODAY: the baseline was just established; zero identity CHANGES observed.
      w.routes["/control-plane/recovery-status"] = {
        recoveryRequired: false,
        configEmpty: true,
        resumeApplied: false,
        deploy: { engineVersion: "0.1.0", cfVersionId: "cfv-current-001", cfVersionIdAbsent: false, baselineEstablished: true, changesObserved: 0, firstSeenAt: iso(now - 4 * HOUR), lastSeenAt: iso(now - 5 * MIN) },
        exportHealth: { at: iso(now - 15 * MIN), wroteAny: true, configVersion: 1, perDest: [{ id: "d-primary", ok: true }] },
      };
      w.routes["/control-plane/export-state"] = { configVersion: 1, exportedAt: iso(now - 15 * MIN) };
      w.routes["/status-baseline"] = { version: "0.1.0", cfVersionId: "cfv-current-001", at: now - 4 * HOUR };
      w.routes["/config-history-health"] = { count: 2, headId: 2, verify: { intact: true, checkedThrough: 2, earliestId: 1 } };
    },
    capture: (b) => {
      const dest = preflightItem(b, "destination");
      const fails: string[] = [];
      if (dest?.["status"] !== "verified") fails.push(`preflight destination expected verified (console-set + live HEAD), got ${String(dest?.["status"])}`);
      if (((b["downpipes"] as Dict[]) ?? []).length !== 0) fails.push("expected an empty downpipe roster");
      return fails;
    },
  },

  // Diagnosis-bug-8 lock-in: a token-source-only fleet (cf-config + workers) has NO binding and NO
  // liveness probe by design — unconfigured-with-required:false must stay a valid state, not a fault.
  {
    id: "healthy.token-source-fleet",
    title: "cf-config + workers token-source fleet: discovery token verified, no binding sources at all",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["bindings-probe-failed", "posture-failed", "discovery-surfaces-unavailable", "source-records-collapsed"],
    mutate: (w) => {
      const now = Date.now();
      delete w.env["UPLOADS_KV"]; // no binding-backed source anywhere on this fleet
      w.routes["/downpipes"] = [
        {
          config: { id: "dp-cfg", name: "cloudflare-config", enabled: true, cadenceSeconds: 86400, source: { type: "cf-config", accountId: "acct-corpus-lab", include: [], exclude: [] } },
          lastRunId: "01CFGOK",
          inFlight: false,
          nextRunAt: now + 20 * HOUR,
          cronResolve: { class: "ok", at: now + 20 * HOUR },
          lastRestoreTestAt: now - 9 * HOUR,
          lastRestoreTestOk: true,
          cfConfigDiscovery: { at: now - 90 * MIN, present: ["dns_records", "rulesets", "page_rules", "load_balancers", "firewall_rules"], empty: ["waiting_rooms"], gated: [], unavailable: [] },
        },
        {
          config: { id: "dp-wrk", name: "workers-scripts", enabled: true, cadenceSeconds: 86400, source: { type: "workers", accountId: "acct-corpus-lab", include: [], exclude: [] } },
          lastRunId: "01WRKOK",
          inFlight: false,
          nextRunAt: now + 22 * HOUR,
          lastRestoreTestAt: now - 11 * HOUR,
          lastRestoreTestOk: true,
        },
      ];
      w.routes["/history"] = {
        byDownpipe: {
          "dp-cfg": [okRun("01CFGOK", 5, now - 3 * HOUR, 214, 350_000), okRun("01CFGPRV", 4, now - 27 * HOUR, 213, 348_500)],
          "dp-wrk": [okRun("01WRKOK", 5, now - 4 * HOUR, 12, 120_000), okRun("01WRKPRV", 4, now - 28 * HOUR, 12, 119_800)],
        },
      };
      w.routes["/replication"] = {
        byDownpipe: {
          "dp-cfg": { "d-primary": { holdsRunId: "01CFGOK", holdsIndex: 5, lastOk: true, lastAttemptAt: now - 3 * HOUR + MIN } },
          "dp-wrk": { "d-primary": { holdsRunId: "01WRKOK", holdsIndex: 5, lastOk: true, lastAttemptAt: now - 4 * HOUR + MIN } },
        },
      };
      // The console-set discovery token resolves (the api-source-discovery-token probe verifies it).
      w.routes["/sources/discovery-config"] = { config: { engineAccountId: "acct-corpus-lab", token: "corpus-read-only-discovery-token" } };
      w.routes["/notify/history"] = [
        { seq: 2, ts: iso(now - 3 * HOUR + 2 * MIN), event: "backup-success", severity: "info", downpipeId: "dp-cfg", channelKind: "webhook", delivered: true },
        { seq: 1, ts: iso(now - 4 * HOUR + 2 * MIN), event: "backup-success", severity: "info", downpipeId: "dp-wrk", channelKind: "webhook", delivered: true },
      ];
      const sched = w.routes["/scheduler-signals"] as Dict;
      sched["dueIndex"] = { at: now - 3 * MIN, indexEntriesBeforeRebuild: 2, indexEntriesRequired: 2, dpTotal: 2, matched: true };
    },
    capture: (b) => {
      const fails: string[] = [];
      const sb = preflightItem(b, "source-bindings");
      if (sb?.["status"] !== "unconfigured" || sb?.["required"] !== false) fails.push(`preflight source-bindings expected unconfigured/required:false, got ${String(sb?.["status"])}/${String(sb?.["required"])}`);
      const tok = preflightItem(b, "api-source-discovery-token");
      if (tok?.["status"] !== "verified") fails.push(`preflight api-source-discovery-token expected verified, got ${String(tok?.["status"])}`);
      return fails;
    },
  },

  // F-C1/F-C2 lock-in: a community engine (valid:false, reasonCode no-token) is a fully-valid tier,
  // not an entitlement fault; webhook-only alerting with no Access/email is a complete small setup.
  {
    id: "healthy.community-minimal",
    title: "community licence (no-token), one KV downpipe, webhook-only alerting, no Access, no email",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["licence-invalid", "licence-expired", "licence-expiring-soon", "licence-expiry-stale", "posture-failed", "no-notify-channels"],
    mutate: (w) => {
      // A one-person shop's single KV namespace; no licence env anywhere (the harness default).
      delete w.env["UPLOADS_KV"];
      w.env["SESSIONS_KV"] = liveKvNamespace();
      const d = dp1(w);
      (d["config"] as Dict)["name"] = "sessions";
      (d["config"] as Dict)["source"] = { type: "kv", binding: "SESSIONS_KV", namespaceId: "ns-sessions", include: [], exclude: [] };
    },
    capture: (b) => [
      ...expectInBundle(b, '"reasonCode":"no-token"', "the community no-token licence reason code"),
      ...expectInBundle(b, '"tier":"community"', "the community licence tier"),
    ],
  },

  // 3-2-1 done right: three destinations all holding the SAME latest run, canary alive. Neither
  // replication-redundancy-degraded (indices aligned) nor destination-degraded (all ok) may fire.
  {
    id: "healthy.replicated-321",
    title: "origin + 2 replicas all lastOk with aligned holdsIndex; canary enabled and alive",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["replication-redundancy-degraded", "destination-degraded", "canary-standing-death", "dest-write-misconfigured", "throttled"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/destinations"] = {
        destinations: [
          { id: "d-primary", label: "Primary R2", endpointHost: DEST_HOST, bucket: "corpus-archive", addressing: "path" },
          { id: "d-replica-s3", label: "Offsite S3", endpointHost: "s3.ap-southeast-2.amazonaws.com", bucket: "corpus-replica", addressing: "auto" },
          { id: "d-replica-b2", label: "Offsite B2", endpointHost: "s3.us-west-004.backblazeb2.com", bucket: "corpusreplica2", addressing: "path" },
        ],
        defaultId: "d-primary",
      };
      w.routes["/replication"] = {
        byDownpipe: {
          dp1: {
            "d-primary": { holdsRunId: "01RUNOK", holdsIndex: 7, lastOk: true, lastAttemptAt: now - 54 * MIN },
            "d-replica-s3": { holdsRunId: "01RUNOK", holdsIndex: 7, lastOk: true, lastAttemptAt: now - 53 * MIN },
            "d-replica-b2": { holdsRunId: "01RUNOK", holdsIndex: 7, lastOk: true, lastAttemptAt: now - 52 * MIN },
          },
        },
      };
      const rs = w.routes["/control-plane/recovery-status"] as Dict;
      rs["exportHealth"] = { at: iso(now - 20 * MIN), wroteAny: true, configVersion: 7, perDest: [{ id: "d-primary", ok: true }, { id: "d-replica-s3", ok: true }, { id: "d-replica-b2", ok: true }] };
      w.routes["/canary/transitions"] = { enabled: true, status: "alive", deadDestinations: 0, transitionCount: 0, transitions: [] };
    },
    capture: (b) => expectInBundle(b, '"holdsIndex":7', "the aligned replica holdsIndex"),
  },

  // The opt-in reconcile pass turned ON and CLEAN: an all-ok inventory must add zero signals.
  {
    id: "healthy.reconcile-enabled-clean",
    title: "reconcile inventory present and all-ok: runlog ok, 0 orphans, 0 residuals, committed > 0",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["reconcile-runlog-corrupt", "reconcile-orphans-present", "freshness-residual-present"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/reconcile-inventory"] = {
        byDest: [
          { destKey: "d-primary", at: now - 2 * HOUR, runlogPresent: true, runlogSigVerified: true, runlogHealth: "ok", committed: 8, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, freshnessResiduals: 0, circuitBreakerTripped: false },
        ],
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"runlogHealth":"ok"', "the clean reconcile runlog verdict"),
      ...expectInBundle(b, '"committed":8', "the reconcile committed count"),
    ],
  },

  // F-HV2 FIXED 2026-07-02: deploy-identity-changed is now a correlator — a routine same-config
  // redeploy with bindings verified and runs green stays QUIET and the fleet reads clean HEALTHY.
  {
    id: "healthy.recent-redeploy",
    title: "same-config redeploy 30 minutes ago: bindings verified, runs green, deploy tracker saw 1 change",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["deploy-identity-changed", "bindings-probe-failed", "roster-dropped-across-version-change", "user-removed-binding", "recovery-required"],
    mutate: (w) => {
      const now = Date.now();
      // The deploy tracker observed exactly one identity change (the redeploy), half an hour ago.
      (w.env as Dict)["CF_VERSION_METADATA"] = { id: "cfv-current-002", tag: "v8" };
      const rs = w.routes["/control-plane/recovery-status"] as Dict;
      const deploy = rs["deploy"] as Dict;
      deploy["cfVersionId"] = "cfv-current-002";
      deploy["changesObserved"] = 1;
      deploy["lastChangeAt"] = iso(now - 30 * MIN);
      deploy["lastSeenAt"] = iso(now - 2 * MIN);
    },
    capture: (b) => expectInBundle(b, '"changesObserved":1', "the deploy tracker's observed identity change"),
  },

  // A SIEM collector actively pulling the audit feed: configured + recent pull must NOT read lapsed.
  {
    id: "healthy.audit-feed-active",
    title: "SIEM audit-feed grant configured, unexpired, last pulled 2 hours ago",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["siem-feed-lapsed"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/ingest-credential"] = (url: URL): Dict => {
        const scope = url.searchParams.get("scope");
        if (scope === "audit-feed") {
          return {
            grant: {
              clientId: "dpc_siemfeed",
              secretSha384: "0".repeat(96),
              scope: "audit-feed",
              grantedAt: iso(now - 60 * DAY),
              grantedBy: "secops@example.com",
              expiresAt: iso(now + 300 * DAY),
              // newest LAST (the engine projects lastPullAt from the final entry)
              pulls: [{ at: iso(now - 26 * HOUR) }, { at: iso(now - 2 * HOUR) }],
            },
          };
        }
        return { grant: null };
      };
    },
    capture: (b) => {
      const af = (b["auditFeed"] ?? {}) as Dict;
      const fails: string[] = [];
      if (af["configured"] !== true) fails.push(`auditFeed.configured expected true, got ${String(af["configured"])}`);
      if (af["expired"] !== false) fails.push(`auditFeed.expired expected false, got ${String(af["expired"])}`);
      if (typeof af["lastPullAt"] !== "string") fails.push("auditFeed.lastPullAt expected (recent pull recorded)");
      return fails;
    },
  },

  // A paid customer in good standing: a REAL vendor-signed enterprise token verifies against the
  // pinned signer, notAfter ~1 year out, and the observed tracked expiry row matches it exactly.
  {
    id: "healthy.paid-licenced",
    title: "valid enterprise licence (real signed token, ~1y out) with a MATCHING tracked expiry row",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["licence-invalid", "licence-expired", "licence-expiring-soon", "licence-expiry-stale", "licence-activation-failed"],
    mutate: (w) => {
      w.env["LICENCE_TOKEN"] = LICENCE_TOKEN;
      w.env["LICENCE_SIGNER_PUBLIC"] = LICENCE_SIGNER_PIN;
      // The engine-observed expiry-registry row tracks the SAME notAfter (no drift).
      w.routes["/expiry"] = [{ id: "lic-observed", label: "assurance licence", kind: "licence", expiresAt: LICENCE_NOT_AFTER, state: "ok", source: "observed" }];
    },
    capture: (b) => [
      ...expectInBundle(b, '"valid":true', "the verified licence"),
      ...expectInBundle(b, `"notAfter":"${LICENCE_NOT_AFTER}"`, "the licence expiry"),
      ...expectInBundle(b, `"trackedNotAfter":"${LICENCE_NOT_AFTER}"`, "the matching tracked expiry row"),
    ],
  },

  // Aggregation noise: 8 downpipes across kv/r2/d1, every binding live, every run verified, every
  // replica aligned. The fleet-wide scans must not manufacture a signal from sheer breadth.
  {
    id: "healthy.big-fleet",
    title: "8-downpipe kv/r2/d1 fleet, all bindings live, all runs verified, replication aligned",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["bindings-probe-failed", "run-stalled", "cron-unresolvable", "replication-redundancy-degraded", "destination-degraded", "restore-test-failed"],
    mutate: (w) => {
      const now = Date.now();
      const fleet: Array<{ id: string; name: string; type: "kv" | "r2" | "d1"; binding: string }> = [
        { id: "dp1", name: "uploads", type: "kv", binding: "UPLOADS_KV" },
        { id: "dp2", name: "sessions", type: "kv", binding: "SESSIONS_KV" },
        { id: "dp3", name: "feature-flags", type: "kv", binding: "FLAGS_KV" },
        { id: "dp4", name: "media", type: "r2", binding: "MEDIA_R2" },
        { id: "dp5", name: "invoices", type: "r2", binding: "INVOICES_R2" },
        { id: "dp6", name: "exports", type: "r2", binding: "EXPORTS_R2" },
        { id: "dp7", name: "app-db", type: "d1", binding: "APP_D1" },
        { id: "dp8", name: "analytics-db", type: "d1", binding: "ANALYTICS_D1" },
      ];
      const liveR2 = (): unknown => ({ list: async () => ({ objects: [], truncated: false }) });
      const liveD1 = (): unknown => ({ prepare: () => ({ bind: () => ({ first: async () => ({ one: 1 }) }), first: async () => ({ one: 1 }) }) });
      const dps: Dict[] = [];
      const by: Record<string, Dict[]> = {};
      const repl: Record<string, Dict> = {};
      for (let i = 0; i < fleet.length; i++) {
        const f = fleet[i]!;
        if (f.type === "kv") w.env[f.binding] = liveKvNamespace();
        else if (f.type === "r2") w.env[f.binding] = liveR2();
        else w.env[f.binding] = liveD1();
        const source: Dict =
          f.type === "kv"
            ? { type: "kv", binding: f.binding, namespaceId: `ns-${f.name}`, include: [], exclude: [] }
            : f.type === "r2"
              ? { type: "r2", binding: f.binding, bucketName: `${f.name}-bucket`, include: [], exclude: [] }
              : { type: "d1", binding: f.binding, include: [], exclude: [] };
        const runId = `01FLEET${i}OK`;
        const started = now - (40 + i * 13) * MIN;
        const idx = 5 + (i % 3);
        dps.push({
          config: { id: f.id, name: f.name, enabled: true, cadenceSeconds: i % 2 === 0 ? 3600 : 21600, source },
          lastRunId: runId,
          inFlight: false,
          nextRunAt: now + (30 + i * 7) * MIN,
          ...(i % 2 === 0 ? { cronResolve: { class: "ok", at: now + (30 + i * 7) * MIN } } : {}),
          lastRestoreTestAt: now - (5 + i) * HOUR,
          lastRestoreTestOk: true,
        });
        by[f.id] = [okRun(runId, idx, started, 20 + i * 11, 4096 * (i + 1)), okRun(`01FLEET${i}PRV`, idx - 1, started - 6 * HOUR, 19 + i * 11, 4000 * (i + 1))];
        repl[f.id] = { "d-primary": { holdsRunId: runId, holdsIndex: idx, lastOk: true, lastAttemptAt: started + MIN } };
      }
      w.routes["/downpipes"] = dps;
      w.routes["/history"] = { byDownpipe: by };
      w.routes["/replication"] = { byDownpipe: repl };
      const sched = w.routes["/scheduler-signals"] as Dict;
      sched["dueIndex"] = { at: now - 3 * MIN, indexEntriesBeforeRebuild: 8, indexEntriesRequired: 8, dpTotal: 8, matched: true };
      sched["runlog"] = { counter: 61, maxHistoryIndex: 8 };
      (sched["ticks"] as Dict[])[0]!["due"] = 3;
      (sched["ticks"] as Dict[])[0]!["dispatched"] = 3;
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - 39 * MIN), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
        { seq: 2, ts: iso(now - 66 * MIN), event: "backup-success", severity: "info", downpipeId: "dp4", channelKind: "webhook", delivered: true },
        { seq: 1, ts: iso(now - 79 * MIN), event: "backup-success", severity: "info", downpipeId: "dp7", channelKind: "webhook", delivered: true },
      ];
    },
    capture: (b) => {
      const dps = (b["downpipes"] as Dict[]) ?? [];
      return dps.length === 8 ? [] : [`expected 8 downpipes in the bundle, got ${dps.length}`];
    },
  },

  // F-HV3 FIXED 2026-07-02: an INTENTIONAL SEAL_VERIFY_SAMPLE=0 posture (verified Tier-0, cause
  // sample-off) no longer fires tier0-verify-only — the fleet reads clean HEALTHY; the knob stays
  // visible to humans in sealKnobs. break-glass/too-large still fire (seal.tier0-only-break-glass).
  {
    id: "healthy.tier0-verify",
    title: "runs verified at Tier-0 with tier0Cause sample-off (operator set SEAL_VERIFY_SAMPLE=0)",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["tier0-verify-only", "seal-suspect", "seal-verify-disabled", "restore-test-failed"],
    mutate: (w) => {
      const now = Date.now();
      // The knob is genuinely set, and both recent runs verified structurally at Tier-0 because of it.
      w.env["SEAL_VERIFY_SAMPLE"] = "0";
      runs(w)[0]!["sealVerification"] = { status: "verified", tier: "tier-0", sampled: 0, at: now - 54 * MIN, tier0Cause: "sample-off" };
      runs(w)[1]!["sealVerification"] = { status: "verified", tier: "tier-0", sampled: 0, at: now - 114 * MIN, tier0Cause: "sample-off" };
    },
    capture: (b) => [
      ...expectInBundle(b, '"tier0Cause":"sample-off"', "the Tier-0 sample-off cause"),
      ...expectInBundle(b, '"sample":0', "the resolved SEAL_VERIFY_SAMPLE=0 knob"),
    ],
  },

  // WORM done right: a compliance policy is configured AND the bucket really enforces Object-Lock
  // (the live GetObjectLockConfiguration probe answers Enabled). worm-not-enforced must NOT fire.
  {
    id: "healthy.worm-enforced",
    title: "DEST_WORM_MODE=compliance with the Object-Lock probe answering ENFORCED (Enabled, 30d default)",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["worm-not-enforced", "dest-auth-failed", "throttled", "dest-write-misconfigured"],
    mutate: (w) => {
      w.env["DEST_WORM_MODE"] = "compliance";
      w.env["DEST_WORM_RETENTION_DAYS"] = "30";
      // The bucket-root GET ?object-lock probe (fetchWormPosture -> objectLockStatus) answers the
      // real S3 enforcement XML; everything else on the dest host keeps the healthy 200.
      w.net.unshift({ re: /object-lock/, status: 200, body: OBJECT_LOCK_ENFORCED_XML, headers: { "content-type": "application/xml" } });
    },
    capture: (b) => {
      const wp = (b["wormPosture"] ?? {}) as Dict;
      const fails: string[] = [];
      if (wp["configured"] !== true) fails.push(`wormPosture.configured expected true, got ${String(wp["configured"])}`);
      if (wp["misconfigured"] !== false) fails.push(`wormPosture.misconfigured expected false, got ${String(wp["misconfigured"])}`);
      if (wp["bucketEnforces"] !== true) fails.push(`wormPosture.bucketEnforces expected true, got ${String(wp["bucketEnforces"])}`);
      return fails;
    },
  },

  // Aged, resolved history everywhere: every "bad thing" in this bundle is PAST its recency window
  // (an SSO failure run 12 days back, an auth lockout 9 days back, a notify failure 10 days back —
  // also SUPERSEDED by newer successes, the item-17 self-healed discrimination — and a 6-week-old
  // IdP connection delete) or benignly pending (a digest due in 4 hours). None of the recency-bounded
  // signals may re-gate HEALTHY. UPDATED 2026-07-02: the old 2-day-expired cooldown-row fixture was
  // engine-unrealistic (reconcileAlerts DELETES the row on recovery and refreshes `at` on re-nudge),
  // and under the fixed genuinely-stuck rule it would rightly fire; the recovered incident's row is
  // now honestly ABSENT (deleted), and the benign ACTIVE-cooldown proof lives in
  // notify.canary-dead-cooldown-suppressed.
  {
    id: "healthy.quiet-history",
    title: "stale resolved noise: old SSO/auth/notify failures, recovered incident (cooldown row cleared), future digest — all outside their windows",
    domain: "healthy-variant",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: [
      "sso-signin-failing",
      "sign-in-failing-by-protocol",
      "auth-defensive-branch-firing",
      "notify-delivery-failed",
      "notify-rule-misconfigured",
      "alert-cooldown-stuck",
      "idp-connection-disrupted",
      "idp-management-denied",
    ],
    mutate: (w) => {
      const now = Date.now();
      // An issuer-mismatch burst 12 days ago (fixed since); the aggregate never decays but MUST age out.
      w.routes["/sso-failures"] = { issuer: { count: 3, lastAt: iso(now - 12 * DAY) } };
      w.routes["/sso-failures-by-kind"] = { oidc: { issuer: { count: 3, lastAt: iso(now - 12 * DAY) } } };
      // A forced re-auth epoch event 9 days ago (an expected security action, long settled).
      w.routes["/auth-signals"] = { "session-revoked-email-epoch": { count: 2, lastAt: iso(now - 9 * DAY) } };
      // One delivery failure 10 days ago, then recent successes: historical, not a current outage.
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - 50 * MIN), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
        { seq: 2, ts: iso(now - 2 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
        { seq: 1, ts: iso(now - 10 * DAY), event: "backup-failure", severity: "critical", downpipeId: "dp1", channelKind: "webhook", delivered: false, deliveryCode: "http-5xx" },
      ];
      // A success digest batch exists but is due 4 hours FROM NOW (pending, not overdue).
      w.routes["/notify/digest-pending"] = {
        count: 1,
        oldestAt: iso(now - 2 * HOUR),
        byPeriod: { daily: { count: 1, oldestAt: iso(now - 2 * HOUR), dueAt: iso(now + 4 * HOUR) } },
      };
      // The incident 2 days ago RECOVERED: reconcileAlerts deleted its cooldown row (the engine-true
      // steady state — a surviving long-elapsed row would be a genuine alert-reconciliation fault).
      w.routes["/notify/cooldowns"] = { cooldownMs: 3_600_000, alert: [], replication: [] };
      // A SAML connection deleted 6 weeks ago (outside IDP_RECENT_MS) still sits in the excerpt.
      const prev = w.routes["/audit/export"] as (url: URL, body: unknown) => Dict;
      w.routes["/audit/export"] = (url: URL, body: unknown): Dict => {
        const action = url.searchParams.get("action");
        if (action !== null) return prev(url, body);
        return {
          events: [
            { seq: 10, ts: iso(now - 42 * DAY), action: "idp-connection-change", outcome: "success", target: { kind: "idpconnection", connId: "legacy-saml", connKind: "saml", op: "delete" }, prevHash: "sha384:h9", hash: "sha384:h10" },
            { seq: 11, ts: iso(now - 2 * DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
            { seq: 12, ts: iso(now - DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h11", hash: "sha384:h12" },
          ],
          headSeq: 12,
          headHash: "sha384:h12",
          exportedAt: iso(now - MIN),
        };
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"issuer"', "the aged SSO failure aggregate"),
      ...expectInBundle(b, '"delivered":false', "the historical notify delivery failure"),
      ...expectInBundle(b, '"op":"delete"', "the stale IdP connection-change excerpt event"),
    ],
  },
];
