// CORE corpus scenarios: the closed diagnosis-class set, one induced world per class
// (plus healthy variants). Engine-exact vocabulary throughout: coarse run errors are the
// closed strings src/seal/slice.ts writes; seal reasons are verify-at-seal's coarse reasons;
// preflight outcomes come from the REAL probes (env-driven), never hand-authored items.

import { DEST_HOST, deletedKvNamespace, type Scenario, type World } from "./harness.ts";

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
function latestRun(w: World): Dict {
  return runs(w)[0]!;
}
/** Replace the latest run with a FAILED row carrying the engine's closed coarse error string. */
function failLatestRun(w: World, error: string, extra: Dict = {}): void {
  const now = Date.now();
  runs(w)[0] = {
    runId: "01RUNBAD",
    index: 8,
    startedAt: iso(now - 20 * MIN),
    status: "failed",
    error,
    causeDigest: "a1b2c3d4e5f6",
    ...extra,
  };
  dp1(w).lastRunId = "01RUNBAD";
}

function bundleText(b: Dict): string {
  return JSON.stringify(b);
}
function expectInBundle(b: Dict, needle: string, what: string): string[] {
  return bundleText(b).includes(needle) ? [] : [`bundle does not carry ${what} (expected substring ${JSON.stringify(needle)})`];
}

/** The owner-#1 keystone: a RECENT engine-version-change audit marker served by the action filter. */
function addVersionChangeKeystone(w: World, at: number, withDetachAfter: boolean): void {
  const routes = w.routes;
  const prev = routes["/audit/export"] as (url: URL, body: unknown) => Dict;
  routes["/audit/export"] = (url: URL, body: unknown): Dict => {
    const action = url.searchParams.get("action");
    if (action === "engine-version-change") {
      return { events: [{ seq: 5, ts: iso(at), action: "engine-version-change", target: { detail: "0.1.0" }, prevHash: "sha384:k4", hash: "sha384:k5" }], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(Date.now()) };
    }
    if (action === "sources-detached") {
      if (!withDetachAfter) return { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(Date.now()) };
      return { events: [{ seq: 6, ts: iso(at + 5 * MIN), action: "sources-detached", prevHash: "sha384:k5", hash: "sha384:k6" }], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(Date.now()) };
    }
    return prev(url, body);
  };
}

export const CORE_SCENARIOS: Scenario[] = [
  // ------------------------------------------------------------------ healthy
  {
    id: "healthy.kv-baseline",
    title: "single KV downpipe, recent verified run, alerting delivering",
    domain: "healthy",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    mutate: () => {},
    capture: (b) => [
      ...expectInBundle(b, '"sealKnobs"', "the resolved seal knobs block"),
      ...expectInBundle(b, '"sectionsSummary"', "the sections completeness summary"),
    ],
  },
  {
    id: "healthy.three-source-fleet",
    title: "kv+r2+d1 fleet, all bindings live, all runs verified",
    domain: "healthy",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    mutate: (w) => {
      const now = Date.now();
      const dps = w.routes["/downpipes"] as Dict[];
      dps.push(
        { config: { id: "dp2", name: "media", enabled: true, cadenceSeconds: 7200, source: { type: "r2", binding: "MEDIA_R2", bucketName: "media-bucket", include: [], exclude: [] } }, lastRunId: "01R2OK", inFlight: false, nextRunAt: now + HOUR, cronResolve: { class: "ok", at: now + HOUR }, lastRestoreTestAt: now - 8 * HOUR, lastRestoreTestOk: true },
        { config: { id: "dp3", name: "app-db", enabled: true, cadenceSeconds: 86400, source: { type: "d1", binding: "APP_D1", include: [], exclude: [] } }, lastRunId: "01D1OK", inFlight: false, nextRunAt: now + 4 * HOUR, cronResolve: { class: "ok", at: now + 4 * HOUR }, lastRestoreTestAt: now - 20 * HOUR, lastRestoreTestOk: true },
      );
      const by = (w.routes["/history"] as Dict).byDownpipe as Record<string, Dict[]>;
      by["dp2"] = [{ runId: "01R2OK", index: 3, startedAt: iso(now - 90 * MIN), status: "ok", recordCount: 10, bytes: 2048, durationMs: 400, recordsSkipped: 0, recordsIncomplete: 0, destinationId: "d-primary", sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: 4, at: now - 89 * MIN } }];
      by["dp3"] = [{ runId: "01D1OK", index: 2, startedAt: iso(now - 5 * HOUR), status: "ok", recordCount: 200, bytes: 40960, durationMs: 900, recordsSkipped: 0, recordsIncomplete: 0, destinationId: "d-primary", sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: 12, at: now - 5 * HOUR + MIN } }];
      // Bindings present + live (a fake platform object per binding).
      w.env["MEDIA_R2"] = { list: async () => ({ objects: [], truncated: false }) };
      w.env["APP_D1"] = { prepare: () => ({ bind: () => ({ first: async () => ({ one: 1 }) }), first: async () => ({ one: 1 }) }) };
      const repl = (w.routes["/replication"] as Dict).byDownpipe as Record<string, Dict>;
      repl["dp2"] = { "d-primary": { holdsRunId: "01R2OK", holdsIndex: 3, lastOk: true, lastAttemptAt: now - 89 * MIN } };
      repl["dp3"] = { "d-primary": { holdsRunId: "01D1OK", holdsIndex: 2, lastOk: true, lastAttemptAt: now - 5 * HOUR + MIN } };
    },
  },

  // ------------------------------------------------------------ destinations
  {
    id: "dest-auth.preflight-403",
    title: "destination credentials revoked: S3 HEAD answers 403 through the real probe + classifier",
    domain: "dest",
    trueClass: "DEST-AUTH-FAILED",
    isFault: true,
    expectEscalate: false, // auto-postable class (conf 0.90 >= bar 0.90) when nothing else fires
    expectSignals: ["dest-auth-failed"],
    expectAbsentSignals: ["throttled"],
    mutate: (w) => {
      w.net = [{ re: new RegExp(DEST_HOST.replace(/\./g, "\\.")), status: 403, body: "<Error><Code>AccessDenied</Code></Error>" }];
    },
    capture: (b) => {
      const items = ((b["preflight"] as Dict)?.["items"] ?? []) as Dict[];
      const dest = items.find((i) => i["id"] === "destination");
      const fails: string[] = [];
      if (dest?.["status"] !== "failed") fails.push(`preflight destination expected failed, got ${String(dest?.["status"])}`);
      if (dest?.["failureClass"] !== "auth") fails.push(`preflight destination failureClass expected auth, got ${String(dest?.["failureClass"])}`);
      return fails;
    },
  },
  {
    id: "dest-auth.run-rejected-write",
    title: "latest run failed: destination rejected the write (AccessDenied)",
    domain: "dest",
    trueClass: "DEST-AUTH-FAILED",
    isFault: true,
    expectEscalate: false,
    expectSignals: ["dest-auth-failed"],
    mutate: (w) => {
      failLatestRun(w, "destination rejected the write (AccessDenied)");
    },
    capture: (b) => expectInBundle(b, "destination rejected the write (AccessDenied)", "the failed run's coarse dest-reject error"),
  },
  {
    id: "dest-throttle.run-rejected-slowdown",
    title: "latest run failed: destination rejected the write (SlowDown) -- transient reject",
    domain: "dest",
    trueClass: "DEST-THROTTLED-OR-DOWN",
    isFault: true,
    expectEscalate: true, // conf 0.85 < 0.90 bar: always human-gated
    expectSignals: ["throttled"],
    expectAbsentSignals: ["dest-auth-failed"],
    mutate: (w) => {
      failLatestRun(w, "destination rejected the write (SlowDown)");
    },
  },
  {
    id: "dest-throttle.preflight-503",
    title: "destination down: S3 HEAD answers 503 through the real probe (post-false-green fix)",
    domain: "dest",
    trueClass: "DEST-THROTTLED-OR-DOWN",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["throttled"],
    expectAbsentSignals: ["dest-auth-failed"],
    mutate: (w) => {
      w.net = [{ re: new RegExp(DEST_HOST.replace(/\./g, "\\.")), status: 503, body: "<Error><Code>SlowDown</Code></Error>" }];
    },
    capture: (b) => {
      const items = ((b["preflight"] as Dict)?.["items"] ?? []) as Dict[];
      const dest = items.find((i) => i["id"] === "destination");
      return dest?.["status"] === "failed" && dest?.["failureClass"] === "transient" ? [] : [`preflight destination expected failed/transient, got ${String(dest?.["status"])}/${String(dest?.["failureClass"])}`];
    },
  },
  {
    id: "dest-other.rejected-nosuchbucket",
    title: "latest run failed: destination rejected the write (NoSuchBucket) -- bucket deleted",
    domain: "dest",
    // Designed routing: a PERMANENT non-auth reject is a warning-only signal (precise missing-bucket
    // prose) under an INDETERMINATE primary + escalate -- never "check your credentials", never a
    // self-heals throttle story. The closed class set has no DEST-MISCONFIGURED primary (candidate
    // future class; see the campaign report).
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["dest-rejected-other"],
    expectAbsentSignals: ["dest-auth-failed"],
    mutate: (w) => {
      failLatestRun(w, "destination rejected the write (NoSuchBucket)");
    },
  },

  // ----------------------------------------------------------------- stalled
  {
    id: "runs.stalled-in-flight",
    title: "run in-flight 45 minutes past start (lease expired): the parked-503 / killed-isolate signature",
    domain: "runs",
    // Designed routing: run-stalled / run-wedged-stalled are warning-only signals (they force escalation
    // and block HEALTHY but never set the primary), so a stall with no other evidence is INDETERMINATE
    // with the two stall warnings -- exactly the diaglab round-3 design.
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["run-stalled", "run-wedged-stalled"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      d.inFlight = true;
      d.inFlightSince = now - 45 * MIN;
      d.lastRunId = "01RUNWEDGE";
      runs(w).unshift({ runId: "01RUNWEDGE", index: 8, startedAt: iso(now - 45 * MIN), status: "in-flight" });
    },
    capture: (b) => {
      const d = (b["downpipes"] as Dict[])[0]!;
      return d["stalled"] === true ? [] : [`downpipes[0].stalled expected true, got ${String(d["stalled"])}`];
    },
  },

  // -------------------------------------------------------------------- seal
  {
    id: "seal.suspect-record-integrity",
    title: "verify-at-seal readback found corrupt bytes: sealVerification suspect (record integrity)",
    domain: "seal",
    trueClass: "SEAL-SUSPECT",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["seal-suspect"],
    mutate: (w) => {
      const now = Date.now();
      latestRun(w)["sealVerification"] = { status: "suspect", tier: "sampled-decrypt", sampled: 8, at: now - 50 * MIN, reason: "record integrity check failed" };
    },
    capture: (b) => expectInBundle(b, '"suspect"', "the suspect seal verification verdict"),
  },
  {
    id: "seal.fault-ring-shard-truncated",
    title: "seal DO observed a truncated shard enumeration (refuse-to-sign) in the fault ring",
    domain: "seal",
    // Designed routing: seal-fault-observed is a warning-only signal (the refuse-to-sign means nothing
    // bad was SEALED, so SEAL-SUSPECT would overclaim); the failed run + the precise shard-truncated
    // warning escalate under INDETERMINATE.
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["seal-fault-observed"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/seal-faults"] = { faults: [{ kind: "shard-list-truncated", at: now - 10 * MIN, downpipeId: "dp1", runId: "01RUNBAD", found: 968, expected: 970 }] };
      failLatestRun(w, "run failed");
    },
    capture: (b) => expectInBundle(b, "shard-list-truncated", "the seal fault ring entry"),
  },

  // -------------------------------------------------------------- incompleteness
  {
    id: "incomplete.partial-source-403",
    title: "run sealed with 3 incompleteness markers (partial token scope), surfaces attributed",
    domain: "sources",
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["records-incomplete-nonzero", "incompleteness-attributed-to-surface"],
    mutate: (w) => {
      const r = latestRun(w);
      r["recordsIncomplete"] = 3;
      r["incompleteByMarker"] = { _unavailable: 3 };
      r["incompleteIds"] = { _unavailable: ["dns_records", "rulesets", "page_rules"] };
    },
    capture: (b) => [
      ...expectInBundle(b, '"recordsIncomplete":3', "the incompleteness count on the run row"),
      ...expectInBundle(b, "dns_records", "the per-surface incompleteness attribution"),
    ],
  },
  {
    id: "incomplete.vanished-mid-crawl",
    title: "2 objects vanished mid-crawl (recordsVanished + _vanished markers)",
    domain: "sources",
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["records-incomplete-nonzero"],
    mutate: (w) => {
      const r = latestRun(w);
      r["recordsVanished"] = 2;
      r["recordsIncomplete"] = 2;
      r["incompleteByMarker"] = { _vanished: 2 };
    },
  },

  // ------------------------------------------------------------ owner-#1 chain
  {
    id: "bindings.currently-missing-after-deploy",
    title: "owner-#1: source binding absent from env after an engine-version-change, NO sources-detached",
    domain: "bindings",
    trueClass: "BINDINGS-CURRENTLY-MISSING",
    isFault: true,
    expectEscalate: false, // the conservative auto-postable default (never accuses the vendor)
    expectSignals: ["bindings-probe-failed", "roster-dropped-across-version-change"],
    expectAbsentSignals: ["user-removed-binding", "vendor-deploy-corroborated"],
    mutate: (w) => {
      delete w.env["UPLOADS_KV"]; // the REAL source-bindings probe now fails, naming the binding
      addVersionChangeKeystone(w, Date.now() - 2 * HOUR, false);
    },
    capture: (b) => {
      const items = ((b["preflight"] as Dict)?.["items"] ?? []) as Dict[];
      const sb = items.find((i) => i["id"] === "source-bindings");
      const fails: string[] = [];
      if (sb?.["status"] !== "failed") fails.push(`preflight source-bindings expected failed, got ${String(sb?.["status"])}`);
      fails.push(...expectInBundle(b, "engine-version-change", "the retained engine-version-change keystone"));
      return fails;
    },
  },
  {
    id: "bindings.removed-by-user",
    title: "binding absent AND a sources-detached audit event follows the version change",
    domain: "bindings",
    trueClass: "BINDINGS-REMOVED-BY-USER",
    isFault: true,
    expectEscalate: false,
    expectSignals: ["bindings-probe-failed", "user-removed-binding"],
    mutate: (w) => {
      delete w.env["UPLOADS_KV"];
      addVersionChangeKeystone(w, Date.now() - 2 * HOUR, true);
    },
    capture: (b) => expectInBundle(b, "sources-detached", "the sources-detached keystone event"),
  },
  {
    id: "bindings.dropped-by-deploy-corroborated",
    title: "owner-#1 chain + an INDEPENDENT vendor deploy record (deploy ledger corroboration)",
    domain: "bindings",
    trueClass: "BINDING-DROPPED-BY-DEPLOY",
    isFault: true,
    expectEscalate: true, // vendor accusation is ALWAYS human-gated
    expectSignals: ["bindings-probe-failed", "roster-dropped-across-version-change", "vendor-deploy-corroborated"],
    corroboration: { vendorDeployForAccount: true },
    mutate: (w) => {
      delete w.env["UPLOADS_KV"];
      addVersionChangeKeystone(w, Date.now() - 2 * HOUR, false);
    },
  },

  // ------------------------------------------------------------------ sources
  {
    id: "source.resource-deleted",
    title: "binding present but the KV namespace it names was deleted (real liveness probe fails)",
    domain: "sources",
    trueClass: "SOURCE-RESOURCE-DELETED",
    isFault: true,
    expectEscalate: false, // auto-postable (0.93)
    expectSignals: [],
    expectAbsentSignals: ["bindings-probe-failed"],
    mutate: (w) => {
      w.env["UPLOADS_KV"] = deletedKvNamespace();
    },
    capture: (b) => {
      const items = ((b["preflight"] as Dict)?.["items"] ?? []) as Dict[];
      const sl = items.find((i) => i["id"] === "source-liveness");
      return sl?.["status"] === "failed" ? [] : [`preflight source-liveness expected failed, got ${String(sl?.["status"])}`];
    },
  },
  {
    id: "source.run-resource-missing",
    title: "latest run died on 'source resource missing' (deleted mid-life, probe not yet run)",
    domain: "sources",
    trueClass: "SOURCE-RESOURCE-DELETED",
    isFault: true,
    expectEscalate: false,
    expectSignals: [],
    mutate: (w) => {
      failLatestRun(w, "source resource missing");
    },
  },

  // ------------------------------------------------------------------ posture
  {
    id: "posture.recipients-unparseable",
    title: "BREAK_GLASS_PUBLIC set but does not parse: recipients preflight fails (recoverability at risk)",
    domain: "posture",
    trueClass: "POSTURE-ISSUE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["posture-failed"],
    mutate: (w) => {
      w.env["BREAK_GLASS_PUBLIC"] = "bm90LWEta2V5"; // parses as b64, not a recipient key
    },
    capture: (b) => {
      const items = ((b["preflight"] as Dict)?.["items"] ?? []) as Dict[];
      const rec = items.find((i) => i["id"] === "recipients");
      return rec?.["status"] === "failed" ? [] : [`preflight recipients expected failed, got ${String(rec?.["status"])}`];
    },
  },

  // ------------------------------------------------------------- indeterminate
  {
    id: "indeterminate.status-preflight-conflict",
    title: "gap-B6: status resolves the dest from env-fallback while the live preflight probe verifies",
    domain: "infra",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["status-preflight-conflict"],
    mutate: (w) => {
      // The gap-B6 "do-read-hiccup-flips-source" state: the DO /dest-status read fails THIS probe
      // (statusSource honestly falls back to env-fallback; no env dest -> destResolved unknown), while
      // the console-set destination itself is fine (the /dest-config read + the live HEAD verify).
      // The status story ("no destination") and the preflight story ("destination verified") conflict.
      w.routes["/dest-status"] = () => {
        throw new Error("scheduler DO read hiccup");
      };
    },
  },

  // ----------------------------------------------------------------- recovery
  {
    id: "recovery.amnesia-latch",
    title: "control-plane amnesia: scheduler DO found empty while signed archives remain",
    domain: "cpr",
    trueClass: "RECOVERY-REQUIRED",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["recovery-required"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/control-plane/recovery-status"] = {
        recoveryRequired: true,
        reason: "scheduler durable object was found empty while signed archives remain",
        configEmpty: true,
        resumeApplied: false,
        deploy: { engineVersion: "0.1.0", cfVersionId: "cfv-current-001", cfVersionIdAbsent: false, baselineEstablished: true, changesObserved: 1, firstSeenAt: iso(now - 30 * DAY), lastSeenAt: iso(now - 5 * MIN), lastChangeAt: iso(now - HOUR) },
        exportHealth: { at: iso(now - 20 * MIN), wroteAny: true, configVersion: 7, perDest: [{ id: "d-primary", ok: true }] },
      };
      // An amnesiac DO also serves an empty fleet -- mirror that honestly.
      w.routes["/downpipes"] = [];
      w.routes["/history"] = { byDownpipe: {} };
      w.routes["/replication"] = { byDownpipe: {} };
    },
  },
];
