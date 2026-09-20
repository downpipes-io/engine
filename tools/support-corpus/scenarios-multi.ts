// MULTI-FAULT corpus scenarios: several things wrong at once. These prove the two combination
// invariants over REAL bundles (not hand-shaped facts, which is what test/combination.test.ts uses):
//   PRECEDENCE -- the diagnose.ts primary tree picks the designed most-actionable class
//     (recovery > conflict > source-deleted > bindings > dest-auth > throttled > incompleteness
//      > posture > seal-suspect), and neither owner-#1 nor RECOVERY-REQUIRED is ever masked;
//   ESCALATION -- ANY integrity / data-shortfall / recovery-blocking / alerting secondary forces
//     escalateToHuman even under an auto-postable primary (the 9th-bug invariant: never auto-post
//     with an incompleteness/seal/wrap-key/notify concern aboard).
// Every composed payload copies shapes the REAL DO write-paths are validated to produce
// (test/validate-support.ts schedulerDouble) or that the core scenarios already serve; run errors,
// seal reasons, cooldown states, canary states and tier0 causes are the engine's CLOSED vocabularies.
// Where a precedence outcome would read WRONG for a customer, a // FINDING labels CURRENT behavior
// (this corpus is diagnostic OBSERVE-side only -- the bot is never changed from here); see ## FINDINGS.

import { DEST_HOST, type Scenario, type World } from "./harness.ts";

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
/** Replace dp1's latest run with a FAILED row carrying the engine's closed coarse error string. */
function failLatestRun(w: World, error: string): void {
  const now = Date.now();
  runs(w)[0] = {
    runId: "01RUNBAD",
    index: 8,
    startedAt: iso(now - 20 * MIN),
    status: "failed",
    error,
    causeDigest: "a1b2c3d4e5f6",
  };
  dp1(w).lastRunId = "01RUNBAD";
}
/** Mark a run's seal read-back SUSPECT with the engine's closed record-integrity verify reason. */
function suspectSeal(run: Dict): void {
  run["sealVerification"] = { status: "suspect", tier: "sampled-decrypt", sampled: 8, at: Date.now() - 50 * MIN, reason: "record integrity check failed" };
}
/** Mark a prior-OK run silently SHORT with the engine's per-marker breakdown (validate-support shape). */
function shortRun(run: Dict, count: number): void {
  run["recordsIncomplete"] = count;
  run["incompleteByMarker"] = count >= 3 ? { _truncated: count - 1, _skipped: 1 } : { _truncated: count };
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
function expectDestAuthPreflight(b: Dict): string[] {
  const dest = preflightItem(b, "destination");
  const fails: string[] = [];
  if (dest?.["status"] !== "failed") fails.push(`preflight destination expected failed, got ${String(dest?.["status"])}`);
  if (dest?.["failureClass"] !== "auth") fails.push(`preflight destination failureClass expected auth, got ${String(dest?.["failureClass"])}`);
  return fails;
}
function expectBindingsProbeFailed(b: Dict): string[] {
  const sb = preflightItem(b, "source-bindings");
  return sb?.["status"] === "failed" ? [] : [`preflight source-bindings expected failed, got ${String(sb?.["status"])}`];
}

/** The owner-#1 keystone (same shape as scenarios-core): a RECENT engine-version-change audit marker
 * served by the server-side action filter, with NO sources-detached at/after it. */
function addVersionChangeKeystone(w: World, at: number): void {
  const routes = w.routes;
  const prev = routes["/audit/export"] as (url: URL, body: unknown) => Dict;
  routes["/audit/export"] = (url: URL, body: unknown): Dict => {
    const action = url.searchParams.get("action");
    if (action === "engine-version-change") {
      return { events: [{ seq: 5, ts: iso(at), action: "engine-version-change", target: { detail: "0.1.0" }, prevHash: "sha384:k4", hash: "sha384:k5" }], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(Date.now()) };
    }
    if (action === "sources-detached") {
      return { events: [], headSeq: 12, headHash: "sha384:h12", exportedAt: iso(Date.now()) };
    }
    return prev(url, body);
  };
}

/** Destination credentials revoked at the store: the real preflight HEAD answers 403 AccessDenied. */
function destNet403(w: World): void {
  w.net = [{ re: new RegExp(DEST_HOST.replace(/\./g, "\\.")), status: 403, body: "<Error><Code>AccessDenied</Code></Error>" }];
}

export const MULTI_FAULT_SCENARIOS: Scenario[] = [
  // ------------------------------------------------------------------ 1. recovery outranks everything
  {
    id: "multi.amnesia-plus-dest-auth",
    title: "control-plane amnesia latched AND destination credentials revoked (preflight 403)",
    domain: "multi",
    // RECOVERY-REQUIRED is the tree's HIGHEST precedence: the wiped scheduler outranks the dest-auth
    // fault (which still fires as a signal from the real destination probe + classifier).
    trueClass: "RECOVERY-REQUIRED",
    isFault: true,
    expectEscalate: true, // review-only fix + the recovery reason: never auto-posted
    // deploy-identity-changed rides the amnesia deploy marker (lastChangeAt 1h ago -- a DO
    // migration/reset is deploy-adjacent), exactly as the core amnesia payload carries it.
    expectSignals: ["recovery-required", "dest-auth-failed", "deploy-identity-changed"],
    expectAbsentSignals: ["throttled"],
    // F-1 FIXED 2026-07-02 (item 19): dest-auth-failed as a SECONDARY now appends a warning line
    // ("the DESTINATION is ALSO rejecting writes ... any recovery/restore that must READ or WRITE the
    // destination will fail"), so the note prescribing a control-plane recovery names the revoked
    // credential that would block it (bot-side prose asserted by the fixround item-19 unit test over
    // this exact recovery+dest-auth composition). See ## FINDINGS.
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
      // An amnesiac DO serves an empty fleet (mirrors the core amnesia scenario honestly).
      w.routes["/downpipes"] = [];
      w.routes["/history"] = { byDownpipe: {} };
      w.routes["/replication"] = { byDownpipe: {} };
      destNet403(w);
    },
    capture: (b) => [
      ...expectInBundle(b, '"recoveryRequired":true', "the latched recovery-required state"),
      ...expectDestAuthPreflight(b),
    ],
  },

  // --------------------------------------------------- 2. the 9th-bug invariant (incompleteness aboard)
  {
    id: "multi.dest-auth-plus-incompleteness",
    title: "latest run rejected AccessDenied AND the last OK run sealed silently short",
    domain: "multi",
    trueClass: "DEST-AUTH-FAILED", // dest-auth outranks incompleteness in the tree
    isFault: true,
    // The 9th-bug invariant: DEST-AUTH-FAILED alone is auto-postable (conf 0.90 >= bar 0.90), but a
    // records-incomplete secondary ALWAYS pushes an escalate-reason -- never auto-post with a data
    // shortfall aboard. The shortfall also rides as an additive warning.
    expectEscalate: true,
    expectSignals: ["dest-auth-failed", "records-incomplete-nonzero"],
    expectAbsentSignals: ["throttled"],
    mutate: (w) => {
      failLatestRun(w, "destination rejected the write (AccessDenied)");
      shortRun(runs(w)[1]!, 3); // the prior OK run carries the marker breakdown (2 _truncated + 1 _skipped)
    },
    capture: (b) => [
      ...expectInBundle(b, "destination rejected the write (AccessDenied)", "the failed run's coarse dest-reject error"),
      ...expectInBundle(b, '"recordsIncomplete":3', "the incompleteness count on the prior run row"),
    ],
  },

  // ------------------------------------------------------------- 3. owner-#1 never masked by a seal blip
  {
    id: "multi.bindings-missing-plus-seal-suspect",
    title: "owner-#1 deploy-wipe (binding gone after engine-version-change) AND a suspect seal read-back",
    domain: "multi",
    // The binding drop is the tree's pick (bindings > seal): the owner-#1 story must never be masked
    // by a read-back blip -- exactly the regression the original seal-first ordering had.
    trueClass: "BINDINGS-CURRENTLY-MISSING",
    isFault: true,
    expectEscalate: true, // alone this class auto-posts; the seal-suspect secondary forces review
    expectSignals: ["bindings-probe-failed", "roster-dropped-across-version-change", "seal-suspect"],
    expectAbsentSignals: ["user-removed-binding", "vendor-deploy-corroborated"],
    mutate: (w) => {
      delete w.env["UPLOADS_KV"]; // the REAL source-bindings probe now fails, naming the binding
      addVersionChangeKeystone(w, Date.now() - 2 * HOUR);
      failLatestRun(w, "source binding error"); // the post-deploy run died on the missing binding
      suspectSeal(runs(w)[1]!); // the last GOOD run's read-back was suspect (record integrity)
    },
    capture: (b) => [
      ...expectBindingsProbeFailed(b),
      ...expectInBundle(b, "engine-version-change", "the retained engine-version-change keystone"),
      ...expectInBundle(b, '"suspect"', "the suspect seal verification verdict"),
    ],
  },

  // ------------------------------------------------------------ 4. throttle wins the primary over seal
  {
    id: "multi.seal-suspect-plus-dest-throttle",
    title: "latest run rejected SlowDown (transient) AND the prior run's seal read-back suspect",
    domain: "multi",
    // Per the tree, throttled (branch 6) outranks seal-suspect (branch 9): the primary reads
    // "usually transient / self-heals" while the WORST fault aboard is a possible integrity loss.
    // FINDING (F-2): deliberate design (seal sits below the more-actionable causes so a read-back
    // blip cannot mask them), and the invariant HOLDS -- the record-integrity seal warning + its
    // escalate-reason ride on the note and force review -- but the customer-facing HEADLINE is the
    // lesser, reassuring fault. Labeled current behavior; see ## FINDINGS.
    trueClass: "DEST-THROTTLED-OR-DOWN",
    isFault: true,
    expectEscalate: true, // throttle conf 0.85 < 0.90 bar AND the seal reason: doubly human-gated
    expectSignals: ["throttled", "seal-suspect"],
    expectAbsentSignals: ["dest-auth-failed"],
    mutate: (w) => {
      failLatestRun(w, "destination rejected the write (SlowDown)");
      suspectSeal(runs(w)[1]!);
    },
    capture: (b) => [
      ...expectInBundle(b, "destination rejected the write (SlowDown)", "the failed run's transient dest-reject error"),
      ...expectInBundle(b, '"suspect"', "the suspect seal verification verdict"),
    ],
  },

  // ----------------------------------------------------------------- 5. incompleteness beats posture
  {
    id: "multi.incompleteness-plus-posture",
    title: "latest run sealed silently short AND the break-glass recipient key does not parse",
    domain: "multi",
    trueClass: "SILENT-INCOMPLETENESS", // incompleteness (branch 7) outranks posture (branch 8)
    isFault: true,
    expectEscalate: true, // the incompleteness reason (review-only fix) escalates regardless
    // The malformed BREAK_GLASS_PUBLIC fires BOTH the recipients preflight probe (posture-failed) and
    // the keys-health parse probe (key-material-unhealthy) -- the same root cause, two detectors.
    expectSignals: ["records-incomplete-nonzero", "posture-failed", "key-material-unhealthy"],
    // F-3 FIXED 2026-07-02 (item 19): posture-failed as a SECONDARY now appends its own warning line
    // ("a posture/access prerequisite is ALSO failing"), so a posture failure with no keys-block twin
    // is no longer prose-invisible under a higher primary (bot-side prose asserted by the fixround
    // item-19 unit test). See ## FINDINGS.
    mutate: (w) => {
      shortRun(runs(w)[0]!, 2);
      w.env["BREAK_GLASS_PUBLIC"] = "bm90LWEta2V5"; // parses as b64, not a recipient key
    },
    capture: (b) => {
      const rec = preflightItem(b, "recipients");
      return [
        ...(rec?.["status"] === "failed" ? [] : [`preflight recipients expected failed, got ${String(rec?.["status"])}`]),
        ...expectInBundle(b, '"recordsIncomplete":2', "the incompleteness count on the run row"),
        ...expectInBundle(b, '"malformed":true', "the keys-health malformed break-glass parse probe"),
      ];
    },
  },

  // ---------------------------------------------------------- 6. a stall never masks the incompleteness
  {
    id: "multi.stalled-plus-incompleteness",
    title: "run wedged in-flight 45 minutes (lease expired) AND the last completed run silently short",
    domain: "multi",
    // Stall signals are warning-only (they gate HEALTHY + escalate but never set the primary), so the
    // incompleteness is the tree's primary; BOTH stall warnings ride the note.
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["records-incomplete-nonzero", "run-stalled", "run-wedged-stalled"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      d.inFlight = true;
      d.inFlightSince = now - 45 * MIN;
      d.lastRunId = "01RUNWEDGE";
      runs(w).unshift({ runId: "01RUNWEDGE", index: 8, startedAt: iso(now - 45 * MIN), status: "in-flight" });
      shortRun(runs(w)[1]!, 2); // the last COMPLETED run was short
    },
    capture: (b) => {
      const d = (b["downpipes"] as Dict[])[0]!;
      return [
        ...(d["stalled"] === true ? [] : [`downpipes[0].stalled expected true, got ${String(d["stalled"])}`]),
        ...expectInBundle(b, '"recordsIncomplete":2', "the incompleteness count on the completed run row"),
      ];
    },
  },

  // ------------------------------------------------- 7. backups stopped AND alerting could not tell you
  {
    id: "multi.owner1-plus-notify-broken",
    title: "owner-#1 deploy-wipe AND zero notification channels: the fault your alerts could not report",
    domain: "multi",
    trueClass: "BINDINGS-CURRENTLY-MISSING",
    isFault: true,
    // TRUTHFUL LABEL: the bindings primary alone is auto-postable (core scenario expectEscalate:false);
    // the no-notify-channels secondary DOES force escalation (it pushes an escalate-reason: an operator
    // relying on alerts must be told alerting is off). The note carries the combined story -- the
    // re-attach cause text PLUS the "no notification channels; an operator relying on alerts would not
    // be told a backup failed" warning -- one actionable note, human-gated.
    expectEscalate: true,
    expectSignals: ["bindings-probe-failed", "roster-dropped-across-version-change", "no-notify-channels"],
    // Discrimination: channelCount=0 must route to no-notify-channels, NOT the rule-misconfig signal
    // (no dangling ref exists once both lists are empty), and the keystone stays uncorroborated/neutral.
    expectAbsentSignals: ["notify-rule-misconfigured", "user-removed-binding", "vendor-deploy-corroborated"],
    mutate: (w) => {
      delete w.env["UPLOADS_KV"];
      addVersionChangeKeystone(w, Date.now() - 2 * HOUR);
      failLatestRun(w, "source binding error");
      w.routes["/notify/channels"] = []; // the operator never configured (or removed) all channels
      w.routes["/notify/rules"] = [];
    },
    capture: (b) => [
      ...expectBindingsProbeFailed(b),
      ...expectInBundle(b, "engine-version-change", "the retained engine-version-change keystone"),
      ...expectInBundle(b, '"channelCount":0', "the zero-channel notify config"),
    ],
  },

  // ------------------------------------------------------- 8. recovery-blocking secondary under dest-auth
  {
    id: "multi.wrapkey-plus-dest-auth",
    title: "destination credentials revoked (403) AND the wrap key no longer decrypts the export slice",
    domain: "multi",
    trueClass: "DEST-AUTH-FAILED",
    isFault: true,
    // A recovery-BLOCKING secondary must escalate: wrap-key-unhealthy means a control-plane recovery
    // would restore an UNUSABLE credential, so the otherwise auto-postable dest-auth primary is
    // human-gated (warning + escalate-reason both ride).
    expectEscalate: true,
    expectSignals: ["dest-auth-failed", "wrap-key-unhealthy"],
    // Discrimination: the env CONFIG_WRAP_KEY itself parses fine (wrong-key, not malformed-key), so
    // the keys-health parse probe must stay quiet.
    expectAbsentSignals: ["key-material-unhealthy", "throttled"],
    mutate: (w) => {
      destNet403(w);
      // The no-custody export slice still carries an envelope wrapped under the PRIOR wrap key (the
      // credential was re-wrapped after a key rotation but the export has not re-run): flip one
      // base64url char mid-ciphertext so the AEAD open fails -> the real probe classifies "wrong-key".
      // NEW objects only -- keys.wrappedDestSecret is shared across scenarios and /dest-config must
      // stay decryptable so the destination probe reaches the (403) network.
      const exp = w.routes["/control-plane/export"] as Dict;
      const orig = ((exp["destinations"] as Dict[])[0]!["secret"] as Dict)["wrapped"] as Dict;
      const ct = orig["ct"] as string;
      const i = ct.length >> 1;
      const flipped = ct.slice(0, i) + (ct[i] === "A" ? "B" : "A") + ct.slice(i + 1);
      w.routes["/control-plane/export"] = { destinations: [{ id: "d-primary", secret: { wrapped: { ...orig, ct: flipped } } }] };
    },
    capture: (b) => [
      ...expectDestAuthPreflight(b),
      ...expectInBundle(b, '"wrong-key"', "the wrap-key health probe's wrong-key class"),
    ],
  },

  // --------------------------------------------------------------- 9. per-downpipe faults across a fleet
  {
    id: "multi.per-downpipe-mixed-fleet",
    title: "3-downpipe fleet: dp1 healthy, dp2 dest-auth failed run, dp3 seal-suspect",
    domain: "multi",
    // Fleet-wide precedence: signals aggregate ACROSS downpipes, and the tree picks dest-auth over
    // seal-suspect regardless of which downpipe carries which fault; dp3's integrity concern rides
    // as the seal warning + escalate-reason.
    trueClass: "DEST-AUTH-FAILED",
    isFault: true,
    expectEscalate: true, // the seal-suspect secondary forces review of the auto-postable primary
    expectSignals: ["dest-auth-failed", "seal-suspect"],
    expectAbsentSignals: ["bindings-probe-failed", "throttled"],
    mutate: (w) => {
      const now = Date.now();
      const dps = w.routes["/downpipes"] as Dict[];
      dps.push(
        { config: { id: "dp2", name: "media", enabled: true, cadenceSeconds: 7200, source: { type: "r2", binding: "MEDIA_R2", bucketName: "media-bucket", include: [], exclude: [] } }, lastRunId: "01R2BAD", inFlight: false, nextRunAt: now + HOUR, cronResolve: { class: "ok", at: now + HOUR }, lastRestoreTestAt: now - 8 * HOUR, lastRestoreTestOk: true },
        { config: { id: "dp3", name: "app-db", enabled: true, cadenceSeconds: 86400, source: { type: "d1", binding: "APP_D1", include: [], exclude: [] } }, lastRunId: "01D1OK", inFlight: false, nextRunAt: now + 4 * HOUR, cronResolve: { class: "ok", at: now + 4 * HOUR }, lastRestoreTestAt: now - 20 * HOUR, lastRestoreTestOk: true },
      );
      const by = (w.routes["/history"] as Dict).byDownpipe as Record<string, Dict[]>;
      by["dp2"] = [
        { runId: "01R2BAD", index: 4, startedAt: iso(now - 30 * MIN), status: "failed", error: "destination rejected the write (AccessDenied)", causeDigest: "b2c3d4e5f6a1" },
        { runId: "01R2OK", index: 3, startedAt: iso(now - 90 * MIN), status: "ok", recordCount: 10, bytes: 2048, durationMs: 400, recordsSkipped: 0, recordsIncomplete: 0, destinationId: "d-primary", sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: 4, at: now - 89 * MIN } },
      ];
      by["dp3"] = [
        { runId: "01D1OK", index: 2, startedAt: iso(now - 5 * HOUR), status: "ok", recordCount: 200, bytes: 40960, durationMs: 900, recordsSkipped: 0, recordsIncomplete: 0, destinationId: "d-primary", sealVerification: { status: "suspect", tier: "sampled-decrypt", sampled: 12, at: now - 5 * HOUR + MIN, reason: "record integrity check failed" } },
      ];
      // Bindings present + live for dp2/dp3 (fake platform objects), so the bindings/liveness probes
      // stay green and the fleet's faults are RUN-level only.
      w.env["MEDIA_R2"] = { list: async () => ({ objects: [], truncated: false }) };
      w.env["APP_D1"] = { prepare: () => ({ bind: () => ({ first: async () => ({ one: 1 }) }), first: async () => ({ one: 1 }) }) };
      const repl = (w.routes["/replication"] as Dict).byDownpipe as Record<string, Dict>;
      repl["dp2"] = { "d-primary": { holdsRunId: "01R2OK", holdsIndex: 3, lastOk: true, lastAttemptAt: now - 89 * MIN } };
      repl["dp3"] = { "d-primary": { holdsRunId: "01D1OK", holdsIndex: 2, lastOk: true, lastAttemptAt: now - 5 * HOUR + MIN } };
    },
    capture: (b) => [
      ...expectInBundle(b, "destination rejected the write (AccessDenied)", "dp2's coarse dest-reject error"),
      ...expectInBundle(b, '"suspect"', "dp3's suspect seal verification verdict"),
    ],
  },

  // ------------------------------------------------------ 10. kitchen sink of warning-only signals
  {
    id: "multi.everything-recoverable",
    title: "no primary fault, four+ standing warnings: canary dead + cooldown stuck + export stale + tier-0 + degraded replica",
    domain: "multi",
    // NO primary-setting fault fires (all runs OK, probes green), but each warning-only signal gates
    // the clean HEALTHY auto-post -> the tree lands INDETERMINATE and every concern escalates. One
    // coherent story: the offsite replica destination died 2 hours ago (canary dead + replication
    // ok=false), its replication-degraded alert fired then and the re-alert reconciliation has NOT
    // refreshed or cleared the cooldown row since (its 1h window elapsed an hour ago -> genuinely
    // STUCK, the post-fix 2026-07-02 semantics), the no-custody export is 9 days old while the config
    // has since moved to v8 (genuinely stale — the export-pass keeps skipping on budget-yield), and
    // the latest seal verify passed only structurally (break-glass recipient, no decrypt sample).
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["canary-standing-death", "alert-cooldown-stuck", "control-plane-export-stale", "tier0-verify-only", "destination-degraded"],
    expectAbsentSignals: ["dest-auth-failed", "throttled", "seal-suspect", "replication-redundancy-degraded", "export-pass-degraded"],
    mutate: (w) => {
      const now = Date.now();
      // A second (offsite) destination that is failing to receive copies; the origin stays healthy.
      w.routes["/destinations"] = {
        destinations: [
          { id: "d-primary", label: "Primary R2", endpointHost: DEST_HOST, bucket: "corpus-archive", addressing: "path" },
          { id: "d-offsite", label: "Offsite S3", endpointHost: "s3.example.com", bucket: "corpus-offsite", addressing: "path" },
        ],
        defaultId: "d-primary",
      };
      w.routes["/replication"] = {
        byDownpipe: {
          dp1: {
            "d-primary": { holdsRunId: "01RUNOK", holdsIndex: 7, lastOk: true, lastAttemptAt: now - 54 * MIN },
            "d-offsite": { holdsRunId: "01RUNPRV", holdsIndex: 6, lastOk: false, lastAttemptAt: now - 54 * MIN, reason: "unreachable" },
          },
        },
      };
      // The canary is in a STANDING death for that destination (it paged once, 2 hours ago).
      w.routes["/canary/transitions"] = { enabled: true, status: "dead", deadDestinations: 1, transitionCount: 1, transitions: [{ at: iso(now - 2 * HOUR), destinationId: "d-offsite", to: "dead", runSeq: 7 }] };
      // ... and the replication-degraded cooldown row from that page is GENUINELY STUCK: its 1h window
      // elapsed an hour ago yet the row was never refreshed (no re-nudge) nor deleted (no recovery).
      w.routes["/notify/cooldowns"] = { cooldownMs: 3_600_000, alert: [], replication: [{ downpipeId: "dp1", state: "replication-degraded", at: now - 2 * HOUR }] };
      // The no-custody control-plane export a recovery would restore FROM is 9 days old AND the config
      // has moved past it (v7 exported, v8 current) — genuinely stale, not the benign quiet-fleet aging
      // (the export pass keeps skipping on the benign budget-yield code, so export-pass-degraded stays quiet).
      w.routes["/control-plane/export-state"] = { configVersion: 7, exportedAt: iso(now - 9 * DAY) };
      (w.routes["/control-plane/recovery-status"] as Dict)["exportHealth"] = { at: iso(now - 20 * MIN), skipped: "budget-yield", wroteAny: false, configVersion: 8, perDest: [] };
      // The latest run VERIFIED, but only at Tier-0: sealed to a break-glass recipient the engine
      // cannot decrypt-sample (verify-at-seal.ts's exact tier-0 verdict shape).
      runs(w)[0]!["sealVerification"] = { status: "verified", tier: "tier-0", sampled: 0, at: now - 54 * MIN, tier0Cause: "break-glass" };
    },
    capture: (b) => [
      ...expectInBundle(b, '"deadDestinations":1', "the canary standing-death count"),
      ...expectInBundle(b, '"replication-degraded"', "the stuck replication alert-cooldown row"),
      ...expectInBundle(b, '"tier0Cause":"break-glass"', "the tier-0 verify cause on the run row"),
      ...expectInBundle(b, '"configVersion":8', "the moved-on current config version (the genuine staleness evidence)"),
    ],
  },
];

// ## FINDINGS (precedence / masking concerns; F-1/F-3 FIXED 2026-07-02, F-2/F-4 by-design)
//
// F-1 (multi.amnesia-plus-dest-auth) — FIXED 2026-07-02 (item 19): dest-auth-failed now HAS a
//     secondary surface — when it fires under a non-dest primary, diagnose.ts appends the "the
//     DESTINATION is ALSO rejecting writes ... any recovery/restore that must READ or WRITE the
//     destination will fail" warning, so the note prescribing a control-plane recovery names the
//     revoked credential that would block it. (Warning-only: the escalation posture is unchanged —
//     recovery was already review-only.)
//
// F-2 (multi.seal-suspect-plus-dest-throttle): by design, DEST-THROTTLED-OR-DOWN (a "usually
//     transient, self-heals" story) outranks SEAL-SUSPECT as the primary, so the headline is the
//     LESSER fault while a record-integrity read-back failure rides only as a warning. The escalation
//     invariant holds (both the <0.90 confidence bar and the seal escalate-reason force review, and
//     the sub-class-specific seal warning is on the note), so nothing is lost -- but a customer
//     skimming the primary cause line sees "transient" first. Labeled as designed (the seal-after-
//     actionable-causes ordering exists so a read-back blip cannot mask owner-#1/dest faults).
//
// F-3 (multi.incompleteness-plus-posture) — FIXED 2026-07-02 (item 19): posture-failed now HAS a
//     secondary surface (its own "a posture/access prerequisite is ALSO failing" warning line), so a
//     posture failure with no keys-block twin is no longer prose-invisible under a higher primary.
//
// F-4 (multi.owner1-plus-notify-broken): answering the design question "is escalation forced by the
//     notify secondary?" -- YES: no-notify-channels pushes an escalate-reason ("an operator relying on
//     alerts must be told alerting is off"), so the otherwise auto-postable BINDINGS-CURRENTLY-MISSING
//     primary is human-gated, and the note reads as one combined story (re-attach fix + the
//     alerting-was-off warning). expectEscalate: true is the truthful label.
//
// Escalation invariant summary: every multi-fault scenario in this batch escalates -- each secondary
// (incompleteness, seal-suspect, wrap-key, no-notify-channels, canary/cooldown/export/tier0/degraded-
// replica, stall) forces escalateToHuman even where the primary alone would auto-post (scenarios 2, 3,
// 7, 8, 9 have auto-postable primaries). No composition was found where an integrity/shortfall
// secondary failed to escalate.
