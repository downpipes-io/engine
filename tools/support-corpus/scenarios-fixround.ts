// FIX-ROUND corpus scenarios (2026-07-02): genuine-fault proofs for every diagnosis gap closed in the
// fix round — the backup-overdue P1 gap, the status DO-opts keystones, the restore-test reason routing,
// changeKind correlation, thaw-needed, config-integrity history/snapshot, the scheduler tail
// (state-inconsistent + the new cron-false-green arms), seal-loop budget starvation, the unmarked-account
// update blocker, the genuinely-stuck alert cooldown, and the notify self-healed-blip benign twin.
// Engine-exact vocabulary throughout, same discipline as the sibling files: every DO payload copies the
// shapes validate-support pins; every enum value is a member of the engine's closed sets; knob faults are
// induced through the REAL env resolvers. Labels are the DESIGNED post-fix bot behavior: the new signals
// are WARNING-ONLY (each gates a clean HEALTHY + escalates but never sets the primary BACKUP class), so a
// world where such a signal is the only evidence is INDETERMINATE + escalate.

import type { Scenario, World } from "./harness.ts";

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
function schedSignals(w: World): Dict {
  return w.routes["/scheduler-signals"] as Dict;
}
/** Replace the latest run with a FAILED row carrying the engine's closed coarse error string. */
function failLatestRun(w: World, error: string): void {
  const now = Date.now();
  runs(w)[0] = {
    runId: "01RUNBAD",
    index: 8,
    startedAt: iso(now - 20 * MIN),
    status: "failed",
    error,
    causeDigest: "c3d4e5f6a1b2",
  };
  dp1(w).lastRunId = "01RUNBAD";
}
function bundleText(b: Dict): string {
  return JSON.stringify(b);
}
function expectInBundle(b: Dict, needle: string, what: string): string[] {
  return bundleText(b).includes(needle) ? [] : [`bundle does not carry ${what} (expected substring ${JSON.stringify(needle)})`];
}
/** Append extra allowlisted audit events (ascending seq from 13) to the healthy recent window,
 * preserving the baseline route's per-action keystone filter behaviour. */
function appendAuditEvents(w: World, events: Dict[]): void {
  const prev = w.routes["/audit/export"] as (url: URL, body: unknown) => Dict;
  const headSeq = 12 + events.length;
  w.routes["/audit/export"] = (url: URL, body: unknown): Dict => {
    const action = url.searchParams.get("action");
    if (action !== null) return prev(url, body); // keystone action-filter lookups: unchanged (none retained)
    const base = prev(url, body) as { events: Dict[] } & Dict;
    return { ...base, events: [...base.events, ...events], headSeq, headHash: `sha384:h${headSeq}` };
  };
}

export const FIXROUND_SCENARIOS: Scenario[] = [
  // ------------------------------------------------- item 1: backup-overdue (the P1 robustness gap)
  {
    id: "fixround.backup-overdue-scheduler-dead",
    title: "the deploy dropped the cron trigger three days ago: the downpipe's nextRunAt sits days past due, nothing in flight, nothing failed",
    domain: "sched",
    // Designed routing: backup-overdue is warning-only (it gates HEALTHY + escalates but never sets the
    // primary), so the silently-stopped scheduler with green old runs is INDETERMINATE + escalate. Before
    // the fix this world read auto-postable HEALTHY (the confirmed P1 silent miss).
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["backup-overdue"],
    expectAbsentSignals: ["run-stalled", "cron-false-green", "plan-ceiling-exceeded", "scheduler-state-inconsistent", "cron-unresolvable"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      d["nextRunAt"] = now - 3 * DAY; // due 3 days ago on a 1h cadence, never dispatched
      d["inFlight"] = false;
      (d["cronResolve"] as Dict)["at"] = now - 3 * DAY;
      // The last runs really happened 3 days ago (green then; nothing since).
      const rs = runs(w);
      rs[0]!["startedAt"] = iso(now - 3 * DAY);
      (rs[0]!["sealVerification"] as Dict)["at"] = now - 3 * DAY + MIN;
      rs[1]!["startedAt"] = iso(now - 3 * DAY - HOUR);
      (rs[1]!["sealVerification"] as Dict)["at"] = now - 3 * DAY - HOUR + MIN;
      // The dead scheduler's own ticks see NOTHING due (the lost alarm / removed trigger never surfaces the
      // downpipe), and nothing dispatches — which also proves the plan-ceiling dispatch gate stays quiet.
      schedSignals(w)["ticks"] = [
        { at: now - 8 * MIN, intervalMs: 300_000, due: 0, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 9, budgetRemaining: 691, overBudget: false },
        { at: now - 3 * MIN, intervalMs: 300_000, due: 0, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 7, budgetRemaining: 693, overBudget: false },
      ];
      // Old delivered notifications from the last real runs (nothing recent to deliver).
      w.routes["/notify/history"] = [
        { seq: 2, ts: iso(now - 3 * DAY + 5 * MIN), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
      ];
    },
    capture: (b) => {
      const d = (b["downpipes"] as Dict[])[0]!;
      const fails: string[] = [];
      if (typeof d["nextRunAt"] !== "number") fails.push("downpipes[0].nextRunAt expected (the overdue evidence)");
      else if ((d["nextRunAt"] as number) > Date.now() - 2 * DAY) fails.push("downpipes[0].nextRunAt expected days in the past");
      if (d["inFlight"] !== false) fails.push(`downpipes[0].inFlight expected false, got ${String(d["inFlight"])}`);
      return fails;
    },
  },

  // ----------------------------------------- item 2: status DO-opts (expiry / disposal / restorability)
  {
    id: "fixround.credential-expiry-warnings",
    title: "two tracked credential expiries have crossed into WARNING and one spent token awaits deletion",
    domain: "posture",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["credential-expiry-warnings"],
    expectAbsentSignals: ["break-glass-bootstrap-undisposed", "licence-expiry-stale", "posture-failed"],
    mutate: (w) => {
      w.routes["/expiry/warnings"] = { expiryWarnings: 2, cleanupPending: 1 };
    },
    capture: (b) => [
      ...expectInBundle(b, '"expiryWarnings":2', "the status expiry-warning count"),
      ...expectInBundle(b, '"cleanupPending":1', "the pending-cleanup count"),
    ],
  },
  {
    id: "fixround.bootstrap-token-undisposed",
    title: "the first Owner was claimed with the bootstrap ADMIN_TOKEN months ago but the bearer was never retired and is still deployed",
    domain: "posture",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["break-glass-bootstrap-undisposed"],
    expectAbsentSignals: ["no-admin-credential-path", "credential-expiry-warnings"],
    mutate: (w) => {
      // The standing bearer credential: ADMIN_TOKEN still in the deploy env (status.adminTokenConfigured=true);
      // the harness disposal route already reports { bootstrapConsumed: true, breakGlassTokenRetired: false }.
      w.env["ADMIN_TOKEN"] = "corpus-bootstrap-bearer-secret";
    },
    capture: (b) => {
      const fails = [
        ...expectInBundle(b, '"bootstrapConsumed":true', "the consumed-bootstrap latch"),
        ...expectInBundle(b, '"breakGlassTokenRetired":false', "the unretired latch"),
        ...expectInBundle(b, '"adminTokenConfigured":true', "the standing-bearer presence flag"),
      ];
      if (bundleText(b).includes("corpus-bootstrap-bearer-secret")) fails.push("the ADMIN_TOKEN VALUE leaked into the pack (presence-only violated)");
      return fails;
    },
  },
  {
    id: "fixround.restorability-never-proven",
    title: "a fleet with months of green runs where NO restore has ever been proven and NO scheduled restore test has ever run",
    domain: "dr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["restorability-unproven"],
    expectAbsentSignals: ["restore-test-failed", "deep-verify-stale", "seal-suspect"],
    mutate: (w) => {
      // No drill outcome anywhere: the per-downpipe restore-test fields never existed on this fleet, and no
      // downpipe carries a restoreProven block -> status.restorabilityProven computes 0 (the keystone).
      const d = dp1(w);
      delete d["lastRestoreTestAt"];
      delete d["lastRestoreTestOk"];
    },
    capture: (b) => [
      ...expectInBundle(b, '"restorabilityProven":0', "the zero proven-restore status count"),
    ],
  },

  // ------------------------------------------------- item 3: restore-test reason routing (dest-access)
  {
    id: "fixround.restore-test-dest-access",
    title: "the nightly restore drill cannot READ the destination (revoked read credential): two drills failed with dest-access",
    domain: "dr",
    // The restore test drives the late SEAL-SUSPECT primary; the dest-access reason routes AVAILABILITY
    // prose ("says nothing about the bytes"), not corruption prose — the integrity variant is
    // dr.scheduled-restore-test-failed.
    trueClass: "SEAL-SUSPECT",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["restore-test-failed", "seal-suspect"],
    expectAbsentSignals: ["restorability-unproven", "dest-auth-failed"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      d["lastRestoreTestAt"] = now - 3 * HOUR;
      d["lastRestoreTestOk"] = false;
      d["lastRestoreTestReason"] = "dest-access"; // RESTORE_TEST_REASON_CODES member
      d["restoreTestConsecutiveFailures"] = 2;
    },
    capture: (b) => [
      ...expectInBundle(b, '"lastRestoreTestReason":"dest-access"', "the closed dest-access drill reason"),
      ...expectInBundle(b, '"restoreTestConsecutiveFailures":2', "the drill failure streak"),
    ],
  },

  // ------------------------------------- item 4: the control-plane lifecycle actions stay legible
  {
    id: "fixround.cp-lifecycle-events-visible",
    title: "last week's recovery lifecycle (export written, plane resumed) sits in the audit excerpt of an otherwise healthy fleet",
    domain: "cpr",
    // Context-only events: nothing fires (they are legible context for a human, not a fault) — the fleet
    // reads HEALTHY. Before the fix each degraded to other-config-change (the action identity was lost).
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["dest-config-change-risky", "recovery-required", "recovery-staged-pending"],
    mutate: (w) => {
      const now = Date.now();
      appendAuditEvents(w, [
        { seq: 13, ts: iso(now - 6 * DAY), action: "control-plane-exported", outcome: "ok", prevHash: "sha384:h12", hash: "sha384:h13" },
        { seq: 14, ts: iso(now - 6 * DAY + 10 * MIN), action: "control-plane-resumed", outcome: "ok", prevHash: "sha384:h13", hash: "sha384:h14" },
      ]);
    },
    capture: (b) => [
      ...expectInBundle(b, '"control-plane-exported"', "the retained control-plane-exported lifecycle action"),
      ...expectInBundle(b, '"control-plane-resumed"', "the retained control-plane-resumed lifecycle action"),
    ],
  },

  // ---------------------------------------------- item 5: changeKind correlates a notify config change
  {
    id: "fixround.notify-change-preceded-broken-alerting",
    title: "a config-approved notify-channel-delete went through yesterday; today no channels remain and alerting is off",
    domain: "notify",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["no-notify-channels"],
    expectAbsentSignals: ["notify-rule-misconfigured", "notify-delivery-failed"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/notify/channels"] = [];
      w.routes["/notify/rules"] = [];
      // The dual-control config-approval trail: the approved change names the closed changeKind
      // (configchange audit target; support.ts configChangeFields projects ONLY the changeKind).
      appendAuditEvents(w, [
        { seq: 13, ts: iso(now - DAY), action: "config-change-approve", outcome: "ok", prevHash: "sha384:h12", hash: "sha384:h13", target: { kind: "configchange", id: "01CRDELETE", changeKind: "notify-channel-delete" } },
      ]);
    },
    capture: (b) => {
      const fails = [
        ...expectInBundle(b, '"changeKind":"notify-channel-delete"', "the closed notify changeKind on the approved change"),
        ...expectInBundle(b, '"channelCount":0', "the zero-channel notify config"),
      ];
      if (bundleText(b).includes("01CRDELETE")) fails.push("the change-request id leaked into the excerpt (only changeKind may ride)");
      return fails;
    },
  },

  // --------------------------------------------------------------- item 6: thaw-needed (cold storage)
  {
    id: "fixround.seal-thaw-needed",
    title: "a bucket lifecycle rule moved the archive to GLACIER: the seal read-back reports thaw-needed (present but unreadable)",
    domain: "seal",
    trueClass: "SEAL-SUSPECT",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["seal-suspect"],
    expectAbsentSignals: ["dest-auth-failed", "throttled", "restore-test-failed"],
    mutate: (w) => {
      const now = Date.now();
      // verify-at-seal's coarseVerifyReason emits the distinct closed "thaw-needed" token for a
      // GLACIER/DEEP_ARCHIVE (InvalidObjectState / cold storage class) read-back.
      const verdict = { status: "suspect", tier: "tier-0", sampled: 0, at: now - 50 * MIN, reason: "thaw-needed" };
      latestRun(w)["sealVerification"] = verdict;
      dp1(w)["lastSealVerify"] = verdict;
    },
    capture: (b) => expectInBundle(b, '"thaw-needed"', "the closed thaw-needed verify reason"),
  },

  // ------------------------------------- item 7: config-history verify + snapshot-capture failures
  {
    id: "fixround.config-history-key-rotated",
    title: "an auth-DO storage reset regenerated the config-history signing key: the chain no longer verifies (rotation, not tamper)",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["config-history-unverifiable"],
    expectAbsentSignals: ["config-snapshot-capture-failing", "audit-chain-broken", "change-control-refusing"],
    mutate: (w) => {
      w.routes["/config-history-health"] = { count: 4, headId: 4, verify: { intact: false, checkedThrough: 1, earliestId: 1, signingKeyRotated: true } };
    },
    capture: (b) => [
      ...expectInBundle(b, '"intact":false', "the failed config-history verify"),
      ...expectInBundle(b, '"signingKeyRotated":true', "the key-rotation (not-tamper) discriminator"),
    ],
  },
  {
    id: "fixround.config-snapshot-failing-and-history-broken",
    title: "config auto-snapshots have failed 3 times and the config-history chain is broken at version 2 (key NOT rotated)",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["config-snapshot-capture-failing", "config-history-unverifiable"],
    expectAbsentSignals: ["audit-chain-broken"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/config-snapshot-health"] = { count: 3, lastAt: iso(now - 2 * HOUR) };
      w.routes["/config-history-health"] = { count: 4, headId: 4, verify: { intact: false, brokenAt: 2, checkedThrough: 4, earliestId: 1 } };
    },
    capture: (b) => [
      ...expectInBundle(b, '"snapshotFailures":{"count":3', "the snapshot-failure tally"),
      ...expectInBundle(b, '"brokenAt":2', "the broken config-history version"),
    ],
  },

  // ------------------------- item 8: scheduler-state-inconsistent + the new cron-false-green arms
  {
    id: "fixround.scheduler-state-inconsistent",
    title: "the due-index rebuild found drift AND the runlog counter sits behind the recorded history (a DO restore reset it)",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["scheduler-state-inconsistent"],
    expectAbsentSignals: ["cron-false-green", "scheduler-storage-faulting"],
    mutate: (w) => {
      const now = Date.now();
      const sched = schedSignals(w);
      sched["dueIndex"] = { at: now - 3 * MIN, indexEntriesBeforeRebuild: 0, indexEntriesRequired: 1, dpTotal: 1, matched: false };
      sched["runlog"] = { counter: 2, maxHistoryIndex: 7 };
    },
    capture: (b) => [
      ...expectInBundle(b, '"matched":false', "the due-index mismatch"),
      ...expectInBundle(b, '"counter":2', "the reset runlog counter"),
    ],
  },
  {
    id: "fixround.sched-partial-dispatch",
    title: "5 downpipes came due but only 2 dispatched and 1 carried: 2 vanished from the tick's accounting",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["cron-false-green"],
    expectAbsentSignals: ["scheduler-state-inconsistent", "scheduler-storage-faulting", "plan-ceiling-exceeded"],
    mutate: (w) => {
      const now = Date.now();
      // Keep tick[0] (the survived paid-plan proof); the latest tick lost 2 of 5 due downpipes.
      (schedSignals(w)["ticks"] as Dict[])[1] = { at: now - 3 * MIN, intervalMs: 300_000, due: 5, dispatched: 2, coalesced: 0, carried: 1, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 80, budgetRemaining: 620, overBudget: false };
    },
    capture: (b) => expectInBundle(b, '"due":5', "the partially-dispatched tick"),
  },
  {
    id: "fixround.sched-overbudget-tick",
    title: "a tick overdrew its subrequest budget (overBudget): the drive loop was cut short mid-tick",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["cron-false-green"],
    expectAbsentSignals: ["plan-ceiling-exceeded", "scheduler-state-inconsistent"],
    mutate: (w) => {
      const now = Date.now();
      (schedSignals(w)["ticks"] as Dict[])[1] = { at: now - 3 * MIN, intervalMs: 300_000, due: 1, dispatched: 1, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 745, budgetRemaining: 0, overBudget: true };
    },
    capture: (b) => expectInBundle(b, '"overBudget":true', "the over-budget tick flag"),
  },
  {
    id: "fixround.sched-missed-ticks",
    title: "a 45-minute gap between recorded ticks on a 5-minute cron: the platform missed ~8 firings",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["cron-false-green"],
    expectAbsentSignals: ["scheduler-storage-faulting", "backup-overdue"],
    mutate: (w) => {
      const now = Date.now();
      (schedSignals(w)["ticks"] as Dict[])[1] = { at: now - 3 * MIN, intervalMs: 45 * MIN, due: 1, dispatched: 1, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 30, budgetRemaining: 670, overBudget: false };
    },
    capture: (b) => expectInBundle(b, `"intervalMs":${45 * MIN}`, "the missed-ticks interval gap"),
  },

  // ------------------------------------------------- item 9: seal-loop budget starvation (driveBudgetYields)
  {
    id: "fixround.seal-loop-budget-starved",
    title: "the fleet outgrew the per-tick budget: the seal loop yielded 6 times, most recently carrying 3 undispatched downpipes",
    domain: "infra",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["seal-loop-budget-starved"],
    expectAbsentSignals: ["cron-false-green", "plan-ceiling-exceeded"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/drive-budget-yield"] = { count: 6, lastAt: now - 20 * MIN, lastCarried: 3 };
    },
    capture: (b) => [
      ...expectInBundle(b, '"driveBudgetYields"', "the budget-yield record"),
      ...expectInBundle(b, '"lastCarried":3', "the last starved-downpipe count"),
    ],
  },

  // ------------------------------------------- item 10: the unmarked-account update blocker
  {
    id: "fixround.update-blocked-unmarked-account",
    title: "an update to 0.1.1 is pending but the engine account was never marked: every apply/settle is refused by the account gate",
    domain: "updates",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["update-failed-or-rollback-needed"],
    expectAbsentSignals: ["engine-flapping-two-versions", "licence-activation-failed"],
    mutate: (w) => {
      const now = Date.now();
      // The account is unmarked BOTH ways the engine checks: no CF_ACCOUNT_ID deploy var, and no marked
      // engineAccountId in the discovery config.
      delete w.env["CF_ACCOUNT_ID"];
      w.routes["/sources/discovery-config"] = { config: null };
      w.routes["/update-status"] = {
        pending: { fromVersion: "0.1.0", toVersion: "0.1.1", recommendedVersion: "0.1.1", riskClass: "standard", promotedAt: now - 2 * HOUR },
        settledHighWaterMark: "0.1.0",
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"engineAccountMarked":false', "the unmarked-account gate verdict"),
      ...expectInBundle(b, '"riskClass":"standard"', "the pending update's risk class"),
    ],
  },

  // ------------------------------------------------- item 16: the GENUINELY stuck alert cooldown
  {
    id: "fixround.alert-cooldown-genuinely-stuck",
    title: "the destination has thrown SlowDown for 3 hours; the one alert fired then, its 1h cooldown elapsed 2 hours ago, and no re-nudge ever came",
    domain: "notify",
    // The transient dest fault sets the DEST-THROTTLED-OR-DOWN primary (conf 0.85 < 0.90 -> human-gated);
    // the STUCK cooldown (window elapsed, row still present -- the reconcile that should refresh or delete
    // it is not happening) rides as the alerting warning.
    trueClass: "DEST-THROTTLED-OR-DOWN",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["throttled", "alert-cooldown-stuck"],
    expectAbsentSignals: ["dest-auth-failed", "no-notify-channels"],
    mutate: (w) => {
      const now = Date.now();
      failLatestRun(w, "destination rejected the write (SlowDown)");
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - 3 * HOUR), event: "backup-failure", severity: "critical", downpipeId: "dp1", channelKind: "webhook", delivered: true },
        { seq: 2, ts: iso(now - 5 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
      ];
      // The cooldown row from that alert, 3h old with a 1h window: elapsed 2h ago and STILL present.
      w.routes["/notify/cooldowns"] = { cooldownMs: 3_600_000, alert: [{ downpipeId: "dp1", state: "failed", at: now - 3 * HOUR }], replication: [] };
    },
    capture: (b) => [
      ...expectInBundle(b, '"state":"failed"', "the stuck alert-cooldown row"),
      ...expectInBundle(b, "destination rejected the write (SlowDown)", "the standing transient dest fault"),
    ],
  },

  // ------------------------------------------------- item 17: the self-healed notify blip (benign twin)
  {
    id: "fixround.notify-self-healed-blip",
    title: "the ops webhook 500'd once during a provider blip 3 hours ago; every delivery since (newest included) succeeded",
    domain: "notify",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["notify-delivery-failed", "notify-rule-misconfigured", "notify-sink-rebind-exposed"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - 30 * MIN), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
        { seq: 2, ts: iso(now - 3 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: false, deliveryCode: "http-5xx" },
        { seq: 1, ts: iso(now - 5 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
      ];
    },
    capture: (b) => [
      ...expectInBundle(b, '"deliveryCode":"http-5xx"', "the healed blip's failure code"),
      ...expectInBundle(b, '"delivered":true', "the newer successful delivery"),
    ],
  },
];
