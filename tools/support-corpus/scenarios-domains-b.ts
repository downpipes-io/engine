// DOMAIN batch B: SEAL / RECONCILE / RUNS-SCHEDULER / INFRA / DEST-CONFIG / UPDATES /
// DR-RESTORE / SOURCES fault scenarios. Engine-exact vocabulary throughout: seal verdict tiers +
// tier0 causes are verify-at-seal.ts literals ("tier-0", "break-glass"); restore-test reasons are
// RESTORE_TEST_REASON_CODES; cron classes are CRON_RESOLVE_CLASSES; update outcomes are
// update-apply.ts UpdateOutcome literals; reconcile rows copy the validate-support DO shapes;
// knob faults are induced through the REAL env resolvers (VERIFY_AT_SEAL / SCALE_SLICE_WALL_MS /
// DEST_RATE_PER_SEC / DEST_WORM_*), never hand-authored blocks.
//
// Labels are the DESIGNED bot behavior (diagnose.ts precedence): the phase-3 availability /
// posture / assurance signals are WARNING-ONLY -- each blocks a clean HEALTHY auto-post and
// forces escalation but never sets the primary class -- so a world where such a signal is the
// only evidence is INDETERMINATE + escalate with isFault:true.
//
// ## FINDINGS (all three FIXED in the 2026-07-02 fix round; labels encode the POST-FIX behavior)
//  1. FIXED 2026-07-02: source-records-collapsed now joins diagnose.ts's HEALTHY class gate, so a
//     source whose latest ok run collapsed to 0 records classes INDETERMINATE (it already escalated;
//     the class label now agrees). See sources.record-count-collapsed.
//  2. FIXED 2026-07-02: restore-test-failed now carries the CLOSED lastRestoreTestReason (+ streak) and
//     both the warning and (when the restore test is the ONLY suspect-seal evidence) the SEAL-SUSPECT
//     cause are routed by it — an `integrity` failure gets AT-REST-CORRUPTION prose ("a re-run does NOT
//     repair the stored archive"), never the reassuring re-run line. See dr.scheduled-restore-test-failed
//     (+ fixround.restore-test-dest-access for the availability routing).
//  3. FIXED 2026-07-02: plan-ceiling-exceeded now also requires some recorded tick to have DISPATCHED
//     work, so a brand-new install (nothing due, nothing dispatched) no longer cries wolf; a working
//     unproven fleet still fires. See infra.free-plan-ceiling-unproven (its ticks dispatch) and
//     healthy.fresh-install (relabelled).

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

function bundleText(b: Dict): string {
  return JSON.stringify(b);
}
function expectInBundle(b: Dict, needle: string, what: string): string[] {
  return bundleText(b).includes(needle) ? [] : [`bundle does not carry ${what} (expected substring ${JSON.stringify(needle)})`];
}

/** Append ONE extra allowlisted audit event (seq 13) to the healthy recent window, preserving the
 * action-filter (keystone) behaviour of the baseline route. The head advances to seq 13 so the
 * excerpt window fetch sees the event. */
function appendAuditEvent(w: World, event: Dict): void {
  const prev = w.routes["/audit/export"] as (url: URL, body: unknown) => Dict;
  w.routes["/audit/export"] = (url: URL, body: unknown): Dict => {
    const action = url.searchParams.get("action");
    if (action !== null) return prev(url, body); // keystone action-filter lookups: unchanged (none retained)
    const base = prev(url, body) as { events: Dict[] } & Dict;
    return { ...base, events: [...base.events, event], headSeq: 13, headHash: "sha384:h13" };
  };
}

export const DOMAIN_B_SCENARIOS: Scenario[] = [
  // ---------------------------------------------------------------------- seal
  {
    id: "seal.verify-at-seal-disabled",
    title: "ops set VERIFY_AT_SEAL=off to speed runs up: archives now seal with no read-back check",
    domain: "seal",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["seal-verify-disabled"],
    expectAbsentSignals: ["seal-suspect", "tier0-verify-only"],
    mutate: (w) => {
      w.env["VERIFY_AT_SEAL"] = "off"; // the real resolveSealVerifyKnobs falsey vocabulary
      delete latestRun(w)["sealVerification"]; // the first run sealed after the knob flip has no verdict
    },
    capture: (b) => expectInBundle(b, '"verifyAtSeal":{"enabled":false', "the resolved verify-at-seal enabled=false knob"),
  },
  {
    id: "seal.tier0-only-break-glass",
    title: "owner moved to break-glass-only sealing: verify passes but only structurally (no decrypt sample)",
    domain: "seal",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["tier0-verify-only"],
    expectAbsentSignals: ["seal-suspect", "seal-verify-disabled"],
    mutate: (w) => {
      const now = Date.now();
      // verify-at-seal.ts:361 emits exactly this shape for a verified Tier-0 verdict.
      const verdict = { status: "verified", tier: "tier-0", sampled: 0, at: now - 54 * MIN, tier0Cause: "break-glass" };
      latestRun(w)["sealVerification"] = verdict;
      dp1(w)["lastSealVerify"] = verdict; // the engine persists the downpipe-level twin
    },
    capture: (b) => expectInBundle(b, '"tier0Cause":"break-glass"', "the Tier-0 skipped-sample cause"),
  },
  {
    id: "seal.multipart-abort-stranded",
    title: "a segment multipart upload failed and its abort ALSO failed: invisible parts stranded at the destination",
    domain: "seal",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["multipart-abort-stranded"],
    expectAbsentSignals: ["dest-auth-failed", "throttled"],
    mutate: (w) => {
      // The run itself completed on retry; the failed multipart's best-effort abort did not.
      latestRun(w)["multipartAbortFailed"] = true;
    },
    capture: (b) => expectInBundle(b, '"multipartAbortFailed":true', "the stranded-multipart boolean on the run row"),
  },

  // ------------------------------------------------------------------ reconcile
  {
    id: "reconcile.orphans-and-freshness-residuals",
    title: "reconcile pass found 2 recoverable orphan run-trees + 1 dangling prev-link after an interrupted finalise",
    domain: "reconcile",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["reconcile-orphans-present", "freshness-residual-present"],
    expectAbsentSignals: ["reconcile-runlog-corrupt"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/reconcile-inventory"] = {
        byDest: [
          { destKey: "d-primary", at: now - 30 * MIN, runlogPresent: true, runlogSigVerified: true, runlogHealth: "ok", committed: 12, orphanedRecoverable: 2, neverReferenced: 1, undetermined: 0, freshnessResiduals: 1, circuitBreakerTripped: false },
        ],
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"orphanedRecoverable":2', "the recoverable-orphan count"),
      ...expectInBundle(b, '"freshnessResiduals":1', "the dangling prev-link residual count"),
    ],
  },
  {
    id: "reconcile.runlog-corrupt",
    title: "the offsite destination's signed RUNLOG no longer parses: reconcile abstained (runlog-unverifiable)",
    domain: "reconcile",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["reconcile-runlog-corrupt"],
    expectAbsentSignals: ["reconcile-orphans-present", "freshness-residual-present"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/reconcile-inventory"] = {
        byDest: [
          { destKey: "d-primary", at: now - 25 * MIN, runlogPresent: true, runlogSigVerified: false, runlogHealth: "corrupt", committed: 0, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, freshnessResiduals: 0, circuitBreakerTripped: false, deferred: "runlog-unverifiable" },
        ],
      };
    },
    capture: (b) => expectInBundle(b, '"runlogHealth":"corrupt"', "the corrupt RUNLOG health verdict"),
  },

  // ----------------------------------------------------------- runs-scheduler
  {
    id: "sched.cron-false-green-crashed-pass",
    title: "cron ticks look green but the drive pass crashed and none of the 2 due downpipes ran",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["cron-false-green"],
    expectAbsentSignals: ["scheduler-storage-faulting", "plan-ceiling-exceeded", "run-stalled"],
    mutate: (w) => {
      const now = Date.now();
      // Keep tick[0] (the survived budgetSpent-300 paid-plan proof); the LATEST tick crashed its pass.
      (schedSignals(w)["ticks"] as Dict[])[1] = { at: now - 3 * MIN, intervalMs: 300_000, due: 2, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 1, budgetCap: 700, budgetSpent: 40, budgetRemaining: 660, overBudget: false };
    },
    capture: (b) => expectInBundle(b, '"passErrors":1', "the crashed-pass count on the tick outcome"),
  },
  {
    id: "sched.do-storage-value-too-large",
    title: "a run-state row outgrew the 128KiB DO value cap: persist-state puts are faulting",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["scheduler-storage-faulting"],
    expectAbsentSignals: ["cron-false-green"],
    mutate: (w) => {
      const now = Date.now();
      schedSignals(w)["storageFaults"] = { total: 2, valueTooLarge: 2, putFailed: 0, lastAt: now - 10 * MIN, lastKind: "value-too-large" };
    },
    capture: (b) => expectInBundle(b, '"storageFaults":{"total":2', "the persist-state storage-fault counter"),
  },
  {
    id: "sched.cron-tz-invalid",
    title: "customer pasted a cron with a bad IANA timezone: the schedule silently fell back to cadence",
    domain: "sched",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["cron-unresolvable"],
    mutate: (w) => {
      const now = Date.now();
      dp1(w)["cronResolve"] = { class: "tz-invalid", at: now - 30 * MIN }; // CRON_RESOLVE_CLASSES member
    },
    capture: (b) => expectInBundle(b, '"cronResolve":{"class":"tz-invalid"', "the closed cron-resolution class"),
  },

  // ----------------------------------------------------------------------- infra
  {
    // FIXED 2026-07-02 (finding 3, header): the signal now ALSO requires a dispatching fleet (some
    // tick with dispatched>0) — this scenario's tick[0] dispatches, so the genuine working-but-unproven
    // free-plan risk still fires; the brand-new-install cry-wolf (nothing dispatched) no longer does.
    id: "infra.free-plan-ceiling-unproven",
    title: "free-plan account with the default 700-subrequest slice budget: large backups die at the platform 50-cap",
    domain: "infra",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["plan-ceiling-exceeded"],
    expectAbsentSignals: ["cron-false-green", "slice-wall-misconfigured"],
    mutate: (w) => {
      const now = Date.now();
      // No recorded tick ever spent past the free-plan 50-subrequest ceiling -> paidPlanProven false.
      schedSignals(w)["ticks"] = [
        { at: now - 8 * MIN, intervalMs: 300_000, due: 1, dispatched: 1, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 42, budgetRemaining: 658, overBudget: false },
        { at: now - 3 * MIN, intervalMs: 300_000, due: 0, dispatched: 0, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 9, budgetRemaining: 691, overBudget: false },
      ];
    },
    capture: (b) => [
      ...expectInBundle(b, '"budgetExceedsFreeCeiling":true', "the budget-over-free-ceiling derivation"),
      ...expectInBundle(b, '"paidPlanProven":false', "the unproven paid-plan verdict"),
    ],
  },
  {
    id: "infra.slice-wall-typo-low",
    title: "SCALE_SLICE_WALL_MS typo'd as 200 (meant 20000): large runs seal a handful of records per slice",
    domain: "infra",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["slice-wall-misconfigured"],
    expectAbsentSignals: ["plan-ceiling-exceeded"],
    mutate: (w) => {
      w.env["SCALE_SLICE_WALL_MS"] = "200"; // valid numeric, resolved as-is (source "env"), far below LOW_SLICE_WALL_MS
    },
    capture: (b) => [
      ...expectInBundle(b, '"sliceWallUnusuallyLow":true', "the unusually-low slice-wall flag"),
      ...expectInBundle(b, '"wallMs":200', "the resolved 200ms slice wall"),
    ],
  },
  {
    id: "infra.bundle-section-unreadable",
    title: "a scheduler DO blip while the pack was built: the control-plane export-state section could not be read",
    domain: "infra",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["bundle-sections-incomplete"],
    expectAbsentSignals: ["control-plane-export-stale", "status-preflight-conflict"],
    mutate: (w) => {
      w.routes["/control-plane/export-state"] = () => {
        throw new Error("scheduler DO read hiccup");
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"controlPlaneExport":"error"', "the errored section marker"),
      ...expectInBundle(b, '"error":1', "the sections summary error count"),
    ],
  },

  // ------------------------------------------------------------------ dest-config
  {
    id: "destcfg.rate-knob-typo",
    title: "DEST_RATE_PER_SEC set to 'fast': the invalid knob silently fell back to the default write rate",
    domain: "destcfg",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["dest-write-misconfigured"],
    mutate: (w) => {
      w.env["DEST_RATE_PER_SEC"] = "fast"; // non-numeric -> rateKnobInvalid through the real resolver
    },
    capture: (b) => expectInBundle(b, '"rateKnobInvalid":true', "the invalid rate-knob flag"),
  },
  {
    id: "destcfg.worm-policy-not-enforced",
    title: "a WORM policy is configured but the archive bucket was never created with Object-Lock: retention headers are ignored",
    domain: "destcfg",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["worm-not-enforced"],
    expectAbsentSignals: ["dest-auth-failed", "throttled"],
    mutate: (w) => {
      w.env["DEST_WORM_MODE"] = "governance";
      w.env["DEST_WORM_RETENTION_DAYS"] = "30";
      // The live capability probe is GET <endpoint>/<bucket>/?object-lock= (S3 GetObjectLockConfiguration);
      // a bucket not created with Object-Lock answers 404 ObjectLockConfigurationNotFoundError -> enabled:false.
      // Rule order matters: the object-lock rule must match BEFORE the catch-all 200 for the dest host.
      w.net.unshift({
        re: /\?object-lock=/,
        status: 404,
        body: "<Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>Object Lock configuration does not exist for this bucket</Message></Error>",
      });
    },
    capture: (b) => [
      ...expectInBundle(b, '"wormPosture":{"configured":true', "the configured WORM policy"),
      ...expectInBundle(b, '"bucketEnforces":false', "the live probe's definite not-enforced verdict"),
      ...expectInBundle(b, '"mode":"governance"', "the valid policy mode"),
    ],
  },
  {
    id: "destcfg.forced-remove-uncovered-runs",
    title: "an owner force-removed the offsite destination past the orphan guard, stranding 3 runs' only proven copy",
    domain: "destcfg",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["dest-config-change-risky"],
    expectAbsentSignals: ["restore-apply-incomplete"],
    mutate: (w) => {
      const now = Date.now();
      appendAuditEvent(w, {
        seq: 13,
        ts: iso(now - 2 * HOUR),
        action: "dest-config-cleared",
        outcome: "success",
        prevHash: "sha384:h12",
        hash: "sha384:h13",
        target: { kind: "dest-change", op: "remove", id: "offsite-s3", fromDefaultId: "offsite-s3", toDefaultId: "d-primary", force: true, uncoveredOriginRunCount: 3 },
      });
    },
    capture: (b) => [
      ...expectInBundle(b, '"uncoveredOriginRunCount":3', "the forced-removal uncovered-run count"),
      ...expectInBundle(b, '"defaultChanged":true', "the moved default-pointer derivation"),
    ],
  },
  {
    id: "destcfg.change-number-refusals",
    title: "ITIL change-number enforcement is bouncing an operator's destination changes (3 refusals, last a dest-remove)",
    domain: "destcfg",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["change-control-refusing"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/change-control/refusals"] = { count: 3, lastAt: iso(now - 2 * HOUR), lastActionKind: "dest-remove" };
    },
    capture: (b) => expectInBundle(b, '"changeControlRefusals":{"count":3', "the change-number refusal tally"),
  },
  {
    id: "destcfg.replica-destination-down",
    title: "the 3-2-1 offsite replica has stopped receiving copies (unreachable) while the origin still succeeds",
    domain: "destcfg",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["destination-degraded"],
    expectAbsentSignals: ["replication-redundancy-degraded", "throttled", "dest-auth-failed"],
    mutate: (w) => {
      const now = Date.now();
      const repl = ((w.routes["/replication"] as Dict).byDownpipe as Record<string, Dict>)["dp1"]!;
      // The down replica is recorded ONLY in the repl: state (not on the run row) -- the coarse
      // "unreachable" reason is the engine's replication heartbeat class.
      repl["offsite-s3"] = { holdsRunId: "01RUNPRV", holdsIndex: 6, lastOk: false, lastAttemptAt: now - 54 * MIN, reason: "unreachable" };
    },
    capture: (b) => expectInBundle(b, '"reason":"unreachable"', "the down replica's coarse reason"),
  },

  // --------------------------------------------------------------------- updates
  {
    id: "updates.canary-dead-rolled-back",
    title: "a self-apply engine update failed its canary read-back and auto-rolled back to the prior version",
    domain: "updates",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["update-failed-or-rollback-needed"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/update-status"] = {
        last: {
          outcome: "rolled-back", // update-apply.ts UpdateOutcome literal
          recommendedVersion: "0.1.1",
          fromVersion: "0.1.0",
          toVersion: "0.1.1",
          canaryVerdict: "dead",
          at: now - 2 * HOUR,
          // the engine-authored rollback reason (update-apply.ts base({outcome:"rolled-back"}) phrasing)
          reason: "the update to 0.1.1 did not pass the canary (dead); your engine was automatically rolled back to the prior version. Nothing was lost and no backup or restore was affected.",
        },
        settledHighWaterMark: "0.1.0",
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"outcome":"rolled-back"', "the failed update outcome"),
      ...expectInBundle(b, '"canaryVerdict":"dead"', "the condemning canary verdict"),
    ],
  },

  // ------------------------------------------------------------------- dr-restore
  {
    // FIXED 2026-07-02 (finding 2, header): the reason code + streak now ride the restore-test-failed
    // signal, and the SEAL-SUSPECT primary cause is routed by them — this scenario's `integrity`
    // reason gets the AT-REST-CORRUPTION prose ("a re-run does NOT repair the stored archive"), not
    // the reassuring re-run line (bot-side prose asserted by the fixround item-3 unit tests).
    id: "dr.scheduled-restore-test-failed",
    title: "the nightly scheduled restore test has failed 3 runs straight with an integrity error on the stored archive",
    domain: "dr",
    trueClass: "SEAL-SUSPECT",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["restore-test-failed", "seal-suspect"],
    expectAbsentSignals: ["restorability-unproven", "deep-verify-stale"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      d["lastRestoreTestAt"] = now - 2 * HOUR;
      d["lastRestoreTestOk"] = false;
      d["lastRestoreTestReason"] = "integrity"; // RESTORE_TEST_REASON_CODES member
      d["restoreTestConsecutiveFailures"] = 3;
    },
    capture: (b) => [
      ...expectInBundle(b, '"lastRestoreTestOk":false', "the failed restore-test verdict"),
      ...expectInBundle(b, '"lastRestoreTestReason":"integrity"', "the closed restore-test failure code"),
      ...expectInBundle(b, '"restoreTestConsecutiveFailures":3', "the consecutive-failure streak"),
    ],
  },
  {
    id: "dr.assurance-stale",
    title: "the assurance loop lapsed six weeks ago: no full deep-verify pass and no proven restore in over 30 days",
    domain: "dr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["deep-verify-stale", "restorability-unproven"],
    expectAbsentSignals: ["restore-test-failed"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      d["deepVerify"] = { runId: "01RUNOK", cursor: 42, records: 42, updatedAt: now - 40 * DAY, lastFullPassAt: now - 45 * DAY };
      d["restoreProven"] = { at: now - 40 * DAY, by: "ops@corpus-lab.example", method: "blind-test", runId: "01RUNOLD" };
    },
    capture: (b) => [
      ...expectInBundle(b, '"lastFullPassAt"', "the (stale) full deep-verify pass timestamp"),
      ...expectInBundle(b, '"restoreProven":{"at"', "the (stale) offline-restorability proof"),
    ],
  },
  {
    id: "dr.drill-oom-then-killed",
    title: "a 48MiB record put the restore drill over the 32MiB isolate-safe ceiling; the next drill was killed mid-flight",
    domain: "dr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["restore-drill-oom-risk", "restore-drill-stalled"],
    expectAbsentSignals: ["restore-test-failed", "run-wedged-stalled"],
    mutate: (w) => {
      const now = Date.now();
      const d = dp1(w);
      // RESTORE_OOM_SAFE_BYTES = 32 MiB (drill.ts); the drill buffered a 48 MiB record whole.
      d["lastRestoreOom"] = { at: now - 26 * HOUR, maxRecordBytes: 48 * 1024 * 1024, safeBytes: 32 * 1024 * 1024, overSafe: true };
      // The NEXT scheduled drill's start marker is still set + far past the lease: its tick was killed.
      d["restoreTestStartedAt"] = now - 2 * HOUR;
    },
    capture: (b) => [
      ...expectInBundle(b, '"overSafe":true', "the re-derived OOM-risk flag"),
      ...expectInBundle(b, '"restoreTestStalled":true', "the killed-mid-drill indicator"),
    ],
  },
  {
    id: "dr.restore-apply-incomplete",
    title: "yesterday's windowed restore landed incomplete: 2 records failed and 2 readbacks mismatched",
    domain: "dr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["restore-apply-incomplete"],
    expectAbsentSignals: ["dest-config-change-risky"],
    mutate: (w) => {
      const now = Date.now();
      appendAuditEvent(w, {
        seq: 13,
        ts: iso(now - DAY),
        action: "restore-verified",
        outcome: "failed",
        prevHash: "sha384:h12",
        hash: "sha384:h13",
        target: { kind: "restore-receipt", runId: "01RESTORE", receiptSha384: "sha384:rcpt", recordsRestored: 8, allVerified: false, complete: false, recordsVerified: 10, failures: 2, outOfWindow: 3, readbackVerified: 8, readbackMismatched: 2, d1Total: 4, d1Verified: 3 },
      });
    },
    capture: (b) => [
      ...expectInBundle(b, '"complete":false', "the windowed-restore incomplete flag"),
      ...expectInBundle(b, '"readbackMismatched":2', "the post-write readback mismatch count"),
    ],
  },
  {
    id: "dr.replica-lags-leader",
    title: "both destinations are reachable but the offsite replica is 3 runs behind the leader (redundancy below 3-2-1)",
    domain: "dr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["replication-redundancy-degraded"],
    expectAbsentSignals: ["destination-degraded", "throttled"],
    mutate: (w) => {
      const now = Date.now();
      const repl = ((w.routes["/replication"] as Dict).byDownpipe as Record<string, Dict>)["dp1"]!;
      repl["offsite-s3"] = { holdsRunId: "01RUNOLD", holdsIndex: 4, lastOk: true, lastAttemptAt: now - 53 * MIN };
    },
    capture: (b) => expectInBundle(b, '"holdsIndex":4', "the lagging replica's held run index"),
  },

  // --------------------------------------------------------------------- sources
  {
    id: "sources.records-skipped-mid-crawl",
    title: "the KV namespace was being written during the backup: 4 records changed behind their etag pin and were skipped",
    domain: "sources",
    trueClass: "SILENT-INCOMPLETENESS",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["records-skipped-nonzero"],
    expectAbsentSignals: ["records-incomplete-nonzero"],
    mutate: (w) => {
      latestRun(w)["recordsSkipped"] = 4; // checkpoint.ts recordsSkippedChanged -> run row recordsSkipped
    },
    capture: (b) => expectInBundle(b, '"recordsSkipped":4', "the skipped-record count on the run row"),
  },
  {
    // FIXED 2026-07-02 (finding 1, header): source-records-collapsed now joins the HEALTHY class gate,
    // so the probable silently-emptied source classes INDETERMINATE (it already escalated with the
    // collapse warning; the class label a reviewer sees now agrees with the concern).
    id: "sources.record-count-collapsed",
    title: "the latest run captured ZERO records where the prior run captured 42: the source may have been emptied",
    domain: "sources",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["source-records-collapsed"],
    expectAbsentSignals: ["records-incomplete-nonzero", "run-stalled"],
    mutate: (w) => {
      const now = Date.now();
      runs(w).unshift({
        runId: "01RUNZERO",
        index: 8,
        startedAt: iso(now - 20 * MIN),
        status: "ok",
        recordCount: 0,
        bytes: 0,
        durationMs: 300,
        recordsSkipped: 0,
        recordsIncomplete: 0,
        destinationId: "d-primary",
      });
      const d = dp1(w);
      d["lastRunId"] = "01RUNZERO";
      const repl = ((w.routes["/replication"] as Dict).byDownpipe as Record<string, Dict>)["dp1"] as Record<string, Dict>;
      repl["d-primary"] = { holdsRunId: "01RUNZERO", holdsIndex: 8, lastOk: true, lastAttemptAt: now - 19 * MIN };
    },
    capture: (b) => expectInBundle(b, '"recordCount":0', "the zero-record latest run"),
  },
  {
    id: "sources.discovery-surfaces-unavailable",
    title: "the cf-config token lost two scopes: the last discovery probe could not read 2 surfaces, so they were excluded",
    domain: "sources",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["discovery-surfaces-unavailable"],
    expectAbsentSignals: ["posture-failed", "records-incomplete-nonzero"],
    mutate: (w) => {
      const now = Date.now();
      // The discovery token itself resolves (DO discovery config), so the token PROBE verifies; the
      // per-surface reads are what errored (a scope gap on two surfaces).
      w.routes["/sources/discovery-config"] = { config: { engineAccountId: "acct-corpus-lab", token: "corpus-ro-discovery-token" } };
      (w.routes["/downpipes"] as Dict[]).push({
        config: { id: "dp2", name: "cf-config", enabled: true, cadenceSeconds: 86400, source: { type: "cf-config", accountId: "acct-corpus-lab", include: [], exclude: [] } },
        lastRunId: "01CFGOK",
        inFlight: false,
        nextRunAt: now + 12 * HOUR,
        cronResolve: { class: "ok", at: now + 12 * HOUR },
        lastRestoreTestAt: now - 20 * HOUR,
        lastRestoreTestOk: true,
        cfConfigDiscovery: {
          at: now - 45 * MIN,
          present: ["dns_records", "zone_settings", "rulesets", "firewall_rules"],
          empty: ["page_rules"],
          gated: [],
          unavailable: ["logpush_jobs", "access_policies"],
        },
      });
      const by = (w.routes["/history"] as Dict).byDownpipe as Record<string, Dict[]>;
      by["dp2"] = [
        { runId: "01CFGOK", index: 5, startedAt: iso(now - 50 * MIN), status: "ok", recordCount: 180, bytes: 250_000, durationMs: 2000, recordsSkipped: 0, recordsIncomplete: 0, destinationId: "d-primary", sealVerification: { status: "verified", tier: "sampled-decrypt", sampled: 8, at: now - 49 * MIN } },
      ];
      const repl = (w.routes["/replication"] as Dict).byDownpipe as Record<string, Dict>;
      repl["dp2"] = { "d-primary": { holdsRunId: "01CFGOK", holdsIndex: 5, lastOk: true, lastAttemptAt: now - 49 * MIN } };
    },
    capture: (b) => [
      ...expectInBundle(b, '"unavailableCount":2', "the true unavailable-surface count"),
      ...expectInBundle(b, "logpush_jobs", "the excluded surface's fixed product id"),
    ],
  },
];
