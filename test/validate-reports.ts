// Prove reporting (contract section 6): the four ReportKind generators (restore-tests, sla-compliance,
// immutability, posture), the canonical signing (hybrid Ed25519 + ML-DSA, verifiable, tamper-evident),
// the dependency-free PDF renderer, and the DO data routes. In-memory doubles only; no network, no
// deploy, no cost. Run:
//   node test/validate-reports.ts
//
// Coverage:
//  buildRestoreTestsReport: per-downpipe recency + drill-evidence-in-period; entries outside the period
//    are excluded; recency carries lastRestoreTestAt/Ok presence-safe; evidence is newest-first.
//  buildSlaComplianceReport: per-downpipe expected (from cadence + period), successful, strikes, fresh;
//    a downpipe's window clamped forward to its createdAt (or, absent that, its earliest recorded run),
//    never the bare report period, so a young downpipe's expected count reflects its own lifetime.
//  buildImmutabilityReport: the precise attestation (post-quantum hybrid, tamper-evident; never WORM/
//    quantum-proof), per-destination property, break-glass/operational posture.
//  signReport: the signature is "edmldsa1:<b64url>" over canonicalJSON({kind,generatedAt,period,data})
//    and VERIFIES under the signer; a tampered body fails verification.
//  renderReportPDF: a valid PDF (header + %%EOF), deterministic (same report -> identical bytes),
//    non-empty, and free of an unescaped ")" stream break; renders for every kind.
//  DO routes: POST /reports/restore-tests-data and /reports/sla-data return the structured bodies from
//    DO state (run-history ring -> successful/strikes; drill-evidence -> evidence; recency).

import {
  buildRestoreTestsReport,
  buildSlaComplianceReport,
  buildImmutabilityReport,
  buildPostureReport,
  buildEvidencePackReport,
  makeReport,
  signReport,
  isReportKind,
  type Report,
  type RestoreTestsData,
  type SlaComplianceData,
  type ImmutabilityData,
} from "../src/admin/reports.ts";
import { renderReportPDF } from "../src/pdf.ts";
import { escapePdfText } from "../src/pdf-primitives.ts";
import { blocksToElements, paginateContent, type Block } from "../src/pdf-layout.ts";
import { getFramework, FRAMEWORKS } from "../src/admin/frameworks.ts";
import { computePosture, type PostureInput } from "../src/admin/posture.ts";
import { SchedulerDO, type DownpipeState } from "../src/sched/scheduler-do.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { hybridVerify } from "../src/crypto/sign.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { b64urlEncode, b64urlDecode } from "../src/crypto/bytes.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
// The in-memory DO storage double is shared across the DO validators.
import { MockStorage } from "./mock-storage.ts";
import type { DrillEvidenceEntry } from "../src/sched/scheduler-do.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const OWNER_HEADER = encodeCaller(OWNER_CALLER);

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-06-09T00:00:00.000Z");
const NOW_SEC = Math.floor(NOW / 1000);

// makeState builds a DownpipeState for the pure generators (only the fields they read need be present).
function makeState(id: string, name: string, overrides: Partial<DownpipeState["config"]> & { lastRestoreTestAt?: number; lastRestoreTestOk?: boolean } = {}): DownpipeState {
  const { lastRestoreTestAt, lastRestoreTestOk, ...cfg } = overrides;
  return {
    config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] }, ...cfg },
    nextRunAt: NOW,
    lastRunId: null,
    inFlight: false,
    ...(lastRestoreTestAt !== undefined ? { lastRestoreTestAt } : {}),
    ...(lastRestoreTestOk !== undefined ? { lastRestoreTestOk } : {}),
  };
}

// ---- buildRestoreTestsReport --------------------------------------------------------------
function testRestoreTestsReport(): void {
  {
    const downpipes: DownpipeState[] = [
      makeState("dp1", "Primary", { lastRestoreTestAt: NOW - 2 * DAY, lastRestoreTestOk: true }),
      makeState("dp2", "Secondary"), // never tested
    ];
    const evidence: DrillEvidenceEntry[] = [
      { runId: "r-old", kind: "in-account", recordedBy: null, recordedAt: new Date(NOW - 200 * DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), note: "old" },
      { runId: "r-new", kind: "in-account", recordedBy: "o@example.au", recordedAt: new Date(NOW - 3 * DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), note: "scheduled restore test passed" },
    ];
    const period = { fromSeconds: NOW_SEC - 90 * 24 * 60 * 60, toSeconds: NOW_SEC };
    const data: RestoreTestsData = buildRestoreTestsReport(downpipes, evidence, period);
    ok("restore-tests: recency has both downpipes", data.recency.length === 2);
    ok("restore-tests: recency carries lastRestoreTestAt/Ok for the tested one", data.recency.find((r) => r.id === "dp1")?.lastRestoreTestOk === true);
    ok("restore-tests: recency omits the never-tested fields (presence-safe)", !("lastRestoreTestAt" in (data.recency.find((r) => r.id === "dp2") ?? {})));
    ok("restore-tests: only the in-period evidence is included (the 200d-old one is excluded)", data.evidence.length === 1 && data.evidence[0]?.runId === "r-new");
    // With a null period, all evidence is included, newest-first.
    const all = buildRestoreTestsReport(downpipes, evidence, null);
    ok("restore-tests: null period includes all evidence", all.evidence.length === 2);
    ok("restore-tests: evidence is newest-first", all.evidence[0]?.runId === "r-new" && all.evidence[1]?.runId === "r-old");
  }
  {
    // COMPLIANCE-STAMP: the durable keyed attested-verification stamp (restoreProven) + the recency
    // completion's own provenance (lastRestoreTestKind/SampleRate/Deferred) project onto the recency row
    // DIRECTLY from the DownpipeState (no gather change needed -- this generator already receives the full
    // DownpipeState[]), so the report plainly separates a KEYED attended proof from an ordinary pass.
    const proven: DownpipeState = {
      ...makeState("dp3", "Attended", { lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: false }),
      lastRestoreTestKind: "attended",
      lastRestoreTestSampleRate: 100,
      lastRestoreTestDeferred: "posture",
      restoreProven: { at: NOW - 5 * DAY, by: "o@example.au", method: "attended-blind-test", runId: "run-dp3" },
    };
    const data = buildRestoreTestsReport([proven], [], null);
    const row = data.recency.find((r) => r.id === "dp3");
    ok(
      "restore-tests: restoreProvenAt/By/Method project from the state",
      row?.restoreProvenAt === NOW - 5 * DAY && row?.restoreProvenBy === "o@example.au" && row?.restoreProvenMethod === "attended-blind-test",
    );
    ok(
      "restore-tests: lastRestoreTestKind/SampleRate/Deferred project from the state",
      row?.lastRestoreTestKind === "attended" && row?.lastRestoreTestSampleRate === 100 && row?.lastRestoreTestDeferred === "posture",
    );
    // An unproven, ordinary-scheduled-pass downpipe HONESTLY omits every proof field (presence-safe, never
    // a fabricated null/0) -- the anti-masquerade invariant at the report-generator level: an unkeyed
    // scheduled pass must never carry restoreProvenMethod.
    const bare = buildRestoreTestsReport([makeState("dp4", "Bare", { lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: true })], [], null);
    const bareRow = bare.recency.find((r) => r.id === "dp4");
    ok(
      "restore-tests: an unkeyed scheduled pass carries none of the keyed-proof fields (never masquerades as attended)",
      !("restoreProvenAt" in (bareRow ?? {})) && !("restoreProvenMethod" in (bareRow ?? {})) && !("lastRestoreTestKind" in (bareRow ?? {})) && !("lastRestoreTestDeferred" in (bareRow ?? {})),
    );
  }
}

// ---- buildSlaComplianceReport -------------------------------------------------------------
function testSlaComplianceReport(): void {
  {
    const downpipes: DownpipeState[] = [makeState("dp1", "Primary", { cadenceSeconds: 86400 })]; // daily
    // A 7-day period at a daily cadence -> 7 expected runs.
    const period = { fromSeconds: NOW_SEC - 7 * 24 * 60 * 60, toSeconds: NOW_SEC };
    const runStats = new Map([["dp1", { successfulRuns: 5, strikes: 1, lastSuccessAt: NOW - 12 * 60 * 60 * 1000 }]]);
    const data: SlaComplianceData = buildSlaComplianceReport(downpipes, runStats, period, NOW);
    const row = data.downpipes[0];
    ok("sla: expected runs derived from cadence + period (7 daily)", row?.expectedRuns === 7);
    ok("sla: successful runs from stats", row?.successfulRuns === 5);
    ok("sla: strikes from stats", row?.strikes === 1);
    ok("sla: fresh when last success within one cadence", row?.fresh === true);
    // A downpipe with no recent success is not fresh.
    const stale = buildSlaComplianceReport(downpipes, new Map([["dp1", { successfulRuns: 0, strikes: 3 }]]), period, NOW);
    ok("sla: not fresh with no recent success", stale.downpipes[0]?.fresh === false);
    // A null period yields expected 0 (cannot bound a window).
    const noPeriod = buildSlaComplianceReport(downpipes, runStats, null, NOW);
    ok("sla: null period -> expected 0", noPeriod.downpipes[0]?.expectedRuns === 0);

    // RTO companion: the SLA row surfaces the recovery-time estimate NEXT TO the freshness/RPO signal, but
    // ONLY when an estimate was derivable; honestly absent (no fabricated number) otherwise.
    ok("sla: with no RTO estimates the rto fields are absent (honest, never a fabricated 0)", !("rtoEstimateSeconds" in (row ?? {})) && !("rtoBasedOnDrills" in (row ?? {})));
    const withRto = buildSlaComplianceReport(downpipes, runStats, period, NOW, new Map([["dp1", { known: true, estimateSeconds: 42, basedOnDrills: 3 }]]));
    ok("sla: a KNOWN RTO estimate is surfaced on the row (next to fresh)", withRto.downpipes[0]?.rtoEstimateSeconds === 42 && withRto.downpipes[0]?.rtoBasedOnDrills === 3);
    const unknownRto = buildSlaComplianceReport(downpipes, runStats, period, NOW, new Map([["dp1", { known: false }]]));
    ok("sla: an UNKNOWN RTO estimate leaves the rto fields absent (no fabricated number)", !("rtoEstimateSeconds" in (unknownRto.downpipes[0] ?? {})));
  }
}

// ---- buildImmutabilityReport (precise claims) ---------------------------------------------
function testImmutabilityReport(): void {
  {
    const data: ImmutabilityData = buildImmutabilityReport({
      destConfigured: true,
      destKind: "r2",
      breakGlassConfigured: true,
      operationalConfigured: { public: true, private: false },
    });
    ok("immutability: a configured destination is listed", data.destinations.length === 1 && data.destinations[0]?.kind === "r2" && data.destinations[0]?.configured === true);
    ok("immutability: states post-quantum hybrid (precise claim)", /post-quantum hybrid/.test(data.attestation));
    ok("immutability: states tamper-evident (precise claim)", /tamper-evident/.test(data.attestation));
    ok("immutability: never claims tamper-proof", !/tamper-proof/.test(data.attestation) && !/tamper-proof/.test(data.destinations[0]?.property ?? ""));
    ok("immutability: never claims quantum-proof", !/quantum-proof/.test(data.attestation));
    ok("immutability: break-glass posture stated", data.breakGlassConfigured === true && /break-glass recipient is configured/.test(data.attestation));
    ok("immutability: no-custody posture stated when no operational-private", data.operationalPrivatePresent === false && /strict no-custody posture is in force/.test(data.attestation));
    // The attestation is what a customer hands an auditor, so both branches are pinned on their CLAIMS.
    // The absent branch must state the assurance that remains, not only what is missing, or an auditor
    // reading it alone could reasonably conclude nothing is verified in this posture.
    ok("attestation: the strict posture states that runs are still verified at seal", /verified at seal/i.test(data.attestation));
    ok("attestation: the strict posture states the canary still runs", /canary still proves/i.test(data.attestation));
    ok("attestation: the strict posture does not claim recovery moves offline", !/offline[-\s]?only/i.test(data.attestation));
    // The retired framing named a key as enabling "self-test and self-restore", which is no longer true now
    // that verification at seal and the canary run on the run's own per-run key.
    ok("attestation: the retired self-test framing is gone", !/self-test and self-restore/i.test(data.attestation));
    // No destination -> a not-configured row + an honest "not possible" recovery line.
    const none = buildImmutabilityReport({ destConfigured: false, destKind: null, breakGlassConfigured: false, operationalConfigured: { public: false, private: false } });
    ok("immutability: no destination -> not-configured row", none.destinations[0]?.configured === false);
    ok("immutability: no break-glass -> offline recovery not possible", /offline recovery is not currently possible/.test(none.attestation));
  }
  testImmutabilityWormReadings();
  testImmutabilityRetentionAxis();
}

// ---- the four WORM readings, each stated as ITSELF in a SIGNED attestation -----------------
//
// The shared sentence "archives are tamper-evident but not write-once-locked" is true only of the
// invalid-policy reading. On a bucket that does not enforce Object-Lock there are no archives: R2 answers
// a lock-bearing PUT with 501 NotImplemented and AWS S3 with ObjectLockConfigurationNotFoundError, so the
// write is refused, not accepted and stripped. These cases pin each reading against the other two so the
// shared sentence cannot leak from the invalid-policy reading into the others.
function testImmutabilityWormReadings(): void {
  const dest = { destConfigured: true, destKind: "s3" as const, breakGlassConfigured: true, operationalConfigured: { public: false, private: true } };
  const propertyOf = (worm: Parameters<typeof buildImmutabilityReport>[1]): string => buildImmutabilityReport(dest, worm).destinations[0]?.property ?? "";
  const attestationOf = (worm: Parameters<typeof buildImmutabilityReport>[1]): string => buildImmutabilityReport(dest, worm).attestation;

  // ENFORCED: unchanged, the strong claim.
  const enforced = propertyOf({ configured: true, misconfigured: false, bucketEnforces: true, mode: "compliance", retentionDays: 365 });
  ok("worm/enforced: makes the store-enforced claim", /the bucket enforces S3 Object-Lock \(compliance mode, 365 days retention\)/.test(enforced));
  ok("worm/enforced: never says the destination cannot be written to", !/cannot be written to/.test(enforced));

  // NOT ENFORCED: the write is REFUSED. This is the reading the old sentence was false about.
  //
  // THE RULE THESE ASSERTIONS EXPRESS IS NOT LOCAL TO THIS SUITE. The same underlying fact (a not-enforcing
  // bucket refuses the write, and never silently accepts and strips the headers) is graded in ONE gate that
  // covers every surface at once, test/validate-worm-refusal-parity.ts, which also carries the live evidence
  // for it. These assertions stay, because they pin THIS builder's exact phrasing and a cross-surface rule
  // cannot do that. Read the parity gate before you change any wording here.
  const notEnforced = propertyOf({ configured: true, misconfigured: false, bucketEnforces: false, mode: "compliance", retentionDays: 365 });
  ok("worm/not-enforced: says the destination cannot be written to", /this destination cannot be written to/.test(notEnforced));
  ok("worm/not-enforced: says the store refuses the write", /refuses every write carrying the lock headers/.test(notEnforced));
  ok("worm/not-enforced: says no archive is stored there", /no archive is stored here/.test(notEnforced));
  ok("worm/not-enforced: carries the NOT-in-force note the reconciler requires", /store-enforced Object-Lock is NOT in force/.test(notEnforced));
  ok("worm/not-enforced: does NOT say archives are tamper-evident but not write-once-locked", !/archives are tamper-evident but not write-once-locked/.test(notEnforced));
  ok("worm/not-enforced: does NOT say the headers are ignored or discarded", !/ignored|discarded/.test(notEnforced));
  ok("worm/not-enforced: makes no store-enforced claim", !/the bucket enforces S3 Object-Lock/.test(notEnforced));
  ok("worm/not-enforced: the attestation says the store refuses every write", /refuses every write to it and that destination holds no archives/.test(attestationOf({ configured: true, misconfigured: false, bucketEnforces: false })));
  ok("worm/not-enforced: the attestation drops the retired tamper-evidence-only framing", !/immutability is tamper-evidence only until/.test(attestationOf({ configured: true, misconfigured: false, bucketEnforces: false })));

  // UNKNOWN and ABSENT are ONE reading, cannot-confirm, and it must not be written as either of the others.
  // Absent is the shape gatherWormSlice produces on any probe fault, and the old code read it as "the bucket
  // does not enforce Object-Lock (it was not created with it)", a positive finding from a probe that never ran.
  for (const [label, worm] of [
    ["explicit unknown", { configured: true, misconfigured: false, bucketEnforces: "unknown" as const }],
    ["absent verdict", { configured: true, misconfigured: false }],
  ] as const) {
    const p = propertyOf(worm);
    ok(`worm/${label}: says the engine could not read the bucket's enforcement`, /could not read whether the bucket enforces Object-Lock/.test(p));
    ok(`worm/${label}: never asserts the bucket does not enforce`, !/the bucket does not enforce Object-Lock/.test(p));
    ok(`worm/${label}: never asserts the destination cannot be written to`, !/cannot be written to/.test(p));
    ok(`worm/${label}: never asserts archives are not write-once-locked`, !/archives are tamper-evident but not write-once-locked/.test(p));
    ok(`worm/${label}: carries the NOT-in-force note the reconciler requires`, /store-enforced Object-Lock is NOT in force/.test(p));
    ok(`worm/${label}: the attestation asserts nothing either way`, /could not confirm whether the destination bucket enforces S3 Object-Lock/.test(attestationOf(worm)));
  }

  // INVALID POLICY: nothing is armed, so writes are unaffected and the old sentence is the RIGHT one here.
  const invalid = propertyOf({ configured: true, misconfigured: true });
  ok("worm/invalid: says no Object-Lock metadata is written", /no Object-Lock metadata is written/.test(invalid));
  ok("worm/invalid: says writes are unaffected", /Writes are unaffected/.test(invalid));
  ok("worm/invalid: keeps the tamper-evident-but-not-locked sentence, which is true here", /archives are tamper-evident but not write-once-locked/.test(invalid));
  ok("worm/invalid: never says the destination cannot be written to", !/cannot be written to/.test(invalid));

  // NOT CONFIGURED: the bare baseline, no note.
  const off = propertyOf({ configured: false, misconfigured: false });
  ok("worm/off: is the bare tamper-evidence baseline", /^tamper-evident: each archive is signed/.test(off) && !/NOT in force/.test(off));
  ok("worm/off: the attestation states WORM is opt-in and not configured", /WORM\/Object-Lock is not configured \(opt-in\)/.test(attestationOf({ configured: false, misconfigured: false })));
}

// ---- the RETENTION axis: a bucket with Object-Lock ENABLED retains nothing by itself --------
//
// The strongest sentence this report carries is "a compromised delete-credential cannot hard-delete an
// archive within its retention window", and it needs a retention WINDOW on the archive. Exactly two things
// put one there: the per-object retention header the engine writes under a VALID policy, and the bucket's
// own DEFAULT RETENTION RULE. That sentence must NOT be asserted on a lock-enabled bucket where neither
// applies.
//
// These are reachable configurations, not invented ones:
//   - misconfigured:true cannot come from a console-set policy. POST /destination validates the submitted
//     worm value and DROPS an invalid one before anything is stored (router-destinations.ts), and
//     fetchDestConfig drops any stored value that survives (factory.ts), which is why validate-worm.ts
//     records gatherWormSlice's re-validation else-arm as unreachable through the real path. It comes from
//     the deploy-time env knobs: DEST_WORM_MODE or DEST_WORM_RETENTION_DAYS set with the other missing,
//     empty, non-integer or non-positive (parseWormPolicy), on a default destination carrying no policy of
//     its own.
//   - the NOT-configured reading needs no misconfiguration at all. An Object-Lock-enabled bucket with no
//     WORM policy anywhere is the most reachable state of the four, and it took the strong claim too.
//
// The two ARMED cases below are CONTROLS and pass on both sides of the change: a valid policy writes the
// retention header itself, so the strong claim holds whether or not the bucket also has a default rule, and
// nothing here weakens it.
function testImmutabilityRetentionAxis(): void {
  const dest = { destConfigured: true, destKind: "s3" as const, breakGlassConfigured: true, operationalConfigured: { public: false, private: true } };
  const propertyOf = (worm: Parameters<typeof buildImmutabilityReport>[1]): string => buildImmutabilityReport(dest, worm).destinations[0]?.property ?? "";
  const attestationOf = (worm: Parameters<typeof buildImmutabilityReport>[1]): string => buildImmutabilityReport(dest, worm).attestation;
  // The strong claim in either of its two forms ("its retention window" from the engine's own header,
  // "that window" from the bucket's default rule). No non-retaining reading may carry either.
  const STRONG = /cannot hard-delete an archive within (its retention|that) window/;

  // CONTROL 1: enforced + a VALID policy + a bucket default rule. The strong claim stands, and it is stated
  // from the ENGINE's own policy (compliance/365), not the bucket's rule, exactly as before.
  const armedWithRule = { configured: true, misconfigured: false, mode: "compliance" as const, retentionDays: 365, bucketEnforces: true as const, defaultRetention: true, probeMode: "governance" as const, probeDays: 7 };
  ok("retention/armed+rule: the strong claim is unchanged and states the engine's own policy", /the bucket enforces S3 Object-Lock \(compliance mode, 365 days retention\); a compromised delete-credential cannot hard-delete an archive within its retention window/.test(propertyOf(armedWithRule)));
  ok("retention/armed+rule: the attestation keeps the unchanged enforced clause", /enforces S3 Object-Lock \(WORM\), so archives cannot be deleted or overwritten within their retention window/.test(attestationOf(armedWithRule)));

  // CONTROL 2: enforced + a VALID policy + NO bucket default rule. STILL the strong claim: the engine writes
  // the retention header on every archive, so the bucket's default rule is not what the claim rests on.
  const armedNoRule = { configured: true, misconfigured: false, mode: "governance" as const, retentionDays: 30, bucketEnforces: true as const, defaultRetention: false };
  ok("retention/armed, no rule: the valid policy still carries the strong claim", /the bucket enforces S3 Object-Lock \(governance mode, 30 days retention\); a compromised delete-credential cannot hard-delete an archive within its retention window/.test(propertyOf(armedNoRule)));
  ok("retention/armed, no rule: the attestation still carries the enforced clause", /enforces S3 Object-Lock \(WORM\), so archives cannot be deleted or overwritten within their retention window/.test(attestationOf(armedNoRule)));

  // INVALID POLICY on a lock-enabled bucket with NO default rule: nothing writes a retention window, so
  // nothing is protected, and the strong claim must not be made for this reading.
  const invalidNoRule = { configured: true, misconfigured: true, bucketEnforces: true as const, defaultRetention: false };
  const invalidNoRuleP = propertyOf(invalidNoRule);
  ok("retention/invalid, no rule: makes NO strong claim", !STRONG.test(invalidNoRuleP));
  ok("retention/invalid, no rule: says the lock is switched on but nothing is retained", /has S3 Object-Lock switched on/.test(invalidNoRuleP) && /no default retention rule/.test(invalidNoRuleP));
  ok("retention/invalid, no rule: names the invalid policy as why no header is written", /the engine writes no retention header of its own \(the configured WORM policy is invalid\)/.test(invalidNoRuleP));
  ok("retention/invalid, no rule: states the consequence for an archive written there", /carries no retention window and a compromised delete-credential can hard-delete it/.test(invalidNoRuleP));
  ok("retention/invalid, no rule: carries the NOT-in-force note the reconciler requires", /store-enforced Object-Lock is NOT in force/.test(invalidNoRuleP));
  ok("retention/invalid, no rule: does NOT borrow the not-enforced reading's refused-write wording", !/cannot be written to/.test(invalidNoRuleP) && !/refuses every write/.test(invalidNoRuleP));
  const invalidNoRuleA = attestationOf(invalidNoRule);
  ok("retention/invalid, no rule: the attestation makes no strong claim", !/archives cannot be deleted or overwritten/.test(invalidNoRuleA));
  ok("retention/invalid, no rule: the attestation says nothing applies a retention window", /nothing applies a retention window to the archives written to it/.test(invalidNoRuleA) && /they are not write-once-locked/.test(invalidNoRuleA));

  // INVALID POLICY on a lock-enabled bucket that DOES carry a default rule: the archives really are
  // retained, by the bucket's rule and not by anything the engine wrote, and the report says which.
  const invalidWithRule = { configured: true, misconfigured: true, bucketEnforces: true as const, defaultRetention: true, probeMode: "compliance" as const, probeDays: 30 };
  const invalidWithRuleP = propertyOf(invalidWithRule);
  ok("retention/invalid + rule: keeps a strong claim, attributed to the bucket's own default rule", /applies its own default retention rule \(compliance mode, 30 days retention\) to every object written to it, so a compromised delete-credential cannot hard-delete an archive within that window/.test(invalidWithRuleP));
  ok("retention/invalid + rule: says the engine writes no retention header of its own", /The engine writes no retention header of its own on this destination \(the configured WORM policy is invalid\), so the bucket's default rule is the whole of the protection/.test(invalidWithRuleP));
  ok("retention/invalid + rule: never states the invalid policy's window as the engine's", !/\(object-lock\)/.test(invalidWithRuleP));
  ok("retention/invalid + rule: the attestation attributes the window to the bucket's default rule", /applies its own default retention rule, so archives cannot be deleted or overwritten within that window; the engine writes no retention header of its own here \(the configured WORM policy is invalid\)/.test(attestationOf(invalidWithRule)));

  // INVALID POLICY on a lock-enabled bucket whose default rule could NOT be read. Cannot-confirm on the
  // retention axis is its own state, exactly as it is on the enforcement axis: assert neither.
  const invalidUnknownRule = { configured: true, misconfigured: true, bucketEnforces: true as const };
  const invalidUnknownRuleP = propertyOf(invalidUnknownRule);
  ok("retention/invalid, rule unread: makes NO strong claim", !STRONG.test(invalidUnknownRuleP));
  ok("retention/invalid, rule unread: says the rule could not be read", /could not read whether the bucket applies a default retention rule/.test(invalidUnknownRuleP));
  ok("retention/invalid, rule unread: asserts neither locked nor unlocked", /states neither that archives are write-once-locked nor that they are not/.test(invalidUnknownRuleP));
  ok("retention/invalid, rule unread: never asserts the bucket carries no default rule", !/carries no default retention rule/.test(invalidUnknownRuleP));
  ok("retention/invalid, rule unread: the attestation asserts nothing either way", /could not read whether the bucket applies a default retention rule, so store-enforced immutability is not asserted here either way/.test(attestationOf(invalidUnknownRule)));

  // NO POLICY AT ALL on a lock-enabled bucket with no default rule. The most reachable state of the four,
  // and it took the strong claim without a single thing being misconfigured.
  const offNoRule = { configured: false, misconfigured: false, bucketEnforces: true as const, defaultRetention: false };
  const offNoRuleP = propertyOf(offNoRule);
  ok("retention/no policy, no rule: makes NO strong claim", !STRONG.test(offNoRuleP));
  ok("retention/no policy, no rule: names the absent policy as why no header is written", /the engine writes no retention header of its own \(no WORM policy is configured\)/.test(offNoRuleP));
  ok("retention/no policy, no rule: says Object-Lock enabled does not retain anything by itself", /Object-Lock enabled on a bucket does not retain anything by itself/.test(offNoRuleP));
  ok("retention/no policy, no rule: the attestation makes no strong claim", !/archives cannot be deleted or overwritten/.test(attestationOf(offNoRule)));
  ok("retention/no policy, no rule: the attestation names the absent policy", /\(no WORM policy is configured, and the bucket carries no default retention rule\)/.test(attestationOf(offNoRule)));

  // NO POLICY on a lock-enabled bucket that DOES carry a default rule: the bucket protects the archives on
  // its own, which is real and is credited, with the source named.
  const offWithRule = { configured: false, misconfigured: false, bucketEnforces: true as const, defaultRetention: true, probeMode: "governance" as const, probeDays: 14 };
  ok("retention/no policy + rule: credits the bucket's own default rule", /applies its own default retention rule \(governance mode, 14 days retention\) to every object written to it, so a compromised delete-credential cannot hard-delete an archive within that window/.test(propertyOf(offWithRule)));
  ok("retention/no policy + rule: names the absent policy rather than implying the engine set the window", /The engine writes no retention header of its own on this destination \(no WORM policy is configured\)/.test(propertyOf(offWithRule)));
  ok("retention/no policy + rule: the attestation credits the bucket rule and not a policy", /applies its own default retention rule, so archives cannot be deleted or overwritten within that window; the engine writes no retention header of its own here \(no WORM policy is configured\)/.test(attestationOf(offWithRule)));

  // THE THREE-WAY ENFORCEMENT DISTINCTION IS UNTOUCHED, and the retention axis never leaks into it. These
  // are controls, here so the fourth axis cannot be used to soften the refusal or the cannot-confirm reading.
  const notEnforcedStill = propertyOf({ configured: true, misconfigured: false, mode: "compliance", retentionDays: 365, bucketEnforces: false });
  ok("retention/control: a NOT-enforcing bucket keeps the refused-write wording", /this destination cannot be written to/.test(notEnforcedStill) && /refuses every write carrying the lock headers/.test(notEnforcedStill));
  ok("retention/control: a NOT-enforcing bucket says nothing about a default retention rule", !/default retention rule/.test(notEnforcedStill));
  const unknownStill = propertyOf({ configured: true, misconfigured: false, bucketEnforces: "unknown" });
  ok("retention/control: a cannot-confirm bucket keeps its own wording", /could not read whether the bucket enforces Object-Lock/.test(unknownStill));
  ok("retention/control: a cannot-confirm bucket says nothing about a default retention rule", !/default retention rule/.test(unknownStill));
  // A defaultRetention value on a bucket that does not read as enforcing changes nothing: the enforcement
  // axis is decided first, so the fourth axis can never manufacture a claim on an unenforced bucket.
  ok("retention/control: defaultRetention is inert when the bucket does not enforce", propertyOf({ configured: true, misconfigured: false, mode: "compliance", retentionDays: 365, bucketEnforces: false, defaultRetention: true }) === notEnforcedStill);
  ok("retention/control: the bare not-configured baseline is unchanged", propertyOf({ configured: false, misconfigured: false }) === "tamper-evident: each archive is signed with a post-quantum hybrid signature and chained in a signed RUNLOG (anti-rollback)");
}

// ---- signing round-trip -------------------------------------------------------------------
async function testSignReport(): Promise<void> {
  {
    const signer = await loadSigner(b64urlEncode(rand(64)));
    const verifier = verifierFrom(signer);
    const data: ImmutabilityData = buildImmutabilityReport({ destConfigured: true, destKind: "s3", breakGlassConfigured: true, operationalConfigured: { public: false, private: true } });
    const unsigned: Report = makeReport("immutability", data, null, NOW);
    ok("sign: an unsigned report has no signature", unsigned.signature === undefined);
    const signed = await signReport(unsigned, signer);
    ok("sign: a signed report carries an edmldsa1: signature", typeof signed.signature === "string" && signed.signature.startsWith("edmldsa1:"));
    // Verify: the signature is over canonicalJSON({kind,generatedAt,period,data}).
    const signedView = { kind: signed.kind, generatedAt: signed.generatedAt, period: signed.period, data: signed.data };
    const sigBytes = b64urlDecode((signed.signature ?? "").slice("edmldsa1:".length));
    const verified = await hybridVerify(verifier, canonicalJSON(signedView), sigBytes);
    ok("sign: the signature verifies under the signer (tamper-evident)", verified === true);
    // Tamper the body: verification must fail.
    const tampered = { ...signedView, data: { ...(signed.data as Record<string, unknown>), attestation: "tampered" } };
    const tamperedVerified = await hybridVerify(verifier, canonicalJSON(tampered), sigBytes);
    ok("sign: a tampered body fails verification", tamperedVerified === false);
    // generatedAt is RFC-3339 millis.
    ok("sign: generatedAt is RFC-3339 millis", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(signed.generatedAt));
  }
}

// ---- renderReportPDF: structural validity + determinism -----------------------------------
async function testRenderReportPDF(): Promise<void> {
  {
    const posture = computePosture(postureSample(), NOW);
    const report: Report = makeReport("posture", buildPostureReport(posture), null, NOW);
    const pdf1 = renderReportPDF(report);
    const pdf2 = renderReportPDF(report);
    const td = new TextDecoder("latin1");
    const text1 = td.decode(pdf1);
    ok("pdf: non-empty", pdf1.length > 200);
    ok("pdf: starts with the PDF header", text1.startsWith("%PDF-1.4"));
    ok("pdf: ends with %%EOF", text1.trimEnd().endsWith("%%EOF"));
    ok("pdf: has an xref table", text1.includes("\nxref\n"));
    ok("pdf: has a trailer with /Root", /trailer\s*<<[^>]*\/Root 1 0 R/.test(text1));
    ok("pdf: deterministic (same report -> identical bytes)", b64urlEncode(pdf1) === b64urlEncode(pdf2));
    // Byte-for-byte determinism, checked directly on the buffers (length + every byte), not via an
    // encoding round-trip: the same Report must produce identical bytes (no Date.now/random).
    ok(
      "pdf: byte-for-byte determinism across two renders",
      pdf1.length === pdf2.length && pdf1.every((b, i) => b === pdf2[i]),
    );
    ok("pdf: renders the report title", text1.includes("Security posture"));
    ok("pdf: renders the posture score", text1.includes("Posture score"));

    // ---- escapePdfText: upper Latin-1 emits a single WinAnsi byte via octal escape, not raw UTF-8 ---
    // "Ångström" has U+00C5 (Å) and U+00F6 (ö) which TextEncoder would split into two UTF-8 bytes if
    // emitted directly. They must instead appear as octal escapes (\305 for 0xC5, \366 for 0xF6).
    {
      const escaped = escapePdfText("Ångström");
      ok("escapePdfText: U+00C5 -> octal \\305", escaped.includes("\\305"));
      ok("escapePdfText: U+00F6 -> octal \\366", escaped.includes("\\366"));
      // No raw two-byte UTF-8 lead byte (0xC3) leaks into the output.
      ok("escapePdfText: no raw UTF-8 lead byte for upper Latin-1", !escaped.includes("Ã"));
      // ASCII passes through untouched.
      ok("escapePdfText: ASCII passes through", escapePdfText("Acme Pty Ltd") === "Acme Pty Ltd");
    }

    // ---- enterprise redesign: colour, the bold font, and vector graphics ----------------------
    // A colour operator (`rg` text-fill, set before each text run) must be present; the old renderer
    // emitted only black text Tj with no colour op at all.
    ok("pdf: emits a colour text operator (rg)", / rg /.test(text1) || /\brg\b/.test(text1));
    // A stroke-colour operator (`RG`) accompanies the rules/hairlines (accent rule, cell rules, frame).
    ok("pdf: emits a stroke-colour operator (RG)", /\bRG\b/.test(text1));
    // The accent-tinted table header / cover panel are filled rectangles (`re ... f`).
    ok("pdf: emits a filled rectangle (re ... f)", /\bre f\b/.test(text1) || /re\nf/.test(text1));
    // Rules/hairlines are stroked paths (`m ... l S`).
    ok("pdf: emits a stroked rule (m ... l S)", /\bm\b.*\bl\b.*\bS\b/.test(text1) || / S\b/.test(text1));
    // The second base font, Helvetica-Bold, is a real font object AND is referenced (/F2) for headings,
    // table headers and the wordmark. (Standard-14 base font; still no embedded font file.)
    ok("pdf: declares the Helvetica-Bold font object", text1.includes("/BaseFont /Helvetica-Bold"));
    ok("pdf: references the bold font alias /F2", text1.includes("/F2"));
    ok("pdf: every page lists both fonts in its resources", /\/Font << \/F1 3 0 R \/F2 4 0 R >>/.test(text1));
    // The branded cover carries the wordmark and the no-custody footer line.
    ok("pdf: cover carries the downpipes wordmark", text1.includes("downpipes"));
    ok(
      "pdf: cover carries the no-custody footer line",
      text1.includes("Generated in your own account"),
    );
    // The running footer paginates with a "Page N of M" count (computed after pagination).
    ok("pdf: content pages carry a Page N of M footer", /Page 2 of \d+/.test(text1));
    // The cover shows the report's own generatedAt (NOT a wall clock); the fixed NOW must appear verbatim.
    ok("pdf: cover shows the report's generatedAt", text1.includes(report.generatedAt));
    // The signature line states the precise claim when signed.
    const signer = await loadSigner(b64urlEncode(rand(64)));
    const signed = await signReport(report, signer);
    const signedText = td.decode(renderReportPDF(signed));
    ok("pdf: a signed report's PDF states tamper-evident, signed", signedText.includes("tamper-evident, signed"));

    // Every kind renders a valid PDF without throwing.
    const kinds: Array<[Report["kind"], unknown]> = [
      ["restore-tests", { recency: [{ id: "dp1", name: "Primary )with a paren(", lastRestoreTestAt: NOW, lastRestoreTestOk: true }], evidence: [{ runId: "r1", kind: "in-account", recordedAt: "2026-06-01T00:00:00.000Z", recordedBy: null, note: "ok" }] }],
      ["sla-compliance", { downpipes: [{ id: "dp1", name: "Primary", expectedRuns: 7, successfulRuns: 6, strikes: 0, fresh: true }] }],
      ["immutability", buildImmutabilityReport({ destConfigured: true, destKind: "r2", breakGlassConfigured: true, operationalConfigured: { public: true, private: false } })],
      ["posture", buildPostureReport(posture)],
    ];
    for (const [kind, data] of kinds) {
      const r = makeReport(kind, data, kind === "posture" || kind === "immutability" ? null : { fromSeconds: NOW_SEC - 100, toSeconds: NOW_SEC }, NOW);
      const bytes = renderReportPDF(r);
      const t = td.decode(bytes);
      ok(`pdf: ${kind} renders a valid PDF`, t.startsWith("%PDF-1.4") && t.trimEnd().endsWith("%%EOF") && bytes.length > 200);
    }
    // A value with a literal ")" must be escaped so it does not break the content stream: the rendered
    // stream should contain the escaped "\)" sequence (from the "Primary )with a paren(" name above).
    const parenReport = makeReport("restore-tests", { recency: [{ id: "dp1", name: "Primary )with a paren(", lastRestoreTestAt: NOW, lastRestoreTestOk: true }], evidence: [] }, { fromSeconds: NOW_SEC - 100, toSeconds: NOW_SEC }, NOW);
    const parenText = td.decode(renderReportPDF(parenReport));
    ok("pdf: special characters in a value are escaped (\\) present)", parenText.includes("\\)") && parenText.includes("\\("));

    // A non-ASCII Latin-1 name (e.g. "Angstrom GmbH" spelt with U+00C5/U+00F6) must render end-to-end as a
    // valid PDF whose upper Latin-1 characters appear as WinAnsi octal escapes (\305 for 0xC5, \366 for
    // 0xF6), never as raw multi-byte UTF-8. This pins the encoding through the whole Report render path, not
    // just the escapePdfText primitive. The escaped name string sits in the rendered table cell verbatim.
    const nonAsciiReport = makeReport("restore-tests", { recency: [{ id: "dp1", name: "Ångström GmbH", lastRestoreTestAt: NOW, lastRestoreTestOk: true }], evidence: [] }, { fromSeconds: NOW_SEC - 100, toSeconds: NOW_SEC }, NOW);
    const nonAsciiBytes = renderReportPDF(nonAsciiReport);
    const nonAsciiText = td.decode(nonAsciiBytes);
    ok("pdf: a non-ASCII name renders a valid PDF", nonAsciiText.startsWith("%PDF-1.4") && nonAsciiText.trimEnd().endsWith("%%EOF") && nonAsciiBytes.length > 200);
    ok("pdf: a non-ASCII name is WinAnsi octal-escaped, not raw UTF-8", nonAsciiText.includes("(\\305ngstr\\366m GmbH)"));

    // ---- restore-tests "Proven" column (compliance-stamp): plainly separates a KEYED attended proof from
    // an ordinary scheduled pass, and a break-glass deferral renders distinctly from a genuine failure -----
    {
      const provenReport = makeReport(
        "restore-tests",
        {
          recency: [
            { id: "dp1", name: "Attended Co", lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: false, lastRestoreTestDeferred: "posture", restoreProvenAt: NOW - 5 * DAY, restoreProvenMethod: "attended-blind-test" },
            { id: "dp2", name: "Scheduled Co", lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: true },
            { id: "dp3", name: "Never Co" },
          ],
          evidence: [],
        },
        { fromSeconds: NOW_SEC - 100, toSeconds: NOW_SEC },
        NOW,
      );
      const provenText = td.decode(renderReportPDF(provenReport));
      ok("pdf: restore-tests renders the Proven column header", provenText.includes("Proven"));
      // The Proven cell has no parens, so its text is unescaped; the Outcome cell's "(offline posture)"
      // DOES contain parens, so it renders through escapePdfText as "\(offline posture\)" (PDF content
      // streams delimit literal strings with parens), the same convention the paren-name test above checks.
      ok("pdf: a keyed attended proof states 'attended verification, <date>' in the Proven column", provenText.includes(`attended verification, ${new Date(NOW - 5 * DAY).toISOString().slice(0, 10)}`));
      // None of the three rows above is a genuine failure (dp1 is a deferral, dp2 a pass, dp3 never-tested),
      // so the word "fail" must not appear at all: the deferral renders distinctly, never as bare "fail".
      ok(
        "pdf: a break-glass deferral renders distinctly, never as bare 'fail'",
        provenText.includes("deferred \\(offline posture\\)") && !provenText.includes("fail"),
      );
      // A genuine failure (no deferred flag) still renders "fail", never softened to "deferred".
      const failReport = makeReport(
        "restore-tests",
        { recency: [{ id: "dp5", name: "Failing Co", lastRestoreTestAt: NOW - 1 * DAY, lastRestoreTestOk: false }], evidence: [] },
        { fromSeconds: NOW_SEC - 100, toSeconds: NOW_SEC },
        NOW,
      );
      const failText = td.decode(renderReportPDF(failReport));
      ok("pdf: a genuine failure (no deferred flag) still renders 'fail', not softened", /\bfail\b/.test(failText) && !failText.includes("deferred (offline posture)"));
    }

    // ---- evidence-pack rendering (cover + body) ------------------------------------------------
    // A real single-framework pack: the cover names the framework (not the generic title), the body
    // renders the framework heading, the control table, the per-control live evidence cell, and the
    // sources line. The posture below carries a passing and a failing check so an evidence cell shows
    // the real "title: status" pair rather than the empty-check note.
    const evidencePosture = computePosture(postureSample(), NOW);
    const iso = getFramework("iso-27001");
    const isoPack = buildEvidencePackReport(iso ? [iso] : [], evidencePosture, "iso-27001");
    const isoReport = makeReport("evidence-pack", isoPack, null, NOW);
    const isoText = td.decode(renderReportPDF(isoReport));
    ok("pdf: an evidence-pack renders a valid PDF", isoText.startsWith("%PDF-1.4") && isoText.trimEnd().endsWith("%%EOF") && isoReport.kind === "evidence-pack");
    ok("pdf: a single-framework pack names the framework on the cover", isoText.includes("ISO/IEC 27001"));
    ok("pdf: an evidence-pack carries the single-framework cover descriptor", isoText.includes("downpipes compliance evidence pack") && !isoText.includes("all frameworks"));
    ok("pdf: an evidence-pack body renders the controls-mapped summary line", isoText.includes("Controls mapped:"));
    ok("pdf: an evidence-pack renders a live evidence cell for a bound check", isoText.includes(": pass") || isoText.includes(": fail"));
    ok("pdf: an evidence-pack renders the sources line for a framework", isoText.includes("Sources:"));

    // The all-frameworks pack: the cover keeps the generic title and the all-frameworks descriptor (the
    // multi-framework arm), and is larger than the single-framework pack.
    const allPack = buildEvidencePackReport(FRAMEWORKS, evidencePosture, "all");
    const allText = td.decode(renderReportPDF(makeReport("evidence-pack", allPack, null, NOW)));
    ok("pdf: an all-frameworks pack uses the generic cover title", allText.includes("Compliance evidence pack"));
    ok("pdf: an all-frameworks pack uses the all-frameworks cover descriptor", allText.includes("downpipes compliance evidence pack, all frameworks"));

    // A capability-only control (DORA Art. 28 has no bound checks) renders the honest no-check note in its
    // evidence cell rather than a blank, so the empty-checks arm of evidenceCell is exercised.
    const dora = getFramework("dora");
    const doraText = td.decode(renderReportPDF(makeReport("evidence-pack", buildEvidencePackReport(dora ? [dora] : [], evidencePosture, "dora"), null, NOW)));
    // The literal parens in the note are PDF-escaped in the stream, so match the unambiguous leading text.
    ok("pdf: a capability-only control reads the honest no-check note", doraText.includes("no automated check"));

    // A hand-built evidence-pack with sparse data drives the renderer's defensive arms: a non-number
    // postureScore falls back to 0, a pack missing its frameworkTitle falls back to the generic kind title
    // on the cover, a control whose check object omits title/id and status renders the empty-field
    // fallbacks in the evidence cell, and a pack with no sources omits the sources line. The renderer must
    // still produce a valid PDF over this malformed-but-typed body (the router can hand it any shape).
    const sparsePack = {
      generatedFor: "x",
      scope: "scope text",
      postureScore: "not-a-number",
      packs: [
        {
          frameworkDescription: "desc",
          summary: { controlsTotal: 1, checksPassing: 0, checksFailing: 0, checksAccepted: 0, checksTotal: 1 },
          controls: [{ control: "C-1", obligation: "ob", capability: "cap", checks: [{}] }],
          sources: [],
        },
      ],
    };
    const sparseText = td.decode(renderReportPDF(makeReport("evidence-pack", sparsePack, null, NOW)));
    ok("pdf: a sparse evidence-pack still renders a valid PDF", sparseText.startsWith("%PDF-1.4") && sparseText.trimEnd().endsWith("%%EOF"));
    ok("pdf: a pack with no frameworkTitle falls back to the generic cover title", sparseText.includes("Compliance evidence pack"));
    ok("pdf: a posture score of 0 is shown when postureScore is not a number", sparseText.includes("Posture score at generation: 0"));
    // The bound control still renders (the controls table was built over the empty-check row), and the
    // empty check object yields a bare "title: status" with both sides empty (rendered as a lone colon),
    // never a fabricated status word.
    ok("pdf: a sparse pack still renders the mapped control id", sparseText.includes("C-1"));
    ok("pdf: an empty check object yields an empty 'title: status' cell, no fabricated status", sparseText.includes("(:) Tj") && !/\b(pass|fail|not-evaluated)\b/.test(sparseText));

    // A wholly malformed evidence-pack body (packs not an array) drives the not-an-array fallback: the
    // body has no framework sections but the document is still valid.
    const noPacksText = td.decode(renderReportPDF(makeReport("evidence-pack", { postureScore: 0, scope: "s" }, null, NOW)));
    ok("pdf: an evidence-pack with no packs array still renders a valid PDF", noPacksText.startsWith("%PDF-1.4") && noPacksText.trimEnd().endsWith("%%EOF"));

    // A second sparse pack drives the per-pack defensive fallbacks across the framework body. The top-level
    // scope is absent (the scope paragraph falls back to empty). Pack A omits its summary and description and
    // gives non-array controls/sources, so every "summary.checks* ?? 0" count, the "summary ?? {}" guard and
    // the controls/sources not-an-array arms fire. Pack B carries a control and a source whose fields are all
    // absent, so the control row's "?? ''" fallbacks and the source label fallback fire while the
    // sources-present line still emits. The whole malformed body must still render a valid PDF.
    const bodyFallbackPack = {
      generatedFor: "x",
      packs: [
        { frameworkTitle: "FW A", controls: "not-an-array", sources: "not-an-array" },
        { frameworkTitle: "FW B", summary: { controlsTotal: 0 }, controls: [{}], sources: [{}] },
      ],
    };
    const bodyFallbackText = td.decode(renderReportPDF(makeReport("evidence-pack", bodyFallbackPack, null, NOW)));
    ok("pdf: a pack with no summary/description and non-array controls still renders a valid PDF", bodyFallbackText.startsWith("%PDF-1.4") && bodyFallbackText.trimEnd().endsWith("%%EOF"));
    ok("pdf: a pack with an absent summary reports zero counts in its summary line", bodyFallbackText.includes("Controls mapped: 0") && bodyFallbackText.includes("0 passing, 0 failing"));
    ok("pdf: both framework sections are rendered (heading per pack)", bodyFallbackText.includes("FW A") && bodyFallbackText.includes("FW B"));
    ok("pdf: a sources array of one fieldless source still emits the sources line", bodyFallbackText.includes("Sources:"));

    // ---- malformed bodies for the four non-evidence kinds: the defensive empty-state and field
    // fallbacks. Each renders a valid PDF and shows the honest empty-state row, never throwing. The data
    // is deliberately shaped wrong (fields absent or the wrong type) because the renderer reads `unknown`
    // and must degrade safely whatever the caller hands it.
    {
      // posture with no data at all: score falls back to 0 and the checks list is empty (not-an-array arm).
      const emptyPostureText = td.decode(renderReportPDF(makeReport("posture", {}, null, NOW)));
      ok("pdf: an empty posture body shows a zero score", emptyPostureText.includes("Posture score: 0 / 100"));
      // posture with a check row that omits every field: the row cells fall back to empty strings.
      const sparsePostureText = td.decode(renderReportPDF(makeReport("posture", { score: 50, checks: [{}] }, null, NOW)));
      ok("pdf: a posture check row with no fields still renders a valid PDF", sparsePostureText.startsWith("%PDF-1.4") && sparsePostureText.trimEnd().endsWith("%%EOF") && sparsePostureText.includes("Posture score: 50 / 100"));

      // restore-tests with no recency and no evidence: both tables show the honest "(no ...)" rows.
      // The "(no ...)" placeholders carry literal parens, PDF-escaped in the stream, so match the inner text.
      const emptyRtText = td.decode(renderReportPDF(makeReport("restore-tests", {}, null, NOW)));
      ok("pdf: an empty restore-tests body shows the no-downpipes row", emptyRtText.includes("no downpipes"));
      ok("pdf: an empty restore-tests body shows the no-evidence row", emptyRtText.includes("no evidence in period"));
      // restore-tests recency rows: one never-tested row (no name/id/lastRestoreTestAt -> id fallback,
      // "never", "-") and one failed row (lastRestoreTestAt present but lastRestoreTestOk not true -> "fail").
      const rtRowsText = td.decode(renderReportPDF(makeReport("restore-tests", { recency: [{}, { id: "dp9", lastRestoreTestAt: NOW, lastRestoreTestOk: false }], evidence: [{}] }, null, NOW)));
      ok("pdf: a never-tested recency row reads 'never'", rtRowsText.includes("never"));
      ok("pdf: a recency row that failed its last test reads 'fail'", rtRowsText.includes("fail"));

      // sla with no downpipes: the honest "(no downpipes)" row.
      const emptySlaText = td.decode(renderReportPDF(makeReport("sla-compliance", {}, null, NOW)));
      ok("pdf: an empty sla body shows the no-downpipes row", emptySlaText.includes("no downpipes"));
      // an sla row missing fields: counts fall back to 0/-, and fresh!==true renders "no".
      const slaRowText = td.decode(renderReportPDF(makeReport("sla-compliance", { downpipes: [{}] }, null, NOW)));
      ok("pdf: an sla row with no fields still renders a valid PDF", slaRowText.startsWith("%PDF-1.4") && slaRowText.trimEnd().endsWith("%%EOF"));

      // immutability with no destinations: the "(none configured)" row and the attestation fallback.
      const emptyImmText = td.decode(renderReportPDF(makeReport("immutability", {}, null, NOW)));
      ok("pdf: an empty immutability body shows the none-configured row", emptyImmText.includes("none configured"));
      // an immutability destination row with configured!==true renders "no"; missing kind/property fall back.
      const immRowText = td.decode(renderReportPDF(makeReport("immutability", { attestation: "att", destinations: [{}] }, null, NOW)));
      ok("pdf: an immutability destination row with no fields still renders a valid PDF", immRowText.startsWith("%PDF-1.4") && immRowText.trimEnd().endsWith("%%EOF"));
    }
  }
}

// ---- isReportKind -------------------------------------------------------------------------
function testReportKind(): void {
  {
    ok("kind: restore-tests is a kind", isReportKind("restore-tests"));
    ok("kind: posture is a kind", isReportKind("posture"));
    ok("kind: an unknown kind is rejected", !isReportKind("nope"));
  }
}

// ---- SLA compliance: a young downpipe's window is clamped to its own creation time ---------
// buildSlaComplianceReport must clamp expectedRuns to when the downpipe was actually created, not the
// report's DEFAULT 90-DAY WINDOW: unclamped, a downpipe a few hours old at hourly cadence, every run
// successful, would read expectedRuns:2160 against successfulRuns:3-4 -- a ~0.2% compliance figure -- shown
// signed and tamper-evident on the console's Reports screen to any Owner or auditor on day one of every
// install. This drives the sequence: create a downpipe, record three successful runs over three hours at
// hourly cadence, then ask for the SAME 90-day report GET /admin/reports/sla-compliance and the console
// serve. A regression reads expectedRuns as 2160 (90 days / 1 hour), not 3.
async function testYoungDownpipeSlaWindow(): Promise<void> {
  const { stub, storage } = makeScheduler();
  const nowMs = Date.now();
  const HOUR = 60 * 60 * 1000;
  const isoAt = (ms: number): string => new Date(ms).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");

  // First, prove the SCHEMA half of the fix on its own: creating a downpipe through the real addDownpipe
  // path (not a fixture) stamps createdAt to the actual creation time, which is the additive field the
  // fix adds to DownpipeState.
  await fetchDO(stub, "POST", "/downpipes", { id: "stamped1", name: "Stamped", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_stamped1", include: [], exclude: [] } }, OWNER_HEADER);
  const stampedState = await storage.get<DownpipeState>("dp:stamped1");
  ok(
    "sla young-downpipe: addDownpipe stamps createdAt on a genuine create",
    typeof stampedState?.createdAt === "number" && Math.abs((stampedState.createdAt as number) - nowMs) < 5000,
  );

  // THE REPRODUCTION: a downpipe created 3.5 hours ago at hourly cadence, with three successful runs
  // since (the rehearsal shape). createdAt is backdated directly on the stored state (the DO's
  // clock is real and cannot be backdated through the live route), the same convention testDORoutes below
  // uses to seed the run-history ring directly rather than run real ticks.
  const createdAt = nowMs - 3.5 * HOUR;
  await fetchDO(stub, "POST", "/downpipes", { id: "young1", name: "Young", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_young1", include: [], exclude: [] } }, OWNER_HEADER);
  const youngState = await storage.get<DownpipeState>("dp:young1");
  if (youngState !== undefined) {
    youngState.createdAt = createdAt;
    storage.rawPut("dp:young1", youngState);
  }
  const ring = [3, 2, 1].map((hoursAgo, i) => ({ runId: `y${i + 1}`, index: i + 1, startedAt: isoAt(nowMs - hoursAgo * HOUR), status: "ok" as const }));
  storage.rawPut("hist:young1", ring);

  const nowSec = Math.floor(nowMs / 1000);
  const period = { fromSeconds: nowSec - 90 * 24 * 60 * 60, toSeconds: nowSec }; // the report's own 90-day default
  const resp = await fetchDO(stub, "POST", "/reports/sla-data", { period });
  ok("sla young-downpipe: sla-data 200", resp.status === 200);
  const sla = (await resp.json()) as SlaComplianceData;
  const row = sla.downpipes.find((d) => d.id === "young1");
  // THE DEFECT, unfixed: expectedRuns = floor(90 days / 1 hour) = 2160, not 3.
  ok("sla young-downpipe: expected clamped to the downpipe's own 3.5h lifetime, not the report's 90-day period (3, not 2160)", row?.expectedRuns === 3);
  ok("sla young-downpipe: all three runs count as successful", row?.successfulRuns === 3);
  ok(
    "sla young-downpipe: the row carries the effective window, clamped forward to createdAt",
    row?.windowFromSeconds === Math.floor(createdAt / 1000) && row?.windowToSeconds === period.toSeconds,
  );
  ok("sla young-downpipe: the row states WHY it clamped (createdAt), not a bare 'period'", row?.windowStartBasis === "createdAt");

  // THE LEGACY FALLBACK: a downpipe whose stored record predates createdAt (persisted before this fix
  // shipped) has no createdAt at all. Its window still clamps, using the earliest run its history ring
  // still holds instead -- a later, more conservative start than the true creation time, never an
  // earlier one -- rather than falling through to the bare, unclamped 90-day period.
  await fetchDO(stub, "POST", "/downpipes", { id: "legacy1", name: "Legacy", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_legacy1", include: [], exclude: [] } }, OWNER_HEADER);
  const legacyState = await storage.get<DownpipeState>("dp:legacy1");
  if (legacyState !== undefined) {
    delete (legacyState as { createdAt?: number }).createdAt;
    storage.rawPut("dp:legacy1", legacyState);
  }
  const legacyRing = [2, 1].map((hoursAgo, i) => ({ runId: `l${i + 1}`, index: i + 1, startedAt: isoAt(nowMs - hoursAgo * HOUR), status: "ok" as const }));
  storage.rawPut("hist:legacy1", legacyRing);
  const legacyResp = await fetchDO(stub, "POST", "/reports/sla-data", { period });
  const legacySla = (await legacyResp.json()) as SlaComplianceData;
  const legacyRow = legacySla.downpipes.find((d) => d.id === "legacy1");
  ok("sla legacy-downpipe (no createdAt): expected clamped to the earliest run its ring still holds (2, not 2160)", legacyRow?.expectedRuns === 2);
  ok("sla legacy-downpipe (no createdAt): the row states the earliest-run basis, not createdAt", legacyRow?.windowStartBasis === "earliest-run");
}

// ---- DO data routes -----------------------------------------------------------------------
async function testDORoutes(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    // Two downpipes; seed a run-history ring for dp1 with two ok + one failed (newest last), and a
    // drill-evidence entry. The SLA route derives successful/strikes from the ring; restore-tests reads
    // the recency + the evidence.
    await fetchDO(stub, "POST", "/downpipes", { id: "dp1", name: "Primary", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] } }, OWNER_HEADER);
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp1", ok: true, at: NOW - 2 * DAY });
    // Seed the run-history ring directly (the ring is internal; we write it via the storage double under
    // hist:<id>, the exact key the DO uses, so the report data route reads it as the DO would).
    const ring = [
      { runId: "r1", index: 1, startedAt: new Date(NOW - 3 * DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), status: "ok" },
      { runId: "r2", index: 2, startedAt: new Date(NOW - 2 * DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), status: "ok" },
      { runId: "r3", index: 3, startedAt: new Date(NOW - 1 * DAY).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), status: "failed" },
    ];
    storage.rawPut("hist:dp1", ring);

    // TWO CLOCKS ARE IN PLAY HERE AND EACH BOUND BELONGS TO A DIFFERENT ONE. The DO stamps drill-evidence
    // recordedAt with its real clock (Date.now()), so the period's UPPER bound must be the real now, not
    // the fixed test NOW, for the just-recorded entry to fall in window.
    //
    // The LOWER bound must be taken off the SAME clock as the runs it is meant to contain (the fixed test
    // clock the three seeded runs are stamped against at NOW-3/2/1 days), never off the real wall clock,
    // or the floor would drift away from the runs it is supposed to bound.
    //
    // The ceiling carries an HOUR OF HEADROOM: a bare `Math.floor(Date.now() / 1000)` is level with the real
    // clock and rounds DOWN, while the entry it has to admit is stamped by the DO some milliseconds LATER,
    // so a second-boundary crossing in that gap would put recordedAt at realNowSec + 1 and fail the
    // inclusive `sec <= toSeconds` comparison in withinPeriod (reports.ts). The runs above are all months in
    // the past, so nothing else is bounded above and the headroom costs nothing.
    const realNowSec = Math.floor(Date.now() / 1000);
    const period = { fromSeconds: NOW_SEC - 90 * 24 * 60 * 60, toSeconds: realNowSec + 3600 };
    const slaResp = await fetchDO(stub, "POST", "/reports/sla-data", { period });
    ok("DO: sla-data 200", slaResp.status === 200);
    const sla = (await slaResp.json()) as SlaComplianceData;
    const row = sla.downpipes.find((d) => d.id === "dp1");
    ok("DO: sla successful counts the two ok runs in period", row?.successfulRuns === 2);
    ok("DO: sla strikes counts the trailing failed run (1)", row?.strikes === 1);

    // Record a drill-evidence entry via the DO route, then read it back through the report data route.
    await fetchDO(stub, "POST", "/drill-evidence", { runId: "dp1", kind: "in-account", note: "scheduled restore test passed" }, OWNER_HEADER);
    const rtResp = await fetchDO(stub, "POST", "/reports/restore-tests-data", { period });
    ok("DO: restore-tests-data 200", rtResp.status === 200);
    const rt = (await rtResp.json()) as RestoreTestsData;
    ok("DO: restore-tests recency includes dp1 with the recorded outcome", rt.recency.find((r) => r.id === "dp1")?.lastRestoreTestOk === true);
    ok("DO: restore-tests evidence includes the recorded entry", rt.evidence.some((e) => e.note === "scheduled restore test passed"));
  }
}

async function main(): Promise<void> {
  testRestoreTestsReport();
  testSlaComplianceReport();
  testImmutabilityReport();
  await testSignReport();
  await testRenderReportPDF();
  testTableHeaderNeverOrphaned();
  testReportKind();
  await testDORoutes();
  await testYoungDownpipeSlaWindow();

  console.log(failures === 0 ? "\nREPORTS VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}


// A table header must never be the last thing on a page: a header sitting alone above dead space at the
// foot of one page and repeated at the top of the next means the reader meets it twice and the first copy
// holds no data. This is a table header BAND rather than a text heading, so the invariant belongs at the
// paginator itself, which is where it actually lives.
//
// The sweep varies the amount of filler above the table so the header lands at a different offset each
// time, INCLUDING astride a page boundary. A fixed fixture would prove nothing the day the page height
// or the leading changes.
function testTableHeaderNeverOrphaned(): void {
  const HDR = "ZZHDRCOL";
  const ROW = "ZZROWCELL";
  let orphaned = 0;
  let multiPage = 0;
  let headerPastFirstPage = 0;
  for (let filler = 0; filler <= 45; filler++) {
    const blocks: Block[] = [];
    for (let i = 0; i < filler; i++) blocks.push({ kind: "para", text: `filler line ${i} kept short so one line is one row of height` });
    blocks.push({
      kind: "table",
      table: {
        headers: [HDR, `${HDR}-b`, `${HDR}-c`],
        rows: [
          [`${ROW}-1`, "body one", "value one"],
          [`${ROW}-2`, "body two", "value two"],
          [`${ROW}-3`, "body three", "value three"],
        ],
        colWidths: [100, 200, 168],
      },
    });
    const pages = paginateContent(blocksToElements(blocks));
    if (pages.length > 1) multiPage++;
    for (let pi = 0; pi < pages.length; pi++) {
      const page = pages[pi] ?? "";
      if (!page.includes(HDR)) continue;
      if (pi > 0) headerPastFirstPage++;
      // The invariant: a page showing the header must also show at least one body row of that table.
      if (!page.includes(ROW)) orphaned++;
    }
  }
  // POSITIVE CONTROL: the sweep must actually reach the case it is about. Without these two, every
  // assertion above would hold over a sweep that never paginated at all.
  ok("pdf: the orphan sweep actually paginated (control, else it proves nothing)", multiPage > 0);
  ok("pdf: the orphan sweep actually pushed a table header past the first page (control)", headerPastFirstPage > 0);
  ok("pdf: a table header is never the last thing on a page, over 46 filler offsets", orphaned === 0);
}

// postureSample is a representative PostureInput for the PDF test (a couple of failing checks so the
// table has content).
function postureSample(): PostureInput {
  return {
    status: { destConfigured: false, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: false, adminTokenPresent: false, bootstrapConsumed: true, breakGlassTokenRetired: false, recoveryBreakGlassReady: true },
    downpipes: [{ id: "dp1", name: "Primary", restoreTestCadenceSeconds: 604800, lastRestoreTestAt: NOW - 2 * DAY, lastRestoreTestOk: true }],
    expiry: [{ label: "S3 key", state: "approaching" }],
    notifyFailureRuleSet: false,
    ownerCount: 1,
    operationalPrivatePresent: false,
    beaconEnabled: false,
    overrides: new Map(),
    // No pin recorded in this fixture. Stated rather than omitted: PostureInput makes this REQUIRED
    // and nullable so a caller cannot silently default a tamper signal to "no drift".
    recipientPinDrift: null,
  };
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
