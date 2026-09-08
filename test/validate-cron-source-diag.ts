// Prove the CRON + SOURCE diagnostic evidence is RECORDED on the real fault path and is REDACTION-SAFE.
//
// This covers: per-pass attribution, destination-probe class + dangling fan-out refs, tick-ring holes,
// auto-heal stalls, discovery skip causes, beacon class + partial config, cf-config discovery classes
// (truncation, stale-fallback selector mode), D1 defect class + locus, and cf-config restore skip classes.
//
// THE BINDING CLAIM THIS TEST DEFENDS (no-custody). Every one of these recorders sits at a fault site where
// the ONLY thing in hand is a raw provider error -- a Cloudflare API message, an S3 <Code>, a DO free-text
// refusal reason, a SQLite error. Each of those strings can embed a customer's email, bucket, object key,
// table name, hostname, token or secret. The rule is that a classifier may READ such a string ONLY to SELECT
// a closed enum member, and must RETURN that member. So every case below plants a CUSTOMER SENTINEL inside
// the fault the recorder is given, and then asserts the sentinel appears in NO BYTE of the recorded output.
//
// Run: node test/validate-cron-source-diag.ts

import {
  applyCronHealth,
  assertSiemBatchCapSound,
  BEACON_FAIL_CLASSES,
  classifyBeaconFail,
  classifyCronPassError,
  classifyDestProbeReason,
  classifyResumeApplyReason,
  clearPendingTickRecordFailures,
  CRON_PASS_ERROR_CLASSES,
  CRON_PASS_NAMES,
  DISCOVERY_SKIP_REASONS,
  drainCronDestProbeFaults,
  drainCronFaultLedger,
  emptyCronHealth,
  noteAutoHealDeferral,
  noteBeaconEnv,
  noteBeaconFail,
  noteBeaconStateWriteFailure,
  noteCronPass,
  noteDanglingDestinationRef,
  noteDestProbeFault,
  noteDiscoverySkip,
  noteResumeApplyRefusal,
  noteSiemShapingFallback,
  noteTickRecordFailure,
  pendingTickRecordFailureCount,
  RESUME_APPLY_REASON_CODES,
  resetCronFaultLedger,
  SIEM_SHAPING_FALLBACKS,
  type CronHealth,
} from "../src/cron/cron-fault-ledger.ts";
import { applyDestProbeFaults, classifyRestoreFaultClass, DEST_PROBE_REASONS, RESTORE_FAULT_CLASSES } from "../src/admin/diag-records.ts";
import { applySourceFaults } from "../src/admin/run-fault-records.ts";
import { CF_WRITE_SKIP_CLASSES, cfSkipCounts, classifyCfWriteSkip, type CfWriteSkipClass } from "../src/sources/cf-config-fault.ts";
import {
  classifyD1Defect,
  D1_DEFECT_CLASSES,
  drainSourceFaultLedger,
  isEmptyFaultLedger,
  noteCfSelectorMode,
  recordD1Defect,
  resetSourceFaultLedger,
} from "../src/sources/source-fault-ledger.ts";
import { effectiveCfConfigSelector, probeCfConfig, sanitiseCfConfigDiscovery } from "../src/sources/cf-config-discovery.ts";
import type { CfConfigSkipClass } from "../src/admin/restore-types.ts";

let failures = 0;
// This suite is SILENT ON PASS and writes its FAIL lines to stderr, so a run that asserted 40 things
// and a run that asserted none look identical on stdout. That makes it invisible to both halves of a
// verification: the exit code still works, but nothing in the log says how much was checked. Counting
// the checks and handing the count to the guard puts it on the canonical VERDICT line.
let checks = 0;
function ok(cond: boolean, what: string): void {
  checks++;
  if (cond) return;
  failures++;
  console.error(`  FAIL ${what}`);
}
function section(name: string): void {
  console.log(`\n${name}`);
}

// ---- the customer sentinels ------------------------------------------------------------------------------
// Each is a value that MUST NEVER be recorded: a customer email, a bucket, an object key, a secret/token, a
// table name, an endpoint. They are planted INSIDE the raw faults every recorder is handed.
const SENTINELS = [
  "cfo@acme-holdings.example",
  "acme-prod-backups-bucket",
  "run/01JABCDEF/seg/0007.bin",
  "sk_live_51ABCDEFsupersecretvalue",
  "customer_invoices_2026",
  "https://acme.internal.example:9000/ingest",
  "AKIAIOSFODNN7EXAMPLE",
];

/** noSentinel asserts that NO customer sentinel appears in any byte of a recorded value. */
function noSentinel(recorded: unknown, what: string): void {
  const json = JSON.stringify(recorded) ?? "";
  for (const s of SENTINELS) {
    if (json.includes(s)) {
      failures++;
      console.error(`  FAIL ${what}: LEAKED customer sentinel ${JSON.stringify(s)} into ${json.slice(0, 400)}`);
      return;
    }
  }
  // Belt and braces: no free-text carrier field may hold a STRING in one of these aggregates. (A boolean
  // named `url` is fine and is the point of G278's envPresent: it records PRESENCE, never the value.)
  const leaky = /"(message|stack|endpoint|bucket|objectKey|token|secret)"\s*:\s*"/i;
  if (leaky.test(json)) {
    failures++;
    console.error(`  FAIL ${what}: recorded a free-text field: ${json.slice(0, 400)}`);
  }
}

const NOW = Date.UTC(2026, 6, 12, 3, 0, 0);
const FIFTEEN_MIN = 15 * 60 * 1000;

// ==========================================================================================================
section("cron pass attribution (which of the ~20 passes failed, and why)");
{
  resetCronFaultLedger();
  clearPendingTickRecordFailures();

  // The classifier reads a fault carrying a customer bucket + email and returns ONLY a closed class.
  const dofetch = classifyCronPassError(new Error(`Durable Object storage failure while reading ${SENTINELS[1]} for ${SENTINELS[0]}`));
  ok(dofetch === "do-fetch", `a DO fault classifies as do-fetch (got ${dofetch})`);
  const budget = classifyCronPassError(new Error("Too many subrequests: the invocation exceeded its budget"));
  ok(budget === "budget", `a subrequest bail classifies as budget (got ${budget})`);
  const delivery = classifyCronPassError(new Error(`webhook fetch failed to ${SENTINELS[5]}`));
  ok(delivery === "delivery", `an outbound send fault classifies as delivery (got ${delivery})`);
  ok(CRON_PASS_ERROR_CLASSES.includes(classifyCronPassError(new Error("something nobody has seen"))), "an unknown fault still lands in the closed set");

  // The pass records: one healthy, one failed WITH a class.
  noteCronPass("alerts", true);
  noteCronPass("retention", false, new Error(`retention prune failed: cannot delete ${SENTINELS[2]} from ${SENTINELS[1]}`));
  // The DRIVER's classless tally must NOT clobber the pass's own classified record (the ordering the real
  // code produces: the pass catches + classifies, then the driver tallies the false return).
  noteCronPass("retention", false);

  const delta = drainCronFaultLedger();
  ok(delta.passes?.retention?.cls === "do-fetch" || delta.passes?.retention?.cls === "other", "the failed pass carries a closed class");
  const classed = delta.passes?.retention?.cls;
  noteCronPass("retention", false, new Error("Durable Object unavailable"));
  const d2 = drainCronFaultLedger();
  ok(d2.passes?.retention?.cls === "do-fetch", "a classified failure wins");
  ok(classed !== undefined, "the classless driver tally did not erase the pass's own class");

  // Fold into the DO record twice: consecutiveFailures must climb, and an OK must reset it.
  let rec: CronHealth = applyCronHealth(emptyCronHealth(), delta, NOW, FIFTEEN_MIN);
  rec = applyCronHealth(rec, delta, NOW + FIFTEEN_MIN, FIFTEEN_MIN);
  ok(rec.passes.retention?.consecutiveFailures === 2, `consecutiveFailures climbs (got ${rec.passes.retention?.consecutiveFailures})`);
  ok(rec.passes.alerts?.lastOkAt !== undefined, "a healthy pass stamps lastOkAt");
  rec = applyCronHealth(rec, { passes: { retention: { ok: true } } }, NOW + 2 * FIFTEEN_MIN, FIFTEEN_MIN);
  ok(rec.passes.retention?.consecutiveFailures === 0, "a recovered pass resets its consecutive run");
  ok(rec.passes.retention?.failCount === 2, "the lifetime failCount is preserved across recovery");
  noSentinel(rec, "G132 cron-health record");

  // The applier is the REDACTION CHOKEPOINT: an out-of-vocabulary pass name / class cannot enter.
  const hostile = applyCronHealth(emptyCronHealth(), { passes: { [SENTINELS[0]!]: { ok: false, cls: SENTINELS[1] }, retention: { ok: false, cls: SENTINELS[3] } } }, NOW, FIFTEEN_MIN);
  ok(hostile.passes[SENTINELS[0]!] === undefined, "an out-of-vocabulary pass NAME is dropped");
  ok(hostile.passes.retention?.lastErrorClass === "other", "an out-of-vocabulary error CLASS falls back to the closed `other`");
  noSentinel(hostile, "G132 hostile body");
  ok(CRON_PASS_NAMES.length >= 20, "the closed pass vocabulary covers the driver's passes");
}

// ==========================================================================================================
section("tick-ring holes (a DO-unreachable tick is not the same as a cron that never fired)");
{
  resetCronFaultLedger();
  clearPendingTickRecordFailures();

  // A tick that could not report AT ALL: the sink for the record is the thing that is down.
  noteTickRecordFailure();
  noteTickRecordFailure();
  ok(pendingTickRecordFailureCount() === 2, "the tick-record failures are held isolate-locally");
  // The per-invocation reset must NOT drop them: reporting them LATER is their entire purpose.
  resetCronFaultLedger();
  ok(pendingTickRecordFailureCount() === 2, "the carried tally SURVIVES the per-invocation reset");

  const delta = drainCronFaultLedger();
  ok(delta.tickRecordFailures === 2, "the next healthy tick carries the holes");

  // The DO derives the gap from its OWN clock, never from a number the edge sends.
  let rec = applyCronHealth(emptyCronHealth(), { passes: { alerts: { ok: true } } }, NOW, FIFTEEN_MIN);
  ok(rec.tick.gapDetected === false, "the first tick reports no gap");
  // Four intervals later: three ticks are missing.
  rec = applyCronHealth(rec, delta, NOW + 4 * FIFTEEN_MIN, FIFTEEN_MIN);
  ok(rec.tick.gapDetected === true, "a 4-interval gap is DETECTED");
  ok(rec.tick.missedApprox === 3, `the missed-tick count is derived (got ${rec.tick.missedApprox})`);
  ok(rec.tick.recordFailures === 2, "the holes are attributed to failed tick records, not to a dead cron");
  // A consecutive tick with no gap.
  rec = applyCronHealth(rec, { passes: { alerts: { ok: true } } }, NOW + 5 * FIFTEEN_MIN, FIFTEEN_MIN);
  ok(rec.tick.gapDetected === false && rec.tick.missedApprox === 0, "a punctual tick clears the gap flag");
  ok(rec.tick.recordFailures === 2, "the lifetime hole count is preserved");

  // A hostile edge cannot fabricate an unbounded missed-tick claim.
  const hostile = applyCronHealth(emptyCronHealth(), { tickRecordFailures: 9e15 }, NOW, FIFTEEN_MIN);
  ok(hostile.tick.recordFailures > 0 && hostile.tick.recordFailures <= 100_000, `a hostile count is clamped (got ${hostile.tick.recordFailures})`);
  noSentinel(rec, "G205 tick record");
  clearPendingTickRecordFailures();
}

// ==========================================================================================================
section("cf-config discovery skip causes (the stale cache that makes every run crawl ~214 surfaces)");
{
  resetCronFaultLedger();
  for (const r of DISCOVERY_SKIP_REASONS) ok(typeof r === "string", `${r} is a closed reason`);

  noteDiscoverySkip("no-token");
  let rec = applyCronHealth(emptyCronHealth(), drainCronFaultLedger(), NOW, FIFTEEN_MIN);
  ok(rec.discovery.skips["no-token"] === 1, "the skip cause is recorded");
  ok(rec.discovery.consecutiveSkips === 1, "a BLOCKED refresh starts a consecutive run");

  noteDiscoverySkip("out-of-scope");
  rec = applyCronHealth(rec, drainCronFaultLedger(), NOW + FIFTEEN_MIN, FIFTEEN_MIN);
  ok(rec.discovery.consecutiveSkips === 2, "a chronically blocked refresh climbs");

  // "none-due" is the healthy QUIET state and must NOT read as a blocked refresh.
  noteDiscoverySkip("none-due");
  rec = applyCronHealth(rec, drainCronFaultLedger(), NOW + 2 * FIFTEEN_MIN, FIFTEEN_MIN);
  ok(rec.discovery.consecutiveSkips === 0, "a QUIET pass (nothing due) is not a BLOCKED pass");
  ok(rec.discovery.lastAttemptAt !== undefined, "the last attempt is stamped");

  const hostile = applyCronHealth(emptyCronHealth(), { discoverySkips: { [SENTINELS[1]!]: 5, "no-token": 2 } }, NOW, FIFTEEN_MIN);
  ok(hostile.discovery.skips[SENTINELS[1]!] === undefined, "an out-of-vocabulary skip reason is dropped");
  ok(hostile.discovery.skips["no-token"] === 2, "the in-vocabulary reason survives");
  noSentinel(hostile, "G234 discovery skips");
}

// ==========================================================================================================
section("beacon fail class + PARTIAL configuration (a typo'd env var is not a deliberate opt-out)");
{
  resetCronFaultLedger();
  // A malformed BEACON_URL never self-heals; a network blip does. Today both persist ok:false with no class.
  ok(classifyBeaconFail(new Error(`Invalid URL: ${SENTINELS[5]}`)) === "url-invalid", "a malformed BEACON_URL classifies as url-invalid");
  ok(classifyBeaconFail(new Error("fetch failed")) === "network", "a transport fault classifies as network");
  ok(classifyBeaconFail(undefined, 422) === "non-2xx", "a receiver refusal classifies as non-2xx");
  ok(BEACON_FAIL_CLASSES.includes(classifyBeaconFail(new Error("???"))), "an unknown beacon fault stays in the closed set");

  // HALF-configured: url + accountId set, ingest key typo'd/absent. Presence booleans ONLY -- never the values.
  noteBeaconEnv({ url: SENTINELS[5], ingestKey: "", accountId: "acct-123" });
  noteBeaconFail(classifyBeaconFail(new Error(`fetch failed: POST ${SENTINELS[5]} (bearer ${SENTINELS[3]})`)));
  noteBeaconStateWriteFailure();

  const rec = applyCronHealth(emptyCronHealth(), drainCronFaultLedger(), NOW, FIFTEEN_MIN);
  ok(rec.beacon.envPresent.url === true, "the URL is recorded as PRESENT");
  ok(rec.beacon.envPresent.ingestKey === false, "the MISSING ingest key is the recorded diagnosis");
  ok(rec.beacon.envPresent.accountId === true, "the account tag is recorded as present");
  ok(rec.beacon.lastFailClass === "network", "the beacon fail class is recorded");
  ok(rec.beacon.stateWriteFailures === 1, "recordBeaconState's OWN swallowed failure is counted (a stale beacon field is now attributable)");
  // THE BINDING ASSERTION: the URL and the ingest key were both in the fault text and in the env.
  noSentinel(rec, "G278 beacon record");

  const hostile = applyCronHealth(emptyCronHealth(), { beacon: { envPresent: { url: SENTINELS[5], ingestKey: 1, accountId: true }, failClass: SENTINELS[3] } }, NOW, FIFTEEN_MIN);
  ok(hostile.beacon.envPresent.url === false, "a non-boolean presence value coerces to false (never the value itself)");
  ok(hostile.beacon.lastFailClass === undefined, "an out-of-vocabulary beacon class is dropped");
  noSentinel(hostile, "G278 hostile beacon body");
}

// ==========================================================================================================
section("auto-heal stalls (latched, no progress, reason swallowed) with the DO's FREE-TEXT reason");
{
  resetCronFaultLedger();
  // The DO's resume-apply `reason` is FREE TEXT and can embed storage paths. It must be PROJECTED, never carried.
  const leaky = `storage put failed writing ${SENTINELS[2]} to ${SENTINELS[1]} for ${SENTINELS[0]}`;
  ok(classifyResumeApplyReason(leaky) === "storage-failed", "a leaky DO reason projects onto a closed code");
  ok(classifyResumeApplyReason("signature did not verify") === "verify-failed", "a verify refusal projects correctly");
  ok(RESUME_APPLY_REASON_CODES.includes(classifyResumeApplyReason("who knows")), "an unknown reason stays in the closed set");

  noteAutoHealDeferral("budget-reserve");
  noteResumeApplyRefusal(leaky);
  const rec = applyCronHealth(emptyCronHealth(), drainCronFaultLedger(), NOW, FIFTEEN_MIN);
  ok(rec.autoHeal.lastAttemptAt !== undefined, "the auto-heal attempt is stamped (it RAN, and made no progress)");
  ok(rec.autoHeal.lastDeferral === "resume-refused", "the stall class is recorded");
  ok(rec.autoHeal.resumeApplyLastReasonCode === "storage-failed", "the resume refusal is a CLOSED code");
  noSentinel(rec, "G220 auto-heal record");

  // The amnesia-probe POST failure (an empty catch today) is what made the probe field silently go stale.
  resetCronFaultLedger();
  noteAutoHealDeferral("probe-transport");
  const probeRec = applyCronHealth(emptyCronHealth(), drainCronFaultLedger(), NOW, FIFTEEN_MIN);
  ok(probeRec.autoHeal.amnesiaProbeWriteFailures === 1, "a lost amnesia-probe write is counted, so a STALE probe field is attributable");

  const hostile = applyCronHealth(emptyCronHealth(), { autoHeal: { attempted: true, deferral: SENTINELS[1], resumeApplyReason: leaky } }, NOW, FIFTEEN_MIN);
  ok(hostile.autoHeal.lastDeferral === undefined, "an out-of-vocabulary deferral is dropped");
  ok(hostile.autoHeal.resumeApplyLastReasonCode === undefined, "a RAW reason string cannot be posted straight into the record");
  noSentinel(hostile, "G220 hostile auto-heal body");
}

// ==========================================================================================================
section("SIEM shaping + cursor fallbacks (incl. the LATENT batch-tail data-loss path)");
{
  resetCronFaultLedger();
  for (const k of SIEM_SHAPING_FALLBACKS) ok(typeof k === "string", `${k} is a closed fallback kind`);

  noteSiemShapingFallback("timestamp-substituted", 3);
  noteSiemShapingFallback("field-truncated");
  noteSiemShapingFallback("cursor-reset");
  const rec = applyCronHealth(emptyCronHealth(), drainCronFaultLedger(), NOW, FIFTEEN_MIN);
  ok(rec.siem["timestamp-substituted"]?.count === 3, "silent timestamp substitutions are counted");
  ok(rec.siem["field-truncated"]?.count === 1, "a truncated field (which breaks the customer's chain-verify script) is counted");
  ok(rec.siem["cursor-reset"]?.count === 1, "THE cursor reset (thousands of duplicate historical events) is counted");
  noSentinel(rec, "G084 siem record");

  // THE LATENT DATA LOSS: if the drain limit ever exceeds the shaping cap, the batch tail is dropped while
  // the cursor advances PAST it and the trail claims a full delivery. The guard must refuse to let that open.
  let threw = false;
  try {
    assertSiemBatchCapSound(1000, 500);
  } catch {
    threw = true;
  }
  ok(threw, "a drain limit ABOVE the shaping cap is refused (the silent audit-log loss path cannot open)");
  let fine = true;
  try {
    assertSiemBatchCapSound(500, 500);
  } catch {
    fine = false;
  }
  ok(fine, "equal limits are sound");

  const hostile = applyCronHealth(emptyCronHealth(), { siem: { [SENTINELS[2]!]: 9, "cursor-reset": 4 } }, NOW, FIFTEEN_MIN);
  ok(hostile.siem[SENTINELS[2]!] === undefined, "an out-of-vocabulary fallback kind is dropped");
  ok(hostile.siem["cursor-reset"]?.count === 4, "the in-vocabulary kind survives");
  noSentinel(hostile, "G084 hostile siem body");
}

// ==========================================================================================================
section("destination probe class + dangling fan-out refs");
{
  resetCronFaultLedger();
  // The probe's catch used to DROP the S3 error. Each of these has a different remedy.
  ok(classifyDestProbeReason(new Error(`PUT ${SENTINELS[2]}: status 403 AccessDenied for ${SENTINELS[1]} (key ${SENTINELS[6]})`)) === "auth", "an expired/denied credential classifies as auth");
  ok(classifyDestProbeReason(new Error(`PUT ${SENTINELS[2]}: status 404 NoSuchBucket: ${SENTINELS[1]}`)) === "not-found", "a DELETED bucket classifies as not-found (never `auth`)");
  ok(classifyDestProbeReason(new Error(`PUT ${SENTINELS[2]}: status 503 SlowDown from ${SENTINELS[1]}`)) === "throttled", "real backpressure classifies as throttled, NOT as an outage");
  // A bucket/key with a 3-digit number in it must NEVER be read as an HTTP status.
  ok(classifyDestProbeReason(new Error(`PUT run/500/seg/404.bin: fetch failed`)) === "network", "a numeric object key is not mistaken for a status");
  ok(classifyDestProbeReason(new Error(`fetch failed: getaddrinfo ENOTFOUND ${SENTINELS[5]}`)) === "network", "a DNS fault classifies as network");
  ok(DEST_PROBE_REASONS.includes(classifyDestProbeReason(new Error("???"))), "an unknown probe fault stays in the closed set");

  noteDestProbeFault("primary-r2", new Error(`PUT ${SENTINELS[2]}: status 403 AccessDenied writing to ${SENTINELS[1]} with ${SENTINELS[6]}`));
  noteDestProbeFault("replica-s3", new Error(`PUT ${SENTINELS[2]}: status 404 NoSuchBucket: ${SENTINELS[1]}`));
  noteDanglingDestinationRef();

  const { rows, refusedUpstream } = drainCronDestProbeFaults();
  ok(rows.length === 2, "one row per FAILING destination (a healthy destination records nothing)");
  ok(refusedUpstream === 0, "a fleet under DEST_PROBE_MAX declares no upstream refusal");
  noSentinel(rows, "G133 probe rows");

  const map = applyDestProbeFaults({}, rows, NOW);
  ok(map["primary-r2"]?.reason === "auth", "the per-destination cause is recorded (rotate the credential)");
  ok(map["replica-s3"]?.reason === "not-found", "the sibling destination carries a DIFFERENT cause (recreate the bucket)");
  noSentinel(map, "G133 dest-probe record");

  const delta = drainCronFaultLedger();
  const rec = applyCronHealth(emptyCronHealth(), delta, NOW, FIFTEEN_MIN);
  ok(rec.danglingDestinationRefs === 1, "a fan-out id with no config record is counted (the customer holds FEWER copies than configured)");

  // The DO chokepoint drops an out-of-vocabulary reason rather than persisting a message.
  const hostile = applyDestProbeFaults({}, [{ id: "d1", reason: `AccessDenied: ${SENTINELS[3]}` }], NOW);
  ok(hostile.d1 === undefined, "a RAW S3 message cannot be posted as a reason");
  noSentinel(hostile, "G133 hostile probe row");
}

// ==========================================================================================================
section("cf-config discovery: WHY a surface is unavailable, truncation, and the stale-fallback mode");
{
  // A probe where one surface 403s (a token scope gap: ACTIONABLE) and one 5xx's (a CF outage: transient).
  // Both are `unavailable` today, with no way to tell them apart.
  const surfaces = [
    { id: "dns", scope: "zone", read: async () => { throw Object.assign(new Error(`Cloudflare API GET /zones/z/dns_records: 403 forbidden for ${SENTINELS[0]}`), { status: 403 }); } },
    { id: "waf", scope: "zone", read: async () => { throw Object.assign(new Error(`Cloudflare API GET /zones/z/rulesets: 500 internal error (${SENTINELS[1]})`), { status: 500 }); } },
    { id: "settings", scope: "zone", read: async () => ({ a: 1 }) },
    { id: "empty-one", scope: "zone", read: async () => [] },
  ] as unknown as Parameters<typeof probeCfConfig>[4] extends never ? never : never;

  const disc = await probeCfConfig("tok", "acct", "zone", NOW, {
    surfaces: surfaces as never,
    fetchImpl: (() => {
      throw new Error("no network in this validator");
    }) as unknown as typeof fetch,
    concurrency: 2,
  });
  ok(disc.unavailable.length === 2, `both faulted surfaces are unavailable (got ${disc.unavailable.length})`);
  const byClass = disc.unavailableByClass ?? {};
  ok(byClass["403"] === 1, `the token-scope gap is classified 403 (got ${JSON.stringify(byClass)})`);
  ok(byClass["5xx"] === 1, `the Cloudflare outage is classified 5xx (got ${JSON.stringify(byClass)})`);
  ok(disc.present.includes("settings"), "a healthy surface is present");
  noSentinel(disc, "G006 discovery record");

  // The DO-side chokepoint: a hostile body cannot inject a surface id, a class or a free-text key.
  const clean = sanitiseCfConfigDiscovery(
    { at: NOW, present: ["settings", SENTINELS[1]], empty: [], gated: [], unavailable: ["dns"], unavailableByClass: { "403": 2, [SENTINELS[0]!]: 9 }, truncated: ["dns", SENTINELS[2]] },
    [{ id: "settings" }, { id: "dns" }] as never,
  );
  ok(clean !== null, "a well-formed discovery body is accepted");
  ok(clean?.present.length === 1 && clean.present[0] === "settings", "a surface id outside the registry is DROPPED");
  ok(clean?.unavailableByClass?.["403"] === 2, "an in-vocabulary class survives");
  ok(clean?.unavailableByClass?.[SENTINELS[0]!] === undefined, "an out-of-vocabulary class KEY is dropped");
  ok(clean?.truncated?.length === 1, "a truncation id outside the registry is dropped");
  ok(sanitiseCfConfigDiscovery({ nonsense: true }) === null, "a body that is not a discovery result is refused");
  noSentinel(clean, "G006 sanitised discovery");

  // THE COST EXPLOSION: an auto-mode downpipe with a STALE cache silently crawls every surface, forever.
  resetSourceFaultLedger();
  effectiveCfConfigSelector({ cfConfigMode: "auto", include: [], exclude: [] }, { at: NOW - 30 * 60 * 60 * 1000, present: ["dns"], empty: [], gated: [], unavailable: [] }, NOW);
  let led = drainSourceFaultLedger();
  ok(led.cfSelectorMode === "stale-fallback-all", `a stale cache stamps the run with stale-fallback-all (got ${led.cfSelectorMode})`);
  ok(!isEmptyFaultLedger(led), "the stale fail-safe is EVIDENCE (a non-empty ledger), so it reaches the run row");

  resetSourceFaultLedger();
  effectiveCfConfigSelector({ cfConfigMode: "auto", include: [], exclude: [] }, { at: NOW - 60_000, present: ["dns"], empty: [], gated: [], unavailable: [] }, NOW);
  led = drainSourceFaultLedger();
  ok(led.cfSelectorMode === "auto", "a fresh cache stamps `auto`");
  ok(isEmptyFaultLedger(led), "a HEALTHY selector mode does not by itself make a clean run's ledger non-empty");

  resetSourceFaultLedger();
  effectiveCfConfigSelector({ cfConfigMode: "manual", include: ["dns"], exclude: [] }, undefined, NOW);
  ok(drainSourceFaultLedger().cfSelectorMode === "configured", "an explicit selection stamps `configured`");
  resetSourceFaultLedger();
}

// ==========================================================================================================
section("D1 defect class + locus (tamper vs corruption vs ENGINE VERSION SKEW)");
{
  resetSourceFaultLedger();
  // The three that route to COMPLETELY different diagnoses. Each message embeds the customer's TABLE NAME.
  const tamper = new Error(`D1 backup table ${SENTINELS[4]} sql: statement carries content after its terminating ';' (more than one statement)`);
  const skew = new Error(`unsupported D1 backup format d1-backup-v9; this reader understands d1-backup-v1`);
  const corrupt = new Error(`D1 cell of unsupported non-finite numeric value NaN in ${SENTINELS[4]}`);

  ok(classifyD1Defect(tamper) === "multi-statement-ddl", "a multi-statement DDL is a TAMPER signature, never a writer bug");
  ok(classifyD1Defect(skew) === "unknown-format", "an unknown format hint is ENGINE VERSION SKEW (the actionable one-line diagnosis)");
  ok(classifyD1Defect(corrupt) === "non-finite-real", "a NaN cell is a distinct writer-bug class");
  ok(classifyD1Defect(new Error(`D1 export: unexpected non-integer rowid string in ${SENTINELS[4]}`)) === "bad-rowid", "a binding contract violation classifies as bad-rowid");
  ok(classifyD1Defect(new Error("something unrelated entirely")) === null, "a non-D1 fault is not mislabelled as a D1 defect");
  for (const c of D1_DEFECT_CLASSES) ok(typeof c === "string", `${c} is a closed defect class`);

  // The CAPTURE path records the class + a one-way HANDLE of the table (never the customer's schema label).
  recordD1Defect("non-finite-real", `d1-table/h:${"a".repeat(12)}`);
  const led = drainSourceFaultLedger();
  ok(led.d1Defects["non-finite-real"] === 1, "the capture-path defect is counted");
  ok(/^d1-table\/h:[0-9a-f]{12}$/.test(led.d1DefectTables[0] ?? ""), "the locus is a one-way HANDLE, so the customer does not have to bisect their own schema");
  noSentinel(led, "G069 source ledger");

  // The RESTORE path routes the SAME three throws into the restore-fault ring's closed classes.
  ok(classifyRestoreFaultClass(tamper.message) === "d1-decode-tamper", "the restore ring names TAMPER");
  ok(classifyRestoreFaultClass(skew.message) === "d1-format-unknown", "the restore ring names VERSION SKEW");
  ok(classifyRestoreFaultClass(corrupt.message) === "d1-decode-corrupt", "the restore ring names CORRUPTION");
  ok(RESTORE_FAULT_CLASSES.includes("d1-decode-tamper"), "the tamper class is in the closed restore vocabulary");
  // The classifier RETURNS an enum: the table name it just read is nowhere in the return value.
  noSentinel(
    [classifyRestoreFaultClass(tamper.message), classifyRestoreFaultClass(skew.message), classifyRestoreFaultClass(corrupt.message)],
    "G069 restore classes",
  );
  resetSourceFaultLedger();
}

// ==========================================================================================================
section("cf-config restore skip classes (why did 20 of 200 records skip?)");
{
  // ORDER is load-bearing: an entitlement gate often ALSO says "forbidden", and a quota refusal is not a
  // malformed item. Mislabelling either sends the customer to the wrong remedy.
  ok(classifyCfWriteSkip(new Error("This feature is not available on your plan; upgrade your plan to use it")) === "entitlement", "a PLAN gate is entitlement, not auth");
  ok(classifyCfWriteSkip(new Error("limit exceeded: too many records for this zone")) === "quota", "a plan LIMIT is quota, not validation");
  ok(classifyCfWriteSkip(new Error(`403 forbidden: token lacks the edit scope (${SENTINELS[3]})`)) === "auth", "a scope gap is auth");
  ok(classifyCfWriteSkip(new Error(`Invalid DNS record content for ${SENTINELS[0]}: must be a valid IPv4 address`)) === "validation", "a malformed item is validation");
  ok(classifyCfWriteSkip(new Error("429 rate limited")) === "rate-limited", "a throttle is rate-limited");
  ok(classifyCfWriteSkip(new Error("502 bad gateway")) === "api-unavailable", "a CF outage is api-unavailable");
  ok(CF_WRITE_SKIP_CLASSES.includes(classifyCfWriteSkip(new Error("??"))), "an unknown refusal stays in the closed set");

  // The apply's summary now carries a {class: count} map instead of a bare integer.
  const skipped = [
    { path: "dns/1", reason: `Invalid content for ${SENTINELS[0]}`, cls: classifyCfWriteSkip(new Error("invalid content")) },
    { path: "dns/2", reason: "limit exceeded", cls: classifyCfWriteSkip(new Error("limit exceeded: too many records")) },
    { path: "dns/3", reason: "limit exceeded", cls: classifyCfWriteSkip(new Error("limit exceeded: too many records")) },
    { path: "ruleset/x", reason: "no live ruleset for this phase", cls: "no-live-phase" as CfWriteSkipClass },
  ];
  const counts = cfSkipCounts(skipped);
  ok(counts.quota === 2, `the quota refusals are counted (got ${JSON.stringify(counts)})`);
  ok(counts.validation === 1, "the validation refusal is counted separately");
  ok(counts["no-live-phase"] === 1, "the engine-side structural skip is counted");
  // THE BINDING ASSERTION: the raw 120-char CF reasons stay in the operator's live response; the COUNTS are
  // what a pack carries, and they contain no customer value.
  noSentinel(counts, "G191 skip counts");

  // The wire type (restore-types.ts is IMPORT-FREE by contract, so its union is a hand-copy) must not drift.
  const wire: CfConfigSkipClass[] = [...CF_WRITE_SKIP_CLASSES];
  const back: (typeof CF_WRITE_SKIP_CLASSES)[number][] = wire;
  ok(back.length === CF_WRITE_SKIP_CLASSES.length, "the wire-type union and the recorder vocabulary are identical (a drift fails the typecheck above)");
}

// ==========================================================================================================
section("THE DO CHOKEPOINT -- the new source evidence must SURVIVE applySourceFaults and reach the pack read");
{
  // A gap is NOT closed until its evidence reaches the record the pack projects. applySourceFaults re-gates
  // EVERY field of the posted ledger against the closed vocabularies and DROPS anything out of vocabulary --
  // so a field added to the ledger and forgotten here would be recorded at the fault site and then silently
  // discarded at the DO, which is exactly the failure mode this whole programme exists to end.
  resetSourceFaultLedger();
  noteCfSelectorMode("stale-fallback-all");
  recordD1Defect("multi-statement-ddl", `d1-table/h:${"b".repeat(12)}`);
  recordD1Defect("unknown-format");
  const posted = drainSourceFaultLedger();

  const rec = applySourceFaults({}, "dp-acme", posted, NOW);
  const entry = rec["dp-acme"];
  ok(entry !== undefined, "the drained ledger lands against the downpipe");
  ok(entry?.cfSelectorMode === "stale-fallback-all", `the stale-fallback selector mode SURVIVES the chokepoint (got ${entry?.cfSelectorMode})`);
  ok(entry?.d1Defects?.["multi-statement-ddl"] === 1, "the TAMPER class survives the chokepoint");
  ok(entry?.d1Defects?.["unknown-format"] === 1, "the VERSION-SKEW class survives the chokepoint");
  ok((entry?.d1DefectTables ?? []).length === 1, "the table LOCUS handle survives the chokepoint");
  noSentinel(rec, "DO chokepoint source-faults record");

  // A HEALTHY selector mode must NOT be recorded (it would make every clean cf-config run non-empty).
  resetSourceFaultLedger();
  noteCfSelectorMode("auto");
  const clean = applySourceFaults({}, "dp-clean", drainSourceFaultLedger(), NOW);
  ok(clean["dp-clean"]?.cfSelectorMode === undefined, "a HEALTHY selector mode is not recorded (omitempty)");

  // The chokepoint drops an out-of-vocabulary class and a RAW customer table name.
  const hostile = applySourceFaults({}, "dp-x", { d1Defects: { [SENTINELS[4]!]: 3, "bad-json": 2 }, d1DefectTables: [SENTINELS[4]!], cfSelectorMode: SENTINELS[1] }, NOW);
  ok(hostile["dp-x"]?.d1Defects?.[SENTINELS[4]!] === undefined, "an out-of-vocabulary D1 defect class is DROPPED");
  ok(hostile["dp-x"]?.d1Defects?.["bad-json"] === 2, "the in-vocabulary class survives");
  ok(hostile["dp-x"]?.cfSelectorMode === undefined, "an out-of-vocabulary selector mode is DROPPED");
  ok((hostile["dp-x"]?.d1DefectTables ?? []).length === 0, "a RAW customer table name fails the attribution-id shape gate");
  noSentinel(hostile, "DO chokepoint hostile body");
  resetSourceFaultLedger();
}

// ==========================================================================================================
console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`validate-cron-source-diag: ${failures} FAILED`);
  process.exit(1);
}
console.log("validate-cron-source-diag: all checks passed");
