// SCHEDULER-DO pipeline / governance / enrolment evidence validator.
//
// Every gap below is the same shape the audit is about: the scheduler DO ABSORBS a fault -- a resolver that
// substitutes a destination the customer did not choose, a flight that is allocated and abandoned, a drill
// verdict discarded because the downpipe was renamed, an alert rejected at the input boundary, an apply that
// refuses forever, a role row that will not parse, a session signing key that quietly regenerates -- and the
// FACT of it existed nowhere a support pack could carry. Each block proves the same two things:
//
//   (a) RECORDED ON THE FAULT PATH: the evidence is written WHEN the fault happens (never on a happy path)
//       and is readable back through the DO's single support-pack read (readSchedDiag / GET /sched-diag) or
//       through the auth-signal aggregate the pack already carries.
//   (b) REDACTION-SAFE (binding, NO-CUSTODY): a customer email, a bearer secret, a raw thrown message, a
//       destination BUCKET and an object key PLANTED at each fault site appear in NO BYTE of the evidence,
//       and every key it carries is a member of a closed vocabulary declared in sched-fault-ledger.ts.
//
// What each area covers:
//   "my backups are landing in the wrong bucket" -- a malformed destination list, a dangling default
//        healed on read, or a canary pin whose destinations were all deleted. The run row shows the
//        destination USED; nothing said the ENGINE substituted it.
//   "the canary's lastRunAt keeps sliding" (flights allocated and abandoned every lease), a destination
//        frozen on a stale verdict (its result row was skipped), and destinations past the cap NEVER FLOWN.
//   "the fleet drill has been stuck at 3 remaining for two days" (the same members re-queue forever) and
//        the drill verdicts, OOM measurements, deep-verify cursors and PASSED proofs quietly thrown away.
//   "we drilled weekly and the evidence trail is empty for a month" -- indistinguishable from never
//        having drilled, because the evidence write failed in silence.
//   "my backup-failure alert never arrived" -- parseRejects=3 does not say WHICH alert died, and a
//        reject on the record half discards an entire emission's per-channel outcomes.
//   "our second owner approved and nothing happened" -- the record sits pending with zero history of the
//        failed attempts; and a detected record TAMPER or a REPLAYED one-shot approval was seen only by a browser.
//   A licence retried 5 times with 3 different causes reads as count=5 and ONE code (the least useful one).
//   The incident timeline cannot prove WHEN dual control was disarmed, that the break-glass token was
//        UN-retired, or that the canary was switched off before the incident.
//   "I ran the bootstrap and I am only a viewer" / "the invite link does not work" -- six refusals, one
//        coarse "forbidden", and an EXPIRED invite deleted-then-refused leaving no proof it ever existed.
//   "a member disappeared from the people screen" / "three engineers lost access on Tuesday" (a deleted
//        custom role) / "a JIT elevation never lapsed" (an unparseable expiry FAILS OPEN).
//   "every user was logged out at once with no terminate-all in the audit chain" -- the session signing
//        key silently regenerated, and the verify-failure spike that PAIRS with it was never counted.
//   "I cannot get past Verify and save" / "I cannot remove this destination" -- the engine computed
//        a precise refusal and returned it to a toast that is now closed.
//   The console's own crash / bulk-casualty / update-settle / contract-skew evidence, which the
//        engine now SIGNS INTO the pack (POST /client-diag) rather than beaconing anywhere.
//
// Run: node test/validate-sched-pipeline-evidence.ts

import {
  ADMIN_REFUSAL_REASONS,
  ADMIN_REFUSAL_ROUTES,
  CANARY_LOSS_KINDS,
  CLIENT_BULK_FAIL_CLASSES,
  CLIENT_BULK_OPS,
  CLIENT_CRASH_PHASES,
  CLIENT_FAULT_KINDS,
  CLIENT_ROUTE_FAMILIES,
  CLIENT_SETTLE_STATES,
  CLIENT_SKEW_KINDS,
  DEST_RESOLVE_FALLBACK_CLASSES,
  DRILL_DROP_KINDS,
  GOVERNANCE_OUTCOME_CLASSES,
  GOVERNANCE_STAGES,
  NOTIFY_DROP_KINDS,
  REFUSAL_SURFACES,
  SNAPSHOT_FAILURE_CLASSES,
  adminRefusalKey,
  applyClientDiagnostics,
  classifyDestProbeRefusal,
  classifyGovernanceOutcome,
  classifySnapshotFailure,
  governanceFaultKey,
  isMalformedDestList,
  readSchedDiag,
  recordClientDiagnostics,
  type SchedDiagBundle,
} from "../src/sched/sched-fault-ledger.ts";
import { AUTH_SIGNAL_NAMES } from "../src/admin/auth-signals.ts";
import { MockStorage, getFailures, makeConfig, makeScheduler, ok } from "./validate-scheduler-shared.ts";

declare const process: { exit(code?: number): never };

// THE POISON. Each is a class the evidence must NEVER carry: a customer email, a bearer secret, a raw thrown
// message (which embeds a host, a bucket and an object key), a destination bucket, an object key, and an
// operator's own free-text value. Planted at every fault site below.
const POISON_EMAIL = "cfo@customer-example.com";
const POISON_SECRET = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI";
const POISON_ERROR = "connect ECONNREFUSED 10.4.2.7:443 while reading s3://acme-prod-backups/2026/07/run.dpx";
const POISON_BUCKET = "acme-prod-backups";
const POISON_OBJECT_KEY = "2026/07/11/kv-namespace/secrets.dpx";
const POISON_VALUE = "customer-secret-schedule-note";
const POISON_TOKEN = "dpk_live_9f2c4a7e1b6d";
const POISONS = [
  POISON_EMAIL,
  POISON_SECRET,
  POISON_ERROR,
  POISON_BUCKET,
  POISON_OBJECT_KEY,
  POISON_VALUE,
  POISON_TOKEN,
  "ECONNREFUSED",
  "10.4.2.7",
  "customer-example",
  "AKIAIOSFODNN7EXAMPLE",
];

// check is ok() plus the local failure trace the redaction assertions print on a leak. The failure COUNT is
// the shared module-level one (getFailures), so this suite cannot under-report.
function check(label: string, cond: boolean): void {
  ok(label, cond);
}

// scanClean is THE redaction assertion. It serialises the whole evidence record -- KEYS AND VALUES ALIKE --
// so a leak through a map KEY (the classic closed-vocabulary bypass: a caller-derived string becomes a
// storage key) fails exactly as loudly as a leak through a value.
function scanClean(label: string, evidence: unknown): void {
  const json = JSON.stringify(evidence ?? null);
  const hit = POISONS.find((p) => json.includes(p));
  check(`${label}: redaction-safe (no email, secret, raw error, bucket, object key or token)`, hit === undefined);
  if (hit !== undefined) console.log(`       LEAKED: ${hit}\n       in: ${json.slice(0, 500)}`);
}

// vocabClean asserts every KEY of an aggregate is drawn from the closed vocabulary it claims.
function vocabClean(label: string, agg: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  const bad = Object.keys(agg).filter((k) => !allowed.has(k));
  check(`${label}: every key is a closed-vocabulary member`, bad.length === 0);
  if (bad.length > 0) console.log(`       OUT-OF-VOCABULARY KEYS: ${bad.join(", ")}`);
}

const AUTH_SIGNAL_SET = new Set<string>(AUTH_SIGNAL_NAMES);
const DEST_FALLBACK_SET = new Set<string>(DEST_RESOLVE_FALLBACK_CLASSES);
const CANARY_LOSS_SET = new Set<string>(CANARY_LOSS_KINDS);
const DRILL_DROP_SET = new Set<string>(DRILL_DROP_KINDS);
const NOTIFY_DROP_SET = new Set<string>(NOTIFY_DROP_KINDS);
const GOVERNANCE_KEY_SET = new Set<string>(GOVERNANCE_STAGES.flatMap((s) => GOVERNANCE_OUTCOME_CLASSES.map((c) => governanceFaultKey(s, c))));
const REFUSAL_SURFACE_SET = new Set<string>(REFUSAL_SURFACES);
const ADMIN_REFUSAL_KEY_SET = new Set<string>(ADMIN_REFUSAL_ROUTES.flatMap((r) => ADMIN_REFUSAL_REASONS.map((n) => adminRefusalKey(r, n))));

async function diag(storage: MockStorage): Promise<SchedDiagBundle> {
  return await readSchedDiag(storage);
}

// The auth-signal aggregate the pack already carries (section 4.18), read straight from DO storage.
async function authSignals(storage: MockStorage): Promise<Record<string, { count: number; lastAt: string }>> {
  return (await storage.get<Record<string, { count: number; lastAt: string }>>("authsignals:agg")) ?? {};
}

function caller(subject: string, email: string): { method: "access"; email: string; subject: string; role: "owner"; groups: string[]; sourceIp: null } {
  return { method: "access", email, subject, role: "owner", groups: [], sourceIp: null };
}

// ---------------------------------------------------------------------------------------------------------
// G090: the resolvers that SILENTLY write to a destination the customer did not choose. THE DATA-LOSS ONE.
// ---------------------------------------------------------------------------------------------------------
async function testDestResolveFallback(): Promise<void> {
  console.log("\ndestination-resolution fallbacks ('my backups are landing in the wrong bucket')");

  // The PURE predicate first: a list that is present but holds no usable entry is exactly the state
  // primaryDestinationId falls through on. An ABSENT list is the ordinary "follow the default" config and
  // must NOT be a fault (a false positive here would flag every single-destination tenant in the fleet).
  check("isMalformedDestList: a present-but-blank list is a fault", isMalformedDestList({ destinationIds: ["", "   "] }));
  check("isMalformedDestList: an absent list is NOT a fault (the common config)", !isMalformedDestList({ destinationId: "d1" }));
  check("isMalformedDestList: an empty list is NOT a fault", !isMalformedDestList({ destinationIds: [] }));
  check("isMalformedDestList: a usable list is NOT a fault", !isMalformedDestList({ destinationIds: ["d1"] }));

  // (1) MALFORMED LIST at run allocation. The downpipe's list is present and blank, so the run seals to the
  // env default instead. Plant the poison in the fields the config actually carries.
  // NOTE the provenance: validateConfig REFUSES a blank destinationIds entry at create, so this state can
  // only arise from a CORRUPTED or legacy stored row -- which is exactly the case the gap is about (nothing
  // downstream re-validates, primaryDestinationId just falls through). Plant it the way it really occurs: a
  // valid downpipe whose stored row is then corrupted underneath the engine.
  const { storage, stub } = makeScheduler();
  await stub.addDownpipe(makeConfig("dp-wrong-bucket", { name: `Prod KV ${POISON_VALUE}` }), caller("sub-owner", POISON_EMAIL));
  const stored = (await storage.get<{ config: Record<string, unknown> }>("dp:dp-wrong-bucket"))!;
  stored.config.destinationIds = ["", "  "]; // present, and holding nothing usable
  await storage.put("dp:dp-wrong-bucket", stored);
  await stub.trigger({ id: "dp-wrong-bucket" });

  // (2) DANGLING DEFAULT healed on read: the stored collection's defaultId names a destination that no longer
  // exists, so every downpipe following the default silently repoints to list[0].
  await storage.put("destinations", {
    list: [{ id: "d-live", label: POISON_BUCKET, endpoint: `https://${POISON_BUCKET}.s3.amazonaws.com`, bucket: POISON_BUCKET, accessKeyId: POISON_SECRET }],
    defaultId: "d-deleted",
  });
  await stub.loadDestinations();

  const d = await diag(storage);
  const rec = d.destResolveFallbacks;
  check("the malformed-list fallback is recorded at run allocation", (rec?.counts["malformed-list-fallback"]?.count ?? 0) >= 1);
  check("the dangling-default heal is recorded on read", (rec?.counts["dangling-default-healed"]?.count ?? 0) >= 1);
  check("the deviating downpipe is NAMED (its own id, the class downpipes[] already carries)", (rec?.recent ?? []).some((r) => r.downpipeId === "dp-wrong-bucket"));
  vocabClean("destResolveFallbacks", rec?.counts ?? {}, DEST_FALLBACK_SET);
  scanClean("destResolveFallbacks", rec);
}

// ---------------------------------------------------------------------------------------------------------
// G091: the canary's own losses -- abandoned flights, skipped results, destinations never flown.
// ---------------------------------------------------------------------------------------------------------
async function testCanaryLosses(): Promise<void> {
  console.log("\ncanary coverage and flight losses ('lastRunAt keeps sliding')");
  const { storage, stub } = makeScheduler();

  // (1) A LOST FLIGHT: a flight is in flight with an EXPIRED lease, so the next canaryDue abandons it and
  // allocates a fresh one -- the silent re-allocation behind a lastRunAt that never advances.
  await storage.put("canary", {
    config: { enabled: true, destinationIds: null, intervalSeconds: 3600 },
    status: "pending",
    lastRunAt: null,
    nextRunAt: 0,
    inFlight: true,
    inFlightSince: 1, // an ancient lease: expired
    runSeq: 4,
    dests: [],
    history: [],
  });
  await stub.canaryDue(Date.now());

  // (2) A MALFORMED RESULT ROW: one destination's result is unusable and is skipped, so THAT destination's
  // bird freezes on its last verdict forever while the aggregate keeps reporting healthy. The row carries the
  // poison, so the recorded evidence must not.
  await stub.canaryComplete({
    run: { runSeq: 5, dests: [{ runId: "r1", runSeq: 5, destinationId: null, cleanupRunId: null }] },
    results: [{ destinationId: null, status: null, deadReason: POISON_ERROR, bucket: POISON_BUCKET } as unknown],
  }).catch(() => {});

  // (3) A MALFORMED COMPLETION: the whole body is unusable, so EVERY destination's liveness update in that
  // flight is lost and the lease stays taken until it expires.
  await stub.canaryComplete({ run: undefined, results: POISON_ERROR }).catch(() => {});

  const d = await diag(storage);
  const rec = d.canaryLosses;
  check("the abandoned flight is recorded", (rec?.counts["lost-flight"]?.count ?? 0) >= 1);
  check("the skipped per-destination result is recorded", (rec?.counts["malformed-result"]?.count ?? 0) >= 1);
  check("the unusable completion body is recorded", (rec?.counts["malformed-completion"]?.count ?? 0) >= 1);
  vocabClean("canaryLosses", rec?.counts ?? {}, CANARY_LOSS_SET);
  scanClean("canaryLosses", rec);
}

// ---------------------------------------------------------------------------------------------------------
// + G097: the drill pipeline's silent discards, and the evidence trail that quietly diverges.
// ---------------------------------------------------------------------------------------------------------
async function testDrillDrops(): Promise<void> {
  console.log("\nG059/restore-test + fleet-drill drops ('stuck at 3 remaining for two days')");
  const { storage, stub } = makeScheduler();
  await stub.addDownpipe(makeConfig("dp-live"), caller("sub-owner", POISON_EMAIL));

  // The oom / deepVerify members are DECLARED shapes on completeRestoreTest, and these vectors send values
  // that deliberately violate them (that is the fault being exercised: the DO receives garbage off the wire).
  // The declared shapes are derived from the DO signature rather than restated, so a src drift resurfaces
  // here as a type error instead of a fixture that quietly stops matching the real boundary. The cast is
  // compile-time only: the RUNTIME payloads below are the poison, untouched.
  type RestoreTestReq = Parameters<typeof stub.completeRestoreTest>[0];
  type OomField = NonNullable<RestoreTestReq["oom"]>;
  type DeepVerifyField = NonNullable<RestoreTestReq["deepVerify"]>;

  // (1) A COMPLETION FOR A DOWNPIPE THAT NO LONGER EXISTS: the drill RAN and its verdict is thrown away.
  await stub.completeRestoreTest({ id: `dp-renamed-${POISON_VALUE}`, ok: true });

  // (2) A MALFORMED OOM MEASUREMENT: the isolate-OOM early warning silently stops advancing. The measurement
  // carries the poison; the counter must not.
  await stub.completeRestoreTest({ id: "dp-live", ok: true, oom: { maxRecordBytes: POISON_ERROR, safeBytes: -1 } as unknown as OomField });

  // (3) A MALFORMED DEEP-VERIFY CURSOR: the rotating full-decrypt coverage stalls on the same window forever.
  await stub.completeRestoreTest({ id: "dp-live", ok: true, deepVerify: { runId: POISON_OBJECT_KEY, cursor: "NaN", records: -3 } as unknown as DeepVerifyField });

  // (4) A PASSED RESTORABILITY PROOF DROPPED: affirmative evidence the customer paid a full blind restore to
  // produce, discarded because the downpipe was deleted.
  await stub.recordRestoreProven({ downpipeId: "dp-gone", method: "blind-test", runId: "run-1" }, caller("sub-owner", POISON_EMAIL));

  // (5) G097: a drill-evidence append REFUSED by validation. The dated trail the customer's auditor reads now
  // silently has a hole. The note carries the poison.
  await stub.recordDrillEvidence({ runId: "", kind: "in-account", note: POISON_SECRET }, caller("sub-owner", POISON_EMAIL)).catch(() => {});

  const d = await diag(storage);
  check("a completion for an unknown downpipe is recorded (the verdict was thrown away)", (d.drillDrops["completion-unknown-downpipe"]?.count ?? 0) >= 1);
  check("a malformed OOM measurement is recorded (the early warning stopped advancing)", (d.drillDrops["malformed-oom"]?.count ?? 0) >= 1);
  check("a malformed deep-verify cursor is recorded (coverage stalled)", (d.drillDrops["malformed-cursor"]?.count ?? 0) >= 1);
  check("a DROPPED restorability PROOF is recorded", (d.drillDrops["proof-dropped"]?.count ?? 0) >= 1);
  check("a refused drill-evidence append is recorded (the trail's hole explains itself)", (d.drillDrops["evidence-refused"]?.count ?? 0) >= 1);
  check("the refusal is also counted on the admin-refusal surface", (d.adminRefusals[adminRefusalKey("drill-evidence", "shape-rejected")]?.count ?? 0) >= 1);
  vocabClean("drillDrops", d.drillDrops, DRILL_DROP_SET);
  scanClean("G059/drillDrops", d.drillDrops);
}

// ---------------------------------------------------------------------------------------------------------
// G060: WHICH alert died, not just how many.
// ---------------------------------------------------------------------------------------------------------
async function testNotifyDrops(): Promise<void> {
  console.log("\nnotify drop ring ('my backup-failure alert never arrived')");
  const { storage, stub } = makeScheduler();

  // A REJECTED emission whose IDENTIFYING fields (event/severity/downpipeId) are perfectly valid and whose
  // free-text DETAIL is what failed the parse. The ring must name the dead alert and carry NONE of the detail.
  const poisonEmission = {
    event: "backup-failure",
    severity: "critical",
    downpipeId: "dp-prod",
    downpipeName: "Prod KV",
    detail: `${POISON_ERROR} ${POISON_SECRET} ${"x".repeat(5000)}`, // over-long + poisonous: rejected
    at: "2026-07-11T00:00:00.000Z",
  };
  await stub.resolveNotify({ emission: poisonEmission });
  await stub.recordNotify({ emission: poisonEmission, records: [] });

  // A DIGEST CLEAR that could not act on its id: the entry the cron JUST DELIVERED is not cleared, so the SAME
  // digest is delivered again next window, and the one after that.
  await stub.digestSent({ ids: [POISON_OBJECT_KEY, -1] });

  const d = await diag(storage);
  const rec = d.notifyDrops;
  check("the rejected emission is counted", (rec?.counts["parse-reject"]?.count ?? 0) >= 2);
  check("the DEAD ALERT is NAMED by its closed event", (rec?.recent ?? []).some((r) => r.event === "backup-failure"));
  check("the dead alert carries its severity + downpipe (the history ring's own classes)", (rec?.recent ?? []).some((r) => r.severity === "critical" && r.downpipeId === "dp-prod"));
  check("the unclearable digest id is counted (the duplicate-delivery loop)", (rec?.counts["digest-clear-failed"]?.count ?? 0) >= 1);
  check("a drop with no nameable alert adds NO ring row (a broken config cannot flood the ring)", (rec?.recent ?? []).every((r) => r.dropKind !== "digest-clear-failed"));
  vocabClean("notifyDrops", rec?.counts ?? {}, NOTIFY_DROP_SET);
  scanClean("notifyDrops", rec);
}

// ---------------------------------------------------------------------------------------------------------
// + G037: governance apply attempts, tamper/replay, and the last-only refusal counters.
// ---------------------------------------------------------------------------------------------------------
async function testGovernanceAndRefusals(): Promise<void> {
  console.log("\nG034/governance faults + refusal rings ('our second owner approved and nothing happened')");

  // The PURE classifiers first: each reads a poisoned message ONLY to SELECT an enum member and RETURNS that
  // member. This is the redaction contract for every classifier in the engine, so pin it directly.
  const tamper = classifyGovernanceOutcome(new Error(`the change record failed its integrity check: ${POISON_ERROR}`));
  const replay = classifyGovernanceOutcome(new Error(`the approval was already used by ${POISON_EMAIL}`));
  const guard = classifyGovernanceOutcome(new Error(`forbidden: only an Owner may approve (${POISON_EMAIL})`));
  const faulted = classifyGovernanceOutcome(new Error(POISON_ERROR));
  check("an integrity failure classifies to integrity-failed", tamper === "integrity-failed");
  check("a spent one-shot approval classifies to replay-detected", replay === "replay-detected");
  check("a guard refusal classifies to guard-refused (foreseeable, not a bug)", guard === "guard-refused");
  check("an unexpected throw classifies to apply-faulted (a bug, not a policy)", faulted === "apply-faulted");
  check("every classifier RETURNS an enum member, never the message", [tamper, replay, guard, faulted].every((c) => (GOVERNANCE_OUTCOME_CLASSES as readonly string[]).includes(c)));
  scanClean("classifyGovernanceOutcome outputs", [tamper, replay, guard, faulted]);

  const snap = classifySnapshotFailure(new Error(`could not import the signing key: ${POISON_SECRET}`));
  check("a signing-key snapshot failure classifies to signing-key (NO config can ever be versioned)", snap === "signing-key");
  check("classifySnapshotFailure returns an enum member", (SNAPSHOT_FAILURE_CLASSES as readonly string[]).includes(snap));
  scanClean("classifySnapshotFailure output", snap);

  // The LIVE path: a licence activation retried with THREE DIFFERENT CAUSES. The last-only counter keeps one
  // code; the ring must keep the sequence -- which is the thing that actually diagnoses it.
  const { storage, stub } = makeScheduler();
  await stub.recordLicenceActivationRefusal({ reasonCode: "expired" });
  await stub.recordLicenceActivationRefusal({ reasonCode: "signature" });
  await stub.recordLicenceActivationRefusal({ reasonCode: `pin-invalid-${POISON_TOKEN}` }); // out-of-vocab: dropped
  await stub.recordLicenceActivationRefusal({ reasonCode: "malformed-token" });

  // And the DO-side SHAPE reject, which used to bypass the refusal counter entirely (the invisible branch:
  // the ROUTER posts its own refusals to the counter, so a token the router accepted and the DO then rejected
  // on shape touched NOTHING at all). Seat an owner so the DO's owner re-check passes and we reach the shape
  // guard that is actually under test.
  await storage.put("role:sub:sub-owner", { subject: "sub-owner", email: POISON_EMAIL, role: "owner", grantedBy: "bootstrap", grantedAt: "2026-07-01T00:00:00.000Z" });
  await stub.setLicenceToken({ token: POISON_TOKEN }, caller("sub-owner", POISON_EMAIL)).catch(() => {});

  const d = await diag(storage);
  const ring = d.refusalRings["licence-activation"] ?? [];
  check("the licence refusal ring keeps the SEQUENCE, not just the last code", ring.length >= 3);
  check("the ring holds the distinct causes (expired, signature, malformed-token)", ["expired", "signature", "malformed-token"].every((c) => ring.some((r) => r.code === c)));
  check("an out-of-vocabulary reason code never reaches the ring", !ring.some((r) => r.code.includes("dpk_live")));
  check("the DO-side licence SHAPE reject now reaches the counter (it used to bypass it entirely)", ring.filter((r) => r.code === "malformed-token").length >= 2);
  vocabClean("refusalRings", d.refusalRings, REFUSAL_SURFACE_SET);
  scanClean("refusalRings", d.refusalRings);
  scanClean("governanceFaults", d.governanceFaults);
  vocabClean("governanceFaults", d.governanceFaults, GOVERNANCE_KEY_SET);
}

// ---------------------------------------------------------------------------------------------------------
// + G146: the engine-computed refusal the browser showed once and forgot.
// ---------------------------------------------------------------------------------------------------------
async function testAdminRefusals(): Promise<void> {
  console.log("\nG126/admin refusals ('I cannot get past Verify and save' / 'I cannot remove this destination')");

  // The PURE classifier: it reads the engine's own refusal prose (and the store's sanitised error code) ONLY
  // to select a closed reason, and returns THAT. Ordering is load-bearing: a read-only key must never coarsen
  // to "invalid config", and the only-proven-copy guard must never coarsen to anything.
  const auth = classifyDestProbeRefusal(new Error(`AccessDenied writing to ${POISON_BUCKET}/${POISON_OBJECT_KEY} with ${POISON_SECRET}`));
  const lock = classifyDestProbeRefusal(new Error(`ObjectLock retention mismatch on ${POISON_BUCKET}`));
  const orphan = classifyDestProbeRefusal(new Error(`destination is the only proven copy of 4 backed-up run(s) (${POISON_VALUE})`));
  const https = classifyDestProbeRefusal(new Error("the destination endpoint must be an https URL"));
  check("a rotated/denied credential classifies to auth-refused (re-enter the key)", auth === "auth-refused");
  check("an Object-Lock refusal classifies to object-lock-mismatch (a policy decision, never a retry)", lock === "object-lock-mismatch");
  check("the only-proven-copy guard classifies to orphan-guard (THE data-loss guard)", orphan === "orphan-guard");
  check("a non-https endpoint classifies to endpoint-not-https", https === "endpoint-not-https");
  check("every classifier output is a closed member", [auth, lock, orphan, https].every((r) => (ADMIN_REFUSAL_REASONS as readonly string[]).includes(r)));
  scanClean("classifyDestProbeRefusal outputs", [auth, lock, orphan, https]);

  // The LIVE path: a destination save refused by a validator, with the poison in every submitted field.
  // The DO re-resolves the caller's role from its OWN tables (defence in depth), so seat a real owner first --
  // otherwise the owner gate refuses before the validator ever runs, and this block would test the wrong thing.
  const { storage, stub } = makeScheduler();
  await storage.put("role:sub:sub-owner", { subject: "sub-owner", email: POISON_EMAIL, role: "owner", grantedBy: "bootstrap", grantedAt: "2026-07-01T00:00:00.000Z" });
  await stub
    .putDest(
      { label: POISON_BUCKET, config: { endpoint: `http://${POISON_BUCKET}.internal`, bucket: POISON_BUCKET, region: "us-east-1", accessKeyId: POISON_SECRET, secretAccessKey: POISON_SECRET } },
      caller("sub-owner", POISON_EMAIL),
    )
    .catch(() => {});

  // And a "fly now" against a disabled canary (the other end of the same class of ticket).
  await storage.put("canary", { config: { enabled: false, destinationIds: null, intervalSeconds: 3600 }, status: "disabled", lastRunAt: null, nextRunAt: null, inFlight: false, runSeq: 0, dests: [], history: [] });
  await stub.canaryRunNow().catch(() => {});

  const d = await diag(storage);
  check("the refused destination save is counted by closed route x closed reason", Object.keys(d.adminRefusals).some((k) => k.startsWith("dest-set|")));
  check("the refused canary fly-now is counted", (d.adminRefusals[adminRefusalKey("canary-run", "disabled")]?.count ?? 0) >= 1);
  vocabClean("adminRefusals", d.adminRefusals, ADMIN_REFUSAL_KEY_SET);
  scanClean("G126/adminRefusals", d.adminRefusals);
}

// ---------------------------------------------------------------------------------------------------------
// + + G168: enrolment refusals, RBAC degradation, session lifecycle. All ride the auth-signal
// aggregate the pack ALREADY carries (section 4.18), so they need no new plumbing.
// ---------------------------------------------------------------------------------------------------------
async function testAuthSignalGaps(): Promise<void> {
  console.log("\nG005/G061/enrolment, RBAC and session signals (all on the existing authSignals aggregate)");
  const { storage, stub } = makeScheduler();

  // --- G005: the invite lifecycle. The EXPIRED case is the one that mattered: the record is deleted-then-
  // refused, so afterwards NOTHING proved the invite ever existed. It must be recorded BEFORE the burn.
  await storage.put(`passkeyInvite:${POISON_TOKEN}`, { token: POISON_TOKEN, email: POISON_EMAIL, expiresAt: 1 }); // long expired
  const consumed = await stub.consumeInvite(POISON_TOKEN, Date.now());
  check("an EXPIRED invite is still refused (behaviour unchanged)", consumed === null);
  await stub.consumeInvite("this-token-was-never-minted", Date.now());
  await stub.peekInvite("", Date.now());

  // A first-Owner mint refused because the one-shot latch is spent: the documented "email the owner a link"
  // button is permanently inert and told nobody.
  await stub.writeOrgPolicy({ bootstrapConsumed: true }); // the one-shot latch, spent
  const minted = await stub.mintBootstrapInvite(POISON_EMAIL, Date.now());
  check("a spent bootstrap latch still refuses the mint (behaviour unchanged)", minted === null);

  // --- G061: a role row that will not parse is filtered out of authority resolution -- the member VANISHES.
  await storage.put("role:sub:corrupt", { subject: "", role: `owner-${POISON_VALUE}`, email: POISON_EMAIL });
  await stub.listRoleEntries();

  // A JIT elevation whose expiresAt does not PARSE fails OPEN: the temporary owner is now permanent.
  const failOpen = stub.effectiveRole({ subject: "s", email: POISON_EMAIL, role: "owner", grantedBy: "x", grantedAt: "y", expiresAt: POISON_VALUE }, Date.now());
  check("an unparseable expiry FAILS OPEN (behaviour unchanged: malformed data must not revoke)", failOpen === "owner");

  // The owner TAMPER-CLAMP: a stored group mapping that CLAIMS owner is clamped. It fired silently.
  const clamped = stub.capGroupRole("owner");
  check("the owner clamp still clamps (behaviour unchanged)", clamped !== "owner");

  // --- G168: THE HEADLINE. The session signing key is absent/corrupt and is regenerated, so every live
  // session in the account instantly stops verifying: a MASS LOGOUT with no terminate-all in the audit chain.
  await storage.put("passkeySessionKey", { key: "!!!not-base64url!!!", createdAt: "2026-07-01T00:00:00.000Z" });
  await stub.sessionSigningKey();

  // The verify-failure SPIKE that PAIRS with it -- the pair support could never assemble.
  await stub.passkeySessionVerify({ token: `${POISON_TOKEN}.${POISON_SECRET}` });

  // A logout that revoked NOTHING: the user is told they signed out and their token is still live.
  await stub.passkeySessionLogout({ token: "a-token-that-does-not-verify" });

  const sig = await authSignals(storage);
  // G005
  check("the EXPIRED invite is recorded BEFORE the burn (the proof it existed survives)", (sig["invite-redeem-refused-expired"]?.count ?? 0) >= 1);
  check("an absent invite is a DISTINCT class from an expired one", (sig["invite-redeem-refused-absent"]?.count ?? 0) >= 1);
  check("a malformed invite token is its own class", (sig["invite-redeem-refused-malformed"]?.count ?? 0) >= 1);
  check("the spent-latch mint refusal is recorded (the permanently inert button)", (sig["invite-mint-refused-latch-consumed"]?.count ?? 0) >= 1);
  // G061
  check("the dropped malformed role row is recorded (the member who VANISHED)", (sig["rbac-malformed-role-row-dropped"]?.count ?? 0) >= 1);
  check("the unparseable-expiry FAIL-OPEN is recorded (the elevation that never lapses)", (sig["rbac-expiry-unparseable-fail-open"]?.count ?? 0) >= 1);
  check("the owner tamper-clamp firing is recorded", (sig["rbac-owner-clamp-fired"]?.count ?? 0) >= 1);
  // G168
  check("the SILENT session-signing-key regeneration is recorded (the mass logout, as a FACT)", (sig["session-signing-key-regenerated"]?.count ?? 0) >= 1);
  check("the verify-failure spike is recorded (the other half of the key-lost diagnosis)", (sig["session-verify-failed"]?.count ?? 0) >= 1);
  check("a no-op logout is recorded (the user believes they signed out)", (sig["session-logout-noop"]?.count ?? 0) >= 1);

  vocabClean("G005/G061/authSignals", sig, AUTH_SIGNAL_SET);
  scanClean("G005/G061/authSignals", sig);
}

// ---------------------------------------------------------------------------------------------------------
// DEAD VOCABULARY: the auth-signal members that were DECLARED and had no producer, so the pack
// promised a support engineer an answer nothing could ever put there. Each block below drives the REAL entry
// point (the DO route / the resolution path the product actually takes) and asserts the signal now lands. A
// hand-written record posted into the recorder would prove only that the aggregate can carry the name; it is
// the self-certifying test that let these rot, and it is deliberately not what any of these do.
// ---------------------------------------------------------------------------------------------------------
async function testDeadAuthSignalProducers(): Promise<void> {
  console.log("\nDEAD-VOCAB auth signals: the declared members that nothing could emit");

  // --- rbac-groups-param-unparseable. THE REAL ENTRY POINT: whoami, the DO route behind every authenticated
  // request (GET /whoami?groups=...). A corrupt groups param coerces to [] and EVERY group->role mapping in
  // the account stops resolving at once -- "all our AD-group users dropped to viewer" -- and it was silent.
  {
    const { storage, stub } = makeScheduler();
    await storage.put("role:sub:sub-owner", { subject: "sub-owner", email: POISON_EMAIL, role: "owner", grantedBy: "bootstrap", grantedAt: "2026-07-01T00:00:00.000Z" });
    const notJson = await stub.whoami("member@example.com", "sub-member", "access", `${POISON_VALUE}[not json`);
    check("groups-param: a param that is not JSON still coerces to no-groups (behaviour unchanged)", notJson.groups.length === 0);
    const notArray = await stub.whoami("member@example.com", "sub-member", "access", '{"groups":"admins"}');
    check("groups-param: a param that is JSON but not an array still coerces to no-groups (behaviour unchanged)", notArray.groups.length === 0);
    // NOISE GUARD: the legitimate no-groups caller (an absent param) must NOT be recorded as a fault.
    await stub.whoami("member@example.com", "sub-member", "access", null);
    await stub.whoami("member@example.com", "sub-member", "access", '["engineering"]');

    const sig = await authSignals(storage);
    check("the coerced-to-[] groups param is recorded (every group mapping silently stopped resolving)", (sig["rbac-groups-param-unparseable"]?.count ?? 0) >= 1);
    check("the groups recorder does not fire on a legitimate absent/valid groups param", (sig["rbac-groups-param-unparseable"]?.count ?? 0) <= 2);
    vocabClean("groups-param authSignals", sig, AUTH_SIGNAL_SET);
    scanClean("groups-param authSignals", sig);
  }

  // --- rbac-empty-table-with-latch. THE DEADLOCK: no role row anywhere AND the one-shot bootstrap latch is
  // spent, so nobody holds authority and nobody can claim it. In a pack this was byte-identical to "an account
  // whose members happen to all be viewers", and the two have completely different remedies.
  // THE REAL ENTRY POINT: whoami (every sign-in), and resolveRegistrationAuthorisation (every enrolment).
  {
    const { storage, stub } = makeScheduler();
    await stub.writeOrgPolicy({ bootstrapConsumed: true }); // the latch, spent; the role table is empty
    const who = await stub.whoami(POISON_EMAIL, "sub-first", "access", null);
    check("empty-table+latch: the caller still resolves to least-privilege viewer (behaviour unchanged)", who.role === "viewer");
    const auth = await stub.resolveRegistrationAuthorisation(POISON_EMAIL, { authMethod: "token", bootstrapAuthorised: true }, Date.now());
    check("empty-table+latch: a first-Owner passkey enrolment is still refused (behaviour unchanged)", auth === null);

    const sig = await authSignals(storage);
    check("the bootstrap DEADLOCK is recorded (nobody has authority and nobody can bootstrap)", (sig["rbac-empty-table-with-latch"]?.count ?? 0) >= 1);
    vocabClean("empty-table+latch authSignals", sig, AUTH_SIGNAL_SET);
    scanClean("empty-table+latch authSignals", sig);
  }

  // --- rbac-malformed-pending-row-dropped + rbac-provenance-fabricated. THE REAL ENTRY POINT: GET /roles, the
  // DO route the people screen loads. A pending row that will not parse is filtered out and the invitee can
  // NEVER bind; a row with no usable provenance is read as granted by "unknown" at the time of THIS READ, so
  // the audit answer to "who granted this, and when?" is an engine guess presented as a fact.
  {
    const { storage, stub } = makeScheduler();
    await storage.put("role:pending:corrupt@example.com", { email: POISON_EMAIL, role: `operator-${POISON_VALUE}` }); // role does not parse: DROPPED
    await storage.put("role:pending:noprov@example.com", { email: "noprov@example.com", role: "operator" }); // no grantedBy / grantedAt: FABRICATED
    const res = await stub.fetch(new Request("https://do/roles", { method: "GET" }));
    const rows = (await res.json()) as { email: string; grantedBy: string }[];
    check("people screen: the malformed pending row is still filtered out (behaviour unchanged)", !rows.some((r) => r.email === "corrupt@example.com"));
    check("people screen: the provenance-less row is still shown with a substituted grantedBy (behaviour unchanged)", rows.some((r) => r.email === "noprov@example.com" && r.grantedBy === "unknown"));

    const sig = await authSignals(storage);
    check("the dropped malformed PENDING row is recorded (the invitee who can never bind)", (sig["rbac-malformed-pending-row-dropped"]?.count ?? 0) >= 1);
    check('the FABRICATED provenance is recorded (the audit answer to "who granted this?" is an engine guess)', (sig["rbac-provenance-fabricated"]?.count ?? 0) >= 1);
    vocabClean("people-screen authSignals", sig, AUTH_SIGNAL_SET);
    scanClean("people-screen authSignals", sig);
  }

  // --- invite-redeem-refused-token-mismatch. The bootstrap slot is ONE fixed key that minting OVERWRITES, so
  // re-sending the first-Owner link silently invalidates every earlier one. The owner clicks the link in the
  // older email, is told it is invalid, and a perfectly valid invite is sitting in the slot. That is not an
  // absent invite and not an expired one: it is its own remedy ("open the newest email").
  // THE REAL ENTRY POINT: peekBootstrapInvite, which register/begin calls with the token from the link.
  {
    const { storage, stub } = makeScheduler();
    const first = await stub.mintBootstrapInvite("owner@example.com", Date.now());
    check("bootstrap invite: the first link mints (behaviour unchanged)", typeof first === "string" && first.length > 0);
    const second = await stub.mintBootstrapInvite("owner@example.com", Date.now()); // the RE-SEND overwrites the slot
    check("bootstrap invite: the re-send mints a NEW link (behaviour unchanged)", typeof second === "string" && second !== first);
    const stale = await stub.peekBootstrapInvite(first as string, Date.now());
    check("bootstrap invite: the SUPERSEDED link is still refused (behaviour unchanged)", stale === null);
    const live = await stub.peekBootstrapInvite(second as string, Date.now());
    check("bootstrap invite: the current link still works (the recorder did not fire on a legitimate redeem)", live === "owner@example.com");

    const sig = await authSignals(storage);
    check("the superseded first-Owner link is recorded as a TOKEN MISMATCH (not an absent invite)", (sig["invite-redeem-refused-token-mismatch"]?.count ?? 0) === 1);
    vocabClean("bootstrap-invite authSignals", sig, AUTH_SIGNAL_SET);
    scanClean("bootstrap-invite authSignals", sig);
  }
}

// ---------------------------------------------------------------------------------------------------------
// G172-(+ G097's console half): the engine sink for the console's OWN diagnostic ring. The body is
// BROWSER-AUTHORED and therefore UNTRUSTED: this is the redaction chokepoint, and it is the one that matters
// most, because everything a browser knows is a message, a stack, a screen name or a URL.
// ---------------------------------------------------------------------------------------------------------
async function testClientDiagnostics(): Promise<void> {
  console.log("\nG172-client diagnostics (the console's ring, SIGNED INTO the pack -- no beacon)");
  const { storage, stub } = makeScheduler();

  // A HOSTILE body: every field a compromised or buggy console might post, with the poison in each. The
  // applier must keep the closed-vocabulary members and DROP everything else -- including through map KEYS.
  const hostile = {
    consoleBuildId: "1.4.7",
    crashes: { boot: 3, [`render-${POISON_OBJECT_KEY}`]: 9, "chunk-load": 1 },
    faults: { "evidence-write-failed": 2, "worker-unhandled-500": 1, [POISON_SECRET]: 99 },
    skew: [
      { routeFamily: "dual-control", skewKind: "route-missing", count: 4 },
      { routeFamily: POISON_BUCKET, skewKind: "route-missing" }, // out-of-vocab family: DROPPED
      { routeFamily: "restore", skewKind: POISON_ERROR }, // out-of-vocab kind: DROPPED
    ],
    bulkOutcomes: [
      {
        op: "bulk-create",
        attempted: 1000,
        succeeded: 300,
        failed: 700,
        halted: true,
        timedOut: false,
        pollFailures: 2,
        failedByClass: { "rate-limited": 500, "halted-401": 200, [POISON_EMAIL]: 7 },
        itemNames: [POISON_OBJECT_KEY, POISON_BUCKET], // an unread field: must never be persisted
        errorMessage: POISON_ERROR, // ditto
      },
      { op: `bulk-protect-${POISON_VALUE}`, attempted: 5 }, // out-of-vocab op: DROPPED
    ],
    settleJourneys: [
      { terminalState: "stalled", settleAttempts: 30, statusReadFailures: 4, pollAttempts: 30, pollCeilingHit: true, unexpectedOutcome: true, rawOutcome: POISON_ERROR },
      { terminalState: POISON_VALUE }, // out-of-vocab terminal state: DROPPED
    ],
    stack: POISON_ERROR, // a whole unread top-level field
    screen: POISON_OBJECT_KEY,
  };
  await recordClientDiagnostics(storage, hostile);
  // And through the real DO route the console actually calls.
  await stub.fetch(new Request("https://do/client-diag", { method: "POST", body: JSON.stringify(hostile) }));

  const d = await diag(storage);
  const c = d.clientDiagnostics;
  check("a boot crash is recorded by closed phase", (c?.crashes["boot"]?.count ?? 0) >= 3);
  check("an out-of-vocabulary crash phase is DROPPED (a browser string can never become a key)", Object.keys(c?.crashes ?? {}).every((k) => (CLIENT_CRASH_PHASES as readonly string[]).includes(k)));
  check("a console-Worker 500 is recorded", (c?.faults["worker-unhandled-500"]?.count ?? 0) >= 1);
  check("the console-side evidence-write failure is recorded (the half the engine never sees)", (c?.faults["evidence-write-failed"]?.count ?? 0) >= 2);
  check("an out-of-vocabulary fault kind is DROPPED", Object.keys(c?.faults ?? {}).every((k) => (CLIENT_FAULT_KINDS as readonly string[]).includes(k)));
  check("the contract skew is recorded as routeFamily|skewKind", (c?.skew["dual-control|route-missing"]?.count ?? 0) >= 4);
  check("an out-of-vocabulary route family or skew kind is DROPPED", Object.keys(c?.skew ?? {}).every((k) => {
    const [fam, kind] = k.split("|");
    return (CLIENT_ROUTE_FAMILIES as readonly string[]).includes(fam ?? "") && (CLIENT_SKEW_KINDS as readonly string[]).includes(kind ?? "");
  }));
  check("the console BUILD ID rides (the skew PAIR's other half; engine.version is already in the pack)", c?.consoleBuildId === "1.4.7");
  const bulk = (c?.bulkOutcomes ?? []).find((b) => b.op === "bulk-create");
  check("G172/the bulk casualty summary is recorded ('created only 300 of 1000 then logged me out')", bulk !== undefined && bulk.attempted === 1000 && bulk.succeeded === 300 && bulk.halted === true);
  check("the failure classes are closed-set only", Object.keys(bulk?.failedByClass ?? {}).every((k) => (CLIENT_BULK_FAIL_CLASSES as readonly string[]).includes(k)));
  check("an out-of-vocabulary bulk op is DROPPED", (c?.bulkOutcomes ?? []).every((b) => (CLIENT_BULK_OPS as readonly string[]).includes(b.op)));
  const settle = (c?.settleJourneys ?? []).find((j) => j.terminalState === "stalled");
  check("the update settle journey is recorded ('always hangs at Still verifying')", settle !== undefined && settle.pollCeilingHit === true && settle.settleAttempts === 30);
  check("an out-of-vocabulary terminal state is DROPPED", (c?.settleJourneys ?? []).every((j) => (CLIENT_SETTLE_STATES as readonly string[]).includes(j.terminalState)));

  // THE ONE THAT MATTERS: a browser knows nothing BUT messages, stacks, screen names and URLs, so if the
  // chokepoint leaks anywhere, it leaks here.
  scanClean("G172-clientDiagnostics (from a HOSTILE browser-authored body)", c);

  // And the applier is pure: the same hostile body against no prior record must be equally clean.
  scanClean("G172-applyClientDiagnostics (pure)", applyClientDiagnostics(undefined, hostile, "2026-07-11T00:00:00.000Z"));
  check("G172-a non-object body is a no-op, never a throw", JSON.stringify(applyClientDiagnostics(undefined, POISON_ERROR, "2026-07-11T00:00:00.000Z").crashes) === "{}");
}

// ---------------------------------------------------------------------------------------------------------
// The DROPPED-WRITE invariant (G104): a recorder whose OWN write fails must COUNT that loss, because a pack
// that under-counts during the outage it exists to explain is the bug this whole audit is about.
// ---------------------------------------------------------------------------------------------------------
async function testDroppedWrites(): Promise<void> {
  console.log("\nthe new recorders' own dropped writes (a pack that under-counts must SAY so)");
  const { storage, stub } = makeScheduler();

  // Break storage.put, drive a fault, then heal it. The loss must land the moment the store comes back.
  const realPut = storage.put.bind(storage);
  let broken = true;
  storage.put = async (k: string, v: unknown): Promise<void> => {
    if (broken && String(k).startsWith("diag:")) throw new Error(`storage unavailable: ${POISON_ERROR}`);
    return realPut(k, v);
  };
  await stub.canaryComplete({ run: undefined, results: [] }).catch(() => {});
  broken = false;
  await stub.canaryComplete({ run: undefined, results: [] }).catch(() => {});

  const d = await diag(storage);
  check("a DROPPED canary-loss write is itself counted (the pack's under-count caveat)", (d.droppedWrites["canary-loss"]?.count ?? 0) >= 1);
  scanClean("droppedWrites", d.droppedWrites);
}

// ---------------------------------------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("SCHEDULER-DO pipeline / governance / enrolment evidence");
  await testDestResolveFallback();
  await testCanaryLosses();
  await testDrillDrops();
  await testNotifyDrops();
  await testGovernanceAndRefusals();
  await testAdminRefusals();
  await testAuthSignalGaps();
  await testDeadAuthSignalProducers();
  await testClientDiagnostics();
  await testDroppedWrites();

  const failures = getFailures();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${failures} failure(s)`);
  if (failures > 0) process.exit(1);
}

await main();
