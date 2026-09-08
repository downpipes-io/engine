// SCHEDULER-DO recovery / dual-control / skew evidence validator.
//
// These five gaps share the shape the whole audit is about: the scheduler DO ABSORBS a fault (a closed-set
// gate drops an unknown token, a fail-open observe swallows a throw, a refusal is thrown as prose to one
// operator's screen, a tolerant resume skips a downpipe, a defensive read coerces a corrupt value to a safe
// default) and the fact of it existed nowhere a support pack could carry. Each block below proves the same
// two things the audit demands of every new recording:
//
//   (a) RECORDED ON THE FAULT PATH: the evidence is written WHEN the fault happens (never on a happy path),
//       and it is readable back through the DO's support-pack read (GET /sched-diag / readSchedDiag).
//   (b) REDACTION-SAFE (binding, NO-CUSTODY): a customer value, a secret, a raw error message and a bucket
//       name PLANTED at each fault site NEVER appear in the recorded evidence, and every key the evidence
//       carries is drawn from the closed vocabularies declared in src/sched/sched-fault-ledger.ts.
//
// The gaps, and the ticket each one makes diagnosable:
//   After a PARTIAL update: new-kind seal faults fire every run yet the pack's ring stays empty, failed
//        webhooks arrive with no deliveryCode, and a new deferral kind makes a drill that COULD NOT RUN read
//        as "tested and failed". Every one of those was a closed-set gate dropping a token without counting.
//   "our SAML cert expired with no warning" / "the console stopped warning about our licence expiry":
//        the observation was rejected, threw, or carried no usable date, months earlier, in silence.
//   "prove nobody tried to self-approve a restore", "our veto kept failing and the apply went through",
//        and the accounting hole: a SUCCESSFUL apply whose consume found its lease reclaimed, so one approval
//        may have authorised two applies and nothing recorded it.
//   After a DR auto-heal: "one of my backups never came back" (which one, and why), "backups land in an
//        unexpected bucket" (a dangling default silently re-pointed), "our WORM retention vanished" (an
//        import validator dropped it), and a recovery stalled forever on a refusal with no recorded class.
//   The silent self-heals: an audit head pointer rebuilt, a lost rollover record, a CPU-killed verify, a
//        corrupt idpEpoch coerced to 0 (a REVOCATION BYPASS), an emergency tally reset to zero, and a roster
//        repair discarding a divergent claimant's config.
//
// Run: node test/validate-sched-recovery-evidence.ts

import { AUDIT_HEAD_KEY, AUDIT_VERIFY_META_KEY } from "../src/sched/scheduler-do-base.ts";
import {
  APPROVAL_REFUSAL_CLASSES,
  APPROVAL_STAGES,
  EXPIRY_FAULT_CLASSES,
  EXPIRY_ITEM_CLASSES,
  IMPORT_DROP_FIELDS,
  RESUME_SKIP_CLASSES,
  STAGED_APPLY_REFUSAL_CLASSES,
  STORAGE_ANOMALY_KINDS,
  VOCAB_DROP_SURFACES,
  approvalFaultKey,
  classifyApprovalRefusal,
  classifyExpiryItem,
  classifyResumeSkip,
  expiryFaultKey,
  readSchedDiag,
  type SchedDiagBundle,
} from "../src/sched/sched-fault-ledger.ts";
import type { ControlPlaneMixin } from "../src/sched/scheduler-do-control-plane.ts";
import type { ObservabilityMixin } from "../src/sched/scheduler-do-observability.ts";
import { type MockStorage, bindApprovalPrincipals, getFailures, makeConfig, makeScheduler, ok } from "./validate-scheduler-shared.ts";
import { notePlanAnchor } from "./testutil.ts";

declare const process: { exit(code?: number): never };

// The POISON values planted at every fault site. Each is a class the ledger must NEVER carry: a customer
// email, a bearer secret, a raw thrown message, a destination bucket, and an operator's own config value.
const POISON_EMAIL = "cfo@customer-example.com";
const POISON_SECRET = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI";
const POISON_ERROR = "connect ECONNREFUSED 10.4.2.7:443 while reading s3://acme-prod-backups/2026/07";
const POISON_BUCKET = "acme-prod-backups";
const POISON_VALUE = "customer-secret-schedule-note";
const POISONS = [POISON_EMAIL, POISON_SECRET, POISON_ERROR, POISON_BUCKET, POISON_VALUE, "ECONNREFUSED", "10.4.2.7", "customer-example"];

// scanClean is the redaction assertion: the SERIALISED evidence must contain no planted value. It scans the
// whole record (keys and values alike), so a leak through a map KEY (the classic closed-vocabulary bypass)
// fails just as loudly as a leak through a value.
function scanClean(label: string, evidence: unknown): void {
  const json = JSON.stringify(evidence ?? null);
  const hit = POISONS.find((p) => json.includes(p));
  ok(`${label}: redaction-safe (no customer value, secret, raw error or bucket)`, hit === undefined);
  if (hit !== undefined) console.log(`       leaked: ${hit}\n       in: ${json.slice(0, 400)}`);
}

// vocabClean asserts every KEY of an aggregate is a member of the closed vocabulary it claims to draw on.
function vocabClean(label: string, agg: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  const bad = Object.keys(agg).filter((k) => !allowed.has(k));
  ok(`${label}: every key is a closed-vocabulary member`, bad.length === 0);
  if (bad.length > 0) console.log(`       out-of-vocabulary keys: ${bad.join(", ")}`);
}

const VOCAB_DROP_SET = new Set<string>(VOCAB_DROP_SURFACES);
const STORAGE_ANOMALY_SET = new Set<string>(STORAGE_ANOMALY_KINDS);
const EXPIRY_KEY_SET = new Set<string>(EXPIRY_ITEM_CLASSES.flatMap((i) => EXPIRY_FAULT_CLASSES.map((f) => expiryFaultKey(i, f))));
const APPROVAL_KEY_SET = new Set<string>(APPROVAL_STAGES.flatMap((s) => APPROVAL_REFUSAL_CLASSES.map((c) => approvalFaultKey(s, c))));
const IMPORT_DROP_SET = new Set<string>(IMPORT_DROP_FIELDS);

// SchedulerDOSurface (scheduler-do-base.ts) publishes the COMPOSED entry points, so two things this validator
// drives on purpose are not visible through the SchedulerDO type even though the instance carries them: the two
// halves of the resume apply (ControlPlaneMixin's applyResumeDownpipes / applyResumeDestinations, reached in
// production through applyControlPlaneResumeSlice), and completeRestoreTest's `deferred` field, which the
// implementation reads (scheduler-do-observability.ts) but the surface declaration omits. Both views are of the
// SAME instance through the mixin's own class type, so no call site or runtime behaviour changes.
type ControlPlaneInternals = InstanceType<ReturnType<typeof ControlPlaneMixin>>;
type ObservabilityInternals = InstanceType<ReturnType<typeof ObservabilityMixin>>;

// diag reads the whole ledger the way the support pack does.
async function diag(storage: MockStorage): Promise<SchedDiagBundle> {
  return await readSchedDiag(storage);
}

// A caller shape the DO's dual-control re-check accepts (the router forwards this).
function caller(subject: string, email: string): { method: "access"; email: string; subject: string; role: "owner"; groups: string[]; sourceIp: null } {
  return { method: "access", email, subject, role: "owner", groups: [], sourceIp: null };
}

// ---------------------------------------------------------------------------------------------------------
// the closed-set gates that DROP an out-of-vocabulary observation without counting it.
// ---------------------------------------------------------------------------------------------------------
async function testVocabDrops(): Promise<void> {
  console.log("\nout-of-vocabulary drops (component skew after a partial update)");
  const { storage, stub } = makeScheduler();

  // (1) auth-signal: a newer edge posts a name this DO's closed set does not hold. The counter it was meant
  // to bump silently stops moving, so the pack reads a QUIET auth aggregate during a live lockout.
  await stub.recordAuthSignal(`csrf-origin-unset-${POISON_EMAIL}`);
  // (2) seal-fault: the seal DO is a separate script, so a partial update leaves it emitting kinds this DO
  // cannot parse. The pack's seal-fault ring then stays EMPTY while every run faults.
  await stub.recordSealFault({ kind: `merge-count-mismatch-${POISON_BUCKET}`, downpipeId: "dp1", message: POISON_ERROR });
  // (3) delivery-code: a webhook failure carrying a code from a newer notify build lands with NO code at all.
  const emission = { event: "backup-failure", severity: "critical", downpipeId: "dp1", downpipeName: "Prod KV", detail: "run failed", at: "2026-07-11T00:00:00.000Z" };
  await stub.recordNotify({ emission, records: [{ channelId: "ch1", channelKind: "webhook", delivered: false, code: `sink-blocked-${POISON_BUCKET}` }] });
  // (4) sink-screen: same skew, and it erases the DNS-rebind exposure evidence for that send.
  await stub.recordNotify({ emission, records: [{ channelId: "ch1", channelKind: "webhook", delivered: true, sinkScreen: `hostname-${POISON_SECRET}` }] });
  // (5) deferral-kind (the cruel one): a drill that could NOT RUN is booked as a plain not-ok completion, so
  // the console tells the customer their backup FAILED its restore test.
  await stub.addDownpipe(makeConfig("dp1"), caller("sub-owner", POISON_EMAIL));
  await (stub as unknown as ObservabilityInternals).completeRestoreTest({ id: "dp1", ok: false, deferred: `quarantined-${POISON_VALUE}` });

  const d = await diag(storage);
  ok("the dropped auth-signal name is counted", (d.vocabDrops["auth-signal"]?.count ?? 0) === 1);
  ok("the dropped seal-fault kind is counted", (d.vocabDrops["seal-fault"]?.count ?? 0) === 1);
  ok("the dropped delivery code is counted", (d.vocabDrops["delivery-code"]?.count ?? 0) === 1);
  ok("the dropped sink-screen verdict is counted", (d.vocabDrops["sink-screen"]?.count ?? 0) === 1);
  ok("the dropped deferral kind is counted", (d.vocabDrops["deferral-kind"]?.count ?? 0) === 1);
  ok("each drop carries a timestamp", typeof d.vocabDrops["seal-fault"]?.lastAt === "string");
  vocabClean("vocabDrops", d.vocabDrops, VOCAB_DROP_SET);
  scanClean("vocabDrops (five drifted tokens planted)", d.vocabDrops);

  // The IN-vocabulary paths must NOT be counted as drops (a counter that fires on healthy traffic is noise).
  const clean = makeScheduler();
  await clean.stub.recordAuthSignal("csrf-origin-mismatch");
  await clean.stub.recordNotify({ emission, records: [{ channelId: "ch1", channelKind: "webhook", delivered: true }] });
  const cd = await diag(clean.storage);
  ok("an in-vocabulary signal and a clean delivery record NO drop", Object.keys(cd.vocabDrops).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// the credential-expiry warning ladder that never armed.
// ---------------------------------------------------------------------------------------------------------
async function testExpiryObserveFaults(): Promise<void> {
  console.log("\ncredential-expiry observation faults (the ladder that never armed)");
  const { storage, stub } = makeScheduler();

  // (1) validate-rejected: a SAML cert observation the validator refuses is never written, so the connection
  // is absent from the ladder and its expiry is discovered when every login stops.
  await stub.upsertObservedItem({ id: `idp-cert-${POISON_BUCKET}`, label: `SAML signing cert, ${POISON_EMAIL}`, kind: "certificate", lifecycleClass: "functional", expiresAt: POISON_ERROR });
  // (2) unparseable-date: a licence refresh carrying a date the engine cannot parse DELETES the tracked row,
  // which is indistinguishable from "this account has no licence expiry".
  await stub.observeLicence({ notAfter: `2026-13-45T99:99:99Z ${POISON_SECRET}` });
  // (3) storage-fault: the observe threw. The credential is now untracked and the create carried on.
  const realPut = storage.put.bind(storage);
  storage.put = (async (key: string, value: unknown) => {
    if (key.startsWith("expiry:")) throw new Error(POISON_ERROR);
    return await realPut(key, value);
  }) as unknown as MockStorage["put"];
  await stub.upsertObservedItem({ id: "idp-secret-conn-1", label: "IdP client secret", kind: "credential", lifecycleClass: "functional", expiresAt: new Date(Date.now() + 86_400_000).toISOString() });
  storage.put = realPut;

  const d = await diag(storage);
  ok("a REJECTED SAML-cert observation is recorded", (d.expiryObserveFaults[expiryFaultKey("saml-cert", "validate-rejected")]?.count ?? 0) === 1);
  ok("an UNPARSEABLE licence date is recorded (not silently 'no expiry')", (d.expiryObserveFaults[expiryFaultKey("licence", "unparseable-date")]?.count ?? 0) === 1);
  ok("an observe that THREW on storage is recorded", (d.expiryObserveFaults[expiryFaultKey("idp-secret", "storage-fault")]?.count ?? 0) === 1);
  vocabClean("expiryObserveFaults", d.expiryObserveFaults, EXPIRY_KEY_SET);
  scanClean("expiryObserveFaults (cert id, licence date and thrown message planted)", d.expiryObserveFaults);

  // The classifier reads the item id ONLY to select an enum member and returns that enum.
  ok("classifyExpiryItem selects saml-cert from the engine's own id prefix", classifyExpiryItem(`idp-cert-${POISON_BUCKET}`) === "saml-cert");
  ok("classifyExpiryItem returns an enum, never the id", (EXPIRY_ITEM_CLASSES as readonly string[]).includes(classifyExpiryItem(POISON_EMAIL)));
}

// ---------------------------------------------------------------------------------------------------------
// the dual-control restore lifecycle's refusals and lease anomalies.
// ---------------------------------------------------------------------------------------------------------
async function testApprovalFaults(): Promise<void> {
  console.log("\ndual-control restore refusals + the consume-miss accounting hole");
  const { storage, stub } = makeScheduler();
  const maker = caller("sub-maker", POISON_EMAIL);
  const checker = caller("sub-checker", "approver@customer-example.com");
  // Both principals must exist in the DO's own role table: the reserve re-resolves each recorded subject
  // LIVE and refuses an approval whose maker or checker no longer holds their half of the authority. Without
  // the seeding this section drove an estate where neither person existed, every reserve refused as an
  // authority lapse, and the lease-anomaly accounting the block is about was never reached.
  const principals = [
    { email: maker.email, subject: maker.subject, role: "approver" as const },
    { email: checker.email, subject: checker.subject, role: "approver" as const },
  ];
  await bindApprovalPrincipals(stub, principals);
  const planHash = "sha384:aaaaaaaabbbbbbbbccccccccdddddddd";
  const request = { planHash, runId: "01JRUN000000000000000000", isLatest: true, plannedWrites: 3, bytes: 10, reason: `restore after incident ${POISON_VALUE}`, redirectBinding: null };

  await notePlanAnchor(stub, planHash);
  await stub.requestRestore(request, maker);

  // (1) SELF-APPROVAL: the maker tries to approve their own request. This is the single event a maker-checker
  // attestation is asked to prove never happened, and it was recorded NOWHERE.
  await stub.approveRestore({ planHash }, maker).then(
    () => ok("a self-approval is refused", false),
    () => ok("a self-approval is refused", true),
  );
  // (2) NOT-REJECTABLE / NOT-APPROVABLE: refusals on a record in a terminal or mid-apply state.
  await stub.approveRestore({ planHash }, checker); // legitimate approval
  await stub.approveRestore({ planHash }, checker).catch(() => undefined); // already approved
  // (3) The lease anomalies. Reserve the approval, then BACK-DATE the lease so it reads reclaimed, then run
  // the post-apply consume: the apply SUCCEEDED and its approval is not marked consumed.
  const reserved = await stub.reserveRestore({ planHash });
  ok("the apply reserves the approval", reserved.reserved === true);
  const rec = (await storage.get(`approval:${planHash}`)) as { appliedAt: string; status: string };
  await storage.put(`approval:${planHash}`, { ...rec, status: "approved" }); // the lease lapsed and a fresh reserve reclaimed it
  const consumed = await stub.consumeApproval({ planHash });
  ok("the consume MISSES (the reservation was reclaimed)", consumed.consumed === false);
  // (4) A reserve against a plan nobody raised.
  await stub.reserveRestore({ planHash: "sha384:0000000000000000000000000000000f" });

  const d = await diag(storage);
  ok("the blocked SELF-APPROVAL is a counted, dated fact in the pack", (d.approvalFaults[approvalFaultKey("approve", "self-approval")]?.count ?? 0) === 1);
  ok("an approve refused on an already-approved record is recorded", (d.approvalFaults[approvalFaultKey("approve", "not-approvable")]?.count ?? 0) === 1);
  ok("THE ACCOUNTING HOLE: consume|lease-reclaimed is recorded (one approval may have authorised two applies)", (d.approvalFaults[approvalFaultKey("consume", "lease-reclaimed")]?.count ?? 0) === 1);
  ok("a reserve against an unraised plan is recorded", (d.approvalFaults[approvalFaultKey("reserve", "no-such-request")]?.count ?? 0) === 1);
  vocabClean("approvalFaults", d.approvalFaults, APPROVAL_KEY_SET);
  scanClean("approvalFaults (maker email and the plan reason planted)", d.approvalFaults);

  // A clean maker/checker cycle records NOTHING (the ledger holds refusals, never the successes the audit
  // chain already carries).
  const clean = makeScheduler();
  await bindApprovalPrincipals(clean.stub, principals);
  await notePlanAnchor(clean.stub, planHash);
  await clean.stub.requestRestore(request, maker);
  await clean.stub.approveRestore({ planHash }, checker);
  await clean.stub.reserveRestore({ planHash });
  const okConsume = await clean.stub.consumeApproval({ planHash });
  const cd = await diag(clean.storage);
  ok("a clean request/approve/reserve/consume cycle records no fault", okConsume.consumed === true && Object.keys(cd.approvalFaults).length === 0);

  // The classifier maps STRUCTURED status (never the refusal prose) to the closed class.
  ok("classifyApprovalRefusal reads status, not prose", classifyApprovalRefusal("expired") === "expired" && classifyApprovalRefusal(null) === "no-such-request" && classifyApprovalRefusal("requested", true) === "self-approval");
  ok("every class it can return is in the closed vocabulary", (APPROVAL_REFUSAL_CLASSES as readonly string[]).includes(classifyApprovalRefusal("applying")));
}

// ---------------------------------------------------------------------------------------------------------
// what the DR auto-heal silently dropped, re-pointed and stripped.
// ---------------------------------------------------------------------------------------------------------
async function testRecoveryResume(): Promise<void> {
  console.log("\nDR auto-heal: the skipped downpipes, the re-pointed default, the stripped fields");
  const { storage, stub } = makeScheduler();

  // (1) A tolerant resume SKIPS a malformed downpipe. Until now the customer's downpipe simply did not come
  // back and the pack held only the integer resumeSkipped.
  const exp = {
    configVersion: 4,
    downpipes: [makeConfig("dp-good"), { id: "dp-broken", name: `pipe ${POISON_VALUE}`, cadenceSeconds: -1, enabled: true, source: { kind: "kv", binding: POISON_BUCKET } }],
    destinations: [
      // The default the export names is NOT in the list: the default silently re-points at the first entry,
      // so every unpinned downpipe starts writing to a bucket the operator never chose.
      { id: "dest-b", label: "Secondary", endpoint: `https://${POISON_BUCKET}.r2.cloudflarestorage.com`, bucket: POISON_BUCKET, region: "auto", accessKeyId: "AKIA-PUBLIC-HALF", secret: { reestablish: true as const }, setAt: new Date().toISOString(), setBy: POISON_EMAIL, verifiedAt: null, deleteProbe: null, worm: { mode: `governance-${POISON_SECRET}` }, storageClass: `GLACIER_${POISON_VALUE}` },
    ],
    defaultDestinationId: "dest-a-deleted",
    discovery: null,
  } as unknown as Parameters<ControlPlaneInternals["applyResumeDownpipes"]>[0];

  const resume = stub as unknown as ControlPlaneInternals;
  await resume.applyResumeDownpipes(exp, true);
  await resume.applyResumeDestinations(exp);

  const d = await diag(storage);
  const rr = d.recoveryResume;
  ok("the SKIPPED downpipe is named (which backup never came back)", rr !== null && rr.resumeSkips.some((s) => s.downpipeId === "dp-broken"));
  ok("with a closed reason class, never the thrown message", rr !== null && rr.resumeSkips.every((s) => (RESUME_SKIP_CLASSES as readonly string[]).includes(s.reasonClass)));
  ok("the healthy downpipe is NOT recorded as skipped", rr !== null && !rr.resumeSkips.some((s) => s.downpipeId === "dp-good"));
  ok("the silently RE-POINTED default destination is recorded", rr !== null && rr.defaultRepointed === true);
  ok("the destination that came back with no secret is named (it cannot run until re-entered)", rr !== null && rr.reestablishDestIds.includes("dest-b"));
  ok("the WORM field the import validator STRIPPED is counted", rr !== null && (rr.importFieldDrops.worm?.count ?? 0) === 1);
  ok("the storage-class field the import validator STRIPPED is counted", rr !== null && (rr.importFieldDrops.storageClass?.count ?? 0) === 1);
  vocabClean("importFieldDrops", rr?.importFieldDrops ?? {}, IMPORT_DROP_SET);
  scanClean("recoveryResume (bucket, endpoint, WORM value and operator email planted)", rr);

  // (2) A staged apply refused for a version mismatch: the recovery now stalls forever, and the class is the
  // whole diagnosis. Also the unclassified auto-heal refusal, whose pack reason is structurally EMPTY.
  const two = makeScheduler();
  await two.stub.applyControlPlaneResumeSlice(); // no latch set
  await two.stub.recordControlPlaneRecoveryRefused(`no signer to verify ${POISON_SECRET}`);
  const d2 = await diag(two.storage);
  ok("a staged-apply refusal carries a closed class", d2.recoveryResume?.stagedApplyRefusal !== null && (STAGED_APPLY_REFUSAL_CLASSES as readonly string[]).includes(d2.recoveryResume?.stagedApplyRefusal?.cls ?? ""));
  scanClean("stagedApplyRefusal (the operator-facing refusal prose planted)", d2.recoveryResume);

  // The classifier reads the throw ONLY to select an enum member.
  ok("classifyResumeSkip returns an enum, never the message", (RESUME_SKIP_CLASSES as readonly string[]).includes(classifyResumeSkip(new Error(POISON_ERROR))));
}

// ---------------------------------------------------------------------------------------------------------
// the silent self-heals, coercions and safe-default reads.
// ---------------------------------------------------------------------------------------------------------
async function testStorageAnomalies(): Promise<void> {
  console.log("\nsilent self-heals, coercions and discards (the storage-corruption blind spot)");
  const { storage, stub } = makeScheduler();

  // (1) epoch-corrupt-defaulted: THE REVOCATION BYPASS. A corrupt idpEpoch coerces to 0 = "kill no sessions",
  // so "we disabled that connection but a session kept working" left no trace at all.
  await storage.put("idpEpoch:conn-1", { corrupted: POISON_SECRET });
  const epoch = await stub.getIdpEpoch("conn-1");
  ok("a corrupt idpEpoch still reads 0 (the safe default is unchanged)", epoch === 0);

  // (2) marker-corrupt-defaulted: the emergency-change tally reads back malformed and silently becomes zero,
  // so the compliance posture says no emergency changes were ever raised.
  await storage.put("change-emergency-marker", { count: `many ${POISON_VALUE}`, lastAt: 42 });
  await stub.readEmergencyChangeMarker();

  // (3) audit-head-rebuilt: the head POINTER is missing while entries exist, so it is reconstructed from the
  // chain. A REPEAT of this is how a chain silently re-anchors around a deleted entry.
  await stub.appendAudit({ actorSubject: "sub-1", actorEmail: POISON_EMAIL, actorMethod: "access", sourceIp: null, action: "downpipe-create", outcome: "success", target: { kind: "downpipe", id: "dp1" } });
  await storage.delete(AUDIT_HEAD_KEY);
  await stub.appendAudit({ actorSubject: "sub-1", actorEmail: POISON_EMAIL, actorMethod: "access", sourceIp: null, action: "downpipe-create", outcome: "success", target: { kind: "downpipe", id: "dp2" } });

  // (4) verify-incomplete: a PRIOR verify was killed mid-recompute (its complete:false tombstone survives), so
  // the pack has been reading a stale verdict as if it were current.
  await storage.put(AUDIT_VERIFY_META_KEY, { at: new Date().toISOString(), entriesChecked: 9, durationMs: 0, complete: false });
  const verdict = await stub.verifyAudit();
  ok("the verify still returns its verdict", typeof verdict.intact === "boolean");
  const meta = (await storage.get(AUDIT_VERIFY_META_KEY)) as { complete: boolean };
  ok("a verify that FINISHES stamps complete:true (a killed one leaves complete:false behind)", meta.complete === true);

  // (5) roster-claimant-discarded: a repair deletes a DIVERGENT claimant's row because a healthy twin exists.
  // The operator's schedule/retention edits in that row go with it.
  await stub.addDownpipe(makeConfig("dp-real"), caller("sub-owner", POISON_EMAIL));
  await storage.put("dp:dp-ghost", { config: { ...makeConfig("dp-real"), name: `pipe ${POISON_VALUE}` }, nextRunAt: Date.now(), lastRunAt: null });
  await stub.reconcileRoster();

  const d = await diag(storage);
  ok("the corrupt idpEpoch coercion is recorded (the revocation bypass is finally visible)", (d.storageAnomalies["epoch-corrupt-defaulted"]?.count ?? 0) >= 1);
  ok("the corrupt emergency-change marker coercion is recorded", (d.storageAnomalies["marker-corrupt-defaulted"]?.count ?? 0) >= 1);
  ok("the audit head-pointer rebuild is recorded", (d.storageAnomalies["audit-head-rebuilt"]?.count ?? 0) >= 1);
  ok("the CPU-killed prior verify is recorded", (d.storageAnomalies["verify-incomplete"]?.count ?? 0) === 1);
  ok("the DISCARDED roster claimant is recorded", (d.storageAnomalies["roster-claimant-discarded"]?.count ?? 0) === 1);
  ok("and the discarded claimant is named with a one-way config digest", d.rosterDiscards.length === 1 && /^[0-9a-f]{12}$/.test(d.rosterDiscards[0]!.configDigest));
  ok("the digest is NOT the config (the discarded config content never rides)", !JSON.stringify(d.rosterDiscards).includes(POISON_VALUE));
  vocabClean("storageAnomalies", d.storageAnomalies, STORAGE_ANOMALY_SET);
  scanClean("storageAnomalies (corrupt values, an operator email and a config note planted)", d.storageAnomalies);
  scanClean("rosterDiscards (the discarded config carried a planted note)", d.rosterDiscards);

  // A healthy DO records NO anomaly (these counters must stay at zero on a clean account, or they are noise).
  const clean = makeScheduler();
  await clean.stub.addDownpipe(makeConfig("dp1"), caller("sub-owner", POISON_EMAIL));
  await clean.stub.getIdpEpoch("conn-never-bumped");
  await clean.stub.readEmergencyChangeMarker();
  await clean.stub.reconcileRoster();
  const cd = await diag(clean.storage);
  ok("a healthy DO records no storage anomaly", Object.keys(cd.storageAnomalies).length === 0 && cd.rosterDiscards.length === 0);
}

// ---------------------------------------------------------------------------------------------------------
// The dropped-write floor: a diagnostic write that is itself DROPPED must be counted, or
// the pack under-reports during the exact outage it exists to explain.
// ---------------------------------------------------------------------------------------------------------
async function testDroppedDiagnosticWrites(): Promise<void> {
  console.log("\nthe new recorders' OWN dropped writes (the pack's under-count caveat)");
  const { storage, stub } = makeScheduler();
  const realPut = storage.put.bind(storage);
  storage.put = (async (key: string, value: unknown) => {
    if (key === "diag:vocabdrops" || key === "diag:storageanomalies") throw new Error(POISON_ERROR);
    return await realPut(key, value);
  }) as unknown as MockStorage["put"];
  await stub.recordAuthSignal(`drifted-${POISON_SECRET}`); // its ledger write is dropped
  await storage.put("idpEpoch:conn-1", { corrupted: true });
  await stub.getIdpEpoch("conn-1"); // its ledger write is dropped too
  storage.put = realPut;

  const d = await diag(storage);
  ok("a DROPPED vocab-drop write is itself counted", (d.droppedWrites["vocab-drop"]?.count ?? 0) >= 1);
  ok("a DROPPED storage-anomaly write is itself counted", (d.droppedWrites["storage-anomaly"]?.count ?? 0) >= 1);
  scanClean("droppedWrites (the storage fault's raw message planted)", d.droppedWrites);
}

async function main(): Promise<void> {
  console.log("scheduler-DO recovery / dual-control / skew evidence");
  await testVocabDrops();
  await testExpiryObserveFaults();
  await testApprovalFaults();
  await testRecoveryResume();
  await testStorageAnomalies();
  await testDroppedDiagnosticWrites();
  const failures = getFailures();
  console.log(failures === 0 ? "\nsched-recovery-evidence: all checks passed" : `\nsched-recovery-evidence: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

await main();
