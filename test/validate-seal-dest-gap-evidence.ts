// Validates the SEAL + DESTINATION diagnostic evidence added for the support-pack gap audit.
//
// Each case proves TWO things, which is what "closed" means for a gap:
//   (a) RECORDED: the evidence is produced on the FAULT path (not only in a happy-path unit), in a closed
//       vocabulary, and survives the redaction chokepoint (the DO-side sanitiser / applier) that a real post
//       would pass through;
//   (b) REDACTION-SAFE: a customer SENTINEL planted at the fault site (an email, a bucket, an object key, a
//       secret value, a role ARN, a region host, a SQL row value) appears in NO BYTE of the recorded record.
//
// No network, no Durable Object: the S3 driver is driven over a stubbed global fetch, and the DO-side appliers
// are called directly (they are pure by design, which is the whole point of the leaf modules).
//
// Run: node test/validate-seal-dest-gap-evidence.ts

import { closedS3Code, DestFaultLog, regionHintFromLocation } from "../src/dest/fault-log.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { applyDestBuildHealth, classifyStsErrorBody, DestBuildError, destBuildFaultOf, DEST_BUILD_CAUSES, STS_FAILURE_CLASSES } from "../src/dest/build-health.ts";
import { classifyD1Error, D1RestoreError, d1FaultEvidence } from "../src/dest/restore-fault.ts";
import { unwiredSecretSinks } from "../src/dest/restore-sink.ts";
import { sanitiseDestFaults } from "../src/admin/run-fault-records.ts";
import { classifyRestoreFaultClass } from "../src/admin/diag-records.ts";
import { CONFIG_FAULT_CODES } from "../src/seal/config-fault.ts";
import { buildAdapter } from "../src/seal/adapters.ts";
import { ConfigFaultError, configFaultOf } from "../src/seal/config-fault.ts";
import { classifyWormRefusal, sanitiseSealFault, SEAL_FAULT_KINDS } from "../src/seal/seal-faults.ts";
import { beginRunObservations, drainRunObservations, noteLockPlane, notePartialAbandoned, noteSealMode, noteSkippedChanged, noteStranded } from "../src/seal/run-observations.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---------------------------------------------------------------------------------------------------------
// THE CUSTOMER SENTINELS. Every one of these is planted at a fault site below. NONE of them may appear in any
// byte of any recorded record. They are deliberately the WORST values in the product: a customer email, the
// archive bucket, a payroll object key, a live secret, an IAM role ARN, a regional host with the bucket in it,
// and a SQL row value from a constraint violation.
// ---------------------------------------------------------------------------------------------------------
const EMAIL = "cfo@acme-corp.example";
const BUCKET = "acme-prod-payroll-archive";
const OBJECT_KEY = "seg/2026/payroll-Q3-final.xlsx";
const SECRET_VALUE = "sk_live_51ACMEsecretVALUE";
const ROLE_ARN = "arn:aws:iam::999999999999:role/acme-backup";
const ROW_VALUE = "employee_id=4471, salary=285000";
const SENTINELS = [EMAIL, BUCKET, OBJECT_KEY, SECRET_VALUE, ROLE_ARN, ROW_VALUE, "acme", "payroll", "salary", "sk_live"];

// noSentinel asserts a recorded value carries NONE of the sentinels, in any byte, case-insensitively. This is
// the binding no-custody proof: the record is serialised exactly as it would be to the DO and to the pack.
function noSentinel(label: string, record: unknown): void {
  const json = JSON.stringify(record ?? null);
  const hay = json.toLowerCase();
  const hit = SENTINELS.find((s) => hay.includes(s.toLowerCase()));
  ok(`${label}: no customer sentinel in any byte${hit === undefined ? "" : ` (LEAKED ${hit} in ${json})`}`, hit === undefined);
}

// ---------------------------------------------------------------------------------------------------------
// A stubbed S3 wire. The store's error bodies and headers are stuffed with sentinels, exactly as a real store
// would echo the customer's own bucket / key / ARN back at us.
// ---------------------------------------------------------------------------------------------------------
type Reply = { status: number; body?: string; headers?: Record<string, string> };
let queue: Reply[] = [];
function stubFetch(replies: Reply[]): void {
  queue = [...replies];
  (globalThis as { fetch: unknown }).fetch = async (): Promise<Response> => {
    const r = queue.shift();
    if (r === undefined) throw new Error("stub fetch: no reply queued");
    return new Response(r.body ?? "", { status: r.status, headers: r.headers ?? {} });
  };
}
function dest(): S3Destination {
  return new S3Destination("https://s3.example.com", BUCKET, "us-east-1", "AKIAEXAMPLE", "secret", {});
}
const errorBody = (code: string): string =>
  `<?xml version="1.0"?><Error><Code>${code}</Code><Message>Denied for ${ROLE_ARN} on ${OBJECT_KEY}</Message><Resource>/${BUCKET}/${OBJECT_KEY}</Resource></Error>`;

// ---------------------------------------------------------------------------------------------------------
console.log("a wrong-type secrets binding is REFUSED, not sealed as String(store) garbage");
// ---------------------------------------------------------------------------------------------------------
{
  ok("secret-binding-wrong-type is in the closed config-fault vocabulary", (CONFIG_FAULT_CODES as readonly string[]).includes("secret-binding-wrong-type"));

  // A KV namespace accidentally bound under a SECRET's name: it has no get(), and it is not a string. The old
  // adapter coerced it with String(store) and sealed "[object Object]" as the secret, every run, silently.
  const wrongType = { list: () => Promise.resolve({ keys: [] }), put: () => Promise.resolve(), toString: () => SECRET_VALUE };
  // The BINDING NAME is an operator label (a Workers identifier), the same redaction class sourcesDetached
  // already carries, and it is gated to [A-Za-z0-9_] -- so it may ride, while the binding's VALUE may not. The
  // name here is deliberately free of the sentinel substrings so the two classes cannot be confused; the gate
  // itself is asserted separately below.
  const env = { STRIPE_KEY_BINDING: wrongType } as unknown as Parameters<typeof buildAdapter>[0];
  const state = { config: { source: { type: "secrets", secrets: [{ name: "stripe", binding: "STRIPE_KEY_BINDING" }] } } } as unknown as Parameters<typeof buildAdapter>[1];
  let caught: unknown;
  try {
    buildAdapter(env, state);
  } catch (e) {
    caught = e;
  }
  ok("the build REFUSES the record rather than sealing a coerced value", caught !== undefined);
  const fault = configFaultOf(caught);
  ok("it is typed with the closed code secret-binding-wrong-type", fault?.code === "secret-binding-wrong-type");
  ok("it names the BINDING (an operator label)", fault?.bindingName === "STRIPE_KEY_BINDING");
  noSentinel("config fault", fault);
  // The name field is the ONE free-ish field on this record, so prove its gate (isConfigFaultName): it admits
  // ONLY a bare operator identifier [A-Za-z0-9_]{1,64}. An object key, an endpoint, a message or a customer
  // value carries slashes, dots, colons, spaces or punctuation and structurally CANNOT pass -- so even a future
  // call site that wrongly passed one would have it DROPPED rather than persisted.
  //
  // The honest bound of a CHARSET gate (as opposed to an allow-list): a value that happens to be
  // identifier-shaped is indistinguishable from a binding name. That is acceptable here because no call site
  // can pass one -- the name is read straight out of the stored CONFIG (sec.binding), never out of a message
  // or a value -- and it is the pre-existing G142 contract this code reuses rather than a new seam.
  ok("an object key in the name field is DROPPED by the gate", configFaultOf(new ConfigFaultError("secret-binding-wrong-type", "x", OBJECT_KEY))?.bindingName === undefined);
  ok("an endpoint in the name field is DROPPED by the gate", configFaultOf(new ConfigFaultError("secret-binding-wrong-type", "x", `https://${BUCKET}.s3.amazonaws.com`))?.bindingName === undefined);
  ok("a message in the name field is DROPPED by the gate", configFaultOf(new ConfigFaultError("secret-binding-wrong-type", "x", `denied for ${ROLE_ARN}`))?.bindingName === undefined);

  // A plaintext string secret is still accepted (no regression): the refusal is precise, not a blanket ban.
  const strEnv = { STRIPE_KEY_BINDING: SECRET_VALUE } as unknown as Parameters<typeof buildAdapter>[0];
  let built = true;
  try {
    buildAdapter(strEnv, state);
  } catch {
    built = false;
  }
  ok("a plaintext string secret still builds (no regression)", built);
}

// ---------------------------------------------------------------------------------------------------------
console.log("a listing the store truncates WITHOUT a cursor is recorded (the silent early stop)");
// ---------------------------------------------------------------------------------------------------------
{
  // IsTruncated=true and NO NextContinuationToken: the walk stops believing it saw the whole keyspace, so a
  // replica silently holds only the first page of the segment store and reads healthy.
  const page = `<?xml version="1.0"?><ListBucketResult><Key>${OBJECT_KEY}</Key><IsTruncated>true</IsTruncated></ListBucketResult>`;
  stubFetch([{ status: 200, body: page }]);
  const d = dest();
  await d.list("seg/");
  const snap = d.destFaults();
  ok("the anomaly is recorded", (snap.anomalies?.["list-truncated-no-cursor"] ?? 0) === 1);
  ok("with the clamped page count reached", snap.listPagesReached === 1);
  noSentinel("snapshot", snap);
  const gated = sanitiseDestFaults(snap, undefined, 1);
  ok("it survives the DO-side redaction chokepoint", (gated?.anomalies?.["list-truncated-no-cursor"] ?? 0) === 1);
  noSentinel("DO record", gated);
}

// ---------------------------------------------------------------------------------------------------------
console.log("a wrong-region redirect carries the REGION TOKEN, never the Location URL");
// ---------------------------------------------------------------------------------------------------------
{
  // The Location a real 301 carries embeds the BUCKET and the HOST. Only the region token may ride.
  const loc = `https://${BUCKET}.s3.eu-central-1.amazonaws.com/${OBJECT_KEY}`;
  ok("the region token is extracted", regionHintFromLocation(loc) === "eu-central-1");
  ok("a non-AWS target (a proxy/appliance) yields NO token", regionHintFromLocation("https://corp-proxy.acme-corp.example/x") === undefined);

  stubFetch([{ status: 301, headers: { location: loc } }]);
  const d = dest();
  await d.get("run/x/root.manifest.json").catch(() => undefined);
  const snap = d.destFaults();
  ok("redirect-wrong-region is recorded", (snap.anomalies?.["redirect-wrong-region"] ?? 0) === 1);
  ok("the region hint rides", snap.redirectRegionHint === "eu-central-1");
  noSentinel("snapshot", snap);

  // An unrecognised redirect target records ONLY the closed class -- never the proxy host.
  stubFetch([{ status: 307, headers: { location: `https://interception.acme-corp.example/${OBJECT_KEY}` } }]);
  const d2 = dest();
  await d2.get("x").catch(() => undefined);
  const s2 = d2.destFaults();
  ok("an unrecognised target records the closed class only", (s2.anomalies?.["redirect-target-unrecognised"] ?? 0) === 1 && s2.redirectRegionHint === undefined);
  noSentinel("unrecognised snapshot", s2);

  // Defence in depth: even if a WRITE SITE regressed and posted a URL, the DO applier must drop it.
  const forged = sanitiseDestFaults({ total: 0, faults: [], anomalies: { "redirect-wrong-region": 1 }, redirectRegionHint: loc }, undefined, 1);
  ok("a forged Location in the region field is DROPPED by the applier", forged?.redirectRegionHint === undefined);
  noSentinel("forged record", forged);
}

// ---------------------------------------------------------------------------------------------------------
console.log("non-conformant store behaviour is fingerprinted (no ETag / no UploadId / error-in-200)");
// ---------------------------------------------------------------------------------------------------------
{
  // A 200 GET with no ETag: the store cannot satisfy the conditional-write contract the RUNLOG needs.
  stubFetch([{ status: 200, body: "x" }]);
  const d = dest();
  await d.get("k").catch(() => undefined);
  ok("no-etag-on-get is recorded", (d.destFaults().anomalies?.["no-etag-on-get"] ?? 0) === 1);

  // A conditional PUT that succeeds with no ETag: SILENTLY TOLERATED today, so RUNLOG concurrency degrades
  // with no evidence. The tolerance is unchanged; the non-conformance is now recorded.
  stubFetch([{ status: 200 }]);
  const d2 = dest();
  const res = await d2.putConditional("_RECOVERY/RUNLOG", new Uint8Array([1]), { ifNoneMatch: "*" });
  ok("the conditional PUT still SUCCEEDS (behaviour unchanged)", res.ok === true);
  ok("no-etag-on-conditional-put is recorded", (d2.destFaults().anomalies?.["no-etag-on-conditional-put"] ?? 0) === 1);
  noSentinel("snapshot", d2.destFaults());
}

// ---------------------------------------------------------------------------------------------------------
console.log("engine guard refusals carry their MAGNITUDE and identity");
// ---------------------------------------------------------------------------------------------------------
{
  const log = new DestFaultLog();
  log.noteGuardRefusal("segment-over-limit", 3_221_225_472); // a 3 GiB segment against the 1 GiB ceiling
  log.noteGuardRefusal("key-shape-refused");
  const snap = log.snapshot();
  ok("segment-over-limit is recorded", (snap.anomalies?.["segment-over-limit"] ?? 0) === 1);
  ok("the clamped magnitude rides (off-by-framing vs wildly wrong)", snap.overBoundBytes === 3_221_225_472);
  ok("key-shape-refused is recorded WITHOUT the key", (snap.anomalies?.["key-shape-refused"] ?? 0) === 1);
  noSentinel("snapshot", snap);

  // The traversal guard fires on a REAL dot-segmented key, through the driver.
  const d = dest();
  await d.get("seg/../../etc/passwd").catch(() => undefined);
  ok("the traversal guard's refusal is recorded on the driver", (d.destFaults().anomalies?.["key-shape-refused"] ?? 0) === 1);
}

// ---------------------------------------------------------------------------------------------------------
console.log("the STS AssumeRole failure cause is a CLOSED class, read from a body that never rides");
// ---------------------------------------------------------------------------------------------------------
{
  // A real STS error document, stuffed with the role ARN. Only the closed class may leave.
  const stsBody = `<ErrorResponse><Error><Code>AccessDenied</Code><Message>User is not authorized to perform sts:AssumeRole on ${ROLE_ARN}</Message></Error></ErrorResponse>`;
  ok("AccessDenied maps to the closed class access-denied", classifyStsErrorBody(stsBody) === "access-denied");
  ok("ExpiredToken maps to expired-token", classifyStsErrorBody("<Error><Code>ExpiredToken</Code></Error>") === "expired-token");
  ok("a code OUTSIDE the table records as other", classifyStsErrorBody(`<Error><Code>AcmePrivateCode</Code></Error>`) === "other");
  ok("a body with NO code records as other", classifyStsErrorBody(`the role ${ROLE_ARN} was denied`) === "other");
  for (const cls of [classifyStsErrorBody(stsBody), classifyStsErrorBody("garbage")]) {
    ok(`the classifier returns a member of the closed vocabulary (${cls})`, (STS_FAILURE_CLASSES as readonly string[]).includes(cls));
    noSentinel(`class ${cls}`, cls);
  }

  const e = new DestBuildError("sts-assume-role-failed", `STS AssumeRole: status 403`, { stsFailureClass: classifyStsErrorBody(stsBody) });
  const fault = destBuildFaultOf(e);
  ok("the typed build fault carries the closed STS class", fault.stsFailureClass === "access-denied");
  noSentinel("build fault", fault);
}

// ---------------------------------------------------------------------------------------------------------
console.log("destination-unbuildable is a STANDING state with failingSinceAt and a named knob");
// ---------------------------------------------------------------------------------------------------------
{
  ok("every cause is in the closed vocabulary", DEST_BUILD_CAUSES.length > 0);
  // The highest-impact failure mode: a redeploy wiped DEST_ENDPOINT. The var NAME is product vocabulary; its VALUE is not.
  const wiped = destBuildFaultOf(new DestBuildError("env-missing", `missing required configuration: DEST_ENDPOINT`, { varName: "DEST_ENDPOINT" }));
  let h = applyDestBuildHealth(undefined, { ok: false, ...wiped }, 1000);
  ok("the first failure sets failingSinceAt", h.failingSinceAt === 1000 && h.lastOutcome === "failed");
  ok("it names the knob from the CLOSED var vocabulary", h.lastVarName === "DEST_ENDPOINT");
  h = applyDestBuildHealth(h, { ok: false, ...wiped }, 5000);
  ok("failingSinceAt is the streak START, not the last failure (the fact a run row can never carry)", h.failingSinceAt === 1000 && h.consecutiveFailures === 2);
  h = applyDestBuildHealth(h, { ok: true }, 9000);
  ok("a successful build CLEARS the failing state", h.lastOutcome === "ok" && h.failingSinceAt === undefined && h.consecutiveFailures === 0);
  ok("but KEEPS the cumulative counters (a flapping destination stays legible)", (h.causes["env-missing"] ?? 0) === 2);

  // The applier is the redaction chokepoint: a drifted caller that posted a bucket, an endpoint or a raw
  // message must have every one of them DROPPED.
  const forged = applyDestBuildHealth(undefined, { ok: false, cause: `endpoint ${BUCKET} rejected`, varName: SECRET_VALUE, stsFailureClass: ROLE_ARN, doStatus: 999 }, 1);
  ok("an out-of-vocabulary cause becomes the residual other", forged.lastCause === "other");
  ok("an out-of-vocabulary var name is DROPPED", forged.lastVarName === undefined);
  ok("an out-of-vocabulary STS class is DROPPED", forged.lastStsFailureClass === undefined);
  noSentinel("forged record", forged);
}

// ---------------------------------------------------------------------------------------------------------
console.log("the readback split (absent vs bodyless) and the offline-recoverable size refusal");
// ---------------------------------------------------------------------------------------------------------
{
  ok("an ABSENT read-back classifies as readback-absent", classifyRestoreFaultClass(`restored object ${OBJECT_KEY} was absent on read-back (the bucket accepted the write and does not hold it)`) === "readback-absent");
  ok("a BODYLESS read-back classifies as readback-bodyless", classifyRestoreFaultClass(`restored object ${OBJECT_KEY} carried no body on read-back (the store returned a bodyless object)`) === "readback-bodyless");
  ok("an over-single-put refusal is its own OFFLINE-RECOVERABLE class, never data loss", classifyRestoreFaultClass(`restore of ${OBJECT_KEY} is too large for the in-account path; recover it offline with the downpipe CLI`) === "over-single-put-limit");
  for (const cls of ["readback-absent", "readback-bodyless", "over-single-put-limit"]) noSentinel(`class ${cls}`, cls);
}

// ---------------------------------------------------------------------------------------------------------
console.log("the D1 restore receipt LOCALISES a partial apply, with no schema or row value");
// ---------------------------------------------------------------------------------------------------------
{
  // A constraint violation's message embeds the ROW VALUE -- the most dangerous string in the restore path.
  const sqlite = new Error(`D1_ERROR: UNIQUE constraint failed: employees.id (${ROW_VALUE})`);
  ok("the SQLite message selects the closed class constraint", classifyD1Error(sqlite) === "constraint");
  ok("a bind-type failure selects type-error", classifyD1Error(new Error("D1_TYPE_ERROR: Type 'bigint' not supported")) === "type-error");
  noSentinel("class", classifyD1Error(sqlite));

  const e = new D1RestoreError(classifyD1Error(sqlite), "partial restore: the D1 apply failed at batch 4 of 900", { failedBatchIndex: 3, batchTotal: 900 });
  const ev = d1FaultEvidence(e);
  ok("the evidence localises the fault (batch 3 of 900)", ev?.failedBatchIndex === 3 && ev?.batchTotal === 900);
  ok("and names the closed D1 error class", ev?.d1ErrorClass === "constraint");
  noSentinel("partial-apply evidence", ev);
  ok("the reason still classifies as d1-partial for the ring", classifyRestoreFaultClass(e.message) === "d1-partial");

  const refusal = new D1RestoreError("target-not-empty", "D1 restore target is not empty; restore requires a fresh database (drop the target and retry into an empty database)", { residualTableCount: 12 });
  ok("a not-empty refusal carries the residual table COUNT (never the names)", d1FaultEvidence(refusal)?.residualTableCount === 12);
  ok("and classifies as its own closed class d1-target-not-empty", classifyRestoreFaultClass(refusal.message) === "d1-target-not-empty");
  noSentinel("refusal evidence", d1FaultEvidence(refusal));
}

// ---------------------------------------------------------------------------------------------------------
console.log("secrets restorability is a STANDING posture count, not a disaster-time discovery");
// ---------------------------------------------------------------------------------------------------------
{
  const sinks = [
    { name: "stripe-live", put: async (): Promise<void> => undefined },
    { name: "acme-db-password" }, // no write path: NOT restorable in-account, and nobody knows until the disaster
    { name: EMAIL }, // a customer-named secret, to prove the count never carries a name
  ];
  const posture = unwiredSecretSinks(sinks);
  ok("the standing count names how many secrets are bound", posture.bound === 3);
  ok("and how many CANNOT be restored in-account", posture.unwired === 2);
  noSentinel("posture", posture);
  ok("the reactive refusal also carries its own closed class", classifyRestoreFaultClass(`secret acme-db-password has no runtime write path; restore it out of band (Secrets Store bindings are read-only at runtime)`) === "secret-sink-unwired");
}

// ---------------------------------------------------------------------------------------------------------
console.log("strandings are COUNTED, and a plain 403 is no longer mislabelled as WORM");
// ---------------------------------------------------------------------------------------------------------
{
  // THE bug: WORM_REFUSAL_RE folded "access denied" and "status 403" into the WORM arm, so a ROTATED credential
  // was reported as "locked by design, nothing to fix".
  ok("a genuine Object-Lock refusal is worm-locked", classifyWormRefusal("delete refused: object is protected by an object-lock retention window") === "worm-locked");
  ok("a bare 403 AccessDenied is access-denied, NOT worm-locked (the mislabelling bug)", classifyWormRefusal(`DELETE ${OBJECT_KEY}: status 403 AccessDenied`) === "access-denied");
  ok("a 5xx is transient", classifyWormRefusal("DELETE x: status 503") === "transient");
  for (const m of ["worm-locked", "access-denied", "transient"]) noSentinel(`class ${m}`, m);

  beginRunObservations();
  noteStranded("scratch-delete-failed", 33);
  noteStranded("multipart-parts", 7);
  const obs = drainRunObservations();
  ok("scratch strandings are counted (the WORM fan-out leak)", obs.strandsByClass["scratch-delete-failed"] === 33);
  ok("multipart parts are a COUNT, not a boolean", obs.strandsByClass["multipart-parts"] === 7);
  noSentinel("observations", obs);

  const rec = sanitiseSealFault({ kind: "dest-stranding", at: 1, downpipeId: "dp_1", strandClass: "scratch-delete-failed", stranded: 33 }, 1);
  ok("the DO sanitiser persists the stranding record", rec?.strandClass === "scratch-delete-failed" && rec?.stranded === 33);
  const forged = sanitiseSealFault({ kind: "dest-stranding", at: 1, strandClass: `${BUCKET}/${OBJECT_KEY}`, wormRefusalClass: SECRET_VALUE }, 1);
  ok("a forged strand class is DROPPED by the sanitiser", forged?.strandClass === undefined && forged?.wormRefusalClass === undefined);
  noSentinel("forged record", forged);
}

// ---------------------------------------------------------------------------------------------------------
console.log("skipped-changed records carry a CLOSED cause and one-way handles, never object names");
// ---------------------------------------------------------------------------------------------------------
{
  beginRunObservations();
  noteSkippedChanged("range-read-failed", "h:ab12cd34ef56"); // an INFRA fault masked as churn today
  noteSkippedChanged("etag-changed", "h:0011223344ff");
  notePartialAbandoned();
  const obs = drainRunObservations();
  ok("the infra-fault cause is recorded (not folded into churn)", obs.skipsByCause["range-read-failed"] === 1);
  ok("the abandoned partial is counted", obs.partialsAbandoned === 1);
  noSentinel("observations", obs);

  // The handle gate: a RAW object key must never be accepted, even if a write site regressed.
  beginRunObservations();
  noteSkippedChanged("etag-changed", OBJECT_KEY);
  ok("a RAW object key is REFUSED as a handle at the write site", drainRunObservations().skipHandles.length === 0);

  const rec = sanitiseSealFault({ kind: "record-skipped-changed", at: 1, downpipeId: "dp_1", skipCause: "range-read-failed", skipped: 2, handles: ["h:ab12cd34ef56", OBJECT_KEY, `s3://${BUCKET}/${OBJECT_KEY}`] }, 1);
  ok("the DO sanitiser keeps the closed cause", rec?.skipCause === "range-read-failed");
  ok("it keeps the one-way handle and DROPS the raw key and the s3:// URL", JSON.stringify(rec?.handles) === JSON.stringify(["h:ab12cd34ef56"]));
  noSentinel("DO record", rec);
}

// ---------------------------------------------------------------------------------------------------------
console.log("the requested-vs-effective seal mode makes the silent fan-out downgrade visible");
// ---------------------------------------------------------------------------------------------------------
{
  beginRunObservations();
  noteSealMode({ requested: "fanout", effective: "serial", downgradeReason: "no-sampler" });
  const obs = drainRunObservations();
  ok("the DOWNGRADE is recorded (fan-out asked for, serial delivered)", obs.sealMode?.requested === "fanout" && obs.sealMode?.effective === "serial");
  ok("with the closed downgrade reason", obs.sealMode?.downgradeReason === "no-sampler");
  noSentinel("observations", obs);

  const rec = sanitiseSealFault({ kind: "seal-mode", at: 1, downpipeId: "dp_1", requestedMode: "fanout", effectiveMode: "serial", downgradeReason: "no-sampler", fanoutRanges: 0 }, 1);
  ok("the DO sanitiser persists the mode pair", rec?.requestedMode === "fanout" && rec?.effectiveMode === "serial" && rec?.downgradeReason === "no-sampler");
  const forged = sanitiseSealFault({ kind: "seal-mode", at: 1, requestedMode: BUCKET, downgradeReason: OBJECT_KEY }, 1);
  ok("forged modes/reasons are DROPPED", forged?.requestedMode === undefined && forged?.downgradeReason === undefined);
  noSentinel("forged record", forged);
}

// ---------------------------------------------------------------------------------------------------------
console.log("the RUNLOG lock plane's faults are counted, so a scheduler blip is not blamed on the bucket");
// ---------------------------------------------------------------------------------------------------------
{
  beginRunObservations();
  noteLockPlane("acquireFaults", 3);
  noteLockPlane("releaseFaults");
  noteLockPlane("casExhausted");
  noteLockPlane("sigPublishSkipped");
  const obs = drainRunObservations();
  ok("lock-acquire faults are counted", obs.lock.acquireFaults === 3);
  ok("a RELEASE fault (after a COMMITTED archive + RUNLOG) is counted", obs.lock.releaseFaults === 1);
  ok("CAS exhaustion and a skipped signature publish are counted", obs.lock.casExhausted === 1 && obs.lock.sigPublishSkipped === 1);
  noSentinel("observations", obs);

  const rec = sanitiseSealFault({ kind: "lock-plane", at: 1, downpipeId: "dp_1", lockAcquireFaults: 3, releaseFaults: 1, casExhausted: 1, sigPublishSkipped: 1, lockWindowExhausted: 0 }, 1);
  ok("the DO sanitiser persists the lock-plane counters", rec?.lockAcquireFaults === 3 && rec?.releaseFaults === 1);
  noSentinel("DO record", rec);
}

// ---------------------------------------------------------------------------------------------------------
console.log("replication reasons are real, and the pass's own health is visible");
// ---------------------------------------------------------------------------------------------------------
{
  // The reason that mattered most and could not be said: the copy VERIFIED BAD on the replica.
  const rec = sanitiseSealFault({ kind: "replica-target-fault", at: 1, downpipeId: "dp_1", destinationId: "dest_2", replicaReason: "integrity-verify-failed", strandedRuns: 4 }, 1);
  ok("integrity-verify-failed survives as its own closed reason", rec?.replicaReason === "integrity-verify-failed");
  ok("the stranded (never-mirrorable) run count rides", rec?.strandedRuns === 4);
  noSentinel("DO record", rec);
  const forged = sanitiseSealFault({ kind: "replica-target-fault", at: 1, replicaReason: `connect ECONNREFUSED ${BUCKET}.s3.amazonaws.com` }, 1);
  ok("a raw transport message in the reason field is DROPPED", forged?.replicaReason === undefined);
  noSentinel("forged record", forged);

  const pass = sanitiseSealFault({ kind: "replication-pass", at: 1, passOutcome: "budget-exhausted", deferredDownpipes: 12, stateWriteFailures: 2, verifySampleShortfall: 5, segmentVanishDeferrals: 1 }, 1);
  ok("the pass outcome is a closed enum", pass?.passOutcome === "budget-exhausted");
  ok("the per-pass deferral / state-write / verify-shortfall counters ride", pass?.deferredDownpipes === 12 && pass?.stateWriteFailures === 2 && pass?.verifySampleShortfall === 5);
  noSentinel("DO record", pass);
}

// ---------------------------------------------------------------------------------------------------------
console.log("a suspect verdict is bounded, and a lost critical alert is no longer silent");
// ---------------------------------------------------------------------------------------------------------
{
  const rec = sanitiseSealFault({ kind: "verify-suspect", at: 1, downpipeId: "dp_1", runId: "01JRUN", verifyMode: "full", causeDigest: "a1b2c3d4", ordinal: 48_231, verifiedBeforeFail: 48_230, attemptsRun: 3, recovered: false }, 1);
  ok("the failing ORDINAL rides (an integer index, never a key)", rec?.ordinal === 48_231);
  ok("the records that verified CLEAN before the fault ride (sampled is zeroed today)", rec?.verifiedBeforeFail === 48_230);
  ok("the correlation digest rides", rec?.causeDigest === "a1b2c3d4");
  ok("the verify MODE distinguishes off from legacy-absent", sanitiseSealFault({ kind: "verify-suspect", at: 1, verifyMode: "off" }, 1)?.verifyMode === "off");
  noSentinel("DO record", rec);
  const forged = sanitiseSealFault({ kind: "verify-suspect", at: 1, causeDigest: `shard ${OBJECT_KEY} failed`, verifyMode: BUCKET }, 1);
  ok("a message in the digest field is DROPPED (it is gated to hex)", forged?.causeDigest === undefined && forged?.verifyMode === undefined);
  noSentinel("forged record", forged);

  const alert = sanitiseSealFault({ kind: "alert-routing-failed", at: 1, downpipeId: "dp_1", alertEventClass: "restore-test-fail", historyWriteFailed: true }, 1);
  ok("a lost critical alert is recorded with its closed event class", alert?.alertEventClass === "restore-test-fail");
  ok("historyWriteFailed separates 'never sent' from 'sent, record lost'", alert?.historyWriteFailed === true);
  noSentinel("DO record", alert);
  const forgedAlert = sanitiseSealFault({ kind: "alert-routing-failed", at: 1, alertEventClass: `https://hooks.slack.com/services/${SECRET_VALUE}` }, 1);
  ok("a channel URL in the event-class field is DROPPED", forgedAlert?.alertEventClass === undefined);
  noSentinel("forged record", forgedAlert);
}

// ---------------------------------------------------------------------------------------------------------
console.log("the vocabularies stay closed and disjoint");
// ---------------------------------------------------------------------------------------------------------
{
  const kinds = new Set<string>(SEAL_FAULT_KINDS);
  ok("SEAL_FAULT_KINDS has no duplicate member", kinds.size === SEAL_FAULT_KINDS.length);
  for (const k of ["replica-target-fault", "replication-pass", "record-skipped-changed", "dest-stranding", "verify-suspect", "seal-mode", "alert-routing-failed", "lock-plane"]) {
    ok(`the new kind ${k} is in the closed vocabulary`, kinds.has(k));
  }
  ok("an unknown kind is REFUSED by the sanitiser (never persisted)", sanitiseSealFault({ kind: "acme-custom-kind", at: 1 }, 1) === null);
  // The S3 <Code> allow-list still cannot be smuggled through.
  ok("an out-of-allow-list S3 code records as other", closedS3Code(errorBody("AcmeInternalCode")) === "other");
  noSentinel("closed S3 code", closedS3Code(errorBody("AccessDenied")));
}

console.log(failures === 0 ? "\nseal+dest gap evidence: all checks passed" : `\nseal+dest gap evidence: ${failures} FAILED`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
