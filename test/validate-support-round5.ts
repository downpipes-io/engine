// Prove the fault evidence is RECORDED ON THE FAULT PATH and is REDACTION-SAFE.
//
// Subsystem eng-cron-dest-sources. Covers a D1 restore that half-applies (data loss); metadata shed at a
// restore sink; a failed multipart abort's stranding count; WORM "cannot confirm" causes; and the cron plane's
// undelivered alerts, control-plane export, push-trail writes, restore-test skips, reconcile passes and
// estate-size probe.
//
// THE RULE THIS FILE ENFORCES: nothing counts as validated until its evidence is in the bundle. So nothing here
// asserts that a recorder "could" be called: every case DRIVES THE REAL FAULT PATH (a D1 batch that throws, an
// abort request that never answers, a probe the store refuses, a claim spent on an alert that is never
// delivered, a trail write the DO rejects) and then asserts the evidence on the object the pack actually reads
// -- the RestoreResult the router stamps onto the restore-receipt audit target, the DestFaultSnapshot the run
// posts to /diag/run-faults, the WormStatus the pack's live probe returns, and the CronHealth record
// applyCronHealth builds from a posted delta (GET /cron-health) plus the admin-counter tally the same drain
// raises (GET /admin-counters).
//
// THE NO-CUSTODY PROOF. Every fault is planted with CUSTOMER SENTINELS at the fault site itself: a SQLite error
// carrying a table name, a column name and a ROW VALUE (an operator's e-mail and a live-looking secret -- the
// single most dangerous string in the restore path), an S3 error body carrying a bucket and an endpoint, a
// notify emission carrying a webhook url. Each recorded artefact is then serialised WHOLE and asserted to
// contain not one byte of any sentinel. The cron chokepoint is additionally served a HOSTILE delta whose map
// KEYS are sentinels (the classic closed-vocabulary bypass, where a caller-derived string rides in as a key
// rather than a value) and whose enum VALUES are out of vocabulary.
//
// Run: node test/validate-support-round5.ts

import { D1RestoreSink, KVRestoreSink, R2RestoreSink, type RestorePutOptions } from "../src/dest/restore-sink.ts";
import { classifyD1Error, d1FaultEvidence, drainMetadataShed, sanitiseMetadataShed, D1_ERROR_CLASSES, METADATA_SHED_FIELDS } from "../src/dest/restore-fault.ts";
import { D1_HEADER_FORMAT, D1_ROWS_FORMAT, D1_SCHEMA_FORMAT } from "../src/sources/d1-format.ts";
import { DestFaultLog, classifyAbortFailure, sanitiseStrandedAborts, ABORT_FAILURE_CLASSES } from "../src/dest/fault-log.ts";
import { abortMultipart } from "../src/dest/s3-multipart-ops.ts";
import { objectLockStatus, wormUnknownReasonForStatus } from "../src/dest/s3-read-ops.ts";
import { parseObjectLockConfig } from "../src/dest/s3-worm.ts";
import { R2Destination } from "../src/dest/r2.ts";
import { WORM_UNKNOWN_REASONS } from "../src/dest/types.ts";
import { sanitiseDestFaults } from "../src/admin/run-fault-records.ts";
import { ADMIN_COUNTER_NAMES, applyAdminCounters } from "../src/admin/diag-records.ts";
import { handleEstateSize } from "../src/admin/router-sources.ts";
import {
  applyCronHealth,
  carriedCronNotes,
  classifyCpExportFail,
  clearCarriedCronNotes,
  CP_EXPORT_FAIL_CLASSES,
  drainCronFaultLedger,
  emptyCronHealth,
  noteCpExportDestFail,
  noteCpExportPassThrew,
  noteCpExportRecordWriteFailure,
  noteCpExportTruncated,
  noteCpPlaintextPurgePending,
  noteDigestNoTransport,
  noteDroppedEmission,
  noteFleetDrillBatch,
  noteNotifyHistoryAppendFailure,
  notePushTrailWriteFailure,
  noteReconcileCircuitBreaker,
  noteReconcileEnabled,
  noteReconcileSkip,
  noteRestoreTestPassDeferred,
  noteRestoreTestSkip,
  noteRunlogSigVerdict,
  noteUndeliveredCriticalAlert,
  noteUpdateChannelCheck,
  noteUpdateConfirmClearFailure,
  recordCronHealth,
  resetCronFaultLedger,
  RECONCILE_SKIP_REASONS,
  RESTORE_TEST_SKIP_CLASSES,
} from "../src/cron/cron-fault-ledger.ts";
import { resetPendingDroppedWrites } from "../src/admin/diag-writer.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The customer sentinels, planted AT the fault site (inside the provider's own error text, inside the stored
// descriptor, inside the emission). Not one byte of any of these may reach a recorded artefact.
// The keys are FIXED, so the shape is inferred rather than declared Record<string, string>: every sentinel is a
// definite string (a Record index read is string | undefined), which is what lets them ride as computed keys and
// as arguments below without a per-use non-null assertion.
const SENTINELS = {
  email: "cfo@acme-payroll.example",
  bucket: "acme-prod-payroll-backups",
  objectKey: "kv/tenants/acme/salaries-2026.json",
  secret: "sk_live/51H8xQ2eZ+vKYlo2C0abcdefghij=",
  endpoint: "https://acme.r2.cloudflarestorage.com/payroll",
  table: "employee_salaries",
};
// A SQLite constraint error is the single most dangerous string in the restore path: it embeds the table, the
// column AND the offending ROW VALUE. This one carries the operator's e-mail and a live-looking secret.
const D1_CONSTRAINT_MESSAGE = `D1_ERROR: UNIQUE constraint failed: ${SENTINELS.table}.email (value '${SENTINELS.email}', token '${SENTINELS.secret}')`;

function leaks(label: string, artefact: unknown): void {
  const body = JSON.stringify(artefact);
  for (const [name, value] of Object.entries(SENTINELS)) {
    ok(`${label}: no ${name} sentinel`, !body.includes(value));
  }
  // NOTE: the S3 <Code> token ("AccessDenied") is a documented, closed, vendor-defined enum member that the
  // fault ring is DESIGNED to carry (dest/fault-log.ts S3_ERROR_CODES); it is never customer data. What must
  // never ride is the store's / SQLite's free-text MESSAGE, which embeds the bucket, the key and the row value.
  ok(`${label}: no raw provider message text`, !body.includes("UNIQUE constraint failed") && !body.includes("not authorized to") && !body.includes("constraint failed"));
}

// ---------------------------------------------------------------------------------------------------------
// Data loss: a D1 restore that half-applies, and one that refuses "target not empty"
// ---------------------------------------------------------------------------------------------------------
console.log("D1 partial apply is localised (batch, total, closed class) and the SQLite message never rides");

// A D1 double whose batch() throws the sentinel-bearing constraint error on the Nth call.
function d1Double(opts: { throwOnBatch?: number; userTables?: string[] } = {}): D1Database {
  let batchCalls = 0;
  const stmt = { bind: () => stmt } as unknown as D1PreparedStatement;
  return {
    prepare: (sql: string) => {
      if (sql.startsWith("SELECT name FROM sqlite_master")) {
        return {
          all: async () => ({ results: (opts.userTables ?? []).map((name) => ({ name })) }),
        } as unknown as D1PreparedStatement;
      }
      return stmt;
    },
    batch: async () => {
      batchCalls++;
      if (opts.throwOnBatch !== undefined && batchCalls === opts.throwOnBatch) throw new Error(D1_CONSTRAINT_MESSAGE);
      return [];
    },
  } as unknown as D1Database;
}

// 60 rows => two batches of 50/10. The SECOND batch throws, so the database is HALF LOADED: the exact silent
// corruption this check exists to localise.
const rows = Array.from({ length: 60 }, (_, i) => [i, `row-${i}`]);
const rowsRecord = new TextEncoder().encode(JSON.stringify({ format: D1_ROWS_FORMAT, table: SENTINELS.table, columns: ["id", "name"], rows }));
const midApply = new D1RestoreSink(d1Double({ throwOnBatch: 2 }), "payroll-db", false);
let d1Caught: unknown;
try {
  await midApply.put("d1/payroll", rowsRecord);
} catch (e) {
  d1Caught = e;
}
const midEvidence = d1FaultEvidence(d1Caught);
ok("mid-apply fault is TYPED (the apply can read it off the throw)", midEvidence !== null);
ok("mid-apply names the closed class from D1's own tokens", midEvidence?.d1ErrorClass === "constraint");
ok("mid-apply LOCALISES the fault: failedBatchIndex 1 of batchTotal 2", midEvidence?.failedBatchIndex === 1 && midEvidence?.batchTotal === 2);
ok("mid-apply carries no residual-table count (nothing was refused)", midEvidence?.residualTableCount === undefined);
leaks("mid-apply evidence", midEvidence);

// The fresh-target refusal: NOTHING is written, and the operator needs to know how many tables are in the way.
const dirty = new D1RestoreSink(d1Double({ userTables: [SENTINELS.table, "audit_log", "sqlite_sequence", "_cf_KV"] }), "payroll-db", false);
const headerRecord = new TextEncoder().encode(JSON.stringify({ format: D1_HEADER_FORMAT, tables: [{ name: SENTINELS.table, columns: ["id"], sql: `CREATE TABLE ${SENTINELS.table} (id)`, rows: [] }] }));
let refusal: unknown;
try {
  await dirty.put("d1/payroll", headerRecord);
} catch (e) {
  refusal = e;
}
const refusalEvidence = d1FaultEvidence(refusal);
ok("fresh-target refusal is TYPED", refusalEvidence !== null);
ok("fresh-target refusal is its OWN class (nothing was written)", refusalEvidence?.d1ErrorClass === "target-not-empty");
ok("fresh-target refusal counts the residual USER tables (sqlite_/_cf_ internals excluded)", refusalEvidence?.residualTableCount === 2);
leaks("fresh-target evidence", refusalEvidence);

// The classifier reads a message ONLY to select a member, and RETURNS the member.
ok("classifyD1Error selects from the closed set", D1_ERROR_CLASSES.includes(classifyD1Error(new Error(D1_CONSTRAINT_MESSAGE))));
ok("classifyD1Error returns an enum, never the text", typeof classifyD1Error(new Error(D1_CONSTRAINT_MESSAGE)) === "string" && !classifyD1Error(new Error(D1_CONSTRAINT_MESSAGE)).includes(SENTINELS.email));
ok("classifyD1Error names a bigint bind refusal (an ENGINE/format question, not a data one)", classifyD1Error(new Error("D1_TYPE_ERROR: Type 'bigint' not supported")) === "type-error");

// The table-SUBSET restore silently drops the indexes/triggers of tables it did not create.
const subset = new D1RestoreSink(d1Double(), "payroll-db", false, new Set(["kept"]));
const schemaRecord = new TextEncoder().encode(
  JSON.stringify({
    format: D1_SCHEMA_FORMAT,
    schema: [
      "CREATE INDEX idx_kept ON kept (id)",
      `CREATE INDEX idx_dropped ON ${SENTINELS.table} (id)`,
      `CREATE TRIGGER trg_dropped AFTER INSERT ON ${SENTINELS.table} BEGIN SELECT 1; END`,
    ],
  }),
);
await subset.put("d1/payroll", schemaRecord);
ok("subset restore COUNTS the schema objects it filtered away (the app that breaks after a 'complete' restore)", subset.schemaFilteredCount() === 2);
ok("schemaFilteredCount is an integer, never a DDL string", typeof subset.schemaFilteredCount() === "number");

// ---------------------------------------------------------------------------------------------------------
// The restore metadata a sink SHEDS while the receipt claims full fidelity
// ---------------------------------------------------------------------------------------------------------
console.log("metadata shed at the sink is counted (closed field kinds), never the unusable value");
drainMetadataShed(); // start clean

const kvPuts: Array<{ name: string; opts?: KVNamespacePutOptions }> = [];
const kvSink = new KVRestoreSink({ put: async (name: string, _v: unknown, opts?: KVNamespacePutOptions) => void kvPuts.push({ name, ...(opts !== undefined ? { opts } : {}) }) } as unknown as KVNamespace, "ns-1");
// A stored descriptor whose expiration is UNUSABLE (the customer's own garbage TTL, carrying a sentinel).
await kvSink.put("k1", new Uint8Array([1]), { kv: { expiration: SENTINELS.secret as unknown as number } } as RestorePutOptions);
ok("KV restore still WRITES the record (the shed is by design, not a failure)", kvPuts.length === 1);
ok("KV restore drops the unusable expiration rather than writing garbage", kvPuts[0]?.opts?.expiration === undefined);

const r2Puts: unknown[] = [];
const r2Sink = new R2RestoreSink({ put: async (_k: string, _v: unknown, o?: unknown) => void r2Puts.push(o) } as unknown as R2Bucket, "bucket-1");
await r2Sink.put("o1", new Uint8Array([1]), { r2: { httpMetadata: { cacheExpiry: `not-a-date ${SENTINELS.objectKey}` } } } as RestorePutOptions);
const shed = sanitiseMetadataShed(drainMetadataShed());
ok("both sheds are counted", shed?.["kv-expiration"] === 1 && shed?.["r2-cache-expiry"] === 1);
ok("the shed map's key space is exactly the closed field vocabulary", Object.keys(shed ?? {}).every((k) => (METADATA_SHED_FIELDS as readonly string[]).includes(k)));
leaks("shed tally", shed);
ok("the shed tally is DRAINED (a warm isolate cannot attribute one restore's shed to the next)", sanitiseMetadataShed(drainMetadataShed()) === undefined);
// The chokepoint drops an out-of-vocabulary field and a hostile count outright.
const hostileShed = sanitiseMetadataShed({ "kv-expiration": 2, [SENTINELS.objectKey]: 9, [SENTINELS.email]: "1" });
ok("sanitiseMetadataShed DROPS an out-of-vocabulary field KEY", hostileShed !== undefined && Object.keys(hostileShed).length === 1 && hostileShed["kv-expiration"] === 2);
leaks("hostile shed", hostileShed);

// ---------------------------------------------------------------------------------------------------------
// Stranded multipart parts: how many, and why
// ---------------------------------------------------------------------------------------------------------
console.log("a failed multipart abort records its count AND its closed class");

// The DENIED abort (the credential may write parts but not abort them: fix the bucket policy).
const deniedLog = new DestFaultLog();
const deniedIO = {
  signedRequest: async () =>
    new Response(`<Error><Code>AccessDenied</Code><Message>not authorized to AbortMultipartUpload on ${SENTINELS.bucket}/${SENTINELS.objectKey}</Message></Error>`, { status: 403 }),
  objectLockHeaders: () => ({}),
  storageClassHeader: () => ({}),
  faults: deniedLog,
  io: { noteRetryAfterUnparseable: () => {}, noteThrottled: () => {} },
};
let abortThrew = false;
try {
  await abortMultipart(deniedIO as never, `seg/${SENTINELS.objectKey}`, "upload-id-1");
} catch {
  abortThrew = true;
}
ok("a refused abort still THROWS (the caller's best-effort contract is unchanged)", abortThrew);
const deniedSnap = deniedLog.snapshot();
ok("the stranding is COUNTED", deniedSnap.strandedAborts?.count === 1);
ok("the stranding names the DENIED class (fix the bucket policy, not a lifecycle rule)", deniedSnap.strandedAborts?.lastClass === "denied");
leaks("denied snapshot", deniedSnap);

// The NETWORK abort: the request never got an answer. This threw PAST every sink before this change.
const netLog = new DestFaultLog();
const netIO = {
  signedRequest: async () => {
    throw new Error(`fetch failed: connect ECONNRESET ${SENTINELS.endpoint}`);
  },
  objectLockHeaders: () => ({}),
  storageClassHeader: () => ({}),
  faults: netLog,
  io: {},
};
try {
  await abortMultipart(netIO as never, "seg/0001", "upload-id-2");
} catch {
  /* expected: the original fault still surfaces */
}
const netSnap = netLog.snapshot();
ok("a TRANSPORT-failed abort is recorded at all (it previously threw past every sink)", netSnap.strandedAborts?.count === 1);
ok("a transport-failed abort names the NETWORK class (it will likely heal; nothing to fix)", netSnap.strandedAborts?.lastClass === "network");
ok("a transport-failed abort also lands a fault row", netSnap.faults.some((f) => f.op === "multipart-abort"));
ok("the destination now reports EVIDENCE (so the run posts it rather than looking clean)", netLog.hasEvidence());
leaks("network snapshot", netSnap);

ok("classifyAbortFailure: a 5xx is the store, not the policy", classifyAbortFailure(undefined, 500) === "server-error");
ok("classifyAbortFailure returns a member of the closed set", ABORT_FAILURE_CLASSES.includes(classifyAbortFailure(new Error(D1_CONSTRAINT_MESSAGE))));

// The DO-side chokepoint carries it, and DROPS a hostile one.
const carried = sanitiseDestFaults({ total: 1, faults: [], strandedAborts: { count: 4, lastClass: "denied" } }, {}, 1_752_277_400_000);
ok("sanitiseDestFaults CARRIES strandedAborts into the per-downpipe record (GET /dest-faults)", carried?.strandedAborts?.count === 4 && carried.strandedAborts.lastClass === "denied");
const hostileAbort = sanitiseStrandedAborts({ count: 9, lastClass: `denied ${SENTINELS.bucket}` });
ok("an out-of-vocabulary abort class is DROPPED WHOLE (never coerced, never carried as text)", hostileAbort === undefined);
ok("a hostile strandedAborts record cannot enter the DO record", sanitiseDestFaults({ strandedAborts: { count: 1, lastClass: SENTINELS.secret } }, {}, 1)?.strandedAborts === undefined);

// ---------------------------------------------------------------------------------------------------------
// WORM "unknown" separates five otherwise indistinguishable causes
// ---------------------------------------------------------------------------------------------------------
console.log("every WORM cannot-confirm names its cause (and its remedy)");

function readIO(resp: Response | Error): Parameters<typeof objectLockStatus>[0] {
  const faults = new DestFaultLog();
  return {
    url: () => `https://s3.example.com/${SENTINELS.bucket}/`,
    amzDate: () => "20260712T000000Z",
    sha256Hex: async () => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    metered: async () => {
      if (resp instanceof Error) throw resp;
      return resp;
    },
    securityTokenHeader: () => ({}),
    signedRequest: async () => new Response("", { status: 500 }),
    creds: { accessKeyId: "AKIA", secretAccessKey: "s", region: "us-east-1", service: "s3" },
    faults,
    io: {},
  } as unknown as Parameters<typeof objectLockStatus>[0];
}
const S3_DENIED_BODY = `<Error><Code>AccessDenied</Code><Message>${SENTINELS.bucket} ${SENTINELS.endpoint}</Message></Error>`;
const denied = await objectLockStatus(readIO(new Response(S3_DENIED_BODY, { status: 403 })));
ok("a 403 probe names DENIED (the one-line IAM fix: s3:GetBucketObjectLockConfiguration)", denied.enabled === "unknown" && denied.unknownReason === "denied");
leaks("denied status", denied);
const notImpl = await objectLockStatus(readIO(new Response("<Error><Code>NotImplemented</Code></Error>", { status: 501 })));
ok("a 501 probe names NOT-IMPLEMENTED (the store has no Object-Lock API: no IAM change can help)", notImpl.unknownReason === "not-implemented");
const serverErr = await objectLockStatus(readIO(new Response("<Error/>", { status: 503 })));
ok("a 5xx probe names SERVER-ERROR (the store, not the customer)", serverErr.unknownReason === "server-error");
const redirected = await objectLockStatus(readIO(new Response("", { status: 307, headers: { location: `https://s3.us-west-2.amazonaws.com/${SENTINELS.bucket}` } })));
ok("a redirected probe names REDIRECT (a proxy, or the bucket lives elsewhere)", redirected.unknownReason === "redirect");
leaks("redirect status", redirected);
const mangled = await objectLockStatus(readIO(new Response(`<html>proxy error for ${SENTINELS.bucket}</html>`, { status: 200 })));
ok("a 200 whose body is not an ObjectLockConfiguration names BODY-UNPARSEABLE (a proxy mangling the XML)", mangled.unknownReason === "body-unparseable");
leaks("mangled status", mangled);
const netProbe = await objectLockStatus(readIO(new Error(`fetch failed ${SENTINELS.endpoint}`)));
ok("a transport fault names NETWORK (self-healing; it used to read exactly like a permanent denial)", netProbe.unknownReason === "network");
const notEnabled = await objectLockStatus(readIO(new Response("", { status: 404 })));
ok("a 404 is still the honest not-enabled, with NO reason (it is not an unknown at all)", notEnabled.enabled === false && notEnabled.unknownReason === undefined);
const enforced = parseObjectLockConfig("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>");
ok("a real Object-Lock answer is unchanged (enabled, no reason)", enforced.enabled === true && enforced.unknownReason === undefined);
// R2Destination's second constructor argument is the optional spend Meter, which this probe does not exercise.
const r2Status = await new R2Destination({} as unknown as R2Bucket).objectLockStatus();
ok("the R2 binding names its STRUCTURAL limit (no IAM fix exists, and no S3-endpoint one either)", r2Status.enabled === "unknown" && r2Status.unknownReason === "r2-binding-unsupported");
ok("every reason is a member of the closed set", [denied, notImpl, serverErr, redirected, mangled, netProbe, r2Status].every((s) => s.unknownReason === undefined || (WORM_UNKNOWN_REASONS as readonly string[]).includes(s.unknownReason)));
ok("wormUnknownReasonForStatus never mislabels an unrecognised refusal", wormUnknownReasonForStatus(418) === "other");

// ---------------------------------------------------------------------------------------------------------
// The CRON plane.
// Each note is raised on its real fault path by the passes; here the LEDGER is driven directly, drained, and
// folded through the DO-side chokepoint exactly as POST /diag/cron-health does.
// ---------------------------------------------------------------------------------------------------------
console.log("cron: the drained delta folds into the bounded record, and a HOSTILE delta cannot land anything");
resetCronFaultLedger();
clearCarriedCronNotes();

// Three one-shot critical alerts consumed and never delivered.
noteUndeliveredCriticalAlert("update-rollback-needed", true);
noteUndeliveredCriticalAlert("canary-dead", true);
noteUndeliveredCriticalAlert("posture-regression", true);
noteNotifyHistoryAppendFailure();
noteDigestNoTransport();
noteDroppedEmission("backup-failure");
noteUpdateChannelCheck(false);
noteUpdateConfirmClearFailure();
noteCpExportTruncated(3);
noteCpExportDestFail(new Error(`PUT ${SENTINELS.objectKey}: status 403 (AccessDenied) on ${SENTINELS.bucket}`));
noteCpExportDestFail(new Error(`could not unwrap the destination credential: CONFIG_WRAP_KEY envelope ${SENTINELS.secret}`));
noteCpPlaintextPurgePending(2);
noteCpExportRecordWriteFailure();
noteCpExportPassThrew();
notePushTrailWriteFailure("siem");
notePushTrailWriteFailure("otlp");
noteRestoreTestSkip("dp-payroll", "pre-drill-fault");
noteRestoreTestSkip("dp-payroll", "budget-deferred");
noteRestoreTestSkip("dp-crm", "record-failed");
noteRestoreTestPassDeferred();
noteFleetDrillBatch(true);
noteReconcileEnabled(true);
noteReconcileSkip("dest-build-failed");
noteRunlogSigVerdict(false); // the .sig object was ABSENT
noteRunlogSigVerdict(true); // the signature FAILED to verify
noteReconcileCircuitBreaker();

const delta = drainCronFaultLedger();
const health = applyCronHealth(undefined, delta, 1_752_277_400_000, 900_000);

ok("the undelivered CRITICAL alerts are latched, by closed event", health.notify.undeliveredCritical["update-rollback-needed"]?.count === 1 && health.notify.undeliveredCritical["canary-dead"]?.count === 1 && health.notify.undeliveredCritical["posture-regression"]?.count === 1);
ok("the spent one-shot CLAIMS are counted (the page will never be re-attempted)", health.notify.claimSpent === 3);
ok("the lost history append is counted, with a time", health.notify.historyAppendFailures === 1 && typeof health.notify.historyAppendFailuresLastAt === "string");
ok("the digest flushed to a dead channel is counted", health.notify.digestNoTransport === 1);
ok("the WHOLE lost emission names its event", health.notify.droppedEmissions["backup-failure"] === 1);
ok("the update channel's verification verdict is recorded", health.updates.channelVerified === false && health.updates.verifyFailures === 1 && typeof health.updates.lastCheckAt === "string");
ok("the stuck confirm-clear is counted", health.updates.confirmClearFailures === 1);
ok("the budget-TRUNCATED export is visible (the record no longer looks complete)", health.cpExport.truncated === true && health.cpExport.destsSkippedByBudget === 3);
ok("each per-destination refusal names its CLOSED cause", health.cpExport.perDestFail.auth === 1 && health.cpExport.perDestFail["wrap-key"] === 1);
ok("the unpurged plaintext recovery generations are counted", health.cpExport.plaintextPurgePending === 2);
ok("the export-health record's OWN lost write is counted", health.cpExport.recordWriteFailures === 1);
ok("a pass-level throw (which bypasses the health record entirely) is counted", health.cpExport.passThrewCount === 1);
ok("both push trails' lost writes are counted (a stranded cursor => duplicate batches)", health.push.siemTrailWriteFailures === 1 && health.push.otlpTrailWriteFailures === 1);
ok("the per-downpipe restore-test NON-EXECUTION is recorded, by closed class", health.restoreTest.skips["dp-payroll"]?.cls === "budget-deferred" && health.restoreTest.skips["dp-crm"]?.cls === "record-failed");
ok("the whole-pass budget deferral is counted (chronic starvation is the fleet-wide-overdue ticket)", health.restoreTest.passBudgetDeferred === 1);
ok("the fleet-drill campaign's own batch health moves", health.restoreTest.fleetBatchFailures === 1 && typeof health.restoreTest.fleetLastBatchAt === "string");
ok("the opt-in flag is ECHOED (so an empty section is no longer ambiguous)", health.reconcile.enabled === true && typeof health.reconcile.lastPassAt === "string");
ok("the skip names its closed reason", health.reconcile.skips["dest-build-failed"] === 1 && health.reconcile.lastSkipReason === "dest-build-failed");
ok("sig-absent and verify-failed are SPLIT (re-sign vs do-not-proceed)", health.reconcile.runlogSigAbsent === 1 && health.reconcile.runlogVerifyFailed === 1);
ok("the circuit breaker is a boolean, not the free text that could describe the topology", health.reconcile.circuitBreakerTripped === true);
leaks("cron health record", health);

ok("classifyCpExportFail returns a member of the closed set", CP_EXPORT_FAIL_CLASSES.includes(classifyCpExportFail(new Error(D1_CONSTRAINT_MESSAGE))));
ok("classifyCpExportFail names a WORM refusal (permanent) apart from a blip", classifyCpExportFail(new Error("PUT failed: status 403 (InvalidRetentionPeriod) object lock")) === "worm-denied");

// ---- the HOSTILE delta: sentinels as map KEYS and as enum VALUES, from a drifted or malicious caller ------
const hostile = {
  notify: {
    undeliveredCritical: { [SENTINELS.email]: 9, "backup-failure": 1 },
    droppedEmissions: { [SENTINELS.endpoint]: 4 },
    claimSpent: 1e12,
    historyAppendFailures: -5,
  },
  updates: { channelVerified: SENTINELS.secret, verifyFailures: "many" },
  cpExport: { perDestFail: { [SENTINELS.bucket]: 3, [D1_CONSTRAINT_MESSAGE]: 1, auth: 2 }, plaintextPurgePending: 4 },
  push: { siemTrailWriteFailures: 2 },
  restoreTest: {
    skips: [
      { id: `dp-ok`, cls: "pre-drill-fault" },
      { id: `dp-evil\r\nX-Injected: header`, cls: "pre-drill-fault" },
      { id: "dp-2", cls: `budget-deferred ${SENTINELS.secret}` },
      { id: "dp-3", cls: SENTINELS.objectKey },
    ],
  },
  reconcile: { skips: { [SENTINELS.objectKey]: 2, "signer-missing": 1 }, lastSkipReason: SENTINELS.secret },
  // A whole unknown sub-record from a future/hostile writer: nothing may be read from it.
  [SENTINELS.secret]: { anything: SENTINELS.email },
};
const gated = applyCronHealth(emptyCronHealth(), hostile, 1_752_277_400_000, 900_000);
ok("HOSTILE: an out-of-vocabulary EVENT key is dropped; the in-vocabulary one survives", gated.notify.undeliveredCritical[SENTINELS.email] === undefined && gated.notify.undeliveredCritical["backup-failure"]?.count === 1);
ok("HOSTILE: an out-of-vocabulary dropped-emission key is dropped", Object.keys(gated.notify.droppedEmissions).length === 0);
ok("HOSTILE: a hostile count is clamped, and a negative one is discarded", gated.notify.claimSpent <= 100_000 && gated.notify.historyAppendFailures === 0);
ok("HOSTILE: a non-boolean channelVerified is not carried", gated.updates.channelVerified === undefined);
ok("HOSTILE: an out-of-vocabulary export fail class is dropped; the real one survives", Object.keys(gated.cpExport.perDestFail).length === 1 && gated.cpExport.perDestFail.auth === 2);
ok("HOSTILE: an out-of-vocabulary restore-test class drops the ROW WHOLE (never half-carried)", gated.restoreTest.skips["dp-2"] === undefined && gated.restoreTest.skips["dp-3"] === undefined && gated.restoreTest.skips["dp-ok"]?.cls === "pre-drill-fault");
ok("HOSTILE: a downpipe id is control-stripped (a label can never inject a line break)", Object.keys(gated.restoreTest.skips).every((k) => !k.includes("\n")));
ok("HOSTILE: an out-of-vocabulary reconcile reason is dropped; the real one survives", Object.keys(gated.reconcile.skips).length === 1 && gated.reconcile.skips["signer-missing"] === 1 && gated.reconcile.lastSkipReason === "signer-missing");
leaks("cron health record (hostile delta)", gated);

// ---- END TO END: the drain POSTS to the DO sink, and raises the pack-visible admin alarms ----------------
console.log("cron: the drain posts the delta AND raises the admin alarms the pack already carries");
resetCronFaultLedger();
clearCarriedCronNotes();
resetPendingDroppedWrites();
const posted: Array<{ path: string; body: unknown }> = [];
const schedulerDouble = {
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = new URL(input instanceof Request ? input.url : String(input));
    posted.push({ path: url.pathname, body: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  },
} as unknown as DurableObjectStub;

noteUndeliveredCriticalAlert("backup-failure", true);
noteRestoreTestSkip("dp-payroll", "pre-drill-fault");
notePushTrailWriteFailure("siem");
noteReconcileSkip("inventory-fault");
await recordCronHealth(schedulerDouble, 900_000);

const cronPost = posted.find((p) => p.path === "/diag/cron-health");
const counterPost = posted.find((p) => p.path === "/diag/admin-counters");
ok("the cron delta reaches its DO sink (POST /diag/cron-health -> GET /cron-health)", cronPost !== undefined);
ok("the ADMIN ALARMS reach the aggregate the pack already carries in full (POST /diag/admin-counters)", counterPost !== undefined);
const bumps = (counterPost?.body as { bumps?: Record<string, number> } | undefined)?.bumps ?? {};
ok("the alarm for an undelivered critical page is raised", bumps["notify-critical-alert-undelivered"] === 1);
ok("the alarm for a restore test that did not run is raised", bumps["restore-test-not-run"] === 1);
ok("the alarm for a lost push-trail write is raised", bumps["push-trail-write-failed"] === 1);
ok("the alarm for a skipped reconcile pass is raised", bumps["reconcile-pass-skipped"] === 1);
ok("every alarm name is in the CLOSED admin-counter vocabulary (so the pack's projection carries it)", Object.keys(bumps).every((n) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(n)));
const alarmRecord = applyAdminCounters(undefined, bumps, "2026-07-12T00:00:00.000Z");
ok("the alarms survive the admin-counter chokepoint (they land in the pack's adminCounters)", alarmRecord["notify-critical-alert-undelivered"]?.count === 1);
ok("a LANDED report clears the carried notes (they are not re-reported forever)", Object.keys(carriedCronNotes().notify ?? {}).length === 0);
leaks("cron drain (posted bodies)", posted);

// A DROPPED report must NOT lose the notes: they re-report on the next healthy tick.
clearCarriedCronNotes();
noteUndeliveredCriticalAlert("backup-stale", true);
const deadScheduler = { async fetch(): Promise<Response> { return new Response("no", { status: 503 }); } } as unknown as DurableObjectStub;
await recordCronHealth(deadScheduler, 900_000);
ok("a DROPPED report KEEPS the carried notes (the outage cannot erase its own evidence)", (carriedCronNotes().notify?.undeliveredCritical?.["backup-stale"] ?? 0) === 1);
clearCarriedCronNotes();
resetPendingDroppedWrites();

// ---------------------------------------------------------------------------------------------------------
// A broken discovery token reads as an EMPTY ACCOUNT in the cost projection
// ---------------------------------------------------------------------------------------------------------
console.log("an estate projection that could not be made says so (it no longer reads as an empty account)");
const estateBumps: Array<Record<string, number>> = [];
const estateScheduler = {
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.pathname === "/diag/admin-counters") estateBumps.push((JSON.parse(String(init?.body ?? "{}")) as { bumps: Record<string, number> }).bumps);
    // No discovery config and no token: the probe cannot run at all.
    return new Response(JSON.stringify({ config: null, token: null }), { headers: { "content-type": "application/json" } });
  },
} as unknown as DurableObjectStub;
const estateResp = await handleEstateSize({} as Env, estateScheduler);
const estateBody = (await estateResp.json()) as { available: boolean; totalBytes: number };
ok("the console response is BYTE-UNCHANGED (an honest empty estate, available:false)", estateBody.available === false && estateBody.totalBytes === 0);
ok("the engine now RECORDS that the estimate was impossible, not that the account is empty", estateBumps.some((b) => b["cost-estate-token-missing"] === 1));
ok("the counter name is in the closed vocabulary the pack projects", (ADMIN_COUNTER_NAMES as readonly string[]).includes("cost-estate-token-missing") && (ADMIN_COUNTER_NAMES as readonly string[]).includes("cost-estate-probe-failed"));
leaks("counter bumps", estateBumps);
resetPendingDroppedWrites();

// ---------------------------------------------------------------------------------------------------------
// Vocabulary hygiene: every closed set here is non-empty, unique and text-free.
// ---------------------------------------------------------------------------------------------------------
for (const [name, set] of Object.entries({
  D1_ERROR_CLASSES,
  METADATA_SHED_FIELDS,
  ABORT_FAILURE_CLASSES,
  WORM_UNKNOWN_REASONS,
  CP_EXPORT_FAIL_CLASSES,
  RESTORE_TEST_SKIP_CLASSES,
  RECONCILE_SKIP_REASONS,
}) as Array<[string, readonly string[]]>) {
  ok(`${name}: a closed, unique, lower-case-token vocabulary`, set.length > 0 && new Set(set).size === set.length && set.every((m) => /^[a-z0-9-]+$/.test(m)));
}

console.log(failures === 0 ? "\nvalidate-support-round5: PASS" : `\nvalidate-support-round5: ${failures} FAILURE(S)`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
