// Prove that fault evidence reaches the BUNDLE, and reaches it redaction-safe.
//
// THE CARDINAL RULE THIS SUITE ENFORCES: a fault is NOT closed until its evidence is IN THE PACK. A recorder
// built, a closed vocabulary declared, a classifier written, a DO route serving it, and NOTHING reading the
// result LOOKS closed to a reviewer who checks the recorder and stops there, while recording into a void is
// worse than not recording at all.
//
// This suite drives the pack end to end rather than trusting the recorders' own reports, and guards against
// three shapes of that failure:
//
//   1. GET /rto exists on the scheduler DO; unless a support gatherer fetches it, every field the RTO
//      estimator computes -- including rejectedSamples and degradationCause -- lands in a route nothing reads.
//   2. fetchSealFaults is a FIELD ALLOWLIST, not an unfiltered projection. The kind gate admits new kinds
//      automatically, so rows can arrive in the pack stripped of the very fields that diagnose them -- present,
//      and useless. The most dangerous shape of all: it looks fine.
//   3. fetchIntegrityFaults is likewise a field whitelist, so new fault fields can be stored, served, and
//      dropped silently at the pack boundary.
//
// Every assertion below is therefore END TO END: a DO record goes in, buildSupportBundle runs, and the FIELD is
// asserted in the BUILT BUNDLE BODY. Nothing is asserted against a gatherer in isolation.
//
// The second half is the no-custody proof. Every DO record here is served HOSTILE: each carries planted
// customer sentinels (an operator e-mail, a bucket, an object key, a live-looking secret, an endpoint, a connId
// and a raw provider/SQLite error message), out-of-vocabulary enum VALUES, and out-of-vocabulary map KEYS --
// the last being the classic closed-vocabulary bypass, where a caller-derived string becomes a map key and
// rides into the pack as a KEY rather than a value, which a value-only gate misses entirely. The suite then
// serialises the whole bundle and asserts that not one byte of any sentinel survives, keys and values alike.
//
// Run: node test/validate-support-round5-plumb.ts

import { buildSupportBundle } from "../src/admin/support.ts";
import { SUPPORT_SECTION_NAMES } from "../src/admin/support-roster.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The customer sentinels. Each is planted INSIDE a DO record the pack reads, in the field a drifted, older or
// malicious writer would most plausibly have put it in. None may appear in any byte of the bundle.
// Declared WITHOUT an index signature so each sentinel is a known key of a known type: several are used as
// computed property names below (the hostile-map-KEY vectors), which a Record<string, string> lookup cannot
// be, since every read off it is string|undefined. Object.entries still walks the whole set for the
// redaction sweep, so no sentinel can be added here and silently skipped.
const SENTINELS = {
  email: "cfo@acme-payroll.example",
  bucket: "acme-prod-payroll-backups",
  objectKey: "kv/tenants/acme/salaries-2026.json",
  secret: "sk_live/51H8xQ2eZ+vKYlo2C0abcdefghij=",
  endpoint: "https://acme.r2.cloudflarestorage.com/payroll",
  connId: "acme-okta-prod",
  providerMessage: "SqliteError: UNIQUE constraint failed: employees.email (cfo@acme-payroll.example)",
};

// The scheduler double. Every route below answers with a record that is deliberately CONTAMINATED: real,
// in-vocabulary evidence sits alongside sentinels, hostile enum values and hostile map keys.
function schedulerDouble(opts: { faultRoutes?: Set<string> } = {}): DurableObjectStub {
  const json = (v: unknown): Response => new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
  return {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const p = url.pathname;
      // A route in faultRoutes THROWS: the section must read "error", never a clean "empty". An unreadable
      // ledger reported as an honest absence is a lie a diagnosis would act on.
      if (opts.faultRoutes?.has(p)) throw new Error(`DO unreachable: ${SENTINELS.endpoint}`);
      switch (p) {
        // ---- the SAML signing certs the engine actually holds ----------------------------------------------
        case "/idp-cert-health":
          return json({
            health: {
              // THE HALF-CORRUPT ROLLOVER PASTE: 3 certs, only 2 parse. The engine verified on a good one and
              // said nothing; when that one expires, every sign-in dies at once.
              certCount: 3,
              parseableCount: 2,
              windowReadableCount: 1,
              // p521 is the "every sign-in dies in a generic import error" diagnosis. The hostile key must not
              // become a bundle key, and a negative count must not ride.
              curves: { p256: 1, p521: 1, [SENTINELS.connId]: 4, rsa: -3 },
              nearestNotAfter: 1767225600000,
              expiryObserved: false, // the state in which NO expiry warning can EVER fire
              unparseableCertsTotal: 7,
              windowUnreadableTotal: 2,
              windowUnenforcedVerifies: 9, // sign-ins whose freshness check ran DISARMED
              noUsableCertRefusals: 4, // the outage itself
              unsupportedCurveSeen: 1,
              observations: 12,
              lastAt: 1752277400000,
            },
          });
        // ---- WHICH connection is failing, by OPAQUE ordinal ------------------------------------------------
        case "/sso-failures-by-conn":
          return json({
            "conn-2": { signature: { count: 12, lastAt: "2026-07-11T00:00:00.000Z" } },
            // A raw connId as a KEY is the bypass this gate exists to foreclose: it must never become a
            // bundle key, even though its inner payload is perfectly well-formed.
            [SENTINELS.connId]: { signature: { count: 99, lastAt: "2026-07-11T00:00:00.000Z" } },
            // A well-shaped ordinal carrying an out-of-vocabulary CODE: the code is dropped, and because that
            // leaves the connection with nothing, the connection drops too.
            "conn-3": { [SENTINELS.providerMessage]: { count: 5, lastAt: "x" } },
          });
        case "/auth-posture":
          return json({
            sessionSigningKey: { present: true, ageMs: 86_400_000, adequateLength: true },
            doPlaintextSecretsMissing: 2,
            // The ordinals ride; the raw connId and the secret must be dropped by the SHAPE gate outright.
            doPlaintextSecretsMissingConns: ["conn-1", "conn-4", SENTINELS.connId, SENTINELS.secret],
            adminCredentialPaths: { passkeyCredentials: 1, enabledIdpConnections: 2 },
          });
        // ---- the RTO estimator's self-assessment (a route NOTHING read) ------------------------------------
        case "/rto":
          return json({
            fleet: { known: true, confidence: "low", estimateSeconds: 7200, basedOnDrills: 2, degradationCause: "thin-sample" },
            downpipes: [
              {
                id: "payroll",
                // The customer LABEL and the free-text reason/caveat must NOT ride: only the closed cause does.
                name: SENTINELS.email,
                reason: `could not size ${SENTINELS.bucket}`,
                caveat: `derived from ${SENTINELS.objectKey}`,
                known: true,
                confidence: "low",
                estimateSeconds: 3600,
                basedOnDrills: 2,
                observedThroughputBytesPerSec: 1_048_576,
                // "basedOnDrills says 2 but we ran 15 restore tests": here are the other 13.
                rejectedSamples: { count: 13, lastReason: "non-positive-bytes" },
                degradationCause: "archive-size-unknown",
              },
              // A drifted confidence drops the estimate WHOLE: a recovery number with no confidence is worse
              // than no number, because a DR plan would be built on it.
              { id: "ledger", known: true, confidence: SENTINELS.providerMessage, estimateSeconds: 60 },
            ],
          });
        // ---- the format layer's forensics --------------------------------------------------------------------
        case "/integrity-faults":
          return json({
            payroll: {
              at: 1752277400000,
              // the anti-rollback anomaly. The detector's own reason string interpolates the customer's
              // downpipe and run ids and must never ride; the two DISAGREEING indices and the RUNLOG byte
              // digest are the whole evidence.
              runlogAnomalies: [
                { kind: "index-regression", indexA: 41, indexB: 37, entryCount: 42, digest: "a1b2c3d4e5f6" },
                { kind: "sig-invalid", lineOrdinal: 3, entryCount: 42, digest: "0f1e2d3c4b5a" },
                // A raw exception message as the KIND, and an object key in the DIGEST seam: both dropped.
                { kind: SENTINELS.providerMessage, indexA: 1, digest: SENTINELS.objectKey },
              ],
              // the writer's loud refusals. source-enumerated-zero is the CUSTOMER-side fault (an emptied
              // KV namespace) that reached support as "the engine broke".
              writerRefusals: { "source-enumerated-zero": 3, [SENTINELS.bucket]: 9 },
              // the attestation OVERCLAIM -- a strided sample with NO presence pass, the mode in which a
              // durably missing shard outside the sample reads as complete.
              attestCoverage: "sampled-no-presence",
            },
            ledger: {
              at: 1752277400001,
              // A drifted coverage mode must be DROPPED, never coerced to a neighbouring member: coercing
              // "sampled-no-presence-ish" to "full" would manufacture a completeness claim out of a fault.
              attestCoverage: `sampled-no-presence${SENTINELS.secret}`,
              writerRefusals: { "stream-no-destination": 1 },
            },
          });
        // ---- the seal ring --------------------------------------------------------------------------------
        case "/seal-faults":
          return json({
            faults: [
              // the run's verdict never reached the scheduler. outcome "ok" on a run the history shows
              // as ABANDONED is a DIRECT contradiction between the run history and the bucket.
              { kind: "completion-lost", at: 1752277400000, downpipeId: "payroll", runId: "r-9", outcome: "ok", causeDigest: "9f8e7d6c5b4a", attemptClasses: ["transient", SENTINELS.secret, "destination"] },
              // the corrupt checkpoint NAMES ITSELF and SIZES the loss. This is the mechanism behind
              // "the big backup restarts from scratch every night" -- 137 slices, 41,000 records, discarded.
              { kind: "checkpoint-unwrap-failed", at: 1752277400001, downpipeId: "payroll", runId: "r-9", unwrapCode: "master-unwrap" },
              { kind: "resume-abandoned", at: 1752277400002, downpipeId: "payroll", runId: "r-9", slicesDiscarded: 137, recordsDiscarded: 41000 },
              { kind: "checkpoint-coerced", at: 1752277400003, downpipeId: "payroll", checkpointField: "counts", coerced: 2, legacyAbsent: false },
              // the refuse-to-sign guard. found/expected SIZE the shortfall; the bytes are THERE and
              // CHANGED, which is corruption or tamper and never a lifecycle event.
              { kind: "scratch-hash-mismatch", at: 1752277400004, downpipeId: "payroll", found: 11, expected: 12, ordinal: 7 },
              // the history chain RESTARTED -- a downpipe repointed at a re-created or wrong bucket.
              { kind: "runlog-absent", at: 1752277400005, downpipeId: "payroll", priorRuns: 8, historyChainRestarted: true },
              // A drifted checkpoint field and a drifted unwrap code must be DROPPED (the row may still ride;
              // the drifted FIELD may not).
              { kind: "checkpoint-invalid", at: 1752277400006, downpipeId: "payroll", checkpointField: SENTINELS.objectKey },
            ],
          });
        // ---- the cron plane -------------------------------------------------------------------------------
        case "/cron-health":
          return json({
            passes: {},
            tick: { gapDetected: false, missedApprox: 0, recordFailures: 0 },
            discovery: { skips: {}, consecutiveSkips: 0 },
            beacon: { envPresent: { url: false, ingestKey: false, accountId: false }, failCounts: {}, stateWriteFailures: 0 },
            autoHeal: { deferrals: {}, amnesiaProbeWriteFailures: 0 },
            siem: {},
            danglingDestinationRefs: 0,
            // the CRITICAL alert CLAIMED and never delivered. claimSpent means the
            // one-shot claim is gone: a bad update is live and the owner is never paged, permanently.
            notify: {
              undeliveredCritical: { "update-rollback-needed": { count: 1, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.email]: { count: 5, lastAt: "x" } },
              claimSpent: 1,
              historyAppendFailures: 3,
              historyAppendFailuresLastAt: "2026-07-11T00:00:00.000Z",
              digestNoTransport: 2,
              droppedEmissions: { "backup-failure": 4, [SENTINELS.objectKey]: 7 },
            },
            // the update channel STOPPED VERIFYING (a signing-key rotation, or tamper) and the pass
            // returned in silence -- no alert, no evidence.
            updates: { lastCheckAt: "2026-07-11T00:00:00.000Z", channelVerified: false, verifyFailures: 6, confirmClearFailures: 2, confirmClearFailuresLastAt: "2026-07-11T00:00:00.000Z" },
            // worm-denied is deliberately its own class -- it arrives as a 403 and the shared classifier
            // would file it under auth and send the operator to rotate a perfectly good key.
            cpExport: {
              lastAttemptAt: "2026-07-11T00:00:00.000Z",
              truncated: true,
              destsSkippedByBudget: 3,
              perDestFail: { "worm-denied": 2, transport: 1, [SENTINELS.bucket]: 9 },
              plaintextPurgePending: 4,
              recordWriteFailures: 1,
              passThrewCount: 1,
            },
            // a lost trail write on a SUCCESSFUL delivery strands the cursor => the next tick re-sends
            // the same batch. This is the duplicate-events ticket.
            push: { siemTrailWriteFailures: 5, otlpTrailWriteFailures: 1, lastAt: "2026-07-11T00:00:00.000Z" },
            // the drills that did NOT RUN. The pre-drill throw lands before all recording machinery.
            restoreTest: {
              skips: {
                payroll: { cls: "pre-drill-fault", count: 9, lastAt: "2026-07-11T00:00:00.000Z" },
                // A drifted class drops the ROW whole: a downpipe named as skipped with no reason invites a
                // wrong diagnosis more surely than an absent row does.
                ledger: { cls: SENTINELS.providerMessage, count: 3, lastAt: "x" },
              },
              passBudgetDeferred: 7,
              fleetLastBatchAt: "2026-07-11T00:00:00.000Z",
              fleetBatchFailures: 2,
            },
            // the flag ECHO: without this field, "never turned on" and "on and bailing for weeks" read identically.
            reconcile: {
              enabled: true,
              lastPassAt: "2026-07-11T00:00:00.000Z",
              lastSkipReason: "signer-missing",
              skips: { "signer-missing": 4, [SENTINELS.secret]: 2 },
              runlogSigAbsent: 1,
              runlogVerifyFailed: 3, // a signer rotation or TAMPER: do NOT proceed
              persistFailures: 2,
              circuitBreakerTripped: true,
            },
          });
        // ---- the sched plane ------------------------------------------------------------------------------
        case "/sched-diag":
          return json({
            ceremonyFaults: {}, recentErrors: [], contractFaults: {}, droppedWrites: {}, defaultDestination: null,
            freshnessFaults: {}, vocabDrops: {}, expiryObserveFaults: {}, approvalFaults: {}, storageAnomalies: {},
            rosterDiscards: [], recoveryResume: null, destResolveFallbacks: null, canaryLosses: null, drillDrops: {},
            notifyDrops: null, governanceFaults: {}, refusalRings: {}, adminRefusals: {}, clientDiagnostics: null,
            // every refused config save, at the ONE funnel every DO validator throw passes through.
            // reserved-binding is tested FIRST so a SIGNER_PRIVATE confused-deputy attempt can never coarsen
            // into an ordinary typo. cp-reconcile is the DR half: without this recording it writes NOTHING AT ALL.
            configRejections: {
              "destination-set|reserved-binding": { count: 2, lastAt: "2026-07-11T00:00:00.000Z" },
              "cp-reconcile|body-unparseable": { count: 1, lastAt: "2026-07-11T00:00:00.000Z" },
              // A hostile composite key OUTSIDE the re-derived cross product: dropped, never split.
              [`${SENTINELS.bucket}|cron-invalid`]: { count: 9, lastAt: "x" },
              [SENTINELS.providerMessage]: { count: 4, lastAt: "x" },
            },
            // grant-over-authority is a SELF-ELEVATION attempt. The public 403 stays the bare
            // "forbidden"; the GATE is recorded engine-side only.
            authzRefusals: {
              "grant-over-authority": { count: 3, lastAt: "2026-07-11T00:00:00.000Z" },
              "restore.apply": { count: 5, lastAt: "2026-07-11T00:00:00.000Z" },
              [SENTINELS.email]: { count: 8, lastAt: "x" },
            },
            // delete your last channel and detection SILENTLY STOPS.
            alertingHealth: {
              "detection-off-no-sink": { count: 4, lastAt: "2026-07-11T00:00:00.000Z" },
              "cron-deadman-tripped": { count: 2, lastAt: "2026-07-11T00:00:00.000Z" },
              "undeliverable-alert-batch": { count: 6, lastAt: "2026-07-11T00:00:00.000Z" },
              [SENTINELS.endpoint]: { count: 3, lastAt: "x" },
            },
            // the "we rotated the Datadog key and the engine kept pushing with the old one" ticket. The
            // count is DROPPED ITEMS. Nothing about either secret is recorded -- only that a substitution happened.
            configCoercions: {
              "otlp-destination|malformed-secret-kept-prior": { count: 1, lastAt: "2026-07-11T00:00:00.000Z" },
              "destination|invalid-optional-field": { count: 3, lastAt: "2026-07-11T00:00:00.000Z" },
              [`${SENTINELS.secret}|coerced-zero`]: { count: 7, lastAt: "x" },
            },
            // the rows a bounded record dropped.
            capTruncations: {
              "export-health-perdest": { count: 5, lastAt: "2026-07-11T00:00:00.000Z" },
              "roster-ghosts": { count: 2, lastAt: "2026-07-11T00:00:00.000Z" },
              [SENTINELS.objectKey]: { count: 4, lastAt: "x" },
            },
            // the collector's cursor sits BELOW the oldest retained entry, so those audit events
            // rolled over and it will NEVER receive them.
            auditEgress: {
              mirrorFailures: { count: 11, lastAt: "2026-07-11T00:00:00.000Z" },
              gapPagesServed: { count: 2, lastAt: "2026-07-11T00:00:00.000Z", lastGapBeforeSeq: 4096 },
            },
            // THIS PROJECTION IS THE CHOKEPOINT. The override carries a free-text justification and the
            // acceptedBy EMAIL of whoever accepted the risk, and NEITHER may cross.
            posture: {
              lastEvaluatedAt: "2026-07-11T00:00:00.000Z",
              checks: [
                { id: "immutability", passed: false, severity: "high" },
                { id: SENTINELS.bucket, passed: true, severity: "low" }, // invented id: dropped
              ],
              overrides: [
                { checkId: "immutability", overrideKind: "risk-accepted", at: "2026-07-11T00:00:00.000Z", justification: `accepted by ${SENTINELS.email} for ${SENTINELS.bucket}`, acceptedBy: SENTINELS.email },
              ],
              // identity-read-failed is a DROPPED IDP_KV BINDING: a permanent one-line fix that would otherwise be
              // indistinguishable from a transient blip ("admin-strong-auth reports cannot-verify for weeks").
              inputFaults: { "identity-read-failed": { count: 14, lastAt: "2026-07-11T00:00:00.000Z" }, [SENTINELS.secret]: { count: 2, lastAt: "x" } },
            },
          });
        // ---- the beacon's intermittency ----------------------------------------------------------------------
        case "/beacon-state":
          return json({
            at: 1752277400000,
            ok: false,
            status: 401,
            errorClass: "non-2xx",
            // "ok, fail, ok, fail" is a DIFFERENT ticket from "fail, fail, fail", and a last-attempt-only
            // record could tell neither. A hostile class inside the ring must be dropped.
            recent: [
              { at: 1752277400000, ok: true },
              { at: 1752277400001, ok: false, status: 500, errorClass: "non-2xx" },
              { at: 1752277400002, ok: false, errorClass: "url-invalid" },
              { at: 1752277400003, ok: false, errorClass: SENTINELS.endpoint },
            ],
          });
        // ---- the roster's in-record truncation markers -----------------------------------------------------
        case "/roster-hygiene":
          return json({
            scanned: 120,
            ghostCount: 40,
            ghosts: [{ key: "dp:ghost-1", embeddedId: "ghost-1", kind: "key-id-mismatch" }],
            ghostsTruncated: true,
            ghostsDropped: 15,
            neverRanCount: 3,
            neverRan: [{ id: "fresh-1", enabled: true }],
            neverRanTruncated: false,
          });
        // ---- the stranded multipart abort (the credential can write parts but not abort them) ---------------
        case "/dest-faults":
          return json({
            payroll: {
              at: 1752277400000,
              total: 2,
              faults: [{ op: "multipart-abort", httpStatus: 403, fault: "denied", arm: "classified", count: 2 }],
              strandedAborts: { count: 4, lastClass: "denied" },
            },
          });
        // ---- the export-health record that LOOKED complete -------------------------------------------------
        case "/control-plane/recovery-status":
          return json({
            recoveryRequired: false,
            exportHealth: {
              at: "2026-07-11T00:00:00.000Z",
              wroteAny: true,
              configVersion: 7,
              perDest: [{ id: "dest-primary", ok: true }],
              // A failed 65th destination is dropped from the record, which then reads as fully covered.
              perDestTotal: 65,
              perDestTruncated: true,
            },
          });
        // ---- the restore receipt + the posture-override mutation --------------------------------------------
        case "/audit/export":
          return json({
            events: [
              {
                seq: 12,
                ts: "2026-07-11T00:00:00.000Z",
                action: "restore-apply",
                outcome: "failed",
                prevHash: "sha384:11",
                hash: "sha384:12",
                target: {
                  kind: "restore-receipt",
                  runId: "r-9",
                  recordsRestored: 400,
                  // the D1 fault LOCUS. The SQLite driver's message quotes the offending ROW VALUE (and
                  // therefore the customer's own data); it is read ONLY to select the class and never rides.
                  d1Fault: { d1ErrorClass: "constraint", failedBatchIndex: 1, batchTotal: 2, residualTableCount: 2 },
                  d1SchemaObjectsFiltered: 2,
                  // the KV key restored with NO TTL -- it will never expire. A compliance and a cost
                  // fault that no error anywhere reported.
                  metadataFieldsDropped: { "kv-expiration": 3, [SENTINELS.objectKey]: 9 },
                },
              },
              {
                seq: 13,
                ts: "2026-07-11T00:00:01.000Z",
                action: "posture-override-set",
                outcome: "ok",
                prevHash: "sha384:12",
                hash: "sha384:13",
                target: { kind: "posture-override", detail: SENTINELS.email },
              },
              // A restore whose D1 class DRIFTED: the whole d1Fault block drops (a magnitude with no cause
              // invites a wrong diagnosis more surely than an absent record does).
              {
                seq: 14,
                ts: "2026-07-11T00:00:02.000Z",
                action: "restore-apply",
                outcome: "failed",
                prevHash: "sha384:13",
                hash: "sha384:14",
                target: { kind: "restore-receipt", runId: "r-10", d1Fault: { d1ErrorClass: SENTINELS.providerMessage, failedBatchIndex: 1 } },
              },
            ],
          });
        default:
          // Every other route the bundle reads answers empty/absent. The sections under test are the point;
          // the rest must not fabricate evidence.
          if (p === "/downpipes") return json([]);
          if (p === "/audit-status") return json({});
          return json({});
      }
    },
  } as unknown as DurableObjectStub;
}

function envDouble(): Env {
  return { SCHEDULER: {} as DurableObjectNamespace, CF_ACCOUNT_ID: "acct-xyz" } as unknown as Env;
}

async function main(): Promise<void> {
  const bundle = await buildSupportBundle(envDouble(), schedulerDouble());
  const text = JSON.stringify(bundle);
  const sections = bundle.sections as Record<string, string>;

  // --dump <path> writes the REAL bundle this harness just built, for the diagnostics bot's engine-contract
  // fixture. The bot asserts unknownKeyCount === 0 against it, which is the ONLY test that proves the bot can
  // ingest what THIS engine actually emits. Generated, never hand-written: a hand-maintained fixture drifts
  // behind the engine and then passes while proving nothing, silently opening a gap between the signal names
  // and pack sections the engine emits and the ones the bot actually recognises.
  const dumpAt = process.argv.indexOf("--dump");
  if (dumpAt !== -1 && process.argv[dumpAt + 1] !== undefined) {
    const { writeFileSync } = await import("node:fs");
    writeFileSync(process.argv[dumpAt + 1] as string, `${JSON.stringify(bundle, null, 2)}\n`);
    console.log(`dumped the real bundle to ${process.argv[dumpAt + 1]}`);
  }

  console.log("THE THREE ROUTES THAT REACHED NO READER (the cardinal rule, caught in the plumb pass):");
  {
    // GET /rto has no gatherer fetching it unless one is wired up: the estimator's whole output would land in a void.
    const rto = bundle.recoveryRto as { fleet?: Record<string, unknown>; downpipes?: Array<Record<string, unknown>> };
    ok("recoveryRto rides AT ALL (the /rto route had no reader whatsoever)", rto?.downpipes !== undefined);
    const pay = rto?.downpipes?.[0];
    ok("rejectedSamples answers 'basedOnDrills says 2 but we ran 15 drills'", (pay?.rejectedSamples as { count: number; lastReason: string })?.count === 13 && (pay?.rejectedSamples as { lastReason: string })?.lastReason === "non-positive-bytes");
    ok("degradationCause splits the confidence enum's ERASED cause", pay?.degradationCause === "archive-size-unknown" && (rto?.fleet as { degradationCause?: string })?.degradationCause === "thin-sample");
    ok("a drifted confidence drops the estimate WHOLE (a DR plan is built on this number)", rto?.downpipes?.length === 1);

    // The seal ring: fetchSealFaults is a FIELD ALLOWLIST. Without the new field lines the rows would have
    // arrived stripped of the very fields that diagnose them -- present, and useless.
    const sf = bundle.sealFaults as Array<Record<string, unknown>>;
    const byKind = (k: string): Record<string, unknown> | undefined => sf.find((r) => r.kind === k);
    ok("completion-lost rides its OUTCOME (ok on an 'abandoned' run = history CONTRADICTS the bucket)", byKind("completion-lost")?.outcome === "ok");
    ok("the checkpoint unwrap code rides (master-unwrap = a rotation stranded the run, or tamper)", byKind("checkpoint-unwrap-failed")?.unwrapCode === "master-unwrap");
    ok("resume-abandoned SIZES the loss (137 slices / 41,000 records thrown away, nightly)", byKind("resume-abandoned")?.slicesDiscarded === 137 && byKind("resume-abandoned")?.recordsDiscarded === 41000);
    ok("the coercion split rides (legacyAbsent:false = PRESENT and malformed = a miscounted archive)", byKind("checkpoint-coerced")?.checkpointField === "counts" && byKind("checkpoint-coerced")?.legacyAbsent === false);
    ok("the refuse-to-sign guard SIZES the shortfall (found/expected/ordinal)", byKind("scratch-hash-mismatch")?.found === 11 && byKind("scratch-hash-mismatch")?.expected === 12 && byKind("scratch-hash-mismatch")?.ordinal === 7);
    ok("the history chain RESTART rides (a downpipe repointed at a re-created bucket)", byKind("runlog-absent")?.priorRuns === 8 && byKind("runlog-absent")?.historyChainRestarted === true);

    // The format layer: fetchIntegrityFaults is likewise a whitelist.
    const ifs = bundle.integrityFaults as Record<string, Record<string, unknown>>;
    const anomalies = ifs?.payroll?.runlogAnomalies as Array<Record<string, unknown>>;
    ok("the RUNLOG anomaly rides with BOTH disagreeing indices and the document digest", anomalies?.[0]?.kind === "index-regression" && anomalies[0].indexA === 41 && anomalies[0].indexB === 37 && anomalies[0].digest === "a1b2c3d4e5f6");
    ok("the writer's loud refusal rides (source-enumerated-zero = the CUSTOMER's emptied namespace)", (ifs?.payroll?.writerRefusals as Record<string, number>)?.["source-enumerated-zero"] === 3);
    ok("the attestation OVERCLAIM rides (sampled with NO presence pass = a missing shard reads complete)", ifs?.payroll?.attestCoverage === "sampled-no-presence");
    ok("a drifted coverage mode is DROPPED, never coerced into a completeness claim", ifs?.ledger?.attestCoverage === undefined);
  }

  console.log("the cron plane's evidence reaches the bundle:");
  {
    const ch = bundle.cronHealth as Record<string, Record<string, unknown>>;
    // notify and restoreTest are pulled into consts and their PRESENCE asserted in the same expression. The
    // sibling assertions narrow through their own optional chains (ch?.updates?.channelVerified === false
    // proves ch.updates), but these two read the ledger THROUGH a cast, which breaks that chain. An absent
    // sub-ledger is a real failure of "the evidence reaches the bundle", so it fails rather than being skipped.
    const notify = ch.notify;
    const restoreTest = ch.restoreTest;
    ok("the CRITICAL alert claimed-and-never-delivered rides, with the claim SPENT (page lost forever)", notify !== undefined && (notify.undeliveredCritical as Record<string, { count: number }>)?.["update-rollback-needed"]?.count === 1 && notify.claimSpent === 1);
    ok("the delivered alert whose history row was LOST rides", ch?.notify?.historyAppendFailures === 3 && ch.notify.digestNoTransport === 2);
    ok("the update channel that STOPPED VERIFYING rides (a rotation, or tamper -- and it was silent)", ch?.updates?.channelVerified === false && ch.updates.verifyFailures === 6);
    ok("the control-plane export's TRUNCATION + worm-denied class ride", ch?.cpExport?.truncated === true && (ch.cpExport.perDestFail as Record<string, number>)["worm-denied"] === 2 && ch.cpExport.plaintextPurgePending === 4);
    ok("the stranded push cursor rides (a lost trail write => the next tick re-sends the batch)", ch?.push?.siemTrailWriteFailures === 5);
    ok("the drill that did NOT RUN rides, per downpipe, with its closed class", restoreTest !== undefined && ((restoreTest.skips as Record<string, { cls: string; count: number }>)?.payroll)?.cls === "pre-drill-fault" && restoreTest.passBudgetDeferred === 7);
    ok("the reconcile flag ECHO rides ('never on' and 'on and bailing for weeks' were identical)", ch?.reconcile?.enabled === true && ch.reconcile.runlogVerifyFailed === 3 && ch.reconcile.circuitBreakerTripped === true);
  }

  console.log("the sched plane's evidence reaches the bundle:");
  {
    const sd = bundle.schedDiag as Record<string, Record<string, unknown>>;
    ok("the refused config save rides (reserved-binding is its OWN reason, never a typo)", (sd?.configRejections as Record<string, { count: number }>)?.["destination-set|reserved-binding"]?.count === 2);
    ok("the DR-hour refusal rides (an unrecorded break-glass reconcile would write NOTHING AT ALL)", (sd?.configRejections as Record<string, { count: number }>)?.["cp-reconcile|body-unparseable"]?.count === 1);
    ok("the SELF-ELEVATION attempt rides, while the public 403 stays a bare 'forbidden'", (sd?.authzRefusals as Record<string, { count: number }>)?.["grant-over-authority"]?.count === 3);
    ok("detection-off-no-sink rides (delete your last channel and detection silently STOPS)", (sd?.alertingHealth as Record<string, { count: number }>)?.["detection-off-no-sink"]?.count === 4);
    ok("the cron dead-man trip rides as a first-class availability signal", (sd?.alertingHealth as Record<string, { count: number }>)?.["cron-deadman-tripped"]?.count === 2);
    ok("the retained-prior-secret substitution rides ('we rotated the key and it kept using the old one')", (sd?.configCoercions as Record<string, { count: number }>)?.["otlp-destination|malformed-secret-kept-prior"]?.count === 1);
    ok("the dropped rows ride (a truncated export-health read as fully covered)", (sd?.capTruncations as Record<string, { count: number }>)?.["export-health-perdest"]?.count === 5);
    ok("the audit mirror failures + the gap page ride (events the collector will NEVER receive)", (sd?.auditEgress?.mirrorFailures as { count: number })?.count === 11 && (sd?.auditEgress?.gapPagesServed as { lastGapBeforeSeq: number })?.lastGapBeforeSeq === 4096);
    ok("the posture evaluation rides (the failing check + the override that makes it read GREEN)", (sd?.posture?.checks as Array<{ id: string; passed: boolean }>)?.[0]?.id === "immutability" && (sd?.posture?.overrides as Array<{ overrideKind: string }>)?.[0]?.overrideKind === "risk-accepted");
    ok("identity-read-failed rides (a DROPPED IDP_KV binding, not a blip -- a one-line permanent fix)", (sd?.posture?.inputFaults as Record<string, { count: number }>)?.["identity-read-failed"]?.count === 14);
  }

  console.log("the auth / IdP / destination / restore evidence reaches the bundle:");
  {
    const ich = bundle.idpCertHealth as Record<string, unknown>;
    ok("the half-corrupt rollover paste rides (parseableCount < certCount)", ich?.certCount === 3 && ich?.parseableCount === 2);
    ok("expiryObserved:false rides -- the state in which NO expiry warning can EVER fire", ich?.expiryObserved === false && ich?.noUsableCertRefusals === 4);
    ok("the unsupported curve rides ('every sign-in dies in a generic import error')", (ich?.curves as Record<string, number>)?.p521 === 1);
    ok("the DISARMED freshness check is counted (sign-ins verified with the window unenforced)", ich?.windowUnenforcedVerifies === 9);
    const byConn = bundle.ssoFailuresByConn as Record<string, Record<string, { count: number }>>;
    ok("the failing connection is named by OPAQUE ORDINAL (never the operator's connId)", byConn?.["conn-2"]?.signature?.count === 12);
    ok("the secretless connections are named by ordinal", ((bundle.authPosture as Record<string, unknown>)?.doPlaintextSecretsMissingConns as string[])?.join(",") === "conn-1,conn-4");
    ok("the stranded multipart abort rides (the credential can write parts but not abort them)", ((bundle.destFaults as Record<string, Record<string, unknown>>)?.payroll?.strandedAborts as { count: number; lastClass: string })?.lastClass === "denied");
    ok("the beacon's error CLASS and its intermittency RING ride ('ok,fail,ok,fail' != 'fail,fail,fail')", (bundle.beacon as Record<string, unknown>)?.errorClass === "non-2xx" && ((bundle.beacon as Record<string, unknown>)?.recent as unknown[])?.length === 4);
    ok("the roster's truncation marker rides (the ghost list is NOT the whole ghost list)", (bundle.rosterIntegrity as Record<string, unknown>)?.ghostsTruncated === true && (bundle.rosterIntegrity as Record<string, unknown>)?.ghostsDropped === 15);
    ok("the export-health TRUNCATION rides (a failed 65th destination read as fully covered)", ((bundle.recovery as Record<string, Record<string, unknown>>)?.exportHealth)?.perDestTruncated === true && ((bundle.recovery as Record<string, Record<string, unknown>>)?.exportHealth)?.perDestTotal === 65);
    // the D1 fault locus, the KV TTL drop and the posture-override mutation on the audit excerpt.
    const ev = bundle.configEvents as Array<Record<string, unknown>>;
    const restore = ev?.find((e) => e.action === "restore-apply" && (e.d1Fault as { failedBatchIndex?: number })?.failedBatchIndex === 1);
    ok("the D1 fault LOCUS rides (batch 1 of 2 => roughly half the rows never landed)", (restore?.d1Fault as { d1ErrorClass: string; batchTotal: number })?.d1ErrorClass === "constraint" && (restore?.d1Fault as { batchTotal: number })?.batchTotal === 2);
    ok("residualTableCount answers 'is my database half-loaded?'", (restore?.d1Fault as { residualTableCount: number })?.residualTableCount === 2 && restore?.d1SchemaObjectsFiltered === 2);
    ok("the KV key restored with NO TTL is counted (it will never expire; nothing reported it)", (restore?.metadataFieldsDropped as Record<string, number>)?.["kv-expiration"] === 3);
    ok("a DRIFTED d1 class drops the whole fault block (a magnitude with no cause misleads)", ev?.find((e) => (e.target as { runId?: string })?.runId === "r-10")?.d1Fault === undefined);
    ok("the posture-override MUTATION is allowlisted into the excerpt", ev?.some((e) => e.action === "posture-override-set") === true);
  }

  console.log("the section roster and the health vector stay honest:");
  {
    for (const name of ["idpCertHealth", "ssoFailuresByConn", "recoveryRto"]) {
      ok(`${name} is in the roster and gathered "ok"`, (SUPPORT_SECTION_NAMES as readonly string[]).includes(name) && sections[name] === "ok");
    }
    // A faulted read must read "error", never a clean "empty": an unreadable ledger reported as an honest
    // absence is a lie a diagnosis would act on ("nothing was wrong" vs "I could not look").
    const degraded = await buildSupportBundle(envDouble(), schedulerDouble({ faultRoutes: new Set(["/rto", "/idp-cert-health", "/sso-failures-by-conn"]) }));
    const ds = degraded.sections as Record<string, string>;
    ok('a faulted read propagates to section() as "error", never "empty"', ds.recoveryRto === "error" && ds.idpCertHealth === "error" && ds.ssoFailuresByConn === "error");
    ok("one faulted section does not crash the build (the rest still gather)", ds.cronHealth === "ok" && ds.schedDiag === "ok");
  }

  console.log("REDACTION (no-custody): no customer sentinel reaches the pack, as a value OR as a key:");
  {
    for (const [what, s] of Object.entries(SENTINELS)) {
      ok(`the planted ${what} appears in NO byte of the bundle`, !text.includes(s));
    }
    // The hostile map KEYS are the classic closed-vocabulary bypass: a caller-derived string becoming a bundle
    // KEY rides as a key, not a value, so a value-only gate misses it entirely. Every aggregate here is a
    // map, and several are COMPOSITE ("<surface>|<reason>") -- which is why the pack re-derives the whole cross
    // product rather than parsing the key.
    const sd = bundle.schedDiag as Record<string, Record<string, unknown>>;
    const cronHealth = bundle.cronHealth as Record<string, Record<string, unknown>>;
    // Each sub-ledger this block counts KEYS on is pulled into a const and asserted PRESENT in the same
    // expression: a key count over an absent map proves nothing, so absence must fail here rather than pass
    // for want of anything to count.
    const rejections = sd.configRejections;
    const coercions = sd.configCoercions;
    const posture = sd.posture;
    const notify = cronHealth.notify;
    ok("a hostile composite key outside the re-derived cross product is dropped, never split", rejections !== undefined && coercions !== undefined && Object.keys(rejections).length === 2 && Object.keys(coercions).length === 2);
    ok("a raw connId can never become a bundle key (the ordinal is the ONLY admissible key)", Object.keys(bundle.ssoFailuresByConn as object).length === 1);
    ok("an invented posture check id cannot become a bundle key", (posture?.checks as unknown[] | undefined)?.length === 1);
    ok("a hostile curve class cannot become a bundle key, and a NEGATIVE count cannot ride", Object.keys((bundle.idpCertHealth as { curves: object }).curves).length === 2);
    ok("a hostile notify event cannot become a bundle key", notify !== undefined && Object.keys(notify.undeliveredCritical as object).length === 1);
    // THE PROJECTION CHOKEPOINT. The posture override carries a free-text JUSTIFICATION and the acceptedBy EMAIL of
    // whoever accepted the risk. Both are read by the DO and dropped at the projection -- and this is the ONLY
    // thing standing between them and the bundle, so it is asserted rather than assumed.
    // The override row itself must EXIST for the drop assertions to mean anything: an absent row would make
    // "justification is undefined" true for the wrong reason, so presence is part of each assertion.
    const ov = (posture?.overrides as Array<Record<string, unknown>> | undefined)?.[0];
    ok("the override's free-text justification is DROPPED at the projection chokepoint", ov !== undefined && ov.justification === undefined && !text.includes("accepted by"));
    ok("the override's acceptedBy EMAIL is DROPPED at the projection chokepoint", ov !== undefined && ov.acceptedBy === undefined);
    ok("only the closed checkId + overrideKind + timestamp survive", ov !== undefined && Object.keys(ov).sort().join(",") === "at,checkId,overrideKind");
    // the estimate carries a customer downpipe NAME and free-text reason/caveat. The projection is an
    // explicit allowlist, so none of the three may ride.
    const pay = (bundle.recoveryRto as { downpipes: Array<Record<string, unknown>> }).downpipes[0]!;
    ok("the estimate's customer NAME and free-text reason/caveat are dropped by the allowlist", pay.name === undefined && pay.reason === undefined && pay.caveat === undefined);
    // The hostile ENUM VALUES must be dropped, not carried and not coerced into a neighbouring member.
    const payrollIntegrity = (bundle.integrityFaults as Record<string, Record<string, unknown>>).payroll;
    const restoreTest = cronHealth.restoreTest;
    ok("an out-of-vocabulary runlog-anomaly kind drops the whole row", payrollIntegrity !== undefined && (payrollIntegrity.runlogAnomalies as unknown[]).length === 2);
    ok("an out-of-vocabulary restore-test class drops the whole row (never a downpipe named with no reason)", restoreTest !== undefined && Object.keys(restoreTest.skips as object).length === 1);
    ok("an out-of-vocabulary seal attemptClass is dropped from the list, not carried", ((bundle.sealFaults as Array<Record<string, unknown>>).find((r) => r.kind === "completion-lost")!.attemptClasses as string[]).join(",") === "transient,destination");
    ok("an object key in a checkpointField seam is dropped", (bundle.sealFaults as Array<Record<string, unknown>>).find((r) => r.kind === "checkpoint-invalid")?.checkpointField === undefined);
    ok("an object key in a 12-hex digest seam is dropped (no message can ride a digest field)", !JSON.stringify(bundle.integrityFaults).includes(SENTINELS.objectKey));
    ok("a hostile beacon error class inside the ring is dropped", ((bundle.beacon as { recent: Array<Record<string, unknown>> }).recent[3]!).errorClass === undefined);
    // No raw exception text, stack frame, S3 error document or bearer may ride anywhere.
    ok("no raw exception text, stack frame, SQLite message or bearer rides anywhere in the bundle", !text.includes("Error:") && !text.includes("    at ") && !text.includes("constraint failed") && !text.includes("Bearer "));
  }

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
