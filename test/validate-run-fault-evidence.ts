// Prove the SOURCE + DESTINATION fault evidence reaches the SUPPORT BUNDLE -- end to end, through every real
// hop, with a customer sentinel planted at the fault site.
//
// WHY THIS TEST EXISTS. Both fault ledgers were recorded at the exact fault site and then DROPPED ON THE
// FLOOR: drainSourceFaultLedger() had NO CALLER anywhere in src/, and destFaults()/destIo() were read by
// nothing on the run path. So the evidence was written into an isolate-local accumulator and died there. A
// gap is NOT closed until its evidence is in the bundle a remote diagnosis can read, so this validator walks
// the WHOLE chain and refuses to accept any single hop as proof:
//
//   adapter records at the fault site   (the REAL source-fault-ledger writers)
//     -> the seal path drains + posts   (the REAL reportRunFaults)
//       -> the DO re-gates + stores     (the REAL applySourceFaults / applyDestFaults chokepoint)
//         -> the pack projects          (the REAL fetchSourceFaults / fetchDestFaults)
//           -> the BUNDLE carries it    (the REAL buildSupportBundle, signed)
//
// Run: node test/validate-run-fault-evidence.ts

import {
  recordIncompleteFault,
  recordResumeTokenDefect,
  recordRowidProbeFallback,
  recordSecurityRefusal,
  recordShapeAnomaly,
  recordSnapshotConsistency,
  recordSourceFatal,
  recordThrottle,
  faultItemId,
  isEmptyFaultLedger,
  readSourceFaultLedger,
} from "../src/sources/source-fault-ledger.ts";
import { beginRunFaults, reportRunFaults } from "../src/seal/run-fault-report.ts";
import { applyDestFaults, applySourceFaults, sanitiseDestFaults, sanitiseSourceFaults, type DestFaults, type SourceFaults } from "../src/admin/run-fault-records.ts";
import { fetchDestFaults, fetchSourceFaults } from "../src/admin/support-sections-diag.ts";
import { fetchDestResolution } from "../src/admin/support-sections-config.ts";
import { DestFaultLog } from "../src/dest/fault-log.ts";
import { resetPendingDroppedWrites, pendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { buildSupportBundle, SUPPORT_SECTION_NAMES } from "../src/admin/support.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- the CUSTOMER SENTINELS -----------------------------------------------------------------------------
// Every one of these is planted at a real fault site below. None of them may appear in ANY recorded byte.
// They are the values a real fault message actually interpolates: a bucket, an object key, a script name, an
// endpoint with a token in the query, an AWS secret, and a Cloudflare request id.
const SENTINEL_BUCKET = "acme-prod-customer-invoices";
const SENTINEL_KEY = "uploads/2026/payroll-Q3-CONFIDENTIAL.xlsx";
const SENTINEL_SCRIPT = "acme-internal-billing-worker";
const SENTINEL_URL = "https://acme.internal.example/hooks?token=hunter2";
const SENTINEL_SECRET = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI";
const SENTINEL_REQID = "cf-req-8f3a1d0c-acme";
const SENTINELS = [SENTINEL_BUCKET, SENTINEL_KEY, SENTINEL_SCRIPT, SENTINEL_URL, SENTINEL_SECRET, SENTINEL_REQID];

// scanForSentinels walks any structure and returns every sentinel it finds ANYWHERE -- in a key or a value,
// at any depth. The whole redaction claim rests on this coming back empty.
function scanForSentinels(v: unknown): string[] {
  const hay = JSON.stringify(v) ?? "";
  return SENTINELS.filter((s) => hay.includes(s));
}

// ---- a scheduler double that records what the seal path POSTS -------------------------------------------
function schedulerDouble(opts: { refuse?: boolean } = {}): {
  stub: DurableObjectStub;
  posts: Array<{ path: string; body: Record<string, unknown> }>;
  sourceAgg: SourceFaults;
  destAgg: DestFaults;
} {
  const posts: Array<{ path: string; body: Record<string, unknown> }> = [];
  // The DO's live aggregates, folded through the REAL appliers -- so the storage this test reads back is the
  // storage production would hold, not a hand-written fixture. They carry the appliers' OWN record types, so
  // the field assertions below read the shipped shape rather than a hand-written one.
  let sourceAgg: SourceFaults = {};
  let destAgg: DestFaults = {};
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      if (url.pathname === "/diag/run-faults") {
        posts.push({ path: url.pathname, body });
        if (opts.refuse === true) return new Response("nope", { status: 503 });
        const id = String(body.id);
        const now = 1_700_000_000_000;
        if (body.source !== undefined) sourceAgg = applySourceFaults(sourceAgg, id, body.source, now);
        const d = body.dest as { faults?: unknown; io?: unknown } | undefined;
        if (d !== undefined) destAgg = applyDestFaults(destAgg, id, d.faults, d.io, now);
        return new Response(JSON.stringify({ ok: true }));
      }
      if (url.pathname === "/diag/dropped-writes") {
        posts.push({ path: url.pathname, body });
        return new Response(JSON.stringify({ ok: true }));
      }
      if (url.pathname === "/source-faults") return new Response(JSON.stringify(sourceAgg));
      if (url.pathname === "/dest-faults") return new Response(JSON.stringify(destAgg));
      // The roster read is the one bundle fetch that runs OUTSIDE section() (its result feeds the
      // dangling-destination cross-check), so it must answer with a real array shape.
      if (url.pathname === "/downpipes") return new Response(JSON.stringify([]));
      // Everything else the bundle reads is guarded by section(), which degrades an unknown/empty answer to
      // honest absence -- exactly what we want here: this test is about the two new sections, and the rest of
      // the pack simply reads "empty".
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
  return {
    stub,
    posts,
    get sourceAgg() {
      return sourceAgg;
    },
    get destAgg() {
      return destAgg;
    },
  };
}

// ---- a destination double carrying REAL fault-log + dest-io snapshots ------------------------------------
// The fault log is the PRODUCTION class, driven with a real S3 error body, so the S3 <Code> allow-list and the
// classifier arm are exercised for real rather than asserted over a literal.
function faultingDest(): { destFaults(): ReturnType<DestFaultLog["snapshot"]>; destIo(): Record<string, number> } {
  const flog = new DestFaultLog();
  // A REAL S3 error body: the store's <Code> is the diagnostic (ExpiredToken = a lapsed STS session, NOT a
  // bucket-policy problem), and everything AROUND it -- the bucket, the key, the request id -- is exactly what
  // must never be recorded.
  const body = `<?xml version="1.0"?><Error><Code>ExpiredToken</Code><Message>The provided token has expired for ${SENTINEL_BUCKET}/${SENTINEL_KEY}</Message><RequestId>${SENTINEL_REQID}</RequestId></Error>`;
  const resp = new Response(body, { status: 403, headers: { "x-amz-request-id": SENTINEL_REQID } });
  flog.noteResponse("put", resp, body);
  flog.noteResponse("multipart-part", resp, body);
  // A THROWN transport fault the classifier could not read at all: the "default-permanent" arm, which is the
  // one support must see (a retryable fault may have been given up on because the message was unreadable).
  flog.noteThrown("head", new Error(`connect ECONNRESET ${SENTINEL_URL}`));
  return {
    destFaults: () => flog.snapshot(),
    // The degradation counters of a destination quietly making a GREEN run slow and expensive.
    destIo: () => ({
      throttleObservations: 41,
      retryAttemptsTotal: 118,
      timeouts: 2,
      conditionalPutConflicts: 1,
      headNon200CollapsedToAbsent: 7, // the dedup-defeating fault: the segment re-uploads every night
      retryAfterUnparseable: 3,
      minEffectiveRatePerSec: 2,
    }),
  };
}

// plantSourceFaults drives the REAL ledger writers, with a customer sentinel at every site a classifier or an
// attribution id could possibly carry one.
async function plantSourceFaults(): Promise<void> {
  // an incompleteness sentinel WITH its reason and its shortfall magnitude. The scope is an engine
  // product token; the customer's SCRIPT NAME is reduced to a one-way handle by faultItemId before it can
  // ever reach the ledger.
  recordIncompleteFault("_unavailable", "auth", { id: await faultItemId("workers/settings", SENTINEL_SCRIPT) });
  recordIncompleteFault("_truncated", "page-cap", { id: await faultItemId("cf-config/rulesets"), pagesRead: 25, recordsAccumulated: 12_500 });
  recordIncompleteFault("_pending", "render-pending", { id: await faultItemId("stream/downloads", SENTINEL_KEY), pendingAgeMs: 21 * 24 * 3600 * 1000 });
  // the tolerant-parse drop -- the ONLY trace that a Cloudflare API shape change is voiding coverage
  // while every run still reports ok.
  recordShapeAnomaly("workers/versions");
  // the run-fatal transport verdict + the crawl STAGE.
  recordSourceFatal({ sourceType: "images", statusClass: "403", stage: "list", attempted: 9, succeeded: 0 });
  // the D1 point-in-time verdict -- a DATA-INTEGRITY signal that rides on a run reporting OK.
  recordSnapshotConsistency("re-anchored");
  recordRowidProbeFallback();
  // a corrupt resume token, and the COUNT that separates a one-off from a WEDGE.
  recordResumeTokenDefect("d1", "bad-bookmark");
  recordResumeTokenDefect("d1", "bad-bookmark");
  // the absorbed 429s (the early warning), and the platform's own Retry-After ask.
  recordThrottle(30);
  recordThrottle(7);
  // a redirect that tried to steer a validated byte read at an unvalidated host. The HOST is precisely
  // what must never be recorded, so the KIND is the whole record.
  recordSecurityRefusal("redirect-refused");
}

async function main(): Promise<void> {
  console.log("run-fault evidence (source + destination) reaches the bundle:");

  // ---- 1. the DRAIN + POST: the hop that did not exist -------------------------------------------------
  resetPendingDroppedWrites();
  const d1 = schedulerDouble();
  beginRunFaults();
  await plantSourceFaults();
  await reportRunFaults(d1.stub, "dp1", faultingDest() as never);

  const posted = d1.posts.filter((p) => p.path === "/diag/run-faults");
  ok("the seal path DRAINS the ledger and POSTS it (the hop drainSourceFaultLedger never had a caller for)", posted.length === 1);
  ok("the drain EMPTIES the isolate ledger, so a warm isolate cannot attribute this run's faults to the next", isEmptyFaultLedger(readSourceFaultLedger()));

  const body = posted[0]?.body ?? {};
  ok("the post carries the source evidence", body.source !== undefined);
  ok("the post carries the destination evidence", body.dest !== undefined);
  ok("REDACTION: the POSTED body carries no customer sentinel", scanForSentinels(body).length === 0);

  // ---- 2. the DO applier (the redaction chokepoint) ------------------------------------------------------
  const srcAgg = d1.sourceAgg;
  const dstAgg = d1.destAgg;
  ok("the DO stores the source evidence under the customer's own downpipe id", srcAgg.dp1 !== undefined);
  ok("the DO stores the destination evidence under the customer's own downpipe id", dstAgg.dp1 !== undefined);
  ok("REDACTION: the STORED source aggregate carries no customer sentinel", scanForSentinels(srcAgg).length === 0);
  ok("REDACTION: the STORED destination aggregate carries no customer sentinel", scanForSentinels(dstAgg).length === 0);

  // The two stored entries, read at the appliers' own record types. Each read stays optional-chained: the
  // entry's presence is asserted just above, and a missing entry must FAIL the field assertion below rather
  // than throw past the remaining checks.
  const e = srcAgg.dp1;
  ok("the closed REASON behind the _unavailable sentinel survives (auth, not just 'unavailable')", e?.incompleteReasons?.["_unavailable"]?.auth === 1);
  ok("the truncation MAGNITUDE survives (12,500 records over 25 pages)", e?.truncation?.recordsAccumulated === 12_500);
  ok("the stuck render's AGE survives (a video pending for three weeks, not minutes)", (e?.oldestPendingAgeMs ?? 0) > 1_000_000_000);
  ok("the tolerant-parse drop count survives (coverage voided behind a green run)", e?.shapeAnomalies === 1);
  ok("the run-fatal transport class AND crawl stage survive (a 403 that cannot even LIST)", e?.fatal?.statusClass === "403" && e?.fatal?.stage === "list");
  ok("the MIXED-SNAPSHOT verdict survives on a run that reported ok", e?.snapshotConsistency === "re-anchored");
  ok("the resume-token defect COUNT survives (2 = a wedge, not a one-off)", e?.resumeTokenDefects?.["bad-bookmark"] === 2);
  ok("the absorbed 429s survive (the early warning a healthy-looking pipe hides)", e?.throttle429Count === 2);
  ok("the platform's own worst Retry-After ask survives", e?.maxRetryAfterSeconds === 30);
  ok("the security refusal KIND survives (and only the kind)", e?.securityRefusals?.["redirect-refused"] === 1);

  const de = dstAgg.dp1;
  const dfaults = de?.faults ?? [];
  ok("the destination fault's closed S3 <Code> survives (ExpiredToken = a lapsed STS session)", dfaults.some((f) => f.s3Code === "ExpiredToken"));
  ok("the classifier ARM survives, so a fault DEFAULTED to permanent is visible", dfaults.some((f) => f.arm === "default-permanent"));
  ok("the store's request id survives only as a PRESENCE boolean", dfaults.every((f) => typeof f.requestIdPresent === "boolean") && !JSON.stringify(dfaults).includes(SENTINEL_REQID));
  ok("headNon200CollapsedToAbsent survives (the dedup-defeating nightly re-upload)", de?.io?.headNon200CollapsedToAbsent === 7);
  ok("the store's throttle pushback survives on a run that SUCCEEDED", de?.io?.throttleObservations === 41);

  // ---- 3. the PACK PROJECTION -----------------------------------------------------------------------------
  const projSrc = await fetchSourceFaults(d1.stub);
  const projDst = await fetchDestFaults(d1.stub);
  ok("the pack projector reads the source evidence back", Object.keys(projSrc).length === 1);
  ok("the pack projector reads the destination evidence back", Object.keys(projDst).length === 1);
  ok("REDACTION: the PROJECTED source section carries no customer sentinel", scanForSentinels(projSrc).length === 0);
  ok("REDACTION: the PROJECTED destination section carries no customer sentinel", scanForSentinels(projDst).length === 0);

  // ---- 4. the BUNDLE (the only hop that actually matters) -------------------------------------------------
  const env = { CF_ACCOUNT_ID: "acct-123" } as unknown as Env;
  const bundle = await buildSupportBundle(env, d1.stub);
  ok("THE BUNDLE CARRIES sourceFaults (the evidence was dead code before this)", bundle.sourceFaults !== undefined);
  ok("THE BUNDLE CARRIES destFaults", bundle.destFaults !== undefined);
  ok("the two sections are on the closed roster, so a future fetch cannot slip past the health vector", SUPPORT_SECTION_NAMES.includes("sourceFaults" as never) && SUPPORT_SECTION_NAMES.includes("destFaults" as never));
  const secs = bundle.sections as Record<string, string>;
  ok("the sections health vector reports them as gathered (ok), not error", secs.sourceFaults === "ok" && secs.destFaults === "ok");
  ok("REDACTION: the WHOLE BUNDLE carries no customer sentinel", scanForSentinels(bundle).length === 0);

  // ---- 5. a CLEAN run must record NOTHING (the omit-when-empty discipline) ---------------------------------
  const clean = schedulerDouble();
  beginRunFaults();
  await reportRunFaults(clean.stub, "dp-clean", undefined);
  ok("a CLEAN run posts nothing at all (no subrequest, no record, no section)", clean.posts.length === 0);
  const cleanBundle = await buildSupportBundle(env, clean.stub);
  ok("a clean fleet's bundle OMITS sourceFaults entirely", cleanBundle.sourceFaults === undefined);
  ok("a clean fleet's bundle OMITS destFaults entirely", cleanBundle.destFaults === undefined);

  // A destination that behaved records nothing either, even though its snapshot exists and is all-zero.
  const quiet = schedulerDouble();
  beginRunFaults();
  await reportRunFaults(quiet.stub, "dp-quiet", { destFaults: () => ({ total: 0, overflow: 0, faults: [] }), destIo: () => ({ throttleObservations: 0, retryAttemptsTotal: 0, timeouts: 0, conditionalPutConflicts: 0, headNon200CollapsedToAbsent: 0, retryAfterUnparseable: 0 }) } as never);
  ok("a destination that behaved posts nothing (an all-zero snapshot is not evidence)", quiet.posts.length === 0);

  // ---- 6. a DROPPED report is itself RECORDED (the pack's under-count caveat) ------------------------------
  resetPendingDroppedWrites();
  const down = schedulerDouble({ refuse: true });
  beginRunFaults();
  await plantSourceFaults();
  await reportRunFaults(down.stub, "dp1", undefined);
  // The report was REFUSED (a 503), so recordDiagWrite notes the loss and FLUSHES it to the droppedWrites
  // aggregate -- which is the whole protocol: the loss lands the moment the DO can take it, and the pack then
  // carries an explicit "this bundle is incomplete, by this many records, of this kind" caveat. (Here the
  // flush itself lands, so the tally is correctly cleared rather than left pending.)
  const flushed = down.posts.filter((p) => p.path === "/diag/dropped-writes");
  ok("a DROPPED run-fault report is itself RECORDED, so the pack declares its own under-count", flushed.length === 1 && ((flushed[0]?.body.drops as Record<string, number>)?.["run-faults"] ?? 0) >= 1);
  ok("nothing is left pending once the loss has been durably recorded", (pendingDroppedWrites()["run-faults"] ?? 0) === 0);
  ok("REDACTION: the dropped-write report carries only a {kind: count} tally, never the lost payload", scanForSentinels(flushed).length === 0);
  ok("the drain still EMPTIED the ledger even though the report was refused (no cross-run leak on a DO outage)", isEmptyFaultLedger(readSourceFaultLedger()));
  resetPendingDroppedWrites();

  // ---- 7. the CHOKEPOINT refuses a drifted / HOSTILE record ------------------------------------------------
  // A compromised or version-skewed writer tries to smuggle free text through every field that could carry it.
  const hostile = sanitiseSourceFaults(
    {
      incompleteReasons: { _unavailable: { "not-a-reason": 5, auth: 2 }, "not-a-marker": { auth: 9 } },
      incompleteIds: { _unavailable: [`the bucket ${SENTINEL_BUCKET} returned 403 for ${SENTINEL_KEY}`, "workers/settings"] },
      fatal: { sourceType: SENTINEL_SCRIPT, statusClass: "403", stage: "list" },
      resumeTokenSourceTypes: [SENTINEL_SCRIPT, "d1"],
      securityRefusals: { "not-a-kind": 3 },
      snapshotConsistency: SENTINEL_URL,
      maxRetryAfterSeconds: 999_999_999,
      rawMessage: `S3 said: ${SENTINEL_SECRET}`,
    },
    1_700_000_000_000,
  );
  ok("HOSTILE: an out-of-vocabulary reason is DROPPED, the valid one beside it survives", hostile?.incompleteReasons?.["_unavailable"]?.auth === 2 && hostile?.incompleteReasons?.["_unavailable"]?.["not-a-reason"] === undefined);
  ok("HOSTILE: an out-of-vocabulary MARKER KIND is dropped whole", hostile?.incompleteReasons?.["not-a-marker"] === undefined);
  ok("HOSTILE: a raw error MESSAGE smuggled into an attribution id fails the shape gate and is dropped", JSON.stringify(hostile?.incompleteIds ?? {}) === JSON.stringify({ _unavailable: ["workers/settings"] }));
  ok("HOSTILE: a customer name smuggled into fatal.sourceType drops the WHOLE fatal row (a half-named fault is worse than none)", hostile?.fatal === undefined);
  ok("HOSTILE: a customer name in resumeTokenSourceTypes is dropped, the real product token survives", JSON.stringify(hostile?.resumeTokenSourceTypes ?? []) === JSON.stringify(["d1"]));
  ok("HOSTILE: an out-of-vocabulary security-refusal kind is dropped", hostile?.securityRefusals === undefined);
  ok("HOSTILE: a URL smuggled into the snapshot verdict is dropped", hostile?.snapshotConsistency === undefined);
  ok("HOSTILE: an unbounded Retry-After is CLAMPED to a day, never carried raw", hostile?.maxRetryAfterSeconds === 86_400);
  ok("HOSTILE: a field the applier never reads (rawMessage) simply does not exist in the record", !("rawMessage" in (hostile ?? {})));
  ok("HOSTILE: no sentinel survives the chokepoint at all", scanForSentinels(hostile).length === 0);

  const hostileDest = sanitiseDestFaults(
    { total: 3, faults: [{ op: "put", httpStatus: 403, s3Code: `AccessDenied for ${SENTINEL_BUCKET}`, fault: "permanent", arm: "matched-status", count: 1 }, { op: "not-an-op", httpStatus: 500, s3Code: "InternalError", fault: "transient", arm: "matched-status" }] },
    { throttleObservations: "lots" as unknown as number, headNon200CollapsedToAbsent: 4 },
    1_700_000_000_000,
  );
  ok("HOSTILE: an S3 <Code> outside the documented allow-list is dropped, taking its row with it", (hostileDest?.faults ?? []).length === 0);
  ok("HOSTILE: an out-of-vocabulary dest op is dropped", !JSON.stringify(hostileDest ?? {}).includes("not-an-op"));
  ok("HOSTILE: a non-numeric counter is dropped, the real one beside it survives", hostileDest?.io?.throttleObservations === undefined && hostileDest?.io?.headNon200CollapsedToAbsent === 4);
  ok("HOSTILE: no sentinel survives the destination chokepoint", scanForSentinels(hostileDest).length === 0);

  // ---- 8. the storageClass SHAPE GATE (a live redaction hole, pre-existing and already shipping) -----------
  // destResolution.destinations[].storageClass was projected on a bare `typeof === "string"` check: an
  // OPERATOR-CONTROLLED field riding into the confidential pack ungated. It is now gated to the engine's own
  // S3 storage-class allow-list, so a value stored before the validator existed (or by a drifted writer)
  // cannot ride verbatim.
  const destStub = {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/destinations") {
        return new Response(
          JSON.stringify({
            destinations: [
              { id: "d-good", endpointHost: "s3.example.com", bucket: "b1", addressing: "path", storageClass: "STANDARD_IA" },
              // The hole: an ungated operator string. Before the fix this rode into the pack verbatim.
              { id: "d-hostile", endpointHost: "s3.example.com", bucket: "b2", addressing: "path", storageClass: `GLACIER ${SENTINEL_BUCKET} ${SENTINEL_SECRET}` },
            ],
          }),
        );
      }
      return new Response(JSON.stringify({}));
    },
  } as unknown as DurableObjectStub;
  const dr = await fetchDestResolution({} as unknown as Env, destStub);
  const rows = dr.destinations as Array<Record<string, unknown>>;
  ok("storageClass: a REAL member of the S3 allow-list still rides", rows.find((r) => r.id === "d-good")?.storageClass === "STANDARD_IA");
  ok("storageClass: an operator-controlled value outside the allow-list is GATED, never carried verbatim", rows.find((r) => r.id === "d-hostile")?.storageClass === "unknown-code");
  ok("storageClass REDACTION: the customer value planted in it reaches no byte of the section", scanForSentinels(dr).length === 0);

  console.log(failures === 0 ? "\nrun-fault evidence: OK" : `\nrun-fault evidence: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
