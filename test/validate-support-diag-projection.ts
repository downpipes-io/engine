// Prove that fault evidence PROJECTS into the support pack, and that the projection is
// REDACTION-SAFE: a hostile customer value, a raw destination error, a live AWS key, a bucket name, an
// operator email, a source IP and a secret are planted at EVERY seam a recorder feeds (the scheduler fault
// ledger, the seal-error stamps, the metrics-scrape health, the WebAuthn fault aggregate, the dropped-write
// aggregate, the rate-limit DO health, the seal-fault ring, the OTLP trail, the notify ring and the audit
// excerpt) and NONE of them may appear anywhere in the built bundle.
//
// It covers the plumbing for: the scheduler fault ledger (schedDiag), the per-downpipe seal-dispatch fault
// (sealErrors), the /metrics scrape surface's own health (metricsHealth), the structural WebAuthn fault
// classes (webauthnFaults), the dropped-write aggregate (droppedWrites, whose vocabulary is the UNION of the
// Worker-edge and scheduler-DO kinds sharing one record), the seal-fault ring's fan-out fields, the seal
// knobs' running-value sources (sealKnobs.knobSources), the OTLP trail's droppedCount, plus the pack
// projections for the unknown-code placeholder and the invalid env marker, smart-retained boundary rows,
// the failure-biased notify history, the update-availability verdicts, accessPerimeter, the mutation
// attribution flag, and the advertised capability vector.
// Run: node test/validate-support-diag-projection.ts

import { buildSupportBundle, type SupportBundleContext } from "../src/admin/support.ts";
import { PACK_DROPPED_WRITE_KINDS } from "../src/admin/support-sections-diag.ts";
import { DROPPED_WRITE_KINDS as ADMIN_DROPPED_WRITE_KINDS } from "../src/admin/diag-records.ts";
import { DROPPED_WRITE_KINDS as SCHED_DROPPED_WRITE_KINDS } from "../src/sched/sched-fault-ledger.ts";
import { classifyChannelIssue, classifyCompatBlock } from "../src/admin/support-sections-runs.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The POISON set: every one of these is a value the pack must NEVER carry. Each is planted at a real seam
// below (a free-text error, a credential, a bucket, an endpoint, an operator identity, a source IP).
const POISON = [
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "acme-prod-backups-bucket",
  "s3.us-east-2.amazonaws.com",
  "ops@acme.example",
  "203.0.113.77",
  "SignatureDoesNotMatch: the request signature we calculated does not match",
  "hunter2-super-secret",
  "cred_01HXYZ",
];

// A scheduler double serving ONLY the routes this test cares about; everything else answers {} so the rest of
// the bundle degrades to honest absence (each unknown route is a valid empty read, not a fault).
function schedulerDouble(over: Record<string, unknown> = {}): DurableObjectStub {
  const routes: Record<string, unknown> = {
    // The roster: dp1 is the downpipe every per-downpipe join below attributes evidence to.
    "/downpipes": [
      { config: { id: "dp1", name: "kv nightly", enabled: true, cadenceSeconds: 3600, source: { type: "kv" } }, lastRunId: "run1", inFlight: false },
      { config: { id: "dp2", name: "r2 nightly", enabled: true, cadenceSeconds: 3600, source: { type: "r2" } }, lastRunId: "run2", inFlight: false },
    ],
    // ---- the scheduler DO fault ledger (GET /sched-diag) ----
    "/sched-diag": {
      ceremonyFaults: {
        "passkey-challenge-evicted": { count: 12, lastAt: "2026-07-11T01:02:03.000Z" },
        "recovery-limiter-unavailable": { count: 3, lastAt: "2026-07-11T01:02:04.000Z" },
        // out-of-vocabulary: must be DROPPED, and its payload must not ride
        "ops@acme.example": { count: 9, lastAt: "2026-07-11T01:02:05.000Z" },
      },
      recentErrors: [
        { errorId: "3f2a1b0c", stage: "login/finish", reasonClass: "stored-key-corrupt", count: 4, at: "2026-07-11T01:00:00.000Z" },
        // a drifted writer putting a CUSTOMER VALUE in the id: the shape guard must drop the whole row
        { errorId: "ops@acme.example", stage: "login/finish", reasonClass: "internal", count: 1, at: "2026-07-11T01:00:01.000Z" },
        // an out-of-vocabulary stage: dropped
        { errorId: "aa11bb22", stage: "203.0.113.77", reasonClass: "internal", count: 1, at: "2026-07-11T01:00:02.000Z" },
      ],
      contractFaults: {
        "drift-reconcile|coerced-default": { count: 7, lastAt: "2026-07-11T01:03:00.000Z" },
        "s3.us-east-2.amazonaws.com|bad-body": { count: 5, lastAt: "2026-07-11T01:03:01.000Z" }, // dropped
      },
      droppedWrites: { "ceremony-fault": { count: 2, lastAt: "2026-07-11T01:04:00.000Z" } },
      defaultDestination: {
        ok: false,
        reason: "auth",
        at: "2026-07-11T01:05:00.000Z",
        downSince: "2026-07-04T01:05:00.000Z",
        // a drifted writer smuggling the raw rejection alongside the closed class: never projected
        rawError: "SignatureDoesNotMatch: the request signature we calculated does not match",
      },
      freshnessFaults: { dp1: { cause: "cadence-malformed", at: "2026-07-11T01:06:00.000Z" } },
    },
    // ---- the per-downpipe PRE-RUN seal-dispatch fault ----
    "/seal-errors": {
      byDownpipe: {
        dp1: { cls: "trigger-transport", at: 1_752_230_000_000, consecutive: 3 },
        dp2: { cls: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", at: 1_752_230_000_000, consecutive: 1 }, // dropped
      },
    },
    // ---- the /metrics scrape surface's own health ----
    "/metrics-health": {
      health: {
        lastScrapeAt: 1_752_230_000_000,
        lastOutcome: "auth-check-unavailable",
        outcomes: { ok: 412, "auth-check-unavailable": 3, "hunter2-super-secret": 99 },
        shapeFallbacks: 1,
        recordPullFailures: 0,
      },
    },
    // ---- the structural WebAuthn fault classes, split by ceremony phase ----
    "/webauthn-faults": {
      "login:key-import-failed": { count: 7, lastAt: "2026-07-11T02:00:00.000Z" },
      "enrol:cose-unsupported-alg": { count: 31, lastAt: "2026-07-11T02:00:01.000Z", algs: [-8] },
      "enrol:cred_01HXYZ": { count: 5, lastAt: "2026-07-11T02:00:02.000Z" }, // dropped
    },
    // ---- the recorders' own dropped writes (ONE record, TWO vocabularies) ----
    "/dropped-writes": {
      "auth-signal": { count: 2, lastAt: "2026-07-11T03:00:00.000Z" }, // a Worker-edge kind
      "freshness-fault": { count: 5, lastAt: "2026-07-11T03:00:01.000Z" }, // a scheduler-DO kind
      "AKIAIOSFODNN7EXAMPLE": { count: 9, lastAt: "2026-07-11T03:00:02.000Z" }, // dropped
    },
    // ---- the seal-fault ring's fan-out fields ----
    "/seal-faults": {
      faults: [
        { kind: "fanout-range-stalled", at: 1_752_230_000_001, downpipeId: "dp1", runId: "run1", rangeIndex: 3 },
        { kind: "fanout-report-discarded", at: 1_752_230_000_002, downpipeId: "dp1", discardClass: "stale-phase" },
        { kind: "fanout-report-discarded", at: 1_752_230_000_003, downpipeId: "dp1", discardClass: "acme-prod-backups-bucket" },
        { kind: "observe-dropped", at: 1_752_230_000_004, dropClass: "transport", dropped: 11 },
        { kind: "shard-list-truncated", at: 1_752_230_000_005, downpipeId: "dp1", found: 3, expected: 9, countsMalformed: true },
      ],
    },
    // ---- the OTLP trail's droppedCount ----
    "/otlp-push": {
      present: true,
      enabled: true,
      trail: [{ at: "2026-07-11T04:00:00.000Z", ok: true, httpStatus: 200, downpipeCount: 5000, truncated: true, droppedCount: 1234 }],
    },
    // ---- the notify delivery ring (NEWEST-FIRST). 22 recent successes bury the failures. ----
    "/notify/history": [
      ...Array.from({ length: 22 }, (_, i) => ({ seq: 100 - i, ts: `2026-07-1${1}T05:${String(i).padStart(2, "0")}:00.000Z`, event: "backup-ok", severity: "info", channelKind: "email", delivered: true })),
      { seq: 60, ts: "2026-07-05T05:00:00.000Z", event: "backup-failed", severity: "critical", channelKind: "pagerduty", delivered: false, deliveryCode: "http-5xx" },
      { seq: 59, ts: "2026-07-04T05:00:00.000Z", event: "backup-failed", severity: "critical", channelKind: "pagerduty", delivered: false, deliveryCode: "http-gone" },
      { seq: 20, ts: "2026-06-20T05:00:00.000Z", event: "backup-failed", severity: "critical", channelKind: "pagerduty", delivered: true },
    ],
    // ---- the audit excerpt's attribution boolean ----
    "/audit/export": {
      headSeq: 3,
      events: [
        { seq: 1, ts: "2026-07-01T00:00:00.000Z", action: "config-change-propose", actorEmail: "ops@acme.example", target: { changeKind: "notify-rule-set" }, hash: "sha384:aa", prevHash: "sha384:00" },
        { seq: 2, ts: "2026-07-02T00:00:00.000Z", action: "config-change-approve", actorEmail: null, target: { changeKind: "notify-rule-set" }, hash: "sha384:bb", prevHash: "sha384:aa" },
      ],
    },
    // ---- an out-of-vocabulary amnesia probe + refusal code (placeholder, not silent omission) ----
    "/control-plane/recovery-status": {
      recoveryRequired: true,
      configEmpty: true,
      refused: { reason: "the field acme.secret at $.dest[0].secret would leak" },
      refusedCode: "hunter2-super-secret",
      amnesiaProbe: { probe: "203.0.113.77", at: "2026-07-11T06:00:00.000Z" },
    },
    "/licence-activation-refusal": { count: 4, lastAt: 1_752_230_000_000, lastReasonCode: "cred_01HXYZ" },
    ...over,
  };
  return {
    fetch: async (input: RequestInfo | URL) => {
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url).pathname;
      const body = Object.prototype.hasOwnProperty.call(routes, path) ? routes[path] : {};
      return new Response(JSON.stringify(body ?? {}), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

// The rate-limit DO double: a limiter that has been FAILING OPEN (nothing is being throttled).
function rateLimitNamespace(): DurableObjectNamespace {
  return {
    idFromName: (n: string) => n,
    get: () => ({
      fetch: async () =>
        new Response(JSON.stringify({ failOpenCount: 42, lastFailOpenAt: 1_752_230_000_000, knobInvalid: true, endpoint: "s3.us-east-2.amazonaws.com" })),
    }),
  } as unknown as DurableObjectNamespace;
}

function envDouble(): Env {
  return {
    SCHEDULER: {} as DurableObjectNamespace,
    RATELIMIT_DO: rateLimitNamespace(),
    // the CPU_MS mirror is SET but a typo -- an INVALID marker, not silent absence.
    CPU_MS: "not-a-number",
    // no update channel configured -> checkUpdates short-circuits (NO network call) and the availability
    // block reports the closed not-configured issue.
  } as unknown as Env;
}

async function main(): Promise<void> {
  console.log("the support pack: fault-evidence projection\n");

  const ctx: SupportBundleContext = { accessPerimeter: true };
  const bundle = await buildSupportBundle(envDouble(), schedulerDouble(), ctx);
  const text = JSON.stringify(bundle);

  // ---- 1. REDACTION: not one planted value may appear ANYWHERE in the pack -------------------------------
  console.log("redaction (the planted customer values, credentials, endpoints and identities):");
  for (const p of POISON) {
    ok(`the pack never carries "${p.slice(0, 32)}"`, !text.includes(p));
  }

  // ---- 2. schedDiag: the scheduler fault ledger's evidence ------------------------------------------------
  console.log("\nschedDiag (the scheduler DO's fault ledger):");
  const sd = bundle["schedDiag"] as Record<string, unknown>;
  ok("the schedDiag section rides", sd !== undefined);
  const ceremony = sd["ceremonyFaults"] as Record<string, { count: number }>;
  ok("A DO-side ceremony fault class the Worker edge cannot see rides (passkey-challenge-evicted)", ceremony["passkey-challenge-evicted"]?.count === 12);
  ok("WHICH recovery limiter denied rides (recovery-limiter-unavailable: a fail-CLOSED store, not a throttle)", ceremony["recovery-limiter-unavailable"]?.count === 3);
  ok("an out-of-vocabulary ceremony key is DROPPED (not projected under a customer-value key)", !("ops@acme.example" in ceremony));
  const errs = sd["recentErrors"] as Array<Record<string, unknown>>;
  ok("The OPAQUE errorId a customer quotes rides with its stage + coarse reason class + recurrence count", errs.length === 1 && errs[0]!["errorId"] === "3f2a1b0c" && errs[0]!["stage"] === "login/finish" && errs[0]!["reasonClass"] === "stored-key-corrupt" && errs[0]!["count"] === 4);
  ok("an errorId that is NOT engine-minted-shaped is dropped WHOLE (a drifted writer cannot push a customer value through)", errs.every((e) => e["errorId"] !== "ops@acme.example"));
  const cf = sd["contractFaults"] as Record<string, { count: number }>;
  ok("A silent Worker<->DO coercion is counted (drift-reconcile|coerced-default -- the `?? []` that CLEARS a real marker)", cf["drift-reconcile|coerced-default"]?.count === 7);
  ok("a contract-fault key outside the closed route x kind cross product is DROPPED", Object.keys(cf).length === 1);
  const dd = sd["defaultDestination"] as Record<string, unknown>;
  ok("The ENV-DEFAULT destination's heartbeat rides with a CLOSED reason class + a preserved downSince", dd["ok"] === false && dd["reason"] === "auth" && dd["downSince"] === "2026-07-04T01:05:00.000Z");
  ok("the raw destination rejection planted beside the class is NOT projected", !("rawError" in dd));
  const ff = sd["freshnessFaults"] as Record<string, { cause: string }>;
  ok("The downpipe whose staleness rule can NEVER arm is named, with its closed cause", ff["dp1"]?.cause === "cadence-malformed");
  ok("schedDiag does NOT re-project droppedWrites (one shared record, one home in the pack)", !("droppedWrites" in sd));
  // The per-downpipe JOINS: the evidence must reach the row a diagnoser actually reads.
  const rows = bundle["downpipes"] as Array<Record<string, unknown>>;
  const dp1 = rows.find((r) => r["id"] === "dp1")!;
  const dp2 = rows.find((r) => r["id"] === "dp2")!;
  ok("downpipes[].freshnessComputable=false marks the pipe the map would read 'Fresh' forever", dp1["freshnessComputable"] === false);
  ok("a downpipe whose freshness IS computable carries no marker (a healthy row is byte-identical to before)", !("freshnessComputable" in dp2));
  ok("downpipes[].lastSealError attributes the pre-run dispatch fault to the row (a fault that produces NO run row at all)", (dp1["lastSealError"] as Record<string, unknown>)["class"] === "trigger-transport");

  // ---- 3. the remaining recorder sections ----------------------------------------------------------------
  console.log("\nsealErrors / metricsHealth / webauthnFaults / droppedWrites / rateLimitDoHealth:");
  const se = bundle["sealErrors"] as Record<string, Record<string, unknown>>;
  ok("The PRE-RUN seal-dispatch fault is attributed to its downpipe (closed class + streak)", se["dp1"]?.["class"] === "trigger-transport" && se["dp1"]?.["consecutive"] === 3);
  ok("an out-of-vocabulary seal-error class is DROPPED (the row does not ride)", !("dp2" in se));
  const mh = bundle["metricsHealth"] as Record<string, unknown>;
  ok("The fail-CLOSED auth-check-unavailable refusal rides (the '401 with an unexpired credential' ticket)", mh["lastOutcome"] === "auth-check-unavailable" && (mh["outcomes"] as Record<string, number>)["auth-check-unavailable"] === 3);
  ok("The shape-coercion fallback (a valid scrape rendering ZERO series) is counted", mh["shapeFallbacks"] === 1);
  ok("an out-of-vocabulary scrape outcome is DROPPED from the histogram", !("hunter2-super-secret" in (mh["outcomes"] as Record<string, number>)));
  const wf = bundle["webauthnFaults"] as Record<string, Record<string, unknown>>;
  ok("The PHASE is the diagnosis -- login:key-import-failed (the STORED COSE key is corrupt) rides", wf["login:key-import-failed"]?.["count"] === 7);
  ok("cose-unsupported-alg carries the offered IANA COSE alg ints", JSON.stringify(wf["enrol:cose-unsupported-alg"]?.["algs"]) === "[-8]");
  ok("a fault key outside the closed phase:class cross product is DROPPED", Object.keys(wf).length === 2);
  const dw = bundle["droppedWrites"] as Record<string, { count: number }>;
  ok("A Worker-EDGE dropped-write kind rides (auth-signal)", dw["auth-signal"]?.count === 2);
  ok("A scheduler-DO dropped-write kind rides from the SAME record (freshness-fault) -- the projection carries the UNION", dw["freshness-fault"]?.count === 5);
  ok("an out-of-vocabulary dropped-write kind is DROPPED", Object.keys(dw).length === 2);
  ok(
    "PACK_DROPPED_WRITE_KINDS is exactly the union of the two writers' vocabularies (neither half can be silently dropped at the pack boundary)",
    PACK_DROPPED_WRITE_KINDS.length === ADMIN_DROPPED_WRITE_KINDS.length + SCHED_DROPPED_WRITE_KINDS.length &&
      [...ADMIN_DROPPED_WRITE_KINDS, ...SCHED_DROPPED_WRITE_KINDS].every((k) => PACK_DROPPED_WRITE_KINDS.includes(k)),
  );
  const infra = bundle["infra"] as Record<string, unknown>;
  const rl = infra["rateLimitDoHealth"] as Record<string, unknown>;
  ok("The limiter's FAIL-OPEN count rides (presence alone could not tell a healthy limiter from one that stopped throttling)", rl["failOpenCount"] === 42 && rl["knobInvalid"] === true);
  ok("the limiter's own endpoint field is NOT projected", !("endpoint" in rl));

  // ---- 4. the seal-fault ring's fan-out fields + knobSources ----------------------------------------------
  console.log("\nsealFaults (fan-out parity + the ring's own ingestion losses) and sealKnobs.knobSources:");
  const sf = bundle["sealFaults"] as Array<Record<string, unknown>>;
  const stalled = sf.find((f) => f["kind"] === "fanout-range-stalled");
  ok("A stalled fan-out worker names WHICH range wedged (a wedged worker throws nothing, so the int IS the attribution)", stalled?.["rangeIndex"] === 3);
  const discarded = sf.filter((f) => f["kind"] === "fanout-report-discarded");
  ok("A discarded worker report carries its CLOSED discard class", discarded.some((f) => f["discardClass"] === "stale-phase"));
  ok("an out-of-vocabulary discard class is DROPPED (the row rides, the value does not)", discarded.every((f) => f["discardClass"] !== "acme-prod-backups-bucket"));
  const dropped = sf.find((f) => f["kind"] === "observe-dropped");
  ok("The ring's OWN ingestion loss rides (dropClass transport + how many were lost) -- a DO-side counter structurally cannot see this", dropped?.["dropClass"] === "transport" && dropped?.["dropped"] === 11);
  ok("countsMalformed marks a clamped-to-0 count that must NOT be read as a measured zero", sf.some((f) => f["countsMalformed"] === true));
  const knobSources = (bundle["sealKnobs"] as Record<string, unknown>)["knobSources"] as Record<string, { source: string }>;
  ok("Every seal knob reports HOW it got its running value (default | env | clamped | invalid)", Object.keys(knobSources).length >= 19 && knobSources["verifyAtSeal"]?.source === "default");

  // ---- 5. the OTLP trail's droppedCount -------------------------------------------------------------------
  console.log("\notlpPush:");
  const otlp = (bundle["otlpPush"] as Record<string, unknown>)["trail"] as Array<Record<string, unknown>>;
  ok("truncated:true is now SIZED -- how many data points were dropped over the 5000-point cap", otlp[0]?.["truncated"] === true && otlp[0]?.["droppedCount"] === 1234);

  // ---- 6. failure-biased notify history + the smart-retained onset ----------------------------------------
  console.log("\nnotifyFailures + the smart-retained boundary rows:");
  const notify = bundle["notify"] as Array<Record<string, unknown>>;
  ok("the recency window is (as before) 20 rows, and on this ring they are ALL recent successes", notify.length === 20 && notify.every((n) => n["delivered"] === true));
  const nf = bundle["notifyFailures"] as { recent: Array<Record<string, unknown>>; byChannelKind: Record<string, Record<string, unknown>> };
  ok("The FAILURE-BIASED window reaches the undelivered rows the recency window buried", nf.recent.length === 2 && nf.recent.every((r) => r["delivered"] === false));
  ok("The ONSET row (the OLDEST undelivered row for the kind) is smart-retained, so the first failure's code survives", nf.recent.some((r) => r["at"] === "2026-07-04T05:00:00.000Z" && r["deliveryCode"] === "http-gone"));
  ok("The per-channelKind rollup answers 'this kind has not delivered since' over the WHOLE ring", nf.byChannelKind["pagerduty"]?.["failCount"] === 2 && nf.byChannelKind["pagerduty"]?.["lastDeliveredAt"] === "2026-06-20T05:00:00.000Z");
  ok("a kind that has never failed carries no failCount but still reports its last delivery", nf.byChannelKind["email"]?.["failCount"] === 0);

  // ---- 7. the unknown-code placeholder + the invalid env marker -------------------------------------------
  console.log("\ndrift is legible, never silent:");
  const rec = bundle["recovery"] as Record<string, unknown>;
  ok("an out-of-vocabulary refusal code rides as the placeholder (never `refused:true` with no cause at all)", rec["refusedCode"] === "unknown-code");
  ok("an out-of-vocabulary amnesia probe no longer drops the WHOLE block: the block rides with the placeholder", (rec["amnesiaProbe"] as Record<string, unknown>)["probe"] === "unknown-code");
  ok("the refusal's free-text reason (which can embed a secret FIELD NAME and a storage path) is still never carried", !text.includes("would leak"));
  const lar = bundle["licenceActivationRefusals"] as Record<string, unknown>;
  ok("an out-of-vocabulary licence-refusal code rides as the placeholder ('I pasted my licence' keeps its cause)", lar["lastReasonCode"] === "unknown-code");
  ok("a SET-but-unparseable CPU_MS mirror is marked invalid (a typo is no longer identical to 'never mirrored')", infra["cpuMsInvalid"] === true && !("cpuMs" in infra));

  // ---- 8. accessPerimeter / mutation attribution / advertised capabilities / update availability ----------
  console.log("\naccessPerimeter / attributed / capabilities / update availability:");
  ok("The Access-perimeter presence boolean now rides in the SEALED bundle (it was only on the GET /support summary)", bundle["accessPerimeter"] === true);
  const events = bundle["configEvents"] as Array<Record<string, unknown>>;
  const propose = events.find((e) => e["action"] === "config-change-propose");
  const approve = events.find((e) => e["action"] === "config-change-approve");
  ok("A mutation made by a VERIFIED identity is flagged attributed:true (the identity itself never rides)", propose?.["attributed"] === true);
  ok("A mutation made with the shared break-glass token is flagged attributed:false", approve?.["attributed"] === false);
  ok("The actor email is still absent from the excerpt", !text.includes("ops@acme.example"));
  const caps = (bundle["engine"] as Record<string, unknown>)["capabilities"] as Record<string, unknown>;
  ok("The engine's advertised capability vector rides (the console renders the whole sources tier from it)", caps["addedSourcesSupported"] === true && caps["tokenSourceOfferedCount"] === 5 && (caps["tokenSourceTypes"] as string[]).includes("workers"));
  const avail = (bundle["updates"] as Record<string, unknown>)["available"] as Record<string, unknown>;
  ok("The update-availability gating verdicts ride (an unconfigured channel is a CLOSED issue class, never the engine's sentence)", avail["configured"] === false && avail["verified"] === false && avail["channelIssue"] === "not-configured" && avail["channelBaseValid"] === false);

  // The two availability classifiers are pure: drive every arm (they READ a sentence only to SELECT an enum).
  ok("classifyChannelIssue: the non-https gate", classifyChannelIssue("UPDATE_CHANNEL_URL must use https") === "not-https");
  ok("classifyChannelIssue: a failed signature verify", classifyChannelIssue("channel signature did not verify under the pinned signer") === "signature-invalid");
  ok("classifyChannelIssue: an unparseable channel url", classifyChannelIssue("UPDATE_CHANNEL_URL is not a valid URL") === "url-invalid");
  ok("classifyChannelIssue: a NEW refusal path reads as drift, never as free text", classifyChannelIssue("could not reach https://acme.example/channel.json for ops@acme.example") === "unknown-code");
  ok("classifyCompatBlock: a release whose floor is NEWER than this engine", classifyCompatBlock("0.1.9", "0.2.0") === "min-engine-version");
  ok("classifyCompatBlock: an UNPARSEABLE floor is REFUSED (never assumed to fit)", classifyCompatBlock("0.1.9", "not-a-version") === "min-engine-version-unparseable");
  ok("classifyCompatBlock: an applicable release is not blocked", classifyCompatBlock("0.1.9", "0.1.0") === null);

  // ---- 8b. the smart-retained boundary row on the RUN ring and the CANARY transition ring ------------------
  console.log("\nthe fault ONSET survives the ring's pack window:");
  // A downpipe that has failed hourly for three days: the 10-row recency window shows only the identical-
  // looking tail. The ring is NEWEST-FIRST, so index 13 is the ONSET -- the first flip, whose error and
  // causeDigest differ from every row after it, and which says what changed that day.
  const busy = schedulerDouble({
    "/history": {
      byDownpipe: {
        dp1: [
          ...Array.from({ length: 13 }, (_, i) => ({ runId: `r${i}`, index: 100 - i, startedAt: `2026-07-1${1}T0${i % 9}:00:00.000Z`, status: "failed", error: "destination-unreachable", causeDigest: "aaaaaaaaaaaa" })),
          { runId: "onset", index: 87, startedAt: "2026-07-08T00:00:00.000Z", status: "failed", error: "destination-auth", causeDigest: "bbbbbbbbbbbb" },
          { runId: "healthy", index: 86, startedAt: "2026-07-07T00:00:00.000Z", status: "ok" },
        ],
      },
    },
    "/canary/transitions": {
      enabled: true,
      status: "dead",
      deadDestinations: 1,
      transitionCount: 60,
      // 60 transitions: the ONSET death (index 0) predates the last-50 window entirely.
      transitions: [
        { at: "2026-06-01T00:00:00.000Z", destinationId: "dest-a", to: "dead", runSeq: 1 },
        ...Array.from({ length: 59 }, (_, i) => ({ at: `2026-07-01T00:00:${String(i).padStart(2, "0")}.000Z`, destinationId: "dest-b", to: i % 2 === 0 ? "recovered" : "dead", runSeq: i + 2 })),
      ],
    },
  });
  const busyBundle = await buildSupportBundle(envDouble(), busy, ctx);
  const busyRuns = (busyBundle["runs"] as Record<string, Array<Record<string, unknown>>>)["dp1"]!;
  ok("The run window is still the 10 most recent rows PLUS one smart-retained row", busyRuns.length === 11);
  ok("The retained row is the OLDEST FAILING run -- the ONSET, whose error and causeDigest differ from the tail", busyRuns.some((r) => r["runId"] === "onset" && r["error"] === "destination-auth" && r["causeDigest"] === "bbbbbbbbbbbb"));
  const busyTransitions = (busyBundle["canary"] as Record<string, unknown>)["transitions"] as Array<Record<string, unknown>>;
  ok("The ORIGINAL death of a destination is retained even though it predates the last-50 window", busyTransitions.some((t) => t["destinationId"] === "dest-a" && t["to"] === "dead" && t["at"] === "2026-06-01T00:00:00.000Z"));
  // 50 recency rows + the two out-of-window ONSET deaths (one per destination): the canary pages exactly once
  // per crossing, so without these the standing death has no recorded beginning anywhere in the pack.
  ok("The recency window is still carried in full beside the retained onsets", busyTransitions.length === 52);

  // ---- 9. the section roster stays complete + honest -----------------------------------------------------
  console.log("\nsections (the health vector):");
  const sections = bundle["sections"] as Record<string, string>;
  for (const name of ["schedDiag", "sealErrors", "metricsHealth", "webauthnFaults", "droppedWrites"]) {
    ok(`the new '${name}' section is in the health vector and read ok`, sections[name] === "ok");
  }
  // A section whose DO read THROWS must read "error" (a fault is not an honest absence).
  const faulting = {
    fetch: async (input: RequestInfo | URL) => {
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url).pathname;
      if (path === "/sched-diag" || path === "/dropped-writes") throw new Error("DO unavailable");
      return new Response(JSON.stringify(path === "/downpipes" ? [] : {}));
    },
  } as unknown as DurableObjectStub;
  const degraded = await buildSupportBundle(envDouble(), faulting);
  const dsec = degraded["sections"] as Record<string, string>;
  ok("a FAULTING /sched-diag read marks the section 'error', never a clean 'empty'", dsec["schedDiag"] === "error");
  ok("a FAULTING /dropped-writes read marks the section 'error' (an unreadable under-count caveat is not 'nothing was lost')", dsec["droppedWrites"] === "error");
  ok("a bundle built with NO request context honestly OMITS accessPerimeter (never a fabricated false)", !("accessPerimeter" in degraded));

  console.log(failures === 0 ? "\nSUPPORT-PACK FAULT-EVIDENCE PROJECTION PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
