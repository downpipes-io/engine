// Validates the CRON-PASS FAULT EVIDENCE the support pack reasons over: the SIEM + OTLP push drains and
// the retention prune. Each of these passes used to take an early
// `return` on a pre-delivery fault -- a malformed CONFIG_WRAP_KEY, an unreadable DO config/cursor/export/
// snapshot, a break-glass-only posture, an unloadable signer, an unreadable RUNLOG, an abstaining planner --
// and record NOTHING, so "our SIEM/metrics push silently stopped" and "storage keeps growing despite
// retention.enforce=true" both reached support with an empty pack.
//
// This test proves, with a fake scheduler DO capturing every write:
//   (a) the evidence IS recorded on each fault path (the row lands on the push trail / the retention record);
//   (b) it is REDACTION-SAFE: a customer value and a raw error message planted at the fault site never appear
//       anywhere in the recorded body -- only closed enums, counts, booleans and the customer's own opaque ids.
// No network, no real DO. Run:
//   node test/validate-cron-fault-evidence.ts

import { runSiemPushPass, classifyPushConfigFault, PUSH_PASS_FAIL_CODES, PUSH_SINK_FAIL_CODES } from "../src/cron/siem-push-pass.ts";
import { runOtlpPushPass, classifyOtlpConfigFault } from "../src/cron/otlp-push-pass.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
// The retention-pass RECORD (its closed vocabularies, shape, classifiers and sanitiser) lives in the leaf
// module cron/retention-record.ts, so the scheduler DO (which persists it) and the support pack (which projects
// it) can share one vocabulary without importing the cron pass's graph -- which reaches admin/router.ts and
// would close an import cycle through the DO base.
import {
  classifyDeferral,
  classifyPruneError,
  sanitiseRetentionPassRecord,
  RETENTION_SKIP_CODES,
  RETENTION_OUTCOMES,
  RETENTION_DEFERRAL_CLASSES,
  RETENTION_ERROR_CLASSES,
  type RetentionPassRecord,
} from "../src/cron/retention-record.ts";
import { pendingDroppedWrites, resetPendingDroppedWrites } from "../src/admin/diag-writer.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted needles: a customer value, a secret and a raw error message. NONE may appear in ANY recorded
// body. Every recording site coarsens to a closed enum before it writes, so this is the redaction proof.
const SECRET = "hec-token-9f3c-CUSTOMER-SECRET";
const CUSTOMER_VALUE = "acme-payroll-database";
const RAW_ERROR = `connect ECONNREFUSED 10.1.2.3:443 while reading ${CUSTOMER_VALUE} (${SECRET})`;
function noNeedles(label: string, bodies: string[]): void {
  const joined = bodies.join("\n");
  ok(`${label}: the recorded body carries NO secret`, !joined.includes(SECRET));
  ok(`${label}: the recorded body carries NO customer value`, !joined.includes(CUSTOMER_VALUE));
  ok(`${label}: the recorded body carries NO raw error text`, !joined.includes("ECONNREFUSED"));
}

// ---- SIEM push drain -----------------------------------------------------------------------------

type SiemSched = Parameters<typeof runSiemPushPass>[1];
interface SiemFake {
  record: { endpoint: string; format: string; authHeaderName: string; authHeaderValue: unknown; enabled: boolean; gen: string } | null;
  recorded: string[]; // the raw JSON bodies posted to /push-record
  throwOn?: string; // a DO path that faults this tick
}
function siemScheduler(f: SiemFake): SiemSched {
  return {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      if (f.throwOn === url.pathname) throw new Error(RAW_ERROR);
      const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200 });
      if (url.pathname === "/push-config") return json({ record: f.record });
      if (url.pathname === "/push") return json({ lastPushedSeq: 0 });
      if (url.pathname === "/audit/export") return json({ events: [], headSeq: 0, headHash: "" });
      if (url.pathname === "/push-record") {
        f.recorded.push(String(init?.body ?? "{}"));
        return json({ ok: true });
      }
      throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
    },
  } as unknown as SiemSched;
}
const liveSiemRecord = { endpoint: "https://siem.example.com/services/collector", format: "hec", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true, gen: "gen-1" };

console.log("SIEM push drain: a pre-delivery fault lands a CLOSED code on the trail");
{
  const env = {} as unknown as Env;
  const badKeyEnv = { CONFIG_WRAP_KEY: "not-base64url-32-bytes" } as unknown as Env;

  {
    // A malformed CONFIG_WRAP_KEY: the drain cannot open its own sealed auth secret. Before this, the pass
    // returned false and wrote nothing, so a wrap-key rotation stopped the push SILENTLY.
    const f: SiemFake = { record: { ...liveSiemRecord }, recorded: [] };
    ok("a malformed CONFIG_WRAP_KEY still returns false (the false-green signal)", (await runSiemPushPass(badKeyEnv, siemScheduler(f))) === false);
    ok("wrap-key-invalid is RECORDED on the trail", f.recorded.length === 1 && (JSON.parse(f.recorded[0]!) as { reason?: string }).reason === "wrap-key-invalid");
    ok("the fault row is ok:false (so the cursor can never advance on a fault)", (JSON.parse(f.recorded[0]!) as { ok?: boolean }).ok === false);
    noNeedles("wrap-key-invalid", f.recorded);
  }
  {
    // No destination configured: an unconfigured drain has nothing to say, so nothing is recorded (the trail
    // must not fill with rows for a feature the customer never turned on).
    const f: SiemFake = { record: null, recorded: [] };
    await runSiemPushPass(badKeyEnv, siemScheduler(f));
    ok("an UNCONFIGURED drain records nothing, even on a wrap-key fault", f.recorded.length === 0);
  }
  {
    // The DO would not serve the config record this tick.
    const f: SiemFake = { record: { ...liveSiemRecord }, recorded: [], throwOn: "/push-config" };
    ok("an unreadable DO config returns false", (await runSiemPushPass(env, siemScheduler(f))) === false);
    ok("the DO is the trail's only home: an unreachable DO records nothing (the tick ring carries it)", f.recorded.length === 0);
  }
  {
    // The record read back, but its sealed auth secret would not unwrap (a rotated wrap key: the classic
    // silent stop). The record is readable, so the gen probe succeeds and the fault IS recorded.
    const f: SiemFake = { record: { ...liveSiemRecord, authHeaderValue: { v: 1, iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAAA" } }, recorded: [] };
    ok("an unwrappable sealed secret returns false", (await runSiemPushPass(env, siemScheduler(f))) === false);
    ok("secret-unresolvable is RECORDED (distinct from config-unreadable)", (JSON.parse(f.recorded[0] ?? "{}") as { reason?: string }).reason === "secret-unresolvable");
    noNeedles("secret-unresolvable", f.recorded);
  }
  {
    const f: SiemFake = { record: { ...liveSiemRecord }, recorded: [], throwOn: "/push" };
    ok("an unreadable cursor returns false", (await runSiemPushPass(env, siemScheduler(f))) === false);
    ok("cursor-unreadable is RECORDED with the live gen", (JSON.parse(f.recorded[0] ?? "{}") as { reason?: string; gen?: string }).reason === "cursor-unreadable" && (JSON.parse(f.recorded[0] ?? "{}") as { gen?: string }).gen === "gen-1");
    noNeedles("cursor-unreadable", f.recorded);
  }
  {
    const f: SiemFake = { record: { ...liveSiemRecord }, recorded: [], throwOn: "/audit/export" };
    ok("an unreadable audit export returns false", (await runSiemPushPass(env, siemScheduler(f))) === false);
    ok("export-unreadable is RECORDED", (JSON.parse(f.recorded[0] ?? "{}") as { reason?: string }).reason === "export-unreadable");
    noNeedles("export-unreadable", f.recorded);
  }
  {
    // Every reason this pass can write is a member of the closed vocabulary (the pack projects `reason` as a
    // class, so an open string here would be a redaction hole).
    const codes: ReadonlySet<string> = new Set<string>(PUSH_PASS_FAIL_CODES);
    ok("the pass-level vocabulary is closed and contains the six pre-delivery codes + the tail fault", codes.size === 7 && codes.has("wrap-key-invalid") && codes.has("secret-unresolvable") && codes.has("snapshot-unreadable") && codes.has("shape-or-deliver-fault"));
    ok("the sink-level vocabulary is closed (the 9 closed S3 classes + the 2 target-missing reasons)", PUSH_SINK_FAIL_CODES.length === 11 && (PUSH_SINK_FAIL_CODES as readonly string[]).includes("s3-worm-denied") && !(PUSH_SINK_FAIL_CODES as readonly string[]).includes("s3-put-failed"));
    ok("classifyPushConfigFault returns config-unreadable ONLY for the engine's own DO-read literal", classifyPushConfigFault(new Error("push destination configuration unreadable (DO responded 503)")) === "config-unreadable");
    ok("classifyPushConfigFault coarsens any OTHER throw to secret-unresolvable, never carrying its text", classifyPushConfigFault(new Error(RAW_ERROR)) === "secret-unresolvable");
  }
}

// ---- OTLP push drain -----------------------------------------------------------------------------

type OtlpSched = Parameters<typeof runOtlpPushPass>[1];
interface OtlpFake {
  record: { endpoint: string; authHeaderName: string; authHeaderValue: unknown; enabled: boolean; gen: string } | null;
  recorded: string[];
  throwOn?: string;
}
function otlpScheduler(f: OtlpFake): OtlpSched {
  return {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      if (f.throwOn === url.pathname) throw new Error(RAW_ERROR);
      const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200 });
      if (url.pathname === "/otlp-push-config") return json({ record: f.record });
      if (url.pathname === "/otlp-metrics-snapshot") return json({ downpipes: [] });
      if (url.pathname === "/otlp-push-record") {
        f.recorded.push(String(init?.body ?? "{}"));
        return json({ ok: true });
      }
      throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
    },
  } as unknown as OtlpSched;
}
const liveOtlpRecord = { endpoint: "https://otlp.example.com/v1/metrics", authHeaderName: "Authorization", authHeaderValue: SECRET, enabled: true, gen: "gen-o" };

console.log("\nOTLP push drain: a pre-delivery fault lands a CLOSED code on the trail");
{
  const env = {} as unknown as Env;
  const badKeyEnv = { CONFIG_WRAP_KEY: "not-base64url-32-bytes" } as unknown as Env;
  {
    const f: OtlpFake = { record: { ...liveOtlpRecord }, recorded: [] };
    ok("a malformed CONFIG_WRAP_KEY still returns false", (await runOtlpPushPass(badKeyEnv, otlpScheduler(f))) === false);
    ok("wrap-key-invalid is RECORDED on the OTLP trail", (JSON.parse(f.recorded[0] ?? "{}") as { reason?: string }).reason === "wrap-key-invalid");
    noNeedles("otlp wrap-key-invalid", f.recorded);
  }
  {
    const f: OtlpFake = { record: { ...liveOtlpRecord, authHeaderValue: { v: 1, iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAAA" } }, recorded: [] };
    ok("an unwrappable sealed secret returns false", (await runOtlpPushPass(env, otlpScheduler(f))) === false);
    ok("secret-unresolvable is RECORDED", (JSON.parse(f.recorded[0] ?? "{}") as { reason?: string }).reason === "secret-unresolvable");
    noNeedles("otlp secret-unresolvable", f.recorded);
  }
  {
    const f: OtlpFake = { record: { ...liveOtlpRecord }, recorded: [], throwOn: "/otlp-metrics-snapshot" };
    ok("an unreadable metrics snapshot returns false", (await runOtlpPushPass(env, otlpScheduler(f))) === false);
    const row = JSON.parse(f.recorded[0] ?? "{}") as { reason?: string; gen?: string; downpipeCount?: number; ok?: boolean };
    ok("snapshot-unreadable is RECORDED with the live gen, ok:false and a zero count", row.reason === "snapshot-unreadable" && row.gen === "gen-o" && row.ok === false && row.downpipeCount === 0);
    noNeedles("otlp snapshot-unreadable", f.recorded);
  }
  {
    const f: OtlpFake = { record: null, recorded: [] };
    await runOtlpPushPass(badKeyEnv, otlpScheduler(f));
    ok("an UNCONFIGURED OTLP drain records nothing", f.recorded.length === 0);
  }
  ok("classifyOtlpConfigFault matches ONLY the engine's own DO-read literal", classifyOtlpConfigFault(new Error("OTLP push destination configuration unreadable (DO responded 500)")) === "config-unreadable" && classifyOtlpConfigFault(new Error(RAW_ERROR)) === "secret-unresolvable");
}

// ---- Retention prune ----------------------------------------------------------------------

console.log("\nRetention prune: the pass record classes every skip/deferral/error");
{
  ok("the deferral vocabulary is closed", RETENTION_DEFERRAL_CLASSES.length === 2 && RETENTION_ERROR_CLASSES.length === 5);
  ok("the planner's own abstention text classes to retained-run-unreadable", classifyDeferral("a retained run could not be read; deferring the prune so segment GC stays safe") === "retained-run-unreadable");
  ok("an unrecognised abstention classes to `other`, never carrying its text", classifyDeferral(RAW_ERROR) === "other");
  ok("a lock failure classes to lock-contention", classifyPruneError(new Error("RUNLOG lock not acquired: contention")) === "lock-contention");
  ok("a missing manifest classes to run-unreadable", classifyPruneError(new Error(`object run/${CUSTOMER_VALUE}/manifest is missing`)) === "run-unreadable");
  ok("an unknown throw classes to `other`", classifyPruneError(new Error("boom")) === "other");
  // BOTH DIRECTIONS of the `put ` -> `\bput\b` fix, because the old literal failed in both. A native binding
  // throws "put:" and an S3 leg writes "PUT seg/0001", and neither carries the trailing space the old pattern
  // required, so a real destination write failure classed as `other` and the pass lost the label that says
  // where to look. Meanwhile "input " DID contain "put ", so an unrelated validation message classed as a
  // destination write failure that never happened. Each case here fails against the pre-fix pattern.
  ok("a native-binding `put:` write fault classes to dest-write-failed", classifyPruneError(new Error("put: R2 binding rejected the object")) === "dest-write-failed");
  ok("an S3 `PUT seg/0001` write fault classes to dest-write-failed", classifyPruneError(new Error("PUT seg/0001: status 403")) === "dest-write-failed");
  ok("a bare `put,` still classes to dest-write-failed", classifyPruneError(new Error("put, then the store closed")) === "dest-write-failed");
  ok("an `input ` message is NOT mistaken for a destination write", classifyPruneError(new Error("invalid input value for the retention window")) === "other");
  ok("every classifier returns an ENUM MEMBER, never the input text", ([classifyPruneError(new Error(RAW_ERROR)), classifyDeferral(RAW_ERROR)] as string[]).every((c) => !c.includes("ECONNREFUSED") && !c.includes(SECRET)));

  // The sanitiser is the redaction boundary: drifted enum members are DROPPED (never persisted), counts are
  // clamped non-negative, and the arrays are capped.
  const dirty = {
    at: -5,
    downpipesWithRetention: 3,
    downpipesPaused: -1,
    replicationUnreadable: "yes" as unknown as boolean,
    auditWriteFailures: Number.NaN,
    passSkipCode: RAW_ERROR as never,
    destinations: [{ destKey: "dest-1", downpipeCount: -2, skipCode: "runlog-unreadable" as const }],
    downpipes: [
      { id: "dp-1", outcome: "deferred" as const, deferralClass: RAW_ERROR as never, supersededRuns: -1, runTreeObjects: 4, orphanSegs: 2, retainedRuns: 5 },
      { id: "dp-2", outcome: RAW_ERROR as never, supersededRuns: 1, runTreeObjects: 1, orphanSegs: 1, retainedRuns: 1 },
    ],
  } satisfies RetentionPassRecord;
  const clean = sanitiseRetentionPassRecord(dirty);
  const cleanJson = JSON.stringify(clean);
  ok("a drifted passSkipCode is DROPPED, never persisted", clean.passSkipCode === undefined);
  ok("a drifted deferralClass is DROPPED", clean.downpipes[0]?.deferralClass === undefined);
  ok("a drifted outcome DROPS the whole row (an unclassifiable outcome is never persisted)", clean.downpipes.length === 1);
  ok("a non-boolean replicationUnreadable is forced to a strict boolean", clean.replicationUnreadable === false);
  ok("negative / NaN counts clamp to 0", clean.at === 0 && clean.auditWriteFailures === 0 && clean.downpipes[0]?.supersededRuns === 0 && clean.destinations[0]?.downpipeCount === 0);
  ok("a valid skipCode survives", clean.destinations[0]?.skipCode === "runlog-unreadable");
  noNeedles("sanitiseRetentionPassRecord", [cleanJson]);

  ok("the skip vocabulary covers the keys/posture/destination/RUNLOG causes", RETENTION_SKIP_CODES.length === 6 && RETENTION_OUTCOMES.length === 6);
  // PAUSE MEANS PAUSE: "paused" is a first-class outcome, not an absence. A pass that stood down because the
  // operator paused the downpipe must be distinguishable in the pack from a pass that found nothing to delete.
  ok("the outcome vocabulary names the PAUSED stand-down", (RETENTION_OUTCOMES as readonly string[]).includes("paused"));
  ok("downpipesPaused is clamped like every other count (a negative can never ride)", clean.downpipesPaused === 0);
}

console.log("\nRetention prune: the pass POSTS its record on the skip paths (the 'nothing ever gets deleted' ticket)");
{
  interface RetFake {
    recorded: string[];
    throwOn?: string;
  }
  // `enabled: true` is load-bearing, not decoration. retention-pass.ts partitions on the downpipe's own
  // switch with `!s.config.enabled`, so a fixture that omits the field counts as PAUSED and is retained --
  // the deliberate "pause means pause" rule whose own proof is validate-pause-retention.ts. Without it this
  // fixture has no ACTIVE downpipe, the pass returns before it reaches any of the fault branches below, and
  // all four assertions would read a record that was never posted.
  const withRetention = [
    { config: { id: "dp-1", name: CUSTOMER_VALUE, enabled: true, retention: { keepRuns: 3, enforce: true }, source: {} }, nextRunAt: 0, lastRunId: null, inFlight: false },
  ];
  function retScheduler(f: RetFake): DurableObjectStub {
    return {
      fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
        const url = new URL(typeof input === "string" ? input : input.toString());
        if (f.throwOn === url.pathname) throw new Error(RAW_ERROR);
        const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200 });
        if (url.pathname === "/downpipes") return json(withRetention);
        if (url.pathname === "/replication") return json({ byDownpipe: {} });
        if (url.pathname === "/retention-record") {
          f.recorded.push(String(init?.body ?? "{}"));
          return json({ ok: true });
        }
        throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
      },
    } as unknown as DurableObjectStub;
  }
  {
    // Break-glass-only: no OPERATIONAL_PRIVATE. The prune CANNOT run (manifests are unopenable in-account),
    // and before this the pack showed nothing at all -- identical to "retention is fine, nothing to delete".
    const f: RetFake = { recorded: [] };
    await runRetentionPrunes({} as unknown as Env, retScheduler(f));
    const rec = JSON.parse(f.recorded[0] ?? "{}") as RetentionPassRecord;
    ok("the break-glass-only skip IS recorded with its closed code", rec.passSkipCode === "break-glass-only");
    ok("the record counts the downpipes awaiting an offline prune", rec.downpipesWithRetention === 1);
    ok("the record carries no downpipe rows (none were planned)", rec.downpipes.length === 0);
    // The downpipe NAME is a customer value and is deliberately NOT on the record: only opaque ids ride.
    noNeedles("retention break-glass record", f.recorded);
  }
  {
    // The keys would not load (no SIGNER_PRIVATE): a silently skipped prune, every tick, forever.
    const f: RetFake = { recorded: [] };
    await runRetentionPrunes({ OPERATIONAL_PRIVATE: "not-a-real-key" } as unknown as Env, retScheduler(f));
    const rec = JSON.parse(f.recorded[0] ?? "{}") as RetentionPassRecord;
    ok("the keys-unavailable skip IS recorded with its closed code", rec.passSkipCode === "keys-unavailable");
    noNeedles("retention keys-unavailable record", f.recorded);
  }
  {
    // An unreadable replication state makes the M7 coverage gate hold EVERY replicated run (retention appears
    // to do nothing). The flag says so.
    const f: RetFake = { recorded: [], throwOn: "/replication" };
    await runRetentionPrunes({} as unknown as Env, retScheduler(f));
    const rec = JSON.parse(f.recorded[0] ?? "{}") as RetentionPassRecord;
    ok("an unreadable replication state is flagged on the record (the gate ran on no proof)", rec.replicationUnreadable === true);
    noNeedles("retention replication-unreadable record", f.recorded);
  }
  {
    // A DO that has no /retention-record slot (an older engine) must NOT break the prune: the recorder is
    // silent on failure.
    const throwing = { fetch: async (input: string | URL): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      if (url.pathname === "/downpipes") return new Response(JSON.stringify(withRetention), { status: 200 });
      if (url.pathname === "/replication") return new Response(JSON.stringify({ byDownpipe: {} }), { status: 200 });
      throw new Error(RAW_ERROR);
    } } as unknown as DurableObjectStub;
    let threw = false;
    resetPendingDroppedWrites();
    try {
      await runRetentionPrunes({} as unknown as Env, throwing);
    } catch {
      threw = true;
    }
    ok("a DO with no retention-record slot degrades to a no-op, never a thrown prune", threw === false);
    // But not a SILENT no-op. recordRetentionPass routes through recordDiagWrite: the DO here is unreachable
    // (the flush throws too), so the loss is PENDING rather than flushed, and lands the moment the DO
    // recovers. That pending count is the evidence; a zero here would mean the loss went silent.
    ok("the lost retention record is COUNTED as a dropped write, pending until the DO recovers", (pendingDroppedWrites()["retention-record"] ?? 0) === 1);
    resetPendingDroppedWrites();
  }
}

console.log(`\n${failures === 0 ? "PASS" : `FAIL (${failures})`}`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
