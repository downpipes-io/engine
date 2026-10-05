// Support-pack diagnostic coverage for the ADMIN RESTORE / LICENCE / REPORT subsystems. Each site records
// its evidence at the fault path, so a pack is never merely coarse or MISLEADING: a restore that fails carries
// attribution, an apply that dies mid-write leaves a record, an engine bug is distinguishable from a corrupt
// customer token, and a SIGNED compliance report never silently under-reports.
//
// Every block proves the SAME two things a recording must satisfy:
//   (a) the evidence IS recorded ON THE FAULT PATH (through the real classifier / the real DO route), and
//   (b) it is REDACTION-SAFE: a customer value, a secret and a raw provider error message planted at the
//       fault site NEVER appear in the recorded record or in the DO's read-back.
//
// The diagnosable outcomes:
//   "the restore failed / did it write anything?"        -> a bounded restoreFaults ring: WHICH record, WHICH
//        phase (verify aborts with nothing written; readback means the bytes ARE on the target), WHICH closed
//        class -- plus the two paths with no row at all otherwise: an apply that THREW, and every dry-run refusal.
//   "our KV namespace is half restored"                   -> a reclaimed apply lease is durable proof that
//        an EARLIER apply died mid-write, instead of a read-time projection the retry overwrites.
//   "every valid licence reads as malformed" /            -> an ENGINE fault is classed internal-error (never
//        "our Enterprise tier keeps dropping"               body-malformed), and a NON-2XX DO read is recorded
//                                                           as the source flip it is, with a durable rate.
//   "the report shows no changes / no run exists"         -> the silently excluded rows are COUNTED, and a
//        faulted report-data read fails LOUDLY instead of being signed over an error body.
//
// No network, no real Cloudflare. Run:
//   node test/validate-restore-fault-evidence.ts

import {
  applyAdminCounters,
  applyRestoreFault,
  classifyRestoreFaultClass,
  ADMIN_COUNTER_NAMES,
  ADMIN_COUNTERS_KEY,
  RESTORE_FAULT_CLASSES,
  RESTORE_FAULT_OPS,
  RESTORE_FAULT_PHASES,
  RESTORE_FAULTS_KEY,
  RESTORE_FAULTS_RING_CAP,
  RESTORE_FAULT_ROWS_PER_OP,
  type RestoreFaultRow,
} from "../src/admin/diag-records.ts";
import { restoreFaultRows, recordRestoreOutcome } from "../src/admin/restore-faults.ts";
import { withRecordIdentity } from "../src/admin/restore-fault-identity.ts";
import { bumpAdminCounter } from "../src/admin/diag-counters.ts";
import { resetPendingDroppedWrites, pendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { destAccessReason, REASON_INTEGRITY, REASON_ORIGIN_REMOVED } from "../src/restore-reasons.ts";
import { BREAK_GLASS_REASON, RESERVED_REASON, inAccountTooLargeReason, windowSkippedReason } from "../src/admin/restore-sinks.ts";
import { effectiveStatus, RESTORE_APPLY_LEASE_MS, type RestoreApproval } from "../src/admin/approvals.ts";
import { readLicence } from "../src/admin/licence.ts";
import { resolveRunAt } from "../src/admin/point-in-time.ts";
import { buildChangeRequestsReport } from "../src/admin/reports.ts";
import { buildReportBody } from "../src/admin/router-posture.ts";
import { makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";
import type { Env } from "../src/env.d.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { RunHistoryEntry } from "../src/sched/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry } from "../src/format/writer.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { deriveMK, deriveNameMACKey, nameMAC } from "../src/crypto/derive.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { runRestore } from "../src/admin/restore.ts";
import type { RestoreResult } from "../src/admin/restore-types.ts";
import { buildSupportBundle, sealedSupportBundle } from "../src/admin/support.ts";
import { makeSupportRecipient } from "../tools/generate-support-keypair.ts";
import { openSupportBundle } from "../tools/open-support-bundle.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted needles. NONE may appear in ANY recorded record or read-back. Every recording site coarsens to
// a closed enum BEFORE it writes, so a substring scan over the serialised record is conclusive.
const SECRET = "AKIA-POISON-KEY/dps_customer-secret-9f3a";
const CUSTOMER_VALUE = "acme-payroll-crown-jewels";
const RAW_ERROR = `S3 PutObject denied for bucket ${CUSTOMER_VALUE} at https://acme.r2.cloudflarestorage.com (${SECRET})`;

function scanClean(label: string, subject: unknown): void {
  const json = JSON.stringify(subject ?? null);
  const leaked = [SECRET, CUSTOMER_VALUE, "AKIA-POISON-KEY", "r2.cloudflarestorage.com", "PutObject"].filter((p) => json.includes(p));
  ok(`${label} (redaction: no secret / customer value / raw error in the record)`, leaked.length === 0);
}

// A scheduler stub that CAPTURES what the Worker edge posts, so the fault path is observed at the wire.
function capturingScheduler(opts: { down?: boolean } = {}): { scheduler: DurableObjectStub; posts: Array<{ path: string; body: unknown }> } {
  const posts: Array<{ path: string; body: unknown }> = [];
  const scheduler = {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      posts.push({ path, body: init?.body === undefined ? null : JSON.parse(String(init.body)) });
      if (opts.down === true) return new Response("nope", { status: 500 });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  return { scheduler, posts };
}

// ---- the restore / drill / verify fault ring ---------------------------------------------------------

function testRestoreClassifier(): void {
  console.log("\nthe restore reason classifier RETURNS a closed class and never carries the text");

  // The per-record write refusal a WORM / rotated-credential restore target produces. destAccessReason is the
  // REAL producer (restore-apply.ts calls it with the raw sink message), so this is the true fault-site text.
  const wormRefusal = destAccessReason(`PUT seg/0001: status 403 (AccessDenied) ${RAW_ERROR}`);
  ok("a refused destination WRITE classifies as dest-access", classifyRestoreFaultClass(wormRefusal) === "dest-access");
  scanClean("the class of a refused write", classifyRestoreFaultClass(wormRefusal));

  // The distinction the whole gap turns on: was anything WRITTEN?
  ok(
    "written-but-unprovable is readback-failed (the bytes ARE on the target)",
    classifyRestoreFaultClass("the object was written but could not be read back to verify; recover it offline with the downpipe CLI") === "readback-failed",
  );
  ok(
    "written-but-wrong-hash is readback-mismatch (the bucket ate or mangled the write)",
    classifyRestoreFaultClass("the object was written but failed post-write readback verification; recover it offline with the downpipe CLI") === "readback-mismatch",
  );
  ok(
    "a D1 write fault is d1-partial (the target database may be half-loaded)",
    classifyRestoreFaultClass("partial restore: the target D1 may be inconsistent; drop it and retry into a fresh database") === "d1-partial",
  );
  ok("an integrity abort stays integrity, never an availability class", classifyRestoreFaultClass(REASON_INTEGRITY) === "integrity");
  ok("a removed-origin restore is origin-removed", classifyRestoreFaultClass(REASON_ORIGIN_REMOVED) === "origin-removed");

  // The refusals that WROTE NOTHING and persisted nowhere at all.
  ok("the reserved-binding refusal classifies (the whole restore refused before any write)", classifyRestoreFaultClass(RESERVED_REASON) === "reserved-binding");
  ok("the oversized in-account refusal is too-large (OFFLINE-RECOVERABLE, never loss)", classifyRestoreFaultClass(inAccountTooLargeReason(9000)) === "too-large");
  ok("a windowed partial is windowed, NOT the oversized refusal (both mention the offline CLI)", classifyRestoreFaultClass(windowSkippedReason(12, 0)) === "windowed");
  ok("a D1-bearing windowed partial is still windowed", classifyRestoreFaultClass(windowSkippedReason(12, 3)) === "windowed");
  // The break-glass-only posture is an HONEST REFUSAL ("this engine holds no in-account read-back key; recovery
  // is exercised offline with the break-glass key"), not a failure, so filing it under not-configured would make
  // a fleet of amber "failed last test" rows that send support hunting a fault which does not exist. It
  // classifies to its own posture-unexercisable class. Every OTHER not-configured reason (a missing required
  // binding, a half-configured engine) is unchanged, and is asserted immediately below so the split cannot
  // silently swallow them.
  ok("the break-glass-only posture is posture-unexercisable (an honest refusal, NOT a failure)", classifyRestoreFaultClass(BREAK_GLASS_REASON) === "posture-unexercisable");
  ok("a genuinely unconfigured engine is still not-configured", classifyRestoreFaultClass("missing required configuration: SIGNER_PRIVATE") === "not-configured");
  ok("every record skipped for a missing binding is binding-missing", classifyRestoreFaultClass("target binding not present") === "binding-missing");
  ok("a marker skip is marker-skipped (nothing was written back, by design)", classifyRestoreFaultClass("the captured value is an incompleteness marker (the object vanished or was skipped at capture), not real bytes; nothing written") === "marker-skipped");

  // THE REDACTION PROPERTY: a RAW provider message that matches no engine literal returns the residual enum.
  const residual = classifyRestoreFaultClass(RAW_ERROR);
  ok("a raw provider message coarsens to the residual class", residual === "other");
  ok("every class is a closed-vocabulary member", (RESTORE_FAULT_CLASSES as readonly string[]).includes(residual));
  scanClean("the class of a raw provider message", residual);
}

function testRestoreProjection(): void {
  console.log("\na finished restore projects to bounded rows (phase + class + the first record's index and keyed name MAC)");

  // A REAL apply outcome: an integrity-clean run whose writes partly failed. The reasons are built by the
  // engine's own producers, with the raw S3 text (carrying the needles) fed in exactly as restore-apply does.
  // Each entry carries its manifest record's identity the way the restore paths attach it.
  const mac = (c: string): string => c.repeat(96);
  const rec = (i: number, c: string): { recordId: string; keyNameHash: string } => ({ recordId: `r${String(i).padStart(15, "0")}`, keyNameHash: mac(c) });
  const rows = restoreFaultRows("apply", {
    ok: false,
    failures: [
      withRecordIdentity({ name: "uploads/2026/invoice-001.pdf", reason: destAccessReason(`PUT seg/0001: status 403 (AccessDenied) ${RAW_ERROR}`) }, rec(4, "a")),
      withRecordIdentity({ name: "uploads/2026/invoice-002.pdf", reason: destAccessReason(`PUT seg/0002: status 403 (AccessDenied) ${RAW_ERROR}`) }, rec(5, "b")),
      withRecordIdentity({ name: "uploads/2026/invoice-003.pdf", reason: "the object was written but failed post-write readback verification; recover it offline with the downpipe CLI" }, rec(6, "c")),
    ],
    skipped: [
      withRecordIdentity({ name: "cache/tmp-1", reason: "excluded by selector" }, rec(9, "d")), // BENIGN: the caller's own selector, not a fault
      withRecordIdentity({ name: "cache/tmp-2", reason: "the captured value is an incompleteness marker (the object vanished or was skipped at capture), not real bytes; nothing written" }, rec(10, "e")),
      { name: "(window)", reason: windowSkippedReason(40, 0) },
    ],
  });
  const byClass = new Map(rows.map((r) => [r.cls, r]));
  ok("the two refused writes AGGREGATE into one row with a count", byClass.get("dest-access")?.count === 2);
  ok("the aggregated row names the FIRST record by index and keyed name MAC (the one to look at)", byClass.get("dest-access")?.index === 4 && byClass.get("dest-access")?.keyNameHash === mac("a"));
  ok("no row carries a record name", rows.every((r) => !("recordName" in r)) && !JSON.stringify(rows).includes("invoice-00"));
  ok("an entry with no manifest identity leaves its row without one", byClass.get("windowed")?.index === undefined && byClass.get("windowed")?.keyNameHash === undefined);
  ok("the write phase is recorded (bytes were being written when it refused)", byClass.get("dest-access")?.phase === "write");
  ok("the readback mismatch is its OWN row in the readback phase (the object IS on the target)", byClass.get("readback-mismatch")?.phase === "readback");
  ok("the marker skip rides (a _vanished sentinel was never written back)", byClass.has("marker-skipped"));
  ok("the windowed remainder rides (records were left unrestored)", byClass.has("windowed"));
  ok("a selector exclusion is NOT a fault and records nothing", rows.every((r) => r.index !== 9 && r.keyNameHash !== mac("d")));
  ok("every row carries the op", rows.every((r) => r.op === "apply"));
  ok("every phase is a closed-vocabulary member", rows.every((r) => (RESTORE_FAULT_PHASES as readonly string[]).includes(r.phase)));
  scanClean("the projected rows", rows);

  // A CLEAN restore costs nothing at all.
  ok("a clean restore projects NO rows (the healthy steady state is free)", restoreFaultRows("apply", { ok: true, failures: [], skipped: [] }).length === 0);

  // A DRY-RUN refusal, which would otherwise persist NOWHERE, gets a row.
  const dry = restoreFaultRows("dry-run", { ok: false, reason: inAccountTooLargeReason(120_000), skipped: [] });
  ok("an oversized dry-run refusal records (op dry-run, phase plan, class too-large)", dry.length === 1 && dry[0]!.op === "dry-run" && dry[0]!.phase === "plan" && dry[0]!.cls === "too-large");

  // A pathological restore can never flood the ring or the subrequest budget.
  const flood = restoreFaultRows("apply", {
    ok: false,
    failures: Array.from({ length: 5000 }, (_, i) => ({ name: `k-${i}`, reason: destAccessReason("PUT: status 403 (AccessDenied)") })),
  });
  ok("5,000 failed records collapse to ONE aggregated row, not 5,000", flood.length === 1 && flood[0]!.count === 5000);
  ok("the projection is capped at RESTORE_FAULT_ROWS_PER_OP", restoreFaultRows("apply", { ok: false, failures: [] }).length <= RESTORE_FAULT_ROWS_PER_OP);
}

async function testRestoreRingRedaction(): Promise<void> {
  console.log("\napplyRestoreFault is the single redaction chokepoint, and the DO route is live");

  // Out-of-vocabulary op / phase / class are DROPPED: a caller can never inject a key or a value.
  ok("an out-of-vocabulary op is dropped", applyRestoreFault([], { op: RAW_ERROR, phase: "write", cls: "integrity" }, 1).length === 0);
  ok("an out-of-vocabulary phase is dropped", applyRestoreFault([], { op: "apply", phase: CUSTOMER_VALUE, cls: "integrity" }, 1).length === 0);
  ok("an out-of-vocabulary class is dropped", applyRestoreFault([], { op: "apply", phase: "write", cls: SECRET }, 1).length === 0);

  // A hostile row: a raw message, a token and a stack posted ALONGSIDE the closed fields are simply not read.
  const hostile = applyRestoreFault([], { op: "apply", phase: "write", cls: "dest-access", message: RAW_ERROR, stack: RAW_ERROR, token: SECRET, endpoint: "https://acme.r2.cloudflarestorage.com", errId: RAW_ERROR }, 7);
  ok("a hostile row keeps ONLY the closed fields", hostile.length === 1 && Object.keys(hostile[0]!).sort().join(",") === "at,cls,op,phase");
  ok("a non-hex errId is refused (no message can ride in the join-key field)", hostile[0]!.errId === undefined);
  scanClean("a hostile row", hostile);

  // A record name is customer data: a restore row that posts one has it DROPPED at the chokepoint, and only a
  // well-shaped keyed name MAC is kept in its place.
  const named = applyRestoreFault([], { op: "apply", phase: "write", cls: "dest-access", recordName: "user:alice@example.invalid", keyNameHash: "ab".repeat(48), index: 12, errId: "deadbeef" }, 9);
  ok("a restore row's record name is DROPPED by the DO-side applier", named.length === 1 && named[0]!.recordName === undefined);
  ok("a restore row keeps its 96-hex keyed name MAC and its index", named[0]!.keyNameHash === "ab".repeat(48) && named[0]!.index === 12);
  ok("an 8-hex errId IS kept (the only join key to the Workers-Logs line)", named[0]!.errId === "deadbeef");
  ok("a keyed name MAC out of shape is DROPPED", applyRestoreFault([], { op: "apply", phase: "write", cls: "dest-access", keyNameHash: `${"ab".repeat(47)}zz` }, 9)[0]!.keyNameHash === undefined && applyRestoreFault([], { op: "apply", phase: "write", cls: "dest-access", keyNameHash: "user:alice" }, 9)[0]!.keyNameHash === undefined);
  // A drill row keeps its engine-written archive object key, control-stripped and clamped to 128.
  const clamped = applyRestoreFault([], { op: "drill", phase: "open", cls: "object-missing", recordName: `a\u0000b\nc${"x".repeat(500)}` }, 9);
  ok("a drill row's object key is control-stripped and clamped to 128", clamped[0]!.recordName!.length === 128 && !clamped[0]!.recordName!.includes("\n") && !clamped[0]!.recordName!.includes("\u0000"));

  // The ring is bounded: a downpipe failing forever re-bumps it rather than growing storage.
  let ring: RestoreFaultRow[] = [];
  for (let i = 0; i < RESTORE_FAULTS_RING_CAP + 40; i++) ring = applyRestoreFault(ring, { op: "apply", phase: "write", cls: "dest-access" }, i);
  ok("the ring is capped and keeps the NEWEST rows", ring.length === RESTORE_FAULTS_RING_CAP && ring[ring.length - 1]!.at === RESTORE_FAULTS_RING_CAP + 39);

  // THE FAULT PATH, end to end, through the REAL SchedulerDO: the Worker edge posts the projected rows of a
  // failed apply, and the pack read hands them back.
  const { storage, stub } = makeScheduler();
  const outcome = {
    ok: false,
    reason: REASON_INTEGRITY,
    failures: [{ name: "kv/session-index", reason: destAccessReason(`PUT seg/0001: status 403 (AccessDenied) ${RAW_ERROR}`) }],
  };
  const rows = restoreFaultRows("apply", outcome);
  const post = await stubFetch(stub, "POST", "/diag/restore-faults", { rows });
  ok("POST /diag/restore-faults is routed by the DO", post.status === 200);
  const stored = await storage.get<RestoreFaultRow[]>(RESTORE_FAULTS_KEY);
  ok("the rows land under restore:faults", (stored ?? []).length === 2);
  scanClean("the stored ring", stored);
  const read = await (await stubFetch(stub, "GET", "/restore-faults", undefined)).json() as { faults: RestoreFaultRow[] };
  ok("GET /restore-faults reads the ring back for the pack", read.faults.length === 2 && read.faults.every((r) => (RESTORE_FAULT_OPS as readonly string[]).includes(r.op)));
  ok("the integrity abort is recorded in the VERIFY phase (nothing was written)", read.faults.some((r) => r.cls === "integrity" && r.phase === "verify"));
  scanClean("GET /restore-faults", read);

  // THE WRITER: a DROPPED fault write is itself counted (the pack never under-reports in silence).
  resetPendingDroppedWrites();
  const { scheduler: down } = capturingScheduler({ down: true });
  await recordRestoreOutcome(down, "apply", outcome);
  ok("a DROPPED restore-fault write is counted in droppedWrites", pendingDroppedWrites()["restore-fault"] === 1);
  resetPendingDroppedWrites();

  // The Worker edge posts NOTHING at all for a clean restore.
  const { scheduler: healthy, posts } = capturingScheduler();
  await recordRestoreOutcome(healthy, "drill", { ok: true });
  ok("a clean drill costs no subrequest", posts.length === 0);
}

// ---- the crashed apply (the reclaimed reservation lease) ---------------------------------------------

async function testCrashedApplyLease(): Promise<void> {
  console.log("\na RECLAIMED apply lease is durable proof an earlier apply died mid-write");

  const now = Date.now();
  // The record a CRASHED apply leaves behind: reserved ("applying"), stamped with appliedAt, never released
  // (the Worker died) and never consumed. releaseRestore DELETES appliedAt on every clean release and
  // consumeApproval terminates the record, so this state is reachable ONLY through a crash.
  const crashed = {
    planHash: "sha384:abc",
    runId: "01J0",
    status: "applying",
    requesterSubject: "sub-a",
    approverSubject: "sub-b",
    approvedBy: "b@example.com",
    expiresAt: new Date(now + 3_600_000).toISOString(),
    appliedAt: new Date(now - RESTORE_APPLY_LEASE_MS - 60_000).toISOString(),
  } as unknown as RestoreApproval;
  ok("past its lease the crashed reservation reads back as approved (the retry can proceed)", effectiveStatus(crashed, now) === "approved");
  // ...and THAT is the router's detection: a USABLE approval that still carries an appliedAt.
  ok("the reclaim is detectable at the gate (usable + a surviving appliedAt)", crashed.appliedAt !== undefined && effectiveStatus(crashed, now) === "approved");

  const withinLease = { ...crashed, appliedAt: new Date(now - 60_000).toISOString() } as RestoreApproval;
  ok("an apply still WITHIN its lease is not a reclaim (it reads applying and the second apply is refused)", effectiveStatus(withinLease, now) === "applying");

  // The recording, through the real DO: the fault row (with the staleness, in seconds) + the durable counter.
  const { storage, stub } = makeScheduler();
  await stubFetch(stub, "POST", "/diag/restore-faults", { rows: [{ op: "apply", phase: "write", cls: "apply-crashed-lease-reclaimed", count: 1860 }] });
  await stubFetch(stub, "POST", "/diag/admin-counters", { bumps: { "restore-apply-lease-reclaimed": 1 } });
  const ring = (await storage.get<RestoreFaultRow[]>(RESTORE_FAULTS_KEY)) ?? [];
  ok("the reclaim lands in the restore-fault ring with its staleness", ring.length === 1 && ring[0]!.cls === "apply-crashed-lease-reclaimed" && ring[0]!.count === 1860);
  const counters = await (await stubFetch(stub, "GET", "/admin-counters", undefined)).json() as Record<string, { count: number }>;
  ok("the durable RATE is recorded (a retry cannot erase it by overwriting appliedAt)", counters["restore-apply-lease-reclaimed"]?.count === 1);
  scanClean("the reclaim evidence", { ring, counters });
}

// ---- the licence edge cases -------------------------------------------------------------------------

async function testLicenceEdgeCases(): Promise<void> {
  console.log("\nan engine fault is internal-error (never a corrupt token), and a NON-2XX DO read is a source flip");

  const env = { LICENCE_TOKEN: "", CF_ACCOUNT_ID: "acct-1" } as unknown as Env;

  // A DO answering a RESOLVED NON-2XX (a storage incident) is caught rather than bypassing the catch: without
  // this, a console-activated Enterprise licence would silently flip to the deploy token with doReadFellBack UNSET.
  const posts: Array<{ path: string; body: unknown }> = [];
  const nonOk = {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      posts.push({ path, body: init?.body === undefined ? null : JSON.parse(String(init.body)) });
      if (path === "/licence-token") return new Response("internal error", { status: 500 });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  const status = await readLicence(env, nonOk);
  ok("a NON-2XX licence-token read is recorded as a fallback (doReadFellBack)", status.doReadFellBack === true);
  const flip = posts.find((p) => p.path === "/diag/admin-counters");
  ok("the source FLIP is counted durably (an intermittent DO fault leaves a trace)", (flip?.body as { bumps: Record<string, number> } | undefined)?.bumps["licence-source-flip"] === 1);
  scanClean("the licence status", status);

  // THE OTHER HALF: an ENGINE fault must never be reported as a corrupt token. An env whose token read throws
  // stands in for any internal regression inside the licence path (the backstop catch).
  const poisonEnv = new Proxy({} as Record<string, unknown>, {
    get(_t, prop): unknown {
      if (prop === "LICENCE_TOKEN") throw new Error(RAW_ERROR);
      return undefined;
    },
  }) as unknown as Env;
  const { scheduler, posts: p2 } = capturingScheduler();
  const internal = await readLicence(poisonEnv, scheduler);
  ok("an ENGINE fault fails open to community, as always", internal.tier === "community" && internal.valid === false);
  ok("...and is classed internal-error, NEVER body-malformed (support stops chasing token corruption)", internal.reasonCode === "internal-error");
  const bump = p2.find((p) => p.path === "/diag/admin-counters");
  ok("the internal error is counted", (bump?.body as { bumps: Record<string, number> } | undefined)?.bumps["licence-internal-error"] === 1);
  scanClean("the internal-error status", internal);
  ok("every counter name is a closed-vocabulary member", (ADMIN_COUNTER_NAMES as readonly string[]).includes("licence-source-flip"));
}

// ---- the silent exclusions ---------------------------------------------------------------------------

async function testSilentExclusions(): Promise<void> {
  console.log("\na silently excluded row is COUNTED, and a faulted report-data read fails LOUDLY");

  // POINT-IN-TIME: a SUCCESSFUL run whose startedAt is corrupt is dropped from the timeline, so a run that
  // COVERS T reads as "no run exists" -- a data-loss-grade wrong answer produced by a timestamp bug.
  const ring: RunHistoryEntry[] = [
    { runId: "01J1", index: 1, status: "ok", startedAt: "not-a-timestamp", durationMs: 1000 } as unknown as RunHistoryEntry,
    { runId: "01J2", index: 2, status: "ok", startedAt: `${CUSTOMER_VALUE}-corrupt`, durationMs: 1000 } as unknown as RunHistoryEntry,
  ];
  const miss = resolveRunAt("dp-1", ring, Date.parse("2026-07-01T00:00:00.000Z"));
  ok("the resolution still misses (the rows cannot be placed on a timeline)", miss.found === false);
  ok("...but it says HOW MANY successful runs it threw away", miss.excludedCorruptRuns === 2);
  scanClean("the point-in-time result", miss);
  const clean = resolveRunAt("dp-1", [{ runId: "01J3", index: 3, status: "ok", startedAt: "2026-06-01T00:00:00.000Z", durationMs: 5 } as unknown as RunHistoryEntry], Date.parse("2026-07-01T00:00:00.000Z"));
  ok("a clean ring carries NO exclusion field (the healthy case is unchanged)", clean.found === true && clean.excludedCorruptRuns === undefined);

  // COMPLIANCE REPORTS: the report is SIGNED, so a silently dropped row becomes a signed statement that the
  // change was never recorded -- the auditor's worst outcome.
  const events = [
    { action: "change-recorded", ts: "2026-06-15T00:00:00.000Z", actorEmail: "a@example.com", actorMethod: "session", target: { kind: "change", actionKind: "restore-apply", changeNumber: "CHG-1", emergency: false, reason: null } },
    { action: "change-recorded", ts: `${CUSTOMER_VALUE}`, actorEmail: "b@example.com", actorMethod: "session", target: { kind: "change", actionKind: "restore-apply", changeNumber: "CHG-2", emergency: false, reason: null } },
    { action: "change-recorded", ts: "2026-06-16T00:00:00.000Z", actorEmail: "c@example.com", actorMethod: "session", target: { kind: "downpipe", id: SECRET } },
  ] as unknown as AuditEvent[];
  const report = buildChangeRequestsReport(events, { fromSeconds: Math.floor(Date.parse("2026-06-01T00:00:00.000Z") / 1000), toSeconds: Math.floor(Date.parse("2026-06-30T00:00:00.000Z") / 1000) });
  ok("the well-formed change is reported", report.total === 1 && report.entries[0]!.changeNumber === "CHG-1");
  ok("the corrupt-timestamp row is COUNTED, not silently dropped", report.excludedUnparseableTs === 1);
  ok("the shape-drifted row is COUNTED", report.excludedShape === 1);
  scanClean("the change-requests report body", report);
  const cleanReport = buildChangeRequestsReport([events[0]!], null);
  ok("a clean report carries NO exclusion fields (byte-identical to before)", cleanReport.excludedUnparseableTs === undefined && cleanReport.excludedShape === undefined);

  // A faulted DO read must never be cast into the report's data shape and then SIGNED.
  const { scheduler, posts } = capturingScheduler({ down: true });
  const caller = { email: "owner@example.com", role: "owner" } as unknown as Caller;
  let threw = false;
  try {
    await buildReportBody({} as unknown as Env, scheduler, caller, "restore-tests", null, Date.now());
  } catch {
    threw = true;
  }
  ok("a faulted report-data read FAILS LOUDLY instead of being signed over an error body", threw);
  const counted = posts.find((p) => p.path === "/diag/admin-counters");
  ok("...and the faulted read is counted durably", (counted?.body as { bumps: Record<string, number> } | undefined)?.bumps["report-data-read-unavailable"] === 1);

  // The counter applier is the redaction chokepoint for this aggregate.
  ok("an out-of-vocabulary counter name is dropped", Object.keys(applyAdminCounters(undefined, { [CUSTOMER_VALUE]: 5 }, "2026-07-11T00:00:00.000Z")).length === 0);
  const capped = applyAdminCounters(undefined, { "pit-corrupt-run-excluded": 1e12 }, "2026-07-11T00:00:00.000Z");
  ok("a hostile count is clamped", capped["pit-corrupt-run-excluded"]!.count <= 100_000);
  scanClean("the admin counters", capped);

  // The writer records its own dropped write.
  resetPendingDroppedWrites();
  const { scheduler: down } = capturingScheduler({ down: true });
  await bumpAdminCounter(down, "pit-corrupt-run-excluded");
  ok("a DROPPED counter write is itself counted in droppedWrites", pendingDroppedWrites()["admin-counter"] === 1);
  resetPendingDroppedWrites();

  // The DO storage key + read route are live.
  const { storage, stub } = makeScheduler();
  await stubFetch(stub, "POST", "/diag/admin-counters", { bumps: { "report-row-excluded-shape": 3 } });
  ok("the counters land under diag:admincounters", ((await storage.get(ADMIN_COUNTERS_KEY)) as Record<string, { count: number }>)["report-row-excluded-shape"]?.count === 3);
}

// ---- a failed record's NAME never reaches any form of the pack ------------------------------------------
//
// A record's name, such as a KV key or an object key, is customer data. This drives a REAL restore apply: a KV
// run is sealed with a sentinel key name, the target namespace refuses the write of that one key, the router's
// own projection posts the outcome to the REAL SchedulerDO, and the pack is built in every form it leaves the
// engine in. The sentinel must be absent from all of them, and the record must still be identifiable: its
// index and the archive's keyed name MAC ride instead, and the MAC recomputes from the run key.

const NAME_SENTINEL = "user:sntl-u1-7c41@example.invalid";
const NAME_SENTINEL_CORE = "sntl-u1-7c41";

// A KV namespace double that refuses the write of ONE key, with a provider message that quotes the key.
class RefusingKV {
  store = new Map<string, Uint8Array>();
  readonly refuse: string;
  constructor(refuse: string) {
    this.refuse = refuse;
  }
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    if (k === this.refuse) throw new Error(`KV PUT ${k}: status 403 (AccessDenied)`);
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? (v.slice().buffer as ArrayBuffer) : null;
  }
}

// The archive destination double: the R2 binding surface the engine's R2 destination reads.
class ArchiveR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => v.slice().buffer as ArrayBuffer, etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> {
    return this.store.has(key) ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}

async function testRecordNameNeverRidesThePack(): Promise<void> {
  console.log("\na failed record's NAME never rides the pack; its index and keyed name MAC do");

  const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
  const recipient = (role: string): { entry: RecipientEntry; identity: Uint8Array } => {
    const xk = x25519.keygen();
    const seed = rand(64);
    return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
  };
  const RUN = "01ARZ3NDEKTSV4RRFFQ69G5V1A";
  const NS = "ns_u1";
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(signerB64);
  const breakGlass = recipient("break-glass");
  const operational = recipient("operational");
  const master = rand(32);
  const records = [
    { name: "alpha", value: "alpha-value" },
    { name: NAME_SENTINEL, value: "sentinel-value" },
    { name: "omega", value: "omega-value" },
  ];
  const archive = await buildArchive({
    downpipeId: "dp_u1",
    downpipeName: "u1",
    cadence: "3600s",
    runId: RUN,
    master,
    recipients: [breakGlass.entry, operational.entry],
    signer,
    records: records.map((r) => ({ sourceType: "kv", name: r.name, value: utf8(r.value), namespace: NS })),
    windowStart: "2026-09-28T00:00:00.000Z",
    windowEnd: "2026-09-28T00:00:01.000Z",
    createdAt: "2026-09-28T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const r2 = new ArchiveR2();
  for (const [k, b] of archive) r2.store.set(k, b);
  const kv = new RefusingKV(NAME_SENTINEL);
  const vendor = await makeSupportRecipient();
  const env = {
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerB64,
    OPERATIONAL_PRIVATE: b64urlEncode(operational.identity),
    [`KV_${NS}`]: kv as unknown as KVNamespace,
  } as unknown as Env;

  // The apply: two keys land, the sentinel key's write is refused.
  const applied = (await runRestore(env, { runId: RUN, confirm: true })) as RestoreResult;
  ok("the apply wrote the other two keys and failed exactly the sentinel key", applied.recordsRestored === 2 && applied.failures.length === 1 && applied.failures[0]?.name === NAME_SENTINEL);

  // The router's own step: project the outcome into the REAL DO ring.
  // The real SchedulerDO takes a Request; the engine's stubs call fetch(url, init), so adapt the call shape only.
  const sched = makeScheduler();
  const real = sched.stub as unknown as { fetch(req: Request): Promise<Response> };
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => real.fetch(input instanceof Request ? input : new Request(String(input), init)) } as unknown as DurableObjectStub;
  // A ring an earlier engine wrote still holds a record name on a restore row. The pack must drop it too.
  await sched.storage.put(RESTORE_FAULTS_KEY, [{ at: 1, op: "dry-run", phase: "plan", cls: "binding-missing", recordName: `legacy/${NAME_SENTINEL}` }]);
  await recordRestoreOutcome(stub, "apply", applied);

  // Every form the pack leaves the engine in.
  const body = await buildSupportBundle({ ...env } as Env, stub);
  const signedPlain = await sealedSupportBundle({ ...env } as Env, stub);
  const sealed = await sealedSupportBundle({ ...env, VENDOR_SUPPORT_PUBLIC: b64urlEncode(vendor.recipientPublic) } as Env, stub);
  const opened = await openSupportBundle(sealed, parseIdentity(vendor.identity), verifierFrom(signer));
  const unsealedBody = (opened.inner as { bundle?: unknown }).bundle;
  const forms: Array<[string, unknown]> = [
    ["the pack body", body],
    ["the signed pack", signedPlain],
    ["the signed pack's band manifest", (signedPlain as { manifest?: unknown }).manifest],
    ["the sealed envelope", sealed],
    ["the sealed envelope's band manifest", (sealed as { manifest?: unknown }).manifest],
    ["the opened signed inner", opened.inner],
    ["the unsealed body", unsealedBody],
  ];
  ok("the signed pack and the sealed envelope both carry a band manifest", (signedPlain as { manifest?: unknown }).manifest !== undefined && (sealed as { manifest?: unknown }).manifest !== undefined);
  ok("the sealed envelope opens and its body is the signed pack", opened.form === "sealed" && opened.signature === "verified" && typeof unsealedBody === "object" && unsealedBody !== null);
  for (const [label, form] of forms) {
    const json = JSON.stringify(form ?? null);
    ok(`${label}: the failed record's name is absent`, !json.includes(NAME_SENTINEL_CORE));
  }

  // The record is still identifiable: its index and its keyed name MAC, recomputed from the run key.
  const faults = ((unsealedBody as { restoreFaults?: unknown }).restoreFaults ?? []) as Array<Record<string, unknown>>;
  const row = faults.find((f) => f.op === "apply" && f.cls === "dest-access");
  ok("the unsealed body carries the apply's dest-access row", row !== undefined && row.phase === "write");
  ok("the earlier engine's row still rides, without its record name", faults.some((f) => f.op === "dry-run" && f.cls === "binding-missing" && !("recordName" in f)));
  const runIdBytes = decodeULID(RUN);
  const nameKey = await deriveNameMACKey(await deriveMK(master, runIdBytes), runIdBytes);
  const expected = hexEncode(await nameMAC(nameKey, "kv", NAME_SENTINEL));
  ok("the row carries the keyed name MAC of the failed record", typeof row?.keyNameHash === "string" && row.keyNameHash === expected);
  const others = await Promise.all(["alpha", "omega"].map(async (n) => hexEncode(await nameMAC(nameKey, "kv", n))));
  ok("the MAC names that record and no other", !others.includes(String(row?.keyNameHash)));
  const sentinelIndex = records.findIndex((r) => r.name === NAME_SENTINEL);
  ok("the row carries the failed record's index in the run", row?.index === sentinelIndex);
  ok("the row carries no record name", row !== undefined && !("recordName" in row));
}

async function main(): Promise<void> {
  console.log("Support-pack fault evidence: engine-admin restore / licence / reports");
  testRestoreClassifier();
  testRestoreProjection();
  await testRestoreRingRedaction();
  await testCrashedApplyLease();
  await testLicenceEdgeCases();
  await testSilentExclusions();
  await testRecordNameNeverRidesThePack();
  console.log(failures === 0 ? "\nAll restore/licence/report fault-evidence checks passed." : `\n${failures} check(s) FAILED.`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
