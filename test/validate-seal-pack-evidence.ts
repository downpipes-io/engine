// Prove the SUPPORT-PACK evidence the seal subsystem records on its fault paths, and prove that evidence
// is REDACTION-SAFE (NO-CUSTODY: a closed enum, a count, a clamped int, a boolean or a coarse class -- never a
// raw message, a key, an object name or a customer value). No network, no deploy, no DO. Run:
//   node test/validate-seal-pack-evidence.ts
//
// The three cases this covers:
//   Retention/prune outcomes: without this, a perpetual deferral would sit behind an unchanging free-text
//         sentence, a broken superseded run would be silently skipped every pass, a corrupt RUNLOG timestamp
//         would change eligibility with no trace, and a half-applied prune's progress counts would die with
//         the exception.
//         -> prune.ts classes the abstain (PRUNE_DEFER_CLASSES), names the blocking run, counts the skipped
//            and unparseable-time entries, and carries a half-applied prune's progress on PruneApplyError; the
//            pass posts them into the bounded seal-fault ring (POST /seal-fault) as three CLOSED
//            kinds via pruneObservations/postPruneObservations.
//   Reconcile pack signal: without splitting, the signal would fold distinctions the DO inventory already
//         makes.
//         -> ReconcileSignal splits undetermined into within-grace / unreadable / pending-classify, splits
//            neverReferenced into sig-invalid (tamper) vs attest-incomplete (crashed finalise), and carries the
//            orphan fraction's numerator/denominator on a circuit-breaker abstain. sanitiseReconcileSignal is
//            the one redaction chokepoint for all of it.
//   Self-identity: a downpipe whose legacy config lacks its source's NATIVE id can never be roster-rebuilt, and
//         nothing says so without this. -> adapters.selfIdentityClass / selfIdentityDegraded classify it from
//         the stored config.
//
// PART A  prune: the abstain class, the blocking run id, the skipped + unparseable-time counts.
// PART B  prune: the half-applied apply (progress counts + the WORM class) and the observe projection.
// PART C  prune: REDACTION -- a hostile enumerator/destination error message and a hostile deferClass can never
//         reach a recorded seal-fault (sanitiseSealFault is the chokepoint the DO ring runs).
// PART D  reconcile: the split counts + the circuit-breaker fraction.
// PART E  reconcile: REDACTION -- sanitiseReconcileSignal drops free text, clamps hostile counts, gates enums.
// PART F  self-identity: the closed class per source type, and the degraded boolean.

import type { RunlogEntry, Signer } from "../src/format/writer.ts";
import type { Destination } from "../src/dest/types.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { SourceSpec } from "../src/sched/types.ts";
import {
  planPrune,
  applyPrune,
  pruneObservations,
  PruneApplyError,
  type SegEnumerator,
  type RunTreeLister,
} from "../src/seal/prune.ts";
import { sanitiseSealFault, SEAL_FAULT_KINDS, PRUNE_DEFER_CLASSES } from "../src/seal/seal-faults.ts";
import {
  planReconcileInventory,
  reconcileSignalFor,
  sanitiseReconcileSignal,
  type OrphanProbeResult,
} from "../src/seal/reconcile.ts";
import { selfIdentityClass, selfIdentityDegraded, SELF_IDENTITY_CLASSES } from "../src/seal/adapters.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const NOW = 1_700_000_000_000;
const DP = "dp_ret";
const RUNS = ["01ARZ3NDEKTSV4RRFFQ69G5FA0", "01ARZ3NDEKTSV4RRFFQ69G5FA1", "01ARZ3NDEKTSV4RRFFQ69G5FA2", "01ARZ3NDEKTSV4RRFFQ69G5FA3"];

// The two customer-owned values that must NEVER be recorded: they are planted INSIDE the errors the fault paths
// throw (exactly where a raw message would be sealed if the recording site did not coarsen).
const SECRET = "sk-live-CUSTOMER-TOKEN-abc123";
const CUSTOMER_KEY = "run/01ARZ3NDEKTSV4RRFFQ69G5FA0/manifest.json";

function entry(index: number, runId: string, time: string, prevRunId: string | null, status = "active"): RunlogEntry {
  return { index, runId, downpipeId: DP, time, recordCount: 1, prevRunId, status };
}

const listTree: RunTreeLister = async (runId: string) => [`run/${runId}/root.json`];

// ---- PART A: the prune abstain class, blocking run and counts -----------------------------------
async function partA(): Promise<void> {
  console.log("PART A: prune deferral class + blocking run + skipped / unparseable-time counts:");
  // Four runs, keepRuns:2 -> runs 1,2 superseded; runs 3,4 retained. Run 4's RUNLOG time is CORRUPT (it does not
  // parse), which would otherwise silently change keepDays eligibility with no trace.
  const entries: RunlogEntry[] = [
    entry(1, RUNS[0]!, "2026-06-01T00:00:00.000Z", null),
    entry(2, RUNS[1]!, "2026-06-02T00:00:00.000Z", RUNS[0]!),
    entry(3, RUNS[2]!, "2026-06-03T00:00:00.000Z", RUNS[1]!),
    entry(4, RUNS[3]!, "not-a-timestamp", RUNS[2]!),
  ];

  // (1) A RETAINED run that will not open: the pass ABSTAINS, and says WHY, WHICH run blocked it, and how many
  // retained runs were unreadable. The thrown message carries a secret + an object key: neither may survive
  // into the plan's recorded evidence.
  const retainedFails: SegEnumerator = async (runId: string) => {
    if (runId === RUNS[2]!) throw new Error(`GET ${CUSTOMER_KEY} failed for token ${SECRET}`);
    return [`seg/aa/${runId}.seg`];
  };
  const deferredPlan = await planPrune(entries, DP, { keepRuns: 2 }, new Date(NOW), retainedFails, listTree);
  ok("the abstain still defers (no supersede, no delete)", deferredPlan.supersededRunIds.length === 0 && deferredPlan.orphanSegs.length === 0 && deferredPlan.runTreeObjects.length === 0);
  ok("deferredClass is the CLOSED retained-run-unreadable class", deferredPlan.deferredClass === "retained-run-unreadable");
  ok("deferredClass is a member of the closed vocabulary", (PRUNE_DEFER_CLASSES as readonly string[]).includes(deferredPlan.deferredClass ?? ""));
  ok("blockingRunId names the run that defers every pass", deferredPlan.blockingRunId === RUNS[2]!);
  ok("retainedUnreadableCount counts the unreadable retained runs", deferredPlan.retainedUnreadableCount === 1);
  ok("unparseableTimeCount counts the corrupt RUNLOG timestamp", deferredPlan.unparseableTimeCount === 1);

  // (2) A SUPERSEDED run that will not open is silently skipped (the pass proceeds). It is counted.
  const supersededFails: SegEnumerator = async (runId: string) => {
    if (runId === RUNS[0]!) throw new Error(`GET ${CUSTOMER_KEY}: 500 ${SECRET}`);
    return [`seg/aa/${runId}.seg`];
  };
  const skipPlan = await planPrune(entries, DP, { keepRuns: 2 }, new Date(NOW), supersededFails, listTree);
  ok("a skipped superseded run does NOT abstain the pass", skipPlan.deferredClass === undefined && skipPlan.supersededRunIds.length === 1);
  ok("supersededSkippedCount records the silently-excluded run", skipPlan.supersededSkippedCount === 1);
  ok("a clean plan reports zero unreadable retained runs", skipPlan.retainedUnreadableCount === 0);

  // (3) The observe projection: the abstain yields exactly one prune-deferred row, from the CLOSED kind set.
  const rows = pruneObservations(deferredPlan, NOW);
  ok("an abstain emits ONE observation", rows.length === 1);
  ok("its kind is the closed prune-deferred kind", rows[0]!.kind === "prune-deferred" && (SEAL_FAULT_KINDS as readonly string[]).includes(rows[0]!.kind));
  ok("it carries the class, the blocking run and the counts", rows[0]!.deferClass === "retained-run-unreadable" && rows[0]!.runId === RUNS[2]! && rows[0]!.unparseableTime === 1);
  const skipRows = pruneObservations(skipPlan, NOW);
  ok("a skipped-run pass emits ONE prune-runs-skipped observation", skipRows.length === 1 && skipRows[0]!.kind === "prune-runs-skipped" && skipRows[0]!.skipped === 1);

  // (4) A wholly clean pass posts NOTHING (the ring stays a FAULT ring; a healthy fleet is silent).
  const cleanSegs: SegEnumerator = async (runId: string) => [`seg/aa/${runId}.seg`];
  const cleanEntries = entries.slice(0, 3);
  const cleanPlan = await planPrune(cleanEntries, DP, { keepRuns: 2 }, new Date(NOW), cleanSegs, listTree);
  ok("a clean prune emits NO observation", pruneObservations(cleanPlan, NOW).length === 0);
}

// ---- PART B: the half-applied apply (progress + the WORM class) ---------------------------------
// Driven through the REAL S3 destination over a scripted fetch, so the delete refusal has exactly the shape
// production produces: `del` throws DestStatusError("DELETE <key>: status 403") and the S3 <Code> goes to the
// fault ring, never into the message. The earlier version of this part threw a hand-written message
// ("status 403 AccessDenied (object-lock retention)") that no production path emits, and the classifier it
// "proved" read the lock from those words. On real AWS the words are never there, so it never fired.
// The lock is now decided by READING the refused object's own Object Lock headers (a HEAD).
// supersededRunIds is empty, so supersedeRunlog is a no-op (it returns 0 without touching the RUNLOG) and the
// test isolates the delete loop.
const S3_ENDPOINT = "https://s3.example.com";
const S3_BUCKET = "archive-bucket";

// scriptedS3 builds an S3Destination whose fetch answers each request from the script. installS3 returns a
// restore() that puts the real fetch back.
function installS3(script: (method: string, key: string) => Response): { dest: Destination; restore: () => void; seen: string[] } {
  const real = globalThis.fetch;
  const seen: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
    const method = (init?.method ?? "GET").toUpperCase();
    const key = decodeURIComponent(url.pathname.slice(`/${S3_BUCKET}/`.length));
    seen.push(`${method} ${key}${url.search}`);
    return script(method, url.search === "?object-lock=" ? "?object-lock" : key);
  }) as typeof fetch;
  const dest = new S3Destination(S3_ENDPOINT, S3_BUCKET, "us-east-1", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", { now: () => new Date(NOW) });
  return { dest, restore: () => { globalThis.fetch = real; }, seen };
}

const ACCESS_DENIED = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied ${SECRET}</Message></Error>`;

async function partB(): Promise<void> {
  console.log("\nPART B: half-applied prune -- progress counts + the WORM class survive the throw (real S3 del shape):");
  const segA = `seg/aa/${RUNS[0]!}.seg`;
  const segB = `seg/bb/${RUNS[1]!}.seg`;
  const sig = `run/${RUNS[0]!}/root.manifest.json.sig`;
  const root = `run/${RUNS[0]!}/root.manifest.json`;
  const plan = {
    downpipeId: DP,
    retainedRunIds: [RUNS[2]!],
    supersededRunIds: [] as string[],
    runTreeObjects: [sig, root],
    orphanSegs: [segA, segB],
    runTrees: [{ runId: RUNS[0]!, objects: [sig, root], segs: [segA, segB] }],
    reclaimableBytes: 0,
    retainedUnreadableCount: 0,
    supersededSkippedCount: 0,
    unparseableTimeCount: 0,
  } as const;
  const signer = {} as unknown as Signer;
  const future = new Date(NOW + 30 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");

  // A delete refused with a bare 403 AccessDenied, as Amazon S3 answers it, on an object whose own Object
  // Lock headers show a retention that runs into the future: a genuine lock, read, not guessed.
  const worm = installS3((method, key) => {
    if (method === "DELETE" && key === segB) return new Response(ACCESS_DENIED, { status: 403 });
    if (method === "DELETE") return new Response(null, { status: 204 });
    if (method === "HEAD" && key === segB) return new Response(null, { status: 200, headers: { "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": future } });
    return new Response(null, { status: 404 });
  });
  let err: unknown;
  try {
    await applyPrune(worm.dest, signer, plan, undefined);
  } catch (e) {
    err = e;
  } finally {
    worm.restore();
  }
  ok("the apply THROWS a PruneApplyError (a partial apply is never reported clean)", err instanceof PruneApplyError);
  const w = err as PruneApplyError;
  ok("the loop kept going past the refusal: segment A was removed", w.progress.orphansDeleted === 1);
  ok("the refusal is counted as READ-locked (the HEAD showed a future retain-until)", w.progress.refusedLocked === 1 && w.progress.refusedDenied === 0 && w.progress.refusedUnknown === 0);
  ok("the run tree is HELD, because one of its segments did not go (the tree is how a later pass finds it)", w.progress.runTreeDeleted === 0 && w.progress.held === 2);
  ok("the HEAD that decided it was actually sent for the refused key", worm.seen.includes(`HEAD ${segB}`));
  ok("wormBlocked classifies the refusal as irreducible", w.wormBlocked === true);
  ok("the original error is preserved as `cause` for the engine's own log", (w.cause as Error)?.message.includes("403"));
  ok("the cause message is the production shape and carries no body text", !(w.cause as Error).message.includes(SECRET) && !(w.cause as Error).message.includes("AccessDenied"));

  // The SAME bare 403, but the object's own headers show NO lock and the bucket has no Object Lock: a plain
  // permission denial, the fixable case. Before, a bare 403 was read as access-denied only because the words
  // lacked lock vocabulary; now it is read from the object and the bucket.
  const denied = installS3((method, key) => {
    if (method === "DELETE" && key === segB) return new Response(ACCESS_DENIED, { status: 403 });
    if (method === "DELETE") return new Response(null, { status: 204 });
    if (method === "HEAD") return new Response(null, { status: 200 });
    if (key === "?object-lock") return new Response(`<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`, { status: 404 });
    return new Response(null, { status: 404 });
  });
  let err2: unknown;
  try {
    await applyPrune(denied.dest, signer, plan, undefined);
  } catch (e) {
    err2 = e;
  } finally {
    denied.restore();
  }
  const d = err2 as PruneApplyError;
  ok("no lock on the object and none on the bucket: the refusal is access-denied, not WORM", err2 instanceof PruneApplyError && d.progress.refusedDenied === 1 && d.wormBlocked === false);

  // A HEAD that is ITSELF refused cannot say whether a lock holds: could-not-tell, never a lock.
  const blind = installS3((method, key) => {
    if (method === "DELETE" && key === segB) return new Response(ACCESS_DENIED, { status: 403 });
    if (method === "DELETE") return new Response(null, { status: 204 });
    if (method === "HEAD") return new Response(null, { status: 403 });
    return new Response(null, { status: 404 });
  });
  let err3: unknown;
  try {
    await applyPrune(blind.dest, signer, plan, undefined);
  } catch (e) {
    err3 = e;
  } finally {
    blind.restore();
  }
  const b = err3 as PruneApplyError;
  ok("a refused HEAD is could-not-tell, never counted as a lock", err3 instanceof PruneApplyError && b.progress.refusedUnknown === 1 && b.wormBlocked === false);

  // A transient 500 is NOT a WORM refusal (it retries and drains), and it stops the loop.
  const flaky = installS3(() => new Response(`<Error><Code>InternalError</Code></Error>`, { status: 500 }));
  let err4: unknown;
  try {
    await applyPrune(flaky.dest, signer, plan, undefined);
  } catch (e) {
    err4 = e;
  } finally {
    flaky.restore();
  }
  const f = err4 as PruneApplyError;
  ok("a transient 500 is NOT classed WORM-blocked", err4 instanceof PruneApplyError && f.wormBlocked === false);
  ok("a transient 500 stops the loop: one failed, the rest held for the next pass", f.progress.failed === 1 && f.progress.held === 3);

  const rows = pruneObservations({ ...plan, deferred: undefined } as never, NOW, w);
  ok("a half-applied prune emits ONE prune-partial-apply observation", rows.length === 1 && rows[0]!.kind === "prune-partial-apply");
  ok("it carries partial + the removed count + the refused count + the WORM flag", rows[0]!.partial === true && rows[0]!.reclaimed === 1 && rows[0]!.refused === 1 && rows[0]!.wormBlocked === true);
  ok("it carries the refusal class it READ", rows[0]!.wormRefusalClass === "worm-locked");
}

// ---- PART C: REDACTION -- nothing raw can reach the recorded record ------------------------------
async function partC(): Promise<void> {
  console.log("\nPART C: REDACTION -- the recorded seal-fault carries no message, key or secret:");
  const entries: RunlogEntry[] = [
    entry(1, RUNS[0]!, "2026-06-01T00:00:00.000Z", null),
    entry(2, RUNS[1]!, "2026-06-02T00:00:00.000Z", RUNS[0]!),
    entry(3, RUNS[2]!, "2026-06-03T00:00:00.000Z", RUNS[1]!),
  ];
  const retainedFails: SegEnumerator = async (runId: string) => {
    if (runId === RUNS[2]!) throw new Error(`GET https://acct.r2.cloudflarestorage.com/bucket/${CUSTOMER_KEY} 403 token=${SECRET}`);
    return [`seg/aa/${runId}.seg`];
  };
  const plan = await planPrune(entries, DP, { keepRuns: 1 }, new Date(NOW), retainedFails, listTree);

  // The DO ring's own sanitiser is the chokepoint: run every observation through it exactly as POST /seal-fault
  // does, then assert the persisted bytes carry no raw text.
  const recorded = pruneObservations(plan, NOW).map((f) => sanitiseSealFault(f as unknown as Record<string, unknown>, NOW));
  const bytes = JSON.stringify(recorded);
  ok("the recorded record contains NO secret", !bytes.includes(SECRET) && !bytes.includes("sk-live"));
  ok("the recorded record contains NO object key / URL / endpoint", !bytes.includes("cloudflarestorage") && !bytes.includes("manifest.json") && !bytes.includes("bucket"));
  ok("the recorded record contains NO raw error text", !bytes.includes("403") && !bytes.includes("GET "));
  ok("the plan's free-text `deferred` sentence is NOT recorded", !bytes.includes("deferring the prune"));
  ok("only the closed class rides", bytes.includes('"deferClass":"retained-run-unreadable"'));

  // Defence in depth: a hostile / drifted internal value (a raw sentence smuggled into deferClass, a NaN count, a
  // negative count, an unknown kind) is coarsened or dropped at the sanitiser -- it can never be persisted.
  const hostile = sanitiseSealFault({ kind: "prune-deferred", at: NOW, downpipeId: DP, deferClass: `a retained run could not be read: ${SECRET}`, skipped: Number.NaN, unparseableTime: -5, superseded: 1e18 }, NOW);
  ok("a free-text deferClass is coarsened to `other` (never carried)", hostile?.deferClass === "other");
  ok("a NaN count clamps to 0", hostile?.skipped === 0);
  ok("a negative count clamps to 0", hostile?.unparseableTime === 0);
  ok("an absurd count clamps to the ceiling", hostile?.superseded === 1_000_000_000);
  ok("an out-of-vocabulary kind is DROPPED entirely", sanitiseSealFault({ kind: "prune-exfiltrate", at: NOW }, NOW) === null);
  ok("no hostile value survives into the record", !JSON.stringify(hostile).includes(SECRET));
}

// ---- PART D: reconcile split counts + the circuit-breaker fraction --------------------------------
function probeOf(verdicts: Record<string, OrphanProbeResult>): (runId: string) => Promise<OrphanProbeResult> {
  return async (runId: string) => {
    const v = verdicts[runId];
    if (!v) throw new Error(`transient read failure ${SECRET}`);
    return v;
  };
}

// A root old enough to be past the grace window (so the classifier reaches the sig/complete arms).
const OLD_ROOT = { downpipeId: DP, createdAt: "2020-01-01T00:00:00.000Z", freshness: { runlogIndex: 1, prevRunId: null } } as OrphanProbeResult["root"];

async function partD(): Promise<void> {
  console.log("\nPART D: reconcile carries the distinctions the inventory already makes:");
  // Four orphan trees past grace: one TAMPERED (signature invalid), one CRASHED FINALISE (signed but incomplete),
  // one salvageable, and one whose probe THROWS (unreadable). The aggregate `broken` count folds the first two
  // into one number.
  // The bucket also physically holds its ONE committed run, so the orphan fraction (4/5) stays under the
  // circuit-breaker threshold and the classifier actually runs (a 100% orphan bucket abstains by design).
  const orphanIds = ["01ARZ3NDEKTSV4RRFFQ69G5FB0", "01ARZ3NDEKTSV4RRFFQ69G5FB1", "01ARZ3NDEKTSV4RRFFQ69G5FB2", "01ARZ3NDEKTSV4RRFFQ69G5FB3"];
  const physicalRunIds = [...orphanIds, "01ARZ3NDEKTSV4RRFFQ69G5FB9"];
  const verdicts: Record<string, OrphanProbeResult> = {
    "01ARZ3NDEKTSV4RRFFQ69G5FB0": { attestation: { signatureValid: false, complete: true, downpipeId: DP }, root: null },
    "01ARZ3NDEKTSV4RRFFQ69G5FB1": { attestation: { signatureValid: true, complete: false, downpipeId: DP }, root: OLD_ROOT },
    "01ARZ3NDEKTSV4RRFFQ69G5FB2": { attestation: { signatureValid: true, complete: true, downpipeId: DP }, root: OLD_ROOT },
  };
  const inv = await planReconcileInventory({
    destKey: "dest-a",
    committedRunIds: new Set(["01ARZ3NDEKTSV4RRFFQ69G5FB9"]),
    committedMaxIndex: new Map(),
    physicalRunIds,
    now: NOW,
    probe: probeOf(verdicts),
    policy: { maxOrphanFraction: 0.99 },
  });
  ok("broken still totals 2 (unchanged)", inv.byClass.broken === 2);
  ok("brokenSigInvalid isolates the TAMPER case", inv.brokenSigInvalid === 1);
  ok("brokenAttestIncomplete isolates the CRASHED FINALISE case", inv.brokenAttestIncomplete === 1);

  const signal = reconcileSignalFor("dest-a", NOW, true, true, inv);
  ok("the signal splits neverReferenced into sig-invalid vs attest-incomplete", signal.neverReferencedSigInvalid === 1 && signal.neverReferencedAttestIncomplete === 1 && signal.neverReferenced === 2);
  ok("the signal splits undetermined into its causes", signal.undeterminedUnreadable === 1 && signal.undeterminedPendingClassify === 0 && signal.undeterminedWithinGrace === 0 && signal.undetermined === 1);
  ok("no orphan run id rides in the signal", !JSON.stringify(signal).includes("01ARZ3NDEKTSV4RRFFQ69G5FB0"));

  // The circuit-breaker abstain carries the fraction that tripped it (numerator/denominator, not a string).
  const breaker = await planReconcileInventory({
    destKey: "dest-b",
    committedRunIds: new Set<string>(),
    committedMaxIndex: new Map(),
    physicalRunIds,
    now: NOW,
    probe: probeOf({}),
  });
  const bs = reconcileSignalFor("dest-b", NOW, true, true, breaker);
  ok("the circuit-breaker abstain is carried", bs.deferred === "circuit-breaker" && bs.circuitBreakerTripped === true);
  ok("the orphan fraction rides as numerator/denominator counts", bs.orphanFractionNumerator === 5 && bs.orphanFractionDenominator === 5);
}

// ---- PART E: reconcile REDACTION ------------------------------------------------------------------
function partE(): void {
  console.log("\nPART E: REDACTION -- sanitiseReconcileSignal is the chokepoint:");
  const dirty = sanitiseReconcileSignal(
    {
      destKey: "d".repeat(300),
      at: Number.NaN,
      runlogPresent: "yes",
      runlogSigVerified: 1,
      runlogHealth: `corrupt: ${SECRET}`,
      committed: -3,
      orphanedRecoverable: Number.POSITIVE_INFINITY,
      neverReferenced: 1e18,
      undetermined: 2.7,
      undeterminedUnreadable: -1,
      neverReferencedSigInvalid: 1,
      deferred: `circuit-breaker: ${CUSTOMER_KEY}`,
      rawError: `DELETE ${CUSTOMER_KEY} 403 ${SECRET}`,
      orphanIds: [RUNS[0]!],
    },
    NOW,
  );
  const bytes = JSON.stringify(dirty);
  ok("an unknown free-text field is DROPPED (never copied through)", !bytes.includes("rawError") && !bytes.includes(SECRET));
  ok("an orphan run-id list is DROPPED", !bytes.includes(RUNS[0]!) && !bytes.includes("orphanIds"));
  ok("destKey is length-bounded", dirty.destKey.length === 128);
  ok("a NaN timestamp falls back to the DO clock", dirty.at === NOW);
  ok("a non-boolean flag is strict-false", dirty.runlogPresent === false && dirty.runlogSigVerified === false);
  ok("an out-of-vocabulary runlogHealth falls back to the closed class the flags imply", dirty.runlogHealth === "absent");
  ok("a negative count clamps to 0", dirty.committed === 0 && dirty.undeterminedUnreadable === 0);
  ok("a non-finite count clamps to 0", dirty.orphanedRecoverable === 0);
  ok("an absurd count clamps to the ceiling", dirty.neverReferenced === 1_000_000_000);
  ok("a fractional count floors to an int", dirty.undetermined === 2);
  ok("a free-text deferred value is DROPPED (only the closed abstain classes survive)", dirty.deferred === undefined);
  const clean = sanitiseReconcileSignal({ destKey: "", at: NOW, runlogPresent: true, runlogSigVerified: true, runlogHealth: "ok", committed: 5, deferred: "circuit-breaker", circuitBreakerTripped: true, orphanFractionNumerator: 8, orphanFractionDenominator: 9 }, NOW);
  ok("a well-formed signal round-trips (closed abstain class + fraction counts)", clean.deferred === "circuit-breaker" && clean.orphanFractionNumerator === 8 && clean.orphanFractionDenominator === 9 && clean.committed === 5);
}

// ---- PART F: archive self-identity ----------------------------------------------------------------
function spec(s: Partial<SourceSpec> & { type: SourceSpec["type"] }): SourceSpec {
  return { include: [], exclude: [], ...s } as SourceSpec;
}

function partF(): void {
  console.log("\nPART F: degraded archive self-identity is a CLOSED class per downpipe:");
  ok("a legacy kv config (no namespaceId) is native-id-absent", selfIdentityClass(spec({ type: "kv", binding: "KV_uploads" })) === "native-id-absent");
  ok("a kv config WITH its namespaceId is ok", selfIdentityClass(spec({ type: "kv", binding: "KV_uploads", namespaceId: "abc123" })) === "ok");
  ok("a legacy r2 config (no bucketName) is native-id-absent", selfIdentityClass(spec({ type: "r2", binding: "R2_media" })) === "native-id-absent");
  ok("a legacy d1 config (no databaseId) is native-id-absent", selfIdentityClass(spec({ type: "d1", binding: "D1_app" })) === "native-id-absent");
  ok("a d1 config WITH its databaseId is ok", selfIdentityClass(spec({ type: "d1", binding: "D1_app", databaseId: "uuid" })) === "ok");
  ok("a secrets config with a secret missing its storeId is secrets-store-absent", selfIdentityClass(spec({ type: "secrets", secrets: [{ name: "A", binding: "S_A", storeId: "st1" }, { name: "B", binding: "S_B" }] })) === "secrets-store-absent");
  ok("a secrets config with every storeId present is ok", selfIdentityClass(spec({ type: "secrets", secrets: [{ name: "A", binding: "S_A", storeId: "st1" }] })) === "ok");
  ok("an API source (cf-config) carries no native-id degradation", selfIdentityClass(spec({ type: "cf-config", accountId: "acct" })) === "ok");
  ok("the degraded boolean tracks the class", selfIdentityDegraded(spec({ type: "kv", binding: "KV_uploads" })) === true && selfIdentityDegraded(spec({ type: "kv", binding: "KV_uploads", namespaceId: "abc" })) === false);
  // REDACTION: the classifier returns a CLOSED class, never the (missing or present) id itself.
  const cls = selfIdentityClass(spec({ type: "r2", binding: "R2_media", bucketName: SECRET }));
  ok("the classifier returns only a closed class, never the id", (SELF_IDENTITY_CLASSES as readonly string[]).includes(cls) && !cls.includes(SECRET));
}

async function main(): Promise<void> {
  await partA();
  await partB();
  await partC();
  await partD();
  partE();
  partF();
  console.log(failures === 0 ? "\nSEAL SUPPORT-PACK EVIDENCE PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
