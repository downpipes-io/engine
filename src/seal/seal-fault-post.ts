// SEAL-FAULT OBSERVE POSTER (gap G326, support-pack mode seal-fault-observe-dropped). Every seal-fault
// observation is a FIRE-AND-FORGET POST to the scheduler DO's bounded ring, deliberately best-effort so a
// persist hiccup can never affect a run. The cost of that discipline was invisible: when the POST failed
// (a scheduler-DO outage), when an engine-side kind had drifted out of SEAL_FAULT_KINDS, or when a count
// arrived malformed, the observation simply vanished -- and the pack then showed a CLEAN fault ring while
// faults were occurring, which reads as "the engine is healthy" rather than "the evidence was lost".
//
// This module is the ONE send-side chokepoint (the RunSealDO observe path and the retention prune pass both
// route through it), and it makes the ring's own losses self-reporting:
//   - unknown-kind : the kind is pre-gated against the closed vocabulary HERE, so a drifted kind is converted
//                    into a valid "observe-dropped" record (dropClass "unknown-kind") that DOES land, instead
//                    of being silently swallowed by the DO's defensive sanitiser. The drifted kind's STRING is
//                    never sent -- only the closed class and a count.
//   - transport    : a failed / refused POST is TALLIED here and flushed as an "observe-dropped" record
//                    (dropClass "transport", dropped = how many were swallowed) on the next observation that
//                    LANDS. A DO-side counter structurally cannot see this class: the DO is the unreachable
//                    party. The tally is per-isolate and best-effort by construction -- an isolate that is
//                    evicted before another observation lands loses it, which is the honest bound of a
//                    fail-open observe path (never a run's problem).
//   - malformed-count : recorded on the record ITSELF by the DO's sanitiser (countsMalformed), so a clamped-
//                    to-0 count can no longer be misread as a measured 0 (a false severe-truncation escalation).
//
// NO-CUSTODY: nothing here reads or forwards a message, a key, a value or a token. The only new bytes on the
// wire are a closed kind, a closed drop class and a count. Recording NEVER changes the seal / sign / verify /
// finalise path: every call is wrapped and fail-open, exactly as the observe path it replaces was.

import { doURL } from "../do-url.ts";
import { isSealFaultKind, type SealFaultDropClass } from "./seal-faults.ts";

// SealFaultPost is the loose shape a detection point posts. It is deliberately NOT SealFault: a caller may
// hold a drifted kind (that is the very thing G326 catches), and the DO re-validates + clamps everything
// through sanitiseSealFault regardless. Every field is already a closed enum, an id or an integer.
export interface SealFaultPost {
  kind: string;
  at: number;
  downpipeId?: string;
  runId?: string;
  found?: number;
  expected?: number;
  cleaned?: number;
  reclaimed?: number;
  wormBlocked?: boolean;
  deferClass?: string;
  skipped?: number;
  unparseableTime?: number;
  superseded?: number;
  partial?: boolean;
  rangeIndex?: number;
  discardClass?: string;
  // G142 (config-fault): the CLOSED prerequisite code + the offending binding / env-var NAME (an operator
  // label; the DO's sanitiser re-gates it to the bare identifier charset, so a value can never ride here).
  configCode?: string;
  bindingName?: string;
  // G143 (run-pressure): counts + closed classes for the retry / park / strike pressure one run spent.
  retries?: number;
  retriesBySubsystem?: Record<string, number>;
  throttleParks?: number;
  runlogParks?: number;
  strikes?: number;
  probeFlaps?: number;
  throttledSubsystem?: string;
  attemptClasses?: string[];
  outcome?: "ok" | "failed";
  // G063 (replica-target-fault) / G064 (replication-pass) / G065 (record-skipped-changed) / G066
  // (dest-stranding) / G067 (verify-suspect) / G189 (seal-mode) / G212 (alert-routing-failed) / G222
  // (lock-plane). Every field is already a closed enum, a customer-owned opaque id, a hex handle or an integer;
  // the DO's sanitiser re-gates every one of them regardless (this module adds no trust).
  destinationId?: string;
  replicaReason?: string;
  strandedRuns?: number;
  passOutcome?: string;
  deferredDownpipes?: number;
  stateWriteFailures?: number;
  verifySampleShortfall?: number;
  segmentVanishDeferrals?: number;
  skipCause?: string;
  handles?: string[];
  partialsAbandoned?: number;
  strandClass?: string;
  stranded?: number;
  wormRefusalClass?: string;
  listFailed?: boolean;
  verifyMode?: string;
  causeDigest?: string;
  ordinal?: number;
  verifiedBeforeFail?: number;
  attemptsRun?: number;
  recovered?: boolean;
  requestedMode?: string;
  effectiveMode?: string;
  fanoutRanges?: number;
  downgradeReason?: string;
  underCrawlChecked?: boolean;
  budgetOverrideForced?: boolean;
  alertEventClass?: string;
  historyWriteFailed?: boolean;
  lockAcquireFaults?: number;
  lockWindowExhausted?: number;
  casExhausted?: number;
  sigPublishSkipped?: number;
  releaseFaults?: number;
  // G107 (checkpoint-invalid / checkpoint-unwrap-failed / checkpoint-coerced / resume-abandoned), G108
  // (the fan-out + open-shard completeness guards reuse found/expected/ordinal above), G109 (completion-lost
  // reuses outcome/causeDigest/attemptClasses above) and G283 (runlog-absent). Every field is a closed enum,
  // a boolean or an integer; the DO's sanitiser re-gates every one of them regardless.
  checkpointField?: string;
  unwrapCode?: string;
  coerced?: number;
  legacyAbsent?: boolean;
  slicesDiscarded?: number;
  recordsDiscarded?: number;
  priorRuns?: number;
  historyChainRestarted?: boolean;
}

// The per-isolate tally of observations that never reached the ring, keyed by the closed drop class. It is
// FLUSHED (and cleared) by the next observation that lands, so the ring self-reports its own losses instead of
// showing an honest-looking absence. Bounded by DROP_TALLY_MAX so a long DO outage cannot grow it unbounded.
const DROP_TALLY_MAX = 1_000_000;
const dropTally = new Map<SealFaultDropClass, number>();

// sealFaultDropTally exposes the pending (not-yet-flushed) drop counts. Diagnostic + test surface only: it
// reads the tally, never the observations themselves (which were never held).
export function sealFaultDropTally(): Record<string, number> {
  return Object.fromEntries(dropTally);
}

// resetSealFaultDropTally clears the pending tally. Used by the validators to isolate cases; the running
// engine only ever clears it by FLUSHING it into the ring.
export function resetSealFaultDropTally(): void {
  dropTally.clear();
}

// tallyDrop counts one swallowed observation against its closed class (bounded).
function tallyDrop(cls: SealFaultDropClass): void {
  dropTally.set(cls, Math.min((dropTally.get(cls) ?? 0) + 1, DROP_TALLY_MAX));
}

// sendOne posts ONE body to the ring and reports whether it LANDED. A thrown fetch (DO routing/outage) and a
// non-2xx (a refused/erroring DO) are the SAME class to a fire-and-forget observer: the observation is gone.
// No detail is logged: a transport message is not run data, and silence keeps the log clean.
async function sendOne(scheduler: DurableObjectStub, body: Record<string, unknown>): Promise<boolean> {
  try {
    const r = await scheduler.fetch(doURL("/seal-fault"), { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
    return r.ok;
  } catch {
    return false;
  }
}

// flushDrops posts the pending drop tally as "observe-dropped" records (one per class) and clears the classes
// that landed. It is called ONLY after an observation has just landed, so the transport is known good; a class
// whose own flush fails is re-tallied (never lost, never double-counted) so the next landing retries it.
async function flushDrops(scheduler: DurableObjectStub, downpipeId?: string): Promise<void> {
  if (dropTally.size === 0) return;
  const pending = [...dropTally.entries()];
  dropTally.clear();
  for (const [cls, n] of pending) {
    const landed = await sendOne(scheduler, { kind: "observe-dropped", at: Date.now(), dropClass: cls, dropped: n, ...(downpipeId !== undefined ? { downpipeId } : {}) });
    if (!landed) dropTally.set(cls, Math.min((dropTally.get(cls) ?? 0) + n, DROP_TALLY_MAX));
  }
}

/**
 * postSealFault records ONE seal-fault observation in the scheduler DO's bounded ring, and records the ring's
 * OWN ingestion losses (gap G326). STRICTLY BEST-EFFORT and fail-open: it never throws, so a routing/persist
 * hiccup degrades to "no observation" (now a COUNTED one) and can never affect the run. It reads/mutates no
 * archive, RUNLOG or seal path.
 *
 * A kind outside the closed vocabulary is NOT sent as-is (the DO would drop it and nothing would say so): it is
 * replaced by an "observe-dropped" record carrying the closed class "unknown-kind". The drifted kind's string
 * never leaves the engine.
 */
export async function postSealFault(scheduler: DurableObjectStub, fault: SealFaultPost): Promise<void> {
  if (!isSealFaultKind(fault.kind)) {
    // Engine-side drift: a detection point posted a kind that is not in SEAL_FAULT_KINDS. Report the DROP (a
    // closed class + a count), never the kind string, and keep the downpipe id so the drift is attributable.
    tallyDrop("unknown-kind");
    const landed = await sendOne(scheduler, { kind: "observe-dropped", at: fault.at, dropClass: "unknown-kind", dropped: dropTally.get("unknown-kind") ?? 1, ...(fault.downpipeId !== undefined ? { downpipeId: fault.downpipeId } : {}) });
    if (landed) dropTally.delete("unknown-kind");
    return;
  }
  const landed = await sendOne(scheduler, fault as unknown as Record<string, unknown>);
  if (!landed) {
    tallyDrop("transport");
    return;
  }
  await flushDrops(scheduler, fault.downpipeId);
}
