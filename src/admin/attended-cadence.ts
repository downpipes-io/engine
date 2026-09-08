// Whether an estate's attended verifications are due, computed here rather than in a browser.
//
// WHY THIS EXISTS. On a break-glass-only estate the engine holds no key that can reopen a run it sealed
// earlier, so unattended proof is off by design and ATTENDED verification is what replaces it. That only
// happens when a person decides to do it. Today the only thing that says when it is due is a preference in
// one browser: console attend.ts stores the cadence and the reminder toggle under localStorage, both off by
// default, so the nudge does not follow the operator to another machine, private browsing drops it, and
// clearing site data resets it. The estate itself knows nothing about its own proof rhythm.
//
// This is a PURE function with no storage and no alerting, so it can land and be tested before the
// estate-wide setting exists and long before anything notifies on it.
//
// THREE RULES THAT ARE NOT OBVIOUS.
//
//   1. It evaluates PER DOWNPIPE, not estate-newest. An estate-wide "newest attended proof" is satisfied by
//      verifying one downpipe out of forty, which would ship a reassuring number that does not mean what it
//      says.
//
//   2. It credits ONLY a full, proven attended pass, which is the same predicate buildRestoreTestRecency
//      credits (restoreProvenMethod === "attended-blind-test"). Anything looser and a customer could satisfy
//      the reminder with a 5% sample while still failing the posture check, which is a reminder that lies in
//      the reassuring direction.
//
//   3. NEVER-VERIFIED is a distinct state from OVERDUE, and that distinction is a safety property rather
//      than a nicety. A freshly recovered estate restores its org policy (and so its cadence) but not its
//      proof history, so an estate-newest "overdue" would fire during the exact hour the operator is least
//      able to act. Never-verified is honestly different and the caller is expected to treat it differently.
//
// A downpipe that has never completed a run is excluded entirely: there is no sealed archive to verify yet,
// the same has-a-run exclusion buildRestoreTestRecency already applies, keyed on the same lastRunId.

import type { PostureDownpipeInput } from "./posture-types.ts";

/** The full keyed method: the only proof that counts, matching buildRestoreTestRecency's credit exactly. */
const FULL_ATTENDED_METHOD = "attended-blind-test";

/** Per-downpipe verdict. "excluded" carries no obligation; the caller must not count it either way. */
export type AttendedCadenceState = "excluded" | "never-verified" | "current" | "overdue";

export interface AttendedCadenceVerdict {
  id: string;
  name: string;
  state: AttendedCadenceState;
  /** Epoch ms of the newest FULL proven attended pass, absent when there has never been one. */
  provenAt?: number;
  /** Whole days since that proof, absent when there has never been one. Floor, so "0 days" means today. */
  ageDays?: number;
}

export interface AttendedCadenceSummary {
  /** The interval this was evaluated against, echoed so a caller cannot render a verdict without it. */
  cadenceDays: number;
  perDownpipe: AttendedCadenceVerdict[];
  /** Downpipes with a completed run and a proof older than the cadence. */
  overdue: AttendedCadenceVerdict[];
  /** Downpipes with a completed run and no full attended proof at all. Distinct from overdue, see rule 3. */
  neverVerified: AttendedCadenceVerdict[];
  /** Downpipes with no completed run, so nothing to verify yet. */
  excluded: AttendedCadenceVerdict[];
}

const MS_PER_DAY = 86_400_000;

/**
 * dueFor evaluates one downpipe against a cadence.
 *
 * cadenceDays <= 0 means no cadence is set, which is not the same as a cadence of zero: an estate that has
 * never chosen an interval has no obligation, so every downpipe with a run reads "current" rather than
 * "overdue". That keeps an unset cadence behaviourally identical to today.
 */
export function dueFor(d: PostureDownpipeInput, cadenceDays: number, now: number): AttendedCadenceVerdict {
  const base = { id: d.id, name: d.name };
  if (d.lastRunId === undefined || d.lastRunId === null || d.lastRunId === "") {
    return { ...base, state: "excluded" };
  }
  const proven = d.restoreProvenMethod === FULL_ATTENDED_METHOD && typeof d.restoreProvenAt === "number" ? d.restoreProvenAt : undefined;
  if (proven === undefined) return { ...base, state: "never-verified" };

  // A proof stamped in the future is a clock disagreement, not a fresh proof, but it is also not evidence of
  // a lapse. Clamp the age at zero and read it as current: inventing an overdue state out of a skewed clock
  // would alert on a fault this module cannot diagnose.
  const ageDays = Math.max(0, Math.floor((now - proven) / MS_PER_DAY));
  if (cadenceDays <= 0) return { ...base, state: "current", provenAt: proven, ageDays };
  return { ...base, state: ageDays > cadenceDays ? "overdue" : "current", provenAt: proven, ageDays };
}

/**
 * evaluateAttendedCadence sorts every downpipe into its state and groups the ones a caller acts on.
 *
 * It reports rather than decides. Nothing here gates work: a proof obligation that blocks work would be a
 * worse default than the one it replaces, so the caller's job is to display the overdue and never-verified
 * sets and, at most, notify on a transition.
 */
export function evaluateAttendedCadence(
  downpipes: readonly PostureDownpipeInput[],
  cadenceDays: number,
  now: number,
): AttendedCadenceSummary {
  const perDownpipe = downpipes.map((d) => dueFor(d, cadenceDays, now));
  return {
    cadenceDays,
    perDownpipe,
    overdue: perDownpipe.filter((v) => v.state === "overdue"),
    neverVerified: perDownpipe.filter((v) => v.state === "never-verified"),
    excluded: perDownpipe.filter((v) => v.state === "excluded"),
  };
}
