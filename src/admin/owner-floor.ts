// The Owner-count floor that keeps dual control (the Require Approver / four-eyes gate) operable, and closes
// the single-owner dual-control DEADLOCK against every ATTRIBUTABLE ROLE MUTATION. Dual control splits a
// change across a maker and a DISTINCT second Owner who approves it, so the estate must hold at least two
// Owner identities while it is armed: with one Owner every change is its own maker and checker, and so
// permanently unapprovable. This module is the single PURE statement of that invariant, shared by the enable
// path (setRequireConfigApproval) and the two Owner-count-reducing mutations (setRole demotion, deleteRole
// offboard). It counts nothing itself: the Durable Object passes in the live Owner count (countOwners over
// the bound + pending role table, which already excludes an expired grant) and the live gate state, so the
// authority and the tally stay in the DO where they belong.
//
// TWO RESIDUAL EDGES sit OUTSIDE these mutation guards: (1) the bare-token break-glass may arm below two
// Owners (deliberately exempt, see the enable guard); (2) a time-boxed Owner grant can LAPSE below the floor
// without a mutation firing this guard (effectiveRole drops it lazily) - the same property the long-standing
// last-Owner guard already has, since it too gates mutations, not the passage of time.
//
// NEITHER EDGE IS RECOVERABLE via a break-glass off-switch once the token is retired: there is no un-retire
// route, and the product's own
// dispose-bootstrap-token posture check tells the operator to retire it. Measured by another
// pass over the full eight-cell lattice; see wouldStrandDualControl below, which now refuses the
// combination at each of its three entrances, and test/validate-owner-floor-breakglass-escape.ts.
//
// This EXTENDS the existing last-Owner guard rather than replacing it: the floor is ONE while
// dual control is off (removing the last Owner is refused, unchanged) and TWO while it is on. The count is
// specifically the OWNER role: every Owner is approver-capable, and a non-Owner that merely holds an approve
// capability (a restore-operator) is deliberately NOT counted, because the dual-control floor is two OWNERS.
//
// House rules: Australian English, no em dashes, precise claims.

// DUAL_CONTROL_MIN_OWNERS is the floor while dual control is ON: two Owner identities, so a maker always has
// a distinct second Owner able to check them. BASE_MIN_OWNERS is the floor while it is OFF: the long-standing
// last-Owner guard, one Owner, unchanged.
export const DUAL_CONTROL_MIN_OWNERS = 2;
export const BASE_MIN_OWNERS = 1;

// ownerFloor is the minimum number of Owner identities the estate must retain, given whether dual control is
// armed. It is the one place the "one Owner off, two Owners on" rule is written.
export function ownerFloor(dualControlOn: boolean): number {
  return dualControlOn ? DUAL_CONTROL_MIN_OWNERS : BASE_MIN_OWNERS;
}

// The reason strings the DO throws (400) so both the enable refusal and the removal/demotion refusal read the
// SAME sentence at every site and in the tests. LAST_OWNER_REFUSAL is the EXISTING G-P0-042 sentence, kept
// VERBATIM: the SCIM offboard classifier and the availability proofs match on it, and it is still the true
// reason when the count would fall to zero. The two dual-control sentences name the raised floor and, for the
// enable path, tell the operator how to proceed (appoint a second Owner first).
export const LAST_OWNER_REFUSAL = "would remove the last Owner";
export const DUAL_CONTROL_FLOOR_REFUSAL =
  "dual control (Require Approver) is on and needs at least two Owners so a second Owner can approve a change. Removing or demoting this Owner would leave one, and a lone Owner cannot approve their own changes. Appoint another Owner first, or turn Require Approver off.";
export const DUAL_CONTROL_ENABLE_REFUSAL =
  "cannot require dual approval yet: dual control needs at least two Owners so a second Owner can approve a change (a lone Owner cannot be their own approver). Add a second Owner, then require dual approval.";

// RESTORE_DUAL_CONTROL_ENABLE_REFUSAL is the same floor for the RESTORE-apply gate, which is a separate
// owner-opt-in policy from the config one. The sentence differs because the remedy the operator needs differs:
// the config gate needs a second OWNER to approve a change, the restore gate needs a second APPROVER-capable
// identity to approve a plan. Arming either while solo would deadlock the operator, which for restore means
// being unable to recover at all, so the floor is checked on the way in rather than discovered in an incident.
export const RESTORE_DUAL_CONTROL_ENABLE_REFUSAL =
  "cannot require a second approver for restores yet: this estate has one identity, and a restore approval must come from someone other than the person who requested it. Appoint a second Owner or Approver first, otherwise arming this would leave nobody able to approve a restore.";

// OwnerRemovalVerdict is the outcome of the removal/demotion check: allowed, or refused with WHICH floor fired
// so the DO throws the matching sentence (the last-Owner floor of one, or the raised dual-control floor of two).
export type OwnerRemovalVerdict =
  | { ok: true }
  | { ok: false; reason: "last-owner" }
  | { ok: false; reason: "dual-control-floor" };

// checkOwnerRemoval decides whether removing or demoting ONE current Owner is allowed, given the CURRENT Owner
// count (the target inclusive, so it is at least 1 whenever the target is an Owner) and whether dual control is
// armed. It is FAIL-SAFE: an ambiguous count (a non-integer or a negative) refuses rather than allows, and
// because a NaN comparison would otherwise read as "allowed" (NaN < floor is false) that guard is EXPLICIT.
export function checkOwnerRemoval(currentOwnerCount: number, dualControlOn: boolean): OwnerRemovalVerdict {
  const floor = ownerFloor(dualControlOn);
  if (!Number.isInteger(currentOwnerCount) || currentOwnerCount < 0) {
    // Ambiguous count: refuse, labelled by the active floor. A removal must never proceed on a count the
    // engine could not compute.
    return { ok: false, reason: dualControlOn ? "dual-control-floor" : "last-owner" };
  }
  const remaining = currentOwnerCount - 1;
  if (remaining < floor) {
    // Dropping to zero is always the last-Owner floor (the G-P0-042 sentence); dropping below two while one
    // Owner would still remain is the raised dual-control floor.
    return remaining < BASE_MIN_OWNERS ? { ok: false, reason: "last-owner" } : { ok: false, reason: "dual-control-floor" };
  }
  return { ok: true };
}

// ownerRemovalRefusal maps a refusal verdict to its exact operator-facing sentence, so the DO sites never
// spell the message inline (the two guards and the tests all read one source of truth).
export function ownerRemovalRefusal(reason: "last-owner" | "dual-control-floor"): string {
  return reason === "last-owner" ? LAST_OWNER_REFUSAL : DUAL_CONTROL_FLOOR_REFUSAL;
}

// OWNER_FLOOR_REFUSAL_CODE is the MACHINE-READABLE name for "this refusal came from the Owner-floor guard",
// carried on the DO's 400 body beside the operator sentence.
//
// IT EXISTS BECAUSE THE SENTENCE WAS DOING THIS JOB AND COULD NOT. The SCIM facade decided its
// scim-last-owner-refused signal by testing the DO's response text for the literal "would remove the last
// Owner", which is LAST_OWNER_REFUSAL and nothing else. Three consequences, the first of them LIVE on shipped
// code rather than hypothetical:
//   - deleteRole ALSO refuses with DUAL_CONTROL_FLOOR_REFUSAL, whose sentence does not contain that
//     substring, so a SCIM offboard refused by the RAISED two-Owner floor is already filed as a generic 4xx.
//     The one signal that explains the refusal is absent for the case an operator is most likely to hit,
//     because arming dual control is what raises the floor in the first place.
//   - revokeSignInFactors raises its OWN two route-specific sentences, deliberately, because nobody's role
//     changes there. Any future caller of it inherits the same misfiling.
//   - the sentences are operator-facing copy. Anyone improving the wording, in any of the three places, would
//     silently break a signal in a different module with no test naming the coupling.
// The code below is a closed identifier that copy edits cannot reach.
export const OWNER_FLOOR_REFUSAL_CODE = "owner-floor";

// OwnerFloorRefusal is the throw the Owner-floor guards raise. It carries the operator sentence as its
// message exactly as the plain Error it replaces did, so every existing response body and message assertion
// is unchanged, plus the structured reason. The DO's fetch catch reads the class and puts the code on the
// 400 body; nothing downstream reads the prose.
export class OwnerFloorRefusal extends Error {
  reason: "last-owner" | "dual-control-floor";
  constructor(message: string, reason: "last-owner" | "dual-control-floor") {
    super(message);
    this.name = "OwnerFloorRefusal";
    this.reason = reason;
  }
}

// canRequireDualControl decides whether dual control may be ENABLED: there must be at least two Owner
// identities, so a maker always has a distinct second Owner to approve them. FAIL-SAFE: a non-integer or short
// count refuses, so a lone Owner can never arm a gate that would deadlock them.
export function canRequireDualControl(ownerCount: number): boolean {
  return Number.isInteger(ownerCount) && ownerCount >= DUAL_CONTROL_MIN_OWNERS;
}

// ---- THE UNRECOVERABLE COMBINATION, and why the module's own "RECOVERABLE" note above needed a floor ---
//
// The paragraph at the head of this file calls both residual edges "RECOVERABLE via the break-glass
// off-switch (the route guarantees the break-glass can always disarm)". Measured: THE ESCAPE IS
// DISPOSABLE. POST /admin/policy/retire-break-glass-token sets a durable latch after which a bare ADMIN_TOKEN
// never resolves to owner, so the `method === "token"` branch that disarms immediately is unreachable, and
// there is no un-retire route (the DO honours retired:false, nothing sends it). The product's own
// dispose-bootstrap-token posture check tells the operator to retire it.
//
// THREE CONDITIONS TOGETHER MAKE THE ESTATE PERMANENTLY UNADMINISTRABLE, and each can arrive last:
//   1. dual control is ARMED, so an attributable Owner's disarm is queued for a DISTINCT second Owner;
//   2. the break-glass token is RETIRED, so no identity can disarm unilaterally;
//   3. an Owner grant is TIME-BOXED, so the count can fall to one with no mutation firing the floor guard
//      above (residual edge 2), after which appointing a replacement Owner is itself queued for the second
//      Owner who no longer exists.
//
// Driven over the full lattice in test/validate-owner-floor-breakglass-escape.ts: with the token alive the
// bare token disarms at 200 and the DO's flag really goes off; with it retired the same disarm answers 202
// for ever, the role-set answers 202, the maker cannot approve their own action and the lapsed Owner cannot
// approve anything. The gate stays ON in exactly that one cell of eight.
//
// So the invariant this module now states is: THE ESTATE MAY HOLD AT MOST TWO OF THE THREE. It is enforced at
// each of the three entrances rather than at the lapse, because the lapse is the passage of time and there is
// nothing there to refuse. A refusal here always leaves both of its named remedies open, because the second
// Owner is still live at the moment it fires.
export type DeadlockEntrance = "arm-dual-control" | "retire-break-glass" | "grant-expiring-owner";

// wouldStrandDualControl reports whether completing `entrance` would assemble all three conditions. The
// caller passes the state of the OTHER two, so this stays pure and each site reads as the question it is
// actually asking. expiringOwnerGrants is a COUNT of currently-effective Owner grants carrying an expiresAt.
export function wouldStrandDualControl(
  entrance: DeadlockEntrance,
  state: { dualControlOn: boolean; breakGlassRetired: boolean; expiringOwnerGrants: number },
): boolean {
  switch (entrance) {
    case "arm-dual-control":
      return state.breakGlassRetired && state.expiringOwnerGrants > 0;
    case "retire-break-glass":
      return state.dualControlOn && state.expiringOwnerGrants > 0;
    case "grant-expiring-owner":
      return state.dualControlOn && state.breakGlassRetired;
  }
}

// strandRefusal is the operator sentence for each entrance. Each names WHAT is being prevented, WHY the
// combination cannot be undone, and TWO remedies that exist and are reachable right now (the second Owner is
// still live, so both a role-set and a dual-control-disable can still be approved). It never names an
// address: a refusal names the shape, not the people.
export function strandRefusal(entrance: DeadlockEntrance, expiringOwnerGrants: number): string {
  const grants = `${expiringOwnerGrants} Owner grant${expiringOwnerGrants === 1 ? "" : "s"} expire${expiringOwnerGrants === 1 ? "s" : ""}`;
  const those = expiringOwnerGrants === 1 ? "that Owner" : "those Owners";
  const tail =
    "The break-glass token is the only identity that can turn dual control off on its own, and once a time-boxed Owner grant lapses the last Owner cannot disarm it, cannot appoint a replacement Owner (that is queued for a second Owner too) and cannot un-retire the token.";
  switch (entrance) {
    case "arm-dual-control":
      return `cannot require dual approval while the break-glass token is retired and ${grants}: ${tail} Re-grant ${those} without an expiry, or leave the token in place, then require dual approval.`;
    case "retire-break-glass":
      return `cannot retire the break-glass token while dual control is on and ${grants}: ${tail} Re-grant ${those} without an expiry, or turn Require Approver off, then retire the token.`;
    case "grant-expiring-owner":
      return "cannot grant a time-boxed Owner while dual control is on and the break-glass token is retired: if that grant lapses the last Owner cannot turn dual control off, cannot appoint a replacement Owner (that is queued for a second Owner too) and cannot un-retire the token. Grant this Owner without an expiry, or turn Require Approver off first.";
  }
}
