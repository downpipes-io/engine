// The SIGN-IN FACTOR union: the vocabulary and the one decision that turns three storage reads into the
// answer an operator actually asked for, "can this person still sign in?".
//
// WHY THIS EXISTS. The engine could enumerate CREDENTIALS (listAllPasskeyCredentialsForAccount) and nothing
// else. A credential is one of three ways into an account, and it is the HARDEST of the three, because it
// needs the physical authenticator. The other two are bearer secrets:
//
//   - a RECOVERY CODE. deleteRole never touches `recovery:<email>`, recoveryRecover gates on no roster, mints
//     an ordinary session and returns enrolPasskey:true, so an unused code is both a way in AND a way to
//     enrol a fresh credential.
//   - a REGISTRATION INVITE. `passkeyInvite:<token>` is keyed by TOKEN, so an email-keyed offboard cannot
//     reach it even in principle, and consumeInvite checks shape, presence and expiry with no roster check
//     at all. An unexpired link enrols a new credential for the bound email.
//
// So an account could read "no credentials" and still hold two live ways in for the same person. That is the
// false-empty defect one store along, and it is why this had to be designed against all three at once rather
// than bolted onto the credential route.
//
// THE POLARITY, which is the whole reason the classification is not a boolean. recoveryRecordKeyLive
// (scheduler-do-recovery.ts) answers "is a way back in PROVEN" and returns false for anything unprovable,
// deliberately, because the pre-flight it feeds tells an operator it is safe to destroy their last
// credential: there, a false positive locks somebody out permanently.
//
// This read has the OPPOSITE consequence. An operator asking "can my removed colleague still sign in?" who is
// told NO when the truth is UNPROVABLE will close the offboarding and walk away, and the way in stays open.
// Here the false NEGATIVE is the harm. Reusing that helper's boolean directly would have silently inherited
// the wrong safety polarity, which is exactly the kind of reuse that looks correct in review. So an
// unprovable recovery record is reported as INDETERMINATE and never as "no factor": a row an operator must
// look at, not a row they can skip.

// RecoveryKeyContinuity is what is known about whether a banked recovery code can still VERIFY. "none" is the
// absence of a record, and is kept distinct from "unknown" so a person who never had codes is not confused
// with one whose codes cannot be judged.
//   - "live": a code from this record verifies. Either demonstrated (the record's keyProof witness recomputes
//     equal under the live key) or inferred from the key timeline, the same inference the lockout pre-flight
//     already acts on when it says ready.
//   - "orphaned": REFUTED, not merely unproven. The record carries a keyProof and it does not match. A code
//     cannot verify, so it is not a way in.
//   - "unknown": no witness, and the timeline does not place the record under the live key. Might be dead,
//     might be a gap in an old record. Not a licence to report "no way in".
//   - "none": no `recovery:` record for this email.
export type RecoveryKeyContinuity = "live" | "orphaned" | "unknown" | "none";

// SignInPath names a way in that is PROVEN live. It is deliberately not a superset of "might be live": an
// indeterminate row carries no path and the verdict says so, rather than a path an operator would read as
// established.
export type SignInPath = "passkey" | "recovery-code" | "registration-invite";

// SignInVerdict is the tri-state. "indeterminate" is the member that earns its keep: collapsing it into
// either boolean is a lie in one direction, and the two lies are not equally costly (see the polarity note
// above).
export type SignInVerdict = "can-sign-in" | "indeterminate" | "no-factor";

// SignInFactorInput is the measured state of one email across the three stores, with nothing derived.
// recoveryUnconsumed is `null` and NOT 0 when the record could not be parsed: 0 would say "this person has no
// codes left", which is precisely the reassuring answer the reader must not be given about a record nobody
// could read.
export interface SignInFactorInput {
  passkeyCredentials: number;
  recoveryPresent: boolean;
  recoveryParseable: boolean;
  recoveryUnconsumed: number | null;
  recoveryKeyContinuity: RecoveryKeyContinuity;
  liveInvites: number;
}

// classifySignIn is the single decision, kept pure so it can be exercised in both directions without a DO.
//
// A PASSKEY CREDENTIAL is definitive on the positive side: the record IS the factor, and no further evidence
// is needed to say the person can authenticate. Same for an unexpired invite, whose expiry is a number
// comparison with no inference in it.
//
// The recovery arm is the only one that can be indeterminate, and it has exactly two ways to get there: a
// record nobody can parse (so the count is unknowable), or unconsumed codes whose key continuity cannot be
// established. Exhausted codes ("parseable, zero unconsumed") and refuted ones ("orphaned") are DEFINITE
// negatives and are reported as such, because an operator who cannot distinguish "nothing here" from "nothing
// provable here" ends up treating both as noise.
export function classifySignIn(input: SignInFactorInput): { verdict: SignInVerdict; paths: SignInPath[] } {
  const paths: SignInPath[] = [];
  if (input.passkeyCredentials > 0) paths.push("passkey");
  if (input.recoveryPresent && input.recoveryParseable && (input.recoveryUnconsumed ?? 0) > 0 && input.recoveryKeyContinuity === "live") paths.push("recovery-code");
  if (input.liveInvites > 0) paths.push("registration-invite");
  if (paths.length > 0) return { verdict: "can-sign-in", paths };
  // No proven path. The record may still be unjudgeable, and that is a different answer from "no factor".
  const unjudgeable = input.recoveryPresent && (!input.recoveryParseable || ((input.recoveryUnconsumed ?? 0) > 0 && input.recoveryKeyContinuity === "unknown"));
  return { verdict: unjudgeable ? "indeterminate" : "no-factor", paths };
}

// SignInFactorRow is the per-email view returned by the union read. Redaction-safe throughout: counts,
// timestamps, closed enums, and credential ids (base64url PUBLIC identifiers, the same ones the per-email
// credential route already returns). NEVER a recovery code, a code hash, an invite token or any key.
//
// Invites are a COUNT and a soonest-expiry only. The token is the secret and it is also the storage key, so
// the record cannot be reported at all without care: this reports what exists, never what it is called.
//
// hasRoleEntry keeps the name and the meaning the credential route established: whether the email has a row
// in the role table or an unexpired pending invite, and NOT "orphaned". An operator whose role arrives from
// an IdP group claim has no row and is not an orphan.
// SignInFactorRevocation is what a revoke REMOVED, counted per store. It is the write-side twin of
// SignInFactorRow and it is deliberately counts-only: the three stores hold a public credential id, a set of
// code hashes and a token that IS the secret, and none of those may leave the DO on a revocation any more than
// they may on a read.
//
// The live/expired invite split is reported separately rather than summed, because the two mean different
// things to the operator reading the receipt. `invitesLive` is the number of ways in that were actually closed
// by this call, which is the security fact. `invitesExpired` is housekeeping that was swept at the same time,
// and folding it into one number would inflate the count that matters and let a revoke that closed NOTHING
// report a reassuring non-zero total.
export interface SignInFactorRevocation {
  passkeyCredentials: number;
  recovery: boolean;
  invitesLive: number;
  invitesExpired: number;
}

// revocationClosedAWayIn answers whether a revocation removed anything that was a WAY IN, as opposed to
// removing only expired residue. It is the condition the session-epoch bump and the audit row hang off, and it
// is a named function rather than an inline `||` chain because the expired-invite term must never join it: a
// sweep of dead records is not a revocation, and letting it bump the epoch would kill a live session as a side
// effect of housekeeping. That is the precise scoping this decision exists to hold.
export function revocationClosedAWayIn(r: SignInFactorRevocation): boolean {
  return r.passkeyCredentials > 0 || r.recovery || r.invitesLive > 0;
}

export interface SignInFactorRow {
  email: string;
  hasRoleEntry: boolean;
  signIn: SignInVerdict;
  paths: SignInPath[];
  passkey: {
    credentials: number;
    credentialIds: string[];
    lastAssertedAt: string | null;
  };
  recovery: {
    present: boolean;
    parseable: boolean;
    unconsumedCodes: number | null;
    keyContinuity: RecoveryKeyContinuity;
    generatedAt: string | null;
  };
  invites: {
    live: number;
    expired: number;
    soonestExpiresAt: string | null;
  };
}

// ---- ROSTER-BOUND CONSUMPTION -------------------------------------------------------------------------
//
// RosterVerdict is what the engine knows about whether the roster still accounts for an email, at the moment
// a bearer secret is being spent. It exists because a recovery code has no expiry and needs none: a
// break-glass credential that expires on a clock fails during the emergency it exists for. Validity is
// bound to the ROSTER instead, which is the thing that actually changed when the person left.
//
// THE THIRD MEMBER IS THE DESIGN. A two-valued answer would force an unreadable roster to be reported as one
// of the two real answers, and both choices are wrong: "on-roster" makes the gate decorative, and
// "off-roster" refuses a genuine break-glass during exactly the degraded conditions a break-glass is for.
// "unreadable" is carried so the caller can fail OPEN on it deliberately rather than by omission.
export type RosterVerdict = "on-roster" | "off-roster" | "unreadable";

// classifyRosterMembership is the whole refusal rule, as a pure function over three facts, so the fail-open
// direction can be read in one place instead of inferred from a chain of awaits.
//
// It refuses on ONE conjunction: the read SUCCEEDED, it returned a roster that is not empty, and the target
// is not in it. Every other combination admits.
//
//   read "failed"   -> unreadable. A storage fault is not evidence that somebody left. The person holding the
//                     code is at their worst moment and the engine's answer must not be "no" because a list
//                     call threw.
//   rosterSize 0    -> unreadable, NOT off-roster, and this is the failure mode most likely to be missed. An
//                     empty roster is a genuinely new account or a broken one, and neither is a departure. A
//                     naive membership test reads an empty set as "nobody is accounted for", which would
//                     refuse EVERY consumption on an account whose role table failed to populate. Treating
//                     zero as unreadable makes "the roster says this person left" a claim that requires a
//                     roster saying anything at all.
//   present         -> on-roster.
//   otherwise       -> off-roster: a populated roster was read and it does not carry this address.
export function classifyRosterMembership(facts: { read: "ok" | "failed"; rosterSize: number; targetPresent: boolean }): RosterVerdict {
  if (facts.read === "failed") return "unreadable";
  if (!Number.isInteger(facts.rosterSize) || facts.rosterSize <= 0) return "unreadable";
  return facts.targetPresent ? "on-roster" : "off-roster";
}

// rosterRefusesEnrolment is the SINGLE test every caller uses, named so the fail-open direction cannot be
// lost to a negation at a call site. Only "off-roster" refuses. It is deliberately not `verdict !==
// "on-roster"`, which is the same expression with the opposite safety polarity and would read as correct.
export function rosterRefusesEnrolment(verdict: RosterVerdict): boolean {
  return verdict === "off-roster";
}
