// THE IMMUTABILITY POSTURE CHECK, split out of admin/posture-checks.ts.
//
// WHY IT IS ITS OWN FILE. posture-checks.ts crossed the 1000-line budget scripts/max-lines-lint.mjs
// enforces, by seven lines, on the landing that made this check speak each store's own vocabulary. An
// exemption for seven lines is the shape that budget exists to refuse: a ratchet with headroom stops
// being a limit and becomes a formality, and the next seven lines arrive with the argument already made.
//
// THIS IS A REAL SEAM RATHER THAN A CONVENIENT CUT. buildImmutability is the one check with a dependency
// none of its neighbours have, dest/worm-remedy.ts, which carries the per-provider mechanism, store noun,
// enable-when sentence and remedy. Everything the check needs travels with it; nothing it leaves behind
// reaches back for it. It is re-exported from posture-checks.ts so every existing importer, and every
// citation pinned at that module, keeps working.


// CheckDraft and PostureInput are both defined in the leaf posture-types.ts (posture-checks.ts and
// posture.ts each only re-export them), so importing from there, rather than from posture-checks.ts or
// posture.ts, avoids a back-edge entirely: madge does not skip type-only imports, so a type-only import
// of either sibling still closed a cycle on the file graph even though no runtime import existed.
import type { CheckDraft, PostureInput } from "./posture-types.ts";
import { immutabilityEnableWhen, immutabilityMechanism, immutabilityRemedy, immutabilityStoreNoun } from "../dest/worm-remedy.ts";

// immutability (medium, ISO A.8.13 / ransomware resilience): the REAL WORM/Object-Lock posture. This
// SUPERSEDES the old practice of inferring immutability from whether a delete was refused (the canary's
// delete-probe note is a coarse observation, not proof a bucket is locked): it is fed by the live
// capability probe (S3 GetObjectLockConfiguration) plus whether a WORM policy is configured and being
// applied, so the claim is precise and honest.
//
// TWO AXES decide it, not one. Whether the BUCKET enforces Object-Lock, and whether anything actually
// applies a RETENTION WINDOW to the archives written there. Exactly two things put a window on an archive:
// the per-object retention header the engine writes under a VALID configured policy (call that ARMED), and
// the bucket's OWN default retention rule (defaultRetention, read by the same probe). ObjectLockEnabled on
// a bucket retains nothing by itself, which is why "the bucket enforces Object-Lock" cannot stand alone as
// the pass predicate. The readings, one detail sentence each:
//   - ARMED + bucket ENFORCES -> PASS: "WORM enforced (mode, N days)". Real, store-enforced immutability,
//     resting on the header the engine writes on every archive. The strong claim.
//   - ARMED + bucket does NOT enforce / cannot be confirmed -> FAIL (medium warning): the policy is set but
//     the bucket was not created with Object-Lock (or the probe could not confirm it), so archives are NOT
//     actually protected though the operator may believe they are. The dangerous gap.
//   - INVALID policy -> FAIL in every reading, including on an enforcing bucket. The writer armed nothing,
//     so the window the operator asked for is not the window in force, whatever the bucket does on its own.
//     A misconfigured policy is never a green claim (posture-types.ts), and an enforcing bucket does not
//     make an unparseable policy correct.
//   - NOT configured + bucket ENFORCES + the bucket has its OWN default rule -> PASS: the strong claim
//     holds, resting on that rule rather than on any header the engine wrote, and the detail says so.
//   - NOT configured + bucket ENFORCES + NO default rule -> PASS informationally, and the strong claim is
//     REFUSED: lock is switched on and nothing is retained. This is the same posture as WORM being off on
//     an ordinary bucket (opt-in, nothing intended, nothing protected), so it is graded the same way; what
//     changes is that the detail no longer promises a retention window that does not exist.
//   - NOT configured + bucket ENFORCES + the default rule could NOT be read -> PASS informationally,
//     asserting neither direction. An unread rule is not an absent rule, so this never fails on it.
//   - NOT configured + no enforcement -> PASS informationally: WORM is opt-in and off; the platform's
//     tamper-evidence (signed, hash-chained RUNLOG) is still in force, but object-lock is not claimed.
// When the worm slice is ABSENT entirely (an older caller, or no destination to probe) the check reports
// the honest not-configured informational pass rather than fabricating a verdict.
//
// CORRECTED (the retention axis). failed = !enforces asserted the strong claim, "a compromised
// delete-credential cannot hard-delete or overwrite an archive within its retention window", on an
// Object-Lock-enabled bucket carrying an INVALID policy and on one carrying NO policy at all, neither of
// which puts a retention window anywhere. The second needs no misconfiguration by anyone and is the more
// reachable. The comment that stood here said the invalid case "fails here too" and the code did not do it.
// This check is an automatic PASS feeding the posture SCORE, the evidence pack's framework mapping and the
// risk-accept records, so the same false sentence reached a customer through three surfaces at once. The
// slice already carries the fact (defaultRetention, router-posture.ts), so nothing new is probed.
export function buildImmutability(input: PostureInput): CheckDraft {
  // The one "how" line for every branch: the determination is a live capability probe, not an inference.
  const how =
    "Combines the configured WORM policy (env or console-set) with a LIVE capability probe of the default destination, so enforcement is observed, never inferred from delete behaviour: S3 GetObjectLockConfiguration on an S3-compatible or Google Cloud bucket, and the container's version-level-immutability property on Azure Blob. Fails only in the dangerous state: a policy is intended but nothing is applying the retention window it asked for.";
  const base = { id: "immutability", title: "Object-Lock (WORM) immutability", control: "ISO A.8.13", how } as const;
  const w = input.worm;
  // lock is what THIS store calls write-once retention and store is what it calls the thing archives land
  // in, both from dest/worm-remedy.ts and both falling back to the S3 spelling when the provider is not
  // resolvable. The signed report has read them; this check did not, so an Azure customer
  // was told to inspect a "bucket" for "S3 Object-Lock", neither of which exists in their portal. The
  // remedy line here was already provider-aware, which is what made the gap easy to miss: the sentence
  // offering the fix named Azure's mechanism while the sentence stating the finding named Amazon's.
  const lock = immutabilityMechanism(w?.provider);
  const store = immutabilityStoreNoun(w?.provider);
  if (w === undefined || (!w.configured && w.bucketEnforces !== true)) {
    // Not configured (or no observation): informational pass. If the bucket nonetheless enforces
    // object-lock by its own default rule, fall through to the configured branch below to credit it.
    return {
      ...base,
      auto: "pass",
      detail:
        `WORM (${lock}) is not configured (it is opt-in). Archives remain tamper-evident (signed, hash-chained RUNLOG), but the destination ${store} does not enforce write-once retention. Configuring it makes a compromised delete-credential unable to hard-delete archives within the retention window.`,
      remediation: `If ransomware-resilient immutability is required: ${immutabilityRemedy(w?.provider)} Then set a WORM policy (mode + retention days); compliance mode prevents deletion even by the root account for the window.`,
    };
  }
  // A WORM policy is intended (configured) OR the bucket enforces lock by a default rule.
  const enforces = w.bucketEnforces === true;
  const modeLabel = w.mode ? `${w.mode} mode` : w.probeMode ? `${w.probeMode} mode (bucket default)` : "object-lock";
  const days = w.retentionDays ?? w.probeDays;
  const daysLabel = days !== undefined ? `, ${days} day${days === 1 ? "" : "s"} retention` : "";
  // ARMED: the engine writes an Object-Lock retention header on every archive it puts here, which is
  // exactly what a VALID configured policy produces (buildDestination arms the policy only when
  // validateWormPolicyValue / parseWormPolicy accept it, so misconfigured means nothing is armed).
  const armed = w.configured && !w.misconfigured;
  // bucketRule: does the lock-enabled bucket apply a DEFAULT RETENTION RULE of its own? defaultRetention
  // is the probe's own answer (set whenever the bucket reads enabled). probeMode/probeDays ARE that rule
  // as read off the same call, so their presence is the same evidence by a shorter route and is honoured
  // for a caller that forwards the rule without the boolean. Neither present is "unknown", never false: an
  // unread rule is not an absent rule, and this check never fails on the unread reading.
  const bucketRule: boolean | "unknown" =
    w.defaultRetention === true || w.probeMode !== undefined || w.probeDays !== undefined
      ? true
      : w.defaultRetention === false
        ? false
        : "unknown";

  // ARMED on an enforcing bucket: the strong claim, unchanged. The bucket's own default rule is beside the
  // point here, because the header the engine writes is what the claim rests on.
  if (armed && enforces) {
    return {
      ...base,
      auto: "pass",
      detail: `WORM enforced: the destination ${store} enforces ${lock} (${modeLabel}${daysLabel}). A compromised delete-credential cannot hard-delete or overwrite an archive within its retention window.`,
      remediation: "No action required; store-enforced WORM is in force. Verify the retention window meets your policy.",
    };
  }

  // An INVALID policy: the operator intended a window and the engine arms none. It fails in every reading,
  // and on an enforcing bucket the detail states what the bucket does on its own without turning that into
  // a pass, because the policy is still not the thing in force.
  if (w.misconfigured) {
    const invalid = `A WORM policy is configured but INVALID (mode and retention days must both be set, with a positive window), so no ${lock} metadata is being written`;
    return {
      ...base,
      auto: "fail",
      detail: !enforces
        ? `${invalid} and archives are NOT protected. Fix the policy; until then immutability is not in force.`
        : bucketRule === true
          ? `${invalid}. The destination ${store} enforces ${lock} and applies its own default retention rule (${modeLabel}${daysLabel}), which is the whole of the protection here and is not the window you asked for. Fix the policy so the window you intended is the one in force.`
          : bucketRule === false
            ? `${invalid}. The destination ${store} has ${lock} switched on but carries no default retention rule, so nothing applies a retention window to an archive written here and archives are NOT protected. ${lock} enabled on a ${store} does not retain anything by itself.`
            : `${invalid}. The destination ${store} enforces ${lock}, but whether it applies a default retention rule of its own could not be read, and that rule is the only thing that would retain an archive here, so this check states neither that archives are write-once-locked nor that they are not. The policy is invalid either way.`,
      remediation: !enforces
        ? `${immutabilityRemedy(w.provider)} Then set a valid WORM policy (mode + positive retention days). Until the store enforces immutability, immutability is not actually protecting your archives.`
        : `Set a valid WORM policy (mode + positive retention days). The ${store} already enforces ${lock}, so no re-creation is needed; only the policy is stopping the engine arming the window you intended.`,
    };
  }

  // ARMED but the bucket does not enforce, or enforcement could not be confirmed: the dangerous gap. Two
  // readings with OPPOSITE consequences, and both lines below are corrections. The rule, its live evidence
  // and the controls are in test/validate-worm-refusal-parity.ts, which grades these sentences and the
  // signed report's together; read it before editing either.
  //   NOT-ENFORCED: the store REFUSES the lock-bearing write (R2 501, AWS S3 ObjectLockConfigurationNot-
  //   FoundError), so the destination holds no archives. This said the headers were ignored and archives
  //   unprotected, false twice over, and the console renders it to a customer as "Observed".
  //   CANNOT-CONFIRM now includes an ABSENT bucketEnforces. The test read === "unknown", so an absent
  //   verdict (what gatherWormSlice returns on ANY probe fault) took the definite branch and asserted the
  //   bucket was not created with Object-Lock, from a probe that never ran.
  if (!enforces) {
    const notEnforced = w.bucketEnforces === false;
    return {
      ...base,
      auto: "fail",
      detail: notEnforced
        ? `A WORM policy is configured, but the destination ${store} does NOT enforce ${lock}. ${immutabilityEnableWhen(w.provider)} The store REFUSES every write that carries the retention headers, so no archive is stored on this destination at all.`
        : `A WORM policy is configured, but the engine could not confirm the destination ${store} enforces ${lock} (the ${store} may not have been created with it, or the probe could not read the configuration). Archives may NOT actually be protected, do not rely on WORM until this is confirmed.`,
      remediation: notEnforced
        ? `${immutabilityRemedy(w.provider)} Until you do one of those, every backup written to this destination is refused by the store.`
        : `${immutabilityRemedy(w.provider)} Then set a valid WORM policy (mode + positive retention days). Until the store enforces immutability, immutability is not actually protecting your archives.`,
    };
  }

  // NOTHING ARMED on an enforcing bucket: no policy is configured at all, so whether any archive here is
  // retained turns entirely on the bucket's own default rule. Nothing was intended, so none of these is the
  // dangerous gap and none of them fails; what differs is what the detail is entitled to say.
  if (bucketRule === true) {
    return {
      ...base,
      auto: "pass",
      detail: `WORM enforced: the destination ${store} enforces ${lock} (${modeLabel}${daysLabel}). A compromised delete-credential cannot hard-delete or overwrite an archive within its retention window. No WORM policy is configured, so this rests entirely on the ${store}'s own default retention rule and the engine writes no retention header of its own here.`,
      remediation:
        `No action required; store-enforced WORM is in force through the ${store}'s own default retention rule. Verify that rule meets your policy, and set a WORM policy if you want the engine to arm the window itself rather than inherit it.`,
    };
  }
  if (bucketRule === false) {
    return {
      ...base,
      auto: "pass",
      detail:
        `WORM (${lock}) is not configured (it is opt-in). The destination ${store} has ${lock} switched on, but it carries no default retention rule and the engine writes no retention header of its own, so an archive written here carries no retention window and a compromised delete-credential can hard-delete it. ${lock} enabled on a ${store} does not retain anything by itself. Archives remain tamper-evident (signed, hash-chained RUNLOG).`,
      remediation:
        `Set a WORM policy (mode + retention days) so the engine arms a retention header on every archive, or give the ${store} a default retention rule. The ${store} already has ${lock} enabled, so it does not need re-creating.`,
    };
  }
  return {
    ...base,
    auto: "pass",
    detail:
      `WORM (${lock}) is not configured (it is opt-in) and the engine writes no retention header of its own. The destination ${store} enforces ${lock}, but whether it applies a default retention rule could not be read, and that rule is the only thing that would retain an archive here, so this check states neither that archives are write-once-locked nor that they are not. Archives remain tamper-evident (signed, hash-chained RUNLOG).`,
    remediation:
      `Set a WORM policy (mode + retention days) so immutability rests on a retention window the engine arms and observes, rather than on a ${store} default rule this check could not read.`,
  };
}
