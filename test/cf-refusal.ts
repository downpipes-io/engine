// Whose fault is a Cloudflare refusal: the account's, ours, or unknown?
//
// WHY THIS IS ONE MODULE AND NOT THREE REGEXES
// --------------------------------------------
// Three live harnesses ask this question. live-cf-idempotence.ts and live-cf-singleton-prove.ts carried
// character-identical copies of one pattern, and live-cf-autoprove.ts carried a DIFFERENT and much narrower
// one. So the same refusal was classified differently depending on which harness saw it, and the narrow one
// was wrong about most of what it saw: on the proving account it called 14 surfaces CREATE-REFUSED, which
// reads as "our writer cannot create", when at least nine were the account declining outright.
//
// That is the same blur the singleton sweep was just fixed for. A report that cannot separate "we are
// broken" from "this plan does not include that feature" makes the unproven set look like debt when most
// of it is a fact about a free account, and it hides the few entries that ARE debt.
//
// THE CLASSES, AND WHY EACH ONE EXISTS
// ------------------------------------
//   account      The account, plan or token declines. Not a defect. Includes QUOTA-ZERO refusals, which
//                are entitlements wearing a number: "Asset limited reached, max assets: 0" and "exceeded
//                the maximum number of rules in the phase ...: 1 out of 0" both mean "not on this plan",
//                and neither says so in words the older patterns matched.
//   our-body     The request body is malformed or fails schema validation. Always ours, and worth its own
//                class because it MASKS whatever the real answer would have been: two DLP surfaces were
//                recorded as entitlement-blocked when the request never reached the entitlement check.
//   precondition Something must exist or be configured first. Neither a defect nor an entitlement; it is
//                a fact about the account's STATE rather than its plan, and it MAY be satisfiable.
//
//                "May" is doing real work there. A PRECONDITION CAN BE AN ENTITLEMENT IN DISGUISE, and
//                the only way to tell is to try to satisfy it. Two surfaces refused on 2026-07-27 with
//                textbook precondition wording, "No Zone Hold Found" and "Custom Nameserver set doesn't
//                exist", and both were recorded as prereq candidates on the strength of that wording.
//                Creating the missing object was then attempted for each: zone holds answered "only
//                available on Enterprise zones" and custom nameserver sets answered "not enabled for
//                your account". No amount of prereq work reaches either surface on that plan.
//
//                So the class is correct and the INFERENCE from it is not. Classifying a refusal as a
//                precondition says the account lacks an object, never that the account may have one.
//                Recording it as satisfiable without making the second call is a guess, and it is the
//                optimistic direction: it schedules work that cannot succeed and reads as a to-do rather
//                than as a closed answer.
//   unknown      Anything else. Deliberately NOT folded into "account": a broad pattern quietly absorbing
//                a real bug is how three entitlement verdicts in this work turned out to be our defects.
//
// Everything here is matched against Cloudflare's own words. Nothing infers from an HTTP status alone.

export type RefusalClass = "account" | "our-body" | "precondition" | "unknown";

// The account, its plan, or the token's scope declining. Deliberately narrow and enumerated: anything not
// listed is "unknown" and stays visible, rather than being absorbed as somebody else's problem.
//
// "not available to this account or zone" was missing while "not available for your plan type" was
// present, and both are Cloudflare stating an entitlement in its own words. The gap surfaced when the
// echo harness read a dns-settings refusal about Custom SOA records as a BODY defect and failed a run
// over it. Two spellings of one fact, and the narrow one had been enumerated while the other had not.
const ACCOUNT =
  /not entitled|entitlement|entitlements\.missing|not\s+(?:been\s+)?enabled|Plan level|plan type|has not been granted|do not have access|do not have permission|Unauthorized|unauthorized|Authorization Failure|forbidden|requires entitlement|Please enable|limited to enterprise|is limited to enterprise|not available for your plan|not available to this (?:account|zone)|upgrade your plan|does not support account owned tokens|malformed actor email claim|Authentication error|Invalid API [Tt]oken/i;

// Quota-zero: an allowance of nothing is an entitlement stated as a number. "1 out of 0" and "max assets: 0"
// are the two shapes seen on the proving account; both are anchored on the ZERO so a real quota that has
// merely been filled (say 50 of 50) is NOT swallowed as an entitlement, because that one is worth seeing.
const QUOTA_ZERO = /max [a-z ]*:\s*0\b|\b\d+ out of 0\b|limit of 0\b/i;

// The request body did not parse or did not satisfy the schema. Always ours.
// NOTE the absence of a bare "validation error". Cloudflare prefixes RULE-QUOTA refusals with a count,
// "1 validation errors: exceeded the maximum number of rules ...", so matching that phrase classified a
// zero-quota entitlement as our malformed body. The offline vectors caught it on the first run, which is
// the argument for pinning a classifier against real messages rather than invented ones.
const OUR_BODY = /invalid json|bad json data|missing field|expected .*enum|UUID parsing failed|invalid type: |is not valid\b|unrecognized (?:zone setting|field)|unknown field/i;

// Something has to exist or be configured first. A fact about account STATE, not plan.
const PRECONDITION = /without initial account configuration|must be configured|requires an existing|no .* configured|create .* first|does not exist/i;

export function classifyRefusal(message: string): RefusalClass {
  const m = message.replace(/\s+/g, " ");
  // OUR_BODY is tested FIRST on purpose. A malformed body is refused before the endpoint ever reaches its
  // entitlement check, so a message carrying both signals is telling us about our body, not their plan.
  // Getting this order wrong is precisely how dlp-data-classes and dlp-email-rules were recorded as
  // entitlement-blocked on evidence that never touched the entitlement.
  if (OUR_BODY.test(m)) return "our-body";
  if (QUOTA_ZERO.test(m)) return "account";
  if (ACCOUNT.test(m)) return "account";
  if (PRECONDITION.test(m)) return "precondition";
  return "unknown";
}
