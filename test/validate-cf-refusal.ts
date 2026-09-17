// The refusal classifier, pinned against messages a real Cloudflare account actually returned.
//
// WHY THESE VECTORS AND NOT INVENTED ONES
// ---------------------------------------
// Every string below was copied from a live run against the proving account. That matters more than usual
// here: the classifier exists because a hand-written pattern was wrong about most of what it saw, and
// replacing it with a second hand-written pattern tested against hand-written examples would prove only
// that the two agree with each other.
//
// The ORDER of the checks is the load-bearing part, so it is asserted directly. A malformed body is refused
// before the endpoint reaches its entitlement check, so a body error must win over an entitlement match.
// Getting that backwards is how two DLP surfaces were recorded as entitlement-blocked on evidence that
// never touched the entitlement.
//
// Offline and hermetic: no credentials, no network. Runs in `validate`.

import { classifyRefusal, type RefusalClass } from "./cf-refusal.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function is(message: string, want: RefusalClass, why: string): void {
  const got = classifyRefusal(message);
  const ok = got === want;
  console.log(ok ? `  ok   ${why}` : `  FAIL ${why}\n       got "${got}", want "${want}"\n       message: ${message.slice(0, 120)}`);
  if (!ok) failures++;
}

console.log("-- the account declining, in Cloudflare's several spellings --");
is("Zone not entitled to this functionality", "account", "the plain 'not entitled' wording");
is("Account is not entitled to create ipfs hostnames.", "account", "not entitled, account scope");
is("dex.api.entitlements.missing", "account", "a machine-readable entitlement code, which the old pattern missed");
is("Forbidden", "account", "a bare Forbidden, which the old pattern missed and called a create refusal");
is("Forbidden.", "account", "a bare Forbidden with a full stop");
is("IP based proxy endpoints are limited to enterprise accounts.", "account", "an enterprise-only feature, which the old pattern missed");
is("Sorry, this zone setting is not available for your plan type.", "account", "the plan-type wording the ask-probe surfaced");
// A TOKEN-TYPE limitation, not a plan one, and the reason this vector exists: unifying three patterns into
// one dropped this term, and the live sweep immediately reported page-rules as a DEFECT of ours. It is the
// account's token shape, not our reader.
is("Page Rules endpoint does not support account owned tokens.", "account", "an endpoint refusing account-owned tokens");
is("malformed actor email claim", "account", "a token-shape refusal seen on this account");
// The token lacking a product scope. Seen when standing up the Magic Network Monitoring prerequisite on an
// account whose token does not carry that scope: not a defect in any writer, and not something a different
// body would fix, so it belongs with the other credential-shaped refusals rather than in "unknown".
is("Authentication error", "account", "a token missing a product scope");
is("Invalid API Token", "account", "a token the API will not accept at all");

console.log("\n-- quota-zero: an entitlement stated as a number --");
is("Asset limited reached, max assets: 0", "account", "an allowance of zero assets");
is("1 validation errors: exceeded the maximum number of rules in the phase http_response_page_shield: 1 out of 0", "account", "an allowance of zero rules");
// The distinction that keeps this honest: a quota that is merely FULL is not an entitlement, and a real
// writer hitting it is something an operator needs to see rather than have absorbed as somebody else's fault.
is("exceeded the maximum number of rules in the phase http_request_firewall_custom: 51 out of 50", "unknown", "a FULL quota is NOT treated as an entitlement");

console.log("\n-- our own malformed bodies, which must WIN over an entitlement match --");
is("invalid json: bad json data: UUID parsing failed: invalid character: found `p` at 1 at line 1 column 25", "our-body", "a UUID the body got wrong");
is('invalid json: bad json data: invalid type: string "dp-v60491", expected internally tagged enum EmailRuleAction at line 1 column 21', "our-body", "a string where an enum was expected");
is("invalid json: bad json data: missing field `sensitivity_levels` at line 1 column 70", "our-body", "a required field the body omitted");
is("The value provided for origin_max_http_version setting is not valid. The value must either be `1` or `2`", "our-body", "a value outside the legal set");
is("Unrecognized zone setting name: origin_post_quantum_encryption", "our-body", "a setting name we got wrong, which reads like a missing feature");
// THE ORDERING ASSERTION. Both signals present; the body must win, because the request never reached the
// entitlement check.
is("invalid json: bad json data: missing field `x`; account is not entitled to this feature", "our-body", "a body error OUTRANKS an entitlement in the same message");

console.log("\n-- preconditions: account STATE rather than plan, and possibly satisfiable --");
is("Invalid rule request body: rule can not be added without initial account configuration", "precondition", "a rule needing the account configured first");

console.log("\n-- anything else stays VISIBLE rather than absorbed --");
is("Invalid request", "unknown", "an opaque refusal is not guessed at");
is("HTTP 500", "unknown", "a server error is not called an entitlement");
is("connection reset", "unknown", "a transport failure is not called an entitlement");

console.log(failures === 0 ? "\nCF REFUSAL CLASSIFIER PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
