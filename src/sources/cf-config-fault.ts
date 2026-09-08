// THE cf-config RESTORE-WRITE FAULT CLASSIFIER (support-pack gap G191).
//
// THE BUG THIS CLOSES. A cf-config restore applies each item individually and is FAIL-OPEN per item: an item
// the Cloudflare API rejects skips ITSELF, and the rest of the surface still applies. That is the right
// behaviour, and it is why "a DNS restore applied 180 of 200 records, why did 20 skip?" was unanswerable.
// Each skip carried a `reason` that is the RAW Cloudflare API message, prefix-stripped and sliced to 120
// characters -- a string that lives only in the HTTP response the operator may not have kept, that cannot be
// counted or grouped, that carries no HTTP status, and that (being a raw provider message) can never be put
// in a support pack. Worse, the apply's own summary keeps only `skipped: res.skipped.length`: even the text
// is discarded before anything durable is written, so ALL that survives an apply is an integer.
//
// The classes matter because they route to completely different remedies: a quota refusal means "your plan
// caps DNS records" (buy more, or prune), an entitlement refusal means "your plan does not include this
// surface at all" (nothing to do), a validation refusal means the snapshot's item is malformed (a real bug),
// and an auth refusal means the restore token lacks the edit scope (one line to fix, and it will have skipped
// EVERY item). An integer cannot distinguish "your plan is capped" from "your token is wrong".
//
// REDACTION (binding, NO-CUSTODY). classifyCfWriteSkip READS the Cloudflare message ONLY to SELECT a member
// of the closed vocabulary and RETURNS that member. The message itself -- which can embed the account id, the
// zone, a hostname, a record content value, a token hint or an internal request id -- is never returned and
// never recorded. It stays exactly where it is today: in the live HTTP response to the operator who ran the
// restore, and nowhere else.

// CF_WRITE_SKIP_CLASSES is the CLOSED vocabulary for WHY one cf-config item did not apply.
//   auth               - the token was rejected or lacks the edit scope for this surface (401/403). It will
//                        have skipped EVERY item, which is itself the diagnosis.
//   entitlement        - the account's PLAN does not include this surface or feature. Benign and permanent:
//                        nothing to fix, and the restore is complete with respect to the account.
//   quota              - the account is AT its plan limit for this resource (too many records/rules). The
//                        item is valid; there is simply no room for it.
//   validation         - the API refused the item's CONTENT as malformed/invalid. This is the class that can
//                        indicate a real writer bug, and the only one that should ever be escalated.
//   conflict           - an item that already exists / collides with a live one (a duplicate).
//   no-live-id         - the snapshot item CHANGED but the live item carries no id to update in place, so
//                        there is nothing to PUT to (an engine-side structural skip, not an API refusal).
//   no-live-phase      - no live ruleset exists for this phase; creating a phase entrypoint is a reprovision
//                        concern, so the restore reports it rather than blind-creating it.
//   rate-limited       - a 429 that survived: transient, and the item should simply be retried.
//   api-unavailable    - a 5xx / network fault: a Cloudflare-side outage, not a customer misconfiguration.
//   other              - residual. Deliberately last, so an unrecognised refusal is never MISLABELLED as one
//                        of the actionable classes above (a wrong class is worse than an honest unknown).
export const CF_WRITE_SKIP_CLASSES = [
  "auth",
  "entitlement",
  "quota",
  "validation",
  "conflict",
  "no-live-id",
  "no-live-phase",
  // live-only-rules: the live ruleset holds rules the snapshot does not, so applying the snapshot would
  // DELETE them. The restore contract is additive, so the apply is refused for that ruleset and each
  // live-only rule is named in the diff. Distinct from "conflict", which is two items colliding on a key:
  // here nothing collides, the live side simply has more, and the loss would be silent.
  "live-only-rules",
  "rate-limited",
  "api-unavailable",
  "other",
] as const;
export type CfWriteSkipClass = (typeof CF_WRITE_SKIP_CLASSES)[number];

/**
 * classifyCfWriteSkip coarsens a Cloudflare API write refusal into a closed CfWriteSkipClass. It reads the
 * message ONLY to select a member and RETURNS that member; the message never leaves this function.
 *
 * ORDER is load-bearing. Entitlement is tested BEFORE quota and auth: a plan gate ("not available on your
 * plan") often also mentions "forbidden", and mislabelling a benign, permanent plan gate as a fixable auth
 * fault sends the customer to rotate a token that is perfectly good. Quota is tested BEFORE validation for
 * the same reason: "limit exceeded" is not a malformed item, and telling a customer their DNS record is
 * invalid when their plan is simply full is the worst possible answer.
 *
 * @param e - the thrown Cloudflare API fault (untrusted; may be anything).
 * @returns the closed class.
 */
export function classifyCfWriteSkip(e: unknown): CfWriteSkipClass {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (m === "") return "other";
  // A plan/entitlement gate FIRST: benign and permanent, and its message often also says "forbidden".
  if (/not available on your plan|upgrade your plan|not entitled|requires an? \w+ plan|plan does not (include|support)|available to enterprise/i.test(m)) return "entitlement";
  // A quota/limit refusal BEFORE validation: the item is valid, the account is simply full.
  if (/limit (of \d+ )?(exceeded|reached)|exceeded the (maximum|limit)|too many (records|rules|entries)|quota/i.test(m)) return "quota";
  if (/\b(401|403)\b|unauthori[sz]ed|forbidden|authentication|invalid api token|lacks? (the )?(edit )?(scope|permission)|permission denied/i.test(m)) return "auth";
  if (/\b429\b|rate ?limit|too many requests/i.test(m)) return "rate-limited";
  if (/\b5\d\d\b|internal server error|service unavailable|bad gateway|fetch failed|network|timed? ?out|socket/i.test(m)) return "api-unavailable";
  if (/already exists|duplicate|conflict|\b409\b/i.test(m)) return "conflict";
  if (/invalid|malformed|validation|is not valid|must be|required|\b400\b|unprocessable|\b422\b/i.test(m)) return "validation";
  return "other";
}

/**
 * cfSkipCounts folds a surface's per-item skips into a bounded {class: count} map (G191). This is what the
 * restore apply records in place of the bare `skipped: n` integer, and what a support pack can safely carry:
 * every key is a closed vocabulary member and every value is a count.
 *
 * @param skipped - the per-item skips a surface write returned.
 * @returns the {class: count} map (empty when nothing was skipped).
 */
export function cfSkipCounts(skipped: ReadonlyArray<{ cls?: CfWriteSkipClass }>): Partial<Record<CfWriteSkipClass, number>> {
  const out: Partial<Record<CfWriteSkipClass, number>> = {};
  for (const s of skipped) {
    const c = s.cls ?? "other";
    out[c] = (out[c] ?? 0) + 1;
  }
  return out;
}
