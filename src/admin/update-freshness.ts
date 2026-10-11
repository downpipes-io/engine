// The replay-protection check for the signed update channel: the freshness claim a channel carries, the
// engine's persisted watermark and the pure check that compares them.

// FreshnessClaim is the (sanitised) replay-protection metadata read off a signature-verified channel: the
// monotonic sequence and/or the RFC-3339 issuedAt. Both optional (absent = no claim).
export interface FreshnessClaim {
  sequence?: number;
  issuedAt?: string;
  // The claim the resolver erased. loadVerifiedChannel sanitises a signed claim to well-typed-or-absent,
  // so a present-but-malformed field arrives here as `undefined` and this check cannot tell "the publisher
  // shipped a broken sequence" from "this is an ordinary freshness-less descriptor". The resolver sets
  // these flags on what it erased and records the malformed row itself (at the erasure, so it fires even
  // on an engine with no watermark yet); the check reads them only so it never files an erased claim under
  // the honestly-absent name. Booleans, never a value.
  sequenceMalformed?: boolean;
  issuedAtMalformed?: boolean;
}

// FreshnessState is the engine's persisted last-seen freshness watermark (advanced when a descriptor is
// promoted/ramped, setUpdatePending): the highest sequence and the latest issuedAt the engine has accepted.
// maxAgeMs is the OPT-IN staleness backstop (absent/<=0 = OFF, the default): when set, an issuedAt older than
// `now - maxAgeMs` is refused. It is opt-in precisely so it can NEVER false-positive on a legitimate but
// dormant channel (a vendor that has not shipped a new release in a while); the monotonic checks below carry
// the replay protection on their own and are false-positive-proof for a forward update.
export interface FreshnessState {
  lastSeq?: number;
  lastIssuedAt?: string;
  maxAgeMs?: number;
}

// FreshnessVerdict: ok (optionally with a warning the caller logs) or a typed rejection with a redaction-safe
// reason. A rejection is a hard refusal (the replay/superseded descriptor is never applied).
// degradations: the closed names of the replay-protection weakenings this verdict silently tolerated.
// The verdict itself is unchanged -- backward tolerance is deliberate -- but "was replay protection active
// when that update applied?" has an answer other than a shrug.
export type FreshnessVerdict = { ok: true; warn?: string; degradations?: string[] } | { ok: false; reason: string };

// checkChannelFreshness enforces replay protection on a signature-verified channel descriptor. It refuses
// a descriptor whose sequence REGRESSES below the last-seen sequence, whose issuedAt is OLDER than the
// last-applied issuedAt, or (opt-in maxAgeMs) whose issuedAt is older than the configured maximum age. The
// two monotonic checks are false-positive-proof for a forward update: a genuine newer descriptor carries a
// sequence >= and an issuedAt >= the last accepted, and an EQUAL value is allowed (a same-descriptor retry).
// Backward-tolerant: an ABSENT field is "no freshness claim" -> ok + a warning (NEVER a hard failure, so the
// current freshness-less channel still applies); a PRESENT, parseable field that regresses IS a hard refusal.
// Pure + total; `now` is injected so the validator drives the max-age branch deterministically.
export function checkChannelFreshness(claim: FreshnessClaim, state: FreshnessState, now: number): FreshnessVerdict {
  const warns: string[] = [];
  // The closed names of every replay-protection weakening this check silently tolerated. The verdict is
  // unchanged (a weakened claim is still applied: backward tolerance is deliberate); what changes is that the
  // weakening is now sayable.
  const degradations: string[] = [];
  // ---- sequence: monotonic, never regress (equal is allowed: a same-descriptor retry) ----
  const seq = claim.sequence;
  if (typeof seq === "number" && Number.isFinite(seq)) {
    if (typeof state.lastSeq === "number" && Number.isFinite(state.lastSeq) && seq < state.lastSeq) {
      return { ok: false, reason: `the signed channel's sequence ${seq} is older than the last-seen sequence ${state.lastSeq}; refusing a replayed or superseded update descriptor (nothing was changed)` };
    }
  } else if (typeof state.lastSeq === "number" && claim.sequenceMalformed !== true) {
    // A sequence was seen before but this descriptor declares none: replay protection on it is weaker (the
    // issuedAt/anti-rollback floor still apply). Warn, do not hard-fail (backward tolerance).
    // This branch fires only for a genuinely absent sequence. A claim the resolver erased (malformed) also
    // arrives here as undefined, and the resolver has already counted it, so it is excluded here: an erased
    // claim is never also reported as one the publisher never made.
    degradations.push("update-degraded-freshness-sequence-absent");
    warns.push("the signed channel declares no sequence though one was seen before; sequence-replay protection is weaker for this descriptor");
  }
  // ---- issuedAt: monotonic (never older than the last applied) + opt-in max-age ----
  const issuedAt = claim.issuedAt;
  if (typeof issuedAt === "string" && issuedAt.trim() !== "") {
    const t = Date.parse(issuedAt);
    if (Number.isNaN(t)) {
      // An unparseable issuedAt is silently ignored, so the anti-replay floor it exists to enforce simply
      // does not run for this descriptor, and the apply proceeds looking exactly like a clean one.
      degradations.push("update-degraded-freshness-issuedat-unparseable");
      warns.push("the signed channel declared an unparseable issuedAt; ignoring it for freshness (no usable claim)");
    } else {
      if (typeof state.lastIssuedAt === "string" && state.lastIssuedAt.trim() !== "") {
        const last = Date.parse(state.lastIssuedAt);
        if (!Number.isNaN(last) && t < last) {
          return { ok: false, reason: `the signed channel's issuedAt ${issuedAt} is older than the last-applied ${state.lastIssuedAt}; refusing a replayed or superseded update descriptor (nothing was changed)` };
        }
      }
      if (typeof state.maxAgeMs === "number" && state.maxAgeMs > 0 && now - t > state.maxAgeMs) {
        return { ok: false, reason: `the signed channel's issuedAt ${issuedAt} is older than the configured maximum age; refusing a stale update descriptor (nothing was changed)` };
      }
    }
  } else if (typeof state.lastIssuedAt === "string" && claim.issuedAtMalformed !== true) {
    // Same split as the sequence arm above. The descriptor made no timestamp claim at all, which is
    // the ordinary legacy state and not the publisher shipping a broken one.
    degradations.push("update-degraded-freshness-issuedat-absent");
    warns.push("the signed channel declares no issuedAt though one was seen before; timestamp-replay protection is weaker for this descriptor");
  }
  return {
    ok: true,
    ...(warns.length > 0 ? { warn: warns.join("; ") } : {}),
    ...(degradations.length > 0 ? { degradations } : {}),
  };
}
