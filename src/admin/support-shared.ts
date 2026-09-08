// Shared projection helpers for the support-pack gatherer siblings (support-sections-*.ts),
// the bundle assembler (support.ts) and the ingest-credential subsystem (support-ingest.ts):
// the pack-boundary clamps every gatherer applies to untrusted DO fields, plus the
// second-precision ISO timestamp the bundle and grant paths stamp. Moved verbatim out of
// support.ts when the gatherers were split into domain siblings; behaviour is unchanged.

export function nowIso(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export function clampTs(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v.slice(0, 40) : undefined;
}
export function clampInt(v: unknown, max = 1_000_000): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(max, Math.floor(v))) : undefined;
}

// clampNonNegInt projects an untrusted numeric field to a bounded non-negative integer for the pack (defence
// in depth over the DO's own clamping): a NaN/negative/huge value collapses to a safe int. Used by the
// scheduler-signals projection so every count/timestamp is redaction-safe by construction.
export function clampNonNegInt(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, Math.floor(v))) : 0;
}

// UNKNOWN_CODE is the single literal placeholder every closed-set gate in the pack collapses an
// out-of-vocabulary value to, instead of dropping the field (or the whole enclosing block) in silence.
// Silent omission would itself be an evidence bug: after a version skew between a DO writer and this pack
// builder (or an action/class rename), a field could vanish and the row would read as healthy. The
// placeholder keeps the redaction guarantee absolute (the raw value is discarded, never carried) while
// making drift itself legible, and the section's droppedUnknownCount says how often it happened. It
// matches the "unknown-code" literal support-sections-push.ts already establishes.
export const UNKNOWN_CODE = "unknown-code";

// gateClosed is the shared closed-set gate: a member rides verbatim, any other non-empty string collapses to
// UNKNOWN_CODE, and an absent/empty/non-string value stays absent (honest absence is NOT drift). Pure.
export function gateClosed(v: unknown, allowed: ReadonlySet<string>): string | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  return allowed.has(v) ? v : UNKNOWN_CODE;
}

// grantExpiryState reads a stored grant's expiry ONCE and reports readable/expired as two separate
// booleans, rather than the common idiom `Date.now() > Date.parse(grant.expiresAt)` (which answers
// false, i.e. "not expired", for any expiresAt that fails to parse). An expiry that cannot be read is
// not a credential known to be within its TTL -- that TTL is the only bound on a leaked bearer
// credential presented by an unauthenticated caller -- so an unparseable value is treated as a REFUSAL
// (its own closed outcome), never as "live" or silently as "expired". No engine writer can itself
// produce an unparseable value here (mintIngestCredential clamps its TTL and formats through
// Date#toISOString, and the DO's record-pull never touches the field), so an unreadable value means a
// corrupted write, a half-flushed storage page or a hand-edited record, and the recovery is one
// owner-driven re-mint.
export function grantExpiryState(expiresAt: unknown, now: number = Date.now()): { readable: boolean; expired: boolean } {
  const ms = typeof expiresAt === "string" ? Date.parse(expiresAt) : Number.NaN;
  // Number.isFinite is the guard the four siblings use, and it is the one that matters: `> NaN` is false, so
  // an ordinary comparison cannot tell an unreadable expiry from a healthy one.
  if (!Number.isFinite(ms)) return { readable: false, expired: false };
  return { readable: true, expired: now > ms };
}
