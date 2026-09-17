// Shared projection helpers for the support-pack gatherer siblings (support-sections-*.ts),
// the bundle assembler (support.ts) and the ingest-credential subsystem (support-ingest.ts):
// the pack-boundary clamps every gatherer applies to untrusted DO fields, plus the
// second-precision ISO timestamp the bundle and grant paths stamp.

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

// UNKNOWN_CODE is the single literal PLACEHOLDER every closed-set gate in the pack collapses an out-of-
// vocabulary value to, instead of dropping the field (or the whole enclosing block) in silence.
// Silent omission is itself an evidence bug: after a version skew between a DO writer and this pack builder
// (or an action/class rename), the field simply VANISHES and the row reads as healthy -- restore tests fail
// for weeks with no lastRestoreTestReason, a new amnesia-probe class drops the whole probe block, a new SSO
// code never rides. The placeholder keeps the redaction guarantee ABSOLUTE (the raw value is discarded, never
// carried) while making the DRIFT ITSELF legible, and the section's droppedUnknownCount says how often it
// happened. It deliberately matches the "unknown-code" literal support-sections-push.ts already established.
export const UNKNOWN_CODE = "unknown-code";

// gateClosed is the shared closed-set gate: a member rides verbatim, any other non-empty string collapses to
// UNKNOWN_CODE, and an absent/empty/non-string value stays absent (honest absence is NOT drift). Pure.
export function gateClosed(v: unknown, allowed: ReadonlySet<string>): string | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  return allowed.has(v) ? v : UNKNOWN_CODE;
}

// THE BEARER THAT CAN NEVER EXPIRE, AND THE FOUR READERS THAT AGREED WITH IT.
//
// Every reader of a stored grant's expiry ran the same idiom -- `Date.now() > Date.parse(grant.expiresAt)` --
// and Date.parse answers NaN for anything it cannot read, so EVERY comparison with it is false. A stored
// expiresAt that does not parse therefore read as NOT EXPIRED at all four sites at once: the pull/scrape GATE
// authenticated, the customer-facing view reported `expired: false`, and both pack blocks (the audit-feed and
// metrics grant states) wrote `expired: false` into the evidence bundle. A credential that can never expire,
// and no surface anywhere that disagrees with it -- on the ONE credential family that is presented by an
// unauthenticated caller from the public internet, and whose own mint comment promises it is "still expiring
// and re-mintable, never permanent".
//
// This is the same shape of corrupt stored governance record found elsewhere (approvals.ts, prune-approvals
// .ts, owner-action.ts and expiry.ts carry the equivalent check), and it is the same premise they carry: NO engine
// writer can produce an unparseable value here (mintIngestCredential clamps its TTL and formats through
// Date#toISOString, and the DO's record-pull is a read-modify-write that never touches the field), so the
// producer is a corrupted write, a half-flushed storage page or a hand-edited record, exactly as
// approvalTimestampUnparseable's own header says.
//
// THREE STATES, NEVER TWO. grantExpiryState reads the field ONCE and reports readable/expired separately,
// because collapsing "unreadable" into either "expired" or "live" is how the same idiom went wrong in the
// first place. The gate's third state is a REFUSAL and its own closed outcome, not a re-use of
// "credential-expired": an expiry that cannot be read is not a credential known to be within its TTL, that
// TTL is the only bound on a leaked bearer, and the recovery is one owner-driven re-mint whose cause the pack
// now names. The four siblings deliberately fail OPEN because a corrupt record must not strand a destructive
// restore mid-flight; nothing here is stranded, so this one fails CLOSED and says why.
export function grantExpiryState(expiresAt: unknown, now: number = Date.now()): { readable: boolean; expired: boolean } {
  const ms = typeof expiresAt === "string" ? Date.parse(expiresAt) : Number.NaN;
  // Number.isFinite is the guard the four siblings use, and it is the one that matters: `> NaN` is false, so
  // an ordinary comparison cannot tell an unreadable expiry from a healthy one.
  if (!Number.isFinite(ms)) return { readable: false, expired: false };
  return { readable: true, expired: now > ms };
}
