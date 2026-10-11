// lock-facts.ts -- the closed bucket-lock facts a destination row stores and the support pack carries.
//
// The save-time probe reads the bucket's Object-Lock configuration. Besides the enabled verdict and the
// default-retention boolean it already kept, it learns the default retention MODE and PERIOD. Those two are
// closed facts: a member of LOCK_DEFAULT_MODES and a whole number of days. They describe the bucket's own rule,
// never a key, a bucket name or any operator text, and each write boundary re-gates them with this module so
// no path can store a value outside the vocabulary.
//
// LEAF module: it imports nothing, so the router, the scheduler DO and the pack projection share one gate.

/** The default retention mode a lock-enabled bucket reports. "none" is a lock with no default rule. */
export const LOCK_DEFAULT_MODES = ["GOVERNANCE", "COMPLIANCE", "none"] as const;
/** One member of LOCK_DEFAULT_MODES: the closed default retention mode a destination row stores. */
export type LockDefaultMode = (typeof LOCK_DEFAULT_MODES)[number];
const LOCK_DEFAULT_MODE_SET: ReadonlySet<string> = new Set(LOCK_DEFAULT_MODES);

// LOCK_DAYS_MAX bounds the period: S3 caps a default retention at 100 years (36,500 days).
const LOCK_DAYS_MAX = 36_500;

/**
 * gateLockMode returns the value when it is a member of LOCK_DEFAULT_MODES, else undefined.
 *
 * @param v - an untrusted value.
 * @returns the closed mode, or undefined.
 */
export function gateLockMode(v: unknown): LockDefaultMode | undefined {
  return typeof v === "string" && LOCK_DEFAULT_MODE_SET.has(v) ? (v as LockDefaultMode) : undefined;
}

/**
 * gateLockDays returns the value when it is a whole number of days in 1..LOCK_DAYS_MAX, else undefined.
 *
 * @param v - an untrusted value.
 * @returns the period in days, or undefined.
 */
export function gateLockDays(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= LOCK_DAYS_MAX ? v : undefined;
}

/**
 * gateLockFacts re-gates the mode and period beside the live verdict: they are kept only when the bucket reads
 * "enforced" (on any other verdict no lock applies, so a rule would describe nothing), and the period only when
 * the mode is GOVERNANCE or COMPLIANCE (a lock with no default rule has no period).
 *
 * @param objectLock - the stored live verdict.
 * @param mode - an untrusted mode.
 * @param days - an untrusted period in days.
 * @returns a spreadable object carrying the facts that survive.
 */
export function gateLockFacts(objectLock: unknown, mode: unknown, days: unknown): { lockMode?: LockDefaultMode; lockRetentionDays?: number } {
  if (objectLock !== "enforced") return {};
  const lockMode = gateLockMode(mode);
  if (lockMode === undefined) return {};
  const lockRetentionDays = lockMode === "none" ? undefined : gateLockDays(days);
  return { lockMode, ...(lockRetentionDays !== undefined ? { lockRetentionDays } : {}) };
}
