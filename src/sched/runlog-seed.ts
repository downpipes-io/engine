// The recovery path's RUNLOG seed, as the scheduler DO keeps it.
//
// WHAT IT IS. After a control-plane loss the rebuilt DO holds no runlogCounter, while the destination bucket
// still holds a signed RUNLOG. The cron health pass reads that RUNLOG (format/freshness.ts
// readVerifiedRunlogSeed) and posts the outcome here: either the highest index the verified document carries,
// or the closed reason it could not be read. A seed raises the counter, so the next trigger allocates past
// the document. Without one, the next trigger allocates index 1 into a document that already holds it: the
// writer appends a duplicate index, and every later freshness check of that destination reports a rollback.
//
// WHAT IT RECORDS. The outcome, when it was first and last read, and how many reads were made, so the
// recovery status and the support pack can say whether the counter was anchored and why not. The record
// holds a closed reason, integers and timestamps only.
//
// WHEN IT HOLDS ALLOCATION. Two reasons hold every run-index allocation until a later read succeeds:
//   - "unreadable": a read threw. The fault is in the read, not the document, so a retry can succeed with no
//     operator action. A run that reads the same bucket would meet the same fault.
//   - "no-signer": the engine has no usable SIGNER_PRIVATE. No run can seal without one, so holding costs no
//     run; once a signer is set, the next read verifies the document before any run allocates.
// The health pass re-reads every tick while no seed is recorded, and a seed releases the hold.
//
// The other reasons do not hold. "absent" is a bucket with no RUNLOG, where no index can collide.
// "unparsable", "sig-absent" and "sig-invalid" are a document every run already refuses before it appends
// (seal/pipeline.ts verifyRunlogForWrite), so no index can collide there either; an Owner decides the document
// through the attended re-sign (POST /admin/runlog/resign). The per-tick re-read still runs for them: once the
// document verifies, the counter moves past its highest index.

import { RUNLOG_NO_SEED_REASONS, type RunlogNoSeedReason, type RunlogSeedResult } from "../format/freshness.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

const RUNLOG_SEED_KEY = "controlPlaneRunlogSeed";
const RUNLOG_COUNTER_KEY = "runlogCounter";
const COUNT_MAX = 1_000_000_000;

// The reasons that hold allocation (see the header).
export const RUNLOG_SEED_HOLD_REASONS: ReadonlySet<RunlogNoSeedReason> = new Set<RunlogNoSeedReason>(["unreadable", "no-signer"]);
const NO_SEED_REASON_SET: ReadonlySet<string> = new Set(RUNLOG_NO_SEED_REASONS);

/** The stored outcome of the recovery-path RUNLOG read. Exactly one of seed and noSeed is set. */
export interface RunlogSeedRecord {
  seed?: number; // the verified document's highest index, applied to runlogCounter as a monotonic max
  noSeed?: RunlogNoSeedReason; // why no seed was established, on the latest read
  firstNoSeed?: RunlogNoSeedReason; // the reason on the FIRST read, kept after a later read establishes a seed
  allocatedBeforeSeed?: number; // runlogCounter when a late seed was applied: indices up to it were allocated unanchored
  firstAt: string; // the first read (the recovery latch)
  at: string; // the latest read
  reads: number; // reads made: the latch read plus each per-tick retry
  heldAllocations?: number; // trigger calls refused while a hold reason stood
}

interface SeedStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

/**
 * parseRunlogSeedResult validates a seed outcome posted to the DO. It returns null for anything outside the
 * closed shape, so a malformed body records nothing.
 *
 * @param v - the posted value.
 * @returns the outcome, or null.
 */
export function parseRunlogSeedResult(v: unknown): RunlogSeedResult | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as { seed?: unknown; noSeed?: unknown };
  if (o.seed !== undefined && o.noSeed !== undefined) return null;
  if (typeof o.seed === "number" && Number.isSafeInteger(o.seed) && o.seed >= 0) return { seed: o.seed };
  if (typeof o.noSeed === "string" && NO_SEED_REASON_SET.has(o.noSeed)) return { noSeed: o.noSeed as RunlogNoSeedReason };
  return null;
}

/**
 * readRunlogSeedRecord returns the stored outcome, or null when the recovery path never read a RUNLOG.
 *
 * @param storage - the DO storage.
 * @returns the record, or null.
 */
export async function readRunlogSeedRecord(storage: SeedStorage): Promise<RunlogSeedRecord | null> {
  const r = await storage.get<RunlogSeedRecord>(RUNLOG_SEED_KEY);
  return r && typeof r === "object" ? r : null;
}

/**
 * recordRunlogSeed stores one read's outcome. A seed raises runlogCounter to at least the seed and is kept
 * from then on: a later no-seed outcome never replaces an established seed.
 *
 * @param storage - the DO storage.
 * @param result - the outcome of this read.
 */
export async function recordRunlogSeed(storage: SeedStorage, result: RunlogSeedResult): Promise<void> {
  const prior = await readRunlogSeedRecord(storage);
  if (prior?.seed !== undefined && "noSeed" in result) return;
  const now = nowMillisISO();
  const firstNoSeed = prior === null ? ("noSeed" in result ? result.noSeed : undefined) : (prior.firstNoSeed ?? prior.noSeed);
  const base = {
    firstAt: prior?.firstAt ?? now,
    at: now,
    reads: Math.min(COUNT_MAX, (prior?.reads ?? 0) + 1),
    ...(firstNoSeed !== undefined ? { firstNoSeed } : {}),
    ...(prior?.heldAllocations !== undefined ? { heldAllocations: prior.heldAllocations } : {}),
  };
  if ("seed" in result) {
    const current = (await storage.get<number>(RUNLOG_COUNTER_KEY)) ?? 0;
    if (result.seed > current) await storage.put(RUNLOG_COUNTER_KEY, result.seed);
    // A seed that arrives after a no-seed read may find indices already allocated against the unanchored
    // counter; those are the ones that can repeat an index the RUNLOG already held.
    const allocatedBeforeSeed = prior?.noSeed !== undefined && current > 0 ? current : prior?.allocatedBeforeSeed;
    await storage.put(RUNLOG_SEED_KEY, { seed: Math.max(result.seed, prior?.seed ?? 0), ...base, ...(allocatedBeforeSeed !== undefined ? { allocatedBeforeSeed } : {}) } satisfies RunlogSeedRecord);
    return;
  }
  await storage.put(RUNLOG_SEED_KEY, { noSeed: result.noSeed, ...base } satisfies RunlogSeedRecord);
}

/**
 * runlogSeedHold is the allocation check trigger() makes. It returns the hold reason and counts the refused
 * allocation, or null when allocation may proceed.
 *
 * @param storage - the DO storage.
 * @returns the reason allocation is held, or null.
 */
export async function runlogSeedHold(storage: SeedStorage): Promise<RunlogNoSeedReason | null> {
  const rec = await readRunlogSeedRecord(storage);
  if (rec?.noSeed === undefined || !RUNLOG_SEED_HOLD_REASONS.has(rec.noSeed)) return null;
  await storage.put(RUNLOG_SEED_KEY, { ...rec, heldAllocations: Math.min(COUNT_MAX, (rec.heldAllocations ?? 0) + 1) } satisfies RunlogSeedRecord);
  return rec.noSeed;
}
