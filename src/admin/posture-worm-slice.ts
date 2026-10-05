// The WORM slice parser for the scheduler Durable Object's POST /posture, moved out of
// sched/scheduler-do-observability.ts. That mixin sits at its max-lines ceiling, and the
// parser grew when the slice gained provider and writtenDestinations. It is pure and reads only the slice
// shape, so it is a leaf beside the type it produces. The DO method delegates to it unchanged.
//
//

import type { PostureWormInput } from "./posture-types.ts";

// parsePostureWormSlice bounds the router-forwarded WORM observable state for the immutability check.
// It returns undefined when nothing usable was forwarded (an older router, or no destination to probe),
// so the check falls back to the honest not-configured reading rather than a fabricated verdict. Every
// field is read defensively: configured/misconfigured default false (the safe "off" reading), the modes
// are accepted only as the two known literals, days only as a positive integer, and bucketEnforces only
// as true / false / "unknown" (any other value is dropped, so an absent probe never reads as enforcing).
export function parsePostureWormSlice(raw: unknown): PostureWormInput | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const w = raw as Record<string, unknown>;
  const mode = w.mode === "governance" || w.mode === "compliance" ? (w.mode as "governance" | "compliance") : undefined;
  const probeMode = w.probeMode === "governance" || w.probeMode === "compliance" ? (w.probeMode as "governance" | "compliance") : undefined;
  const retentionDays = typeof w.retentionDays === "number" && Number.isInteger(w.retentionDays) && (w.retentionDays as number) > 0 ? (w.retentionDays as number) : undefined;
  const probeDays = typeof w.probeDays === "number" && Number.isInteger(w.probeDays) && (w.probeDays as number) > 0 ? (w.probeDays as number) : undefined;
  // bucketEnforces: only true, false, or the literal "unknown" are honoured; anything else (or absent)
  // is left undefined so the check never reads a missing probe as enforcing (the safe cannot-confirm path).
  const be = w.bucketEnforces;
  const bucketEnforces = be === true || be === false ? be : be === "unknown" ? "unknown" : undefined;
  // defaultRetention: honoured only as a real boolean AND only alongside an enforcing bucket, which is
  // the only state the probe sets it in. A default-retention claim on a bucket that does not read as
  // enforcing is not a state the router can produce, so it is dropped rather than carried.
  const defaultRetention = bucketEnforces === true && typeof w.defaultRetention === "boolean" ? w.defaultRetention : undefined;
  // provider names the default destination's store, which decides the remedy wording. It was dropped
  // here, so the live check always fell back to the S3 wording; it is carried when it is a known value.
  const provider = w.provider === "r2" || w.provider === "s3" || w.provider === "gcs" || w.provider === "azure" ? (w.provider as "r2" | "s3" | "gcs" | "azure") : undefined;
  // writtenDestinations: "unread", or three bounded counts where compliance <= inForce <= total. Any other
  // shape is dropped, which leaves the evidence pack to the default destination's reading.
  const wd = w.writtenDestinations;
  const count = (v: unknown): number | undefined => (typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 10_000 ? v : undefined);
  let writtenDestinations: PostureWormInput["writtenDestinations"];
  if (wd === "unread") writtenDestinations = "unread";
  else if (typeof wd === "object" && wd !== null) {
    const r = wd as Record<string, unknown>;
    const total = count(r.total);
    const inForce = count(r.inForce);
    const compliance = count(r.compliance);
    if (total !== undefined && inForce !== undefined && compliance !== undefined && compliance <= inForce && inForce <= total) {
      writtenDestinations = { total, inForce, compliance };
    }
  }
  return {
    configured: w.configured === true,
    misconfigured: w.misconfigured === true,
    ...(provider !== undefined ? { provider } : {}),
    ...(writtenDestinations !== undefined ? { writtenDestinations } : {}),
    ...(mode !== undefined ? { mode } : {}),
    ...(retentionDays !== undefined ? { retentionDays } : {}),
    ...(bucketEnforces !== undefined ? { bucketEnforces } : {}),
    ...(probeMode !== undefined ? { probeMode } : {}),
    ...(probeDays !== undefined ? { probeDays } : {}),
    ...(defaultRetention !== undefined ? { defaultRetention } : {}),
  };

}
