// beacon-config.ts -- the ONE predicate for "is the opt-in vendor beacon actually on", shared by the
// emitter (cron/beacon-emit.ts) and the posture no-custody check (admin/router-posture.ts) so the two can
// never disagree about whether this engine is phoning home.
//
// The beacon payload carries accountTag as its key and the control plane cannot attribute a beacon without
// it, so all three of BEACON_URL, BEACON_INGEST_KEY and CF_ACCOUNT_ID must be set for the beacon to be
// considered configured -- the emitter's own condition, mirrored here rather than relaxed, so correcting
// the posture report never changes what goes on the wire.
//
// PRESENCE IS READ WITH trim(): a whitespace-only value is not a configured value under any reading, so
// this is the one place all readers (the emitter, the posture check, and noteBeaconEnv in
// cron-fault-ledger.ts) agree on what "set" means.
//
// A LEAF: it takes the three values, not an Env, and imports nothing. cron/beacon-emit.ts reaches
// admin/router.ts for doURL, and admin/router.ts reaches admin/router-posture.ts, so exporting this from
// the emitter would have closed a cycle through the very module that needs to read it.
// It is a TYPE GUARD rather than a bare boolean, so after this returns true the three vars are `string` to
// the typechecker, not `string | undefined`, and a later edit that requires one cannot quietly compile
// against an optional.
export function beaconConfigured<T extends { BEACON_URL?: unknown; BEACON_INGEST_KEY?: unknown; CF_ACCOUNT_ID?: unknown }>(
  env: T,
): env is T & { BEACON_URL: string; BEACON_INGEST_KEY: string; CF_ACCOUNT_ID: string } {
  const set = (v: unknown): boolean => typeof v === "string" && v.trim() !== "";
  return set(env.BEACON_URL) && set(env.BEACON_INGEST_KEY) && set(env.CF_ACCOUNT_ID);
}
