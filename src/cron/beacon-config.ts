// beacon-config.ts -- the ONE predicate for "is the opt-in vendor beacon actually on".
//
// It exists because two places computed it and disagreed. cron/beacon-emit.ts requires BEACON_URL,
// BEACON_INGEST_KEY and CF_ACCOUNT_ID; admin/router-posture.ts computed the beacon-off posture input from
// the first two alone. On an estate with the two beacon vars set and CF_ACCOUNT_ID unset, the emitter
// returned without sending a byte while the posture screen failed the no-custody check and told the
// customer "the vendor beacon is enabled; the engine reports usage to the vendor".
//
// THAT IS THE WRONG DIRECTION FOR A FALSE READING TO RUN. Every other classification fault in this engine
// tells a customer something of theirs is broken when it is fine. This one accused our own product of
// phoning home, on the no-custody claim, which is the central promise, and it did so on a screen the
// customer reads as evidence.
//
// The emitter's condition is the correct one and it is the one mirrored here, rather than the reverse.
// The beacon payload carries accountTag as its key and the control plane cannot attribute a beacon
// without it, so an emission with no account tag is not a beacon. And relaxing the emitter instead would
// make a currently-silent estate start phoning home, which is a policy change dressed as a bug fix;
// correcting the report changes no bytes on the wire.
//
// PRESENCE IS READ WITH trim(), which is the third reading of these same vars and was a fourth
// disagreement. cron-fault-ledger.ts noteBeaconEnv, the diagnostic that tells an operator which of the
// three are set, has always trimmed; the emitter's gate tested `!== ""`. So a whitespace-only BEACON_URL
// was reported to the operator as absent while the emitter treated it as configured and attempted a POST
// to it. A value that is only whitespace is not a configured value under any of the three readings, so
// they now share one.
//
// A LEAF: it takes the three values, not an Env, and imports nothing. cron/beacon-emit.ts reaches
// admin/router.ts for doURL, and admin/router.ts reaches admin/router-posture.ts, so exporting this from
// the emitter would have closed a cycle through the very module that needs to read it.
// It is a TYPE GUARD rather than a bare boolean so the emitter keeps the narrowing its inline condition
// used to give it: after this returns true the three vars are `string` to the typechecker, not
// `string | undefined`, and a later edit that requires one cannot quietly compile against an optional.
export function beaconConfigured<T extends { BEACON_URL?: unknown; BEACON_INGEST_KEY?: unknown; CF_ACCOUNT_ID?: unknown }>(
  env: T,
): env is T & { BEACON_URL: string; BEACON_INGEST_KEY: string; CF_ACCOUNT_ID: string } {
  const set = (v: unknown): boolean => typeof v === "string" && v.trim() !== "";
  return set(env.BEACON_URL) && set(env.BEACON_INGEST_KEY) && set(env.CF_ACCOUNT_ID);
}
