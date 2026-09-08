import type { ShardRecord } from "../format/manifest.ts";
import { log } from "../log.ts";
import type { CfConfigSurface } from "../sources/cf-config-surfaces.ts";
import { RESERVED_REASON, type Resolved } from "./restore-sinks.ts";
import type { RestorePlan, RestoreResult, RestoreSkipped } from "./restore-types.ts";

// A planned data write: a resolved sink plus its record. cf-config and media re-uploads have their own
// plan shapes (configPlan / mediaPlan) because they write through Cloudflare APIs, not a RestoreSink.
export interface RestorePlanState {
  skipped: RestoreSkipped[];
  // How many of `skipped` were REFUSED at sink resolution (a missing/misnamed target binding, or a record
  // type with no write sink) rather than narrowed out by the operator's own selector or recordName. The
  // plan's ok/complete read THIS, never skipped.length: a granular one-of-three restore is a correct plan
  // that happens to skip two, whereas a record the engine could not find a home for is a fixable
  // misconfiguration the operator must see before authorising a write-back. Both shapes shared one array,
  // which is how a plan that could write NOTHING came to report ok:true and complete:true.
  sinkUnresolved: number;
  outOfBand: RestoreSkipped[];
  plan: Array<{ rec: ShardRecord; resolved: Resolved }>;
  configPlan: Array<{ rec: ShardRecord; surface: CfConfigSurface }>;
  // The cf-config identity record, when the archive has one. It is metadata rather than a restorable
  // surface, so it never enters configPlan, but the zone guard (B5) needs its value to learn which zone the
  // archive was captured from. Carried here so the dry-run and the apply read the same record rather than
  // each scanning for it.
  cfIdentityRec?: ShardRecord;
  mediaPlan: Array<{ rec: ShardRecord; type: "images" | "stream"; id: string }>;
}

// A reserved-binding refusal short-circuits the WHOLE restore before any write. buildRestorePlan returns
// it instead of a plan so runRestore can render it as the confirm/dry-run failure shape and write nothing.
export interface ReservedRefusal {
  reserved: true;
  recName: string;
}

// makeReservedRefusalResult renders the single reserved-binding refusal shape both classify-time and
// resolve-time poisoning use, so a confused-deputy attempt is refused identically wherever it is detected.
export function makeReservedRefusalResult(confirm: boolean, runId: string, isLatest: boolean, recName: string): RestoreResult | RestorePlan {
  log("error", `restore ${runId} refused: ${RESERVED_REASON}`);
  return confirm
    ? { ok: false, runId, mode: "applied", recordsVerified: 0, recordsRestored: 0, bytesRestored: 0, isLatest, failures: [{ name: recName, reason: RESERVED_REASON }], reason: RESERVED_REASON }
    : { ok: false, runId, mode: "dry-run", recordsVerified: 0, isLatest, plannedWrites: 0, bytes: 0, sample: [], skipped: [{ name: recName, reason: RESERVED_REASON }], reason: RESERVED_REASON };
}
