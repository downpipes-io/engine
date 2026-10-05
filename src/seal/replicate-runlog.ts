// The replication pass's RUNLOG reads, and the check that an entry agrees with its run's signed root. Kept
// beside replicate.ts so that file stays within its line budget.
//
// A RUNLOG is read once per destination per pass for each reader. Two readers use it. The TARGET's own read only seeds the
// set of runs that destination already holds (its RUNLOG is verified anyway where it is rewritten, at the
// replica append). A target RUNLOG that does not parse throws RunlogIntegrityError rather than reading as
// unreadable. The SOURCE read is VERIFIED, not merely parsed: an entry copied from it is appended and
// signed into a replica, so a RUNLOG whose signature this engine cannot vouch for must not be a source. A
// refusal reads as unreadable, which the pass records with its own reason. The floor is checked where a
// RUNLOG is rewritten (the replica append, through its lock), not here: an older signed RUNLOG holds only
// entries the engine signed, so copying them launders nothing, and the read stays inside the pass window.

import { noteSiteFault } from "../admin/site-faults.ts";
import type { Destination } from "../dest/types.ts";
import { parseRunlog, type RunlogEntry, type Signer } from "../format/writer.ts";
import { verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { RunlogIntegrityError, verifyRunlogForWrite } from "./pipeline.ts";

const RUNLOG_KEY = "_RECOVERY/RUNLOG";

export interface RunlogReaderCaches {
  runlogs: Map<string, RunlogEntry[] | null>;
  runlogBodies: Map<string, Uint8Array | null>;
  verifiedRunlogs: Map<string, RunlogEntry[] | null>;
}

export type RunlogReader = (id: string | undefined, dest: Destination, verified?: boolean) => Promise<RunlogEntry[] | null>;

export function makeRunlogReader(caches: RunlogReaderCaches, signer: Signer): RunlogReader {
  // readBody reads one destination's RUNLOG bytes once per pass: the bytes, "absent", or null when unreadable
  // this tick. The read goes through the metered destination, so it charges the budget automatically.
  const readBody = async (key: string, dest: Destination): Promise<Uint8Array | "absent" | null> => {
    if (caches.runlogBodies.has(key)) {
      const b = caches.runlogBodies.get(key) ?? null;
      return b !== null && b.length === 0 ? "absent" : b;
    }
    try {
      const rl = await dest.get(RUNLOG_KEY);
      caches.runlogBodies.set(key, rl ? rl.body : new Uint8Array(0));
      return rl ? rl.body : "absent";
    } catch (e) {
      noteSiteFault("repl.runlog-read", e);
      caches.runlogBodies.set(key, null);
      return null;
    }
  };
  return async (id, dest, verified = false) => {
    const key = id ?? "";
    const cache = verified ? caches.verifiedRunlogs : caches.runlogs;
    if (cache.has(key)) return cache.get(key) ?? null;
    // The verified read takes the body fresh, never the cached one: the pass may have appended to this
    // destination since the target read cached it, and an old body against the new .sig never verifies.
    if (verified) caches.runlogBodies.delete(key);
    const b = await readBody(key, dest);
    let parsed: RunlogEntry[] | null;
    try {
      if (b === null) parsed = null;
      else if (verified) parsed = await verifyRunlogForWrite(dest, b === "absent" ? null : { body: b }, verifierFrom(signer));
      else parsed = b === "absent" ? [] : parseRunlog(b);
    } catch (e) {
      // A target RUNLOG that does not parse is not a read that failed this tick: no retry clears it. It throws
      // to the pass, which records the target runlog-corrupt (replica-fault.ts), not runlog-unreadable.
      if (!verified) throw new RunlogIntegrityError("unparsable", "the RUNLOG does not parse");
      log("error", `replicate: the RUNLOG of destination ${key || "default"} was not used as a source: ${(e as Error).message.slice(0, 200)}`);
      // A refusal (RunlogIntegrityError) is bucket data: the check records its own anomaly row. Any other
      // throw is a read or write that failed while verifying.
      if (!(e instanceof RunlogIntegrityError)) noteSiteFault("repl.source-runlog-verify", e);
      parsed = null; // unreadable, or unverified, this tick
    }
    cache.set(key, parsed);
    return parsed;
  };
}

// entryMatchesRoot answers whether a RUNLOG entry agrees with its run's root manifest (the bytes
// verifyRunOnReplica read and verified on the replica): the same run id, downpipe and RUNLOG index
// (root.freshness.runlogIndex). An entry that disagrees came from a RUNLOG that does not describe this run.
export function entryMatchesRoot(rootBody: Uint8Array | null, entry: RunlogEntry): boolean {
  type RootFields = { runId?: unknown; downpipeId?: unknown; freshness?: { runlogIndex?: unknown } };
  let root: RootFields | null = null;
  try {
    root = rootBody !== null ? (JSON.parse(new TextDecoder().decode(rootBody)) as RootFields) : null;
  } catch (e) {
    // verifyRunOnReplica verified these bytes, so a root that does not parse is the engine's own fault.
    noteSiteFault("repl.root-parse", e);
    root = null;
  }
  return root !== null && root.runId === entry.runId && root.downpipeId === entry.downpipeId && root.freshness?.runlogIndex === entry.index;
}
