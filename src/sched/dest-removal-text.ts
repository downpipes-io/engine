// The texts removeDest (scheduler-do-dest-config.ts) returns when it refuses a destination removal or
// completes one that cost something. The console shows them to the operator verbatim, so each refusal
// names a step that ends it, in the order that works, and states what force costs. Every step named is
// one the engine carries out: a wait is named only for runs whose downpipe has two or more destinations
// (the replicate pass then copies them at every cron tick, in its own wall window, oldest first within each
// downpipe, with the downpipes taking turns), and the step that makes replication run is named for the rest.
// Pure; no storage, no I/O.

import { CRON_CADENCE_MS } from "../cron/cron-cadence.ts";
import { RING_CAP } from "./scheduler-do-limits.ts";

// RemovalRisk is what the removal scan (uncoveredOriginRuns) found for one destination:
//   count               the ring runs whose only proven copy is this destination;
//   names               the downpipes those runs belong to;
//   unreplicable        how many of `count` belong to downpipes with fewer than two destinations, which the
//                       replicate pass skips, so no wait copies them;
//   olderOutsideHistory the runs of the downpipes that sealed runs here which have left the history ring.
//                       Replication copies only ring runs and the scan sees only ring runs, so nothing
//                       copies or protects these; the refusal and the removal notice state them.
export interface RemovalRisk {
  count: number;
  names: string[];
  unreplicable: number;
  olderOutsideHistory: number;
}

// The two refusals' opening words, so the router can file the singular clear's refusal under its closed class by
// the START of the sentence (never by a word inside it: the names of the downpipes ride later in the text).
export const DEST_IN_USE_PREFIX = "destination is in use by ";
export const DEST_ORPHAN_PREFIX = "destination is the only proven copy of ";

const CRON_MINUTES = Math.round(CRON_CADENCE_MS / 60_000);

function firstFive(names: readonly string[]): string {
  return `${names.slice(0, 5).join(", ")}${names.length > 5 ? ", …" : ""}`;
}

function waitClause(r: RemovalRisk, target: string): string | undefined {
  const replicable = r.count - r.unreplicable;
  if (replicable <= 0) return undefined;
  return `Replication copies ${replicable === r.count ? "them" : `${replicable} of them`} to ${target} at each ${CRON_MINUTES}-minute tick, oldest first within each downpipe.`;
}

function unreplicableClause(r: RemovalRisk): string | undefined {
  if (r.unreplicable <= 0) return undefined;
  const who = r.unreplicable === r.count ? "These runs belong" : `${r.unreplicable} of them belong`;
  return `${who} to downpipes with fewer than two destinations, which replication does not copy, so waiting does not clear them.`;
}

function olderClause(r: RemovalRisk): string | undefined {
  if (r.olderOutsideHistory <= 0) return undefined;
  return `${r.olderOutsideHistory} older run(s) of the downpipes that sealed runs here are no longer in the run history, which keeps the newest ${RING_CAP} runs of each downpipe. Replication does not copy those, so downpipes cannot restore any of them held only here once this destination is removed, with or without force.`;
}

// destInUseRefusal is the in-use refusal: downpipes name this destination. It never uses the orphan
// guard's "only proven copy" phrase (the console and classifyDestProbeRefusal key on it). When runs here
// are not yet copied, it says to keep this destination on the downpipes until they are: a downpipe left
// with one destination is not replicated, and taking this one off first is what sent the operator from
// this refusal to the orphan guard and back.
export function destInUseRefusal(pinned: readonly string[], r: RemovalRisk): string {
  const parts: (string | undefined)[] = [`${DEST_IN_USE_PREFIX}${pinned.length} downpipe(s): ${firstFive(pinned)}.`];
  if (r.count === 0) {
    parts.push("Reassign them first.");
  } else {
    parts.push(`Keep it on them for now: it holds ${r.count} backed-up run(s) that no other destination holds yet (${firstFive(r.names)}).`);
    const w = waitClause(r, "the other destinations of their downpipes");
    parts.push(w !== undefined ? `${w} This can take hours. It stops copying for a downpipe left with one destination.` : undefined);
    const u = unreplicableClause(r);
    // With no wait clause above, this arm states the tick itself; with one, the tick is already stated.
    const tick = w === undefined ? ` It copies at each ${CRON_MINUTES}-minute tick, oldest first within each downpipe. This can take hours.` : " This can take hours too.";
    parts.push(u !== undefined ? `${u} Give each of those downpipes this destination and one other, and wait for replication to copy the runs.${tick}` : undefined);
    parts.push("When a removal no longer reports runs held only here, take this destination off those downpipes and remove it.");
  }
  parts.push(olderClause(r));
  return parts.filter((x): x is string => x !== undefined).join(" ");
}

// stalledCountClause states the case where a run stays in the count while replication copies the rest. The
// replicate pass records a destination's proven window only up to the first run it cannot copy (for example
// a run that no destination of the downpipe holds: sourceOf finds no source, processTarget strands it, and
// highestContiguousRun stops below it). The pass also lists the newer runs it did copy in holdsAbove, and
// replProof counts those as held. Only the stranded run stays in the count, until it leaves the history
// ring, which moves the window floor above it.
function stalledCountClause(): string {
  return `If replication cannot copy a run (for example, no destination holds it), that run stays in this count until it leaves the downpipe's newest ${RING_CAP} runs.`;
}

// destOrphanRefusal is the orphan-guard refusal: no downpipe names this destination, but it is the only
// proven copy of ring runs. The count falls as replication copies them, so the wait it names is one the
// operator can watch end, except for the case stalledCountClause states.
export function destOrphanRefusal(r: RemovalRisk): string {
  const parts: (string | undefined)[] = [`${DEST_ORPHAN_PREFIX}${r.count} backed-up run(s) (${firstFive(r.names)}).`];
  const w = waitClause(r, "another destination of their downpipes");
  // The count can stay flat while replication copies the segment data the runs share: no run is held on a
  // destination until all the segment data from its origin is there (seal/replicate.ts syncSegmentStore).
  parts.push(w !== undefined ? `${w} This count falls as replication copies runs. It can stay the same for several ticks while replication copies shared data, and the wait can take hours. ${stalledCountClause()}` : undefined);
  const u = unreplicableClause(r);
  parts.push(u !== undefined ? `${u} To keep them, give each of those downpipes this destination and one other, wait for replication to copy the runs (this can take hours), then take this destination off them and remove it.` : undefined);
  parts.push(`Or remove it with force: downpipes then cannot restore those ${r.count} run(s).`);
  parts.push(olderClause(r));
  return parts.filter((x): x is string => x !== undefined).join(" ");
}

// destRemovedNotice is the sentence a successful removal returns when it cost something: the runs a
// force dropped, and the older runs outside the run history that no guard could count. Undefined when
// the removal dropped nothing the engine knows of.
export function destRemovedNotice(force: boolean, r: RemovalRisk): string | undefined {
  const older = r.olderOutsideHistory > 0 ? `${r.olderOutsideHistory} older run(s) of the downpipes that sealed runs here are outside the run history, which keeps the newest ${RING_CAP} runs of each downpipe, and replication does not copy runs outside it. Downpipes cannot restore any of them that were only here.` : undefined;
  if (force && r.count > 0) return [`Destination removed with force. Downpipes cannot restore the ${r.count} backed-up run(s) that were only here.`, older].filter((x): x is string => x !== undefined).join(" ");
  if (older !== undefined) return `Destination removed. ${older}`;
  return undefined;
}
