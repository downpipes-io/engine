import type { RunHistoryEntry } from "../sched/types.ts";

// prevRunId was recorded internally (trigger's own ds.lastRunId, mirrored in the
// destination-local RUNLOG's freshness.prevRunId) but reached no admin read, so an auditor could not
// reconstruct a downpipe's per-run predecessor chain from the console or the API -- only from the
// sealed archive itself. This module is the one place that turns the raw prevRunId pointer, plus
// membership in the SAME retained ring, into an honest per-row verdict for GET /history to serve. It
// is a PURE function over the redaction-safe history ring (ids only, no key/value/plaintext), so it
// is unit-tested directly.
//
// FULL-CHAIN HONESTY (the load-bearing claim): a raw prevRunId is not enough on its own. Three
// distinct situations all produce a non-obvious value and must not be conflated:
//   - this IS the downpipe's first run ever: prevRunId is null. Distinct from a missing predecessor.
//   - a predecessor exists, but the ring (bounded to RING_CAP entries) no longer retains its row: the
//     id is real, but this response cannot show its status. Rendering that as an empty string, or
//     silently dropping the field, reads exactly like a rewritten/broken chain to an auditor -- the
//     one failure mode this product exists to make detectable. It is reported honestly as "pruned".
//   - the row predates this field's introduction and carries no prevRunId key at all (an upgrade
//     boundary, not a chain break): reported as "unknown", never coerced to null ("no predecessor").
export type PrevRunIdStatus = "none" | "retained" | "pruned" | "unknown";

export interface RunHistoryEntryWithChain extends RunHistoryEntry {
  // prevRunIdStatus classifies THIS row's prevRunId against the ring it was resolved from:
  //   "none"     -- prevRunId is null: this is the downpipe's first run ever.
  //   "retained" -- prevRunId is a real id AND that predecessor's own row is present in this same
  //                 response, so the chain can be followed one more link without a further read.
  //   "pruned"   -- prevRunId is a real id, but no row with that runId is present in this response
  //                 (it aged out of the RING_CAP-bounded window). The chain is honestly INCOMPLETE
  //                 here, not broken: the predecessor existed, it is simply outside what this ring
  //                 retains.
  //   "unknown"  -- the row carries no prevRunId key at all (sealed before this field existed).
  prevRunIdStatus: PrevRunIdStatus;
}

// annotatePredecessorChain classifies every row in a ring against that SAME ring's own runId
// membership (order-independent: it builds the id set once, so newest-first or oldest-first input
// gives identical verdicts). Pass it the exact set of rows a response returns -- for the byDownpipe
// shape, call it once per downpipe's ring, never once over the merged fleet, since a downpipe's
// predecessor must only ever be looked up within its OWN chain.
export function annotatePredecessorChain(ring: readonly RunHistoryEntry[]): RunHistoryEntryWithChain[] {
  const present = new Set(ring.map((e) => e.runId));
  return ring.map((entry) => {
    const prev = entry.prevRunId;
    let prevRunIdStatus: PrevRunIdStatus;
    if (!Object.hasOwn(entry, "prevRunId") || prev === undefined) {
      prevRunIdStatus = "unknown";
    } else if (prev === null) {
      prevRunIdStatus = "none";
    } else if (present.has(prev)) {
      prevRunIdStatus = "retained";
    } else {
      prevRunIdStatus = "pruned";
    }
    return { ...entry, prevRunIdStatus };
  });
}
