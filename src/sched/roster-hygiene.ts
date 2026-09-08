// Roster hygiene: the structural-integrity analysis of the dp: roster, and the pure repair plan
// for the two GHOST classes that nothing else in the engine can reach or heal.
//
// THE PROBLEM this closes. Every consumer of
// the roster keys off a downpipe's EMBEDDED config.id: the console's map and list render it, the
// delete route removes `dp:<config.id>`, the scheduler indexes it. The storage KEY is meant to be
// `dp:<config.id>` (persistDownpipeState is the single writer and guarantees it), but a record
// written by an older engine, a partial storage fault, or a manual edit can violate that:
//   - KEY-ID MISMATCH: `dp:A` holds a state whose config.id is B. The list returns it (the map
//     draws an edge for B; with no run ring under hist:B it reads a permanent "Unknown"), yet
//     POST /downpipes/delete { id: B } deletes `dp:B`, which does not exist, so it returns
//     deleted:false and the ghost survives every delete attempt. Undeletable by construction.
//   - MALFORMED: `dp:X` holds a value with no readable string config.id at all. No API can name
//     it, so nothing can ever remove or run it.
// Neither class is reachable by the due-index reconcile (rebuildDueIndex heals the due: index,
// not the dp: truth) nor by the delete route. This module gives them a name, a report (surfaced
// in the support pack, so a customer bundle self-diagnoses the grey-line question) and a repair.
//
// NEVER-RAN is deliberately NOT a ghost: an enabled downpipe with no run history yet is a valid,
// operator-addressable config (a freshly created pipe before its first tick looks exactly like
// this). It is REPORTED (it is what a permanent "Unknown" map edge usually is when the roster is
// structurally sound) but never auto-repaired; deleting a valid config is the operator's call,
// via the normal gated delete. The repair plan touches ONLY rows that are provably unaddressable:
// abstain everywhere else.
//
// This module is PURE and IO-free (analyse + plan over a snapshot Map) so a validator drives
// every branch directly; the SchedulerDO methods (rosterHygiene / reconcileRoster) are the thin
// storage shells.

// The dp: storage prefix this module reasons about. Kept in step with the scheduler's own keying
// (persistDownpipeState / listAllByPrefix callers); a literal here because importing the DO would
// invert the dependency (the DO imports this pure leaf).
export const DP_PREFIX = "dp:";

// Bounded list caps for the report: counts are always exact, the LISTS are capped so a degenerate
// store (thousands of ghosts) cannot bloat the support pack or a JSON response. 25 named entries
// is plenty to act on; the count says how many more exist.
export const ROSTER_LIST_CAP = 25;

export interface RosterGhost {
  key: string; // the offending storage key (dp:<suffix>)
  embeddedId: string | null; // the config.id the value carries, or null when unreadable
  kind: "key-id-mismatch" | "malformed";
}

export interface NeverRanEntry {
  id: string;
  enabled: boolean;
}

export interface RosterHygieneReport {
  scanned: number; // dp: rows examined
  ghosts: RosterGhost[]; // capped at ROSTER_LIST_CAP; ghostCount is the exact total
  ghostCount: number;
  neverRan: NeverRanEntry[]; // capped at ROSTER_LIST_CAP; neverRanCount is the exact total
  neverRanCount: number;
  // G325: the two lists are CAPPED and the caps carry no marker, so a reader holding only the pack cannot
  // tell "these are all the ghosts" from "these are the first 25 of 300". The counts above were already
  // exact, but a reader must not have to DERIVE the truncation to know it happened -- and a mass-corruption
  // repair needs to know rows exist that it cannot enumerate. Explicit flags + the dropped row counts.
  ghostsTruncated: boolean;
  ghostsDropped: number;
  neverRanTruncated: boolean;
  neverRanDropped: number;
}

// One step of the repair plan. "delete-ghost" removes a row (and its per-downpipe siblings keyed
// by the KEY SUFFIX, which is the identity the residue actually lives under); "rehome" preserves
// a mismatched row's state by rewriting it under its embedded id's correct key, then removing the
// misplaced original. suffixId is always the key's own suffix (what hist:/repl: residue is named
// by), never the embedded id.
export type RosterRepairAction =
  | { act: "delete-ghost"; key: string; suffixId: string }
  | { act: "rehome"; key: string; suffixId: string; toId: string };

// embeddedConfigId reads the config.id a stored roster value carries, structurally (the value is
// untrusted: the whole point is reasoning about rows that may be malformed). A non-empty string id
// or null; never throws.
export function embeddedConfigId(value: unknown): string | null {
  if (typeof value !== "object" || value === null) return null;
  const config = (value as { config?: unknown }).config;
  if (typeof config !== "object" || config === null) return null;
  const id = (config as { id?: unknown }).id;
  return typeof id === "string" && id !== "" ? id : null;
}

// wellFormed: the key names the id the value itself claims. Everything the engine does with a
// downpipe assumes this invariant; these rows are healthy regardless of their run state.
function isWellFormed(key: string, value: unknown): boolean {
  const id = embeddedConfigId(value);
  return id !== null && key === `${DP_PREFIX}${id}`;
}

// analyseRoster classifies every dp: row in one pass. idsWithRuns is the set of WELL-FORMED ids
// whose run-history ring holds at least one entry (the DO shell batch-reads hist:<id> for the
// well-formed ids only; ghosts are reported regardless of history). lastRunId alone cannot decide
// "never ran": only a SUCCESSFUL run advances it, so a downpipe whose every run failed still has
// lastRunId null while its ring proves it has run (and the map reads it "failed", not "unknown").
export function analyseRoster(
  entries: ReadonlyMap<string, unknown>,
  idsWithRuns: ReadonlySet<string>,
): RosterHygieneReport {
  const ghosts: RosterGhost[] = [];
  let ghostCount = 0;
  const neverRan: NeverRanEntry[] = [];
  let neverRanCount = 0;

  for (const [key, value] of entries) {
    const embedded = embeddedConfigId(value);
    if (embedded === null) {
      ghostCount++;
      if (ghosts.length < ROSTER_LIST_CAP) ghosts.push({ key, embeddedId: null, kind: "malformed" });
      continue;
    }
    if (key !== `${DP_PREFIX}${embedded}`) {
      ghostCount++;
      if (ghosts.length < ROSTER_LIST_CAP) ghosts.push({ key, embeddedId: embedded, kind: "key-id-mismatch" });
      continue;
    }
    // Well-formed: report (never repair) the never-ran state that renders as a standing
    // "Unknown" edge on the map. inFlight means a first run is underway right now, which the
    // map already conveys as running; that is not a standing unknown, so it is excluded.
    const v = value as { lastRunId?: unknown; inFlight?: unknown; config?: { enabled?: unknown } };
    const hasLastRun = typeof v.lastRunId === "string" && v.lastRunId !== "";
    const inFlight = v.inFlight === true;
    if (!hasLastRun && !inFlight && !idsWithRuns.has(embedded)) {
      neverRanCount++;
      if (neverRan.length < ROSTER_LIST_CAP) {
        neverRan.push({ id: embedded, enabled: v.config?.enabled === true });
      }
    }
  }
  // G325: state the truncation rather than making the reader derive it from count-vs-length.
  return {
    scanned: entries.size,
    ghosts,
    ghostCount,
    neverRan,
    neverRanCount,
    ghostsTruncated: ghostCount > ghosts.length,
    ghostsDropped: ghostCount - ghosts.length,
    neverRanTruncated: neverRanCount > neverRan.length,
    neverRanDropped: neverRanCount - neverRan.length,
  };
}

// planRosterRepair computes the deterministic repair for the ghost classes ONLY (never-ran rows
// are valid configs and are never touched; see the module header). Rules, in ascending key order
// (the Map preserves the storage list order, which is ascending):
//   - malformed row: delete-ghost. No API can name it, no run can use it; removal is the only
//     remedy and provably loses nothing addressable.
//   - key-id mismatch WITH a healthy twin (a well-formed dp:<embeddedId> exists): delete-ghost.
//     The twin is the authoritative record; the misplaced row is residue. The ghost's OWN
//     hist:/repl: siblings (keyed by the key suffix, an id that is not a real downpipe) go with it.
//   - key-id mismatch WITHOUT a twin: rehome. The state is real and would otherwise be lost, so
//     it is rewritten under its embedded id's correct key (restoring the invariant and making it
//     addressable/deletable again), and the misplaced key is removed. When SEVERAL twinless
//     ghosts claim the SAME embedded id, the ascending-first key is rehomed and the rest are
//     delete-ghost (after the rehome a healthy twin exists; keeping N divergent claims would
//     mean guessing which is legitimate, and the survivor choice is deterministic + audited).
export function planRosterRepair(entries: ReadonlyMap<string, unknown>): RosterRepairAction[] {
  const plan: RosterRepairAction[] = [];
  const rehomedTo = new Set<string>();
  // Sort keys ascending so the plan is deterministic regardless of Map insertion order (the DO's
  // storage list is already ascending; a test fixture may not be).
  const keys = [...entries.keys()].sort();
  for (const key of keys) {
    const value = entries.get(key);
    const suffixId = key.slice(DP_PREFIX.length);
    const embedded = embeddedConfigId(value);
    if (embedded === null) {
      plan.push({ act: "delete-ghost", key, suffixId });
      continue;
    }
    if (key === `${DP_PREFIX}${embedded}`) continue; // well-formed: never touched
    const twinKey = `${DP_PREFIX}${embedded}`;
    const twinHealthy = entries.has(twinKey) && isWellFormed(twinKey, entries.get(twinKey));
    if (twinHealthy || rehomedTo.has(embedded)) {
      plan.push({ act: "delete-ghost", key, suffixId });
    } else {
      plan.push({ act: "rehome", key, suffixId, toId: embedded });
      rehomedTo.add(embedded);
    }
  }
  return plan;
}
