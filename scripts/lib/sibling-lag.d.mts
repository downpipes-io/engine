// Types for sibling-lag.mjs, following the convention scripts/lib/blank-comments.d.mts sets. See that file
// for why these modules stay plain ESM JavaScript with declarations beside them rather than being converted.

/** One measured sibling checkout. `behind` is null for UNKNOWN and that is never rounded to 0. */
export interface MeasuredSibling {
  name: string;
  path: string | null;
  present: boolean;
  head: string | null;
  behind: number | null;
}

/**
 * Measure one sibling checkout: where it is, what it is at, and how far behind its own origin/main.
 */
export declare function siblingLag(name: string, path: string | null | undefined): MeasuredSibling;

/** One line describing a measured sibling. BEHIND is upper-case because it is the case a reader must not skim. */
export declare function siblingLagLine(s: MeasuredSibling, opts?: { bare?: boolean }): string;

/**
 * Measure every sibling a caller actually read, print one line each, and hand the measurements back.
 *
 * This never changes an exit code. A caller that wants a refusal calls requireFreshSiblings from
 * ../sibling-freshness.mjs instead, and a caller that wants both calls this first so the measurement is on
 * the record either way.
 */
export declare function reportSiblings(
  siblings: Array<{ name: string; path: string | null | undefined }>,
  opts?: { gate?: string; log?: (msg: string) => void },
): MeasuredSibling[];
