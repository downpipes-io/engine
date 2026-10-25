// Types for sibling-freshness.mjs, following the convention scripts/lib/blank-comments.d.mts sets: the gates
// in scripts/ run under bare node with no build step, so the module stays plain ESM JavaScript and its types
// are declared beside it. Four validators under test/ now import it, and test/ IS type-checked in CI
// (tsconfig.test.json), so an untyped import is an implicit-any error rather than a nuisance.
//
// THE .mjs IS A VERBATIM COPY of the scripts/sibling-freshness.mjs that the other product repositories carry, and
// must stay byte-identical to them, which its own header requires. A change to it lands in all four copies
// together; anything only engine needs lives in scripts/lib/sibling-lag.mjs instead. This declaration file is
// not part of that copy.

/**
 * How many commits `repoPath` is behind its own origin/main, or null when that cannot be determined.
 *
 * Null is returned for a path that is not a git checkout, and for one whose origin/main ref is absent. Those
 * are different from zero and must not be rounded to it.
 */
export declare function behindOriginMain(repoPath: string): number | null;

/**
 * The release tag `repoPath`'s HEAD sits on and the newest release tag it has fetched, or null when HEAD is on
 * no X.Y.Z release tag. A checkout at the newest release tag is fresh however far main has moved on.
 */
export declare function releasePin(repoPath: string): { tag: string; newest: string } | null;

/** A sibling a gate actually reads: its repo name, and where on disk it was resolved to. */
export interface SiblingRef {
  name: string;
  path: string | null | undefined;
}

/** Options to requireFreshSiblings. `exit` and `log` are injection points, used in production by the callers
 * that must declare a verdict before the process ends. */
export interface RequireFreshSiblingsOptions {
  gate?: string;
  consequence?: string;
  legacyAllowEnv?: string[];
  allowEmpty?: boolean;
  env?: NodeJS.ProcessEnv;
  // `void` rather than `never | void`: a hook that really does end the process returns never, which is
  // assignable to void, and the union trips biome's noConfusingVoidType.
  exit?: (code: number) => void;
  log?: (msg: string) => void;
}

/**
 * Refuse, with exit 2, when any sibling this gate reads is behind its own origin/main. A sibling on a release
 * tag is graded against the newest release tag instead: at it, fresh; behind it, exit 1 (pin bump owed).
 *
 * Exit 2 is CANNOT CHECK and is deliberately not exit 1, FOUND SOMETHING. Reading a 2 as a 1 is how a stale
 * tree becomes a bug report.
 */
export declare function requireFreshSiblings(siblings: SiblingRef[], opts?: RequireFreshSiblingsOptions): void;
