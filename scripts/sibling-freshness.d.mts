// Types for sibling-freshness.mjs, following the convention scripts/lib/blank-comments.d.mts sets: the gates
// in scripts/ run under bare node with no build step, so the module stays plain ESM JavaScript and its types
// are declared beside it. Four validators under test/ now import it, and test/ IS type-checked in CI
// (tsconfig.test.json), so an untyped import is an implicit-any error rather than a nuisance.
//
// THE .mjs IS A VERBATIM COPY of control-plane/scripts/sibling-freshness.mjs and website's, and must stay
// byte-identical to them, which its own header requires. Nothing may be added to it, so anything engine needs
// beyond it lives in scripts/lib/sibling-lag.mjs instead. This declaration file is not part of that copy.

/**
 * How many commits `repoPath` is behind its own origin/main, or null when that cannot be determined.
 *
 * Null is returned for a path that is not a git checkout, and for one whose origin/main ref is absent. Those
 * are different from zero and must not be rounded to it.
 */
export declare function behindOriginMain(repoPath: string): number | null;

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
 * Refuse, with exit 2, when any sibling this gate reads is behind its own origin/main.
 *
 * Exit 2 is CANNOT CHECK and is deliberately not exit 1, FOUND SOMETHING. Reading a 2 as a 1 is how a stale
 * tree becomes a bug report.
 */
export declare function requireFreshSiblings(siblings: SiblingRef[], opts?: RequireFreshSiblingsOptions): void;
