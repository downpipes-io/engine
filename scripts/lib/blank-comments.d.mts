// Types for blank-comments.mjs, which is plain ESM JavaScript because the gates in scripts/ run under bare
// node with no build step. The .mjs stayed untyped for as long as only other .mjs files imported it. Two
// validators under test/ now use it, and test/ IS type-checked in CI (tsconfig.test.json), so an untyped
// import is an implicit-any error rather than a nuisance.
//
// Declared rather than converted: rewriting the module to TypeScript would put a build step in front of gates
// that must run on a bare checkout, which is the property they were written to have.

/**
 * Replace every COMMENT byte with a space, preserving newlines, offsets and line numbers. Quote-aware: a
 * `//` inside a string is not a comment. String and template-literal CONTENT is left intact.
 */
export declare const blankComments: (src: string) => string;

/**
 * As blankComments, and additionally blanks STRING and template-literal content. For a caller matching a code
 * SHAPE, where a decoy string naming the shape would otherwise read as real.
 */
export declare const blankCommentsAndStrings: (src: string) => string;
