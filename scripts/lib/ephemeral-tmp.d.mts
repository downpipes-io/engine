// Types for ephemeral-tmp.mjs, following the convention scripts/lib/blank-comments.d.mts sets. See that
// file for why these modules stay plain ESM JavaScript with declarations beside them rather than being
// converted.

/**
 * mkdtempSync(join(tmpdir(), prefix)) that removes itself on process exit (success, a thrown error, or
 * process.exit()), so a caller never has to thread its own try/finally around every scratch dir it makes.
 */
export declare function ephemeralTmpDir(prefix: string): string;
