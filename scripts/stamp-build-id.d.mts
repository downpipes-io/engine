// Type declarations for scripts/stamp-build-id.mjs.
//
// WHY THIS FILE EXISTS. `test/validate-stamp-idempotency.ts` is the first TypeScript test in this repo to
// import a script from scripts/, and CI's type-check runs the test surface under noImplicitAny, so a plain
// `.mjs` import fails with TS7016 ("implicitly has an 'any' type"). A local `npm run typecheck` passed and CI
// did not, which is the documented "local typecheck is narrower than CI" trap.
//
// Declared rather than suppressed. A `@ts-expect-error` would have silenced the diagnostic and taken the type
// safety with it, and this repo already treats an unused expect-error directive as an error in its own right.
// These signatures are the real ones, read from the module: keep them in step if it changes.

/** Absolute path to the tracked-but-derived src/format/build-stamp.ts. */
export const STAMP_PATH: string;

/** Absolute path to the engine repo root. */
export const ENGINE_DIR: string;

/**
 * Overwrites the stamp file with the committed placeholder, unconditionally.
 *
 * This is the fix for the self-referential hash: the script used to digest whatever was already sitting in the
 * stamp file and then overwrite that same file with the result, so a second run in the same checkout hashed the
 * first run's output. Every hash-producing build now resets first.
 */
export function resetStampToPlaceholder(stampPath?: string): void;

/** Builds the deployable bundle via a local wrangler dry run and returns its bytes. */
export function buildBundleViaWrangler(mainModule: string, engineDir?: string): Uint8Array;

/**
 * Resets, builds, digests and writes the stamp. `resetFirst` defaults to true and exists as a parameter only so
 * the idempotency test can reproduce the pre-fix behaviour on demand; production callers must not pass false.
 */
export function stampOnce(opts?: {
  mainModule?: string;
  resetFirst?: boolean;
  stampPath?: string;
  engineDir?: string;
}): Promise<{ digest: string; bundleBytes: number }>;
