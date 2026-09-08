// BUILD PROVENANCE, the engine's self-stamped artefact identity (W1).
//
// A running Worker cannot hash its own deployed bytes at runtime, so the artefact digest is stamped at
// BUILD time and shipped as a constant the engine reports (GET /admin/status.artefactSha384). This
// closes the "artefact hash not yet reported" gap: status no longer echoes a manual-only env var
// (env.ARTEFACT_SHA384) that is unset in production, it reports the real, build-stamped SHA-384 of the
// deployable bundle the build produced.
//
// HOW IT IS STAMPED (scripts/stamp-build-id.mjs, deterministic, no Date.now):
//   1. build the deployable bundle the SAME way a deploy does, `wrangler deploy --dry-run --outdir`
//      (the exact bytes a real deploy would push). The committed source ships only the placeholder
//      sentinel below, so the bundle the step hashes is stable and reproducible from source alone (no
//      embedded hash, no timestamp).
//   2. SHA-384 that bundle with the engine's own hash (the same primitive update-apply re-computes).
//   3. OVERWRITE the side-car module src/format/build-stamp.ts with the digest.
// build-stamp.ts is TRACKED but carries only the placeholder in source control (so the source
// typechecks + tests run with no build step); a build regenerates it, like wrangler.deploy.toml. When
// it still holds the placeholder (any non-stamped checkout) the engine honestly reports NO stamped hash
// (presence-safe), never a fabricated value.
//
// SECURITY NOTE: this in-bundle/side-car constant is for DISPLAY + operator cross-check only. The hash
// that GATES a deploy (verify-before-deploy, update-apply.ts) is the SIGNED channel's sha384 over the
// downloaded artefact, that remains the security-critical value and is unaffected by anything here.

/**
 * The fixed sentinel the committed build-stamp side-car always ships (never a real digest). The
 * stamp step hashes the deployable bundle that contains exactly these bytes, so the bundle, and
 * thus the digest, is identical on every rebuild of the same source. It is deliberately not a
 * 96-hex-char string, so it can never be mistaken for a real SHA-384.
 */
export const ARTEFACT_SHA384_PLACEHOLDER = "downpipe-artefact-sha384-build-placeholder";

/**
 * Returns the engine's self-stamped artefact digest, or null when none is stamped (a checkout that
 * still carries the placeholder, or a malformed write). The side-car is included in the bundle
 * (it has to be, for its value to be readable at runtime); the dynamic import only defers reading
 * it so the main bundle's own hash is stable before the stamp step patches the side-car. Any
 * failure degrades to a clean null. Only a well-formed 96-hex-char SHA-384 is reported, never a
 * fabricated value.
 *
 * @returns the lowercase-hex SHA-384 of the deployable bundle when stamped, otherwise null.
 */
export async function reportedArtefactSha384(): Promise<string | null> {
  try {
    const mod = (await import("./build-stamp.ts")) as { ARTEFACT_SHA384?: unknown };
    const v = mod.ARTEFACT_SHA384;
    if (typeof v !== "string") return null;
    const trimmed = v.trim().toLowerCase();
    return /^[0-9a-f]{96}$/.test(trimmed) ? trimmed : null;
  } catch {
    return null;
  }
}
