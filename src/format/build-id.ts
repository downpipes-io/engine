// BUILD PROVENANCE, what the engine reports as its artefact identity.
//
// A running Worker cannot hash its own deployed bytes, and a bundle cannot carry its own hash: writing the
// digest into the source changes the bytes the digest was taken over. So the value GET
// /admin/status.artefactSha384 reports comes from OUTSIDE the uploaded bytes, and status names which source
// it came from in artefactSha384Source:
//
//   "deployed"     the SHA-384 (hex, lower-case) of the main module bytes the last upload sent, recorded as the
//                  plain-text binding DEPLOYED_ARTEFACT_SHA384 by the same upload. `npm run deploy`
//                  (scripts/deploy.sh) builds the bundle once, hashes that file and uploads that same file
//                  with `wrangler deploy --no-bundle`, so the recorded value is the hash of the served main
//                  module. The update-channel apply (src/admin/cf-deploy.ts) records the hash of the bytes it
//                  uploads the same way.
//   "operator"     env.ARTEFACT_SHA384, a value an operator set by hand. The engine does not check it.
//   "build-stamp"  the digest scripts/stamp-build-id.mjs wrote into src/format/build-stamp.ts. It is the
//                  SHA-384 of the bundle built with the committed placeholder in that file, which is the
//                  release artefact for the same source. It is NOT the hash of the bytes a stamped build
//                  serves: those bytes carry the digest in place of the placeholder. Only a deploy path that
//                  stamps and then re-bundles reports this source; `npm run deploy` does not stamp.
//
// SECURITY NOTE: every source is for DISPLAY + operator cross-check only. The hash that GATES a deploy
// (verify-before-deploy, update-apply.ts) is the SIGNED channel's sha384 over the downloaded artefact, that
// remains the security-critical value and is unaffected by anything here.

/**
 * The fixed sentinel the committed build-stamp side-car always ships (never a real digest). The
 * stamp step hashes the deployable bundle that contains exactly these bytes, so the bundle, and
 * thus the digest, is identical on every rebuild of the same source. It is deliberately not a
 * 96-hex-char string, so it can never be mistaken for a real SHA-384.
 */
export const ARTEFACT_SHA384_PLACEHOLDER = "downpipe-artefact-sha384-build-placeholder";

/**
 * Returns the digest scripts/stamp-build-id.mjs wrote into build-stamp.ts, or null when none is stamped (a
 * checkout that still carries the placeholder, or a malformed write). It is the hash of the bundle built with
 * the placeholder, not of the bytes a stamped build serves: the side-car is bundled, so stamping it changes
 * the bundle (see the module header). Any failure degrades to a clean null. Only a well-formed 96-hex-char
 * SHA-384 is reported, never a fabricated value.
 *
 * @returns the lowercase-hex SHA-384 of the bundle built with the placeholder when stamped, otherwise null.
 */
export async function reportedArtefactSha384(): Promise<string | null> {
  try {
    const mod = (await import("./build-stamp.ts")) as { ARTEFACT_SHA384?: unknown };
    return parseArtefactSha384(mod.ARTEFACT_SHA384);
  } catch {
    return null;
  }
}

/**
 * The name of the plain-text binding that carries the SHA-384 of the main module bytes the last upload sent.
 * scripts/deploy.sh sets it with `wrangler deploy --var`, and the update-channel apply sets it on the version
 * it uploads. Both write the hash of the exact bytes they upload, never a value baked into those bytes.
 */
export const DEPLOYED_ARTEFACT_SHA384_BINDING = "DEPLOYED_ARTEFACT_SHA384";

/**
 * Normalises a candidate artefact digest: a string that is a SHA-384 in hex (96 characters, either case,
 * surrounding whitespace ignored) comes back lower-case, and anything else comes back null.
 *
 * @param value - the candidate, of any type.
 * @returns the lower-case hex digest, or null when the value is not one.
 */
export function parseArtefactSha384(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  return /^[0-9a-f]{96}$/.test(trimmed) ? trimmed : null;
}
