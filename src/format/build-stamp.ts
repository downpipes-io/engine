// The build-time artefact-hash stamp (W1 provenance). This committed file ships the UNSTAMPED
// placeholder; scripts/stamp-build-id.mjs OVERWRITES it at build time with the real SHA-384 (hex,
// lower-case) of the deployable engine bundle that build produced. The placeholder is deliberately NOT
// a 96-hex-char string, so reportedArtefactSha384() (src/format/build-id.ts) rejects it and the engine
// honestly reports NO stamped hash until a real build stamps one, never a fabricated value.
//
// This file is TRACKED (so the source typechecks + tests run without a build step) but is a DERIVED
// artefact at build time, like wrangler.deploy.toml: a deploy regenerates it. Commit it ONLY in its
// placeholder form; do not commit a stamped value (the stamp is per-build and reproducible from source).
/**
 * The build-time artefact hash. In committed source this is the `"unstamped-build"` placeholder;
 * scripts/stamp-build-id.mjs overwrites it at build time with the lowercase-hex SHA-384 of the
 * deployable bundle. reportedArtefactSha384 rejects the placeholder, so the engine reports no
 * stamped hash until a real build stamps one.
 */
export const ARTEFACT_SHA384 = "unstamped-build";
