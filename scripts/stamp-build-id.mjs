// Build-time artefact-hash stamp (W1 provenance). It produces the engine's self-reported SHA-384 so
// GET /admin/status reports the REAL digest of the deployable bundle, not a manual-only env var.
//
// WHAT IT DOES (deterministic, no Date.now):
//   1. RESET src/format/build-stamp.ts to the canonical committed placeholder, UNCONDITIONALLY, regardless
//      of what is currently on disk. See "THE IDEMPOTENCY FIX" below for why this step exists.
//   2. Build the deployable bundle the SAME way a deploy does — `wrangler deploy --dry-run --outdir`
//      (the exact bytes `wrangler deploy` would push), now against the just-reset placeholder.
//   3. SHA-384 the produced bundle with the ENGINE's OWN sha384 + hexEncode — the exact value
//      update-apply re-computes (hex, lower-case) — so the in-product display hash uses the same scheme.
//   4. Write src/format/build-stamp.ts exporting ARTEFACT_SHA384 = "<hex>". reportedArtefactSha384()
//      (src/format/build-id.ts) reads it dynamically; its absence is honest "not stamped".
//
// THE IDEMPOTENCY FIX. Before step 1 existed, this script hashed whatever was ALREADY
// sitting in build-stamp.ts and then overwrote that file with the result: a hash computed over its own
// prior output, fed back in as the next run's input. Two consecutive runs against one checkout, same
// commit, same config, nothing else touched, produced two different, unrelated digests from identical
// source, because the second run's input already carried the first run's output.
//
// The fix is the standard one for a self-referential hash: compute it over inputs that exclude the field
// carrying it. Concretely, that means never trusting whatever is currently on disk — reset to the fixed,
// canonical placeholder immediately before every hash-producing build, every single time. That makes the
// computation a pure function of the source tree and the wrangler config again, independent of how many
// times this script has already run against the checkout or in what order.
//
// It writes ONLY src/format/build-stamp.ts. It runs no deploy and contacts no network beyond wrangler's
// local dry-run bundling. Usage:
//   node scripts/stamp-build-id.mjs                 # reset, build via wrangler dry-run, then stamp
//   node scripts/stamp-build-id.mjs --bundle <path> # hash an already-built bundle (e.g. dist/index.js);
//                                                     the reset does not apply here, since no build runs in
//                                                     this process — the caller is responsible for whatever
//                                                     produced that bundle.
//   node scripts/stamp-build-id.mjs --main-module <name>   # entry filename (default index.js)
//
// build-stamp.ts is TRACKED but carries only the "unstamped-build" placeholder in source control (so the
// source typechecks + tests run with no build step); this step OVERWRITES it with the real digest at
// build, like wrangler.deploy.toml. Commit it only in placeholder form.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode } from "../src/crypto/bytes.ts";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
export const ENGINE_DIR = path.join(SCRIPT_DIR, "..");
export const STAMP_PATH = path.join(ENGINE_DIR, "src", "format", "build-stamp.ts");

// The EXACT text committed to src/format/build-stamp.ts in source control. Not read off disk at run time
// (disk content is precisely what this script cannot trust — that is the defect being fixed), so this is a
// literal, checked-in copy. lib/test/stamp-build-id-source-parity.test-style checking that the two stay in
// sync belongs to whatever repo-wide "generated file matches its generator" convention exists; keeping it
// here as a single literal (rather than re-deriving it) is deliberate: the placeholder's CONTENT is not
// itself a build output, it is a fixed constant this script resets to, and re-deriving a fixed constant
// from itself would be the same self-reference shape this file exists to close.
const PLACEHOLDER_BODY = `// The build-time artefact-hash stamp (W1 provenance). This committed file ships the UNSTAMPED
// placeholder; scripts/stamp-build-id.mjs OVERWRITES it at build time with the real SHA-384 (hex,
// lower-case) of the deployable engine bundle that build produced. The placeholder is deliberately NOT
// a 96-hex-char string, so reportedArtefactSha384() (src/format/build-id.ts) rejects it and the engine
// honestly reports NO stamped hash until a real build stamps one, never a fabricated value.
//
// This file is TRACKED (so the source typechecks + tests run without a build step) but is a DERIVED
// artefact at build time, like wrangler.deploy.toml: a deploy regenerates it. Commit it ONLY in its
// placeholder form; do not commit a stamped value (the stamp is per-build and reproducible from source).
/**
 * The build-time artefact hash. In committed source this is the \`"unstamped-build"\` placeholder;
 * scripts/stamp-build-id.mjs overwrites it at build time with the lowercase-hex SHA-384 of the
 * deployable bundle. reportedArtefactSha384 rejects the placeholder, so the engine reports no
 * stamped hash until a real build stamps one.
 */
export const ARTEFACT_SHA384 = "unstamped-build";
`;

/**
 * Resets build-stamp.ts to the canonical, committed placeholder — UNCONDITIONALLY, regardless of what is
 * currently on disk. This is the fix: called immediately before every hash-producing build (stampOnce
 * below), so a leftover digest from any prior run, on this checkout or any other, can never leak into the
 * bundle about to be hashed. Exported so the idempotency mutation test can call it directly and so it can
 * be invoked stand-alone (e.g. to restore a checkout left mid-stamp).
 */
export function resetStampToPlaceholder(stampPath = STAMP_PATH) {
  writeFileSync(stampPath, PLACEHOLDER_BODY);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq >= 0) out[a.slice(2, eq)] = a.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) out[a.slice(2)] = argv[++i];
    else out[a.slice(2)] = true;
  }
  return out;
}

// buildBundleViaWrangler bundles the engine exactly as a deploy would (wrangler dry-run), locally, no
// network, no auth. Returns the bundle bytes. Mirrors tools/publish-channel.mjs so the in-product hash
// uses the canonical deploy bytes.
export function buildBundleViaWrangler(mainModule, engineDir = ENGINE_DIR) {
  const outDir = mkdtempSync(path.join(tmpdir(), "downpipe-stamp-"));
  try {
    execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", outDir], { cwd: engineDir, stdio: ["ignore", "ignore", "inherit"] });
    const entry = path.join(outDir, mainModule);
    if (!existsSync(entry)) {
      const present = readdirSync(outDir).join(", ");
      throw new Error(`wrangler's dry-run produced no "${mainModule}" (found: ${present || "nothing"}). Pass --bundle <path>, or --main-module to the entry wrangler produced.`);
    }
    return new Uint8Array(readFileSync(entry));
  } catch (e) {
    if (e && e.code === "ENOENT") throw new Error("could not run wrangler. Build the bundle yourself and pass it with --bundle <path>, e.g. `npx wrangler deploy --dry-run --outdir dist` then --bundle dist/index.js.");
    throw e;
  } finally {
    try { rmSync(outDir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

function stampBody(digest) {
  // The wording here is house-style-bound like any other prose this repo writes, and it is bound HARDER
  // than most: this text is written into src/format/, which is inside the one tree lint:prose has always
  // read. An em dash here left the gate GREEN in CI, which grades a clean checkout, and RED on the machine
  // of anybody who had actually built or deployed, on a file whose own first line tells them not to commit
  // it. A permanent false red aimed at the people doing the work is how a gate gets ignored.
  return `// GENERATED by scripts/stamp-build-id.mjs at build time. DO NOT EDIT, DO NOT COMMIT.
// The SHA-384 (hex, lower-case) of the deployable engine bundle this build produced. The engine
// reports it via GET /admin/status.artefactSha384 (read through reportedArtefactSha384 in build-id.ts).
// It is display/cross-check provenance only; the deploy-gating hash is the SIGNED channel's sha384.
export const ARTEFACT_SHA384 = "${digest}";
`;
}

/**
 * Builds the bundle and stamps its digest, once. `resetFirst` (default true, the only mode `main()` ever
 * uses) resets build-stamp.ts to the placeholder immediately before the build, which is what makes repeated
 * calls against the same checkout idempotent. `resetFirst: false` exists ONLY so the mutation test below
 * can reproduce the pre-fix defect on demand, by skipping the fix and hashing whatever is already on disk —
 * it must never be used outside that test.
 *
 * @returns {Promise<{ digest: string, bundleBytes: number }>}
 */
export async function stampOnce({ mainModule = "index.js", resetFirst = true, stampPath = STAMP_PATH, engineDir = ENGINE_DIR } = {}) {
  if (resetFirst) resetStampToPlaceholder(stampPath);
  const bundle = buildBundleViaWrangler(mainModule, engineDir);
  const digest = hexEncode(await sha384(bundle));
  writeFileSync(stampPath, stampBody(digest));
  return { digest, bundleBytes: bundle.length };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const mainModule = typeof args["main-module"] === "string" ? args["main-module"] : "index.js";

  if (typeof args.bundle === "string") {
    // The reset does not apply here: this branch builds nothing itself, it only hashes bytes the caller
    // already produced. Whatever produced that bundle is responsible for its own correctness.
    const bundle = new Uint8Array(readFileSync(args.bundle));
    const digest = hexEncode(await sha384(bundle));
    writeFileSync(STAMP_PATH, stampBody(digest));
    process.stdout.write(`stamped artefact SHA-384: ${digest}\n  -> ${path.relative(ENGINE_DIR, STAMP_PATH)} (${bundle.length} bundle bytes)\n`);
    return;
  }

  const { digest, bundleBytes } = await stampOnce({ mainModule });
  process.stdout.write(`stamped artefact SHA-384: ${digest}\n  -> ${path.relative(ENGINE_DIR, STAMP_PATH)} (${bundleBytes} bundle bytes)\n`);
}

/**
 * invokedDirectly answers "was this file the one node was pointed at", and it CANONICALISES both
 * sides. The previous form compared `import.meta.url` against `pathToFileURL(process.argv[1]).href`,
 * which changes the scheme but not the path: node resolves a module to its REALPATH before setting
 * import.meta.url, while argv[1] is left exactly as the caller typed it. Reached through a symlinked
 * path the two therefore differ, and an uncanonicalised guard concludes it is not the entry point,
 * stamps nothing and exits 0.
 *
 * That silence is the whole defect, because scripts/deploy.sh runs this script as
 * `node scripts/stamp-build-id.mjs || echo "artefact-hash stamp skipped ..."`. The warning is the
 * operator's only signal that the deployed engine will self-report no artefact hash, and it is
 * reached only on a NON-ZERO exit, so a guard that declines silently at exit 0 suppresses the very
 * message written to cover it. Measured: an absolute path through a symlink declines, and so does a
 * relative path with a symlink component; deploy.sh's own shape (cd to the repo root, then a
 * relative path) does not, because process.cwd() is physical. The exposure today is therefore
 * narrow, and one edit to how deploy.sh spells the path would widen it without a word of warning.
 *
 * Only realpathSync on BOTH sides closes this. It is spelled out here rather than imported from
 * test/lib/verdict-guard.ts (isEntryPoint) because that module installs a process exit hook that
 * forces a non-zero exit when no verdict is declared, which is correct for a validator and wrong for
 * a build script. scripts/verdict-guard-gate.mjs enforces the canonicalising shape across every
 * derived entry point, this file among them.
 */
function invokedDirectly() {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(argv1);
  } catch {
    // A path that cannot be resolved is not the entry point, and must not throw out of a top-level guard.
    return false;
  }
}

if (invokedDirectly()) {
  main().catch((e) => {
    process.stderr.write(`stamp-build-id: ${e.message}\n`);
    process.exit(1);
  });
}
