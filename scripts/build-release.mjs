// Deterministic release-artefact build. Produces the engine bundle the update channel
// publishes and the safe-apply harness deploys, as a repeatable function of the COMMITTED SOURCE
// alone: same commit, same lockfile toolchain, same bytes, on any machine. That byte-stability is
// what lets the channel digest, the CI attestation subject, a third party's rebuild and the
// engine's own self-report all name the SAME hash.
//
// THE RELEASE ARTEFACT IS THE UNSTAMPED BUNDLE. src/format/build-stamp.ts must be at its committed
// "unstamped-build" placeholder when this runs: a stamped tree builds a bundle that differs from
// the one whose digest was stamped (the stamp cannot contain its own bundle's hash), which is
// exactly the two-digest confusion this script exists to end. scripts/stamp-build-id.mjs hashes
// the same unstamped bundle, so its self-report equals this artefact's digest by construction.
//
// Guards (each refuses, never warns-and-continues):
//   1. build-stamp.ts must be the committed placeholder (see above).
//   2. The git tree must be CLEAN (a release built from uncommitted source is unattestable);
//      --allow-dirty overrides for local experiments only, never for a real release.
//
// The bundle itself is produced by `wrangler deploy --dry-run --outdir` (the exact bytes a real
// deploy pushes), with wrangler pinned by the lockfile (`npm ci` reproduces it exactly) and
// telemetry off. Byte-stability is EMPIRICAL, not assumed: the reproducibility-check CI workflow
// builds twice on two runner images from different working paths and fails on any digest drift,
// and VERIFY.md's third-party rebuild claim stands only while that check is green (prove, then claim).
//
// Usage:
//   node scripts/build-release.mjs                       # writes dist/engine-<version>.mjs
//   node scripts/build-release.mjs --out <path>          # explicit artefact path
//   node scripts/build-release.mjs --main-module <name>  # entry filename (default index.js)
//   node scripts/build-release.mjs --allow-dirty         # local experiments only
// Prints JSON: { version, out, sha384, sha256, bytes }.

import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode } from "../src/crypto/bytes.ts";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_DIR = path.join(SCRIPT_DIR, "..");
const STAMP_PATH = path.join(ENGINE_DIR, "src", "format", "build-stamp.ts");

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

const args = parseArgs(process.argv.slice(2));

// Guard 1: the release artefact is the unstamped bundle.
const stamp = readFileSync(STAMP_PATH, "utf8");
if (!stamp.includes('= "unstamped-build"')) {
  process.stderr.write(
    "build-release: src/format/build-stamp.ts is not at its committed placeholder. The release artefact is the UNSTAMPED bundle (one digest across channel, attestation, rebuild and self-report); restore the placeholder (git checkout -- src/format/build-stamp.ts) and re-run.\n",
  );
  process.exit(1);
}

// Guard 2: a release must be a function of a commit, or the attestation names bytes nobody can
// reproduce. --allow-dirty is for local experiments only.
if (!args["allow-dirty"]) {
  const dirty = execFileSync("git", ["status", "--porcelain"], { cwd: ENGINE_DIR, encoding: "utf8" }).trim();
  if (dirty !== "") {
    process.stderr.write(`build-release: the git tree is dirty; a release artefact must build from committed source alone. Commit or stash first (or --allow-dirty for a local experiment):\n${dirty}\n`);
    process.exit(1);
  }
}

const mainModule = typeof args["main-module"] === "string" ? args["main-module"] : "index.js";
const version = JSON.parse(readFileSync(path.join(ENGINE_DIR, "package.json"), "utf8")).version;
const outPath = typeof args.out === "string" ? args.out : path.join(ENGINE_DIR, "dist", `engine-${version}.mjs`);

const outDir = mkdtempSync(path.join(tmpdir(), "downpipe-release-"));
let bundle;
try {
  // The exact bytes `wrangler deploy` would push, with wrangler resolved from the lockfile-pinned
  // install and telemetry off. TZ/LC_ALL are fixed so nothing locale-shaped can leak into the
  // output; the reproducibility check is what PROVES nothing else does.
  execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", outDir], {
    cwd: ENGINE_DIR,
    stdio: ["ignore", "ignore", "inherit"],
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", TZ: "UTC", LC_ALL: "C" },
  });
  const entry = path.join(outDir, mainModule);
  if (!existsSync(entry)) {
    const present = readdirSync(outDir).join(", ");
    throw new Error(`wrangler's dry-run produced no "${mainModule}" (found: ${present || "nothing"})`);
  }
  bundle = new Uint8Array(readFileSync(entry));
} finally {
  try {
    rmSync(outDir, { recursive: true, force: true });
  } catch {
    /* best effort cleanup */
  }
}

mkdirSync(path.dirname(outPath), { recursive: true });
writeFileSync(outPath, bundle);

// Both digests: sha384 is the channel's gating scheme (the engine's own primitive, so the hex
// matches what update-apply recomputes); sha256 is what SHA256SUMS.txt, cosign subjects and SLSA
// provenance name (the supply-chain tooling lingua franca).
const digest384 = hexEncode(await sha384(bundle));
const digest256 = createHash("sha256").update(bundle).digest("hex");

// CI identifiers (present only under GitHub Actions): these become the channel's provenance block
// via the ceremony, which REFUSES a facts file without them, so a local build can never be passed
// off as an attested release. They ride release-facts.json, which SHA256SUMS.txt names and the
// release workflow cosign-signs, so they are CI's own attested claims, not operator input.
const ciFacts = {
  ...(process.env.GITHUB_REPOSITORY ? { repo: process.env.GITHUB_REPOSITORY } : {}),
  ...(process.env.GITHUB_SHA ? { commit: process.env.GITHUB_SHA } : {}),
  ...(process.env.GITHUB_REF_TYPE === "tag" && process.env.GITHUB_REF_NAME ? { tag: process.env.GITHUB_REF_NAME } : {}),
  ...(process.env.GITHUB_RUN_ID ? { runId: process.env.GITHUB_RUN_ID } : {}),
};
process.stdout.write(JSON.stringify({ version, out: outPath, sha384: digest384, sha256: digest256, bytes: bundle.length, ...ciFacts }, null, 2) + "\n");
