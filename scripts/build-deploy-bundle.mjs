// Builds the engine bundle that `npm run deploy` uploads, ONCE, and prints the SHA-384 of its main module.
//
// WHY IT EXISTS. GET /admin/status reports an artefact hash, and a bundle cannot carry its own hash: writing
// a digest into src/format/build-stamp.ts and bundling again changes the bytes the digest was taken over
// (measured: the re-bundled file is 81 bytes longer than the one hashed). So the hash is taken, and
// recorded, outside the bytes:
//
//   1. reset src/format/build-stamp.ts to its committed placeholder, so the bundle is the unstamped one a
//      release build (scripts/build-release.mjs) makes from the same source, and no digest left behind by
//      an earlier stamp rides into it;
//   2. bundle once with `wrangler deploy --dry-run --outdir <dir>` against the deploy's own config;
//   3. SHA-384 the main module with the engine's own sha384 + hexEncode and print it, hex, lower-case.
//
// deploy.sh then uploads THAT file with `wrangler deploy <dir>/index.js --no-bundle` and records the digest
// as the DEPLOYED_ARTEFACT_SHA384 plain-text binding (`--var`), which status reports with
// artefactSha384Source "deployed". With --no-bundle wrangler uploads the file as it is, so the recorded value
// is the hash of the served main module. test/validate-deploy-artefact-hash.ts checks that end to end.
//
// It writes the bundle directory and src/format/build-stamp.ts (back to the placeholder), and nothing
// else. It uploads nothing and contacts no account. stdout carries the digest only, so a caller can read it
// with $(...); wrangler's own output goes to stderr.
//
// Usage: node scripts/build-deploy-bundle.mjs --config <wrangler config> --outdir <dir> [--main-module index.js]
//

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { ENGINE_DIR, resetStampToPlaceholder } from "./stamp-build-id.mjs";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) out[a.slice(2)] = argv[++i];
    else out[a.slice(2)] = true;
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (typeof args.config !== "string" || typeof args.outdir !== "string") {
    throw new Error("usage: node scripts/build-deploy-bundle.mjs --config <wrangler config> --outdir <dir> [--main-module index.js]");
  }
  const mainModule = typeof args["main-module"] === "string" ? args["main-module"] : "index.js";
  const outDir = path.resolve(process.cwd(), args.outdir);
  // The directory is this script's output and nothing else; a leftover module from an earlier build must not
  // be uploaded beside the new one.
  rmSync(outDir, { recursive: true, force: true });

  resetStampToPlaceholder();
  execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", outDir, "-c", args.config], { cwd: ENGINE_DIR, stdio: ["ignore", process.stderr, process.stderr] });
  const entry = path.join(outDir, mainModule);
  if (!existsSync(entry)) {
    const present = existsSync(outDir) ? readdirSync(outDir).join(", ") : "";
    throw new Error(`wrangler's dry-run produced no "${mainModule}" in ${outDir} (found: ${present || "nothing"}); nothing was deployed.`);
  }
  const digest = hexEncode(await sha384(new Uint8Array(readFileSync(entry))));
  process.stdout.write(`${digest}\n`);
}

main().catch((e) => {
  process.stderr.write(`build-deploy-bundle: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
