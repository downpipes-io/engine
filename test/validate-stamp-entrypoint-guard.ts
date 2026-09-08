// Attack on the entry-point guard in scripts/stamp-build-id.mjs.
//
// The guard decides whether the script was invoked directly (and should stamp, exiting non-zero on
// failure) or merely imported as a library (and should run nothing). A naive comparison such as
//
//   const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
//
// is not enough: pathToFileURL changes the SCHEME, not the PATH. Node resolves a module to its realpath
// before it sets import.meta.url, while argv[1] stays exactly as the caller typed it, so reached through
// a symlinked path the two strings differ, the guard concludes it is not the entry point, and the script
// stamps nothing and exits 0.
//
// WHY THAT MATTERS. scripts/deploy.sh runs it as:
//
//   node scripts/stamp-build-id.mjs || echo "artefact-hash stamp skipped (...); continuing deploy"
//
// The echo is the operator's ONLY warning that the deployed engine will self-report no artefact hash,
// and `||` fires only on a NON-ZERO exit. A guard that declines silently at exit 0 therefore suppresses
// the exact message meant to cover it: the deploy ships an unstamped engine and says nothing.
//
// SILENCE IS THE FAILURE MODE, so an exit-code-only assertion cannot see it. A guard that declines exits
// 0 on the symlink path exactly like a guard that stamped successfully; only the OUTPUT tells them apart.
// Every case below asserts on captured stdout, and case 5 re-evaluates the naive (uncanonicalised)
// expression against the same argv/meta pair to prove the passing cases are not vacuous.
//
// This mutates the checkout's REAL src/format/build-stamp.ts (STAMP_PATH is derived from the script's
// own location and cannot be redirected) and restores the committed content in a finally block on every
// exit path. It uses --bundle so it hashes bytes this file writes rather than spawning a wrangler
// build, which keeps it in the fast chain: test/validate-stamp-idempotency.ts owns the slow build
// property, this file owns the guard.
//
// Run: node test/validate-stamp-entrypoint-guard.ts

import { readFileSync, writeFileSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { STAMP_PATH, ENGINE_DIR } from "../scripts/stamp-build-id.mjs";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `  (${detail})` : ""}`);
  if (!cond) failures++;
}

const SCRIPT_REL = path.join("scripts", "stamp-build-id.mjs");
const STAMPED_LINE = /^stamped artefact SHA-384: [0-9a-f]{96}$/m;

/** Runs a command and returns what an operator would actually see: the streams AND the code. */
function run(argv: string[], cwd: string): { stdout: string; stderr: string; code: number } {
  const r = spawnSync(process.execPath, argv, { cwd, encoding: "utf8" });
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.status ?? -1 };
}

const committedStamp = readFileSync(STAMP_PATH, "utf8");
const tmp = mkdtempSync(path.join(tmpdir(), "stamp-entrypoint-"));

try {
  // A small file of stable bytes to hash, so no case depends on a wrangler build.
  const bundlePath = path.join(tmp, "bundle.js");
  writeFileSync(bundlePath, "export default {};\n");

  // engineLink -> ENGINE_DIR. Reaching the identical script file through this symlink is what the
  // retired guard could not survive.
  const engineLink = path.join(tmp, "englink");
  symlinkSync(ENGINE_DIR, engineLink, "dir");
  const viaLink = path.join(engineLink, SCRIPT_REL);
  const viaReal = path.join(ENGINE_DIR, SCRIPT_REL);

  console.log("\nscripts/stamp-build-id.mjs entry-point guard");

  // ---- 1. clean tree, direct absolute path: it must still do its job and SAY so -------------------
  {
    const r = run([viaReal, "--bundle", bundlePath], ENGINE_DIR);
    ok("clean absolute path: prints its stamped-artefact verdict", STAMPED_LINE.test(r.stdout), JSON.stringify(r.stdout.slice(0, 200)));
    ok("clean absolute path: exits 0", r.code === 0, `code ${r.code} ${r.stderr.slice(0, 200)}`);
    ok("clean absolute path: actually rewrote build-stamp.ts", readFileSync(STAMP_PATH, "utf8") !== committedStamp);
  }

  // ---- 2. the case the retired guard lost: absolute path THROUGH a symlink ------------------------
  writeFileSync(STAMP_PATH, committedStamp);
  {
    const r = run([viaLink, "--bundle", bundlePath], ENGINE_DIR);
    ok("absolute path through a symlink: prints its verdict (retired guard printed NOTHING here)", STAMPED_LINE.test(r.stdout), JSON.stringify(r.stdout.slice(0, 200)));
    ok("absolute path through a symlink: stamped, so the deploy cannot ship unstamped in silence", readFileSync(STAMP_PATH, "utf8") !== committedStamp);
    ok("absolute path through a symlink: exit code alone CANNOT tell the two guards apart", r.code === 0);
  }

  // ---- 3. relative path carrying a symlink component ----------------------------------------------
  writeFileSync(STAMP_PATH, committedStamp);
  {
    const r = run([path.join("englink", SCRIPT_REL), "--bundle", bundlePath], tmp);
    ok("relative path with a symlink component: prints its verdict", STAMPED_LINE.test(r.stdout), JSON.stringify(r.stdout.slice(0, 200)));
    ok("relative path with a symlink component: stamped", readFileSync(STAMP_PATH, "utf8") !== committedStamp);
  }

  // ---- 4. the guard still HAS teeth: imported as a library, it must run nothing --------------------
  // Widening a guard until it fires always is not a fix, it is a deletion. An importer is genuinely not
  // the entry point, and must get no stamp and no output.
  writeFileSync(STAMP_PATH, committedStamp);
  {
    const importer = path.join(tmp, "importer.mjs");
    writeFileSync(importer, `import ${JSON.stringify(pathToFileURL(viaReal).href)};\nprocess.stdout.write("importer finished\\n");\n`);
    const r = run([importer], ENGINE_DIR);
    ok("imported as a library: the importer ran", r.stdout.includes("importer finished"), JSON.stringify(r.stdout.slice(0, 200)));
    ok("imported as a library: main() did NOT run (no stamped-artefact line)", !STAMPED_LINE.test(r.stdout), JSON.stringify(r.stdout.slice(0, 200)));
    ok("imported as a library: build-stamp.ts untouched", readFileSync(STAMP_PATH, "utf8") === committedStamp);
  }

  // ---- 5. non-vacuity: the retired expression still decides DECLINES on case 2's inputs ------------
  // Without this, cases 2 and 3 would pass just as well against a guard that was never broken, and the
  // test would prove nothing about the fix.
  {
    const metaUrl = pathToFileURL(viaReal).href; // what node sets: the REALPATH
    const retired = metaUrl === pathToFileURL(viaLink).href; // argv[1] as typed, scheme changed, path not
    ok("retired guard expression DECLINES on the symlinked path (so cases 2-3 are not vacuous)", retired === false);
    const fixed = fileURLToPath(metaUrl) === fileURLToPath(pathToFileURL(viaReal).href);
    ok("canonicalised comparison agrees the two paths are the same file", fixed === true);
  }

  // ---- 6. the source no longer carries the naive, uncanonicalised comparison -----------------------
  // Checked AT the comparison, not file-wide. A file-wide /realpathSync/ test would pass the moment the
  // file imports realpathSync from node:fs, which this one does on line 53, so it would clear a naive
  // comparison sitting 150 lines below the import. This uses a statement-window rule instead.
  {
    const lines = readFileSync(viaReal, "utf8")
      .replace(/^\s*(\/\/.*|\*.*|\/\*.*)$/gm, "")
      .split("\n");
    // Broad on purpose: any line that both names an entry-point identity and compares. A regex that
    // demanded the token be ADJACENT to the `===` would miss the fixed form, where realpathSync and
    // fileURLToPath sit between them, and so would silently have nothing to check.
    const COMPARE = /(?:import\.meta\.url|process\.argv\[1\])[^\n]*===|===[^\n]*(?:import\.meta\.url|process\.argv\[1\])/;
    const CANON = /realpathSync\s*\(|isEntryPoint\s*\(/;
    const compares = lines.filter((l) => COMPARE.test(l));
    const bare = compares.filter((l, _i) => !CANON.test(l));
    ok("scripts/stamp-build-id.mjs still HAS an entry-point comparison (the check is not vacuous)", compares.length > 0);
    ok("every entry-point comparison in the script canonicalises at the comparison itself", bare.length === 0, bare.join(" | ").slice(0, 200));
  }
} finally {
  writeFileSync(STAMP_PATH, committedStamp);
  rmSync(tmp, { recursive: true, force: true });
}

if (failures > 0) process.exitCode = 1;
console.log(`\n${failures === 0 ? "STAMP ENTRY-POINT GUARD PASS" : `STAMP ENTRY-POINT GUARD: ${failures} FAILURE(S)`}`);
if (failures > 0) process.exit(1);
