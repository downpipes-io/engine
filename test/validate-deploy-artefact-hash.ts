// The artefact hash an `npm run deploy` install reports must be the SHA-384 of the bytes wrangler uploads.
//
// THE DEFECT THIS PINS. GET /admin/status reports artefactSha384. scripts/deploy.sh stamped it into
// src/format/build-stamp.ts from a `wrangler deploy --dry-run` build that held the placeholder, then ran a
// plain `wrangler deploy`, which bundled the source again with the digest in place of the placeholder. The
// uploaded main module was 81 bytes longer than the one hashed, so every install reported a hash that could
// not equal the SHA-384 of what Cloudflare serves.
//
// HOW. The real deploy.sh is read and the span from the preflight switch to the `wrangler deploy` call is
// extracted by anchor (as test/validate-deploy-resumable.ts does), so whatever that span does to build, stamp
// and upload is what runs. It runs under /bin/sh in a COPY of this tree (src, scripts, config, with
// node_modules linked), so the checkout is never written. Three commands are shadowed: the preflight is
// skipped, `node scripts/sync-bindings.mjs` copies wrangler.toml to wrangler.deploy.toml (it would read the
// live account), and the real `wrangler deploy` is given `--dry-run --outdir <capture>` so wrangler writes
// the bytes it would upload instead of uploading them. Everything else, including every build, is real.
//
// Then the engine's OWN status resolution (the copy's buildStatus, fed the copy's reportedArtefactSha384 and
// the `--var` bindings the deploy passed) gives the value the deployed engine would report, and it must equal
// the SHA-384 of the captured main module. On the stamp-then-rebundle deploy.sh this is red; with
// scripts/build-deploy-bundle.mjs and `--no-bundle` it is green.
//
// NEGATIVE CONTROL: the same comparison over the captured bytes with one byte changed must disagree, so the
// check can fail. The assumption that wrangler.toml pins no artefact hash of its own is checked, not assumed.
//
// It runs real wrangler builds, so like test/validate-stamp-idempotency.ts it is not a validate:chain member;
// it runs in CI's stamp-idempotency job. Run: node test/validate-deploy-artefact-hash.ts

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const LINES = readFileSync(join(ENGINE_DIR, "scripts", "deploy.sh"), "utf8").split("\n");

/** The real deploy.sh's lines from the start anchor (inclusive) to the end anchor (exclusive); each must match once. */
function extractBetween(startAnchor: string, endAnchor: string): string {
  const starts = LINES.flatMap((l, i) => (l.includes(startAnchor) ? [i] : []));
  const ends = LINES.flatMap((l, i) => (l.includes(endAnchor) ? [i] : []));
  if (starts.length !== 1 || ends.length !== 1) throw new Error(`deploy.sh anchors matched ${starts.length} and ${ends.length} lines (expected 1 each): "${startAnchor}" .. "${endAnchor}"; update this test's anchors`);
  if (ends[0]! <= starts[0]!) throw new Error("deploy.sh extraction range is empty or inverted; update this test's anchors");
  return LINES.slice(starts[0]!, ends[0]!).join("\n");
}

// From the preflight switch (skipped below) to the line after the upload. Everything the deploy does to the
// tree and to the bytes before it uploads lies in this span.
const DEPLOY_SPAN = extractBetween('if [ "$SKIP_PREFLIGHT" = "1" ]; then', "WRANGLER_EXIT=$?");

async function sha384Hex(bytes: Uint8Array): Promise<string> {
  return hexEncode(await sha384(bytes));
}

async function main(): Promise<void> {
  const work = mkdtempSync(join(tmpdir(), "dp-deploy-artefact-hash-"));
  try {
    const tree = join(work, "engine");
    for (const p of ["src", "scripts", "package.json", "wrangler.toml", "tsconfig.json"]) cpSync(join(ENGINE_DIR, p), join(tree, p), { recursive: true });
    symlinkSync(realpathSync(join(ENGINE_DIR, "node_modules")), join(tree, "node_modules"));
    const capture = join(work, "uploaded");
    const argvFile = join(work, "wrangler-deploy-argv.txt");
    const logFile = join(work, "deploy-span.log");

    const toml = readFileSync(join(tree, "wrangler.toml"), "utf8");
    ok("wrangler.toml pins no artefact hash of its own (so only the deploy's --var values can)", !/^\s*(DEPLOYED_)?ARTEFACT_SHA384\s*=/m.test(toml));

    const harness = `
set -e
cd ${JSON.stringify(tree)}
SKIP_PREFLIGHT=1
node() {
  case "$1" in
    scripts/sync-bindings.mjs) cp wrangler.toml wrangler.deploy.toml; return 0 ;;
  esac
  command node "$@"
}
npx() {
  case "$*" in
    *"deployments status"*) return 0 ;;
    *"--dry-run"*) command npx "$@" ;;
    "wrangler deploy"*) printf '%s\\n' "$@" > ${JSON.stringify(argvFile)}; command npx "$@" --dry-run --outdir ${JSON.stringify(capture)} ;;
    *) command npx "$@" ;;
  esac
}
${DEPLOY_SPAN}
exit $?
`;
    let spanExit = 0;
    try {
      const out = execFileSync("/bin/sh", ["-c", harness], { encoding: "utf8", cwd: tree, env: { ...process.env, WRANGLER_SEND_METRICS: "false" }, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
      writeFileSync(logFile, out);
    } catch (e) {
      const err = e as { status?: number; stdout?: string; stderr?: string };
      spanExit = err.status ?? 1;
      console.log(`${String(err.stdout ?? "")}\n${String(err.stderr ?? "")}`.slice(-4000));
    }
    ok(`the deploy span ran to the upload and wrangler accepted it (exit ${spanExit})`, spanExit === 0);
    const uploadedPath = join(capture, "index.js");
    ok("wrangler wrote the main module it would upload", existsSync(uploadedPath) && existsSync(argvFile));
    if (!existsSync(uploadedPath) || !existsSync(argvFile)) return;

    const uploaded = new Uint8Array(readFileSync(uploadedPath));
    const uploadedSha = await sha384Hex(uploaded);

    // The deployed engine's env: the plain-text bindings this deploy passed with --var.
    const argv = readFileSync(argvFile, "utf8").split("\n").filter((l) => l !== "");
    const env: Record<string, string> = {};
    argv.forEach((a, i) => {
      if (a === "--var" && argv[i + 1] !== undefined) {
        const v = argv[i + 1]!;
        const c = v.indexOf(":");
        if (c > 0) env[v.slice(0, c)] = v.slice(c + 1);
      }
    });

    // The engine's own resolution, from the COPY: build-stamp.ts there is exactly what was bundled.
    const buildId = (await import(pathToFileURL(join(tree, "src", "format", "build-id.ts")).href)) as typeof import("../src/format/build-id.ts");
    const statusMod = (await import(pathToFileURL(join(tree, "src", "admin", "status.ts")).href)) as typeof import("../src/admin/status.ts");
    const stamped = await buildId.reportedArtefactSha384();
    const bundleText = new TextDecoder().decode(uploaded);
    ok(`the build stamp the engine reads is the one inside the uploaded bytes (${stamped ?? "placeholder"})`, bundleText.includes(`"${stamped ?? "unstamped-build"}"`));
    const reported = statusMod.buildStatus(env as unknown as Env, 0, { selfReportedArtefactSha384: stamped }).artefactSha384;

    console.log(`  uploaded main module: ${uploaded.length} bytes, sha384 ${uploadedSha}`);
    console.log(`  the engine would report: ${reported ?? "(nothing)"}`);
    ok("the deployed engine would report an artefact hash", reported !== undefined);
    ok("the reported artefact hash IS the SHA-384 of the bytes wrangler uploads", reported === uploadedSha);

    // NEGATIVE CONTROL: the comparison can fail.
    const altered = uploaded.slice();
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 0x01;
    ok("control: one changed byte gives a hash the report does not match", (await sha384Hex(altered)) !== reported);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

main()
  .then(() => {
    console.log(failures === 0 ? `\nPASS deploy-artefact-hash: ${checks} checks` : `\nFAIL deploy-artefact-hash: ${failures} of ${checks} checks failed`);
    verdictReached(failures, checks);
    process.exit(failures === 0 ? 0 : 1);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
