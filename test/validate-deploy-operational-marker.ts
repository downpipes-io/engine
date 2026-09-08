// Validates the fix in scripts/deploy.sh: the guided deploy script must REFUSE to silently
// auto-generate a replacement operational key when the engine's own OPERATIONAL_RETIRED marker says
// the owner deliberately switched to break-glass-only (POST /keys/break-glass-only), requiring an
// explicit --enable-operational / --yes override, while a genuinely fresh estate (no marker at all)
// keeps today's front-loaded, auto-enable behaviour, and a live OPERATIONAL_PRIVATE always
// short-circuits before the marker is even consulted.
//
// This drives the REAL deploy.sh source, extracted by anchor rather than hand-copied, so the test
// cannot silently drift from the file it validates: if deploy.sh is refactored and an anchor no
// longer matches exactly once, extraction throws loudly instead of quietly testing stale text. The
// extracted fragments run under /bin/sh (deploy.sh's own interpreter) in a throwaway temp directory,
// with `node` and `npx` shadowed as recording shell functions: no real wrangler call, no real key
// generation, no network, nothing touches the real engine checkout. Two fragments are exercised:
//   1. the flag parser, which now sets TWO independent switches from "$@": ENABLE_OPERATIONAL and
// SKIP_PREFLIGHT. The second is the bypass for the blocking preflight added, and
//      most of what is graded about it here is negative: which flags must NOT turn it on. --yes is
//      the one that matters, because it reads like a general "stop asking me" while meaning only
//      "stop asking me about the operational key", and a bypass that a second flag can set by
//      accident is a bypass nobody chose.
//   2. the SIGNER_PRIVATE-present branch's operational-key check, fed a
//      synthetic `wrangler secret list` JSON body and a pre-set ENABLE_OPERATIONAL.
// Run: node test/validate-deploy-operational-marker.ts

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEPLOY_SH = readFileSync(join(ENGINE_DIR, "scripts", "deploy.sh"), "utf8");
const LINES = DEPLOY_SH.split("\n");

// extractBetween slices the REAL deploy.sh's lines between two exact-substring anchors, requiring each
// to match EXACTLY ONE line (throwing otherwise), so a future refactor of deploy.sh either keeps this
// test extracting the current logic, or fails loudly telling the maintainer to update the anchors,
// rather than silently validating a stale, hand-copied duplicate.
function extractBetween(startAnchor: string, endAnchor: string, startInclusive: boolean): string {
  const starts: number[] = [];
  const ends: number[] = [];
  LINES.forEach((l, i) => {
    if (l.includes(startAnchor)) starts.push(i);
    if (l.includes(endAnchor)) ends.push(i);
  });
  if (starts.length !== 1) throw new Error(`extraction anchor "${startAnchor}" matched ${starts.length} lines in deploy.sh (expected exactly 1); update this test's anchors`);
  if (ends.length !== 1) throw new Error(`extraction anchor "${endAnchor}" matched ${ends.length} lines in deploy.sh (expected exactly 1); update this test's anchors`);
  const from = startInclusive ? starts[0]! : starts[0]! + 1;
  const to = ends[0]!;
  if (to <= from) throw new Error(`extraction range is empty or inverted for "${startAnchor}" .. "${endAnchor}"; update this test's anchors`);
  return LINES.slice(from, to).join("\n");
}

// Fragment 1: the flag parser, inclusive of its own "ENABLE_OPERATIONAL=0" initialiser through the
// line before the blocking preflight.
//
// THE END ANCHOR NAMES THE PARSER'S ACTUAL END rather than where its successor happens to start: an
// anchor on the next unrelated command would silently widen the fragment if deploy.sh ever grew a new
// step in between, and both anchors would still match exactly one line each, so the extractor's own
// tripwire would not fire. Anchoring on the preflight's own banner avoids that.
const FLAG_PARSER = extractBetween("ENABLE_OPERATIONAL=0", "# BLOCKING PREFLIGHT. THIS SCRIPT USED TO GRADE NOTHING AT ALL.", true);

// Fragment 2: the operational-key check itself -- everything from the line AFTER the `SECRETS=` read
// (the test supplies $SECRETS directly) through the line before the unrelated BOOTSTRAP_OWNER_EMAIL check.
const KEY_CHECK = extractBetween('SECRETS="$(npx wrangler secret list', '"BOOTSTRAP_OWNER_EMAIL"', false);

// runShFragment runs `body` under /bin/sh in a fresh scratch temp directory, with `node` and `npx`
// shadowed as shell functions that record every invocation (verbatim argv, via "$*") to a call log
// instead of doing real work. `generate-keys.ts` invocations are special-cased to drop the dummy
// .staging/*.b64 files deploy.sh's own `npx wrangler secret put ... < file` lines read, so those real
// shell redirections succeed without ever running real crypto or touching a real wrangler binary.
// Returns the captured stdout (stdout+stderr merged is NOT used: a non-zero exit is captured via the
// catch arm so a genuine script bug shows up as a readable diagnostic, not a crashed test run) and the
// ordered list of shadowed invocations.
function runShFragment(body: string, env: Record<string, string>): { stdout: string; calls: string[] } {
  const scratch = mkdtempSync(join(tmpdir(), "dp-deploy-marker-"));
  const callLog = join(scratch, "calls.log");
  writeFileSync(callLog, "");
  const harness = `
set -e
cd ${JSON.stringify(scratch)}
CALL_LOG=${JSON.stringify(callLog)}
node() {
  printf '%s\\n' "node $*" >> "$CALL_LOG"
  case "$*" in
    *generate-keys.ts*)
      mkdir -p ./recovery-kit/.staging
      echo dummy > ./recovery-kit/.staging/signer-private.b64
      echo dummy > ./recovery-kit/.staging/break-glass-public.b64
      echo dummy > ./recovery-kit/.staging/operational-public.b64
      echo dummy > ./recovery-kit/.staging/operational-private.b64
      ;;
  esac
  return 0
}
npx() {
  printf '%s\\n' "npx $*" >> "$CALL_LOG"
  return 0
}
${body}
`;
  let stdout: string;
  try {
    stdout = execFileSync("/bin/sh", ["-c", harness], { encoding: "utf8", env: { ...process.env, ...env }, cwd: scratch });
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; message?: string };
    stdout = `${err.stdout ?? ""}\n[sh exited non-zero -- see stderr] ${err.stderr ?? err.message ?? ""}`;
  }
  let callLogText = "";
  try {
    callLogText = readFileSync(callLog, "utf8");
  } catch {
    /* no calls made */
  }
  rmSync(scratch, { recursive: true, force: true });
  const calls = callLogText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
  return { stdout, calls };
}

// fakeSecretList builds a synthetic `wrangler secret list` JSON body: an array of {name,type} objects,
// the real shape (values are never returned by the real command either, so deploy.sh's own grep only
// ever checks NAME presence -- this fake matches that exactly).
function fakeSecretList(names: string[]): string {
  return JSON.stringify(names.map((n) => ({ name: n, type: "secret_text" })));
}

function runKeyCheck(names: string[], enableOperational: "0" | "1"): { stdout: string; calls: string[] } {
  const body = `SECRETS=${JSON.stringify(fakeSecretList(names))}\nENABLE_OPERATIONAL=${enableOperational}\n${KEY_CHECK}`;
  return runShFragment(body, {});
}

async function main(): Promise<void> {
  console.log("-- deploy.sh: the --enable-operational / --yes flag parser --");
  {
    const runFlags = (args: string[]): string => {
      const argv = args.map((a) => JSON.stringify(a)).join(" ");
      const body = `set -- ${argv}\n${FLAG_PARSER}\nprintf '%s' "$ENABLE_OPERATIONAL"`;
      return runShFragment(body, {}).stdout.trim();
    };
    ok("no flags at all -> ENABLE_OPERATIONAL stays 0", runFlags([]) === "0");
    ok("--enable-operational alone -> ENABLE_OPERATIONAL becomes 1", runFlags(["--enable-operational"]) === "1");
    ok("--yes (the alias) -> ENABLE_OPERATIONAL becomes 1", runFlags(["--yes"]) === "1");
    ok("an unrelated flag does not set ENABLE_OPERATIONAL", runFlags(["--some-other-flag"]) === "0");
    ok("--yes among OTHER args still sets ENABLE_OPERATIONAL", runFlags(["--dry-run", "--yes"]) === "1");

    // --skip-preflight, the ONLY way to deploy without grading the tree. The assertions that matter
    // here are the negative ones. A bypass flag is dangerous exactly in proportion to how easy it is
    // to set without meaning to, so what is graded below is mostly the set of things that must NOT
    // turn it on: another flag, an unrelated flag, and above all --yes, which reads like a general
    // "stop asking me" and is about the operational key alone. The two switches are independent and
    // this is the only place that says so in something that runs.
    const runSkip = (args: string[]): string => {
      const argv = args.map((a) => JSON.stringify(a)).join(" ");
      const body = `set -- ${argv}\n${FLAG_PARSER}\nprintf '%s' "$SKIP_PREFLIGHT"`;
      return runShFragment(body, {}).stdout.trim();
    };
    ok("no flags at all -> SKIP_PREFLIGHT stays 0 (the preflight is the DEFAULT)", runSkip([]) === "0");
    ok("--skip-preflight -> SKIP_PREFLIGHT becomes 1", runSkip(["--skip-preflight"]) === "1");
    ok("--yes does NOT skip the preflight (it is about the operational key alone)", runSkip(["--yes"]) === "0");
    ok("--enable-operational does NOT skip the preflight", runSkip(["--enable-operational"]) === "0");
    ok("an unrelated flag does not skip the preflight", runSkip(["--some-other-flag"]) === "0");
    ok("a near-miss flag name does not skip the preflight", runSkip(["--skip-preflights"]) === "0");
    ok("--skip-preflight does NOT set ENABLE_OPERATIONAL (the two are independent)", runFlags(["--skip-preflight"]) === "0");
    ok("both flags together set both, each on its own account", runSkip(["--yes", "--skip-preflight"]) === "1" && runFlags(["--yes", "--skip-preflight"]) === "1");
  }

  console.log("\n-- deploy.sh: the operational-key check (inside the SIGNER_PRIVATE-present branch) --");
  {
    const r1 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_RETIRED"], "0");
    ok("marker present, no override -> refuses with the deliberate-choice message", /DELIBERATE choice/.test(r1.stdout));
    ok("marker present, no override -> makes NO node/npx calls at all (nothing generated, nothing PUT)", r1.calls.length === 0);
    ok("marker present, no override -> names both re-enable paths (console and the flag)", /Posture tab/.test(r1.stdout) && /--enable-operational/.test(r1.stdout));

    const r2 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_RETIRED"], "1");
    ok("marker present, ENABLE_OPERATIONAL=1 (the --enable-operational/--yes override) -> proceeds", /Enabling automated restore proof/.test(r2.stdout));
    ok("...and says so (the marker is being overridden, not silently ignored)", /generating a fresh operational key anyway/.test(r2.stdout));
    ok("...and actually calls generate-keys.ts --operational-only", r2.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--operational-only")));
    ok("...and PUTs both OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE", r2.calls.some((c) => c.includes("secret put OPERATIONAL_PUBLIC")) && r2.calls.some((c) => c.includes("secret put OPERATIONAL_PRIVATE")));

    const r3 = runKeyCheck(["SIGNER_PRIVATE"], "0");
    ok("marker ABSENT (a genuinely fresh estate within an existing signer) -> proceeds exactly as before", /Enabling automated restore proof/.test(r3.stdout));
    ok("...with no mention of an overridden marker (there was none to override)", !/generating a fresh operational key anyway/.test(r3.stdout));
    ok("...and calls generate-keys.ts --operational-only, unaffected by this fix", r3.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--operational-only")));

    const r4 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE"], "0");
    ok("OPERATIONAL_PRIVATE present -> the short-circuit 'already on' branch, no calls at all", /Automated restore proof is on/.test(r4.stdout) && r4.calls.length === 0);

    const r5 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE", "OPERATIONAL_RETIRED"], "0");
    ok("OPERATIONAL_PRIVATE present EVEN WITH a stale marker -> still 'already on'; the marker is never consulted", /Automated restore proof is on/.test(r5.stdout) && !/DELIBERATE/.test(r5.stdout) && r5.calls.length === 0);

    const r6 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_RETIRED_LEGACY"], "0");
    ok("grep precision: a near-miss secret name is NOT mistaken for the marker (proceeds normally)", /Enabling automated restore proof/.test(r6.stdout) && !/DELIBERATE/.test(r6.stdout));
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nDEPLOY-OPERATIONAL-MARKER VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
