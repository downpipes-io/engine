// Validates B7's fix in scripts/deploy.sh: the guided deploy script must REFUSE to silently
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
//   2. the SIGNER_PRIVATE-present branch's operational-key check (the B7 logic itself), fed a
//      synthetic `wrangler secret list` JSON body and a pre-set ENABLE_OPERATIONAL.
// Run: node test/validate-deploy-operational-marker.ts

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

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
// THE END ANCHOR MOVED, AND THE REASON IS WORTH KEEPING. It used to be `node scripts/stamp-build-id.mjs`,
// on the reasoning that the stamp was simply the next thing that happened after the parser. That is a
// weaker claim than it looks: it names where the parser's SUCCESSOR starts rather than where the parser
// ENDS, so anything inserted between the two silently joined the fragment. something was:
// deploy.sh gained a blocking preflight there, and this fragment began executing `npm run typecheck` and
// `npm run validate` inside the throwaway temp directory runShFragment creates. That directory has no
// package.json, so npm failed, and all five parser assertions went red over a parser that was correct.
// Both anchors still matched exactly one line each, so the extractor's own tripwire could not fire; the
// span had widened rather than broken. Anchoring on the preflight's banner names the parser's actual end.
const FLAG_PARSER = extractBetween("ENABLE_OPERATIONAL=0", "# BLOCKING PREFLIGHT. THIS SCRIPT USED TO GRADE NOTHING AT ALL.", true);

// Fragment 2: the B7 operational-key check itself -- everything from the line AFTER the `SECRETS=` read
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
    *generate-keys.ts*--config-wrap-key-only*)
      mkdir -p ./recovery-kit/.staging
      echo dummy > ./recovery-kit/.staging/config-wrap-key.b64
      ;;
    *generate-keys.ts*--break-glass-only*)
      # The shadow drops exactly what the real generate-keys.ts --break-glass-only drops, and NOT the two
      # operational values. That is what makes the break-glass-only assertions below real rather than
      # cosmetic: a deploy.sh that still tried to PUT an operational secret on this path would read a
      # missing file, and the fragment's own set -e would take it down rather than quietly installing nothing.
      mkdir -p ./recovery-kit/.staging
      echo dummy > ./recovery-kit/.staging/signer-private.b64
      echo dummy > ./recovery-kit/.staging/break-glass-public.b64
      echo dummy > ./recovery-kit/.staging/config-recipient-public.b64
      echo dummy > ./recovery-kit/.staging/config-recipient-private.b64
      echo dummy > ./recovery-kit/.staging/config-wrap-key.b64
      ;;
    *generate-keys.ts*)
      mkdir -p ./recovery-kit/.staging
      echo dummy > ./recovery-kit/.staging/signer-private.b64
      echo dummy > ./recovery-kit/.staging/break-glass-public.b64
      echo dummy > ./recovery-kit/.staging/operational-public.b64
      echo dummy > ./recovery-kit/.staging/operational-private.b64
      echo dummy > ./recovery-kit/.staging/config-recipient-public.b64
      echo dummy > ./recovery-kit/.staging/config-recipient-private.b64
      echo dummy > ./recovery-kit/.staging/config-wrap-key.b64
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

function runKeyCheck(names: string[], enableOperational: "0" | "1", breakGlassOnly: "0" | "1" = "0"): { stdout: string; calls: string[] } {
  const body = `SECRETS=${JSON.stringify(fakeSecretList(names))}\nENABLE_OPERATIONAL=${enableOperational}\nBREAK_GLASS_ONLY=${breakGlassOnly}\n${KEY_CHECK}`;
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

    // --break-glass-only, the EXPLICIT opposite answer for the fresh-engine branch. It exists so a
    // scripted deploy states its posture in the command rather than relying on the no-TTY default, and
    // the assertions that matter are again mostly negative: it must not be set by anything else, and
    // above all it must not be set by --yes, which answers the other question.
    const runBgo = (args: string[]): string => {
      const argv = args.map((a) => JSON.stringify(a)).join(" ");
      const body = `set -- ${argv}\n${FLAG_PARSER}\nprintf '%s' "$BREAK_GLASS_ONLY"`;
      return runShFragment(body, {}).stdout.trim();
    };
    ok("no flags at all -> BREAK_GLASS_ONLY stays 0 (the branch decides, not the parser)", runBgo([]) === "0");
    ok("--break-glass-only -> BREAK_GLASS_ONLY becomes 1", runBgo(["--break-glass-only"]) === "1");
    ok("--yes does NOT set BREAK_GLASS_ONLY (it answers the opposite way)", runBgo(["--yes"]) === "0");
    ok("--enable-operational does NOT set BREAK_GLASS_ONLY", runBgo(["--enable-operational"]) === "0");
    ok("--skip-preflight does NOT set BREAK_GLASS_ONLY", runBgo(["--skip-preflight"]) === "0");
    ok("a near-miss flag name does not set BREAK_GLASS_ONLY", runBgo(["--break-glass"]) === "0");
    ok("--break-glass-only does NOT set ENABLE_OPERATIONAL (the two are independent switches)", runFlags(["--break-glass-only"]) === "0");

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

  console.log("\n-- deploy.sh: the B7 operational-key check (inside the SIGNER_PRIVATE-present branch) --");
  {
    // CONFIG_WRAP_KEY is in these three fake secret lists deliberately. The assertion each of them turns
    // on is "no calls at all", and the wrap-key top-up added after the key branch would otherwise make one
    // legitimate call and mask the thing being graded. An engine that already holds a wrap key is the case
    // that isolates the operational-key logic.
    const r1 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_RETIRED", "CONFIG_WRAP_KEY"], "0");
    ok("marker present, no override -> refuses with the deliberate-choice message", /DELIBERATE choice/.test(r1.stdout));
    ok("marker present, no override -> makes NO node/npx calls at all (nothing generated, nothing PUT)", r1.calls.length === 0);
    ok("marker present, no override -> names both re-enable paths (console and the flag)", /Posture tab/.test(r1.stdout) && /--enable-operational/.test(r1.stdout));

    const r2 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_RETIRED"], "1");
    ok("marker present, ENABLE_OPERATIONAL=1 (the --enable-operational/--yes override) -> proceeds", /Enabling automated restore proof/.test(r2.stdout));
    ok("...and says so (the marker is being overridden, not silently ignored)", /generating a fresh operational key anyway/.test(r2.stdout));
    ok("...and actually calls generate-keys.ts --operational-only", r2.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--operational-only")));
    ok("...and PUTs both OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE", r2.calls.some((c) => c.includes("secret put OPERATIONAL_PUBLIC")) && r2.calls.some((c) => c.includes("secret put OPERATIONAL_PRIVATE")));

    const r3 = runKeyCheck(["SIGNER_PRIVATE"], "0");
    ok("marker ABSENT (a genuinely fresh estate within an existing signer) -> proceeds exactly as before B7", /Enabling automated restore proof/.test(r3.stdout));
    ok("...with no mention of an overridden marker (there was none to override)", !/generating a fresh operational key anyway/.test(r3.stdout));
    ok("...and calls generate-keys.ts --operational-only, unaffected by this fix", r3.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--operational-only")));

    const r4 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE", "CONFIG_WRAP_KEY"], "0");
    ok("OPERATIONAL_PRIVATE present -> the short-circuit 'already on' branch, no calls at all", /Automated restore proof is on/.test(r4.stdout) && r4.calls.length === 0);

    const r5 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE", "OPERATIONAL_RETIRED", "CONFIG_WRAP_KEY"], "0");
    ok("OPERATIONAL_PRIVATE present EVEN WITH a stale marker -> still 'already on'; the marker is never consulted", /Automated restore proof is on/.test(r5.stdout) && !/DELIBERATE/.test(r5.stdout) && r5.calls.length === 0);

    const r6 = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_RETIRED_LEGACY"], "0");
    ok("grep precision: a near-miss secret name is NOT mistaken for the marker (proceeds normally)", /Enabling automated restore proof/.test(r6.stdout) && !/DELIBERATE/.test(r6.stdout));
  }

  console.log("\n-- deploy.sh: --break-glass-only, the posture the terminal path could not reach --");
  {
    // The flag parser first: the switch has to be independent of the other two, and above all it must not
    // be settable by --yes, which reads like a general "stop asking me" and is about the operational key.
    const runBg = (args: string[]): string => {
      const argv = args.map((a) => JSON.stringify(a)).join(" ");
      const body = `set -- ${argv}\n${FLAG_PARSER}\nprintf '%s' "$BREAK_GLASS_ONLY"`;
      return runShFragment(body, {}).stdout.trim();
    };
    ok("no flags at all -> BREAK_GLASS_ONLY stays 0 (the default posture is unchanged)", runBg([]) === "0");
    ok("--break-glass-only -> BREAK_GLASS_ONLY becomes 1", runBg(["--break-glass-only"]) === "1");
    ok("--yes does NOT ask for break-glass-only", runBg(["--yes"]) === "0");
    ok("--skip-preflight does NOT ask for break-glass-only", runBg(["--skip-preflight"]) === "0");
    ok("a near-miss flag name does not ask for break-glass-only", runBg(["--break-glass-onlyy"]) === "0");

    // The two custody flags contradict each other. Refusing beats letting the parser's order decide, because
    // either silent winner installs key material the operator did not ask for.
    const clashArgv = ["--break-glass-only", "--yes"].map((a) => JSON.stringify(a)).join(" ");
    const clash = runShFragment(`set -- ${clashArgv}\n${FLAG_PARSER}\nprintf 'REACHED-THE-END'`, {});
    ok("--break-glass-only with --yes is REFUSED, not silently resolved", /Refusing: --break-glass-only and --enable-operational/.test(clash.stdout));
    ok("...and the refusal STOPS the script (nothing after the parser runs)", !/REACHED-THE-END/.test(clash.stdout));

    // Now the key branch itself, on a keyless engine: the case that produced the finding.
    const fresh = runKeyCheck([], "0", "1");
    ok("keyless engine + --break-glass-only -> generate-keys.ts is called WITH --break-glass-only", fresh.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--break-glass-only")));
    ok("...and NEITHER operational secret is PUT (the whole point of the flag)", !fresh.calls.some((c) => c.includes("secret put OPERATIONAL_PUBLIC")) && !fresh.calls.some((c) => c.includes("secret put OPERATIONAL_PRIVATE")));
    ok("...while the signer and break-glass public still go in (this is a posture, not a half-deploy)", fresh.calls.some((c) => c.includes("secret put SIGNER_PRIVATE")) && fresh.calls.some((c) => c.includes("secret put BREAK_GLASS_PUBLIC")));
    ok("...and the OPERATIONAL_RETIRED marker is installed, so the NEXT deploy cannot silently reverse it", fresh.calls.some((c) => c.includes("secret put OPERATIONAL_RETIRED")));
    ok("...and the operator is told the engine cannot read its own archives", /Posture installed: BREAK-GLASS-ONLY/.test(fresh.stdout) && /the engine holds nothing that can read/.test(fresh.stdout));

    // The default fresh (no-flag, no-TTY) path used to always take the two-recipient posture unconditionally.
    // It no longer does: the "FRESH-ENGINE branch's posture choice" group below is where that default now
    // lives, and it asserts the SAFE default (break-glass-only) rather than the old unconditional two-recipient
    // one, which is the whole point of the posture-choice feature that group tests.

    // An EXISTING engine with a signer and no operational key: the flag must leave the marker behind, or
    // the next plain deploy auto-generates one and the choice lasts exactly one run.
    const existing = runKeyCheck(["SIGNER_PRIVATE", "CONFIG_WRAP_KEY"], "0", "1");
    ok("signer present, no operational, --break-glass-only -> generates NOTHING", !existing.calls.some((c) => c.includes("generate-keys.ts")));
    ok("...and installs the marker so the posture survives the next deploy", existing.calls.some((c) => c.includes("secret put OPERATIONAL_RETIRED")));

    // And it must never DELETE a live operational key: that can strand an archive only that key opens,
    // which is why the console's switch is confirm-gated and impact-guarded.
    const live = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE", "CONFIG_WRAP_KEY"], "0", "1");
    ok("an operational key that already exists is NOT removed by the flag", !live.calls.some((c) => c.includes("secret delete")) && live.calls.length === 0);
    ok("...and the operator is steered to the screen that shows the stranding impact", /does NOT remove an operational key/.test(live.stdout) && /Keys screen/.test(live.stdout));
  }

  console.log("\n-- deploy.sh: the configuration wrap key is installed rather than left to the operator --");
  {
    // The finding: CONFIG_WRAP_KEY was optional and nothing generated it, so a terminal deploy left every
    // console-stored credential on the Durable Object plaintext floor.
    const fresh = runKeyCheck([], "0", "0");
    ok("a fresh deploy PUTs CONFIG_WRAP_KEY (nothing generated one before)", fresh.calls.some((c) => c.includes("secret put CONFIG_WRAP_KEY")));
    ok("...exactly once (the top-up must not replace the key the ceremony just installed)", fresh.calls.filter((c) => c.includes("secret put CONFIG_WRAP_KEY")).length === 1);
    const freshBg = runKeyCheck([], "0", "1");
    ok("a break-glass-only deploy PUTs it too, and once (it is not a posture choice)", freshBg.calls.filter((c) => c.includes("secret put CONFIG_WRAP_KEY")).length === 1);

    // The top-up, which is what closes the floor for engines already in the field rather than for new
    // estates only.
    const old = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE"], "0");
    ok("an engine deployed BEFORE the key existed gets one on the next deploy", old.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--config-wrap-key-only")) && old.calls.some((c) => c.includes("secret put CONFIG_WRAP_KEY")));
    ok("...and is told the credentials saved earlier stay on the old floor until re-saved", /stay on the platform-encryption floor until each destination or/.test(old.stdout));
    const already = runKeyCheck(["SIGNER_PRIVATE", "OPERATIONAL_PRIVATE", "CONFIG_WRAP_KEY"], "0");
    ok("an engine that already holds one is left alone (no rotation, which would orphan every envelope)", !already.calls.some((c) => c.includes("CONFIG_WRAP_KEY")));
  }

  console.log("\n-- deploy.sh: the FRESH-ENGINE branch's posture choice (no SIGNER_PRIVATE present) --");
  {
    // THE DEFECT THIS GROUP CLOSES. This branch used to PUT OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE
    // unconditionally, with no prompt and no flag, on every fresh install, and mention it afterwards. The
    // console ceremony for the same install presents the trade-off and falls STRICT when nothing was
    // recorded, so the same product installed a decryption-capable key in the engine, or did not, purely
    // on which ceremony was used. These fragments run with stdin NOT a TTY (execFileSync pipes it), which
    // is exactly the unattended-deploy case the old code decided silently.
    const FRESH = ["BOOTSTRAP_OWNER_EMAIL"]; // any list WITHOUT SIGNER_PRIVATE takes the fresh branch

    const noFlag = runKeyCheck(FRESH, "0", "0");
    ok("fresh + no flag + no TTY -> takes the SAFE default and says so", /Posture installed: BREAK-GLASS-ONLY/.test(noFlag.stdout));
    ok("fresh + no flag + no TTY -> OPERATIONAL_PRIVATE is NEVER put", !noFlag.calls.some((c) => c.includes("secret put OPERATIONAL_PRIVATE")));
    ok("fresh + no flag + no TTY -> OPERATIONAL_PUBLIC is never put either", !noFlag.calls.some((c) => c.includes("secret put OPERATIONAL_PUBLIC")));
    ok("fresh + no flag + no TTY -> the OPERATIONAL_RETIRED marker IS written, so every later deploy protects the choice", noFlag.calls.some((c) => c.includes("secret put OPERATIONAL_RETIRED")));
    ok("fresh + no flag + no TTY -> the generator is told, so the recovery sheet states the real posture", noFlag.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--break-glass-only")));
    ok("fresh + no flag -> the signer and break-glass keys still go in (only the operational pair is at issue)", noFlag.calls.some((c) => c.includes("secret put SIGNER_PRIVATE")) && noFlag.calls.some((c) => c.includes("secret put BREAK_GLASS_PUBLIC")));
    ok("fresh + no flag -> BOTH config-recipient halves still go in (config recovery is not a posture choice)", noFlag.calls.some((c) => c.includes("secret put CONFIG_RECIPIENT_PUBLIC")) && noFlag.calls.some((c) => c.includes("secret put CONFIG_RECIPIENT_PRIVATE")));
    ok("fresh + no flag -> the summary names WHY that posture was chosen, not just which", /not an interactive terminal/.test(noFlag.stdout));
    ok("fresh + no flag -> and names the two ways to add restore proof later", /Keys screen/.test(noFlag.stdout) && /--enable-operational/.test(noFlag.stdout));
    ok("fresh + no flag -> it does NOT claim automated restore proof is on", !/restore proof is ON/.test(noFlag.stdout));

    const bgo = runKeyCheck(FRESH, "0", "1");
    ok("fresh + --break-glass-only -> same install, and the summary attributes it to the flag", /Posture installed: BREAK-GLASS-ONLY/.test(bgo.stdout) && /--break-glass-only was passed/.test(bgo.stdout));
    ok("fresh + --break-glass-only -> no operational secret is put", !bgo.calls.some((c) => c.includes("secret put OPERATIONAL_P")));
    ok("fresh + --break-glass-only -> the marker is written", bgo.calls.some((c) => c.includes("secret put OPERATIONAL_RETIRED")));

    const enabled = runKeyCheck(FRESH, "1", "0");
    ok("fresh + --enable-operational -> BOTH operational secrets are put (the flag still means what it meant)", enabled.calls.some((c) => c.includes("secret put OPERATIONAL_PUBLIC")) && enabled.calls.some((c) => c.includes("secret put OPERATIONAL_PRIVATE")));
    ok("fresh + --enable-operational -> the marker is NOT written (there is nothing retired)", !enabled.calls.some((c) => c.includes("OPERATIONAL_RETIRED")));
    ok("fresh + --enable-operational -> the summary states the two-recipient posture and why", /Posture installed: TWO-RECIPIENT/.test(enabled.stdout) && /--enable-operational \(or --yes\) was passed/.test(enabled.stdout));
    ok("fresh + --enable-operational -> the generator is NOT run in break-glass-only mode", !enabled.calls.some((c) => c.includes("generate-keys.ts") && c.includes("--break-glass-only")));

    // The flag wins over the strict default, and BOTH flags together is not a state the parser can
    // produce from one flag; if a caller sets both, the explicit enable is honoured, which is the
    // safer-to-explain of the two and matches the already-keyed branch's own override precedence.
    const both = runKeyCheck(FRESH, "1", "1");
    ok("fresh + both flags -> the explicit enable wins, matching the already-keyed branch's precedence", /Posture installed: TWO-RECIPIENT/.test(both.stdout));
  }

  verdictReached(failures);
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
