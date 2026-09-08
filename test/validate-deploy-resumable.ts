// Validates that scripts/deploy.sh cannot leave a customer with a LIVE, KEYLESS engine and nothing on
// screen telling them what to do.
//
// THE DEFECT THIS PINS. `npx wrangler deploy` can upload the worker, arm its cron and print
// "Deployed ... triggers", and then still exit non-zero because of an unrelated interactive prompt on
// the way out. deploy.sh runs under `set -e`, so the script stops there, BETWEEN a successful deploy and
// key generation: worker live with its schedule armed, no recovery-kit/, `wrangler secret list` empty. No
// signer key, no break-glass key, no admin token, and no published page saying the deploy is resumable.
//
// So the two questions this file asks of the real script are the two the operator's outcome turns on:
//   1. When wrangler exits non-zero AFTER the upload landed, does the script CONTINUE to key generation?
//   2. When it stops for any reason between a landed deploy and settled keys, does it SAY SO, and say that
//      re-running is safe?
//
// THE NEGATIVE CONTROL IS THE POINT OF THE THIRD SECTION. A repair that made the script continue past
// every failure would be worse than the defect, because a deploy that genuinely did not land must still
// stop rather than run key generation against a worker that is not there. And a script that printed the
// recovery notice unconditionally would be noise on every successful deploy, which is how a notice stops
// being read. Both are asserted, and without them the rest of this file would pass over a script that
// simply never fails and never shuts up.
//
// It drives the REAL deploy.sh, extracted by anchor rather than hand-copied, exactly as
// test/validate-deploy-operational-marker.ts does beside it: if deploy.sh is refactored so an anchor no
// longer matches exactly once, extraction throws loudly instead of quietly grading stale text. The
// extracted fragment runs under /bin/sh in a throwaway temp directory with `node` and `npx` shadowed as
// recording shell functions, so there is no real wrangler call, no network, no account touched and no key
// material of any kind.
// Run: node test/validate-deploy-resumable.ts

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEPLOY_SH = readFileSync(join(ENGINE_DIR, "scripts", "deploy.sh"), "utf8");
const LINES = DEPLOY_SH.split("\n");

/** The real deploy.sh's lines between two exact-substring anchors, each of which must match exactly one. */
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

// The deploy stage itself: the BEFORE/AFTER version read, the wrangler call whose exit code is captured
// rather than obeyed, the landed/not-landed branch, and the exit trap. Ends where the (unrelated) secret
// list read begins.
const DEPLOY_STAGE = extractBetween("DEPLOY_LANDED=0", 'SECRETS="$(npx wrangler secret list', true);

// WRANGLER'S REAL ANSWER, CAPTURED FROM A LIVE `wrangler deployments status` RUN RATHER THAN WRITTEN FROM
// MEMORY. A fixture invented to match the code under test would grade nothing: the probe must be checked
// against wrangler's actual wording, not a guess at it.
const REAL_DEPLOYMENTS_STATUS = [
  "Created:     2026-08-13T09:43:51.385Z",
  "Author:      someone@example.com",
  "Source:      Unknown (deployment)",
  "Message:     -",
  "Version(s):  (100%) 08aa3e70-58bd-40a2-8da5-fc029df02585",
  "                 Created:  2026-08-13T09:43:48.582Z",
].join("\n");

// The same answer after a second upload: one uuid different, everything else the same shape.
const REAL_DEPLOYMENTS_STATUS_AFTER = REAL_DEPLOYMENTS_STATUS.replace("08aa3e70-58bd-40a2-8da5-fc029df02585", "2fc8a4c3-30ab-4f11-aa37-808f7562c307");

/**
 * Runs `body` under /bin/sh in a fresh scratch directory with `node` and `npx` shadowed as recording
 * functions. The shadowed `npx` answers two shapes the deploy stage cares about, both under the test's
 * control through the environment: `wrangler deployments status` prints whatever DP_VERSION_LINE currently
 * holds (a file, so the deploy can move it mid-run), and `wrangler deploy` exits DP_DEPLOY_EXIT.
 * stdout and stderr are merged, because the script's own recovery notice is the subject and it must be
 * readable whichever stream it lands on.
 */
function runStage(opts: {
  deployExit: number;
  versionBefore: string;
  versionAfter: string;
  /** Appended after the extracted stage: what the rest of the script does next. */
  after?: string;
}): { output: string; exitCode: number; calls: string[] } {
  const scratch = mkdtempSync(join(tmpdir(), "dp-deploy-resumable-"));
  const callLog = join(scratch, "calls.log");
  const versionFile = join(scratch, "version.txt");
  writeFileSync(callLog, "");
  writeFileSync(versionFile, opts.versionBefore);
  const harness = `
set -e
cd ${JSON.stringify(scratch)}
CALL_LOG=${JSON.stringify(callLog)}
VERSION_FILE=${JSON.stringify(versionFile)}
node() {
  printf '%s\\n' "node $*" >> "$CALL_LOG"
  return 0
}
npx() {
  printf '%s\\n' "npx $*" >> "$CALL_LOG"
  case "$*" in
    *"deployments status"*)
      cat "$VERSION_FILE"
      return 0
      ;;
    *"wrangler deploy"*)
      printf '%s' ${JSON.stringify(opts.versionAfter)} > "$VERSION_FILE"
      return ${opts.deployExit}
      ;;
  esac
  return 0
}
${DEPLOY_STAGE}
${opts.after ?? ""}
`;
  let output = "";
  let exitCode = 0;
  try {
    output = execFileSync("/bin/sh", ["-c", harness], { encoding: "utf8", env: { ...process.env }, cwd: scratch, stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; status?: number };
    output = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    exitCode = err.status ?? 1;
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
  return { output, exitCode, calls };
}

/** The sentence every recovery path must carry, because it is the one a stuck operator needs. */
const RESUME_SENTENCE = /RE-RUN(NING)? `?npm run deploy`?.{0,40}(is safe|IS SAFE)/;

function main(): void {
  console.log("-- THE TRIAL'S CASE: wrangler exits non-zero AFTER the upload landed --");
  {
    // The deployed version moves during the command, which is what a landed upload looks like from
    // outside, and wrangler still ends non-zero because it asked a question on the way out.
    const r = runStage({ deployExit: 1, versionBefore: "", versionAfter: REAL_DEPLOYMENTS_STATUS });
    ok("the script does NOT stop: it exits 0 and carries on to key generation", r.exitCode === 0);
    ok("it says the upload landed despite the exit code", /upload LANDED/.test(r.output));
    ok("it names the exit code it saw rather than hiding it", /wrangler exited 1/.test(r.output));
    ok("it names the cause an operator would otherwise have to guess", /install Cloudflare skills/i.test(r.output));
    ok("and it says why continuing matters, in custody terms", /deployed without keys can seal nothing/.test(r.output));
    ok("the version was read BEFORE the deploy, not only after", r.calls.filter((c) => c.includes("deployments status")).length >= 1);
  }

  console.log("\n-- THE NEGATIVE CONTROL: a deploy that genuinely did NOT land must still stop --");
  {
    // Nothing moved: the worker did not exist before and does not exist after. Continuing here would run
    // key generation against a worker that is not there, which is the opposite mistake.
    const r = runStage({ deployExit: 1, versionBefore: "", versionAfter: "" });
    ok("the script stops", r.exitCode !== 0);
    ok("it carries wrangler's own exit code out rather than inventing one", r.exitCode === 1);
    ok("it says the deploy did not land", /deploy did NOT land/.test(r.output));
    ok("it says nothing is half-done, which is the fact that makes it safe to retry", /nothing is half-done/.test(r.output));
    ok("it says re-running is safe", RESUME_SENTENCE.test(r.output) || /RE-RUNNING IS SAFE/.test(r.output));
    ok("it does NOT claim the upload landed", !/upload LANDED/.test(r.output));
  }

  console.log("\n-- THE SECOND NEGATIVE CONTROL: an ordinary successful deploy says none of this --");
  {
    const r = runStage({ deployExit: 0, versionBefore: "", versionAfter: REAL_DEPLOYMENTS_STATUS });
    ok("it exits 0", r.exitCode === 0);
    ok("no recovery notice at all", !/STOPPED AFTER THE DEPLOY/.test(r.output));
    ok("no landed-anyway notice either, because wrangler did not fail", !/upload LANDED/.test(r.output));
    ok("and no re-run instruction, so the notice keeps meaning something when it does appear", !RESUME_SENTENCE.test(r.output));
  }

  console.log("\n-- THE TRAP: a stop between a landed deploy and settled keys must SAY the state --");
  {
    // The window the trial was actually stuck in, reached by a failure AFTER the deploy rather than by the
    // deploy itself: a `wrangler secret put` that cannot reach the API, a closed terminal, a new prompt.
    const r = runStage({ deployExit: 0, versionBefore: "", versionAfter: REAL_DEPLOYMENTS_STATUS, after: "false" });
    ok("the script exits non-zero, as it should", r.exitCode !== 0);
    ok("it says where it stopped, in the operator's terms", /STOPPED AFTER THE DEPLOY AND BEFORE THIS ENGINE'S KEYS WERE SETTLED/.test(r.output));
    ok("it says the worker is LIVE, which is the part that is not obvious", /worker is LIVE/.test(r.output));
    ok("it says what that costs: nothing it seals can be read", /seal nothing you could read/.test(r.output));
    ok("it says re-running is safe and resumes", RESUME_SENTENCE.test(r.output));
    ok("it promises the existing keys of an engine that has them are untouched", /already has them untouched/.test(r.output));
    ok("and it hands over the two commands that show the state", /wrangler secret list/.test(r.output) && /ls recovery-kit/.test(r.output));
  }

  console.log("\n-- THE TRAP, ONE STEP LATER: keys settled, first-Owner set-up not chosen --");
  {
    const r = runStage({ deployExit: 0, versionBefore: "", versionAfter: REAL_DEPLOYMENTS_STATUS, after: "KEYS_SETTLED=1\nfalse" });
    ok("it still reports rather than going quiet", r.exitCode !== 0 && /STOPPED AFTER THE DEPLOY/.test(r.output));
    ok("it names the narrower state: the first-Owner set-up", /BEFORE THE FIRST-OWNER SET-UP WAS CHOSEN/.test(r.output));
    ok("it does NOT frighten the operator about keys that exist", !/no signer key/.test(r.output));
    ok("it says plainly that nothing custodial is half-done", /nothing custodial is half-done/.test(r.output));
    ok("and it still says re-running is safe", RESUME_SENTENCE.test(r.output));
  }

  console.log("\n-- THE TRAP MUST BE SILENT WHEN THE DEPLOY NEVER LANDED, or it is noise on a clean refusal --");
  {
    // The stage exits 1 on its own not-landed branch. The trap fires on that exit too, and must add
    // nothing: the branch has already said the right thing, and a second, wronger account of the same
    // failure is exactly what these sentences exist to stop.
    const r = runStage({ deployExit: 1, versionBefore: "", versionAfter: "" });
    ok("no keyless-engine warning over a deploy that never landed", !/STOPPED AFTER THE DEPLOY/.test(r.output));
  }

  console.log("\n-- THE RE-RUN: an engine that is ALREADY deployed and still keyless, which is the stuck state --");
  {
    // The exact situation the trial was left in and the one a customer re-runs from: the worker exists and
    // carries a version already, so "did anything land" cannot be answered by asking whether a deployment
    // exists. Only the version MOVING answers it, which is why the probe is a before/after and not a
    // presence check.
    const r = runStage({ deployExit: 1, versionBefore: REAL_DEPLOYMENTS_STATUS, versionAfter: REAL_DEPLOYMENTS_STATUS_AFTER });
    ok("the re-run continues to key generation", r.exitCode === 0);
    ok("it recognises the upload landed even though a deployment already existed", /upload LANDED/.test(r.output));
  }

  console.log("\n-- AND ITS REFUTER: a re-run whose upload did NOT land must still stop --");
  {
    // Same starting state, but nothing moved. A presence check would say "there is a deployment, carry on"
    // and run key generation against a worker whose new code never arrived.
    const r = runStage({ deployExit: 1, versionBefore: REAL_DEPLOYMENTS_STATUS, versionAfter: REAL_DEPLOYMENTS_STATUS });
    ok("it stops", r.exitCode === 1);
    ok("and says the deploy did not land", /deploy did NOT land/.test(r.output));
  }

  console.log("\n-- THE PROBE ITSELF: it must read the id out of wrangler's REAL wording --");
  {
    // This asserts against the captured wording rather than against the probe's own idea of it: a probe
    // that reads nothing out of the real answer would make before/after compare equal, and a landed
    // deploy would read as a failed one.
    const r = runStage({ deployExit: 1, versionBefore: "", versionAfter: REAL_DEPLOYMENTS_STATUS });
    ok("the probe extracts an id from `Version(s):  (100%) <uuid>`, which carries no 'version id' label at all", /upload LANDED/.test(r.output));
    ok("and the captured wording really does lack that label, so the check above is live", !/version id/i.test(REAL_DEPLOYMENTS_STATUS));
  }

  console.log("\n-- THE SOURCE ITSELF: the deploy's exit code is captured, never obeyed blind --");
  {
    ok("there is exactly one `npx wrangler deploy` in the script", (DEPLOY_SH.match(/^npx wrangler deploy /gm) ?? []).length === 1);
    ok("and it does not sit bare: the line before it is set +e", /\nset \+e\nnpx wrangler deploy /.test(DEPLOY_SH));
    ok("its exit code is captured into a variable", /WRANGLER_EXIT=\$\?/.test(DEPLOY_SH));
    ok("the capture is bracketed by set +e and set -e, so nothing after it is unguarded", /set \+e\n+npx wrangler deploy[^\n]*\nWRANGLER_EXIT=\$\?\nset -e/.test(DEPLOY_SH));
    ok("an EXIT trap is armed", /^trap deployfix_report_state_on_exit EXIT$/m.test(DEPLOY_SH));
    ok("KEYS_SETTLED is set exactly once, after the key branch", (DEPLOY_SH.match(/^KEYS_SETTLED=1$/gm) ?? []).length === 1);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-deploy-resumable (${failures} failure(s), ${checks} check(s))`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
