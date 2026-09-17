// verdict-guard: the shared completion guard for validator entry points.
//
// THE CLASS IT CLOSES. A validator that reaches exit 0 without ever reaching its own verdict line.
// It was measured on test/validate-destsim-selftest.ts: the syslog emulator's stall fault parked an
// accepted raw socket behind an unref()'d timer, so net.Server.close()'s completion callback never
// fired, the promise wrapping it never settled, Node found nothing ref'd holding the event loop open,
// drained it, and exited 0. The verdict line never printed and 109 assertions were structurally
// incapable of failing, for any reason at all. Nothing in the repo noticed, because the only thing
// anyone checks is the exit code, and the exit code was 0.
//
// WHY ONE HOOK IS ENOUGH. Assigning process.exitCode inside an "exit" listener is honoured by Node,
// and it overrides an explicit process.exit(0) that has already been requested (measured on Node
// 22.23.1). So a single "exit" listener catches every way the tally can be skipped:
//   - the event loop drained while an await was outstanding (the measured case);
//   - an await on something that never resolves;
//   - a rejection swallowed by an empty .catch(), leaving the tally unreached;
//   - an early return before the tally;
//   - a process.exit(0) before the tally;
//   - a file that only exports its work and never invokes it, so nothing runs at all.
// In all of them the guard was armed and verdictReached() was never called, so the guard fires.
//
// ENROLMENT IS NOT OPTIONAL. scripts/verdict-guard-gate.mjs derives the set of entry points that must
// be enrolled from package.json and the CI workflows rather than from a list kept by hand, and an
// unenrolled entry point is a gate finding. Do not add a bypass; a guard some validators opt into is
// the same defect wearing a helmet.
//
// USAGE, two lines:
//   import { verdictReached } from "./lib/verdict-guard.ts";   // importing this ARMS the guard
//   ...
//   console.log(failures === 0 ? "\nEXAMPLE PASS" : `\n${failures} FAILURE(S)`);
//   verdictReached(failures);                                  // declare the verdict you just printed
//   if (failures > 0) process.exit(1);

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** declared is set by verdictReached(). The exit listener reads it and nothing else writes it. */
let declared = false;
/**
 * refused is set when a verdict was DECLARED BUT REJECTED (zero checks, or no assertion lines). It has to
 * be separate from `declared`, and the exit listener has to re-apply it, because setting
 * process.exitCode = 1 inside verdictReached is not final: a process.exit(0) on the next line overrides
 * it. Without this the guard printed "Forcing exit 1" and the process exited 0, which is the guard
 * producing the exact false green it exists to stop. Found by the docs and website port pass, which hit
 * it on their own copies and traced it back here.
 */
let refused = false;
/** the failure count the entry point declared, kept so the guard can back-stop a missing exit(1). */
let declaredFailures = 0;
/** bytes the process has written to stdout since arming, reported in the guard's message. */
let stdoutBytes = 0;

/** entryName is only for the message. process.argv[1] is the script node was pointed at. */
const entryName = process.argv[1] ?? "(unknown entry)";

// Watching stdout is how the guard refuses a VACUOUS pass without asking every validator to plumb a
// check count through. A validator that declares a verdict having asserted nothing did not pass, it
// abstained: that is the shape of test/validate-notify-crud.ts, which was its own step in the validate
// chain while only exporting runCrud and never calling it, so it printed nothing and exited 0. The
// wrapper is deliberately thin and passes every argument and the return value straight through, so it
// cannot change what a validator prints or how it back-pressures.
//
// assertionLines is the floor itself: how many lines the run printed in the house
// assertion shape. The pattern is anchored at the start of a line, so "not ok" appearing INSIDE a passing
// assertion's label cannot be miscounted, and it is deliberately OVER-inclusive (a section header reading
// "FAIL-SOFT OVER CEILING:" counts) because the floor only ever fires at zero. Over-counting can therefore
// only fail to catch a vacuous run, never turn an honest one red.
const ASSERTION_LINE = /^[ \t]{0,6}(?:ok|OK|FAIL|PASS|✓|✗)\b/;
let assertionLines = 0;
let partial = "";

const realWrite = process.stdout.write.bind(process.stdout);
type WriteArgs = Parameters<typeof process.stdout.write>;
process.stdout.write = ((...args: WriteArgs): boolean => {
  const chunk = args[0];
  const text = typeof chunk === "string" ? chunk : chunk instanceof Uint8Array ? Buffer.from(chunk).toString("utf8") : "";
  stdoutBytes += typeof chunk === "string" ? Buffer.byteLength(chunk) : (chunk?.byteLength ?? 0);
  // A console.log can straddle chunks, so carry the tail rather than losing or double-counting a line.
  const lines = (partial + text).split("\n");
  partial = lines.pop() ?? "";
  for (const line of lines) if (ASSERTION_LINE.test(line)) assertionLines++;
  return realWrite(...args);
}) as typeof process.stdout.write;

process.on("exit", (code: number): void => {
  // A refusal is re-applied FIRST, before the declared short-circuit, because an explicit process.exit(0)
  // after a refused verdict would otherwise carry the day.
  if (refused) {
    if (code === 0) {
      process.stderr.write(`\nVERDICT GUARD: ${entryName} refused its verdict and then exited 0. Forcing exit 1.\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (declared) return;
  // stderr, not stdout: the counted stream must not be moved by the guard's own message, and a
  // harness that only reads stdout still sees the non-zero exit.
  process.stderr.write(
    `\nVERDICT GUARD: ${entryName} reached process exit with code ${code} without declaring a verdict.\n` +
      `  The tally was never reached, so every assertion in this run was incapable of failing.\n` +
      `  Causes seen in this repo: an await on a promise that never settles (a close() whose callback\n` +
      `  never fires), an early return before the tally, a process.exit(0) before the tally, a\n` +
      `  rejection swallowed by an empty catch, or an entry point that only exports its work.\n` +
      `  ${stdoutBytes === 0 ? "It wrote nothing at all to stdout, so it ran no checks.\n" : `It wrote ${stdoutBytes} bytes to stdout before stopping.\n`}` +
      (code === 0 ? "  Forcing exit 1: a silent exit 0 here is a false green.\n" : "  Leaving the non-zero exit code as it stands.\n"),
  );
  if (code === 0) process.exitCode = 1;
});

/**
 * verdictReached declares that the entry point printed its verdict, and is the only thing that
 * disarms the guard. Call it AFTER printing the verdict and BEFORE any exit.
 *
 * @param failures how many assertions failed. A positive count sets process.exitCode = 1 even if the
 *   caller forgets its own process.exit(1), because "printed N FAILURE(S) and exited 0" is the same
 *   false green by a shorter route.
 * @param checks how many assertions ran, where the entry point tracks it. Zero is a failure: a
 *   validator that checked nothing is not a validator that passed.
 */
export function verdictReached(failures: number, checks?: number): void {
  declared = true;
  declaredFailures = failures;
  if (checks !== undefined && checks <= 0) {
    process.stderr.write(
      `\nVERDICT GUARD: ${entryName} declared a verdict after running ${checks} checks.\n` +
        `  Nothing was checked, so there was nothing to pass. Forcing exit 1.\n`,
    );
    refused = true;
    process.exitCode = 1;
    return;
  }
  if (checks === undefined && assertionLines === 0) {
    process.stderr.write(
      `\nVERDICT GUARD: ${entryName} declared a verdict having printed 0 assertion lines` +
        `${stdoutBytes === 0 ? " and nothing at all" : ` in ${stdoutBytes} bytes of stdout`}.\n` +
        `  A validator that asserted nothing did not pass, it abstained. Forcing exit 1.\n` +
        `  If this run legitimately has no per-assertion output, pass its own count as the second\n` +
        `  argument: verdictReached(failures, checks).\n`,
    );
    refused = true;
    process.exitCode = 1;
    return;
  }
  // One canonical line, printed by the guard rather than by each validator, so the LOG-READING half of
  // a verification has a fixed anchor too. Reading the exit code is only half the check: a verification
  // grep of `(^|[^a-zA-Z])FAIL` matches nothing under BSD grep on macOS while plain `grep FAIL` found 41
  // lines on the same log, so a log-reading check can pass on a failing run just as quietly as an exit
  // code can. Grep this with a FIXED STRING, never a regex: `grep -F "VERDICT: FAIL"`.
  process.stdout.write(`VERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures}${checks === undefined ? "" : ` checks=${checks}`} entry=${entryName}\n`);
  if (failures > 0) process.exitCode = 1;
}

/**
 * verdictSkipped declares that the entry point could not run its checks, and why. A skip is a real
 * verdict and must be declared like any other, because "exits 0 having checked nothing" is the same
 * false green whether the cause is a hang or a missing precondition.
 *
 * It does NOT force a non-zero exit. Some preconditions are deliberately opt-in (a live Cloudflare
 * account, a vendored 22 MB OpenAPI schema, a sibling Go toolchain) and those probes must not turn an
 * ordinary run red. What it does is make the skip DECLARED and greppable on one uniform line, so the
 * question "did CI actually run this, or did it skip?" has an answer in the log rather than an
 * inference from a silent exit 0.
 *
 * Pass require: true where the caller has decided the precondition is mandatory in this environment
 * (the REQUIRE_* env-var convention this repo already uses); the skip then exits 1.
 */
export function verdictSkipped(reason: string, opts?: { require?: boolean }): void {
  declared = true;
  process.stdout.write(`\nVERDICT SKIPPED: ${entryName}: ${reason}\n`);
  if (opts?.require === true) {
    process.stderr.write(`  the precondition was declared mandatory here, so the skip is a failure.\n`);
    process.exitCode = 1;
  }
}

/**
 * isEntryPoint answers "was this module the file node was pointed at", and it CANONICALISES both sides.
 *
 * The naive forms do not, and all of them are wrong the moment a path contains a symlink:
 *   import.meta.url === `file://${process.argv[1]}`          (no canonicalisation at all)
 *   fileURLToPath(import.meta.url) === process.argv[1]       (same)
 *   import.meta.url === pathToFileURL(process.argv[1]).href  (changes the scheme, not the path)
 *   path.resolve(process.argv[1]) === fileURLToPath(...)     (makes it absolute, not canonical)
 *
 * It matters here specifically. macOS ships /tmp as a symlink to private/tmp, and every scratch worktree
 * in this workspace sits under that path, so reaching the identical file through /tmp made six harness
 * gates and one engine validator decide they were not the entry point: they printed nothing, ran nothing,
 * and exited 0. That is this repo's own false-green class arriving through the front door, and it was
 * found by the harness port pass rather than by reading the code.
 *
 * Only realpathSync closes it, because only realpathSync resolves the symlink.
 */
export function isEntryPoint(importMetaUrl: string): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(importMetaUrl)) === realpathSync(argv1);
  } catch {
    // A path that cannot be resolved is not the entry point, and must not throw out of a top-level guard.
    return false;
  }
}

/** verdictDeclaredFailures exists for the guard's own self-test; nothing else should need it. */
export function verdictDeclaredFailures(): number {
  return declaredFailures;
}
