#!/usr/bin/env node
// gate-red-proof: plant a fresh defect of each class the two SCOPE gates exist to catch, and prove each
// gate actually goes red on it.
//
// WHY THIS EXISTS. lint:scope and typecheck:test were both red on main, owned by nobody, for long enough
// that every pass running the chain inherited somebody else's failure. The corrosive part is not the two
// failures, it is that a gate people expect to be red stops being read, and a gate nobody reads is not a
// gate. Both are now green. A gate that has just been quieted is exactly the one to distrust, so this file
// asks the only question that settles it: CAN IT STILL GO RED?
//
// A ratchet gate is the easy one to fake. lint:scope compares a live count against a pinned ceiling, and
// there are two ways to make it green: fix the diagnostics, or raise the pin. Both look identical in CI. The
// error and warning arms below plant one diagnostic of each severity and require the gate to name the rise,
// which a raised pin would not survive: if the ceiling had been lifted to 24 instead of the count brought
// down to 23, the error arm would report the rise to 25 and still pass this file, but the PIN arm would see
// a baseline that does not match the recorded 23/100 and refuse.
//
// THE PIN MOVED DOWN ON 2026-08-13 AND THIS ARM IS WHY THAT WAS A DECISION RATHER THAN A SIDE EFFECT.
// Another pass removed 44 unused imports from test/, which are noUnusedImports WARNINGS, so the live
// count fell 144 to 100 while the pin still read 144. lint:scope PASSED (a ratchet never complains about
// going down) and printed "below the pin; re-pin", but the gate then had FORTY-FOUR WARNINGS OF SLACK and
// could not have seen the next forty-four regressions. This file caught it, because ARM 2 plants ONE
// warning and requires a red: at 101 against a pin of 144 the gate stayed green and the arm failed. That
// is the ratchet going slack, reported by the only thing watching for it. The baseline was re-pinned DOWN
// to 23/100, which TIGHTENS the gate; the numbers here follow the pin and must never be edited to make a
// red go away.
//
// THE BOUNDARY ARM IS THE ONE THAT NEEDED A CONTROL. Four of the seven typecheck errors were resolved by
// setting allowJs, which is a coverage widening rather than a fix, and a widening claimed without
// measurement is exactly the shape this campaign keeps finding. So that arm plants a MISUSE of an .mjs
// export from a .ts file and runs it twice: once under the real config, where it must be caught, and once
// under a generated copy with allowJs turned back off, where it must NOT be, because there the module is
// any and the misuse is invisible. Firing under both would mean the arm was measuring something other than
// allowJs. The control has to match the scheme it checks, or the pass merely looks checked.
//
// EXIT CODES. 0 every arm behaved. 1 an arm FAILED, meaning a gate did not go red on a defect it owns, or a
// control did not stay green. 2 could not check, including any unexpected throw, because an uncaught error
// exits 1 on its own and 1 here means a finding, so a crash would be read as a result.
//
// Run: node scripts/gate-red-proof.mjs [--verbose]

import { writeFileSync, unlinkSync, existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERBOSE = process.argv.includes("--verbose");
const PLANT = join(REPO, "test", "gate-red-proof-plant.ts");
const ALTCONFIG = join(REPO, "tsconfig.gate-red-proof-noallowjs.json");
const BASELINE = join(REPO, "scripts", "lint-scope-baseline.json");

let failures = 0;
let checks = 0;
function ok(label, cond, detail) {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "ok  " : "FAIL"}  ${label}`);
  if (detail && (VERBOSE || !cond)) console.log(`          ${String(detail).split("\n").slice(0, 4).join("\n          ")}`);
}

function run(script) {
  const r = spawnSync("npm", ["run", "--silent", script], { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`cannot check: npm run ${script} did not start (${r.error.message})`);
  return { code: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

// Invoked by explicit path, not "npx tsc": "typescript" (6.x, the compiler-API package) and
// "typescript-7" (the aliased 7.x package this CLI comes from) both declare a "tsc" bin, so
// node_modules/.bin/tsc is whichever one npm linked last.
const TSC = join(REPO, "node_modules", "typescript-7", "bin", "tsc");
function tsc(configPath) {
  const r = spawnSync("node", [TSC, "--noEmit", "-p", configPath], { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`cannot check: tsc did not start (${r.error.message})`);
  return { code: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function plant(contents) {
  writeFileSync(PLANT, contents);
}
function unplant() {
  if (existsSync(PLANT)) unlinkSync(PLANT);
  if (existsSync(ALTCONFIG)) unlinkSync(ALTCONFIG);
}

// The four defect classes, each the smallest thing that produces exactly one diagnostic of its kind.
const ERROR_PLANT = `// planted by scripts/gate-red-proof.mjs; deleted by it. biome: noDoubleEquals is an ERROR.
export function gateRedProofPlanted(a: unknown, b: unknown): boolean {
  return a == b;
}
`;
const WARNING_PLANT = `// planted by scripts/gate-red-proof.mjs; deleted by it. biome: noUnusedImports is a WARNING.
import { readFileSync } from "node:fs";
export const gateRedProofPlanted = 1;
`;
const TYPE_PLANT = `// planted by scripts/gate-red-proof.mjs; deleted by it. tsc: TS2322 in a .ts test file.
export const gateRedProofPlanted: number = "not a number";
`;
const BOUNDARY_PLANT = `// planted by scripts/gate-red-proof.mjs; deleted by it. balancedCallAt returns an array or null,
// and this file asks for a number. Catching it requires READING the .mjs, which is what allowJs buys.
import { balancedCallAt } from "../scripts/guard-mutation-harness.mjs";
export const gateRedProofPlanted: number = balancedCallAt("abc", 0);
`;

function main() {
  if (existsSync(PLANT)) throw new Error(`cannot check: ${PLANT} already exists; refusing to overwrite a file this run did not create`);

  console.log("\n-- CONTROL: both gates are green with nothing planted --\n");
  const baseLint = run("lint:scope");
  ok("CONTROL lint:scope passes unplanted", baseLint.code === 0, baseLint.out);
  const baseType = run("typecheck:test");
  ok("CONTROL typecheck:test passes unplanted", baseType.code === 0, baseType.out);

  // THE PIN ARM. A green ratchet proves nothing if the ceiling was lifted to meet the count, so the recorded
  // numbers are asserted outright. Change these two only alongside a written rationale in the gate.
  let pinned;
  try {
    pinned = JSON.parse(readFileSync(BASELINE, "utf8"));
  } catch (e) {
    throw new Error(`cannot check: the lint-scope baseline is unreadable (${e instanceof Error ? e.message : String(e)})`);
  }
  ok("the lint:scope pin is still 23 errors, NOT raised to meet the count", pinned.counts?.error === 23, `error pin is ${pinned.counts?.error}`);
  ok("the lint:scope pin is 100 warnings, NOT raised to meet the count (it came DOWN from 144 by repair)", pinned.counts?.warning === 100, `warning pin is ${pinned.counts?.warning}`);

  console.log("\n-- ARM 1: lint:scope, ERROR class (biome noDoubleEquals) --\n");
  plant(ERROR_PLANT);
  const armError = run("lint:scope");
  unplant();
  ok("lint:scope goes RED on a planted error", armError.code === 1, armError.out);
  ok("  and NAMES the rise rather than failing vaguely", /errors rose from 23 to 24/.test(armError.out), armError.out);

  console.log("\n-- ARM 2: lint:scope, WARNING class (biome noUnusedImports) --\n");
  plant(WARNING_PLANT);
  const armWarn = run("lint:scope");
  unplant();
  ok("lint:scope goes RED on a planted warning", armWarn.code === 1, armWarn.out);
  ok("  and names the WARNING rise, not the error one", /warnings rose from 100 to 101/.test(armWarn.out) && !/errors rose/.test(armWarn.out), armWarn.out);

  console.log("\n-- ARM 3: typecheck:test, a type error in a .ts validator --\n");
  plant(TYPE_PLANT);
  const armType = run("typecheck:test");
  unplant();
  ok("typecheck:test goes RED on a planted TS2322", armType.code !== 0, armType.out);
  ok("  and names the planted file", /gate-red-proof-plant\.ts.*TS2322/.test(armType.out), armType.out);

  console.log("\n-- ARM 4: typecheck:test, MISUSE OF AN .mjs EXPORT, with its allowJs control --\n");
  plant(BOUNDARY_PLANT);
  const armBoundary = run("typecheck:test");
  ok("typecheck:test goes RED when a .ts file misuses an .mjs export", armBoundary.code !== 0, armBoundary.out);
  ok("  and it is the MISUSE that is named (TS2322), not the unreadable module", /gate-red-proof-plant\.ts.*TS2322/.test(armBoundary.out), armBoundary.out);

  // The control for arm 4: the identical plant, under a config with allowJs turned back off. It must NOT be
  // caught there. If it were, the arm would be measuring something other than the setting it claims to test.
  writeFileSync(
    ALTCONFIG,
    `${JSON.stringify(
      {
        "//": "Generated and deleted by scripts/gate-red-proof.mjs. tsconfig.test.json as it stood BEFORE allowJs, so the boundary arm can show what that setting is worth.",
        extends: "./tsconfig.test.json",
        compilerOptions: { allowJs: false },
        include: ["src", "test", "scripts", "tools"],
        exclude: ["test/vitest"],
      },
      null,
      2,
    )}\n`,
  );
  const control = tsc(ALTCONFIG);
  unplant();
  ok("CONTROL with allowJs OFF the same misuse is NOT caught", !/gate-red-proof-plant\.ts.*TS2322/.test(control.out), control.out);
  ok("CONTROL and the module reads as an implicit any there (TS7016), which is the hole allowJs closes", /TS7016/.test(control.out), control.out);

  console.log("\n-- RESTORATION: the plants are gone and the gates are green again --\n");
  ok("the planted file was removed", !existsSync(PLANT));
  ok("the generated config was removed", !existsSync(ALTCONFIG));
  const endLint = run("lint:scope");
  ok("lint:scope is green again after every plant", endLint.code === 0, endLint.out);
  const endType = run("typecheck:test");
  ok("typecheck:test is green again after every plant", endType.code === 0, endType.out);

  console.log(`\ngate-red-proof: ${checks} check(s), ${failures} failure(s)`);
  if (failures) {
    console.log("GATE RED-PROOF FAIL: a gate did not go red on a defect it owns, or a control did not hold.");
    return 1;
  }
  console.log("GATE RED-PROOF PASS: both gates are green, and both still fail on a fresh defect of their own class.");
  return 0;
}

let code;
try {
  code = main();
} catch (e) {
  unplant();
  console.error(`gate-red-proof: ${e instanceof Error ? e.message : String(e)}`);
  code = 2;
}
process.exit(code);
