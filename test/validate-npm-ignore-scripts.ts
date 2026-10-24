// The npm config of this repo turns dependency install scripts off.
//
// WHAT IT GUARDS. An install script is code a dependency runs on the machine that installs it: a developer's
// laptop, a CI runner, the release build. .npmrc sets ignore-scripts=true so that no dependency, direct or
// transitive, runs code at install time, and nothing in this tree needs one to build, lint or test. The
// setting is one line in a file nobody reads twice. Without a check, deleting the line, commenting it out or
// setting it false changes what every later install does and no gate says so.
//
// WHAT IT ASSERTS, on the repo's own .npmrc:
//   1. the file exists;
//   2. ignore-scripts is assigned, outside a comment;
//   3. every assignment of it is the value true (npm reads the last one, so an earlier true does not excuse a
//      later false).
// The parser is exercised first on planted texts, so a pass on the real file is a pass from a check that can
// fail.
//
// Run: node test/validate-npm-ignore-scripts.ts

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ignoreScriptsAssignments returns the value of each ignore-scripts assignment in an .npmrc text, in file
// order. A line that starts with # or ; is a comment. Keys and values are trimmed, and a quoted value is
// unquoted, as npm's ini reader does. The camel-case spelling npm also accepts is read as the same key.
function ignoreScriptsAssignments(text: string): string[] {
  const values: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const eq = line.indexOf("=");
    const key = (eq === -1 ? line : line.slice(0, eq)).trim().toLowerCase();
    if (key !== "ignore-scripts" && key !== "ignorescripts") continue;
    // A bare key with no "=" is the value true in an ini file.
    values.push(eq === -1 ? "true" : line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, "$2").toLowerCase());
  }
  return values;
}

// installScriptsAreOff: at least one assignment, and every one of them true.
function installScriptsAreOff(text: string): boolean {
  const values = ignoreScriptsAssignments(text);
  return values.length > 0 && values.every((v) => v === "true");
}

console.log("A. the parser can tell on from off (planted texts):");
ok("ignore-scripts=true is off", installScriptsAreOff("legacy-peer-deps=true\nignore-scripts=true\n"));
ok("spaces and quotes around the value are read", installScriptsAreOff('ignore-scripts = "true"\n'));
ok("a file with no such line is refused", !installScriptsAreOff("legacy-peer-deps=true\n"));
ok("an empty file is refused", !installScriptsAreOff(""));
ok("a commented-out line is refused", !installScriptsAreOff("# ignore-scripts=true\n; ignore-scripts=true\n"));
ok("ignore-scripts=false is refused", !installScriptsAreOff("ignore-scripts=false\n"));
ok("a later false after an earlier true is refused", !installScriptsAreOff("ignore-scripts=true\nignore-scripts=false\n"));
ok("an earlier false before a later true is refused", !installScriptsAreOff("ignore-scripts=false\nignore-scripts=true\n"));
ok("a value that is not true is refused", !installScriptsAreOff("ignore-scripts=yes\n"));
ok("a key that only contains the name is not read as the setting", !installScriptsAreOff("not-ignore-scripts=true\n"));

console.log("B. this repo's .npmrc:");
const npmrc = join(dirname(fileURLToPath(import.meta.url)), "..", ".npmrc");
ok(".npmrc exists at the repo root", existsSync(npmrc));
const text = existsSync(npmrc) ? readFileSync(npmrc, "utf8") : "";
const found = ignoreScriptsAssignments(text);
ok(`ignore-scripts is assigned (found ${found.length} assignment(s))`, found.length > 0);
ok(`every assignment is true (found: ${found.join(", ") || "none"})`, installScriptsAreOff(text));

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-npm-ignore-scripts (${failures} failure(s))`);
verdictReached(failures, checks);
process.exit(failures === 0 ? 0 : 1);
