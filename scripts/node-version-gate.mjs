#!/usr/bin/env node
// Every workflow's Node version must equal .nvmrc, and .nvmrc is why this repo has one.
//
// WHAT THIS IS FOR, and it is not tidiness. Four workflows each declared `NODE_VERSION: "22"`
// independently, and nothing at all told a developer working locally. `engines` says `>=20`, which a
// machine running Node 25 satisfies, so the local runtime can be three majors ahead of the one that
// gates while every declared constraint is met.
//
// That gap has a cost and it was paid twice in one session. A coverage figure is a property of the
// runtime: src/screens/map/controller.ts measures 181 of 520 statements covered on Node 25 and about 81
// on Node 22, so the per-file gate reported it comfortably above its floor locally and below it in CI. A
// baseline entry was deleted on the local reading and CI went red. The same gap had already swallowed two
// bugs earlier in this workspace's history.
//
// .nvmrc fixes the half a tool can fix: nvm, fnm, volta and asdf all read it, so a developer who uses any
// of them lands on the version CI runs without being told. This gate fixes the other half, which is that
// the file only helps while it agrees with the workflows. Four independent copies of a version string
// drift, and the drift is silent until a job behaves differently from the one beside it.
//
// It deliberately does NOT rewrite the workflows to read .nvmrc directly. That would be the tidier shape,
// and it would change how every job resolves its runtime for a benefit this gate already delivers.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const NVMRC = join(ROOT, ".nvmrc");
const WORKFLOWS = join(ROOT, ".github", "workflows");

if (!existsSync(NVMRC)) {
  console.error("FAIL node-version: .nvmrc is missing. It is what points a local runtime at the version CI gates on.");
  process.exit(1);
}
const want = readFileSync(NVMRC, "utf8").trim();
if (!/^\d+$/.test(want)) {
  console.error(`FAIL node-version: .nvmrc reads ${JSON.stringify(want)}, which is not a bare major version.`);
  process.exit(1);
}

if (!existsSync(WORKFLOWS)) {
  console.error("FAIL node-version: no .github/workflows directory, so this gate checked nothing.");
  process.exit(1);
}

const declared = [];
for (const name of readdirSync(WORKFLOWS)) {
  if (!name.endsWith(".yml") && !name.endsWith(".yaml")) continue;
  const body = readFileSync(join(WORKFLOWS, name), "utf8");
  // Two spellings are in use across these repos: an env var the steps interpolate, and a literal on the
  // setup-node step. Both are read, because a gate that knows one style passes a repo written in the
  // other while checking nothing.
  for (const m of body.matchAll(/^\s*NODE_VERSION:\s*"?(\d+)"?\s*$/gm)) {
    declared.push({ file: name, version: m[1], how: "NODE_VERSION" });
  }
  for (const m of body.matchAll(/node-version:\s*['"](\d+)['"]/g)) {
    declared.push({ file: name, version: m[1], how: "node-version" });
  }
}

// A gate that finds nothing to compare reads exactly like a passing gate.
if (declared.length === 0) {
  console.error(
    "FAIL node-version: no workflow declares NODE_VERSION, so nothing was compared against .nvmrc.\n" +
      "  Either the workflows stopped pinning a version, or this gate's pattern no longer matches how they do it.",
  );
  process.exit(1);
}

const wrong = declared.filter((d) => d.version !== want);
if (wrong.length > 0) {
  console.error(`FAIL node-version: ${wrong.length} workflow declaration(s) disagree with .nvmrc (${want}):\n`);
  for (const w of wrong) console.error(`  ${w.file}: ${w.how} ${w.version}`);
  console.error(
    "\nA local runtime follows .nvmrc and CI follows the workflow, so while these disagree a developer is\n" +
      "testing on one version and gating on another. Coverage, and anything else that depends on which code\n" +
      "paths execute, will differ between them without either side looking wrong.",
  );
  process.exit(1);
}

console.log(`ok   node-version: .nvmrc (${want}) matches all ${declared.length} workflow declaration(s)`);
