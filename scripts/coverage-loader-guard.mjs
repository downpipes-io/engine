// Coverage loader guard: the coverage job refuses a validator that runs under a source-mapping loader.
//
// WHY. c8 merges the raw V8 ranges of every process by file URL, then applies a source map to the merged
// ranges when any one process recorded a map for that file. A validator run under tsx records a map for
// every src/ file it loads. The ranges from the plain `node` runs of the same file have no map, so they
// are mapped to the wrong positions: each function then appears twice, once with the plain-node hits at a
// wrong place and once at its real place with only the tsx hits. Measured: four members run
// as `npx tsx` turned 97.83 per cent functions into 30.99, and rekey-handover.ts read 1 of 9 while a plain
// node validator called all 8 of its functions.
//
// Two checks, both exit 2 (cannot measure) and name what they refused:
//   members <script>   before the run: every member of the npm script, with nested `npm run` members
//                      expanded, must start with plain `node`. tsx, ts-node, a loader or an --import is refused.
//   maps <temp-dir>    after the run: no V8 coverage file may carry a source map for a file under src/ or
//                      test/. This catches a loader set in a way the command does not show (NODE_OPTIONS).
//
// `run` is what npm run coverage calls: members, then c8 over npm run validate with the threshold check held
// back, then maps, then c8 check-coverage. A red validator does not stop the maps check or the floor check,
// so every run reports all three verdicts; the exit code is the worst of them (2 over 1 over 0).
//
// Usage: node scripts/coverage-loader-guard.mjs run
//        node scripts/coverage-loader-guard.mjs members validate:chain
//        node scripts/coverage-loader-guard.mjs maps coverage/c8/tmp

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = process.cwd();
const CANNOT_MEASURE = 2;
const TAG = "[coverage-loader-guard]";

// A member that names a TypeScript runner or a Node loader flag anywhere in its command.
const LOADER_RE = /(?:^|[\s;&|(])(?:tsx|ts-node|ts-node-esm|esno|esbuild-register|swc-node)(?=\s|$)|--(?:experimental-)?loader\b|--import\b|--require\b|(?:^|\s)-r\s|NODE_OPTIONS=/;

function refuse(lines) {
  for (const l of lines) console.error(`${TAG} ${l}`);
  console.error(`${TAG} VERDICT: REFUSED (exit ${CANNOT_MEASURE})`);
  process.exit(CANNOT_MEASURE);
}

function members(script) {
  const scripts = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).scripts ?? {};
  const bad = [];
  let count = 0;
  const walk = (name, depth) => {
    const body = scripts[name];
    if (typeof body !== "string") {
      bad.push(`npm script ${name} does not exist`);
      return;
    }
    for (const raw of body.split("&&")) {
      const m = raw.trim();
      const nested = /^npm run ([A-Za-z0-9:_-]+)(?:\s|$)/.exec(m);
      if (nested && depth < 8) {
        walk(nested[1], depth + 1);
        continue;
      }
      count++;
      if (LOADER_RE.test(m)) bad.push(`${name}: "${m}" runs under a source-mapping loader; run it with plain node`);
    }
  };
  walk(script, 0);
  if (count === 0) bad.push(`npm script ${script} has no members`);
  if (bad.length > 0) refuse(bad);
  console.log(`${TAG} members: ${count} commands in ${script}, none under a loader. VERDICT: PASS`);
}

function maps(dir) {
  const abs = resolve(ROOT, dir);
  const files = existsSync(abs) ? readdirSync(abs).filter((f) => f.endsWith(".json")) : [];
  if (files.length === 0) refuse([`no V8 coverage files in ${dir}, so nothing can be checked`]);
  const under = [`${join(ROOT, "src")}/`, `${join(ROOT, "test")}/`];
  const bad = [];
  for (const f of files) {
    const j = JSON.parse(readFileSync(join(abs, f), "utf8"));
    const urls = Object.keys(j["source-map-cache"] ?? {});
    const ours = urls.map((u) => (u.startsWith("file:") ? fileURLToPath(u) : u)).filter((p) => under.some((d) => p.startsWith(d)));
    if (ours.length === 0) continue;
    const entry = ours.find((p) => /\/test\/validate-[^/]+\.ts$/.test(p)) ?? ours[0];
    bad.push(`${f}: ${ours.length} source maps for repo files; process entry ${entry.slice(ROOT.length + 1)}`);
  }
  if (bad.length > 0) refuse(bad);
  console.log(`${TAG} maps: ${files.length} coverage files, none with a source map for a repo file. VERDICT: PASS`);
}

function run() {
  const step = (args) => {
    const r = spawnSync(process.execPath, args, { stdio: "inherit" });
    return r.status ?? CANNOT_MEASURE;
  };
  const self = fileURLToPath(import.meta.url);
  const c8 = join(ROOT, "node_modules", "c8", "bin", "c8.js");
  const pre = step([self, "members", "validate:chain"]);
  if (pre !== 0) process.exit(pre);
  const suite = spawnSync(process.execPath, [c8, "--no-check-coverage", "npm", "run", "validate"], { stdio: "inherit" }).status ?? CANNOT_MEASURE;
  const mapped = step([self, "maps", "coverage/c8/tmp"]);
  const floors = mapped === 0 ? step([c8, "check-coverage"]) : CANNOT_MEASURE;
  console.log(`${TAG} suite exit ${suite}, maps exit ${mapped}, floors exit ${floors}${mapped === 0 ? "" : " (not checked: the figures are not valid)"}`);
  process.exit(Math.max(suite === 0 ? 0 : suite === 1 ? 1 : CANNOT_MEASURE, mapped, floors === 0 ? 0 : floors === CANNOT_MEASURE ? CANNOT_MEASURE : 1));
}

const [mode, arg] = process.argv.slice(2);
if (mode === "run") run();
else if (mode === "members" && arg) members(arg);
else if (mode === "maps" && arg) maps(arg);
else refuse(["usage: coverage-loader-guard.mjs run | members <npm-script> | maps <temp-dir>"]);
