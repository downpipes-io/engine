// The customer deploy preflight and the developer chain must not drift apart.
//
// WHY THIS EXISTS. scripts/deploy.sh used to run `npm run validate` as its preflight. That chain is the
// developer's: it compares this repo with sibling checkouts and refuses (exit 2) when a sibling is behind
// its own origin/main. A customer following /deploy checks out a release tag in engine and in console,
// and a release tag is behind main as soon as anything lands after it, so every such deploy stopped with
// CANNOT CHECK. The preflight now runs validate:customer:chain instead: the members of validate:chain
// that guard the customer's data and keys, classified member by member in scripts/customer-preflight.json.
//
// WHAT THIS GRADES, so the split cannot rot:
//   1. every member of validate:chain is classified in the manifest, so a new gate has to be placed on one
//      side or the other by someone who read it, and the manifest names no member that still exists outside
//      the chain (an entry whose file is absent from this tree, as a public export drops some developer
//      gates, is noted rather than failed);
//   2. every left-out member carries a category with a one-line reason;
//   3. validate:customer:chain is exactly the kept members, in validate:chain's order, and
//      validate:customer runs it with a floor equal to its length;
//   4. no kept member imports the sibling freshness or sibling lag helpers, except the two named below,
//      which read the downpipe reader only when DOWNPIPE_REPO names one;
//   5. deploy.sh runs the customer preflight (dependencies, typecheck, build, validate:customer) and does
//      not run the developer chain, and the duration it prints is the one the manifest records.
//
// Run: node test/validate-customer-preflight.ts

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
type Manifest = {
  dropReasons: Record<string, string>;
  measured: { seconds: number; text: string } | null;
  members: Record<string, string>;
};
const manifest = JSON.parse(readFileSync(join(ROOT, "scripts", "customer-preflight.json"), "utf8")) as Manifest;
const split = (s: string | undefined): string[] => (s ?? "").split("&&").map((m) => m.trim()).filter(Boolean);

const devChain = split(pkg.scripts["validate:chain"]);
const custChain = split(pkg.scripts["validate:customer:chain"]);
const classified = Object.keys(manifest.members);

console.log("-- every member of validate:chain is classified, and nothing else is --");
{
  const unclassified = devChain.filter((m) => !(m in manifest.members));
  const outside = classified.filter((m) => !devChain.includes(m));
  const present = (m: string): boolean => {
    const script = m.match(/^npm run (\S+)$/)?.[1];
    if (script !== undefined) return script in pkg.scripts;
    const file = m.match(/^node (\S+)/)?.[1];
    return file !== undefined && existsSync(join(ROOT, file));
  };
  const stale = outside.filter(present);
  for (const m of outside.filter((x) => !present(x))) console.log(`  note ${m} is classified but absent from this tree, so it is not graded here`);
  ok(`validate:chain has members to classify (${devChain.length})`, devChain.length > 100);
  ok("every member of validate:chain is classified in scripts/customer-preflight.json", unclassified.length === 0, unclassified.join(", "));
  ok("the manifest names no member that still exists outside validate:chain", stale.length === 0, stale.join(", "));
}

console.log("\n-- every left-out member has a category with a one-line reason --");
{
  const cats = new Set(Object.values(manifest.members));
  const noReason = [...cats].filter((c) => c !== "keep" && !(c in manifest.dropReasons));
  ok("every category a member uses has a reason", noReason.length === 0, noReason.join(", "));
  const badReason = Object.entries(manifest.dropReasons).filter(([, r]) => typeof r !== "string" || r.trim() === "" || r.includes("\n"));
  ok("every reason is one non-empty line", badReason.length === 0, badReason.map(([c]) => c).join(", "));
  const unused = Object.keys(manifest.dropReasons).filter((c) => !cats.has(c));
  ok("no reason is left over from a category nothing uses", unused.length === 0, unused.join(", "));
}

console.log("\n-- validate:customer:chain is exactly the kept members, in order --");
{
  const kept = devChain.filter((m) => manifest.members[m] === "keep");
  ok(`the preflight keeps members (${kept.length})`, kept.length > 0);
  ok("validate:customer:chain equals the kept members in validate:chain's order", JSON.stringify(custChain) === JSON.stringify(kept), `chain has ${custChain.length}, manifest keeps ${kept.length}`);
  ok("validate:customer runs that chain with a floor equal to its length", pkg.scripts["validate:customer"] === `node scripts/run-gate-chain.mjs validate:customer:chain ${custChain.length}`, pkg.scripts["validate:customer"]);
  ok("validate runs the whole developer chain, and only that chain, with a floor equal to its length", pkg.scripts.validate === `node scripts/run-gate-chain.mjs validate:chain ${devChain.length}`, pkg.scripts.validate);
}

console.log("\n-- no kept member reads a sibling's freshness --");
{
  // These two compare the vendored format copy with the downpipe reader ONLY when DOWNPIPE_REPO names a
  // reader checkout, and the freshness call sits inside that branch. A customer deploy sets no such
  // variable, so both grade the vendored copy and never look at a sibling.
  const READ_ONLY_WHEN_NAMED: Record<string, string> = {
    "node test/validate-format-constants.ts": "reads the downpipe reader only when DOWNPIPE_REPO is set",
    "node test/validate-schema-conformance.ts": "reads the downpipe reader only when DOWNPIPE_REPO is set",
  };
  const IMPORT = /from\s+"\.\.\/scripts\/(sibling-freshness\.mjs|lib\/sibling-lag\.mjs)"/;
  const offenders: string[] = [];
  for (const m of custChain) {
    const file = m.match(/^node (test\/\S+\.ts)$/)?.[1];
    if (file === undefined) {
      offenders.push(`${m} (not a single test file, so its imports cannot be read here)`);
      continue;
    }
    if (IMPORT.test(readFileSync(join(ROOT, file), "utf8")) && !(m in READ_ONLY_WHEN_NAMED)) offenders.push(m);
  }
  ok("no kept member imports sibling-freshness.mjs or sibling-lag.mjs outside the named exceptions", offenders.length === 0, offenders.join(", "));
  const guarded = Object.keys(READ_ONLY_WHEN_NAMED).filter((m) => custChain.includes(m));
  for (const m of guarded) {
    const src = readFileSync(join(ROOT, m.replace(/^node /, "")), "utf8");
    ok(`${m.replace(/^node test\//, "")}: its sibling read is behind DOWNPIPE_REPO`, /process\.env\.DOWNPIPE_REPO/.test(src));
  }
}

console.log("\n-- deploy.sh runs the customer preflight, not the developer chain --");
{
  const deploy = readFileSync(join(ROOT, "scripts", "deploy.sh"), "utf8");
  const runs = [...deploy.matchAll(/^\s*preflight_run "([^"]+)" (.+)$/gm)].map((m) => ({ label: m[1]!, cmd: m[2]!.trim() }));
  const want = [
    { label: "dependencies", cmd: "npm run lint:deps-installed" },
    { label: "typecheck", cmd: "npm run typecheck" },
    { label: "build", cmd: "preflight_build" },
    { label: "validate:customer", cmd: "npm run validate:customer" },
  ];
  ok("deploy.sh runs dependencies, typecheck, build and validate:customer, in that order", JSON.stringify(runs) === JSON.stringify(want), JSON.stringify(runs));
  ok("deploy.sh does not run the developer chain (npm run validate) as a preflight", !/^\s*preflight_run "[^"]+" npm run validate\s*$/m.test(deploy));
  ok("the build step is a wrangler dry run into a temporary directory", /npx wrangler deploy --dry-run --outdir "\$preflight_build_dir"/.test(deploy));
  ok("the manifest records a measured duration", manifest.measured !== null && manifest.measured.seconds > 0 && manifest.measured.text !== "");
  if (manifest.measured !== null) {
    ok("deploy.sh prints the measured duration the manifest records", deploy.includes(manifest.measured.text), manifest.measured.text);
  }
  ok("deploy.sh carries no unfilled duration placeholder", !deploy.includes("MEASURED_DURATION"));
}

verdictReached(failures);
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nCUSTOMER PREFLIGHT AND DEVELOPER CHAIN AGREE");
