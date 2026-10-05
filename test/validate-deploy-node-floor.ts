// Validates the Node floor that scripts/deploy.sh sources (scripts/node-floor.sh) and its agreement with
// "engines" in package.json.
//
// The deploy runs node directly on .ts files: scripts/generate-keys.ts, and every test/validate-*.ts under
// the blocking preflight's npm run validate:customer. Node runs a .ts file without a flag from 22.18 on the 22 line
// and from 23.6 on the 23 line. An earlier Node stops partway through the deploy with
// ERR_UNKNOWN_FILE_EXTENSION, after the operator has already started it. The check at the top of deploy.sh
// refuses first, and names the version it needs.
//
// This drives the REAL scripts/node-floor.sh under /bin/sh with `node` shadowed by a shell function that
// reports a chosen version. Nothing runs the real node, npm or wrangler. It also checks that deploy.sh
// sources the file on the line that moves to the repo root, before the flag parser and the preflight.
//
// It also holds three declarations together: the floor deploy.sh names, "engines.node" in package.json,
// and the root package's "engines" in package-lock.json. A floor that moves in one place and not the others
// tells an operator one version and enforces another. The engines range is evaluated against every sampled
// version, so it must refuse 23.0 to 23.5 as the script does, and not only name the 22.18 floor.
//
// Run: node test/validate-deploy-node-floor.ts
//
//

import { spawnSync } from "node:child_process";
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
const FLOOR_SH = join(ENGINE_DIR, "scripts", "node-floor.sh");

let fragment = "";
try {
  fragment = readFileSync(FLOOR_SH, "utf8");
} catch (e) {
  ok(`scripts/node-floor.sh exists (${(e as Error).message})`, false);
  verdictReached(failures);
  process.exit(1);
}
ok("node-floor.sh carries the check and its end marker", fragment.includes("NODE_FLOOR=") && fragment.includes("# END NODE FLOOR"));

// deploy.sh must source it on the cd line, with ";" and not "&&": under set -e a failed cd in an && list
// does not stop the script, and a failed cd must.
const sourceLines = LINES.map((l, i) => ({ l, i })).filter(({ l }) => /\.\s+\.\/scripts\/node-floor\.sh/.test(l));
ok(`deploy.sh sources scripts/node-floor.sh exactly once (${sourceLines.length})`, sourceLines.length === 1);
const src = sourceLines[0];
ok("deploy.sh sources it on the cd to the repo root, after a semicolon", src !== undefined && src.l === 'cd "$(dirname "$0")/.."; . ./scripts/node-floor.sh');
const setE = LINES.indexOf("set -e");
const parser = LINES.findIndex((l) => l.startsWith("ENABLE_OPERATIONAL=0"));
const preflight = LINES.findIndex((l) => l.includes('preflight_run "typecheck"'));
ok("the source line runs after set -e and before the flag parser and the preflight", src !== undefined && setE >= 0 && src.i > setE && parser > src.i && preflight > src.i);

// runWith runs the fragment under /bin/sh with `node` replaced. version === null makes node fail as a
// missing command would.
function runWith(version: string | null): { code: number; stderr: string; ranOn: boolean } {
  const dir = mkdtempSync(join(tmpdir(), "node-floor-"));
  try {
    const shim = version === null ? "node() { return 127; }" : `node() { echo '${version}'; }`;
    const body = `set -e\n${shim}\n${fragment}\necho RAN_ON\n`;
    const file = join(dir, "frag.sh");
    writeFileSync(file, body);
    const r = spawnSync("/bin/sh", [file], { cwd: dir, encoding: "utf8" });
    return { code: r.status ?? -1, stderr: r.stderr ?? "", ranOn: (r.stdout ?? "").includes("RAN_ON") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const REFUSED = ["20.19.0", "22.17.1", "22.0.0", "23.0.0", "23.5.0", "18.20.4"];
const ACCEPTED = ["22.18.0", "22.20.1", "23.6.0", "24.0.0", "25.2.1"];

console.log("\n-- the deploy refuses a Node that cannot run its .ts files --\n");
for (const v of REFUSED) {
  const r = runWith(v);
  ok(`Node ${v}: refused with exit 1, naming 22.18 and the version found`, r.code === 1 && !r.ranOn && r.stderr.includes("22.18") && r.stderr.includes(v));
}
{
  const r = runWith(null);
  ok("no node command: refused with exit 1, naming 22.18", r.code === 1 && !r.ranOn && r.stderr.includes("22.18") && r.stderr.includes("No node command"));
}
{
  const r = runWith("v22.18.0");
  ok("an unparseable version string is refused, not waved through", r.code === 1 && !r.ranOn);
}

console.log("\n-- the deploy goes on with a Node that can --\n");
for (const v of ACCEPTED) {
  const r = runWith(v);
  ok(`Node ${v}: the deploy continues`, r.code === 0 && r.ranOn && r.stderr === "");
}

console.log("\n-- node-floor.sh, package.json and package-lock.json name one floor --\n");
const floorMatch = /^NODE_FLOOR="(\d+)\.(\d+)"$/m.exec(fragment);
ok("node-floor.sh declares NODE_FLOOR as major.minor", floorMatch !== null);
const floorVersion = floorMatch ? `${floorMatch[1]}.${floorMatch[2]}.0` : "(none)";
const pkg = JSON.parse(readFileSync(join(ENGINE_DIR, "package.json"), "utf8")) as { engines?: { node?: string } };
const pkgRange = pkg.engines?.node ?? "";
ok(`package.json engines.node starts from the script's floor >=${floorVersion} (found ${pkgRange || "none"})`, pkgRange.startsWith(`>=${floorVersion}`));
const lock = JSON.parse(readFileSync(join(ENGINE_DIR, "package-lock.json"), "utf8")) as { packages?: Record<string, { engines?: { node?: string } }> };
const lockRoot = lock.packages?.[""]?.engines?.node;
ok(`package-lock.json root engines.node equals package.json (found ${lockRoot ?? "none"})`, lockRoot !== undefined && lockRoot === pkgRange);

// satisfies evaluates the npm range forms engines.node uses here: comparator sets joined by "||", each a
// space-separated list of >=, >, <= or < against a major, major.minor or major.minor.patch. Anything else
// makes it return null, which the checks below count as a failure rather than a pass.
function satisfies(version: string, range: string): boolean | null {
  const parse = (v: string): number[] | null => {
    if (!/^\d+(\.\d+){0,2}$/.test(v)) return null;
    const parts = v.split(".").map(Number);
    while (parts.length < 3) parts.push(0);
    return parts;
  };
  const cmp = (a: number[], b: number[]): number => {
    for (let i = 0; i < 3; i++) {
      const d = (a[i] ?? 0) - (b[i] ?? 0);
      if (d !== 0) return d;
    }
    return 0;
  };
  const have = parse(version);
  if (have === null || range.trim() === "") return null;
  let any = false;
  for (const set of range.split("||")) {
    const comparators = set.trim().split(/\s+/);
    let all = true;
    for (const c of comparators) {
      const m = /^(>=|<=|>|<)(.+)$/.exec(c);
      const op = m?.[1];
      const want = m?.[2] !== undefined ? parse(m[2]) : null;
      if (op === undefined || want === null) return null;
      const d = cmp(have, want);
      const pass = op === ">=" ? d >= 0 : op === ">" ? d > 0 : op === "<=" ? d <= 0 : d < 0;
      if (!pass) all = false;
    }
    if (all) any = true;
  }
  return any;
}
for (const v of REFUSED) ok(`engines.node refuses ${v}, as the script does`, satisfies(v, pkgRange) === false);
for (const v of ACCEPTED) ok(`engines.node accepts ${v}, as the script does`, satisfies(v, pkgRange) === true);

// Negative controls: the range comparison must be able to fail. A bare ">=22.18.0" is the case it exists
// for (it admits 23.0 to 23.5), and the old ">=20.19.0" admits 22.17.
ok("control: a bare >=22.18.0 range would admit 23.5.0", satisfies("23.5.0", ">=22.18.0") === true);
ok("control: the old engines value >=20.19.0 would admit 22.17.1", satisfies("22.17.1", ">=20.19.0") === true);
ok("control: an unsupported range form is not read as a pass", satisfies("24.0.0", "^22.18.0") === null);

console.log(`\n${failures === 0 ? "DEPLOY-NODE-FLOOR PASS" : `DEPLOY-NODE-FLOOR: ${failures} FAILED`}`);
verdictReached(failures);
