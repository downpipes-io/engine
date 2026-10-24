// Build-integrity pins for the release SBOM and the tools CI downloads.
//
// WHAT THIS GRADES, and the defect each check closes:
//   1. scripts/generate-sbom.sh runs @cyclonedx/cyclonedx-npm at an EXACT x.y.z version. The release
//      job runs this script, and npx fetches the generator at that moment. A major-only pin ("@4")
//      lets any later 4.x release change the SBOM bytes, which SHA256SUMS.txt names and cosign signs.
//   2. The same invocation passes --output-reproducible. Without it the tool writes a random
//      serialNumber and the wall-clock metadata.timestamp, so two builds of one commit give two SBOMs.
//      With the flag, two builds of one commit give byte-identical SBOMs.
//   3. The invocation keeps --omit dev and --package-lock-only (the runtime-only, lockfile scope).
//   4. Every file a workflow downloads with curl or wget is checked with `sha256sum -c` in the same
//      step. A version string alone does not pin the bytes: a re-uploaded release asset passes it.
//   5. No workflow pipes a download into a shell.
// Each check is also run against planted inputs, so a check that cannot fail is not reported as a pass.
//
// Run: node test/validate-build-tool-pins.ts

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

// Joins backslash continuations so one command reads as one line, and keeps each line's 1-based source line.
function logicalLines(text: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  let open: { text: string; line: number } | undefined;
  text.split(/\r?\n/).forEach((raw, i) => {
    const cont = raw.endsWith("\\");
    const body = cont ? raw.slice(0, -1) : raw;
    if (open) open.text += ` ${body.trim()}`;
    else open = { text: body, line: i + 1 };
    if (!cont) {
      out.push(open);
      open = undefined;
    }
  });
  if (open) out.push(open);
  return out;
}

type SbomVerdict = { exactPin: boolean; reproducible: boolean; scoped: boolean; found: boolean };
function gradeSbomScript(text: string): SbomVerdict {
  const line = logicalLines(text).find((l) => /^\s*npx\b.*@cyclonedx\/cyclonedx-npm/.test(l.text))?.text;
  if (line === undefined) return { found: false, exactPin: false, reproducible: false, scoped: false };
  return {
    found: true,
    exactPin: /@cyclonedx\/cyclonedx-npm@\d+\.\d+\.\d+(\s|$)/.test(line),
    reproducible: /\s--output-reproducible(\s|$)/.test(line),
    scoped: /\s--omit\s+dev(\s|$)/.test(line) && /\s--package-lock-only(\s|$)/.test(line),
  };
}

// Returns one entry per download that is not digest-checked, and one per pipe into a shell.
function gradeWorkflow(text: string): string[] {
  const problems: string[] = [];
  const all = logicalLines(text);
  const lines = all.map((l) => l.text);
  // A step starts at a "- name:", "- uses:" or "- run:" list item; the digest check must sit in the same step.
  const stepStarts = lines.map((l, i) => (/^\s*-\s+(name|uses|run):/.test(l) ? i : -1)).filter((i) => i >= 0);
  const stepEnd = (i: number): number => stepStarts.find((s) => s > i) ?? lines.length;
  lines.forEach((l, i) => {
    if (/^\s*#/.test(l)) return;
    if (/\b(curl|wget)\b[^|#]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/.test(l)) problems.push(`line ${all[i]?.line}: download piped into a shell`);
    if (!/\b(curl|wget)\b/.test(l)) return;
    const out = l.match(/\s-[A-Za-z]*[oO]\s+"?([^\s"]+)"?/)?.[1];
    if (out === undefined || out === "/dev/null") return;
    const step = lines.slice(i + 1, stepEnd(i)).join("\n");
    if (!/sha256sum\s+(-c|--check)\b/.test(step) || !step.includes(out)) problems.push(`line ${all[i]?.line}: ${out} is downloaded without a sha256sum -c check in the same step`);
  });
  return problems;
}

console.log("-- controls: each check fails on a planted defect and passes a planted fix --");
{
  const good = "npx --yes @cyclonedx/cyclonedx-npm@4.2.1 \\\n  --omit dev \\\n  --output-reproducible \\\n  --package-lock-only\n";
  const g = gradeSbomScript(good);
  ok("CONTROL: an exact pin with --output-reproducible and the scope flags passes", g.found && g.exactPin && g.reproducible && g.scoped);
  ok("CONTROL: a major-only pin (@4) is refused", !gradeSbomScript(good.replace("@4.2.1", "@4")).exactPin);
  ok("CONTROL: an unpinned generator is refused", !gradeSbomScript(good.replace("@4.2.1", "")).exactPin);
  ok("CONTROL: a missing --output-reproducible is refused", !gradeSbomScript(good.replace("  --output-reproducible \\\n", "")).reproducible);
  ok("CONTROL: a missing --omit dev is refused", !gradeSbomScript(good.replace("  --omit dev \\\n", "")).scoped);
  ok("CONTROL: a script with no generator call is refused", !gradeSbomScript("echo none\n").found);
  const dl = '      - name: tool\n        run: |\n          curl -sSfL "https://x/t.tgz" -o /tmp/t.tgz\n';
  ok("CONTROL: a download with no digest check is refused", gradeWorkflow(dl).length === 1);
  ok("CONTROL: a download checked in the same step passes", gradeWorkflow(`${dl}          echo "abc  /tmp/t.tgz" | sha256sum -c -\n`).length === 0);
  ok("CONTROL: a digest check in a LATER step does not count", gradeWorkflow(`${dl}      - name: later\n        run: echo "abc  /tmp/t.tgz" | sha256sum -c -\n`).length === 1);
  ok("CONTROL: curl piped into bash is refused", gradeWorkflow("        run: curl -sSfL https://x/i.sh | bash\n").length === 1);
  ok("CONTROL: a curl that writes only to /dev/null is not a download", gradeWorkflow("        run: curl -sS -o /dev/null https://x\n").length === 0);
}

console.log("\n-- scripts/generate-sbom.sh --");
{
  const v = gradeSbomScript(readFileSync(join(ROOT, "scripts", "generate-sbom.sh"), "utf8"));
  ok("the script runs @cyclonedx/cyclonedx-npm through npx", v.found);
  ok("the generator is pinned to an exact x.y.z version", v.exactPin);
  ok("the generator is run with --output-reproducible (no random serialNumber, no wall-clock timestamp)", v.reproducible);
  ok("the scope stays runtime-only from the lockfile (--omit dev, --package-lock-only)", v.scoped);
}

console.log("\n-- .github/workflows: downloads are digest-checked, nothing is piped into a shell --");
{
  const dir = join(ROOT, ".github", "workflows");
  const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort();
  ok(`there are workflow files to grade (${files.length})`, files.length > 0);
  for (const f of files) {
    const problems = gradeWorkflow(readFileSync(join(dir, f), "utf8"));
    ok(`${f}: every download is digest-checked and none is piped into a shell`, problems.length === 0, problems.join("; "));
  }
}

console.log(failures === 0 ? "\nBUILD TOOL PIN VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
