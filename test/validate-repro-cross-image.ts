// The reproducibility check must fail when the two runner images build different bytes.
//
// THE CLAIM THIS GATE HOLDS. The website trust page says a standing CI check rebuilds the release artefact
// on two runner images and fails on drift. .github/workflows/reproducibility-check.yml runs one matrix leg
// per runner image. Each leg builds twice and fails when its own two builds differ. Until no job
// compared one leg's digest with the other's. The file said cross-image equality was "asserted implicitly":
// both legs printed the digest, and nothing failed when the two digests differed.
//
// WHAT THIS ASSERTS about that workflow:
//   1. One job has a matrix of at least two runner images, and each leg uploads its digest as an artefact
//      named by its image, with if-no-files-found: error.
//   2. A compare job needs that matrix job, downloads every digest artefact, and states EXPECTED_LEGS equal
//      to the number of runner images.
//   3. Neither job can pass or skip without doing its work. No step or job in either job sets
//      continue-on-error, except to false. No step or job in either job has an `if:`, except one that is
//      exactly success(). A step-level continue-on-error lets a mismatch pass. A job-level
//      `if: github.event_name == ...` skips the compare on other events, and GitHub shows a skipped job as
//      green.
//   4. The compare step's own script, run here with bash, exits 0 when the digests agree and exits non-zero
//      when they differ, when a leg's digest is missing, and when a digest is not a sha384 hex string.
// Point 4 runs the exact bytes CI runs, so a compare step that always passes fails here.
//
// Built-in controls plant each refused shape into the workflow and require the same checker to flag it. One
// more control plants an `if: success()`, which the checker must accept.
//
// Run: node test/validate-repro-cross-image.ts [workflow-file]
// The optional argument grades another copy of the workflow, for a negative control against an old file.
//
// FS-WRITES: none outside this repo (the planted digests go to an OS temporary directory, removed after each run)

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictReached } from "./lib/verdict-guard.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = resolve(process.argv[2] ?? resolve(ROOT, ".github/workflows/reproducibility-check.yml"));

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function indentOf(line: string): number {
  return (line.match(/^(\s*)/)?.[1] ?? "").length;
}

/** isCode is false for blank lines and whole-line comments, which never open or close a block. */
function isCode(line: string): boolean {
  const t = line.trim();
  return t !== "" && !t.startsWith("#");
}

/**
 * blockUnder returns the lines nested under the key line at index i: every following line that is blank,
 * a comment, or indented deeper than the key.
 */
function blockUnder(lines: string[], i: number): string[] {
  const keyIndent = indentOf(lines[i] ?? "");
  const out: string[] = [];
  for (let j = i + 1; j < lines.length; j++) {
    const l = lines[j] ?? "";
    if (isCode(l) && indentOf(l) <= keyIndent) break;
    out.push(l);
  }
  return out;
}

interface Step {
  /** start is the absolute index in the workflow's lines of the step's dash line. */
  start: number;
  keyCol: number;
  name: string | undefined;
  continueOnError: string | undefined;
  ifCondition: string | undefined;
  uses: string | undefined;
  withKeys: Map<string, string>;
  run: string | undefined;
}

interface Job {
  id: string;
  /** start is the absolute index of the job's id line; keyIndent is the column of its keys. */
  start: number;
  keyIndent: number;
  lines: string[];
  needs: string[];
  env: Map<string, string>;
  matrixOs: string[];
  continueOnError: string | undefined;
  ifCondition: string | undefined;
  steps: Step[];
}

/**
 * scalar reads `key: value` at the job's own key level, without a trailing comment. It strips one pair of
 * surrounding quotes unless keepQuotes is set; an `if:` keeps its quotes so a message quotes it whole.
 */
function scalar(lines: string[], key: string, indent: number, keepQuotes = false): string | undefined {
  for (const l of lines) {
    if (!isCode(l) || indentOf(l) !== indent) continue;
    const m = l.match(new RegExp(`^\\s*${key}:\\s*(.*?)\\s*(?:#.*)?$`));
    if (m) return keepQuotes ? (m[1] as string) : (m[1] as string).replace(/^["']|["']$/g, "");
  }
  return undefined;
}

function list(value: string): string[] {
  return value
    .replace(/^\[|\]$/g, "")
    .split(",")
    .map((s) => s.trim().replace(/^["']|["']$/g, ""))
    .filter((s) => s !== "");
}

/** parseSteps reads a job's steps; jobStart is the absolute index of the job's id line. */
function parseSteps(jobLines: string[], keyIndent: number, jobStart: number): Step[] {
  const at = jobLines.findIndex((l) => isCode(l) && indentOf(l) === keyIndent && /^\s*steps:\s*$/.test(l));
  if (at < 0) return [];
  const body = blockUnder(jobLines, at);
  const starts: number[] = [];
  const stepIndent = Math.min(...body.filter((l) => /^\s*-\s/.test(l)).map(indentOf));
  body.forEach((l, idx) => {
    if (/^\s*-\s/.test(l) && indentOf(l) === stepIndent) starts.push(idx);
  });
  return starts.map((s, n) => {
    // A step's keys sit two columns right of its dash; the first key shares the dash line.
    const raw = body.slice(s, starts[n + 1] ?? body.length);
    const lines = [(raw[0] ?? "").replace(/-(\s)/, " $1"), ...raw.slice(1)];
    const keyCol = stepIndent + 2;
    const withKeys = new Map<string, string>();
    const withAt = lines.findIndex((l) => indentOf(l) === keyCol && /^\s*with:/.test(l));
    if (withAt >= 0) {
      const flow = (lines[withAt] ?? "").match(/with:\s*\{([^}]*)\}/)?.[1];
      const pairs = flow !== undefined ? flow.split(",") : blockUnder(lines, withAt).filter(isCode);
      for (const p of pairs) {
        const m = p.match(/^\s*([\w-]+)\s*:\s*(.*?)\s*$/);
        if (m) withKeys.set(m[1] as string, (m[2] as string).replace(/\s+#.*$/, ""));
      }
    }
    let run: string | undefined;
    const runAt = lines.findIndex((l) => indentOf(l) === keyCol && /^\s*run:/.test(l));
    if (runAt >= 0) {
      const inline = (lines[runAt] ?? "").match(/^\s*run:\s*(.*)$/)?.[1] ?? "";
      if (/^[|>]/.test(inline)) {
        const block = blockUnder(lines, runAt);
        const nonBlank = block.filter((l) => l.trim() !== "");
        const cut = nonBlank.length > 0 ? Math.min(...nonBlank.map(indentOf)) : 0;
        run = block.map((l) => l.slice(cut)).join("\n");
      } else {
        run = inline;
      }
    }
    return {
      // jobLines[k] is line jobStart + 1 + k, and body[k] is jobLines[at + 1 + k].
      start: jobStart + 1 + at + 1 + s,
      keyCol,
      name: scalar(lines, "name", keyCol),
      continueOnError: scalar(lines, "continue-on-error", keyCol),
      ifCondition: scalar(lines, "if", keyCol, true),
      uses: scalar(lines, "uses", keyCol)?.replace(/\s+#.*$/, ""),
      withKeys,
      run,
    };
  });
}

/** parseJobs reads every job under the top-level `jobs:` key. */
export function parseJobs(yaml: string): Job[] {
  const lines = yaml.split("\n");
  const at = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (at < 0) return [];
  const body = blockUnder(lines, at);
  const idIndent = Math.min(...body.filter(isCode).map(indentOf));
  const jobs: Job[] = [];
  body.forEach((l, idx) => {
    if (!isCode(l) || indentOf(l) !== idIndent) return;
    const id = l.trim().replace(/:\s*$/, "");
    const jobLines = blockUnder(body, idx);
    const keyIndent = Math.min(...jobLines.filter(isCode).map(indentOf));
    let needs: string[] = [];
    const needsAt = jobLines.findIndex((x) => isCode(x) && indentOf(x) === keyIndent && /^\s*needs:/.test(x));
    if (needsAt >= 0) {
      const inline = scalar([jobLines[needsAt] as string], "needs", keyIndent) ?? "";
      needs =
        inline !== ""
          ? list(inline)
          : blockUnder(jobLines, needsAt)
              .filter(isCode)
              .map((x) => x.trim().replace(/^-\s*/, ""));
    }
    const env = new Map<string, string>();
    const envAt = jobLines.findIndex((x) => isCode(x) && indentOf(x) === keyIndent && /^\s*env:\s*$/.test(x));
    if (envAt >= 0) {
      for (const e of blockUnder(jobLines, envAt).filter(isCode)) {
        const m = e.match(/^\s*([\w-]+)\s*:\s*(.*?)\s*(?:#.*)?$/);
        if (m) env.set(m[1] as string, (m[2] as string).replace(/^["']|["']$/g, ""));
      }
    }
    const osLine = jobLines.find((x) => isCode(x) && /^\s*os:\s*\[/.test(x));
    jobs.push({
      id,
      // body[k] is line at + 1 + k.
      start: at + 1 + idx,
      keyIndent,
      lines: jobLines,
      needs,
      env,
      matrixOs: osLine !== undefined ? list(osLine.replace(/^\s*os:\s*/, "")) : [],
      continueOnError: scalar(jobLines, "continue-on-error", keyIndent),
      ifCondition: scalar(jobLines, "if", keyIndent, true),
      steps: parseSteps(jobLines, keyIndent, at + 1 + idx),
    });
  });
  return jobs;
}

/** runCompare runs a compare script over planted digest files and returns its exit status. */
function runCompare(script: string, expectedLegs: string, digests: Record<string, string>): number {
  const temp = mkdtempSync(join(tmpdir(), "repro-cross-image-"));
  try {
    const dir = join(temp, "digests");
    mkdirSync(dir, { recursive: true });
    for (const [os, d] of Object.entries(digests)) writeFileSync(join(dir, `${os}.sha384`), `${d}\n`);
    const r = spawnSync("bash", ["-c", script], {
      env: { PATH: process.env.PATH ?? "", RUNNER_TEMP: temp, EXPECTED_LEGS: expectedLegs },
      encoding: "utf8",
    });
    return r.status ?? 128;
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

const DIGEST_A = "a".repeat(96);
// Workflow expressions are built from parts so this file is not itself read as a template placeholder.
const EXPR_OPEN = `${"$"}{{`;
const MATRIX_OS = `${EXPR_OPEN} matrix.os }}`;
const DIGEST_B = `${"a".repeat(95)}b`;

/** onlySuccess is true for an `if:` that runs the step or job only when everything before it passed. */
function onlySuccess(cond: string): boolean {
  return /^(\$\{\{\s*)?success\(\)(\s*\}\})?$/.test(cond.trim());
}

/**
 * skipOrPass returns every key in one job that lets it pass or skip without doing its work: a
 * continue-on-error other than false, and an `if:` other than success(), at job level or on any step.
 */
function skipOrPass(job: Job): string[] {
  const out: string[] = [];
  const where = (s: Step): string => `${job.id}, step "${s.name ?? s.uses ?? "unnamed"}"`;
  if (job.continueOnError !== undefined && job.continueOnError !== "false")
    out.push(`${job.id}: continue-on-error: ${job.continueOnError} lets the job pass when it fails`);
  if (job.ifCondition !== undefined && !onlySuccess(job.ifCondition))
    out.push(`${job.id}: if: ${job.ifCondition} can skip the job, and a skipped job shows as green`);
  for (const s of job.steps) {
    if (s.continueOnError !== undefined && s.continueOnError !== "false")
      out.push(`${where(s)}: continue-on-error: ${s.continueOnError} lets the step pass when it fails`);
    if (s.ifCondition !== undefined && !onlySuccess(s.ifCondition))
      out.push(`${where(s)}: if: ${s.ifCondition} can skip the step`);
  }
  return out;
}

/** findings grades one workflow's text and returns every reason it fails; an empty list is a pass. */
export function findings(yaml: string, probeScript: boolean): string[] {
  const out: string[] = [];
  const jobs = parseJobs(yaml);
  const matrix = jobs.find((j) => j.matrixOs.length > 0);
  if (matrix === undefined) return ["no job has a runner-image matrix (os: [...])"];
  const legs = matrix.matrixOs;
  if (legs.length < 2) out.push(`${matrix.id}: matrix names ${legs.length} runner image(s); a cross-image claim needs two`);
  const upload = matrix.steps.find((s) => /^actions\/upload-artifact@/.test(s.uses ?? ""));
  const uploadName = upload?.withKeys.get("name") ?? "";
  if (upload === undefined) out.push(`${matrix.id}: no leg uploads its digest (no actions/upload-artifact step)`);
  else {
    if (!uploadName.includes(MATRIX_OS))
      out.push(`${matrix.id}: the digest artefact name (${uploadName}) is not per runner image, so the legs overwrite each other`);
    if (upload.withKeys.get("if-no-files-found") !== "error")
      out.push(`${matrix.id}: the digest upload does not set if-no-files-found: error, so a missing digest uploads nothing and passes`);
  }
  const prefix = uploadName.split(EXPR_OPEN)[0] ?? "";
  const compare = jobs.find(
    (j) => j !== matrix && j.steps.some((s) => /^actions\/download-artifact@/.test(s.uses ?? "")),
  );
  if (compare === undefined) {
    out.push("no compare job: no job downloads the per-image digests");
    return out;
  }
  if (!compare.needs.includes(matrix.id))
    out.push(`${compare.id}: needs [${compare.needs.join(", ")}], not ${matrix.id}, so it can run before both legs finish`);
  for (const job of [matrix, compare]) out.push(...skipOrPass(job));
  const download = compare.steps.find((s) => /^actions\/download-artifact@/.test(s.uses ?? ""));
  const pattern = download?.withKeys.get("pattern") ?? "";
  if (prefix === "" || pattern !== `${prefix}*`)
    out.push(`${compare.id}: downloads pattern "${pattern}", which does not match every "${prefix}<image>" artefact`);
  if (download?.withKeys.get("merge-multiple") !== "true")
    out.push(`${compare.id}: download does not set merge-multiple: true, so the digests land in separate folders`);
  const expected = compare.env.get("EXPECTED_LEGS");
  if (expected !== String(legs.length))
    out.push(`${compare.id}: EXPECTED_LEGS is ${expected ?? "unset"}, but the matrix has ${legs.length} runner images`);
  const script = compare.steps.find((s) => s.run?.includes("RUNNER_TEMP"))?.run;
  if (script === undefined) {
    out.push(`${compare.id}: no step reads the downloaded digests`);
    return out;
  }
  if (script.includes(EXPR_OPEN)) out.push(`${compare.id}: the compare script uses a workflow expression, so this gate cannot run it as CI does`);
  else if (probeScript) {
    const same = Object.fromEntries(legs.map((os) => [os, DIGEST_A]));
    const differ = Object.fromEntries(legs.map((os, n) => [os, n === 0 ? DIGEST_B : DIGEST_A]));
    const missing = Object.fromEntries(legs.slice(1).map((os) => [os, DIGEST_A]));
    const malformed = Object.fromEntries(legs.map((os) => [os, "not-a-digest"]));
    const e = String(legs.length);
    if (runCompare(script, e, same) !== 0) out.push(`${compare.id}: the compare script fails when every image agrees`);
    if (runCompare(script, e, differ) === 0) out.push(`${compare.id}: the compare script passes when the images differ`);
    if (runCompare(script, e, missing) === 0) out.push(`${compare.id}: the compare script passes when one image's digest is missing`);
    if (runCompare(script, e, malformed) === 0) out.push(`${compare.id}: the compare script passes digests that are not sha384 hex`);
  }
  return out;
}

const yaml = readFileSync(WORKFLOW, "utf8");
console.log(`Workflow: ${WORKFLOW}`);

// CONTROLS: the shapes this gate exists to refuse must be refused by the same checker.
console.log("Controls:");
const lines = yaml.split("\n");
/** plant inserts one line after absolute line index `after`, indented to column `col`. */
function plant(after: number, col: number, text: string): string {
  return [...lines.slice(0, after + 1), `${" ".repeat(col)}${text}`, ...lines.slice(after + 1)].join("\n");
}
const parsed = parseJobs(yaml);
const matrixJob = parsed.find((j) => j.matrixOs.length > 0);
const compareJob = parsed.find((j) => j.steps.some((s) => /^actions\/download-artifact@/.test(s.uses ?? "")));
const compareStep = compareJob?.steps.find((s) => s.run?.includes("RUNNER_TEMP"));
if (compareJob !== undefined && matrixJob !== undefined && compareStep !== undefined) {
  const start = lines.findIndex((l) => new RegExp(`^\\s{2}${compareJob.id}:\\s*$`).test(l));
  const withoutCompare = [...lines.slice(0, start), ...lines.slice(start + 1 + compareJob.lines.length)].join("\n");
  ok("CONTROL: the workflow with its compare job removed is flagged", findings(withoutCompare, false).some((f) => f.startsWith("no compare job")));
  const wrongNeeds = yaml.replace(/^(\s*needs:\s*).*$/m, "$1[lint]");
  ok("CONTROL: a compare job that does not need the matrix job is flagged", findings(wrongNeeds, false).some((f) => f.includes("needs [lint]")));
  const alwaysPass = yaml.replace(/(\n\s*)exit 1\n/g, "$1true\n");
  ok("CONTROL: a compare script with every exit 1 removed is flagged", findings(alwaysPass, true).some((f) => f.includes("passes when the images differ")));
  const stepCoe = plant(compareStep.start, compareStep.keyCol, "continue-on-error: true");
  ok(
    "CONTROL: continue-on-error on the compare step is flagged",
    findings(stepCoe, false).some((f) => f.includes(`step "${compareStep.name}": continue-on-error`)),
  );
  const stepIf = plant(compareStep.start, compareStep.keyCol, "if: github.event_name != 'pull_request'");
  ok("CONTROL: an if: on the compare step is flagged", findings(stepIf, false).some((f) => f.includes(`step "${compareStep.name}": if:`)));
  const jobIf = plant(compareJob.start, compareJob.keyIndent, "if: github.event_name == 'workflow_dispatch'");
  ok(
    "CONTROL: a job-level if: that skips the compare on push, pull request and schedule runs is flagged",
    findings(jobIf, false).some((f) => f.startsWith(`${compareJob.id}: if: github.event_name`)),
  );
  const matrixCoe = plant(matrixJob.start, matrixJob.keyIndent, "continue-on-error: true");
  ok(
    "CONTROL: continue-on-error on the matrix job is flagged",
    findings(matrixCoe, false).some((f) => f.startsWith(`${matrixJob.id}: continue-on-error`)),
  );
  const successIf = plant(compareJob.start, compareJob.keyIndent, `if: ${EXPR_OPEN} success() }}`);
  ok("CONTROL: an if: success() on the compare job is accepted", findings(successIf, false).length === 0);
} else {
  ok("CONTROL: a matrix job, a compare job and its compare step exist to build the controls from", false);
}

console.log("Workflow:");
const found = findings(yaml, true);
for (const msg of found) console.log(`       ${msg}`);
const jobs = parseJobs(yaml);
ok(`parsed jobs (${jobs.map((j) => j.id).join(", ")})`, jobs.length > 0);
ok("a compare job needs the matrix job, and fails on a digest mismatch between runner images", found.length === 0);

console.log(failures === 0 ? "\nREPRO CROSS-IMAGE PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
