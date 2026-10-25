// A sibling checked out at a release tag is graded against the newest release tag, not against main.
//
// WHY. CI checks the reader out at a v* tag. Before this rule, any commit on the reader's main after that tag
// made requireFreshSiblings refuse with exit 2 (engine nightly 38276133304, 12 Oct: one SECURITY.md commit),
// so the engine went red with nothing it grades having changed. The rule must not lose the useful half of the
// old check: an engine pinned to an OLDER release while a newer one exists is a finding.
//
// Each case builds a real origin and clone under a temp dir and drives requireFreshSiblings with injected
// exit and log, so the cases grade the git reads, not a stub of them.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { releasePin, requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { verdictReached } from "./lib/verdict-guard.ts";

const root = mkdtempSync(path.join(tmpdir(), "downpipes-release-pin-"));
let failed = 0;

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-C", cwd, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" },
  }).trim();
}

let n = 0;
function commit(repo: string, msg: string): void {
  writeFileSync(path.join(repo, "f.txt"), `${msg} ${n++}\n`);
  git(repo, "add", "f.txt");
  git(repo, "commit", "-q", "-m", msg);
}

/** An origin with commits and tags as listed, cloned and checked out at `checkout`. */
function fixture(name: string, steps: Array<{ commit: string; tag?: string }>, checkout: string): string {
  const work = path.join(root, `${name}-work`);
  git(root, "init", "-q", "-b", "main", work);
  for (const s of steps) {
    commit(work, s.commit);
    if (s.tag) git(work, "tag", "-a", "-m", s.tag, s.tag);
  }
  const clone = path.join(root, name);
  git(root, "clone", "-q", work, clone);
  git(clone, "checkout", "-q", "--detach", checkout);
  return clone;
}

function drive(clone: string): { code: number | null; lines: string[] } {
  const lines: string[] = [];
  let code: number | null = null;
  requireFreshSiblings([{ name: "downpipe", path: clone }], {
    gate: "release-pin self-test",
    env: { DOWNPIPES_REQUIRE_SIBLING_FRESHNESS: "1" },
    exit: (c) => {
      code = c;
    },
    log: (m) => lines.push(m),
  });
  return { code, lines };
}

function expect(label: string, got: { code: number | null; lines: string[] }, code: number | null, line: RegExp): void {
  const ok = got.code === code && got.lines.some((l) => line.test(l));
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}: exit ${got.code ?? "none"} (want ${code ?? "none"})`);
  if (!ok) for (const l of got.lines) console.log(`       ${l}`);
}

try {
  // 1. Pinned at the newest tag, main one commit ahead: fresh. This is the 12 Oct case.
  const a = fixture("newest", [{ commit: "a", tag: "v0.3.4" }, { commit: "b", tag: "v0.3.5" }, { commit: "docs" }], "v0.3.5");
  expect("tag pin at newest, main 1 ahead", drive(a), null, /pinned at v0\.3\.5, its newest release tag; the 1 commit/);

  // 2. Pinned at an older tag while a newer one exists: pin bump owed, exit 1, and the hatch does not hide it.
  const b = fixture("older", [{ commit: "a", tag: "v0.3.4" }, { commit: "b", tag: "v0.3.5" }], "v0.3.4");
  expect("tag pin behind a newer tag", drive(b), 1, /downpipe: pinned at v0\.3\.4, newest release tag v0\.3\.5/);
  const hidden: string[] = [];
  let hiddenCode: number | null = null;
  requireFreshSiblings([{ name: "downpipe", path: b }], {
    env: { DOWNPIPES_ALLOW_STALE_SIBLINGS: "downpipe" },
    exit: (c) => {
      hiddenCode = c;
    },
    log: (m) => hidden.push(m),
  });
  expect("hatch does not suppress pin bump owed", { code: hiddenCode, lines: hidden }, 1, /Pin bump owed/);

  // 3. Numeric order, not string order: v0.3.10 is newer than v0.3.9.
  const c = fixture("numeric", [{ commit: "a", tag: "v0.3.9" }, { commit: "b", tag: "v0.3.10" }, { commit: "c" }], "v0.3.9");
  expect("v0.3.9 behind v0.3.10", drive(c), 1, /pinned at v0\.3\.9, newest release tag v0\.3\.10/);
  const pin = releasePin(c);
  if (pin?.newest !== "v0.3.10") {
    failed++;
    console.log(`FAIL releasePin newest: ${JSON.stringify(pin)}`);
  } else console.log("PASS releasePin reads numeric order");

  // 4. Negative control: a non-tag checkout behind main keeps the old refusal, exit 2.
  const d = fixture("untagged", [{ commit: "a", tag: "v0.3.5" }, { commit: "b" }, { commit: "c" }], "HEAD~1");
  expect("untagged checkout 1 behind main", drive(d), 2, /downpipe: 1 commit\(s\) behind origin\/main/);

  // 5. Negative control: a tag that is not a plain X.Y.Z release does not count as a pin.
  const e = fixture("rc", [{ commit: "a", tag: "v0.3.5-rc1" }, { commit: "b" }], "v0.3.5-rc1");
  expect("non-release tag is not a pin", drive(e), 2, /behind origin\/main/);

  // 6. Pinned at a tag with main not ahead: fresh, and no pin line (nothing to explain).
  const f = fixture("level", [{ commit: "a", tag: "v0.3.5" }], "v0.3.5");
  const level = drive(f);
  const levelOk = level.code === null && !level.lines.some((l) => /pinned at/.test(l));
  if (!levelOk) failed++;
  console.log(`${levelOk ? "PASS" : "FAIL"} tag pin level with main: exit ${level.code ?? "none"}, ${level.lines.length} line(s)`);
} finally {
  rmSync(root, { recursive: true, force: true });
}

// THE PIN ITSELF. Every checkout of the reader in this repo's workflows must name ONE release tag, and that
// tag must exist. On 1-4 Oct engine main pinned v0.3.4 before the tag was cut (5 Oct), and the nightly went
// red at checkout with a git fetch error that named no cause.
const workflowsDir = path.join(import.meta.dirname, "..", ".github", "workflows");
const refs = new Set<string>();
for (const f of readdirSync(workflowsDir).filter((x) => /\.ya?ml$/.test(x))) {
  const lines = readFileSync(path.join(workflowsDir, f), "utf8").split("\n");
  lines.forEach((l, i) => {
    if (!/^\s*repository:\s*downpipes-io\/downpipe\s*$/.test(l)) return;
    const ref = lines.slice(i + 1, i + 6).map((x) => /^\s*ref:\s*(\S+)\s*$/.exec(x)?.[1]).find(Boolean);
    refs.add(ref ?? `(no ref at ${f}:${i + 1})`);
  });
}
const pins = [...refs];
const pin0 = pins[0] ?? "";
const pinOk = pins.length === 1 && /^v\d+\.\d+\.\d+$/.test(pin0);
if (!pinOk) failed++;
console.log(`${pinOk ? "PASS" : "FAIL"} workflows pin the reader to one release tag: ${pins.join(", ") || "(no checkout found)"}`);

// The same candidates validate-backcompat-archives.ts reads, so CI (downpipe beside engine) needs no new env.
const HERE = import.meta.dirname;
const downpipeRepo = [
  process.env.DOWNPIPES_DOWNPIPE_ROOT,
  process.env.DOWNPIPES_DOWNPIPE,
  process.env.DOWNPIPE_WORKTREE,
  process.env.DOWNPIPE_REPO,
  path.resolve(HERE, "../downpipe"),
  path.resolve(HERE, "../../downpipe"),
  path.resolve(HERE, "../../../downpipe"),
]
  .filter((c): c is string => typeof c === "string" && c !== "")
  .find((c) => existsSync(path.resolve(c, "cmd/downpipe/main.go")));
if (pinOk && downpipeRepo) {
  let exists = true;
  try {
    execFileSync("git", ["-C", downpipeRepo, "rev-parse", "--verify", "--quiet", `refs/tags/${pin0}^{commit}`], { stdio: "ignore" });
  } catch {
    exists = false;
  }
  if (!exists) failed++;
  console.log(`${exists ? "PASS" : "FAIL"} ${pin0} is a tag in the reader checkout at ${downpipeRepo}`);
} else if (pinOk) {
  const required = process.env.REQUIRE_DOWNPIPE === "1";
  if (required) failed++;
  console.log(`${required ? "FAIL" : "note"} no reader checkout found, so ${pin0} was not checked to exist${required ? " (REQUIRE_DOWNPIPE=1)" : ""}`);
}

verdictReached(failed);
if (failed > 0) {
  console.log(`\nSIBLING RELEASE PIN FAIL (${failed})`);
  process.exit(1);
}
console.log("\nSIBLING RELEASE PIN OK");
