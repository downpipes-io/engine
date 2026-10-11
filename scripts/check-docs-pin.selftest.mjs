#!/usr/bin/env node
// check-docs-pin.selftest: the fixture builder and case runner behind `check-docs-pin.mjs --self-test`.
//
// check-docs-pin.mjs imports this module only for --self-test and hands it its own functions, so the
// two modules never import each other. The fixtures are disposable git repositories under os.tmpdir():
// an "upstream" with main (A - B - C) and a branch `docs-side` off B (D), cloned in full to give
// remote-tracking refs, plus a --depth 1 clone. They are removed when the process exits (see
// scripts/lib/ephemeral-tmp.mjs).

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ephemeralTmpDir } from "./lib/ephemeral-tmp.mjs";

function buildFixture() {
  const dir = ephemeralTmpDir("check-docs-pin-selftest-");
  const up = join(dir, "upstream");
  mkdirSync(up);
  /** @type {(cwd: string, ...args: string[]) => string} */
  const run = (cwd, ...args) => execFileSync("git", args, { cwd, stdio: "pipe" }).toString().trim();
  run(up, "init", "-q", "-b", "main");
  run(up, "config", "user.email", "selftest@example.invalid");
  run(up, "config", "user.name", "check-docs-pin selftest");
  /** @type {(letter: string) => string} */
  const commit = (letter) => {
    writeFileSync(join(up, "f.txt"), letter);
    run(up, "add", "f.txt");
    run(up, "commit", "-q", "-m", letter);
    return run(up, "rev-parse", "HEAD");
  };
  const A = commit("A");
  const B = commit("B");
  run(up, "branch", "docs-side");
  const C = commit("C");
  run(up, "checkout", "-q", "docs-side");
  const D = commit("D");
  run(up, "checkout", "-q", "main");
  const full = join(dir, "full");
  run(dir, "clone", "-q", `file://${up}`, full);
  const shallow = join(dir, "shallow");
  run(dir, "clone", "-q", "--depth", "1", "--branch", "main", `file://${up}`, shallow);
  return { dir, full, shallow, A, B, C, D, unknown: "9".repeat(40) };
}

/**
 * @param {{ parsePin: (t: string) => { ok: boolean }, evaluateDocsPin: (root: string, sha: string) => any, report: (result: any, sha: string, root: string, log: (l: string) => void, err: (l: string) => void) => number }} fns
 * @returns {{ failures: number, checks: number, lines: string[] }}
 */
export function selfTest({ parsePin, evaluateDocsPin, report }) {
  const lines = [];
  let failures = 0;
  let checks = 0;
  /** @type {(name: string, ok: boolean, detail?: string) => void} */
  const check = (name, ok, detail = "") => {
    checks++;
    if (ok) lines.push(`pass ${name}`);
    else {
      failures++;
      lines.push(`FAIL ${name}${detail ? `: ${detail}` : ""}`);
    }
  };

  const f = buildFixture();
  lines.push(`fixture built at ${f.dir} (removed when this process exits)`);

  /** @type {(root: string, sha: string) => { result: any, code: number, out: string[] }} */
  const grade = (root, sha) => {
    /** @type {string[]} */
    const out = [];
    const result = evaluateDocsPin(root, sha);
    const code = report(result, sha, root, (l) => out.push(l), (l) => out.push(l));
    return { result, code, out };
  };

  let g = grade(f.full, f.C);
  check("pin equal to main passes", g.code === 0 && g.result.state === "main", JSON.stringify(g.out));
  g = grade(f.full, f.A);
  check("pin that is an ancestor of main passes", g.code === 0 && g.result.state === "main", JSON.stringify(g.out));

  g = grade(f.full, f.D);
  const offLine = `check-docs-pin: OFF-MAIN docs pin ${f.D.slice(0, 12)} (on branch origin/docs-side); move the pin to docs main in the next landing`;
  check("off-main pushed branch commit passes", g.code === 0 && g.result.state === "off-main", JSON.stringify(g.out));
  check("off-main pass prints the OFF-MAIN line", g.out.includes(offLine), JSON.stringify(g.out));
  check("off-main verdict line says so", g.out.some((l) => l.includes("VERDICT: PASS") && l.includes("OFF-MAIN")), JSON.stringify(g.out));

  g = grade(f.full, f.unknown);
  check("unknown sha is refused", g.code === 1 && g.result.kind === "refused", JSON.stringify(g.out));

  g = grade(join(f.dir, "does-not-exist"), f.C);
  check("missing checkout is could-not-check", g.code === 2 && g.result.kind === "cannot-check", JSON.stringify(g.out));

  g = grade(f.shallow, f.A);
  check("shallow checkout that cannot resolve the pin is could-not-check", g.code === 2 && g.result.kind === "cannot-check", JSON.stringify(g.out));

  check("malformed pin is refused", !parsePin("not-a-sha\n").ok && !parsePin("A".repeat(40)).ok && !parsePin("1".repeat(39)).ok);
  check("pin with trailing newline is read", parsePin(`${f.C}\n`).ok === true);

  return { failures, checks, lines };
}
