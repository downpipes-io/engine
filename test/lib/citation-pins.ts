// citation-pins: pin a document's file:line citations to the text they cite, not only to a non-blank line.
//
// WHY THIS EXISTS. A doc validator that checks a cited line only for existence passes when a code move
// slides the citation onto a different, still non-blank line. The citation then names the wrong code and
// no gate is red. A pins file records, for every citation, the collapsed text of the cited lines when the
// citation was last reviewed. A later run compares the cited lines with that text.
//
// THE RULES, the same in every validator that uses this file:
//   - a citation whose cited text differs from its pin is a failure, printed with the expected and found text;
//   - a citation with no pin is a failure, so a new citation must be reviewed and pinned;
//   - a pin that no citation uses is a failure (an orphan), so a removed citation cannot leave a stale pass;
//   - `--write-pins` writes the pins file from the current trees. Review the citations first: a wrong
//     citation is pinned as right.
//
// SIBLINGS. A sibling repo is found from `git rev-parse --git-common-dir`, so a linked worktree finds the
// same siblings as the main checkout. A sibling file is read at the sibling's own origin/main, never from
// its working tree, which other work may have left mid-edit or behind. A missing sibling, or one with no
// origin/main ref, is CANNOT CHECK (exit 2), never a pass.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

/** collapse turns cited lines into one comparable string: whitespace runs become one space. */
export function collapse(lines: readonly string[]): string {
  return lines
    .map((l) => l.replace(/\s+/g, " ").trim())
    .join(" | ")
    .trim();
}

/** One citation as found in a document, with the text it cites now (null when it cannot be read). */
export interface CitedText {
  key: string;
  found: string | null;
}

/**
 * gradePins compares the cited text of every citation with its pin.
 *
 * @param pins - the recorded pins, keyed by citation.
 * @param cited - every citation in the document, with the text it cites now.
 * @returns one problem string per mismatch, missing pin, unreadable citation and orphan pin.
 */
export function gradePins(pins: Readonly<Record<string, string>>, cited: readonly CitedText[]): string[] {
  const problems: string[] = [];
  const used = new Set<string>();
  for (const c of cited) {
    used.add(c.key);
    const pin = pins[c.key];
    if (c.found === null) {
      problems.push(`${c.key} cannot be read, so its content cannot be compared with its pin`);
      continue;
    }
    if (pin === undefined) {
      problems.push(`${c.key} has no pin. Review the citation, then run with --write-pins. It reads: ${JSON.stringify(c.found.slice(0, 200))}`);
      continue;
    }
    if (pin !== c.found) problems.push(`${c.key} no longer reads its pinned text.\n         expected: ${JSON.stringify(pin.slice(0, 300))}\n         found:    ${JSON.stringify(c.found.slice(0, 300))}`);
  }
  for (const key of Object.keys(pins)) {
    if (!used.has(key)) problems.push(`the pin for ${key} is an orphan: no citation in the document uses it`);
  }
  return problems;
}

/**
 * pinsFrom builds a pins object from the cited texts, keys sorted, ready to write.
 *
 * @param cited - every citation in the document, with the text it cites now.
 * @returns the pins; a citation that cannot be read is left out, so it stays a failure.
 */
export function pinsFrom(cited: readonly CitedText[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of [...cited].sort((a, b) => a.key.localeCompare(b.key))) {
    if (c.found !== null) out[c.key] = c.found;
  }
  return out;
}

/**
 * readPins reads a pins file.
 *
 * @param path - the absolute path of the pins file.
 * @returns the pins, or null when the file is absent or is not a JSON object of strings.
 */
export function readPins(path: string): Record<string, string> | null {
  if (!existsSync(path)) return null;
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    for (const v of Object.values(parsed)) if (typeof v !== "string") return null;
    return parsed as Record<string, string>;
  } catch {
    return null;
  }
}

/**
 * writePins writes a pins file with one key per line, so a review diff shows one citation per line.
 *
 * @param path - the absolute path of the pins file.
 * @param pins - the pins to write.
 */
export function writePins(path: string, pins: Readonly<Record<string, string>>): void {
  writeFileSync(path, `${JSON.stringify(pins, null, 2)}\n`);
}

/**
 * workspaceRoot finds the folder that holds the engine and its sibling repos, from git-common-dir.
 *
 * @param engineRoot - the engine checkout or linked worktree this validator runs in.
 * @returns the folder above the MAIN engine checkout.
 */
export function workspaceRoot(engineRoot: string): string {
  try {
    const out = execFileSync("git", ["rev-parse", "--git-common-dir"], { cwd: engineRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    if (out !== "") return resolve(engineRoot, out, "..", "..");
  } catch {
    // Not a git checkout: fall back to the folder above this tree.
  }
  return resolve(engineRoot, "..");
}

/**
 * findSibling finds a sibling checkout by an override variable, then beside the main engine checkout.
 *
 * @param engineRoot - the engine checkout or linked worktree this validator runs in.
 * @param name - the sibling folder name, for example "console".
 * @param marker - a file that must exist in the sibling, so a wrong folder is not taken for it.
 * @param envKeys - override variables, checked first.
 * @returns the sibling root, or null when no candidate holds the marker.
 */
export function findSibling(engineRoot: string, name: string, marker: string, envKeys: readonly string[]): string | null {
  const candidates = [...envKeys.map((k) => process.env[k]), resolve(workspaceRoot(engineRoot), name), resolve(engineRoot, "..", name)];
  return candidates.find((c): c is string => typeof c === "string" && c !== "" && existsSync(resolve(c, marker))) ?? null;
}

/**
 * hasOriginMain says whether a checkout has an origin/main ref to read.
 *
 * @param root - the checkout.
 * @returns true when origin/main resolves.
 */
export function hasOriginMain(root: string): boolean {
  try {
    execFileSync("git", ["-C", root, "rev-parse", "--verify", "--quiet", "origin/main"], { stdio: ["ignore", "ignore", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

/**
 * readAtOriginMain reads one file of a sibling at its origin/main.
 *
 * @param root - the sibling checkout.
 * @param rel - the repo-relative path.
 * @returns the file's lines, or undefined when origin/main has no such file.
 */
export function readAtOriginMain(root: string, rel: string): string[] | undefined {
  try {
    return execFileSync("git", ["-C", root, "show", `origin/main:${rel}`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] }).split("\n");
  } catch {
    return undefined;
  }
}
