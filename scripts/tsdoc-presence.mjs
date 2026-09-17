#!/usr/bin/env node

/**
 * TSDoc presence lint. GATING over its declared scope.
 *
 * Reports public exported symbols in the in-scope directories that LACK a
 * preceding TSDoc block. It is a presence heuristic, NOT a TSDoc validator: it
 * checks only that a doc-comment is THERE, never that the @param/@returns/@throws
 * tags are complete or accurate.
 *
 * IN SCOPE (the only directories scanned): src/crypto, src/format, src/dest.
 *
 * WHY THIS SCOPE. Every in-scope export in these three directories carries a doc
 * block, which is what lets this check block rather than merely advise: a
 * permanently red advisory check teaches a reader that red here means nothing.
 *
 * WIDENING, and what it costs. This same heuristic run over all of src finds 3,075
 * further undocumented exports across 336 files, concentrated in admin (1,655 of
 * 1,835), sched (561 of 568), seal (252 of 319) and sources (217 of 224). Widening
 * SCOPE_DIRS to "src" today would make this job red. The criterion, so the next
 * person does not have to guess: widen ONE directory at a time, and only once that
 * directory is already at zero offenders. Raise MIN_FILES and MIN_EXPORTS in the
 * same commit, otherwise the floors below stop being able to tell a widened scope
 * from a broken scanner.
 *
 * THE HEURISTIC (deliberately simple, line-based, no TypeScript parse):
 *   - An in-scope export is a line at column 0 (no leading whitespace) that begins
 *     `export ` and declares a function, class, interface, type or const, i.e.
 *     matches `export [async ]function|class|interface|type|const NAME`.
 *   - A bare re-export (`export { ... }`, `export type { ... } from ...`,
 *     `export * from ...`) declares no new symbol of its own, so it is NOT counted.
 *   - An export is DOCUMENTED when the nearest preceding non-blank line is the close
 *     of a block comment (its trimmed text ends with the comment-close token). A line
 *     `//` comment does NOT count: house style for a documented public export is a
 *     full block doc-comment.
 *
 * Because it is line-based the heuristic can in principle miscount an export wrapped
 * in an unusual way; the three in-scope directories are written so it does not, and
 * the typecheck/lint gates catch anything structural.
 *
 * Usage:  node scripts/tsdoc-presence.mjs
 * Exit:   0 when every in-scope export has a preceding TSDoc block; 1 when any does
 *         not; 2 on a script failure, which includes a scan that read fewer files or
 *         found fewer exports than the floors below (see MIN_FILES / MIN_EXPORTS).
 *         That last case is why the promotion above can be trusted: "zero offenders"
 *         has to mean the scan looked, not that it found nothing to look at.
 */

import { promises as fs } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const SCOPE_DIRS = ["src/crypto", "src/format", "src/dest"];

// A column-0 export that DECLARES a symbol (not a re-export). The capture is the
// declared kind, used only for the offender report.
const DECL_RE = /^export\s+(?:async\s+)?(function|class|interface|type|const|enum|abstract\s+class)\s+([A-Za-z0-9_$]+)/;

// FLOORS. The clean line below ("0 offenders across N exports") is the same sentence whether every
// in-scope export carries a doc block or the scan read nothing at all, and the promotion note above
// makes zero offenders the precondition for turning this job into a gate. So the emptiness has to be
// impossible before that promotion can be honest. Measured over src/crypto, src/format
// and src/dest: 58 files, 394 in-scope exports. The floors sit well under both, so ordinary deletion
// does not trip them, while a renamed scope directory or a DECL_RE that stops matching does.
const MIN_FILES = 25;
const MIN_EXPORTS = 150;

async function listTsFiles(dir) {
  const out = [];
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (err) {
    // Deliberately NOT `return out`. An unreadable or renamed directory used to contribute silently
    // nothing, and a scope that contributes nothing reads exactly like a scope with no offenders.
    throw new Error(`cannot read scope directory ${relative(ROOT, dir)}: ${err.code ?? err.message}`);
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await listTsFiles(p)));
    else if (e.isFile() && p.endsWith(".ts")) out.push(p);
  }
  return out;
}

// precededByBlockComment reports whether the nearest preceding non-blank line ends
// a block comment (its trimmed text ends with "*/"). lines[idx] is the export line.
function precededByBlockComment(lines, idx) {
  for (let i = idx - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (t === "") continue;
    return t.endsWith("*/");
  }
  return false;
}

async function main() {
  const offenders = [];
  let exportCount = 0;

  const files = [];
  for (const d of SCOPE_DIRS) {
    const inDir = await listTsFiles(join(ROOT, d));
    // Per directory, not just in total: two healthy scopes are enough to clear the file floor on their
    // own, so a third that has been moved would otherwise disappear without changing the verdict.
    if (inDir.length === 0) {
      console.error(`tsdoc-presence: scope directory ${d} holds no .ts files. Either it has moved, in which case fix SCOPE_DIRS, or it is gone, in which case say so here rather than scanning what is left.`);
      process.exit(2);
    }
    files.push(...inDir);
  }
  files.sort();

  for (const file of files) {
    const text = await fs.readFile(file, "utf8");
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = DECL_RE.exec(lines[i]);
      if (!m) continue;
      exportCount++;
      if (!precededByBlockComment(lines, i)) {
        offenders.push({ file: relative(ROOT, file), line: i + 1, kind: m[1].replace(/\s+/g, " "), name: m[2] });
      }
    }
  }

  // Checked BEFORE either verdict, so neither the clean line nor an offender list can be printed over a
  // scan that read too little to mean anything. Exit 2 is the script-failure code this file already
  // documents: the gate is reporting that it could not check, which is not the same claim as a pass.
  if (files.length < MIN_FILES) {
    console.error(`tsdoc-presence: scanned ${files.length} files across ${SCOPE_DIRS.join(", ")}, expected at least ${MIN_FILES}.`);
    process.exit(2);
  }
  if (exportCount < MIN_EXPORTS) {
    console.error(`tsdoc-presence: found ${exportCount} in-scope public exports, expected at least ${MIN_EXPORTS}. DECL_RE has stopped matching the way this repo declares exports, so an empty result here says nothing about how many are documented.`);
    process.exit(2);
  }

  if (offenders.length === 0) {
    console.log(`tsdoc-presence: 0 offenders across ${exportCount} in-scope public exports in ${SCOPE_DIRS.join(", ")} (${files.length} files).`);
    process.exit(0);
  }

  console.error(`tsdoc-presence: ${offenders.length} of ${exportCount} in-scope public exports lack a preceding TSDoc block:`);
  for (const o of offenders) {
    console.error(`  ${o.file}:${o.line}  export ${o.kind} ${o.name}`);
  }
  process.exit(1);
}

main().catch((e) => {
  console.error(`tsdoc-presence: script failure: ${e instanceof Error ? e.stack : String(e)}`);
  process.exit(2);
});
