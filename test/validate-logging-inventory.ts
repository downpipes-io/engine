// docs/security/logging-inventory.md must still describe the tree it documents.
//
// WHY THIS EXISTS. The inventory is the ASVS V16.1.1 control (what is logged, in what shape, where it goes,
// who reads it, how long it lives) and the V16.2.3 control (the application stores or broadcasts logs only
// to what the inventory names). Both are prose, and prose does not notice when the tree moves: a format
// sentence outlives the logger, an action list falls behind the vocabulary, a line citation drifts onto a
// comment, and a new broadcast sink gains no row. This gate reads the document against the tree so each
// of those is a red member rather than a quiet lie.
//
// WHAT IT GRADES, each against the tree rather than against another sentence of the document:
//   1. the audit action table equals AUDIT_ACTIONS as a set, in both directions, and the stated count
//   2. the Layer 2 call-site count, file count and file list reproduce the grep the document prints
//      (line count, emitter excluded, *.test.ts excluded), and the summary table repeats the same count
//   3. the set of files under src/ with a direct console.(log|error|warn|info|debug)( call on a code
//      line equals the set the document names as direct emitters, and the named lines carry such a call
//   4. every member of PUSH_SINKS appears in the Layer 4 section
//   5. every `identifier` (`path:line`) citation resolves: the file exists, the line exists, and the
//      identifier is on one of the cited lines. A bare (`path:line`) citation is checked for existence
//      only, and the run prints how many of each kind it graded. Citations into the console, the CLI or
//      the control plane are graded when that checkout sits beside the engine; when it does not, the run
//      says how many it could not look at.
//
// NEGATIVE CONTROL ON EVERY RUN. The pure graders are driven over planted fixtures first (a stale count,
// a removed action, a listed file that carries no call, an extra emitter, a missing sink, a citation whose
// identifier is not on its line). If any plant reads clean the run stops red before it grades the tree.
//
// Run: node test/validate-logging-inventory.ts
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AUDIT_ACTIONS } from "../src/admin/audit-types.ts";
import { PUSH_SINKS } from "../src/sched/scheduler-do-limits.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DOC = "docs/security/logging-inventory.md";

/** The emitter itself. The documented command excludes it with `grep -v '^src/log.ts'`. */
const EMITTER = "src/log.ts";

/** The four levels the documented grep alternates over, in its order. */
const LEVELS = ["error", "warn", "info", "debug"];

/** A line counts once however many calls it carries, because the documented command ends in `wc -l`. */
const CALL_LINE = new RegExp(LEVELS.map((l) => `log\\("${l}"`).join("|"));

/** A direct console call on a code line. */
const CONSOLE_CALL = /console\.(log|error|warn|info|debug)\(/;

/** Floors. A source tree or a document that collapsed is a refusal, never a clean run. */
const MIN_SOURCES = 100;
const MIN_CALLS = 50;
const MIN_ACTIONS = 30;

interface SourceFile {
  path: string;
  text: string;
}

interface Citation {
  token: string | undefined;
  path: string;
  from: number;
  to: number;
}

interface DocClaims {
  actions: string[];
  actionCount: number | undefined;
  prose: number | undefined;
  table: number | undefined;
  fileCounts: number[];
  files: string[];
  emitters: { path: string; from: number; to: number }[] | undefined;
  layer4: string | undefined;
  citations: Citation[];
}

interface TreeFacts {
  calls: number;
  files: string[];
  emitters: string[];
  actions: readonly string[];
  sinks: readonly string[];
}

/** Every .ts file under src/ that is not a test, repo-relative. */
function sourceFiles(): string[] {
  const out: string[] = [];
  const walk = (rel: string): void => {
    for (const e of readdirSync(join(ROOT, rel), { withFileTypes: true })) {
      const child = `${rel}/${e.name}`;
      if (e.isDirectory()) walk(child);
      else if (e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts")) out.push(child);
    }
  };
  walk("src");
  return out.sort();
}

/** A comment line: a leading double-slash, a block-comment continuation line, or a block-comment opener. */
function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");
}

/**
 * measureCalls counts the log( call LINES and the files carrying them.
 *
 * @param files - the source files.
 * @returns the line count and the sorted files that contributed.
 */
export function measureCalls(files: SourceFile[]): { calls: number; files: string[] } {
  let calls = 0;
  const hit = new Set<string>();
  for (const { path, text } of files) {
    if (path === EMITTER) continue;
    for (const line of text.split("\n")) {
      if (!CALL_LINE.test(line)) continue;
      calls++;
      hit.add(path);
    }
  }
  return { calls, files: [...hit].sort() };
}

/**
 * measureEmitters lists the files with a direct console.* call on a code line.
 *
 * @param files - the source files.
 * @returns the sorted files.
 */
export function measureEmitters(files: SourceFile[]): string[] {
  const hit = new Set<string>();
  for (const { path, text } of files) {
    for (const line of text.split("\n")) {
      if (isCommentLine(line)) continue;
      if (CONSOLE_CALL.test(line)) hit.add(path);
    }
  }
  return [...hit].sort();
}

const CITE = /(?:`([^`]+)` \()?`((?:src\/|test\/|wrangler\.toml|console\/|downpipe\/|control-plane\/)[^`\s]*?):(\d+)(?:-(\d+))?`/g;

/**
 * readDoc pulls every graded claim out of the document.
 *
 * @param text - the document.
 * @returns the claims, each undefined or empty when it could not be read.
 */
export function readDoc(text: string): DocClaims {
  const flat = text.replace(/\n/g, " ");

  const eventsStart = text.indexOf("### Events recorded");
  const eventsEnd = eventsStart < 0 ? -1 : text.indexOf("\n###", eventsStart + 1);
  const eventsSection = eventsStart < 0 ? "" : text.slice(eventsStart, eventsEnd < 0 ? undefined : eventsEnd);
  const actions = [...eventsSection.matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1] ?? "");
  const countMatch = flat.match(/`AUDIT_ACTIONS` \(`src\/admin\/audit-types\.ts:\d+`\), (\d+) members/);

  const proseMatch = flat.match(/Measured(?: [0-9-]+)?: (\d+)\s*`log\(` call sites across (\d+) files \(([^)]*)\)/);
  const tableMatch = flat.match(/`src\/log\.ts`, (\d+) call sites \/ (\d+) files/);
  const files = proseMatch?.[3] ? [...proseMatch[3].matchAll(/`([^`]+)`/g)].map((m) => m[1] ?? "").sort() : [];

  const emitterLine = text.split("\n").find((l) => l.startsWith("Direct `console.*` emitters:"));
  const emitters = emitterLine
    ? [...emitterLine.matchAll(/`([^`:]+):(\d+)(?:-(\d+))?`/g)].map((m) => ({
        path: m[1] ?? "",
        from: Number(m[2]),
        to: m[3] === undefined ? Number(m[2]) : Number(m[3]),
      }))
    : undefined;

  const l4Start = text.indexOf("## Layer 4");
  const l4End = l4Start < 0 ? -1 : text.indexOf("\n## ", l4Start + 1);
  const layer4 = l4Start < 0 ? undefined : text.slice(l4Start, l4End < 0 ? undefined : l4End);

  const citations: Citation[] = [];
  for (const m of flat.matchAll(CITE)) {
    citations.push({
      token: m[1],
      path: m[2] ?? "",
      from: Number(m[3]),
      to: m[4] === undefined ? Number(m[3]) : Number(m[4]),
    });
  }

  return {
    actions,
    actionCount: countMatch?.[1] === undefined ? undefined : Number(countMatch[1]),
    prose: proseMatch?.[1] === undefined ? undefined : Number(proseMatch[1]),
    table: tableMatch?.[1] === undefined ? undefined : Number(tableMatch[1]),
    fileCounts: [proseMatch?.[2], tableMatch?.[2]].filter((n): n is string => n !== undefined).map(Number),
    files,
    emitters,
    layer4,
    citations,
  };
}

/** Where a cited path lives: the engine tree, or a sibling checkout named by its first path segment. */
export interface CiteRoots {
  engine: string;
  console?: string;
  downpipe?: string;
  "control-plane"?: string;
}

/** A reader over cited files, so the graders stay pure and the self-test can plant a tree. */
export type LineReader = (root: string, rel: string) => string[] | undefined;

/**
 * compare grades the document against the tree.
 *
 * @param doc - what the document claims.
 * @param tree - what the tree has.
 * @param roots - where cited paths resolve; a missing sibling leaves its citations unchecked.
 * @param read - the line reader for citations.
 * @returns the disagreements, and the citation tallies.
 */
export function compare(
  doc: DocClaims,
  tree: TreeFacts,
  roots: CiteRoots,
  read: LineReader,
): { problems: string[]; cited: { withToken: number; bare: number; unchecked: Record<string, number> } } {
  const problems: string[] = [];

  // 1. the audit action table
  if (doc.actions.length === 0) problems.push("the audit action table could not be read, so the action set cannot be graded");
  else {
    const listed = new Set(doc.actions);
    for (const a of tree.actions) if (!listed.has(a)) problems.push(`AUDIT_ACTIONS has ${a} and the action table does not list it`);
    for (const a of doc.actions) if (!tree.actions.includes(a)) problems.push(`the action table lists ${a}, which AUDIT_ACTIONS does not have`);
    if (listed.size !== doc.actions.length) problems.push("the action table lists an action twice");
  }
  if (doc.actionCount === undefined) problems.push("the stated AUDIT_ACTIONS member count could not be read");
  else if (doc.actionCount !== tree.actions.length) problems.push(`the document says AUDIT_ACTIONS has ${doc.actionCount} members; it has ${tree.actions.length}`);

  // 2. the Layer 2 figures
  if (doc.prose === undefined) problems.push("the Layer 2 call-site paragraph could not be read, so the count cannot be graded");
  else if (doc.prose !== tree.calls) problems.push(`the Layer 2 paragraph says ${doc.prose} call sites; the tree has ${tree.calls}`);
  if (doc.table === undefined) problems.push("the summary table's call-site count could not be read, so it cannot be graded");
  else if (doc.table !== tree.calls) problems.push(`the summary table says ${doc.table} call sites; the tree has ${tree.calls}`);
  for (const n of doc.fileCounts) if (n !== tree.files.length) problems.push(`the document says ${n} files; the tree has ${tree.files.length}`);
  if (doc.files.length === 0) problems.push("the Layer 2 file list could not be read, so it cannot be graded");
  else {
    for (const n of doc.fileCounts) if (n !== doc.files.length) problems.push(`the document says ${n} files and enumerates ${doc.files.length}`);
    for (const f of tree.files) if (!doc.files.includes(f)) problems.push(`${f} carries log( call sites and the Layer 2 list does not name it`);
    for (const f of doc.files) if (!tree.files.includes(f)) problems.push(`the Layer 2 list names ${f}, which carries none`);
  }

  // 3. the direct console.* emitters
  if (doc.emitters === undefined || doc.emitters.length === 0) problems.push("the direct emitter line could not be read, so the emitter set cannot be graded");
  else {
    const named = doc.emitters.map((e) => e.path);
    for (const f of tree.emitters) if (!named.includes(f)) problems.push(`${f} calls console.* directly and the document does not name it as an emitter`);
    for (const f of named) if (!tree.emitters.includes(f)) problems.push(`the document names ${f} as a direct emitter and it carries no console.* call`);
    for (const e of doc.emitters) {
      const lines = read(roots.engine, e.path);
      if (lines === undefined) continue; // reported above as an unknown emitter
      const slice = lines.slice(e.from - 1, e.to);
      if (!slice.some((l) => CONSOLE_CALL.test(l) && !isCommentLine(l))) problems.push(`${e.path}:${e.from}${e.to !== e.from ? `-${e.to}` : ""} is cited as an emitter and no console.* call is on those lines`);
    }
  }

  // 4. the sink kinds
  if (doc.layer4 === undefined) problems.push("the Layer 4 section could not be found, so the sink kinds cannot be graded");
  else for (const s of tree.sinks) if (!doc.layer4.includes(`\`${s}\``)) problems.push(`PUSH_SINKS has "${s}" and the Layer 4 section does not name it`);

  // 5. the citations
  const cited = { withToken: 0, bare: 0, unchecked: {} as Record<string, number> };
  for (const c of doc.citations) {
    const seg = c.path.split("/")[0] ?? "";
    const sibling = seg === "console" || seg === "downpipe" || seg === "control-plane" ? seg : undefined;
    const root = sibling === undefined ? roots.engine : roots[sibling];
    const rel = sibling === undefined ? c.path : c.path.slice(seg.length + 1);
    if (root === undefined) {
      cited.unchecked[seg] = (cited.unchecked[seg] ?? 0) + 1;
      continue;
    }
    const lines = read(root, rel);
    const label = `${c.path}:${c.from}${c.to !== c.from ? `-${c.to}` : ""}`;
    if (lines === undefined) {
      problems.push(`${label} is cited and the file does not exist`);
      continue;
    }
    if (c.to > lines.length || c.from < 1 || c.to < c.from) {
      problems.push(`${label} is cited and the file has ${lines.length} lines`);
      continue;
    }
    if (c.token === undefined) {
      cited.bare++;
      continue;
    }
    cited.withToken++;
    const slice = lines.slice(c.from - 1, c.to);
    if (!slice.some((l) => l.includes(c.token as string))) problems.push(`${label} is cited for \`${c.token}\` and that text is not on the cited line(s)`);
  }
  if (doc.citations.length === 0) problems.push("no citations could be read, so nothing was resolved");

  return { problems, cited };
}

/** Reads a file under a root as lines, or undefined when it does not exist. */
function fileLines(root: string, rel: string): string[] | undefined {
  const p = join(root, rel);
  if (!existsSync(p)) return undefined;
  return readFileSync(p, "utf8").split("\n");
}

/** Where a sibling checkout might be, best first: an explicit override, then beside the engine, then beside a worktree's parent. */
function siblingRoot(name: string, marker: string): string | undefined {
  const envKey = `DOWNPIPES_${name.toUpperCase().replace(/-/g, "_")}`;
  const candidates = [process.env[envKey], resolve(ROOT, "..", name), resolve(ROOT, "../..", name), resolve(ROOT, "../../..", name)];
  return candidates.find((c): c is string => typeof c === "string" && c !== "" && existsSync(resolve(c, marker)));
}

// ---- negative control ---------------------------------------------------------------------------

function selfTest(): number {
  let cases = 0;
  let failures = 0;
  const t = (label: string, cond: boolean): void => {
    cases++;
    console.log(`  ${cond ? "ok  " : "FAIL"} plant: ${label}`);
    if (!cond) failures++;
  };

  const files: SourceFile[] = [
    { path: "src/a.ts", text: 'log("error", "x");\nconst q = 1;\n' },
    { path: "src/b.ts", text: 'log("warn", "y"); log("info", "z");\n// console.log("in a comment")\n' },
    { path: "src/log.ts", text: 'export function log() {}\nif (x) console.error(line);\nelse console.log(line);\n' },
    { path: "src/mirror.ts", text: "export function m() {\n  console.log(JSON.stringify(e));\n}\n" },
    { path: "src/c.ts", text: "const nothing = true;\n" },
  ];
  const tree: TreeFacts = {
    calls: measureCalls(files).calls,
    files: measureCalls(files).files,
    emitters: measureEmitters(files),
    actions: ["alpha", "beta"],
    sinks: ["http", "s3"],
  };
  t("the emitter is excluded from the call count and two calls on one line count once", tree.calls === 2 && !tree.files.includes("src/log.ts"));
  t("a console call inside a comment is not an emitter", tree.emitters.join(",") === "src/log.ts,src/mirror.ts");

  const roots: CiteRoots = { engine: "/engine", console: "/console" };
  const planted: Record<string, string> = {
    "/engine/src/a.ts": files[0]!.text,
    "/engine/src/log.ts": files[2]!.text,
    "/engine/src/mirror.ts": files[3]!.text,
    "/engine/src/admin/audit-types.ts": `${"\n".repeat(37)}export const AUDIT_ACTIONS = [];\n`,
    "/console/src/w.ts": "const x = 1;\nlog(\"error\", \"request.unhandled\");\n",
  };
  const read: LineReader = (root, rel) => {
    const v = planted[`${root}/${rel}`];
    return v === undefined ? undefined : v.split("\n");
  };

  const good = [
    "### Events recorded",
    "The closed action set is `AUDIT_ACTIONS` (`src/admin/audit-types.ts:38`), 2 members.",
    "| Action | What |",
    "|---|---|",
    "| `alpha` | one |",
    "| `beta` | two |",
    "",
    "### Next",
    "Direct `console.*` emitters: `src/log.ts:2-3`, `src/mirror.ts:2`.",
    "Measured 2026-09-12: 2 `log(` call sites across 2 files (`src/a.ts`, `src/b.ts`), reproducible with:",
    "`log` (`src/log.ts:1`) and `request.unhandled` (`console/src/w.ts:2`) and (`src/a.ts:2`).",
    "## Layer 4: push",
    "| `http` | `s3` |",
    "## Summary",
    "| `src/log.ts`, 2 call sites / 2 files |",
  ].join("\n");

  const grade = (text: string): string[] => compare(readDoc(text), tree, roots, read).problems;
  const clean = grade(good);
  t(`a document that agrees is clean (${clean.join("; ") || "no findings"})`, clean.length === 0);
  t("a removed action row is a finding", grade(good.replace("| `beta` | two |\n", "")).some((p) => p.includes("AUDIT_ACTIONS has beta")));
  t("an action the constant lacks is a finding", grade(good.replace("| `beta` |", "| `gamma` |")).some((p) => p.includes("lists gamma")));
  t("a stale member count is a finding", grade(good.replace(", 2 members", ", 9 members")).some((p) => p.includes("says AUDIT_ACTIONS has 9")));
  t("a stale prose call count is a finding", grade(good.replace("Measured 2026-09-12: 2", "Measured 2026-09-12: 9")).some((p) => p.includes("Layer 2 paragraph says 9")));
  t("a stale table call count is a finding", grade(good.replace("`src/log.ts`, 2 call sites", "`src/log.ts`, 9 call sites")).some((p) => p.includes("summary table says 9")));
  t("a file carrying call sites that the list omits is a finding", grade(good.replace(", `src/b.ts`", "")).some((p) => p.includes("src/b.ts carries log(")));
  t("a listed file carrying none is a finding", grade(good.replace("`src/b.ts`", "`src/gone.ts`")).some((p) => p.includes("names src/gone.ts")));
  t("an emitter the document does not name is a finding", grade(good.replace(", `src/mirror.ts:2`", "")).some((p) => p.includes("src/mirror.ts calls console.* directly")));
  t("a named emitter line with no console call is a finding", grade(good.replace("`src/mirror.ts:2`", "`src/mirror.ts:1`")).some((p) => p.includes("cited as an emitter")));
  t("a sink kind missing from Layer 4 is a finding", grade(good.replace("| `http` | `s3` |", "| `http` |")).some((p) => p.includes('PUSH_SINKS has "s3"')));
  t("a citation whose identifier is not on the line is a finding", grade(good.replace("`log` (`src/log.ts:1`)", "`log` (`src/log.ts:2`)")).some((p) => p.includes("is cited for `log`")));
  t("a citation past the end of the file is a finding", grade(good.replace("(`src/a.ts:2`)", "(`src/a.ts:9`)")).some((p) => p.includes("src/a.ts:9 is cited")));
  t("a citation into a missing file is a finding", grade(good.replace("(`src/a.ts:2`)", "(`src/zzz.ts:1`)")).some((p) => p.includes("src/zzz.ts:1 is cited and the file does not exist")));
  t("a sibling citation is graded when the sibling is present", grade(good.replace("`request.unhandled` (`console/src/w.ts:2`)", "`request.unhandled` (`console/src/w.ts:1`)")).some((p) => p.includes("console/src/w.ts:1 is cited for")));
  const noSibling = compare(readDoc(good), tree, { engine: "/engine" }, read);
  t("a sibling citation is counted as unchecked when the sibling is absent", noSibling.problems.length === 0 && noSibling.cited.unchecked.console === 1);
  t("an unreadable document refuses rather than passing", grade("nothing here").length > 0);

  console.log(`logging inventory negative control: ${cases - failures} of ${cases} plant(s) behaved.`);
  return failures;
}

// ---- main ---------------------------------------------------------------------------------------

function main(): void {
  const plantFailures = selfTest();
  if (plantFailures > 0) {
    console.error(`FAIL logging-inventory: ${plantFailures} planted defect(s) read clean, so the grader cannot be trusted on the real document.`);
    verdictReached(plantFailures);
    process.exit(1);
  }

  let paths: string[];
  try {
    paths = sourceFiles();
  } catch (err) {
    verdictSkipped(`src/ could not be walked (${err instanceof Error ? err.message : String(err)}), so nothing could be counted`, { require: true });
    process.exit(2);
  }
  if (paths.length < MIN_SOURCES) {
    verdictSkipped(`only ${paths.length} source file(s) under src/, below the floor of ${MIN_SOURCES}; the walk broke`, { require: true });
    process.exit(2);
  }
  const files = paths.map((p) => ({ path: p, text: readFileSync(join(ROOT, p), "utf8") }));
  const calls = measureCalls(files);
  if (calls.calls < MIN_CALLS) {
    verdictSkipped(`only ${calls.calls} call site(s) found, below the floor of ${MIN_CALLS}; the matcher broke rather than the logging going away`, { require: true });
    process.exit(2);
  }
  if (AUDIT_ACTIONS.length < MIN_ACTIONS) {
    verdictSkipped(`AUDIT_ACTIONS has ${AUDIT_ACTIONS.length} member(s), below the floor of ${MIN_ACTIONS}; the import broke`, { require: true });
    process.exit(2);
  }
  let docText: string;
  try {
    docText = readFileSync(join(ROOT, DOC), "utf8");
  } catch {
    verdictSkipped(`${DOC} could not be read, so nothing could be graded`, { require: true });
    process.exit(2);
  }

  const tree: TreeFacts = { calls: calls.calls, files: calls.files, emitters: measureEmitters(files), actions: AUDIT_ACTIONS, sinks: PUSH_SINKS };
  const roots: CiteRoots = { engine: ROOT };
  const consoleRoot = siblingRoot("console", "src/log.ts");
  const cliRoot = siblingRoot("downpipe", "cmd/downpipe/main.go");
  const cpRoot = siblingRoot("control-plane", "src/beacon/receive.ts");
  if (consoleRoot !== undefined) roots.console = consoleRoot;
  if (cliRoot !== undefined) roots.downpipe = cliRoot;
  if (cpRoot !== undefined) roots["control-plane"] = cpRoot;

  const doc = readDoc(docText);
  const { problems, cited } = compare(doc, tree, roots, fileLines);
  console.log(
    `logging inventory: ${tree.calls} log( line(s) across ${tree.files.length} of ${paths.length} source file(s); ${tree.emitters.length} direct emitter file(s); ` +
      `${tree.actions.length} audit action(s); ${tree.sinks.length} sink kind(s); ${cited.withToken} citation(s) graded with their identifier and ${cited.bare} for existence only; ` +
      `${problems.length} disagreement(s).`,
  );
  for (const [seg, n] of Object.entries(cited.unchecked)) {
    console.log(`  NOTE: ${n} citation(s) into ${seg}/ were not graded: no ${seg} checkout beside this engine (set DOWNPIPES_${seg.toUpperCase().replace(/-/g, "_")} to point at one)`);
  }
  for (const p of problems) console.log(`  ${p}`);
  if (problems.length > 0) {
    console.log(`\nUpdate ${DOC} to match the tree above. A figure moving is ordinary; the document and the tree disagreeing in silence is what this refuses.`);
  }
  const checks = doc.actions.length + doc.files.length + (doc.emitters?.length ?? 0) + tree.sinks.length + cited.withToken + cited.bare;
  verdictReached(problems.length, checks);
  process.exit(problems.length === 0 ? 0 : 1);
}

main();
