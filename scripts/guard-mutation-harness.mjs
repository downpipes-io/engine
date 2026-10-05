#!/usr/bin/env node
// GUARD MUTATION HARNESS: measure which safety call sites are held by a gate and which are held by nothing.
//
// WHY THIS IS LANDED RATHER THAN LEFT IN A SCRATCH BED. Four passes have now built this. `the first attempt` wrote one,
// `the second attempt` rebuilt it with the signature-identical shim, `the third attempt` died rebuilding it and landed nothing,
// and `the fourth attempt` rebuilt it a fourth time. Measured across the campaign: 1,314 scripts written in scratch
// beds, 48 landed, about 3.5 per cent survival. THE ARMS ARE MEANT TO BE DISCARDED; THE HARNESS THAT
// PRODUCES THEM IS NOT. Every rebuild has had to rediscover the same preconditions the hard way, so
// they are built in here rather than left to the next pass's memory.
//
// THE QUESTION IT ANSWERS, from `the originating pass`: for every repair, is the set of sites the FIX touches equal to the
// set of sites the GATE drives. Where it is not, the remainder is a defect with a return address, held
// together by nothing but the author's care. Measured so far: 12 of 35, then 16 of 38.
//
// ------------------------------------------------------------------------------------------------------
// THE EIGHT PRECONDITIONS, EACH PAID FOR BY A PASS
// ------------------------------------------------------------------------------------------------------
//
// 1. THE INERTNESS PROOF. A choice-of-function guard is mutated by swapping the call to a signature-
//    identical TWIN that drops exactly one property, which needs the twin declared and imported. That
//    scaffolding must be applied with NOTHING referencing it and every member must still exit 0 first.
//    Without it, no per-arm red is attributable to the arm rather than to the scaffolding.
//
// 2. THE PARSE CHECK, WITH A KNOWN NEGATIVE. A mutation that does not compile proves nothing, and a parser
//    rig that cannot fail proves less. `proveParserLive` feeds it a deliberate syntax error first and
//    refuses to run if that parses clean.
//
// 3. BYTE-IDENTICAL RESTORE, VERIFIED BY SHA256, AFTER EVERY ARM, plus a clean `git status`. Pristine bytes
//    come from the HEAD BLOB, never from the working file: a run started while a previous one had left the
//    tree mutated would otherwise capture the MUTATION as pristine and restore to it forever after.
//
// 4. WORK IS COUNTED AS ENTRIES EXAMINED, NEVER AS ENTRIES THAT AGREED. A gate shipped this week whose
//    first live red printed "declared a verdict after doing 0 units of work" and had its finding forced
//    through unread, because it counted agreement as work. This harness refuses to print a verdict when
//    zero arms were examined, and it reports examined counts beside outcome counts always.
//
// 5. EXIT CODES ARE READ FROM A FILE, NEVER FROM A PIPE, and a REFUSAL IS NOT A PASS. A member that exits 4
//    could not check; `the second attempt` nearly counted one as "found nothing" while its log read NOT-REACHED, which
//    would have cost it a site. Refusals are reported in their own column and never folded into survivors.
//
// 6. AN ARM THAT COMPILES AND CHANGES BYTES CAN STILL CHANGE NOTHING, AND IT WAS RECORDED AS SURVIVED.
//    This is the newest precondition and it is the one that inflates findings in the campaign's own
//    preferred direction, which is why it is worth the machinery. `SURVIVED (held by nothing)` was printed
//    whenever no member went red, and no check asked whether the arm had done anything at all. All three
//    arm kinds can be silently inert: a `discard-verdict` at a site whose verdict was ALREADY unconsumed
//    discards nothing; a `delete-arg` whose argument the callee ignores on that path deletes nothing that
//    matters; a `swap` to a twin dropping a property nothing reads on that path drops nothing. In every
//    case the tree changes, it parses, no member fails, and the harness reports a site "held by nothing"
//    when in truth the site was never tested.
//
//    MEASURED, and by this harness's own author-pass rather than in the abstract: another pass planted
//    `if (!key.startsWith("seg/"))` on the run-tree copy loop in src/seal/replicate.ts, watched five
//    validators stay green, and was one paragraph away from reporting that the replica's segment copying
//    was held by nothing. The loop copies `run/<id>/...` keys. NO KEY THERE EVER STARTS WITH `seg/`, so the
//    arm was a no-op and the five greens meant nothing. The real mutation at the real site reddens two
//    validators immediately.
//
//    HOW LIVENESS IS DECIDED HERE, WITHOUT A PER-ARM ANNOTATION AND WITHOUT TRUSTING NONDETERMINISM. The
//    baseline runs every member TWICE on the pristine tree and keeps only the lines that agree across both
//    runs: that self-calibrates away timings, random ids and per-run digests, in the same spirit as a
//    known-positive control. An arm that survives is then compared on those STABLE lines only. If not one
//    member's stable output moved, the arm changed nothing this member set can observe, and the verdict is
//    INERT-OR-UNOBSERVED, which is a COULD-NOT-CHECK and NOT a survivor. If some member's stable output DID
//    move and still nothing went red, the arm is genuinely live and genuinely unguarded, which is the
//    finding SURVIVED was always meant to be.
//
//    The direction of the failure mode matters: nondeterminism that defeats the stable-line intersection
//    makes an arm look LIVE, never INERT, so this can only withhold a finding it cannot substantiate and
//    can never manufacture one.
//
// 7. A SITE NOTHING EXECUTES CANNOT BE JUDGED BY MUTATING IT, AND A LINE NUMBER IS NOT AN ADDRESS.
//    Precondition 6 turned "no member went red" into `INERT-OR-UNOBSERVED`, which was the right call and
//    is not the whole answer, because that verdict covers TWO states with DIFFERENT repairs: the site ran
//    and nothing observed it, or the site never ran at all. `reach` mode separates them with node's own
//    NODE_V8_COVERAGE on the PRISTINE tree, and `sitesOfSpec` collapses arms that share a call so a site
//    is not counted twice.
//
//    MEASURED over `the fourth attempt`'s corpus, 39 distinct sites against 425 members: EVERY SITE IS EXECUTED by
//    at least one member, from `cron/reconcile-pass.ts:297` at ONE to `cron/siem-push-pass.ts:203` at 115.
//    So on this corpus the answer is "ran and nothing observed it" every time, and no site is dead. That
//    is worth knowing precisely because it was NOT the expected answer.
//
//    THE OTHER HALF IS DRIFT, AND IT IS A DIFFERENT DISEASE FROM AN INERT ARM. An inert arm ran at the
//    right place and changed nothing. A DRIFTED arm never reached the place. Both end in "no member went
//    red". Re-running this corpus ONE DAY after it landed found three arms off their recorded line. See
//    `resolveIdx`, and put an `anchor` on every arm in a spec meant to outlive the week it was written.
//
//    AND THE LIVENESS TEST IS ASYMMETRIC, WHICH IS DELIBERATE BUT MUST BE SAID. `armMovedStableOutput`
//    reports movement when a baseline line DISAPPEARS or CHANGES, and NOT when the arm merely ADDS output,
//    because a line absent from the baseline is exactly what a nondeterministic line looks like and
//    counting it would manufacture liveness. An arm whose only effect is extra output therefore reads as
//    INERT-OR-UNOBSERVED. That is the safe direction, and it is a reason the verdict is a could-not-check
//    rather than a finding either way.
//
// 8. A MEMBER THAT REDS ON ITS OWN MANUFACTURES A KILL, AND A KILL IS A CONFIDENT GREEN IN THE LEDGER.
//    Precondition 6 already runs every member TWICE on the pristine tree. It compared their LINES and threw
//    away their EXIT CODES, so a member that passed once and failed once was folded into the stable-line
//    intersection and never named. That is the one input this harness cannot absorb, because the damage
//    runs in the direction it trusts most: a site is recorded as HELD when some member goes red under the
//    plant, so a self-inflicted red credits a guard that may not exist and the site is never re-opened.
//    Unlike a noisy red, nobody investigates it.
//
//    MEASURED. test/validate-passkey.ts failed 1 run in 240 on a pristine tree at 4397fd69 and was the SOLE
//    KILLER of arm B7 in the fourth attempt's re-run, turning a could-not-check into a KILLED. The cause was a
//    product ordering defect, not a test defect: the passkey witness epoch was opened AFTER the credential's
//    createdAt had been taken from the clock, so a millisecond tick between the two reads made a brand-new
//    credential read as older than the record-keeping.
//
//    So the two runs must now AGREE ON THEIR EXIT CODE, which costs nothing because both were already being
//    made, and a disagreement REFUSES the whole run rather than dropping the member. Dropping it silently
//    converts the arms it would have killed into could-not-checks of a different kind while the run still
//    publishes a split. TWO RUNS CANNOT SEE A RARE FLAKE: this catches the frequent ones, and
//    scripts/determinism-gate.mjs is the instrument for measuring a rate over many runs.
//
// AND ONE MORE, FROM A GATE THAT SHIPPED ITS OWN SUBJECT: WALK THE TREE, NEVER HAND-KEEP A LIST OF FILES.
// `the second attempt`'s validator asserted "SEVEN call sites in all" while summing a hand-kept list of four files,
// and the repair landing beside it added a fifth. `discoverSites` below walks src/ for exactly that reason.
//
// ------------------------------------------------------------------------------------------------------
// INTERFACE
// ------------------------------------------------------------------------------------------------------
//
//   node scripts/guard-mutation-harness.mjs <spec.json> <mode> [options]
//
//   modes
//     discover   print every call site of each family named in the spec, as arm stubs, so the spec can be
//                filled from the TREE rather than from a reader's memory
//     parse      prove the parser rig live, then parse pristine, scaffolded, and every arm alone
//     inert      apply the scaffolding ONLY and run --members: every one must exit 0
//     grand      apply EVERY arm at once; run --members if given, else leave the tree mutated for an
//                external full-chain run (that run yields the SUPERSET of members that can hold anything)
//     sites      each arm alone, serially, against --members; prints KILLED / SURVIVED / REFUSED-ONLY /
//                INERT-OR-UNOBSERVED
//     reach      run --members on the PRISTINE tree under NODE_V8_COVERAGE and report, per site, how many
//                members EXECUTE it: a site nothing runs cannot be judged by mutating it
//     restore    put the tree back and verify it
//
//   options
//     --members <file>   one shell command per line (e.g. `node test/validate-reader.ts`)
//     --only A1,A2       run a subset of arms
//     --out <file>       JSONL results (default <spec>.results.jsonl)
//
//   SPEC SHAPE
//     {
//       "root": "/path/to/an/engine/worktree",
//       "srcDir": "src",                                  // optional, defaults to "src"
//       "families": ["maybeWrapConfigSecret"],            // for `discover`
//       "scaffold": [{ "file": "admin/config-secret.ts", "append": "export function ...Twin(...)" }],
//       "imports":  { "admin/router-push.ts": ["import { ...Twin } from \"./config-secret.ts\";"] },
//       "arms": [
//         { "id": "A1", "family": "f", "file": "admin/router-push.ts", "line": 262,
//           "kind": "swap",       "from": "maybeWrapConfigSecret", "to": "maybeWrapConfigSecretTwin" },
//         { "id": "B1", "kind": "dropArg",    "arg": ", PUSH_SECRET_AAD" },
//         { "id": "C1", "kind": "discard",    "name": "hybridVerify" },
//         { "id": "D1", "kind": "deleteStmt", "stmt": "assertNoPlaintextSecretInExport(x);" }
//       ]
//     }
//
// SERIALISATION IS THE CALLER'S RESPONSIBILITY IN ONE RESPECT ONLY: never run two harness processes against
// the SAME worktree. Within one process every arm is applied, measured, and restored before the next begins,
// so no member ever imports a file while a driver is writing it.

import { execFileSync, execSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync, appendFileSync, mkdirSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";

// ------------------------------------------------------------------------------------------------------
// mutation kinds
// ------------------------------------------------------------------------------------------------------

// balancedCallAt returns [start, end] of the whole call beginning at `from`, matching parens rather than
// scanning to the first `)`. A non-greedy `\([^;]*?\)` stops at the NESTED call's paren whenever an argument
// is itself a call, which on two real sites produced `f(a, g(b), true), h(c))`: it PARSES CLEAN, passes an
// extra argument, and mutates nothing. Both arms would have been recorded as surviving an unmutated guard.
export function balancedCallAt(text, from) {
  const open = text.indexOf("(", from);
  if (open < 0) return null;
  let depth = 0;
  for (let k = open; k < text.length; k++) {
    if (text[k] === "(") depth++;
    else if (text[k] === ")") {
      depth--;
      if (depth === 0) return [from, k];
    }
  }
  return null;
}

// applyKind returns the mutated LINE, or throws. Every kind asserts its target is present first, so a
// shifted line number is a hard error rather than a silent no-op that reads as a surviving site.
export function applyKind(line, arm) {
  if (arm.kind === "swap") {
    const n = (line.match(new RegExp(`(?<![.\\w$])${arm.from}\\s*\\(`, "g")) ?? []).length;
    if (n !== 1) throw new Error(`${arm.id}: expected exactly 1 call to ${arm.from}, found ${n}`);
    return line.replace(new RegExp(`(?<![.\\w$])${arm.from}(\\s*\\()`), `${arm.to}$1`);
  }
  if (arm.kind === "dropArg") {
    if (!line.includes(arm.arg)) throw new Error(`${arm.id}: argument ${arm.arg} not on the line`);
    return line.replace(arm.arg, "");
  }
  if (arm.kind === "deleteStmt") {
    if (!line.includes(arm.stmt)) throw new Error(`${arm.id}: statement not on the line`);
    return line.replace(arm.stmt, "void 0;");
  }
  if (arm.kind === "discard") {
    const at = line.search(new RegExp(`(?<![.\\w$])${arm.name}\\s*\\(`));
    if (at < 0) throw new Error(`${arm.id}: no call to ${arm.name} on the line`);
    // include a preceding `await` so the awaited value, not the promise, is what gets discarded
    const start = /await\s+$/.test(line.slice(0, at)) ? line.lastIndexOf("await", at) : at;
    const span = balancedCallAt(line, at);
    if (!span) throw new Error(`${arm.id}: unbalanced call to ${arm.name}`);
    const call = line.slice(start, span[1] + 1);
    if ((call.match(/\(/g) ?? []).length !== (call.match(/\)/g) ?? []).length) throw new Error(`${arm.id}: captured call is unbalanced: ${call}`);
    return line.slice(0, start) + `(${call}, true)` + line.slice(span[1] + 1);
  }
  if (arm.kind === "replaceLine") {
    if (!line.includes(arm.find)) throw new Error(`${arm.id}: text not on the line`);
    return line.replace(arm.find, arm.replace);
  }
  throw new Error(`${arm.id}: unknown kind ${arm.kind}`);
}

// ------------------------------------------------------------------------------------------------------
// A SPEC IS A CORPUS AND main MOVES UNDER IT
// ------------------------------------------------------------------------------------------------------
//
// A LINE NUMBER IS NOT AN ADDRESS, IT IS A GUESS THAT WAS TRUE ONCE. `the fourth attempt` landed its 43-arm sweep as
// a worked example so the next pass could run it rather than write it. Re-running that corpus ONE DAY later
// found THREE arms no longer at their recorded line: `B6` and `B7` had moved ten lines when `bf6c9347`
// landed above them in `cron/siem-push-pass.ts`, and `D5` thirty lines when `7468ed9b` landed above it in
// `sched/scheduler-do-control-plane.ts`. Nothing was wrong with the sweep; the tree simply moved.
//
// THIS IS A DIFFERENT DISEASE FROM THE INERT ARM AND IT NEEDS SAYING SEPARATELY. An inert arm ran at the
// right place and changed nothing. A drifted arm never reached the place at all. Both end in "no member
// went red", and reporting either as a site held by nothing is a claim the run does not support.
//
// The kind assertions in `applyKind` are what caught it: `B6` demanded exactly one call to
// `resolveConfigSecret` on its line, found zero, and threw. THAT IS THE GOOD OUTCOME AND IT IS NOT
// GUARANTEED: had the drift landed the arm on a DIFFERENT call of the same family -- and the families here
// have up to ten sites, four of them in files with more than one -- the assertion would have passed and the
// harness would have mutated a site nobody asked about, then reported the answer under the first site's
// name. `discover` prints an `anchor` for exactly this reason.
//
// resolveIdx therefore prefers CONTENT over position when an arm carries one, and REFUSES rather than
// guessing when the anchor is absent or ambiguous.
// AN ANCHOR THAT CANNOT TELL TWO SITES APART IS NOT AN ANCHOR, and this corpus proves it rather than
// supposing it: a single-line anchor is AMBIGUOUS for EIGHT of the 43 arms. `format/reader.ts:397` and
// `:566` are character-identical root-signature verifications in one file -- the very pair `the fourth attempt`
// built its headline on, one killed by seven members and the other by none -- and
// `scheduler-do-dest-config.ts` carries `const worm = validateWormPolicyValue(c.worm);` twice. So an
// anchor is a WINDOW of consecutive lines ending at the site, widened at write time until it is unique.
// Trimmed comparison, so re-indentation does not lose a site.
export function resolveIdx(arm, rows, shift) {
  const idx = arm.line - 1 + shift;
  if (!arm.anchor) return { idx, drift: null };
  const want = arm.anchor.split("\n").map((s) => s.trim());
  const at = (end) => end - want.length + 1 >= 0 && want.every((w, k) => (rows[end - want.length + 1 + k] ?? "").trim() === w);
  if (at(idx)) return { idx, drift: null };
  const hits = [];
  for (let i = 0; i < rows.length; i++) if (at(i)) hits.push(i);
  // Zero means the site is GONE (deleted, or edited so it no longer matches), which is a fact about the
  // tree and not a licence to mutate the nearest thing. More than one means the anchor still cannot tell
  // the sites apart, and picking either would attribute one site's verdict to another.
  if (hits.length !== 1) throw new Error(`${arm.id}: line ${arm.line} of ${arm.file} does not carry its anchor, and the anchor matches ${hits.length} window(s) in that file. REFUSING to guess a site.`);
  return { idx: hits[0], drift: { recorded: arm.line, found: hits[0] + 1 - shift } };
}

// uniqueAnchor builds the narrowest window ending at `line` that occurs exactly once in the file, so a spec
// is written with an anchor that can actually do its job rather than one that will refuse the first time it
// is needed. Returns null when even the whole preceding file cannot disambiguate, which is a fact worth a
// refusal rather than a silent single-line anchor.
export function uniqueAnchor(rows, line, maxWindow = 12) {
  const idx = line - 1;
  for (let w = 1; w <= maxWindow && idx - w + 1 >= 0; w++) {
    const win = rows.slice(idx - w + 1, idx + 1).map((s) => s.trim());
    let hits = 0;
    for (let i = w - 1; i < rows.length; i++) if (win.every((t, k) => (rows[i - w + 1 + k] ?? "").trim() === t)) hits++;
    if (hits === 1) return win.join("\n");
  }
  return null;
}

// ------------------------------------------------------------------------------------------------------
// the harness
// ------------------------------------------------------------------------------------------------------

export function makeHarness(spec) {
  const ROOT = spec.root;
  const SRCDIR = spec.srcDir ?? "src";
  const abs = (f) => join(ROOT, SRCDIR, f);
  const sha = (b) => createHash("sha256").update(b).digest("hex");

  const touched = [...new Set([...(spec.scaffold ?? []).map((s) => s.file), ...Object.keys(spec.imports ?? {}), ...(spec.arms ?? []).map((a) => a.file)])].sort();

  // PRISTINE COMES FROM THE HEAD BLOB, never from the working file. See precondition 3.
  const pristine = new Map();
  for (const f of touched) {
    const bytes = execFileSync("git", ["show", `HEAD:${SRCDIR}/${f}`], { cwd: ROOT, maxBuffer: 128 * 1024 * 1024 });
    pristine.set(f, { bytes, sha: sha(bytes) });
  }

  // SCOPED TO THE FILES THIS HARNESS WRITES, which is stricter where it matters and usable where it does
  // not. Repo-wide, the check fails on any unrelated edit a pass happens to have in its worktree: the very
  // run that proves an anchored spec still applies could not be made from the branch that anchors it,
  // because the spec edit itself read as a dirty tree, and the abort-restore then reported failure over a
  // src/ that was in fact byte-perfect. The harness only ever writes `touched`, so those are the only paths
  // whose cleanliness is evidence about the harness.
  const gitDirty = () => execFileSync("git", ["status", "--porcelain", "--", ...touched.map((f) => `${SRCDIR}/${f}`)], { cwd: ROOT, encoding: "utf8" }).trim();

  const restore = (label) => {
    const bad = [];
    for (const f of touched) {
      writeFileSync(abs(f), pristine.get(f).bytes);
      if (sha(readFileSync(abs(f))) !== pristine.get(f).sha) bad.push(f);
    }
    if (bad.length) throw new Error(`RESTORE FAILED after ${label}: ${bad.join(", ")}`);
    const dirty = gitDirty();
    if (dirty) throw new Error(`TREE DIRTY after restoring ${label}:\n${dirty}`);
  };

  const applyScaffold = () => {
    for (const f of touched) writeFileSync(abs(f), pristine.get(f).bytes);
    for (const s of spec.scaffold ?? []) writeFileSync(abs(s.file), readFileSync(abs(s.file), "utf8") + "\n" + s.append + "\n");
    for (const [f, lines] of Object.entries(spec.imports ?? {})) {
      const rows = readFileSync(abs(f), "utf8").split("\n");
      let last = -1;
      for (let i = 0; i < rows.length; i++) if (/^import\b/.test(rows[i]) && rows[i].includes(";")) last = i;
      if (last < 0) throw new Error(`no import line found in ${f} to anchor a scaffolding import`);
      rows.splice(last + 1, 0, ...lines);
      writeFileSync(abs(f), rows.join("\n"));
    }
  };

  // importShift is how far the scaffolding pushed a file's lines down, so an arm's recorded line number
  // still points at the site it was discovered at.
  const importShift = (file) => (spec.imports?.[file] ?? []).length;

  const applyArm = (arm) => {
    const rows = readFileSync(abs(arm.file), "utf8").split("\n");
    const { idx, drift } = resolveIdx(arm, rows, importShift(arm.file));
    const line = rows[idx];
    if (line === undefined) throw new Error(`${arm.id}: line ${arm.line} missing in ${arm.file}`);
    const out = applyKind(line, arm);
    if (out === line) throw new Error(`${arm.id}: the edit was a NO-OP, which would read as a surviving site`);
    rows[idx] = out;
    writeFileSync(abs(arm.file), rows.join("\n"));
    return { before: line.trim(), after: out.trim(), ...(drift ? { drift } : {}) };
  };

  return { ROOT, SRCDIR, abs, sha, touched, pristine, restore, applyScaffold, applyArm, gitDirty };
}

// ------------------------------------------------------------------------------------------------------
// parse checking, with the known negative that keeps the rig honest
// ------------------------------------------------------------------------------------------------------

export async function makeParser(root) {
  const esbuild = await import(join(root, "node_modules/esbuild/lib/main.js"));
  const api = esbuild.default ?? esbuild;
  const parse = async (src) => {
    try {
      await api.transform(src, { loader: "ts", format: "esm" });
      return null;
    } catch (e) {
      return String(e.message ?? e).split("\n")[0];
    }
  };
  // KNOWN NEGATIVE first: a green parse over a rig that cannot fail is not a check.
  const err = await parse("export const x = (a: number => { return a;\n");
  if (!err) throw new Error("PARSER RIG IS DEAD: the known negative parsed clean");
  return { parse, knownNegative: err };
}

// ------------------------------------------------------------------------------------------------------
// running a member: the exit code is written to a FILE and read back, never taken from a pipe
// ------------------------------------------------------------------------------------------------------

export function runMember(cmd, cwd, scratch) {
  const logPath = join(scratch, "harness-member.log");
  const codePath = join(scratch, "harness-member.exit");
  const t0 = Date.now();
  try {
    execSync(`{ ${cmd} ; } > ${JSON.stringify(logPath)} 2>&1 ; echo $? > ${JSON.stringify(codePath)}`, { cwd, shell: "/bin/bash", timeout: 900000 });
  } catch {
    // a shell-level failure still wrote the code file below; if it did not, the read throws and that is
    // correct: an unread exit code must never be silently treated as a zero
  }
  const code = Number(readFileSync(codePath, "utf8").trim());
  const log = readFileSync(logPath, "utf8");
  return { cmd, code, ms: Date.now() - t0, log, tail: log.split("\n").slice(-25).join("\n") };
}

// normaliseLog strips the parts of a member's output that legitimately move between two identical runs, so
// the stable-line intersection below is not defeated by a clock. It is deliberately blunt: over-normalising
// can only make an arm look INERT when it was live, and that direction merely withholds a finding, while
// under-normalising makes an arm look LIVE, which is the direction that would manufacture one.
export function normaliseLog(log) {
  return log
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, "<ts>")
    .replace(/\b\d+(\.\d+)?\s?ms\b/g, "<ms>")
    // One blunt rule rather than three narrow ones. The first draft matched hex at 16+ and base64 at 40+
    // and MISSED A ULID, which is 26 characters of Crockford base32 and therefore neither: the self-test
    // caught it as two pristine runs disagreeing on a line that was pure run id. Anything 20 characters or
    // longer of id-shaped text is treated as an id.
    .replace(/\b[0-9A-Za-z_-]{20,}\b/g, "<id>")
    .split("\n")
    .map((l) => l.trimEnd());
}

// stableLines keeps only the lines two runs of the SAME tree agree on, as a multiset. Anything that differs
// between two pristine runs is nondeterministic by definition and cannot be evidence that an arm did
// something. This is what makes the liveness test self-calibrating rather than a list of regexes.
export function stableLines(logA, logB) {
  const b = new Map();
  for (const l of normaliseLog(logB)) b.set(l, (b.get(l) ?? 0) + 1);
  const out = [];
  for (const l of normaliseLog(logA)) {
    const n = b.get(l) ?? 0;
    if (n > 0) {
      b.set(l, n - 1);
      out.push(l);
    }
  }
  return out;
}

// armMovedStableOutput answers the precondition-6 question for ONE member: did the arm change anything this
// member can observe. The baseline is the stable intersection of two pristine runs; the arm's output is
// intersected against that same baseline, and a DIFFERENT surviving count means a stable line disappeared
// or changed, which only a live arm can do.
export function armMovedStableOutput(baselineStable, armLog) {
  const arm = new Map();
  for (const l of normaliseLog(armLog)) arm.set(l, (arm.get(l) ?? 0) + 1);
  let matched = 0;
  for (const l of baselineStable) {
    const n = arm.get(l) ?? 0;
    if (n > 0) {
      arm.set(l, n - 1);
      matched++;
    }
  }
  return matched !== baselineStable.length;
}

// ------------------------------------------------------------------------------------------------------
// SITE REACHABILITY: the half `INERT-OR-UNOBSERVED` cannot tell apart on its own
// ------------------------------------------------------------------------------------------------------
//
// That verdict names TWO states, and they are repaired differently:
//   (a) the member set EXECUTED the site and observed nothing. Either the arm was a semantic no-op
//       (a `seg/` archive-fixture no-op case), or it was live and no member's output could show it. The repair is a
//       member that asserts the property, and the site stays UNKNOWN until one exists.
//   (b) NO member ever executed the site. There is no mutation result to read at all, because the mutated
//       code never ran. The repair is a member that DRIVES the site, and no amount of mutation will
//       substitute for one.
//
// Reporting these as one number hides which repair is owed, and (b) is the more serious of the two: it is
// the same shape as a runner nobody invokes, an artefact that exists, looks maintained, and measures
// nothing.
//
// MEASURED WITH NODE'S OWN COVERAGE, ON THE PRISTINE TREE. Nothing is mutated to answer a question about
// mutation, so there is no parse risk and no semantic risk, and the instrument belongs to the platform
// rather than to this file. The first draft of this inserted a marker print at each site, which is editing
// the source to ask a question about the source: the very move this harness exists to be careful about.

// offsetOfCallOnLine is deliberately tighter than "somewhere on the line": a line can execute its head and
// never reach the call (`x && f(y)`, `a ?? f(b)`), and a site that never ran must not read as covered.
export function offsetOfCallOnLine(src, line, name) {
  const rows = src.split("\n");
  let off = 0;
  for (let i = 0; i < line - 1; i++) off += (rows[i] ?? "").length + 1;
  const text = rows[line - 1] ?? "";
  if (name) {
    const at = text.search(new RegExp(`(?<![.\\w$])${name}\\s*\\(`));
    if (at >= 0) return off + at;
  }
  return off + (text.length - text.trimStart().length);
}

// countAtOffset reads the INNERMOST V8 range containing the offset. V8 nests ranges, and an inner range
// OVERRIDES its parent's count, so taking the outermost would report a whole function's entry count for a
// branch that never ran. That is the direction that matters: it would report a site as driven when it is
// not, which is the same false comfort as a mutation that changed nothing reading as a survivor.
export function countAtOffset(cov, url, offset) {
  let best = null;
  for (const script of cov.result ?? []) {
    if (script.url !== url) continue;
    for (const fn of script.functions ?? []) {
      for (const r of fn.ranges ?? []) {
        if (offset < r.startOffset || offset >= r.endOffset) continue;
        const width = r.endOffset - r.startOffset;
        if (best === null || width < best.width) best = { width, count: r.count };
      }
    }
  }
  // null means this process never loaded the script at all, which is not the same as loading it and not
  // reaching the site; both are "not executed here", but only the second is evidence about the site.
  return best === null ? null : best.count;
}

// sitesOfSpec collapses arms that share a file:line to ONE site. `A5` and `AAD4` are the same call on
// `admin/router-push.ts:262`, and counting that site twice would double-count its reachability.
export function sitesOfSpec(spec) {
  const byLine = new Map();
  for (const arm of spec.arms ?? []) {
    const key = `${arm.file}:${arm.line}`;
    const name = arm.from ?? arm.name ?? (arm.stmt?.match(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/) ?? [])[1] ?? null;
    const e = byLine.get(key) ?? { site: key, file: arm.file, line: arm.line, name, arms: [] };
    if (!e.name && name) e.name = name;
    e.arms.push(arm.id);
    byLine.set(key, e);
  }
  return [...byLine.values()];
}

// A REFUSAL IS NOT A PASS AND IT IS NOT A FAILURE. Exit 4 is this repo's could-not-check convention, and a
// member can also ANNOUNCE a refusal in its log while exiting non-zero for the wrong reason, which is how a
// pass nearly lost a site. Both are read.
//
// AND THE FIRST DRAFT OF THIS FUNCTION FAILED IN THE OPPOSITE DIRECTION, ON ITS FIRST LIVE USE. It matched
// the bare word REFUSED anywhere in the log, so a validator that KILLED an arm and printed `VERDICT: FAIL
// failures=1` was classified as a refusal, because among its 169 assertion labels were phrases like "an
// envelope with NO wrap key bound is REFUSED, not returned". Forty genuine kills read as forty
// could-not-checks. `the second attempt` read a refusal as a finding-of-nothing; this read a finding as a refusal.
// Both come from classifying on a substring rather than on the member's own declared verdict.
//
// So a DECLARED VERDICT WINS OVER ANY PROSE. A log carrying `VERDICT: FAIL` or an `N FAILURE(S)` tally is a
// finding whatever words appear elsewhere in it, and only the runner's own refusal sentences -- anchored to
// a line, not floating in the text -- make a refusal.
const DECLARED_FINDING = /^VERDICT: FAIL\b|^\d+ FAILURE\(S\)/m;
const DECLARED_REFUSAL = /^VERDICT SKIPPED|^\s*REFUSED, exit|could not establish its own subject|\bNOT-REACHED\b|\bcould-not-check\b/m;
export function classify(r) {
  if (r.code === 0) return "pass";
  if (DECLARED_FINDING.test(r.log)) return "found";
  if (r.code === 4 || DECLARED_REFUSAL.test(r.log)) return "refused";
  return "found";
}

// ------------------------------------------------------------------------------------------------------
// discovery: walk the tree, never hand-keep a list of files
// ------------------------------------------------------------------------------------------------------

export function discoverSites(root, srcDir, family) {
  const SRC = join(root, srcDir);
  const files = [];
  const walk = (d) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith(".ts")) files.push(p);
    }
  };
  walk(SRC);
  const out = [];
  for (const p of files.sort()) {
    const lines = readFileSync(p, "utf8").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i];
      if (/^\s*(\/\/|\*)/.test(t)) continue;
      if (/^\s*import\b/.test(t) || /^\s*export\s*\{/.test(t)) continue;
      if (new RegExp(`(export\\s+)?(async\\s+)?function\\s+${family}\\s*\\(`).test(t)) continue;
      const n = (t.match(new RegExp(`(?<![.\\w$])${family}\\s*\\(`, "g")) ?? []).length;
      // `anchor` is the site's CONTENT, emitted beside the line number so a spec built from this output
      // can still find the arm after main moves the line under it. See resolveIdx.
      for (let k = 0; k < n; k++) out.push({ family, file: relative(SRC, p), line: i + 1, text: t.trim(), anchor: t.trim() });
    }
  }
  return out;
}

// ------------------------------------------------------------------------------------------------------
// CLI
// ------------------------------------------------------------------------------------------------------

const isMain = process.argv[1]?.endsWith("guard-mutation-harness.mjs");
if (isMain) {
  const [specPath, mode] = process.argv.slice(2);
  if (!specPath || !mode) {
    console.error("usage: guard-mutation-harness.mjs <spec.json> <discover|parse|inert|grand|sites|reach|restore> [--members f] [--only ids] [--out f]");
    process.exit(2);
  }
  const arg = (name) => {
    const i = process.argv.indexOf(name);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  const spec = JSON.parse(readFileSync(specPath, "utf8"));
  const OUT = arg("--out") ?? `${specPath}.results.jsonl`;
  const scratch = arg("--scratch") ?? spec.root;
  const membersFile = arg("--members");
  const members = membersFile ? readFileSync(membersFile, "utf8").split("\n").map((s) => s.trim()).filter(Boolean) : null;
  const only = arg("--only") ? new Set(arg("--only").split(",")) : null;
  const arms = (spec.arms ?? []).filter((a) => !only || only.has(a.id));

  const H = makeHarness(spec);
  writeFileSync(OUT, "");
  const emit = (o) => appendFileSync(OUT, JSON.stringify(o) + "\n");

  // WORK IS COUNTED AS ENTRIES EXAMINED. Every counter below is an examined count; outcome counts are
  // reported beside them and never in place of them.
  let armsExamined = 0;
  let memberRuns = 0;

  const run = async () => {
    if (mode === "discover") {
      let n = 0;
      for (const fam of spec.families ?? []) {
        for (const s of discoverSites(spec.root, spec.srcDir ?? "src", fam)) {
          n++;
          console.log(JSON.stringify(s));
        }
      }
      console.log(`# ${n} site(s) EXAMINED across ${(spec.families ?? []).length} family/families`);
      return n > 0 ? 0 : 2;
    }

    const P = await makeParser(spec.root);
    console.error(`parser rig live, known negative rejected: ${P.knownNegative}`);

    if (mode === "restore") {
      H.restore("manual");
      console.log("restored, tree clean");
      return 0;
    }

    // `reach` answers the question `INERT-OR-UNOBSERVED` leaves open: does the member set EXECUTE this site
    // at all. It mutates NOTHING -- every member runs on the pristine tree under NODE_V8_COVERAGE -- so it
    // is the one mode that can run beside a mutation driver without either seeing the other's tree.
    if (mode === "reach") {
      if (!members) throw new Error("reach mode needs --members");
      if (H.gitDirty()) throw new Error(`reach measures the PRISTINE tree and this one is dirty:\n${H.gitDirty()}`);
      const sites = sitesOfSpec(spec).map((s) => {
        const file = join(spec.root, spec.srcDir ?? "src", s.file);
        return { ...s, url: pathToFileURL(file).href, offset: offsetOfCallOnLine(readFileSync(file, "utf8"), s.line, s.name) };
      });
      // A COVERAGE RIG THAT REPORTS ZERO FOR EVERYTHING IS INDISTINGUISHABLE FROM A TREE NOTHING DRIVES, and
      // "no site is executed" is precisely the dramatic answer this mode could produce by being broken. So
      // the first site the members reach doubles as the known positive: if not one of the probes is ever
      // executed by any member, the run REFUSES rather than reporting 100 per cent unreachable.
      const covDir = join(scratch, "guard-mutation-coverage");
      const tally = new Map(sites.map((s) => [s.site, []]));
      for (const m of members) {
        rmSync(covDir, { recursive: true, force: true });
        mkdirSync(covDir, { recursive: true });
        const r = runMember(`NODE_V8_COVERAGE=${JSON.stringify(covDir)} ${m}`, spec.root, scratch);
        memberRuns++;
        const hit = [];
        for (const f of readdirSync(covDir)) {
          if (!f.endsWith(".json")) continue;
          let cov;
          try {
            cov = JSON.parse(readFileSync(join(covDir, f), "utf8"));
          } catch {
            continue; // a process killed mid-write leaves a truncated file, which is evidence of nothing
          }
          for (const s of sites) if ((countAtOffset(cov, s.url, s.offset) ?? 0) > 0 && !hit.includes(s.site)) hit.push(s.site);
        }
        for (const s of hit) tally.get(s).push(m);
        emit({ mode, member: m, code: r.code, sitesExecuted: hit });
        console.log(`${String(r.code).padStart(3)} ${String(hit.length).padStart(3)} site(s)  ${m}`);
      }
      rmSync(covDir, { recursive: true, force: true });
      const rows = sites.map((s) => ({ ...s, members: tally.get(s.site) })).sort((a, b) => a.members.length - b.members.length);
      let never = 0;
      for (const s of rows) {
        if (!s.members.length) never++;
        console.log(`${String(s.members.length).padStart(4)} member(s) execute  ${s.site}  arms=${s.arms.join(",")}`);
        emit({ mode, site: s.site, arms: s.arms, executedBy: s.members.length, members: s.members });
      }
      console.log(`\n${sites.length} site(s) EXAMINED, ${memberRuns} member run(s) EXAMINED`);
      console.log(`SITES NO MEMBER EXECUTES (a mutation there measures nothing): ${never} of ${sites.length}`);
      if (never === sites.length) {
        console.error("REFUSING to report: NOT ONE site was executed by any member, which is what a dead coverage rig also looks like.");
        return 4;
      }
      return 0;
    }

    if (mode === "parse") {
      let bad = 0;
      for (const f of H.touched) if (await P.parse(readFileSync(H.abs(f), "utf8"))) bad++;
      console.log(`pristine: ${H.touched.length} file(s) EXAMINED, ${bad} parse error(s)`);
      H.applyScaffold();
      let sbad = 0;
      for (const f of H.touched) if (await P.parse(readFileSync(H.abs(f), "utf8"))) sbad++;
      console.log(`scaffolded: ${H.touched.length} file(s) EXAMINED, ${sbad} parse error(s)`);
      H.restore("scaffold parse");
      let abad = 0;
      for (const arm of arms) {
        H.applyScaffold();
        const edit = H.applyArm(arm);
        const err = await P.parse(readFileSync(H.abs(arm.file), "utf8"));
        armsExamined++;
        if (err) {
          abad++;
          console.log(`PARSE FAIL ${arm.id}: ${err}`);
        }
        emit({ mode, arm: arm.id, parse: err ?? "ok", ...edit });
        H.restore(arm.id);
      }
      console.log(`arms: ${armsExamined} EXAMINED, ${abad} parse failure(s)`);
      return bad + sbad + abad > 0 ? 1 : 0;
    }

    if (mode === "inert" || mode === "grand") {
      H.applyScaffold();
      if (mode === "grand")
        for (const arm of arms) {
          armsExamined++;
          H.applyArm(arm);
        }
      for (const f of H.touched) {
        const err = await P.parse(readFileSync(H.abs(f), "utf8"));
        if (err) {
          H.restore(mode);
          throw new Error(`PARSE FAILURE in ${f}: ${err}`);
        }
      }
      if (!members) {
        console.log(`${mode}: ${armsExamined} arm(s) applied, tree left MUTATED for an external chain run; restore with mode 'restore'`);
        return 0;
      }
      let notPass = 0;
      for (const m of members) {
        const r = runMember(m, spec.root, scratch);
        memberRuns++;
        const cls = classify(r);
        if (cls !== "pass") notPass++;
        emit({ mode, member: m, code: r.code, cls, ms: r.ms, tail: r.tail });
        console.log(`${cls.toUpperCase().padEnd(8)} ${m} (${(r.ms / 1000).toFixed(1)}s)`);
      }
      H.restore(mode);
      console.log(`${mode}: ${memberRuns} member run(s) EXAMINED, ${notPass} not passing`);
      return mode === "inert" && notPass > 0 ? 1 : 0;
    }

    if (mode === "sites") {
      if (!members) throw new Error("sites mode needs --members");
      // PRECONDITION 6: the pristine baseline, run TWICE per member so the stable-line intersection can
      // self-calibrate away anything nondeterministic. Without this an arm that changed nothing is reported
      // as a site "held by nothing", which is a finding the harness cannot substantiate.
      const baseline = new Map();
      // PRECONDITION 8: THE BASELINE MUST AGREE WITH ITSELF. The two pristine runs above were already being
      // made and their EXIT CODES were being thrown away; only their lines were compared. A member that
      // passes on run a and fails on run b was therefore folded into the stable-line intersection and never
      // named, and that is the one defect this harness cannot absorb, because a flake does its damage in the
      // direction the harness trusts most: a member that reds on its own manufactures a KILL, a kill records
      // the site as HELD, and a site recorded as held is a confident green nobody re-opens. Measured:
      // test/validate-passkey.ts failed 1 run in 240 on a pristine tree at 4397fd69 and was the SOLE KILLER
      // of arm B7 in the fourth attempt's re-run, so one self-inflicted red turned a could-not-check into a KILLED.
      // This costs no extra runs.
      const unstable = [];
      for (const m of members) {
        const a = runMember(m, spec.root, scratch);
        const b = runMember(m, spec.root, scratch);
        memberRuns += 2;
        if (a.code !== b.code) unstable.push({ m, a: a.code, b: b.code });
        baseline.set(m, stableLines(a.log, b.log));
      }
      if (unstable.length > 0) {
        // REFUSE, never grade. Dropping the member and carrying on would be worse than stopping: the arms it
        // would have killed become could-not-checks of a different kind, silently, and the run would still
        // publish a split. Two pristine runs cannot see a rare flake, so this catches the frequent ones and
        // scripts/determinism-gate.mjs is the instrument for measuring a rate.
        for (const u of unstable) console.error(`::error::NON-DETERMINISTIC MEMBER: ${u.m} exited ${u.a} then ${u.b} on the SAME pristine tree.`);
        console.error(`REFUSING to grade: ${unstable.length} of ${members.length} member(s) do not return the same verdict twice on an unmutated tree. A member that reds on its own MANUFACTURES A KILL, which records a site as guarded and hides the finding. Fix the member, then re-run. Exit 2.`);
        return 2;
      }
      console.log(`precondition 8: all ${members.length} member(s) returned the SAME exit code on both pristine runs.`);
      console.log(`precondition 6 baseline: ${members.length} member(s) run twice pristine; stable lines per member: ${members.map((m) => baseline.get(m).length).join(", ")}`);
      const verdicts = [];
      for (const arm of arms) {
        H.applyScaffold();
        const edit = H.applyArm(arm);
        const perr = await P.parse(readFileSync(H.abs(arm.file), "utf8"));
        if (perr) {
          H.restore(arm.id);
          throw new Error(`${arm.id} did not parse, so it proves nothing: ${perr}`);
        }
        const killers = [];
        const refusals = [];
        const movedIn = [];
        for (const m of members) {
          const r = runMember(m, spec.root, scratch);
          memberRuns++;
          const cls = classify(r);
          if (cls === "found") killers.push(m);
          else if (cls === "refused") refusals.push({ member: m, code: r.code, tail: r.tail });
          if (armMovedStableOutput(baseline.get(m), r.log)) movedIn.push(m);
        }
        H.restore(arm.id);
        armsExamined++;
        // PRECONDITION 6. A kill proves liveness on its own. Otherwise the arm must have moved some
        // member's STABLE output, or it changed nothing observable and is a could-not-check rather than a
        // site held by nothing.
        const verdict = killers.length
          ? "KILLED"
          : refusals.length
            ? "REFUSED-ONLY"
            : movedIn.length
              ? "SURVIVED"
              : "INERT-OR-UNOBSERVED";
        verdicts.push(verdict);
        emit({ mode, arm: arm.id, family: arm.family, site: `${arm.file}:${arm.line}`, verdict, killers, refusals, movedStableOutputIn: movedIn, edit });
        console.log(`${verdict.padEnd(12)} ${arm.id.padEnd(6)} ${arm.file}:${arm.line}  killers=${killers.length} refusals=${refusals.length}`);
      }
      const survived = verdicts.filter((v) => v === "SURVIVED").length;
      const refusedOnly = verdicts.filter((v) => v === "REFUSED-ONLY").length;
      const inert = verdicts.filter((v) => v === "INERT-OR-UNOBSERVED").length;
      console.log(`\n${armsExamined} arm(s) EXAMINED, ${memberRuns} member run(s) EXAMINED`);
      console.log(`SURVIVED (live arm, held by nothing): ${survived}`);
      console.log(`REFUSED-ONLY (could not check, NOT a survivor): ${refusedOnly}`);
      console.log(`INERT-OR-UNOBSERVED (the arm moved no member's stable output, so the site was never tested; could not check, NOT a survivor): ${inert}`);
      return 0;
    }

    throw new Error(`unknown mode ${mode}`);
  };

  run()
    .then((code) => {
      // PRECONDITION 4: never declare a verdict having examined nothing.
      if (mode !== "restore" && mode !== "discover" && armsExamined === 0 && memberRuns === 0) {
        console.error("REFUSING to report: 0 units of work EXAMINED. A verdict after no work is not a verdict.");
        process.exit(2);
      }
      process.exit(code);
    })
    .catch((e) => {
      console.error(e);
      // A THROW MUST NOT LEAVE THE TREE MUTATED. `grand` threw part-way through applying arm `B6`, whose
      // recorded line had drifted, and left SEVENTEEN source files modified: every arm applied before it
      // was still in place. Precondition 3 keeps the next run honest (pristine bytes come from the HEAD
      // blob, never from the working file, so the mutation cannot be captured AS pristine), but a mutated
      // tree is still a tree any concurrent test would import, and the only thing that put it back was a
      // human noticing and running `restore`.
      try {
        H.restore("an aborted run");
        console.error("tree restored after the abort");
      } catch (re) {
        console.error(`RESTORE AFTER THE ABORT ALSO FAILED AND THE TREE IS LEFT MUTATED, DO NOT RUN A TEST AGAINST IT: ${re.message ?? re}`);
      }
      // A THROW IS A COULD-NOT-CHECK, NOT A FINDING. This exited 1, which under this repo's 0/1/2
      // convention licenses the reading "the corpus was graded and here is what it found". A harness that
      // aborted part-way through applying an arm has graded nothing of the kind, and precondition 4 already
      // refuses with 2 for the milder case of examining no work at all. Exit 2 is the honest code.
      process.exit(2);
    });
}
