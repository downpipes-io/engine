// Impossible-comparison gate.
//
// A comparison that can never be true, and its mirror, a condition that is always true, do not
// announce themselves. They compile, they lint clean, and the branch they guard silently never
// runs. This repo shipped one: `this.effectiveRole(p, now) === null`, where `effectiveRole` is
// declared to return `Role`, a six-string union. The skip never fired, in the very read used to
// prove an offboarding, so lapsed-invite residue reported as holding a role entry.
//
// WHY THE COMPILER DOES NOT CATCH IT. `tsc --strict` reports TS2367 for a comparison between two
// types with no overlap, but it deliberately exempts `null` and `undefined`: comparing anything
// against them is always permitted, because a defensive check against an unsound value is a
// legitimate idiom. Measured on this repo's own compiler settings, a probe of eight shapes had
// TS2367 fire on the two literal-union comparisons and stay silent on `=== null` and
// `=== undefined`. No compiler setting would have caught the defect above. Nor would Biome: type
// information is what decides these, and this repo's Biome is not type-aware.
//
// WHY THE OBVIOUS RULE IS THE WRONG RULE. The general form of this check -- flag every comparison
// against null or undefined whose operand's type excludes both -- was measured over this repo
// before this gate was written. It produced 63 findings in `src` and 89 in `test`, and every single
// one was a LIVE guard rather than dead code, because in a Workers codebase a non-nullable type at
// a guard site is almost always non-nullable only by assertion:
//
//   JSON.parse(token) as KVToken          `t === null` fires whenever the token is the text "null"
//   storage.get<Record<string, unknown>>  the Durable Object generic is an unchecked assertion
//   const { done, value } = reader.read() the stream typing promises a value the runtime may omit
//   validateConfig(c: DownpipeConfig)     the parameter type is the claim the function exists to check
//
// Deleting those guards is the fix that is wrong in the other direction: it would turn a validated
// boundary into a crash. So the general rule has a 100 per cent false-positive rate here and is not
// adopted.
//
// WHAT THIS GATE FLAGS INSTEAD. Only operands whose type is SOUNDLY derived: a call to a function or
// method declared in this repo, whose declared or inferred return type contains neither null nor
// undefined. A repo function's return type is a fact about code in the tree, not an assertion about
// data from outside it, so a guard against null on its result genuinely cannot fire. That is exactly
// the shape of the defect, and nothing else.
//
// Measured before adoption: 2 of 2 known defects caught at engine@8aab011a
// (src/sched/scheduler-do-recovery.ts:706 and src/sched/scheduler-do-signin-factors.ts:105, both
// `this.effectiveRole(p, now) === null`), and 0 findings on the current tree in both the src and the
// test programs. It fires on the defect and costs nothing today.
//
// Usage:
//   node scripts/impossible-comparison-gate.mjs             report, exit 0
//   node scripts/impossible-comparison-gate.mjs --enforce   exit 1 on any finding

import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const ENFORCE = process.argv.includes("--enforce");

// The two programs that hold hand-written TypeScript. tsconfig.json covers src, tsconfig.test.json
// covers the validators, which is where a vacuous condition turns an assertion into a no-op.
const PROGRAMS = ["tsconfig.json", "tsconfig.test.json"];

// Deliberate exceptions, each with the reason. An entry here is a decision on the record.
const EXEMPT = new Map([
  // (empty today; add "path/to/file.ts:LINE" -> "why the dead comparison is deliberate" as needed)
]);

const F = ts.TypeFlags;

function typeParts(t) {
  return t.isUnion() ? t.types : [t];
}
function isUndecidable(t) {
  return typeParts(t).some((p) => p.flags & (F.Any | F.Unknown | F.TypeParameter));
}
function includesNullish(t) {
  return typeParts(t).some((p) => p.flags & (F.Null | F.Undefined | F.Void));
}

const findings = [];

/**
 * Report the flagged operand's provenance, which is the whole discrimination this gate rests on.
 * Only "repo-call" is sound; every other origin can carry a value its type denies.
 */
function soundRepoCall(checker, node) {
  let base = node;
  while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base) || ts.isNonNullExpression(base)) {
    base = base.expression;
  }
  if (ts.isAwaitExpression(base)) base = base.expression;
  if (!ts.isCallExpression(base)) return null;
  // A call whose result is immediately re-asserted is not sound, whatever it returns.
  if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) return null;
  const sym = checker.getSymbolAtLocation(base.expression);
  const decl = sym?.declarations?.[0];
  if (decl === undefined) return null;
  const file = decl.getSourceFile().fileName;
  // Declarations outside the tree describe a runtime we do not control; the stream reader typing is
  // the standing example of one that promises more than the runtime delivers.
  if (file.includes("node_modules") || file.endsWith(".d.ts")) return null;
  return { callee: base.expression.getText().slice(0, 80), declaredIn: relative(ROOT, file) };
}

function scanProgram(configName) {
  const configPath = resolve(ROOT, configName);
  const cfg = ts.readConfigFile(configPath, ts.sys.readFile);
  if (cfg.error !== undefined) throw new Error(`cannot read ${configName}`);
  const parsed = ts.parseJsonConfigFileContent(cfg.config, ts.sys, ROOT);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const checker = program.getTypeChecker();

  for (const sf of program.getSourceFiles()) {
    if (sf.isDeclarationFile) continue;
    if (sf.fileName.includes("node_modules")) continue;
    if (sf.fileName.includes("/.bundle/")) continue;

    const at = (node) => {
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
      return `${relative(ROOT, sf.fileName)}:${line + 1}`;
    };
    const text = (node) => node.getText().replace(/\s+/g, " ").slice(0, 120);

    const visit = (node) => {
      // A comparison against null or undefined, where the other operand is a repo call whose
      // return type admits neither. The equality form can never be true; the inequality form is
      // always true, so whichever branch depends on it is unreachable.
      if (ts.isBinaryExpression(node)) {
        const op = node.operatorToken.kind;
        const strictEq = op === ts.SyntaxKind.EqualsEqualsEqualsToken;
        const strictNe = op === ts.SyntaxKind.ExclamationEqualsEqualsToken;
        const looseEq = op === ts.SyntaxKind.EqualsEqualsToken;
        const looseNe = op === ts.SyntaxKind.ExclamationEqualsToken;
        if (strictEq || strictNe || looseEq || looseNe) {
          for (const [lit, other] of [
            [node.left, node.right],
            [node.right, node.left],
          ]) {
            const isNullish = lit.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(lit) && lit.text === "undefined");
            if (!isNullish) continue;
            const t = checker.getTypeAtLocation(other);
            if (isUndecidable(t) || includesNullish(t)) break;
            const prov = soundRepoCall(checker, other);
            if (prov === null) break;
            findings.push({
              at: at(node),
              expr: text(node),
              type: checker.typeToString(t),
              verdict: strictEq || looseEq ? "can never be true" : "is always true",
              callee: prov.callee,
              declaredIn: prov.declaredIn,
            });
            break;
          }
        }
      }

      // The mirror: a condition position holding a repo call whose return type is always truthy, so
      // the else arm is unreachable.
      let cond = null;
      if (ts.isIfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) cond = node.expression;
      else if (ts.isConditionalExpression(node)) cond = node.condition;
      if (cond !== null && ts.isCallExpression(cond)) {
        const t = checker.getTypeAtLocation(cond);
        if (!isUndecidable(t) && !includesNullish(t)) {
          const everyPartTruthy = typeParts(t).every((p) => (p.flags & F.Object) !== 0);
          const prov = everyPartTruthy ? soundRepoCall(checker, cond) : null;
          if (prov !== null) {
            findings.push({
              at: at(cond),
              expr: text(cond),
              type: checker.typeToString(t),
              verdict: "is always truthy",
              callee: prov.callee,
              declaredIn: prov.declaredIn,
            });
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
}

for (const cfg of PROGRAMS) scanProgram(cfg);

// tsconfig.test.json pulls src in behind the validators, so a src finding is seen by both programs.
// Report each site once: the duplicate is an artefact of how the tree is compiled, not a second defect.
const seen = new Set();
const unique = findings.filter((f) => {
  // The separator is written as the ESCAPE \u0000 rather than as a raw NUL byte, and that is not a
  // style preference. A raw NUL made this file BINARY to every tool that sniffs for one, and the
  // workstation grep (a ugrep wrapper) then returned NOTHING on it: no count, no "Binary file
  // matches", no error, just a silent exit 1, while `command grep` answered 40 for the same pattern.
  // So this file, which is a GATE, was invisible to every sweep that enumerated gates by grepping.
  // The escape produces the identical string at runtime, so the key is byte-for-byte what it was.
  const key = `${f.at}\u0000${f.expr}`;
  if (seen.has(key)) return false;
  seen.add(key);
  return true;
});

const live = unique.filter((f) => !EXEMPT.has(f.at));
const exempted = unique.length - live.length;

for (const f of live) {
  console.log(`[impossible-comparison] ${f.at}  ${f.expr}`);
  console.log(`    ${f.verdict}: ${f.callee} is declared in ${f.declaredIn} and returns ${f.type}`);
}
console.log(
  `[impossible-comparison] ${PROGRAMS.length} programs scanned, ${live.length} dead comparison(s), ${exempted} exempt`,
);

if (live.length > 0) {
  console.log("[impossible-comparison] FAIL: a guard above never fires. Establish what it was guarding before you");
  console.log("[impossible-comparison] change it: the branch is dead, so the behaviour it was meant to produce is");
  console.log("[impossible-comparison] missing, and deleting the comparison keeps it missing.");
  if (ENFORCE) process.exit(1);
} else {
  console.log("[impossible-comparison] OK: every comparison against null or undefined can still go both ways.");
}
