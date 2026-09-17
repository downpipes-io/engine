// validate-regex-construction: every `new RegExp(` built from a template literal must escape an
// interpolated segment before it reaches the pattern, or must be provably fed by fixed, compile-time
// data that cannot carry a regex metacharacter. ASVS V1.2.9.
//
// WHAT THE REPO ACTUALLY HAS TODAY. Three `new RegExp(` calls in src/ take a template literal with an
// interpolated segment:
//
//   src/dest/provider.ts:107      new RegExp(`\.${family}\.(?:${clouds})$`, "i")
//   src/sched/config-validate.ts:147  new RegExp(`^[A-Za-z0-9._-]{1,${DOWNPIPE_ID_MAX_LEN}}$`)
//   src/admin/router-sources.ts:530   new RegExp(`^/${prefix}/([^/]+)/(approve|reject)$`)
//
// Only one of the three interpolates data whose SHAPE is not fixed by the type system or by every
// call site: `clouds` in provider.ts, built by mapping the (mutable-length) AZURE_STORAGE_SUFFIXES
// list. It is escaped: `AZURE_STORAGE_SUFFIXES.map((s) => s.replace(/\./g, "\\."))`. The other two
// values, and provider.ts's own `family` parameter, never need an escape step because nothing that
// reaches them can carry a regex metacharacter:
//
//   `family` is typed `"blob" | "dfs"`, a closed union of two literals the type checker enforces.
//   `DOWNPIPE_ID_MAX_LEN` is a `const` bound to the integer literal 128; a decimal digit string is
//     never a regex metacharacter.
//   `prefix` is a plain `string` parameter, but matchActionPath is module-private and every call to
//     it in the file passes a literal ("config/changes", "owner-actions"); nothing but those two
//     fixed strings can ever reach the interpolation.
//
// WHAT THIS GATE CHECKS, for every `new RegExp`/`RegExp(` call in src/ whose first argument is a
// template literal with at least one `${...}` span. Each interpolated expression passes if any one
// of these holds, and fails otherwise:
//
//   (A) it resolves to a single `const` declaration whose initialiser is a plain non-negative integer
//       literal;
//   (B) it resolves to a parameter whose declared type is a single string-literal type or a union of
//       only string-literal types;
//   (C) it resolves to a parameter of a function declared (not exported) in the same file, where
//       every call to that function in the file passes a literal string (never a variable or another
//       template) for that parameter position;
//   (D) an escape step lies on the path that actually produces the value reaching the interpolation
//       (its own initialiser, if it resolves to one, or the interpolated expression itself): a
//       `.replace(regex, string)` call whose pattern contains a regex metacharacter and whose
//       replacement contains a backslash, reached by following call chains and their function-valued
//       arguments, but never a subtree a comma expression discards, and never only one side of an
//       `&&`/`||`/`??`/non-literal ternary where the other side is not equally escaped.
//
// Rule (D) is what keeps provider.ts's `clouds` green without hard-coding its shape into this gate:
// any future list-to-pattern join stays green only if it keeps escaping the same way, and a join that
// drops the `.replace` fails here rather than at a live host. It also stays red against a value that
// merely sits in the same initialiser as an unrelated escape, such as `(escaped, userSupplied)`.
//
// SELF-TEST FIRST (negative control). Before scanning the real tree, this gate writes seven small
// fixtures to a scratch directory: one exercising each of rules A to D, and three unsafe fixtures
// none of the rules clears: a parameter reached through a call site that passes a variable rather
// than a literal, an escape run only on the discarded left side of a comma expression, and an escape
// present on only one side of an `&&`. It asserts the detector clears the first four and flags the
// last three. A checker that always says "safe" would pass a scan of provider.ts by never finding
// anything to report; the self-test is what proves this one can still say "unsafe" when the input
// warrants it, including when an escape step exists somewhere in the tree but not on the path that
// actually produces the interpolated value.
//
// Run: node test/validate-regex-construction.ts

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { verdictReached } from "./lib/verdict-guard.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, "..");

interface Classification {
  safe: boolean;
  reason: string;
}

interface Finding {
  file: string;
  line: number;
  text: string;
  reason: string;
}

// A regex-literal source is treated as an escape pattern when it names at least one of the
// characters that a regex engine treats specially. This is deliberately permissive: it only has to
// tell an escaping `.replace` apart from an unrelated one, not decide which characters a given
// pattern needs to escape.
const REGEX_METACHAR = /[.*+?^${}()|[\]\\]/;

function resolveSingleDeclaration(expr: ts.Expression, checker: ts.TypeChecker): ts.Declaration | undefined {
  if (!ts.isIdentifier(expr)) return undefined;
  const symbol = checker.getSymbolAtLocation(expr);
  const decls = symbol?.getDeclarations();
  if (decls === undefined || decls.length !== 1) return undefined;
  return decls[0];
}

// Rule A: a const bound to a plain non-negative integer literal. The textual form of such a value is
// digits only, so it can never introduce a regex metacharacter regardless of how large it grows.
function isSafeIntegerConst(decl: ts.Declaration | undefined): boolean {
  if (decl === undefined || !ts.isVariableDeclaration(decl)) return false;
  const init = decl.initializer;
  if (init === undefined || !ts.isNumericLiteral(init)) return false;
  if (!/^[0-9]+$/.test(init.text)) return false;
  const list = decl.parent;
  return ts.isVariableDeclarationList(list) && (list.flags & ts.NodeFlags.Const) !== 0;
}

function isClosedStringLiteralType(typeNode: ts.TypeNode): boolean {
  if (ts.isLiteralTypeNode(typeNode)) return ts.isStringLiteral(typeNode.literal);
  if (ts.isUnionTypeNode(typeNode)) {
    return typeNode.types.every((member) => ts.isLiteralTypeNode(member) && ts.isStringLiteral(member.literal));
  }
  return false;
}

// Rule B: a parameter typed as a single string-literal type, or a union of only string-literal types.
// Every value the type checker admits at that position is one of a fixed, source-visible set.
function isSafeLiteralUnionParam(decl: ts.Declaration | undefined): boolean {
  if (decl === undefined || !ts.isParameter(decl) || decl.type === undefined) return false;
  return isClosedStringLiteralType(decl.type);
}

// Rule C: a parameter of a function declared, and never exported, in this file, where every call to
// that function anywhere in the file passes a literal string (not a variable, not another template)
// for the same parameter position. Nothing outside the file can call it under a different name, and
// nothing inside the file passes it anything but a fixed string.
function isSafeClosedCallSiteParam(decl: ts.Declaration | undefined, sf: ts.SourceFile): boolean {
  if (decl === undefined || !ts.isParameter(decl)) return false;
  const fn = decl.parent;
  if (!ts.isFunctionDeclaration(fn) || fn.name === undefined) return false;
  if ((ts.getCombinedModifierFlags(fn) & ts.ModifierFlags.Export) !== 0) return false;
  const paramIndex = fn.parameters.indexOf(decl);
  if (paramIndex === -1) return false;
  const fnName = fn.name.text;
  let callSites = 0;
  let allLiteral = true;
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === fnName) {
      callSites++;
      const arg = node.arguments[paramIndex];
      if (arg === undefined || !ts.isStringLiteralLike(arg)) allLiteral = false;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return callSites > 0 && allLiteral;
}

// isEscapingReplaceCall recognises the one call shape rule D treats as an escape step: a
// `.replace(pattern, replacement)` whose pattern is a regex literal naming a metacharacter and
// whose replacement is a string literal carrying a backslash (`s.replace(/\./g, "\\.")`), as
// opposed to a replace that strips or rewrites content for an unrelated reason.
function isEscapingReplaceCall(node: ts.Node): boolean {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== "replace") {
    return false;
  }
  if (node.arguments.length < 2) return false;
  const pattern = node.arguments[0];
  const replacement = node.arguments[1];
  return (
    pattern !== undefined &&
    ts.isRegularExpressionLiteral(pattern) &&
    replacement !== undefined &&
    ts.isStringLiteralLike(replacement) &&
    REGEX_METACHAR.test(pattern.text) &&
    replacement.text.includes("\\")
  );
}

// functionValueHasEscapeStep resolves a function-like node (an argument such as the callback passed
// to `.map`) to the expression(s) it can return, and requires the escape on every one of them: a
// concise arrow body is that single expression; a block body may return from several places, and
// since any of them can run, an escape on only some leaves the others' callers unescaped. Nested
// function bodies are not descended into: a `return` inside a callback defined within this callback
// belongs to that inner function, not to this one.
function functionValueHasEscapeStep(fn: ts.ArrowFunction | ts.FunctionExpression): boolean {
  if (!ts.isBlock(fn.body)) return containsEscapeStep(fn.body);
  let sawReturn = false;
  let allEscaped = true;
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionLike(node) && node !== fn) return;
    if (ts.isReturnStatement(node)) {
      sawReturn = true;
      if (node.expression === undefined || !containsEscapeStep(node.expression)) allEscaped = false;
    }
    ts.forEachChild(node, visit);
  };
  visit(fn.body);
  return sawReturn && allEscaped;
}

// Rule D: an escaping `.replace()` call must lie on the path that actually produces the value
// reaching the interpolation, not merely exist somewhere in the initialiser's syntax tree. This
// walks only the nodes that can carry that value forward, so it does not chase into a subtree a
// comma expression discards or count an escape found on only one side of a runtime branch:
//
//   - a parenthesised expression: its value is its inner expression's value;
//   - a comma expression: JS always evaluates it to its RIGHT operand only, so the left (commonly
//     used to run an escaping `.replace()` for its side effect and discard the result) is not
//     inspected at all;
//   - `&&` / `||` / `??`: which operand's value survives is a runtime truthiness decision this gate
//     does not evaluate, so both operands must independently carry the escape;
//   - a conditional (`? :`) with a literal `true`/`false` condition: only the branch JS always takes
//     is inspected; with any other condition, both branches must carry the escape;
//   - a call expression: the escaping call itself (matched directly), the receiver of a chained call
//     (`X.map(cb).join(sep)` walks into `X.map(cb)`), and any function-valued argument (a callback
//     such as `cb`, whose return value becomes every element the chain carries forward); a plain
//     data argument (a separator, a flags string) is not a value-bearing path and is not walked;
//   - a property access: its receiver expression.
//
// Anything else (an identifier, a literal, an object/array literal, ...) is not a shape rule D
// resolves further and is treated as carrying no escape.
function containsEscapeStep(root: ts.Node): boolean {
  if (isEscapingReplaceCall(root)) return true;

  if (ts.isParenthesizedExpression(root)) return containsEscapeStep(root.expression);

  if (ts.isBinaryExpression(root)) {
    const op = root.operatorToken.kind;
    if (op === ts.SyntaxKind.CommaToken) return containsEscapeStep(root.right);
    if (op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
      return containsEscapeStep(root.left) && containsEscapeStep(root.right);
    }
    return false;
  }

  if (ts.isConditionalExpression(root)) {
    if (root.condition.kind === ts.SyntaxKind.TrueKeyword) return containsEscapeStep(root.whenTrue);
    if (root.condition.kind === ts.SyntaxKind.FalseKeyword) return containsEscapeStep(root.whenFalse);
    return containsEscapeStep(root.whenTrue) && containsEscapeStep(root.whenFalse);
  }

  if (ts.isCallExpression(root)) {
    const receiver = ts.isPropertyAccessExpression(root.expression) ? root.expression.expression : undefined;
    if (receiver !== undefined && containsEscapeStep(receiver)) return true;
    return root.arguments.some((arg) => (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) && functionValueHasEscapeStep(arg));
  }

  if (ts.isPropertyAccessExpression(root)) return containsEscapeStep(root.expression);

  return false;
}

function classifyInterpolation(expr: ts.Expression, sf: ts.SourceFile, checker: ts.TypeChecker): Classification {
  const decl = resolveSingleDeclaration(expr, checker);
  if (isSafeIntegerConst(decl)) return { safe: true, reason: "const bound to a non-negative integer literal" };
  if (isSafeLiteralUnionParam(decl)) return { safe: true, reason: "parameter typed as a closed string-literal union" };
  if (isSafeClosedCallSiteParam(decl, sf)) return { safe: true, reason: "parameter fed only by literal arguments at every call site in this file" };
  const searchRoot = decl !== undefined && ts.isVariableDeclaration(decl) && decl.initializer !== undefined ? decl.initializer : expr;
  if (containsEscapeStep(searchRoot)) return { safe: true, reason: "an escaping .replace() is present in the value's construction" };
  return { safe: false, reason: "interpolates non-literal data with no escape step and no provably-fixed binding" };
}

// scanSourceFile is the one detector, shared by the self-test and the real scan, so a rule that
// clears the self-test fixtures is the same rule graded against the tree.
function scanSourceFile(sf: ts.SourceFile, checker: ts.TypeChecker): Finding[] {
  const out: Finding[] = [];
  const visit = (node: ts.Node): void => {
    const isRegexConstruction =
      (ts.isNewExpression(node) || ts.isCallExpression(node)) && ts.isIdentifier(node.expression) && node.expression.text === "RegExp";
    if (isRegexConstruction) {
      const args = node.arguments;
      const first = args?.[0];
      if (first !== undefined && ts.isTemplateExpression(first)) {
        for (const span of first.templateSpans) {
          const { safe, reason } = classifyInterpolation(span.expression, sf, checker);
          if (!safe) {
            const { line } = sf.getLineAndCharacterOfPosition(span.expression.getStart(sf));
            out.push({ file: sf.fileName, line: line + 1, text: span.expression.getText(sf), reason });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

const SELF_TEST_OPTIONS: ts.CompilerOptions = {
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  strict: true,
  skipLibCheck: true,
  noEmit: true,
};

interface SelfTestCase {
  name: string;
  code: string;
  expectFindings: number;
}

const SELF_TEST_CASES: SelfTestCase[] = [
  {
    name: "rule-a-integer-const",
    expectFindings: 0,
    code: [
      "export const MAX = 128;",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "export const PATTERN = new RegExp(`^[A-Za-z0-9._-]{1,${MAX}}$`);",
      "",
    ].join("\n"),
  },
  {
    name: "rule-b-literal-union-param",
    expectFindings: 0,
    code: [
      "function hostPattern(family: \"blob\" | \"dfs\"): RegExp {",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "  return new RegExp(`\\\\.${family}\\\\.example\\\\.test$`, \"i\");",
      "}",
      "export { hostPattern };",
      "",
    ].join("\n"),
  },
  {
    name: "rule-c-closed-call-site-param",
    expectFindings: 0,
    code: [
      "function matchPath(prefix: string): RegExp {",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "  return new RegExp(`^/${prefix}/id$`);",
      "}",
      "function useAlpha(): RegExp {",
      "  return matchPath(\"alpha\");",
      "}",
      "function useBeta(): RegExp {",
      "  return matchPath(\"beta\");",
      "}",
      "export { useAlpha, useBeta };",
      "",
    ].join("\n"),
  },
  {
    name: "rule-d-escaped-join",
    expectFindings: 0,
    code: [
      "const SUFFIXES: readonly string[] = [\"a.b\", \"c.d\"];",
      "export function suffixPattern(): RegExp {",
      "  const joined = SUFFIXES.map((s) => s.replace(/\\./g, \"\\\\.\")).join(\"|\");",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "  return new RegExp(`^(?:${joined})$`);",
      "}",
      "",
    ].join("\n"),
  },
  {
    // The negative control: a parameter reached through a call site that passes a variable rather
    // than a literal clears none of A to D and must still be flagged.
    name: "unsafe-variable-call-site",
    expectFindings: 1,
    code: [
      "function search(term: string): RegExp {",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "  return new RegExp(`^${term}$`);",
      "}",
      "export function run(userInput: string): RegExp {",
      "  return search(userInput);",
      "}",
      "",
    ].join("\n"),
  },
  {
    // A comma expression's value is always its right operand; the left operand (here, an escaping
    // .replace() over a fixed list) runs but is discarded. An escape present only on the discarded
    // left operand must not launder the unescaped right operand that actually reaches the pattern.
    name: "unsafe-comma-operator-sibling-escape",
    expectFindings: 1,
    code: [
      "const RAW_LIST: readonly string[] = [\"a.b\", \"c.d\"];",
      "export function buildPattern(userSupplied: string): RegExp {",
      "  const clouds = (RAW_LIST.map((s) => s.replace(/\\./g, \"\\\\.\")), userSupplied);",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "  return new RegExp(`\\\\.(?:${clouds})$`);",
      "}",
      "",
    ].join("\n"),
  },
  {
    // A second, differently-shaped escape-elsewhere trick: `&&` also discards one operand at
    // runtime. Whichever operand survives is a runtime decision this gate does not evaluate, so an
    // escape present on only one side (here, the left) must not clear the other (the unescaped
    // right operand, which is what actually reaches the pattern whenever the left is truthy).
    name: "unsafe-escape-elsewhere-logical-and",
    expectFindings: 1,
    code: [
      "const RAW_LIST2: readonly string[] = [\"e.f\", \"g.h\"];",
      "export function buildPatternAlt(userSupplied2: string): RegExp {",
      "  const clouds2 = RAW_LIST2.map((s) => s.replace(/\\./g, \"\\\\.\")) && userSupplied2;",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: fixture source text, not this file's own template literal.
      "  return new RegExp(`\\\\.(?:${clouds2})$`);",
      "}",
      "",
    ].join("\n"),
  },
];

function runSelfTest(): { failures: number; checks: number } {
  const dir = mkdtempSync(path.join(tmpdir(), "validate-regex-construction-"));
  const filesByCase = new Map<string, string>();
  try {
    for (const testCase of SELF_TEST_CASES) {
      const file = path.join(dir, `${testCase.name}.ts`);
      writeFileSync(file, testCase.code, "utf8");
      filesByCase.set(testCase.name, file);
    }
    const program = ts.createProgram([...filesByCase.values()], SELF_TEST_OPTIONS);
    const checker = program.getTypeChecker();
    let failures = 0;
    for (const testCase of SELF_TEST_CASES) {
      const file = filesByCase.get(testCase.name);
      if (file === undefined) throw new Error(`unreachable: no file recorded for self-test case ${testCase.name}`);
      const sf = program.getSourceFile(file);
      if (sf === undefined) {
        console.log(`  FAIL  self-test ${testCase.name}: the fixture did not load into the program`);
        failures++;
        continue;
      }
      const findings = scanSourceFile(sf, checker);
      const gotOk = findings.length === testCase.expectFindings;
      const detail = findings.length > 0 ? ` (${findings.map((f) => f.reason).join("; ")})` : "";
      console.log(`  ${gotOk ? "ok" : "FAIL"}   self-test ${testCase.name}: expected ${testCase.expectFindings} finding(s), got ${findings.length}${detail}`);
      if (!gotOk) failures++;
    }
    return { failures, checks: SELF_TEST_CASES.length };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function buildSrcProgram(): { checker: ts.TypeChecker; sourceFiles: ts.SourceFile[] } {
  const configPath = path.join(REPO, "tsconfig.json");
  const configFile = ts.readConfigFile(configPath, ts.sys.readFile);
  if (configFile.error !== undefined) {
    throw new Error(`cannot read ${configPath}: ${ts.flattenDiagnosticMessageText(configFile.error.messageText, "\n")}`);
  }
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, REPO);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const checker = program.getTypeChecker();
  const srcRoot = path.join(REPO, "src") + path.sep;
  const sourceFiles = program
    .getSourceFiles()
    .filter((sf) => !sf.isDeclarationFile && !sf.fileName.includes("/node_modules/") && sf.fileName.startsWith(srcRoot.replace(/\\/g, "/")));
  return { checker, sourceFiles };
}

function main(): void {
  let failures = 0;
  let checks = 0;

  console.log("Self-test (negative control): the detector must clear each recognised safe pattern and still flag the one it does not.");
  const selfTest = runSelfTest();
  failures += selfTest.failures;
  checks += selfTest.checks;

  console.log("\nScanning src/ for new RegExp(...) built from a template literal with an interpolated segment.");
  const { checker, sourceFiles } = buildSrcProgram();
  const allFindings: Finding[] = [];
  let sitesSeen = 0;
  for (const sf of sourceFiles) {
    const findings = scanSourceFile(sf, checker);
    allFindings.push(...findings);
  }
  // A second, coarser pass counts every interpolation this gate looked at (safe and unsafe alike),
  // so the printed check count reflects real coverage rather than only the failures.
  for (const sf of sourceFiles) {
    const visit = (node: ts.Node): void => {
      const isRegexConstruction =
        (ts.isNewExpression(node) || ts.isCallExpression(node)) && ts.isIdentifier(node.expression) && node.expression.text === "RegExp";
      if (isRegexConstruction) {
        const first = node.arguments?.[0];
        if (first !== undefined && ts.isTemplateExpression(first)) sitesSeen += first.templateSpans.length;
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  checks += sitesSeen;

  if (sitesSeen === 0) {
    console.log("  FAIL  no `new RegExp` template-literal interpolation was found anywhere in src/; the detector has nothing to grade.");
    failures++;
  } else {
    console.log(`  ok   ${sitesSeen} interpolated segment(s) checked across src/`);
  }

  for (const finding of allFindings) {
    const rel = path.relative(REPO, finding.file);
    console.log(`  FAIL   ${rel}:${finding.line}: \`${finding.text}\` ${finding.reason}`);
    failures++;
  }
  if (allFindings.length === 0) {
    console.log("  ok   every interpolated segment is either escaped or provably fixed at compile time");
  }

  console.log(failures === 0 ? "\nREGEX CONSTRUCTION VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

main();
