#!/usr/bin/env node
// Silent-catch ratchet.
//
// Every error handler in product source (a `catch` clause, a `.catch(h)` handler, a `.then(ok, h)` rejection
// handler) must do one of three things:
//   - rethrow: every exit of the handler throws (a final `throw`, or `return Promise.reject(...)`);
//   - record: the handler calls a recorder (a callee whose name matches the baseline's `recorderRe`);
//   - carry a waiver: a comment inside the handler of the exact form
//       // site-fault-waiver: <site id> -- <reason>
//     where <site id> is this handler's own id (file:function:kind:ordinal, as printed by --list) and the
//     reason is at least three words. A waiver that names another site, uses a wildcard or pattern, sits
//     outside a handler, or has no reason is a finding.
// A handler that does none of these is "silent". The baseline file holds today's silent handlers, counted per
// file:function. The check fails when any file:function holds more silent handlers than its baseline
// (a new silent site), and when it holds fewer (the baseline has slack and must be rewritten, so the count
// only falls). --write-baseline rewrites the file and refuses when the total would rise.
//
// Site ids use the same naming as the audit failure map: <file>:<function>:<kind>:<n>, where <function> is
// the nearest named enclosing function (Class.method, outer>inner, obj.prop) and <n> counts handlers of that
// kind in that function in source order.
//
// When the baseline names a site-fault recorder (baseline.siteFault), the same run checks its legend: every call
// passes a string-literal id, every id has a legend entry with a subsystem, a sentence and a fix class from the
// closed list, every legend entry has a call, and no id is called from two functions. --legend-map writes the
// legend joined to the current call locations, generated from source.
//
// Exit codes: 0 clean, 1 finding, 2 could not check (no baseline, no files, a parse failure).
//
// Usage:
//   node silent-catch-ratchet.mjs [--root <repo>] [--baseline <file>]      check
//   node silent-catch-ratchet.mjs --write-baseline [--root] [--baseline]    rewrite the baseline (total may not rise)
//   node silent-catch-ratchet.mjs --list [--root] [--baseline]              print every handler with its verdict
//   node silent-catch-ratchet.mjs --json <out> ...                          also write the full site list as JSON
//   node silent-catch-ratchet.mjs --self-test                               run the controls on a synthetic tree
//   node silent-catch-ratchet.mjs --init --repo <name> [--roots src] [--recorder-re <re>] [--promise-kind k] [--then-kind k]
//                                                                           create the first baseline (refuses to overwrite)
//
// FS-WRITES: none outside this repo
// It writes the baseline in scripts/, a --json or --legend-map file the caller names, and its self-test tree
// under the OS temp directory, which it removes.

import ts from "@typescript/typescript6";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA = "silent-catch-ratchet/1";
const WAIVER_TAG = "site-fault-waiver";
const WAIVER_RE = /site-fault-waiver:?[ \t]*([^\n]*)/;
const PATTERN_CHARS = /[*?[\]{}|\\^$]/;
const REASON_MIN_WORDS = 3;
const REASON_MIN_CHARS = 20;
const REASON_EMPTY = /^(todo|tbd|n\/a|na|none|ignore|later|fixme|wip|temp|x+)\b/i;
/** @typedef {import("@typescript/typescript6").Node} TsNode */
/** @typedef {import("@typescript/typescript6").Expression} TsExpr */
/** @typedef {import("@typescript/typescript6").CallExpression} TsCall */
/** @typedef {import("@typescript/typescript6").ConciseBody} TsBody */
/** @typedef {"rethrow" | "record" | "waived" | "silent"} Verdict */
/**
 * @typedef {object} Handler
 * @property {string} id
 * @property {string} key
 * @property {string} file
 * @property {number} line
 * @property {string} fn
 * @property {string} kind
 * @property {[number, number]} [range]
 * @property {Verdict | null} verdict
 * @property {string | null} shape
 * @property {string[]} recorders
 * @property {boolean} [logs]
 * @property {boolean} [someThrow]
 * @property {string} [waiver]
 */
/** @typedef {{ kind: string, file: string, line?: number, site?: string, detail: string }} Problem */
/** @typedef {{ id: string | null, file: string, line: number, fn: string }} SiteCall */
/** @typedef {{ recorder: string, legendFile: string, legendConst: string, fixClassConst: string }} SiteFaultCfg */
/** @typedef {{ promiseCatch?: string | undefined, thenReject?: string | undefined }} KindNames */
/** @typedef {{ repo?: string | undefined, roots: string[], recorderRe: string, kindNames?: KindNames | undefined, siteFault?: SiteFaultCfg | null | undefined }} Cfg */
/** @typedef {{ id: string, subsystem: string | null, what: string | null, fixClass: string | null, calls: string[] }} LegendEntry */
/** @typedef {{ files: string[], handlers: Handler[], problems: Problem[], legend: LegendEntry[] | null }} Result */
/** @typedef {{ schema?: string, repo?: string | undefined, roots: string[], recorderRe: string, kindNames?: KindNames | undefined, siteFault?: SiteFaultCfg | null | undefined, total?: number, byFunction?: Record<string, number>, sites?: string[] }} Baseline */
/** @typedef {{ repo: string, roots: string[], recorderRe: string, kindNames?: KindNames | undefined }} InitArgs */
/** @typedef {{ root?: string | undefined, baseline?: string | undefined, writeBaseline?: boolean, list?: boolean, json?: string | undefined, legendMap?: string | undefined, init?: InitArgs | null }} RunArgs */

const SILENT_SHAPES = ["empty", "[]", "{}", "null", "undefined", "0", "false", '""', "new Map()", "new Set()", "bare-return"];

// ------------------------------------------------------------------------------------------ small helpers
/**
 * @param {TsNode | undefined | null} e
 * @returns {any}
 */
function unwrap(e) {
  while (e && (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isSatisfiesExpression(e) || ts.isNonNullExpression(e) || ts.isTypeAssertionExpression(e))) e = e.expression;
  return e;
}
/** @param {TsNode} n */
function isFnLike(n) {
  return ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n);
}
/**
 * @param {any} n
 * @returns {string}
 */
function propNameText(n) {
  if (!n) return "?";
  if (ts.isIdentifier(n) || ts.isPrivateIdentifier(n)) return n.text;
  if (ts.isStringLiteral(n) || ts.isNumericLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  if (ts.isComputedPropertyName(n)) return `[${n.expression.getText()}]`;
  return n.getText();
}
/**
 * @param {any} c
 * @param {string | null} outerName
 * @returns {string}
 */
function classNameOf(c, outerName) {
  if (c.name) return c.name.text;
  const p = c.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  return outerName ?? "<class>";
}
/**
 * @param {any} o
 * @param {string | null} outerName
 * @returns {string}
 */
function objNameOf(o, outerName) {
  let p = o.parent;
  while (p && (ts.isParenthesizedExpression(p) || ts.isAsExpression(p) || ts.isSatisfiesExpression?.(p))) p = p.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return (outerName ? `${outerName}>` : "") + p.name.text;
  if (p && ts.isExportAssignment(p)) return "default";
  if (p && ts.isPropertyAssignment(p)) return `${objNameOf(p.parent, outerName)}.${propNameText(p.name)}`;
  return `${outerName ?? "<module>"}.{}`;
}
// The same naming the audit failure map uses, so a gate id and an audit id name the same handler.
/**
 * @param {any} n
 * @param {string | null} outerName
 * @returns {string | null}
 */
function namedFnName(n, outerName) {
  if (ts.isFunctionDeclaration(n)) return (outerName ? `${outerName}>` : "") + (n.name ? n.name.text : "default");
  if (ts.isMethodDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n) || ts.isConstructorDeclaration(n)) {
    const nm = ts.isConstructorDeclaration(n) ? "constructor" : propNameText(n.name);
    const p = n.parent;
    if (ts.isClassDeclaration(p) || ts.isClassExpression(p)) return `${classNameOf(p, outerName)}.${nm}`;
    if (ts.isObjectLiteralExpression(p)) return `${objNameOf(p, outerName)}.${nm}`;
    return nm;
  }
  if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) {
    let p = n.parent;
    while (p && (ts.isParenthesizedExpression(p) || ts.isAsExpression(p) || ts.isSatisfiesExpression?.(p))) p = p.parent;
    if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return (outerName ? `${outerName}>` : "") + p.name.text;
    if (p && ts.isPropertyDeclaration(p) && (ts.isClassDeclaration(p.parent) || ts.isClassExpression(p.parent))) return `${classNameOf(p.parent, outerName)}.${propNameText(p.name)}`;
    if (p && ts.isPropertyAssignment(p) && ts.isObjectLiteralExpression(p.parent)) return `${objNameOf(p.parent, outerName)}.${propNameText(p.name)}`;
    if (p && ts.isExportAssignment(p)) return "default";
    return null;
  }
  return null;
}
/**
 * @param {TsCall} call
 * @returns {string | null}
 */
function calleeLastName(call) {
  const e = unwrap(call.expression);
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  if (ts.isElementAccessExpression(e) && ts.isStringLiteral(e.argumentExpression)) return e.argumentExpression.text;
  return null;
}
/**
 * @param {TsNode | undefined} e
 * @returns {boolean}
 */
function isPromiseReject(e) {
  e = unwrap(e);
  if (!e || !ts.isCallExpression(e)) return false;
  const c = unwrap(e.expression);
  return ts.isPropertyAccessExpression(c) && ts.isIdentifier(c.expression) && c.expression.text === "Promise" && c.name.text === "reject";
}
// Visit a handler body without entering nested functions (their statements are not the handler's).
/**
 * @param {TsNode} node
 * @param {(n: TsNode) => void} fn
 */
function walkOwn(node, fn) {
  /** @param {TsNode} n */
  const v = (n) => {
    if (n !== node && isFnLike(n)) return;
    fn(n);
    ts.forEachChild(n, v);
  };
  v(node);
}
/**
 * @param {TsNode | undefined} e
 * @returns {string | null}
 */
function exprShape(e) {
  e = unwrap(e);
  if (!e) return null;
  if (ts.isArrayLiteralExpression(e) && e.elements.length === 0) return "[]";
  if (ts.isObjectLiteralExpression(e) && e.properties.length === 0) return "{}";
  if (e.kind === ts.SyntaxKind.NullKeyword) return "null";
  if (ts.isIdentifier(e) && e.text === "undefined") return "undefined";
  if (ts.isVoidExpression(e)) return "undefined";
  if (ts.isNumericLiteral(e) && e.text === "0") return "0";
  if (e.kind === ts.SyntaxKind.FalseKeyword) return "false";
  if ((ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) && e.text === "") return '""';
  if (ts.isNewExpression(e) && ts.isIdentifier(e.expression) && (e.expression.text === "Map" || e.expression.text === "Set") && (!e.arguments || e.arguments.length === 0)) return `new ${e.expression.text}()`;
  return null;
}
/**
 * @param {any} body
 * @returns {string | null}
 */
function bodyShape(body) {
  if (!body) return null;
  if (!ts.isBlock(body)) return exprShape(body);
  const st = body.statements;
  if (st.length === 0) return "empty";
  if (st.length !== 1) return null;
  const s = st[0];
  if (s === undefined) return null;
  if (ts.isReturnStatement(s)) return s.expression ? exprShape(s.expression) : "bare-return";
  if (ts.isExpressionStatement(s) && ts.isBinaryExpression(s.expression) && s.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(unwrap(s.expression.left))) {
    const sh = exprShape(s.expression.right);
    return sh ? `assign ${sh}` : null;
  }
  return null;
}
/**
 * @param {string} root
 * @param {string} rel
 * @returns {string[]}
 */
function listFiles(root, rel) {
  const abs = path.join(root, rel);
  if (!fs.existsSync(abs)) return [];
  const st = fs.statSync(abs);
  if (st.isFile()) return [rel];
  /** @type {string[]} */
  const out = [];
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    if (ent.name === "node_modules" || ent.name === ".git") continue;
    const r = path.posix.join(rel, ent.name);
    if (ent.isDirectory()) out.push(...listFiles(root, r));
    else if (ent.isFile()) out.push(r);
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ analyse
// Returns { files, handlers: [{id, key, file, line, fn, kind, verdict, shape, waiver?}], problems: [...] }.
// verdict: "rethrow" | "record" | "waived" | "silent". problems: waiver defects, each a finding.
/**
 * @param {string} root
 * @param {Cfg} cfg
 * @returns {Result}
 */
export function analyse(root, cfg) {
  const recorderRe = new RegExp(cfg.recorderRe);
  const kinds = { catch: "catch", promiseCatch: cfg.kindNames?.promiseCatch ?? "catch-promise", thenReject: cfg.kindNames?.thenReject ?? "then-reject" };
  /** @type {string[]} */
  const files = [];
  for (const r of cfg.roots) files.push(...listFiles(root, r));
  const src = files.filter((f) => /\.(ts|tsx|mts|cts)$/.test(f) && !f.endsWith(".d.ts") && !/\.(test|spec)\.[cm]?tsx?$/.test(f) && !/\/__tests__\//.test(f)).sort();
  /** @type {Handler[]} */
  const handlers = [];
  /** @type {Problem[]} */
  const problems = [];
  /** @type {Map<string, number>} */
  const ordinals = new Map();
  const sfCfg = cfg.siteFault ?? null;
  /** @type {SiteCall[]} */
  const siteCalls = [];
  for (const rel of src) {
    const text = fs.readFileSync(path.join(root, rel), "utf8");
    const sf = ts.createSourceFile(rel, text, ts.ScriptTarget.Latest, true, rel.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    // parseDiagnostics is internal to the compiler API, so it is read through a cast.
    const diags = /** @type {{ parseDiagnostics?: import("@typescript/typescript6").Diagnostic[] }} */ (/** @type {unknown} */ (sf)).parseDiagnostics;
    if (diags !== undefined && diags.length > 0 && diags[0] !== undefined) {
      problems.push({ kind: "parse", file: rel, detail: ts.flattenDiagnosticMessageText(diags[0].messageText, " ") });
      continue;
    }
    /** @type {Handler[]} */
    const fileHandlers = [];
    /**
     * @param {string} kind
     * @param {TsNode} node
     * @param {TsBody | null} body
     * @param {[number, number]} range
     * @param {string} fnName
     * @param {TsNode | null} [handlerExpr]
     */
    const addHandler = (kind, node, body, range, fnName, handlerExpr) => {
      const okey = `${rel}|${fnName}|${kind}`;
      const ord = (ordinals.get(okey) ?? 0) + 1;
      ordinals.set(okey, ord);
      const id = `${rel}:${fnName}:${kind}:${ord}`;
      /** @type {Handler} */
      const h = { id, key: `${rel}:${fnName}`, file: rel, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1, fn: fnName, kind, range, verdict: null, shape: null, recorders: [] };
      if (!body) {
        // A handler passed by reference: judged by its name alone.
        const nm = handlerExpr && ts.isIdentifier(unwrap(handlerExpr)) ? unwrap(handlerExpr).text : handlerExpr && ts.isPropertyAccessExpression(unwrap(handlerExpr)) ? unwrap(handlerExpr).name.text : null;
        h.verdict = nm && recorderRe.test(nm) ? "record" : "silent";
        if (nm && recorderRe.test(nm)) h.recorders.push(nm);
        h.shape = "by-reference";
      } else {
        walkOwn(body, (n) => {
          if (ts.isCallExpression(n)) {
            const nm = calleeLastName(n);
            if (nm && recorderRe.test(nm)) h.recorders.push(nm);
            const c = unwrap(n.expression);
            if (nm === "log" || (ts.isPropertyAccessExpression(c) && ts.isIdentifier(c.expression) && c.expression.text === "console")) h.logs = true;
          }
          if (ts.isThrowStatement(n)) h.someThrow = true;
        });
        let allExitsThrow;
        if (ts.isBlock(body)) {
          let badReturn = false;
          walkOwn(body, (n) => {
            if (ts.isReturnStatement(n) && !(n.expression && isPromiseReject(n.expression))) badReturn = true;
          });
          const last = body.statements.at(-1);
          allExitsThrow = !badReturn && !!last && (ts.isThrowStatement(last) || (ts.isReturnStatement(last) && !!last.expression && isPromiseReject(last.expression)));
        } else allExitsThrow = isPromiseReject(body);
        h.shape = bodyShape(body);
        h.verdict = allExitsThrow ? "rethrow" : h.recorders.length > 0 ? "record" : "silent";
      }
      fileHandlers.push(h);
      handlers.push(h);
    };
    /**
     * @param {TsNode} n
     * @param {string | null} owner
     */
    const visit = (n, owner) => {
      let next = owner;
      if (isFnLike(n)) {
        const nm = namedFnName(n, owner);
        if (nm !== null) next = nm;
      }
      if (sfCfg && ts.isCallExpression(n) && calleeLastName(n) === sfCfg.recorder) {
        const a0 = n.arguments[0] ? unwrap(n.arguments[0]) : null;
        const line = sf.getLineAndCharacterOfPosition(n.getStart()).line + 1;
        siteCalls.push({ id: a0 && (ts.isStringLiteral(a0) || ts.isNoSubstitutionTemplateLiteral(a0)) ? a0.text : null, file: rel, line, fn: owner ?? "<module>" });
      }
      if (ts.isTryStatement(n) && n.catchClause) {
        addHandler(kinds.catch, n.catchClause, n.catchClause.block, [n.catchClause.getStart(), n.catchClause.end], owner ?? "<module>");
      } else if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(unwrap(n.expression))) {
        const m = unwrap(n.expression).name.text;
        const argIdx = m === "catch" ? 0 : m === "then" ? 1 : -1;
        if (argIdx >= 0 && n.arguments.length > argIdx) {
          const h = unwrap(n.arguments[argIdx]);
          const body = h && (ts.isArrowFunction(h) || ts.isFunctionExpression(h)) ? h.body : null;
          addHandler(m === "catch" ? kinds.promiseCatch : kinds.thenReject, n, body, [n.arguments.pos, n.end], owner ?? "<module>", body ? null : h);
        }
      }
      ts.forEachChild(n, (c) => visit(c, next));
    };
    ts.forEachChild(sf, (c) => visit(c, null));

    // Waivers: every occurrence of the tag in a comment must sit inside exactly one handler (the innermost).
    /** @type {Array<[number, number]>} */
    const literalRanges = [];
    /** @param {TsNode} n */
    const lv = (n) => {
      if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateExpression(n) || ts.isRegularExpressionLiteral(n)) literalRanges.push([n.getStart(), n.end]);
      ts.forEachChild(n, lv);
    };
    lv(sf);
    let at = text.indexOf(WAIVER_TAG);
    while (at >= 0) {
      const inLiteral = literalRanges.some(([a, b]) => at >= a && at < b);
      if (!inLiteral) {
        const lineEnd = text.indexOf("\n", at);
        const rawLine = text.slice(at, lineEnd < 0 ? text.length : lineEnd).replace(/\*\/.*$/, "").trim();
        const line = sf.getLineAndCharacterOfPosition(at).line + 1;
        const owners = fileHandlers.filter((h) => h.range !== undefined && at >= h.range[0] && at < h.range[1]).sort((a, b) => (b.range?.[0] ?? 0) - (a.range?.[0] ?? 0));
        const target = owners[0];
        const m = WAIVER_RE.exec(rawLine);
        const rest = m ? (m[1] ?? "").trim() : "";
        const sep = rest.indexOf("--");
        const wid = (sep >= 0 ? rest.slice(0, sep) : rest.split(/\s+/)[0] ?? "").trim();
        const reason = sep >= 0 ? rest.slice(sep + 2).trim() : "";
        const where = `${rel}:${line}`;
        if (!target) problems.push({ kind: "waiver-outside-handler", file: rel, line, detail: `${where}: a waiver must sit inside the handler it waives (found: ${rawLine})` });
        else if (wid === "") problems.push({ kind: "waiver-no-id", file: rel, line, site: target.id, detail: `${where}: waiver names no site; expected "${target.id}"` });
        else if (PATTERN_CHARS.test(wid)) problems.push({ kind: "waiver-pattern", file: rel, line, site: target.id, detail: `${where}: waiver id "${wid}" is a pattern; name the exact site "${target.id}"` });
        else if (wid !== target.id) problems.push({ kind: "waiver-wrong-site", file: rel, line, site: target.id, detail: `${where}: waiver names "${wid}" but sits in "${target.id}"` });
        else if (reason.split(/\s+/).filter(Boolean).length < REASON_MIN_WORDS || reason.length < REASON_MIN_CHARS || REASON_EMPTY.test(reason)) problems.push({ kind: "waiver-no-reason", file: rel, line, site: target.id, detail: `${where}: waiver for "${target.id}" gives no reason (at least ${REASON_MIN_WORDS} words after "--")` });
        else if (target.waiver) problems.push({ kind: "waiver-duplicate", file: rel, line, site: target.id, detail: `${where}: a second waiver for "${target.id}"` });
        else {
          target.waiver = reason;
          if (target.verdict === "silent") target.verdict = "waived";
        }
      }
      at = text.indexOf(WAIVER_TAG, at + WAIVER_TAG.length);
    }
  }
  for (const h of handlers) delete h.range;
  const legend = sfCfg ? checkLegend(root, sfCfg, siteCalls, problems) : null;
  return { files: src, handlers, problems, legend };
}

// checkLegend reads the legend object and the fix-class list from their source file and checks them against
// the recorder calls. Problems are pushed as findings; the joined legend is returned for --legend-map.
/**
 * @param {string} root
 * @param {SiteFaultCfg} sfCfg
 * @param {SiteCall[]} calls
 * @param {Problem[]} problems
 * @returns {LegendEntry[] | null}
 */
function checkLegend(root, sfCfg, calls, problems) {
  const rel = sfCfg.legendFile;
  const abs = path.join(root, rel);
  if (!fs.existsSync(abs)) {
    problems.push({ kind: "parse", file: rel, detail: `site-fault legend file ${rel} not found` });
    return null;
  }
  const sf = ts.createSourceFile(rel, fs.readFileSync(abs, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  /** @type {any} */
  let legendObj = null;
  /** @type {Array<string | null> | null} */
  let fixList = null;
  /** @param {TsNode} n */
  const v = (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      const init = unwrap(n.initializer);
      if (n.name.text === sfCfg.legendConst && ts.isObjectLiteralExpression(init)) legendObj = init;
      if (n.name.text === sfCfg.fixClassConst && ts.isArrayLiteralExpression(init)) fixList = init.elements.map((/** @type {TsNode} */ e) => (ts.isStringLiteral(unwrap(e)) ? unwrap(e).text : null));
    }
    ts.forEachChild(n, v);
  };
  v(sf);
  if (!legendObj || !fixList) {
    problems.push({ kind: "parse", file: rel, detail: `${sfCfg.legendConst} or ${sfCfg.fixClassConst} not found as a literal in ${rel}` });
    return null;
  }
  /** @type {Array<string | null>} */
  const fixes = fixList;
  /** @type {Map<string, LegendEntry>} */
  const entries = new Map();
  for (const p of legendObj.properties) {
    if (!ts.isPropertyAssignment(p) || !(ts.isStringLiteral(p.name) || ts.isIdentifier(p.name))) {
      problems.push({ kind: "legend-shape", file: rel, detail: `${rel}: a legend entry is not a plain "id": { ... } property` });
      continue;
    }
    const id = p.name.text;
    const o = unwrap(p.initializer);
    /**
     * @param {string} k
     * @returns {string | null}
     */
    const field = (k) => {
      const q = ts.isObjectLiteralExpression(o) ? o.properties.find((/** @type {TsNode} */ x) => ts.isPropertyAssignment(x) && propNameText(x.name) === k) : null;
      const e = q && ts.isPropertyAssignment(q) ? unwrap(q.initializer) : null;
      return e && (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) ? e.text : null;
    };
    /** @type {LegendEntry} */
    const entry = { id, subsystem: field("subsystem"), what: field("what"), fixClass: field("fixClass"), calls: [] };
    if (!entry.subsystem || !entry.what || entry.what.split(/\s+/).length < 5 || !entry.fixClass || !fixes.includes(entry.fixClass)) problems.push({ kind: "legend-entry", file: rel, detail: `legend entry "${id}" needs a subsystem, a sentence of what failed, and a fix class from ${sfCfg.fixClassConst}` });
    entries.set(id, entry);
  }
  /** @type {Map<string, Set<string>>} */
  const fnsById = new Map();
  for (const c of calls) {
    if (c.id === null) {
      problems.push({ kind: "site-id-not-literal", file: c.file, detail: `${c.file}:${c.line}: ${sfCfg.recorder} must be called with a string-literal site id` });
      continue;
    }
    const e = entries.get(c.id);
    if (!e) {
      problems.push({ kind: "site-id-no-legend", file: c.file, detail: `${c.file}:${c.line}: site id "${c.id}" has no entry in ${sfCfg.legendConst}` });
      continue;
    }
    e.calls.push(`${c.file}:${c.fn}:${c.line}`);
    const fns = fnsById.get(c.id) ?? new Set();
    fns.add(`${c.file}:${c.fn}`);
    fnsById.set(c.id, fns);
  }
  for (const [id, fns] of fnsById) if (fns.size > 1) problems.push({ kind: "site-id-shared", file: rel, detail: `site id "${id}" is called from ${fns.size} functions (${[...fns].join(", ")}); give each its own id` });
  for (const e of entries.values()) if (e.calls.length === 0) problems.push({ kind: "legend-orphan", file: rel, detail: `legend entry "${e.id}" has no ${sfCfg.recorder} call` });
  return [...entries.values()];
}

/**
 * @param {Handler[]} handlers
 * @returns {Record<string, number>}
 */
function countByKey(handlers) {
  /** @type {Record<string, number>} */
  const m = {};
  for (const h of handlers) if (h.verdict === "silent") m[h.key] = (m[h.key] ?? 0) + 1;
  return Object.fromEntries(Object.entries(m).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

// ------------------------------------------------------------------------------------------------ compare
/**
 * @param {Result} result
 * @param {Baseline} baseline
 * @returns {{ findings: string[], total: number, baseTotal: number }}
 */
export function compare(result, baseline) {
  /** @type {string[]} */
  const findings = [];
  for (const p of result.problems) if (p.kind !== "parse") findings.push(p.detail);
  const now = countByKey(result.handlers);
  const base = baseline.byFunction ?? {};
  const baseIds = new Set(baseline.sites ?? []);
  for (const [k, n] of Object.entries(now)) {
    const b = base[k] ?? 0;
    if (n > b) {
      const ids = result.handlers.filter((h) => h.key === k && h.verdict === "silent").map((h) => h.id);
      const fresh = ids.filter((id) => !baseIds.has(id));
      findings.push(`new silent handler in ${k}: ${n} silent, baseline ${b} (${(fresh.length ? fresh : ids).join(", ")}). Rethrow, call a recorder, or add "// ${WAIVER_TAG}: <id> -- <reason>" inside the handler.`);
    }
  }
  for (const [k, b] of Object.entries(base)) {
    const n = now[k] ?? 0;
    if (n < b) findings.push(`baseline slack in ${k}: ${n} silent, baseline ${b}. Rewrite the baseline with --write-baseline so the count stays down.`);
  }
  const total = Object.values(now).reduce((a, b) => a + b, 0);
  return { findings, total, baseTotal: baseline.total ?? Object.values(base).reduce((a, b) => a + b, 0) };
}

/** @param {Result} result */
function tally(result) {
  /** @type {{ handlers: number, rethrow: number, record: number, waived: number, silent: number, silentShaped: number, byKind: Record<string, { handlers: number, silent: number }> }} */
  const t = { handlers: result.handlers.length, rethrow: 0, record: 0, waived: 0, silent: 0, silentShaped: 0, byKind: {} };
  for (const h of result.handlers) {
    if (h.verdict !== null) t[h.verdict]++;
    if (h.verdict === "silent" && h.shape && (SILENT_SHAPES.includes(h.shape) || h.shape.startsWith("assign "))) t.silentShaped++;
    const k = t.byKind[h.kind] ?? { handlers: 0, silent: 0 };
    t.byKind[h.kind] = k;
    k.handlers++;
    if (h.verdict === "silent") k.silent++;
  }
  return t;
}

/**
 * @param {Result} result
 * @param {Cfg} cfg
 * @returns {Baseline & { total: number, byFunction: Record<string, number>, sites: string[] }}
 */
function baselineOf(result, cfg) {
  const byFunction = countByKey(result.handlers);
  return {
    schema: SCHEMA,
    repo: cfg.repo,
    roots: cfg.roots,
    recorderRe: cfg.recorderRe,
    ...(cfg.kindNames ? { kindNames: cfg.kindNames } : {}),
    ...(cfg.siteFault ? { siteFault: cfg.siteFault } : {}),
    total: Object.values(byFunction).reduce((a, b) => a + b, 0),
    byFunction,
    sites: result.handlers.filter((h) => h.verdict === "silent").map((h) => h.id),
  };
}

// ------------------------------------------------------------------------------------------------ run
/**
 * @param {RunArgs} args
 * @returns {number}
 */
function run(args) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(args.root ?? path.join(here, ".."));
  const baselinePath = path.resolve(args.baseline ?? path.join(root, "scripts", "silent-catch-baseline.json"));
  if (args.init) {
    if (fs.existsSync(baselinePath)) {
      console.error(`silent-catch-ratchet: --init refuses to overwrite ${baselinePath}`);
      return 2;
    }
    const cfg = { repo: args.init.repo, roots: args.init.roots, recorderRe: args.init.recorderRe, ...(args.init.kindNames ? { kindNames: args.init.kindNames } : {}) };
    const result = analyse(root, cfg);
    if (result.files.length === 0 || result.problems.some((p) => p.kind === "parse")) {
      console.error("silent-catch-ratchet: --init could not parse the tree");
      return 2;
    }
    const b = baselineOf(result, cfg);
    fs.writeFileSync(baselinePath, `${JSON.stringify(b, null, 1)}\n`);
    console.log(`silent-catch-ratchet: baseline created: ${b.total} silent handlers in ${Object.keys(b.byFunction).length} functions`);
    return 0;
  }
  if (!fs.existsSync(baselinePath)) {
    console.error(`silent-catch-ratchet: no baseline at ${baselinePath}`);
    return 2;
  }
  /** @type {Baseline} */
  const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
  if (baseline.schema !== SCHEMA || !Array.isArray(baseline.roots) || typeof baseline.recorderRe !== "string") {
    console.error(`silent-catch-ratchet: ${baselinePath} is not a ${SCHEMA} baseline`);
    return 2;
  }
  const cfg = { repo: baseline.repo, roots: baseline.roots, recorderRe: baseline.recorderRe, kindNames: baseline.kindNames, siteFault: baseline.siteFault };
  const result = analyse(root, cfg);
  const parseProblems = result.problems.filter((p) => p.kind === "parse");
  if (result.files.length === 0 || result.handlers.length === 0 || parseProblems.length > 0) {
    const p0 = parseProblems[0];
    console.error(`silent-catch-ratchet: could not check: ${result.files.length} files, ${result.handlers.length} handlers, ${parseProblems.length} parse failures${p0 ? ` (${p0.file}: ${p0.detail})` : ""}`);
    return 2;
  }
  const t = tally(result);
  if (args.json) fs.writeFileSync(args.json, `${JSON.stringify({ root, files: result.files.length, tally: t, handlers: result.handlers, problems: result.problems, legend: result.legend }, null, 1)}\n`);
  if (args.legendMap && result.legend) fs.writeFileSync(args.legendMap, `${JSON.stringify(result.legend, null, 1)}\n`);
  if (args.list) for (const h of result.handlers) console.log(`${String(h.verdict).padEnd(7)} ${h.id}  (line ${h.line}${h.shape ? `, ${h.shape}` : ""})`);
  const summary = `${result.files.length} files, ${t.handlers} handlers: rethrow ${t.rethrow}, record ${t.record}, waived ${t.waived}, silent ${t.silent} (silent-shaped ${t.silentShaped})${result.legend ? `; site-fault legend ${result.legend.length} entries, ${result.legend.reduce((a, e) => a + e.calls.length, 0)} calls` : ""}`;
  if (args.writeBaseline) {
    const next = baselineOf(result, cfg);
    const waiverProblems = result.problems.filter((p) => p.kind !== "parse");
    if (waiverProblems.length > 0) {
      for (const p of waiverProblems) console.error(`  ${p.detail}`);
      console.error("silent-catch-ratchet: refusing to write a baseline while a waiver is malformed");
      return 1;
    }
    if (next.total > (baseline.total ?? 0)) {
      console.error(`silent-catch-ratchet: refusing to write a baseline: total would rise ${baseline.total} -> ${next.total}`);
      return 1;
    }
    const moved = Object.entries(next.byFunction).filter(([k, n]) => n > (baseline.byFunction?.[k] ?? 0)).map(([k]) => k);
    fs.writeFileSync(baselinePath, `${JSON.stringify(next, null, 1)}\n`);
    console.log(`silent-catch-ratchet: baseline written: total ${baseline.total} -> ${next.total}${moved.length ? `; keys that rose (moved or renamed; review them): ${moved.join(", ")}` : ""}`);
    return 0;
  }
  const cmp = compare(result, baseline);
  if (cmp.findings.length > 0) {
    for (const f of cmp.findings) console.error(`  ${f}`);
    console.error(`silent-catch-ratchet: FAIL (${cmp.findings.length} finding(s)); ${summary}; baseline ${cmp.baseTotal}`);
    return 1;
  }
  console.log(`silent-catch-ratchet: OK; ${summary}; baseline ${cmp.baseTotal}`);
  return 0;
}

// ------------------------------------------------------------------------------------------------ self-test
// Controls on a synthetic tree. Each control states the verdict it must reach; the test fails if any control
// reaches another verdict, so the gate cannot pass while it is unable to go red.
function selfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "silent-catch-ratchet-"));
  const srcDir = path.join(dir, "src");
  fs.mkdirSync(srcDir);
  const cfg = { repo: "fixture", roots: ["src"], recorderRe: "^(record|note)[A-Z]" };
  const base = [
    "export function readA(): number[] {",
    "  try { return [1]; } catch { return []; }",
    "}",
    "export async function loadB(): Promise<void> {",
    "  try { await Promise.resolve(); } catch (e) { noteFault(e); }",
    "  await Promise.resolve().catch((e) => { throw e; });",
    "}",
    "function noteFault(_e: unknown): void {}",
    "",
  ].join("\n");
  /** @param {string} body */
  const write = (body) => fs.writeFileSync(path.join(srcDir, "a.ts"), body);
  /**
   * @param {string} body
   * @param {Baseline} baseline
   */
  const check = (body, baseline) => {
    write(body);
    const r = analyse(dir, cfg);
    return { r, cmp: compare(r, baseline) };
  };
  write(base);
  const b0 = baselineOf(analyse(dir, cfg), cfg);
  let failed = 0;
  /**
   * @param {string} label
   * @param {boolean} cond
   */
  const expect = (label, cond) => {
    console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
    if (!cond) failed++;
  };
  expect("baseline holds exactly the one silent handler", b0.total === 1 && b0.sites[0] === "src/a.ts:readA:catch:1");
  {
    const { cmp } = check(base, b0);
    expect("negative control: the unchanged tree is clean", cmp.findings.length === 0);
  }
  {
    const { cmp } = check(`${base}export function readC(): string {\n  try { return 'x'; } catch { return ''; }\n}\n`, b0);
    expect("planted silent catch in a new function goes red and names it", cmp.findings.some((f) => f.includes("src/a.ts:readC:catch:1")));
  }
  {
    const planted = base.replace("try { return [1]; } catch { return []; }", "try { return [1]; } catch { return []; }\n  try { return [2]; } catch { return []; }");
    const { cmp } = check(planted, b0);
    expect("planted second silent catch in a baselined function goes red", cmp.findings.some((f) => f.startsWith("new silent handler in src/a.ts:readA")));
  }
  {
    const { cmp } = check(base.replace("catch { return []; }", "catch {\n    // site-fault-waiver: src/a.ts:readA:catch:1\n    return [];\n  }"), b0);
    expect("planted waiver without a reason goes red", cmp.findings.some((f) => f.includes("gives no reason")));
  }
  {
    const { cmp } = check(base.replace("catch { return []; }", "catch {\n    // site-fault-waiver: src/a.ts:readA:catch:1 -- todo\n    return [];\n  }"), b0);
    expect("a placeholder reason is no reason", cmp.findings.some((f) => f.includes("gives no reason")));
  }
  {
    const { cmp } = check(base.replace("catch { return []; }", "catch {\n    // site-fault-waiver: src/a.ts:*:catch:* -- the value is re-derived on the next read\n    return [];\n  }"), b0);
    expect("planted pattern waiver goes red", cmp.findings.some((f) => f.includes("is a pattern")));
  }
  {
    const { cmp } = check(base.replace("catch { return []; }", "catch {\n    // site-fault-waiver: src/a.ts:readA:catch:2 -- the value is re-derived on the next read\n    return [];\n  }"), b0);
    expect("a waiver naming another site goes red", cmp.findings.some((f) => f.includes("but sits in")));
  }
  {
    const { cmp } = check(`// site-fault-waiver: src/a.ts:readA:catch:1 -- the value is re-derived on the next read\n${base}`, b0);
    expect("a waiver outside any handler goes red", cmp.findings.some((f) => f.includes("must sit inside the handler")));
  }
  {
    const { r, cmp } = check(base.replace("catch { return []; }", "catch {\n    // site-fault-waiver: src/a.ts:readA:catch:1 -- the empty list is the documented answer for a missing table\n    return [];\n  }"), b0);
    expect("a valid waiver clears the site (and the untightened baseline then reports slack)", r.handlers.find((h) => h.id === "src/a.ts:readA:catch:1")?.verdict === "waived" && cmp.findings.length === 1 && (cmp.findings[0] ?? "").startsWith("baseline slack"));
  }
  {
    const { cmp } = check(base.replace("catch { return []; }", "catch (e) { noteFault(e); return []; }"), b0);
    expect("fixing the site without tightening the baseline goes red (slack)", cmp.findings.some((f) => f.startsWith("baseline slack in src/a.ts:readA")));
  }
  {
    const { r } = check(base.replace("catch { return []; }", "catch (e) { if (Math.random() > 1) return []; throw e; }"), b0);
    expect("a conditional return before a rethrow is still silent", r.handlers.find((h) => h.id === "src/a.ts:readA:catch:1")?.verdict === "silent");
  }
  {
    const { r } = check(`${base}export const p = Promise.resolve().then(() => 1, () => 0);\nexport const q = Promise.resolve().catch(noteFault);\n`, b0);
    const then = r.handlers.find((h) => h.kind === "then-reject");
    const ref = r.handlers.find((h) => h.id === "src/a.ts:<module>:catch-promise:1");
    expect("a .then rejection handler is enumerated and judged", then?.verdict === "silent");
    expect("a recorder passed by reference counts as recording", ref?.verdict === "record");
  }
  {
    const { r } = check(base.replace("return [1];", "const s = 'site-fault-waiver: src/a.ts:readA:catch:1 -- a string, not a comment'; return [s.length];"), b0);
    expect("the tag inside a string literal is not a waiver", r.handlers.find((h) => h.id === "src/a.ts:readA:catch:1")?.verdict === "silent" && r.problems.length === 0);
  }
  {
    write(`${base}export function readC(): string {\n  try { return 'x'; } catch { return ''; }\n}\n`);
    const bp = path.join(dir, "baseline.json");
    fs.writeFileSync(bp, JSON.stringify(b0));
    const code = run({ root: dir, baseline: bp, writeBaseline: true });
    expect("--write-baseline refuses a total that would rise", code === 1 && JSON.parse(fs.readFileSync(bp, "utf8")).total === 1);
  }
  // Legend controls, on a second synthetic tree with a recorder and a legend.
  {
    const d2 = fs.mkdtempSync(path.join(os.tmpdir(), "silent-catch-ratchet-legend-"));
    fs.mkdirSync(path.join(d2, "src"));
    const legendSrc = (extra = "") => [
      'export const FIX = ["engine-defect", "storage-health"] as const;',
      "export const LEGEND = {",
      '  "a.read": { subsystem: "a", what: "The read of the a record failed and a default was used.", fixClass: "storage-health" },',
      extra,
      "} as const;",
      "",
    ].join("\n");
    /** @param {string} body */
    const code = (body) => `import { noteSiteFault } from "./rec.ts";\nexport function readA(): number {\n  try { return 1; } catch (e) { ${body} return 0; }\n}\n`;
    fs.writeFileSync(path.join(d2, "src", "rec.ts"), "export function noteSiteFault(_id: string, _e: unknown): void {}\n");
    const lcfg = { repo: "fixture", roots: ["src"], recorderRe: "^(record|note)[A-Z]", siteFault: { recorder: "noteSiteFault", legendFile: "src/legend.ts", legendConst: "LEGEND", fixClassConst: "FIX" } };
    /**
     * @param {string} legend
     * @param {string} body
     */
    const lcheck = (legend, body) => {
      fs.writeFileSync(path.join(d2, "src", "legend.ts"), legend);
      fs.writeFileSync(path.join(d2, "src", "a.ts"), code(body));
      return analyse(d2, lcfg).problems.map((p) => p.kind);
    };
    expect("legend: a known id with a full entry is clean", lcheck(legendSrc(), 'noteSiteFault("a.read", e);').length === 0);
    expect("legend: an id with no legend entry goes red", lcheck(legendSrc(), 'noteSiteFault("a.write", e);').includes("site-id-no-legend"));
    expect("legend: a legend entry with no call goes red", lcheck(legendSrc('  "a.gone": { subsystem: "a", what: "An entry whose call site was deleted from the code.", fixClass: "engine-defect" },'), 'noteSiteFault("a.read", e);').includes("legend-orphan"));
    expect("legend: a non-literal id goes red", lcheck(legendSrc(), 'const id = "a.read"; noteSiteFault(id, e);').includes("site-id-not-literal"));
    expect("legend: an entry with no fix class from the list goes red", lcheck(legendSrc().replace('fixClass: "storage-health"', 'fixClass: "try-again"'), 'noteSiteFault("a.read", e);').includes("legend-entry"));
    fs.writeFileSync(path.join(d2, "src", "b.ts"), 'import { noteSiteFault } from "./rec.ts";\nexport function readB(): void {\n  try { return; } catch (e) { noteSiteFault("a.read", e); }\n}\n');
    expect("legend: one id called from two functions goes red", lcheck(legendSrc(), 'noteSiteFault("a.read", e);').includes("site-id-shared"));
    fs.rmSync(d2, { recursive: true, force: true });
  }
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failed === 0 ? "silent-catch-ratchet self-test: PASS" : `silent-catch-ratchet self-test: FAIL (${failed})`);
  return failed === 0 ? 0 : 1;
}

// ------------------------------------------------------------------------------------------------ main
// The entry check canonicalises both paths, so a run through a symlinked path is still the entry point (the
// verdict-guard gate's rule). It is spelled out here rather than imported from test/lib/verdict-guard.ts,
// because that module is TypeScript and installs a validator exit hook, and this gate owns its exit codes.
function invokedDirectly() {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(argv1);
  } catch {
    // site-fault-waiver: scripts/silent-catch-ratchet.mjs:invokedDirectly:catch:1 -- a path that cannot be resolved is not the entry point
    return false;
  }
}
if (invokedDirectly()) {
  const a = process.argv.slice(2);
  /** @param {string} k */
  const val = (k) => {
    const i = a.indexOf(k);
    return i >= 0 ? a[i + 1] : undefined;
  };
  if (a.includes("--self-test")) process.exitCode = selfTest();
  else {
    const init = a.includes("--init")
      ? {
          repo: val("--repo") ?? "repo",
          roots: (val("--roots") ?? "src").split(","),
          recorderRe: val("--recorder-re") ?? "^(record|note|bump|report|flush|post|observe)[A-Z]",
          ...(val("--promise-kind") || val("--then-kind") ? { kindNames: { ...(val("--promise-kind") ? { promiseCatch: val("--promise-kind") } : {}), ...(val("--then-kind") ? { thenReject: val("--then-kind") } : {}) } } : {}),
        }
      : null;
    process.exitCode = run({ root: val("--root"), baseline: val("--baseline"), writeBaseline: a.includes("--write-baseline"), list: a.includes("--list"), json: val("--json"), legendMap: val("--legend-map"), init });
  }
}
