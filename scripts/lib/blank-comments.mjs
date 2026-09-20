// blankComments replaces every comment byte with a space, keeping newlines so nothing else shifts.
//
// WHY THIS EXISTS, because without it a scanner lies in the one direction it is meant to prevent. A
// COMMENTED-OUT import counted as a real dependency in the validator reachability gate, so leaving
//   // await import("./validate-thing.ts"); // temporarily disabled while chasing a flake
// behind in a wired validator marked validate-thing.ts REACHABLE. An orphan that runs nowhere then reported as
// wired, which is exactly the "a gate that cannot see the gap reads as a pass" failure that gate was written
// for. Proven by adding a genuine orphan (1 orphaned), then commenting an import of it into a chained
// validator (0 orphaned).
//
// Quote-aware, because a `//` inside a string is not a comment. Offsets and line numbers are preserved, so a
// caller may report positions from the blanked text against the original file.
//
// Shared rather than copied: two gates need the same scan, and a second hand-rolled copy is a second place for
// the comment blindness above to come back.
//
// blankComments alone leaves STRING and template-literal content untouched. That is exactly right for a
// caller that needs to read a path out of a string (validator-reachability-gate.mjs's import scan), but it
// is a hole for any caller matching a code SHAPE, because a decoy string that merely names the shape reads
// as real. blankCommentsAndStrings below closes that hole for those callers; blankComments keeps its
// original, narrower contract for the one caller that needs strings intact.
export const blankComments = (src) => {
  const out = [...src];
  let i = 0;
  const blank = (from, to) => {
    for (let k = from; k < to && k < out.length; k++) if (out[k] !== "\n") out[k] = " ";
  };
  while (i < src.length) {
    const c = src[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i++;
      while (i < src.length) {
        if (src[i] === "\\") {
          i += 2;
          continue;
        }
        if (src[i] === quote) break;
        if (quote !== "`" && src[i] === "\n") break;
        i++;
      }
      i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      const end = src.indexOf("\n", i);
      blank(i, end === -1 ? src.length : end);
      i = end === -1 ? src.length : end;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      const to = end === -1 ? src.length : end + 2;
      blank(i, to);
      i = to;
      continue;
    }
    i++;
  }
  return out.join("");
};

// blankCommentsAndStrings additionally blanks the INTERIOR of every string and template literal
// (delimiters and newlines kept, so line numbers and offsets stay valid, and stay aligned 1:1 with the
// raw source and with blankComments's output).
//
// WHY THIS EXISTS, and why it is a SEPARATE function rather than a flag on blankComments (engine-guard-
// attack, 2026-08-03, consolidated 2026-08-03 from three independently-written copies -- verdict-guard-
// gate.mjs, validator-reachability-gate.mjs, crossrepo-typecheck-gate.mjs -- into this one).
//
// verdict-guard-gate.mjs's enrolment check used to test comment-blanked text (strings intact) with a bare
// substring/regex search for "verdict-guard.ts" and "verdictReached(" ANYWHERE in the file. A validator
// whose real import and real call were deleted still passed as "enrolled" when a STRING (not a comment)
// merely NAMED them -- a stray prose constant reading `"...import { verdictReached } from
// \"./lib/verdict-guard.ts\"; ...verdictReached(failures)..."`. Confirmed live: deleting the real
// import+call from test/validate-keys-env.ts and adding exactly that decoy string made the gate report
// PASS, all 383 validators enrolled, 0 findings (R-106). validator-reachability-gate.mjs had the same
// hole in the other direction: a decoy string shaped like `from "./orphan.ts"` made a genuine orphan read
// as reached (R-107). crossrepo-typecheck-gate.mjs has the same hole again, this time producing a false
// FAIL instead of a false pass: a decoy string shaped like `from "../../console/x.ts"` makes an innocent
// file with no real cross-repo import read as one, demanding an exclusion it has not earned (R-109).
//
// A `${...}` interpolation inside a template literal is REAL CODE, not string content, and it can itself
// contain a nested backtick template (`${`nested ${x}`}`, used more than once in this repo's own
// logging). A first pass that treats every backtick as a bare open/close toggle misreads that nesting: it
// can close the outer template early, leave the scanner in the wrong mode, and blank real code after it on
// the same line. `stack` tracks nested template/expression frames (with brace depth per expression) so a
// `${` opens an expression, `}` at depth 0 closes it back to the enclosing template, and a nested backtick
// inside the expression opens its OWN template frame rather than closing the outer one.
//
// REGEX LITERALS are the other place a bare quote-toggle misreads structure: this repo's own
// validate-console-route-parity.ts matches route-extraction regexes containing a literal backtick, and a
// scanner that treats every backtick as a string delimiter opens a phantom template literal partway
// through the regex, corrupting everything after it on that line. isRegexContext uses the standard
// lookbehind heuristic (a `/` after an operator/punctuation/keyword-or-nothing is a regex; after an
// identifier, number, `)` or `]` it is division) to decide, then skips the regex body (respecting `[...]`
// character classes, where `/` need not be escaped, and `\`-escapes) and its trailing flags without
// toggling string/template mode.
//
// Corpus-verified: run over every file in test/ and scripts/ this repo has (383+ validator entry points at
// R-106, 446 validators at R-107) with 0 false positives and 0 false negatives against the pre-existing
// baseline, both before and after this consolidation.
function isRegexContext(src, i) {
  let j = i - 1;
  while (j >= 0 && (src[j] === " " || src[j] === "\t")) j--;
  if (j < 0) return true;
  const c = src[j];
  if (/[)\]]/.test(c)) return false;
  if (/[A-Za-z0-9_$]/.test(c)) {
    let k = j;
    while (k >= 0 && /[A-Za-z0-9_$]/.test(src[k])) k--;
    const word = src.slice(k + 1, j + 1);
    const REGEX_PRECEDING_KEYWORDS = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);
    return REGEX_PRECEDING_KEYWORDS.has(word);
  }
  return true; // an operator, punctuation, opening bracket, or start of file precedes it
}

export const blankCommentsAndStrings = (src) => {
  const out = Array.from(src);
  const stack = [];
  let mode = "code", quote = "", inClass = false;
  let i = 0;
  while (i < src.length) {
    const c = src[i], d = src[i + 1];
    if (mode === "code") {
      if (c === "/" && d === "/") { mode = "line"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "/" && d === "*") { mode = "block"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "/" && isRegexContext(src, i)) { mode = "regex"; inClass = false; i++; continue; }
      if (c === '"' || c === "'") { mode = "str"; quote = c; i++; continue; }
      if (c === "`") { mode = "str"; quote = "`"; stack.push({ kind: "template" }); i++; continue; }
      const top = stack[stack.length - 1];
      if (top && top.kind === "expr") {
        if (c === "{") { top.depth++; i++; continue; }
        if (c === "}") {
          if (top.depth > 0) { top.depth--; i++; continue; }
          stack.pop(); // back to the enclosing template literal's string content
          mode = "str"; quote = "`";
          i++; continue;
        }
      }
      i++; continue;
    }
    if (mode === "line") { if (c === "\n") mode = "code"; else out[i] = " "; i++; continue; }
    if (mode === "block") { if (c === "*" && d === "/") { out[i] = out[i + 1] = " "; mode = "code"; i += 2; continue; } if (c !== "\n") out[i] = " "; i++; continue; }
    if (mode === "regex") {
      if (c === "\\") { i += 2; continue; } // regex content is left as-is; only skip past it correctly
      if (c === "[") { inClass = true; i++; continue; }
      if (c === "]") { inClass = false; i++; continue; }
      if (c === "/" && !inClass) { mode = "code"; i++; while (i < src.length && /[a-z]/.test(src[i])) i++; continue; } // consume flags
      if (c === "\n") { mode = "code"; i++; continue; } // an unterminated regex cannot span a real newline
      i++; continue;
    }
    if (mode === "str") {
      if (c === "\\") { out[i] = " "; if (d !== undefined && d !== "\n") out[i + 1] = " "; i += 2; continue; }
      if (quote === "`" && c === "$" && d === "{") {
        stack.push({ kind: "expr", depth: 0 });
        mode = "code";
        i += 2; continue; // enter the interpolation as real code; $ and { need no blanking either way
      }
      if (c === quote) {
        mode = "code";
        if (quote === "`") stack.pop(); // close this template frame
        i++; continue;
      }
      if (c !== "\n") out[i] = " ";
      i++; continue;
    }
  }
  return out.join("");
};
