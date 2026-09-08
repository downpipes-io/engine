// blankComments replaces every comment byte with a space, keeping newlines so nothing else shifts
// (an offset or a line number taken from the blanked text still points at the same place in the
// original). Quote-aware: a `//` inside a string is not a comment. blankComments alone leaves
// string and template-literal CONTENT untouched, which is right for a caller reading a path out of
// a string but leaves a hole for a caller matching a code shape (a decoy string merely naming that
// shape reads as real). blankCommentsAndStrings below closes that hole by additionally blanking the
// interior of every string and template literal.
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

// A `${...}` interpolation inside a template literal is real code, not string content, and it can
// itself contain a nested backtick template. `stack` tracks nested template/expression frames (with
// brace depth per expression) so a `${` opens an expression, `}` at depth 0 closes it back to the
// enclosing template, and a nested backtick inside the expression opens its own template frame
// rather than closing the outer one.
//
// A regex literal is the other place a bare quote-toggle misreads structure. isRegexContext uses the
// standard lookbehind heuristic (a `/` after an operator/punctuation/keyword-or-nothing is a regex;
// after an identifier, number, `)` or `]` it is division) to decide, then skips the regex body
// (respecting `[...]` character classes, where `/` need not be escaped, and `\`-escapes) and its
// trailing flags without toggling string/template mode.
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
