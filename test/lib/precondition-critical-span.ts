// precondition-critical-span.ts -- the check that the base check cannot be quietly turned back into a race.
//
// WHAT IT GUARDS, and it is a claim the code makes in prose that nothing else tests. The precondition in
// addDownpipe / removeDownpipe is atomic with the write it guards ONLY because a Durable Object's input
// gate holds concurrent events out while a STORAGE operation is in flight. That gate does NOT hold across a
// non-storage await: `interleave` diagnosed exactly this shape in the audit-chain append, where a WebCrypto
// digest sits between a head read and the write derived from it, and it is a yield point.
//
// So the span between the read of `dp:<id>` and the write of `dp:<id>` must contain STORAGE awaits and
// synchronous JS and nothing else. Today it does. A later edit that inserts a hash, a fetch, a timer or a
// blockConcurrencyWhile in the middle would reopen the window and change no test, because every functional
// assertion would still pass: the interleave it reopens cannot be driven in-process at all.
//
// IT READS CODE, NOT COMMENTS. This workspace has recorded scanners that matched a forbidden idiom inside a
// comment and reported a defect that was prose, and scanners that missed one because the comment stripping
// was wrong in the other direction. Comments and string/template literals are removed first, and the
// stripper carries its own fixtures below.

import { readFileSync } from "node:fs";

// The yield points. Each is a real await that does NOT hold the input gate: WebCrypto (the shape interleave
// found), the network, timers, and the explicit concurrency guard, which by definition ends the gate's hold.
export const YIELD_POINT_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "crypto.subtle", re: /crypto\.subtle\./ },
  { name: "a digest helper", re: /\b(auditHash|changeContentHash|sha256|sha384|digest)\s*\(/ },
  { name: "fetch", re: /\bfetch\s*\(/ },
  { name: "a timer", re: /\b(setTimeout|setInterval|scheduler\.wait)\s*\(/ },
  { name: "blockConcurrencyWhile", re: /blockConcurrencyWhile\s*\(/ },
];

// stripNonCode removes line comments, block comments, and string / template literal bodies, so a pattern can
// only ever match executable text. Deliberately simple and deliberately conservative: it never treats code
// as a comment, and the fixtures below pin both directions.
export function stripNonCode(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;
  let mode: "code" | "line" | "block" | "single" | "double" | "tmpl" = "code";
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (mode === "code") {
      if (c === "/" && d === "/") { mode = "line"; i += 2; continue; }
      if (c === "/" && d === "*") { mode = "block"; i += 2; continue; }
      if (c === "'") { mode = "single"; i += 1; out += " "; continue; }
      if (c === '"') { mode = "double"; i += 1; out += " "; continue; }
      if (c === "`") { mode = "tmpl"; i += 1; out += " "; continue; }
      out += c; i += 1; continue;
    }
    if (mode === "line") { if (c === "\n") { mode = "code"; out += "\n"; } i += 1; continue; }
    if (mode === "block") { if (c === "*" && d === "/") { mode = "code"; i += 2; continue; } if (c === "\n") out += "\n"; i += 1; continue; }
    // Inside a string or template: skip an escaped character whole, so a trailing backslash cannot end it.
    if (c === "\\") { i += 2; continue; }
    if ((mode === "single" && c === "'") || (mode === "double" && c === '"') || (mode === "tmpl" && c === "`")) { mode = "code"; i += 1; continue; }
    if (c === "\n") out += "\n";
    i += 1;
  }
  return out;
}

export interface SpanFinding { method: string; yieldPoint: string; line: number; text: string }

// scanSpan reads the executable text between `from` and `to` (both matched on the STRIPPED source, so a
// mention of either marker in a comment cannot move the span) and reports every yield point in it.
// `after` anchors the search, and it exists because of a defect this scanner had and a plant caught.
// addDownpipe reads `dp:${resolved.id}` and removeDownpipe reads `dp:${req.id}`; stripping the template
// literal bodies makes those two lines BYTE-IDENTICAL, so a bare indexOf found addDownpipe's read for BOTH
// and the delete's span was never scanned while reporting that it had been. Planting a yield point in the
// upsert reddened the DELETE's assertion at the upsert's line number, which is what gave it away. The anchor
// is the method signature, which is unique, and `found` is false if the anchor is missing rather than the
// search silently starting at zero.
export function scanSpan(strippedSrc: string, method: string, from: string, to: string, after?: string): { found: boolean; findings: SpanFinding[] } {
  let offset = 0;
  if (after !== undefined) {
    offset = strippedSrc.indexOf(stripNonCode(after));
    if (offset < 0) return { found: false, findings: [] };
  }
  strippedSrc = strippedSrc;
  // THE MARKERS ARE STRIPPED THE SAME WAY THE SOURCE IS. Both markers here contain a template literal
  // (`dp:${id}`), and the stripper removes literal bodies, so a raw marker cannot match stripped source and
  // the span would silently not be FOUND. That failure mode is the reason `found` is reported separately and
  // asserted separately: a scanner that located nothing would otherwise report zero findings and read as a
  // clean pass, which is exactly the shape "a positive control of the wrong kind" records.
  const start = strippedSrc.indexOf(stripNonCode(from), offset);
  if (start < 0) return { found: false, findings: [] };
  const end = strippedSrc.indexOf(stripNonCode(to), start);
  if (end < 0) return { found: false, findings: [] };
  const span = strippedSrc.slice(start, end);
  const before = strippedSrc.slice(0, start).split("\n").length;
  const findings: SpanFinding[] = [];
  span.split("\n").forEach((line, idx) => {
    for (const p of YIELD_POINT_PATTERNS) {
      if (p.re.test(line)) findings.push({ method, yieldPoint: p.name, line: before + idx, text: line.trim().slice(0, 120) });
    }
  });
  return { found: true, findings };
}

export function readStripped(path: string): string {
  return stripNonCode(readFileSync(path, "utf8"));
}
