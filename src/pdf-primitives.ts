// Low-level PDF rendering primitives for the report writer (pdf.ts). This leaf module holds the
// page geometry, the typography scale, the brand palette, the PDF number formatting, the Helvetica
// AFM advance-width table and text measurement, the WinAnsi escaping, the line-wrapper, the
// content-stream graphics primitives (filled rect, rules, text runs) and the vector brand mark.
// Everything here was MOVED VERBATIM out of pdf.ts to keep that module under a readable size; the
// behaviour is unchanged. pdf.ts re-exports nothing from here (these are its own internals); it
// imports exactly the symbols its document-assembly and block-painting code needs.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations.

// ---- Page geometry (US Letter, points; origin bottom-left) ----------------------------------------
export const PAGE_WIDTH = 612;
export const PAGE_HEIGHT = 792;
// 72 (one inch), not 54: the margin is sized together with BODY_SIZE so the column stays a readable
// measure. A smaller body size in an unchanged (wider) column packs MORE glyphs per line, not fewer, so
// the margin widens with the type to keep the longest line within a comfortable measure (~114 glyphs in
// this 468pt column).
export const MARGIN_X = 72;
// Content pages carry chrome, so the usable band is inset from the true top/bottom by the header/footer.
// 60, not 46: the first body baseline must clear a 60pt floor from the trim, the same standard the
// trust-centre packs are held to (the console does not build a PDF, it serves these bytes), so these
// reports are held to the same floor rather than a laxer one.
export const HEADER_BAND = 60; // points reserved at the top of a content page for the running header
export const FOOTER_BAND = 40; // points reserved for the running footer; also the lowest usable y on a content page
export const CONTENT_TOP = PAGE_HEIGHT - HEADER_BAND; // first usable baseline reference on a content page
export const USABLE_WIDTH = PAGE_WIDTH - 2 * MARGIN_X; // body column width

// ---- Typography (distinct size AND leading per role; never one shared LINE_HEIGHT) ----------------
export const TITLE_SIZE = 26; // cover title
export const SUBTITLE_SIZE = 13; // cover descriptor / metadata
export const HEADING_SIZE = 13; // section heading on content pages
export const HEADING_LEAD = 19; // includes the space-above a heading wants
// 9.5, not 10, and the leading opens with it rather than staying put: dropping the size alone would make
// the page DENSER, so the leading ratio opens from 1.40 to 1.58 alongside it, keeping the page comfortably
// spaced rather than merely smaller.
export const BODY_SIZE = 9.5; // paragraph / table body
export const BODY_LEAD = 15;
export const CAPTION_SIZE = 8; // footer / fine print
export const CAPTION_LEAD = 11;
export const TABLE_HEADER_SIZE = 9;
export const TABLE_ROW_LEAD = 15; // baseline-to-baseline inside a table (one text line per row line)
export const CELL_PAD_X = 5; // horizontal padding inside a table cell
export const ROW_PAD_Y = 4; // vertical padding above/below text inside a row band

export const FONT_NAME = "Helvetica"; // standard-14 base font; no embedded font file
export const FONT_BOLD_NAME = "Helvetica-Bold"; // standard-14 base bold font; no embedded font file

// ---- Brand palette (from console tokens.css; hex -> 0..1 rgb) -------------------------------------
// Each constant is the [r,g,b] triple a PDF colour operator (rg / RG) consumes.
export type RGB = [number, number, number];
function hex(h: string): RGB {
  const n = parseInt(h, 16);
  return [((n >> 16) & 0xff) / 255, ((n >> 8) & 0xff) / 255, (n & 0xff) / 255];
}
export const INK: RGB = hex("14171d"); // --n-900 primary text
export const MUTED: RGB = hex("5b6575"); // --n-550 secondary text
export const ACCENT: RGB = hex("3b66f0"); // --a-500 action accent
export const ACCENT_DK: RGB = hex("1f40b0"); // --a-700 active accent (table header text)
export const TINT: RGB = hex("eef3ff"); // --a-50 accent tint (table header fill, cover metadata block)
export const RULE: RGB = hex("eef1f5"); // --n-100 hairline rule
export const ZEBRA: RGB = hex("f6f8fa"); // --n-50 zebra body row fill
export const LOGO: RGB = hex("0F172A"); // brand mark colour (downpipes-mark.svg stroke/fill)

// ---- PDF number formatting -----------------------------------------------------------------------
// Coordinates/colours are emitted with a fixed, locale-independent format so the bytes stay deterministic
// (toFixed(3), then trailing zeros trimmed; -0 normalised to 0).
function num(n: number): string {
  if (Object.is(n, -0)) n = 0;
  let s = n.toFixed(3);
  if (s.includes(".")) s = s.replace(/0+$/, "").replace(/\.$/, "");
  return s;
}
function rgbOp(c: RGB, op: "rg" | "RG"): string {
  return `${num(c[0])} ${num(c[1])} ${num(c[2])} ${op}`;
}

// ---- Helvetica AFM advance-width table (standard-14, 1/1000 em) -----------------------------------
// The Adobe Helvetica metrics for the WinAnsi-relevant range. Used for accurate text measurement so
// wrapping and column fitting are tight (the old single average factor over-estimated, cramping lines).
// Index is the Latin-1 code point; entries are glyph advance widths in 1/1000 of the font size.
// Helvetica and Helvetica-Bold share the SAME advance widths for the ASCII range used here EXCEPT bold is
// wider; we keep one table for the regular body (the bold runs are short headers/labels, measured with a
// small bold uplift below). Any code point not listed falls back to 556 (a safe average for Helvetica).
const HELV_W: Record<number, number> = {
  32: 278, 33: 278, 34: 355, 35: 556, 36: 556, 37: 889, 38: 667, 39: 191,
  40: 333, 41: 333, 42: 389, 43: 584, 44: 278, 45: 333, 46: 278, 47: 278,
  48: 556, 49: 556, 50: 556, 51: 556, 52: 556, 53: 556, 54: 556, 55: 556,
  56: 556, 57: 556, 58: 278, 59: 278, 60: 584, 61: 584, 62: 584, 63: 556,
  64: 1015, 65: 667, 66: 667, 67: 722, 68: 722, 69: 667, 70: 611, 71: 778,
  72: 722, 73: 278, 74: 500, 75: 667, 76: 556, 77: 833, 78: 722, 79: 778,
  80: 667, 81: 778, 82: 722, 83: 667, 84: 611, 85: 722, 86: 667, 87: 944,
  88: 667, 89: 667, 90: 611, 91: 278, 92: 278, 93: 278, 94: 469, 95: 556,
  96: 333, 97: 556, 98: 556, 99: 500, 100: 556, 101: 556, 102: 278, 103: 556,
  104: 556, 105: 222, 106: 222, 107: 500, 108: 222, 109: 833, 110: 556, 111: 556,
  112: 556, 113: 556, 114: 333, 115: 500, 116: 278, 117: 556, 118: 500, 119: 722,
  120: 500, 121: 500, 122: 500, 123: 334, 124: 260, 125: 334, 126: 584,
};
const HELV_DEFAULT_W = 556;

// textWidth measures a string's rendered width in points at a given size. The bold uplift widens the
// estimate slightly for bold runs (Helvetica-Bold advances run a touch wider than the regular table), so
// a bold heading/label never overflows its box even though we keep a single advance table.
export function textWidth(s: string, size: number, bold: boolean): number {
  let units = 0;
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    units += HELV_W[code] ?? HELV_DEFAULT_W;
  }
  const w = (units / 1000) * size;
  return bold ? w * 1.06 : w;
}

// WIN_ANSI_EXTRA maps the handful of common typographic code points that live in the WinAnsiEncoding
// upper range (0x80-0x9F), which Unicode places ABOVE U+00FF, to their WinAnsi byte. Without this the
// em-dash/en-dash/curly quotes in brand copy and operator-entered names would fall through to "?" (the
// fonts use WinAnsiEncoding, so these bytes ARE renderable). Anything not listed and outside Latin-1 still
// degrades to "?" deterministically. The byte is emitted as an octal escape so the stream stays ASCII.
const WIN_ANSI_EXTRA: Record<number, number> = {
  8364: 0x80, // euro
  8218: 0x82, // single low-9 quote
  402: 0x83, // florin
  8222: 0x84, // double low-9 quote
  8230: 0x85, // horizontal ellipsis
  8224: 0x86, // dagger
  8225: 0x87, // double dagger
  710: 0x88, // circumflex
  8240: 0x89, // per mille
  352: 0x8a, // S caron
  8249: 0x8b, // single left angle quote
  338: 0x8c, // OE
  381: 0x8e, // Z caron
  8216: 0x91, // left single quote
  8217: 0x92, // right single quote / apostrophe
  8220: 0x93, // left double quote
  8221: 0x94, // right double quote
  8226: 0x95, // bullet
  8211: 0x96, // en dash
  8212: 0x97, // em dash
  732: 0x98, // small tilde
  8482: 0x99, // trademark
  353: 0x9a, // s caron
  8250: 0x9b, // single right angle quote
  339: 0x9c, // oe
  382: 0x9e, // z caron
  376: 0x9f, // Y diaeresis
};

// escapePdfText escapes the three characters that are special inside a PDF literal string: backslash, and
// the two parentheses. Without this a value containing ")" would terminate the string early and corrupt
// the stream. It also drops bare control characters (newlines/tabs are handled by line splitting upstream),
// maps common WinAnsi-range typography (em-dash, curly quotes, ellipsis) to its WinAnsi byte via an octal
// escape so brand copy renders as intended, and replaces any remaining non-Latin-1 code point with "?" (a
// built-in font with WinAnsi encoding covers Latin-1 plus that upper band; a report's redaction-safe
// strings are control labels and operator-entered names, so this is a safe, deterministic fallback).
// ASCII (U+0000..U+007F) is emitted directly because TextEncoder writes it as one byte. The upper Latin-1
// band U+0080..U+00FF is emitted as an octal escape, NOT directly: TextEncoder (used by renderReportPDF to
// build the content stream) encodes those code points as two UTF-8 bytes, which a WinAnsi reader would
// parse as two wrong glyphs and which would inflate the stream /Length. The octal escape writes the single
// WinAnsi byte the reader expects (WinAnsi is identical to Latin-1 across U+00A0..U+00FF).
export function escapePdfText(s: string): string {
  let out = "";
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === "\\") out += "\\\\";
    else if (ch === "(") out += "\\(";
    else if (ch === ")") out += "\\)";
    else if (code < 0x20 || code === 0x7f) out += " "; // drop bare control chars to a space
    else if (code < 0x80) out += ch; // ASCII: TextEncoder writes one byte, emit directly
    else if (code <= 0xff) out += `\\${code.toString(8).padStart(3, "0")}`; // upper Latin-1 -> single WinAnsi byte via octal escape
    else if (WIN_ANSI_EXTRA[code] !== undefined) out += `\\${(WIN_ANSI_EXTRA[code] as number).toString(8).padStart(3, "0")}`; // WinAnsi upper band -> octal byte
    else out += "?"; // outside the renderable set; deterministic placeholder
  }
  return out;
}

// wrap splits a single logical string into as many lines as needed to fit within `width` points at a font
// size, breaking on spaces where possible and hard-breaking an over-long token (measured glyph-by-glyph
// via the AFM table). Deterministic; never returns an empty array (an empty input yields one empty line).
export function wrap(text: string, width: number, size: number, bold: boolean): string[] {
  const words = text.split(/\s+/).filter((w) => w.length > 0);
  if (words.length === 0) return [""];
  const lines: string[] = [];
  let cur = "";
  const fits = (s: string): boolean => textWidth(s, size, bold) <= width;
  const hardSplit = (w: string): void => {
    // Break an over-long token into width-sized chunks by accumulating glyphs until the next would overflow.
    let chunk = "";
    for (const ch of w) {
      if (chunk.length > 0 && !fits(chunk + ch)) {
        lines.push(chunk);
        chunk = ch;
      } else {
        chunk += ch;
      }
    }
    if (chunk.length > 0) cur = chunk; // the remainder seeds the current line
  };
  for (const w of words) {
    if (!fits(w)) {
      if (cur.length > 0) {
        lines.push(cur);
        cur = "";
      }
      hardSplit(w);
      continue;
    }
    const candidate = cur.length === 0 ? w : `${cur} ${w}`;
    if (!fits(candidate)) {
      if (cur.length > 0) lines.push(cur);
      cur = w;
    } else {
      cur = candidate;
    }
  }
  if (cur.length > 0) lines.push(cur);
  return lines.length > 0 ? lines : [""];
}

// ---- Content-stream graphics primitives ----------------------------------------------------------
// Each returns a fragment of PDF page content-stream operators: a filled rectangle, a stroked
// horizontal rule, a stroked rectangle outline, and a single positioned text run in a chosen font
// and colour.

// fillRect: `r g b rg  x y w h re f`, a filled rectangle (rows backgrounds, the cover metadata block).
export function fillRect(x: number, y: number, w: number, h: number, color: RGB): string {
  return `${rgbOp(color, "rg")}\n${num(x)} ${num(y)} ${num(w)} ${num(h)} re f\n`;
}

// hRule: `R G B RG  lw w  x1 y M x2 y l S`, a stroked horizontal rule (header/footer hairlines, cell
// rules, the cover accent rule).
export function hRule(x1: number, x2: number, y: number, color: RGB, lineWidth: number): string {
  return `${rgbOp(color, "RG")}\n${num(lineWidth)} w\n${num(x1)} ${num(y)} m ${num(x2)} ${num(y)} l S\n`;
}

// vRule: a stroked vertical rule (light column separators inside a table).
export function vRule(x: number, y1: number, y2: number, color: RGB, lineWidth: number): string {
  return `${rgbOp(color, "RG")}\n${num(lineWidth)} w\n${num(x)} ${num(y1)} m ${num(x)} ${num(y2)} l S\n`;
}

// textRun: a single line of coloured text at an absolute baseline, in /F1 (regular) or /F2 (bold). The
// font alias and colour are set per run (a BT/ET text object wraps all runs on a page, see composeStream).
export function textRun(x: number, baseline: number, s: string, size: number, color: RGB, bold: boolean): string {
  const font = bold ? "/F2" : "/F1";
  return `${rgbOp(color, "rg")} ${font} ${num(size)} Tf 1 0 0 1 ${num(x)} ${num(baseline)} Tm (${escapePdfText(s)}) Tj\n`;
}

// rightAlignedRun lays a text run flush to a right edge (numeric columns read right-aligned).
export function rightAlignedRun(rightX: number, baseline: number, s: string, size: number, color: RGB, bold: boolean): string {
  const x = rightX - textWidth(s, size, bold);
  return textRun(x, baseline, s, size, color, bold);
}

// ---- Brand mark (vector, translated from downpipes-mark.svg) --------------------------------------
// downpipes-mark.svg (512 viewBox, group translate(-11.5,-15), stroke-width 72):
//   rect 160,256 192x192 rx52      -> the rounded square (the downpipe outlet)
//   path M352 84 V400 (butt cap)   -> the vertical pipe/bar
//   rect 293,58 118x26 rx9 (fill)  -> the cap/lip rect at the top
// drawMark redraws those three shapes as filled vector paths scaled into a `size`-point box at (x,y)
// (y is the box's BOTTOM-LEFT, PDF origin bottom-left). The SVG y-axis points down, so we flip y. At small
// sizes a stroke becomes a thin filled bar; the rounded square is approximated by a plain filled rect with
// a small corner notch removed via an inner cut is overkill, so we draw a filled square (rounded-ish reads
// fine at header sizes). The mark is filled in `color`.
export function drawMark(x: number, y: number, size: number, color: RGB): string {
  // Map an SVG coordinate (post the group translate) into the output box. The drawable content of the
  // mark, with the stroke width accounted for, spans roughly SVG x[124..399] y[7..436] after translate;
  // we scale the full 512 box for simplicity and let the shapes sit naturally within it.
  const s = size / 512;
  const tx = -11.5;
  const ty = -15;
  // px/py map an SVG point to output space; flip Y (svgY grows downward).
  const px = (sx: number): number => x + (sx + tx) * s;
  const py = (sy: number): number => y + size - (sy + ty) * s;
  const sw = 72 * s; // stroke width in output points
  let out = `${rgbOp(color, "rg")}\n`;
  // 1) The rounded square outlet, drawn as the stroke OUTLINE of rect 160,256 192x192: four filled bars
  //    forming a square ring (so it reads as the open square the SVG strokes, not a solid block).
  const sqL = px(160);
  const sqR = px(160 + 192);
  const sqB = py(256 + 192); // bottom (larger svgY -> lower)
  const sqT = py(256); // top
  // top bar, bottom bar, left bar, right bar (each `sw` thick), composing the square outline.
  out += `${num(sqL)} ${num(sqT - sw)} ${num(sqR - sqL)} ${num(sw)} re\n`; // top
  out += `${num(sqL)} ${num(sqB)} ${num(sqR - sqL)} ${num(sw)} re\n`; // bottom
  out += `${num(sqL)} ${num(sqB)} ${num(sw)} ${num(sqT - sqB)} re\n`; // left
  out += `${num(sqR - sw)} ${num(sqB)} ${num(sw)} ${num(sqT - sqB)} re\n`; // right
  // 2) The vertical pipe: path M352 84 V400, a butt-capped stroke -> a filled bar `sw` wide centred on x352.
  const barX = px(352) - sw / 2;
  const barTop = py(84);
  const barBot = py(400);
  out += `${num(barX)} ${num(barBot)} ${num(sw)} ${num(barTop - barBot)} re\n`;
  // 3) The cap/lip rect at the top: rect 293,58 118x26 (already a filled shape in the SVG).
  const capL = px(293);
  const capR = px(293 + 118);
  const capB = py(58 + 26);
  const capT = py(58);
  out += `${num(capL)} ${num(capB)} ${num(capR - capL)} ${num(capT - capB)} re\n`;
  out += "f\n";
  return out;
}
