// The report body block model and its painting/pagination machinery for the PDF writer (pdf.ts). A
// Block is a heading/para/caption/spacer/table; blocksToElements flattens the block list into measured,
// paintable Elements, and paginateContent slices those into content pages. Everything here was MOVED
// VERBATIM out of pdf.ts to keep that module a readable size; the behaviour is unchanged. pdf.ts imports
// Block/Table (to build the per-report block list) and blocksToElements/paginateContent (to lay it out).
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations.

import {
  ACCENT,
  ACCENT_DK,
  BODY_LEAD,
  BODY_SIZE,
  CAPTION_LEAD,
  CAPTION_SIZE,
  CELL_PAD_X,
  CONTENT_TOP,
  FOOTER_BAND,
  fillRect,
  HEADING_LEAD,
  HEADING_SIZE,
  hRule,
  INK,
  MARGIN_X,
  MUTED,
  ROW_PAD_Y,
  RULE,
  rightAlignedRun,
  TABLE_HEADER_SIZE,
  TABLE_ROW_LEAD,
  TINT,
  textRun,
  USABLE_WIDTH,
  vRule,
  wrap,
  ZEBRA,
} from "./pdf-primitives.ts";

// ---- Block model (the renderable report body) ----------------------------------------------------
// A Table is a fixed-column-width table; numericCols marks columns to right-align.
export interface Table {
  headers: string[];
  rows: string[][];
  colWidths: number[]; // per-column width in points, left-aligned; a sum over USABLE_WIDTH is SCALED to fit
  numericCols?: boolean[]; // per-column: right-align this column's body cells (numbers read right-aligned)
}

// Block is one element of the report body. The renderer measures each block's height, paginates, then
// paints it (so a table can draw its own zebra/rules at the right y).
export type Block =
  | { kind: "heading"; text: string }
  | { kind: "para"; text: string }
  | { kind: "caption"; text: string } // muted fine print (e.g. the attestation note)
  | { kind: "spacer"; height: number }
  | { kind: "table"; table: Table };

// ---- Painting: a placed element knows its own height and how to draw at a top y ------------------
// blocksToElements flattens blocks into measured, paintable elements. Each element has a height (points)
// and a paint(topY) -> content-stream string that draws it with its top edge at topY (y decreasing as we
// go down the page). Pagination then slices the elements into pages by the usable content height.
interface Element {
  height: number;
  paint: (topY: number) => string;
  // breakable: a table body may split across a page boundary; a heading/para is atomic. For simplicity we
  // keep single rows atomic and let a *table* be one element only when it fits; otherwise we split it into
  // per-row elements (header row repeated) so large tables paginate cleanly.
}

function headingElement(text: string): Element {
  return {
    height: HEADING_LEAD,
    paint: (topY) => {
      // space-above is baked into HEADING_LEAD; baseline sits a little below the top of the band.
      const baseline = topY - HEADING_SIZE - 4;
      return textRun(MARGIN_X, baseline, text, HEADING_SIZE, ACCENT, true);
    },
  };
}

function paraElements(text: string): Element[] {
  const lines = wrap(text, USABLE_WIDTH, BODY_SIZE, false);
  return lines.map((line) => ({
    height: BODY_LEAD,
    paint: (topY: number) => textRun(MARGIN_X, topY - BODY_SIZE, line, BODY_SIZE, INK, false),
  }));
}

function captionElements(text: string): Element[] {
  const lines = wrap(text, USABLE_WIDTH, CAPTION_SIZE, false);
  return lines.map((line) => ({
    height: CAPTION_LEAD,
    paint: (topY: number) => textRun(MARGIN_X, topY - CAPTION_SIZE, line, CAPTION_SIZE, MUTED, false),
  }));
}

function spacerElement(height: number): Element {
  return { height, paint: () => "" };
}

// Pre-wrap a table into laid-out rows so each row's height (and the whole table's geometry) is known for
// pagination. A row is the wrapped cell text per column + the row height (tallest cell).
interface LaidRow {
  cells: string[][]; // per-column wrapped lines
  height: number; // band height in points (text + vertical padding)
  isHeader: boolean;
}

// Table.colWidths are ABSOLUTE POINTS chosen by each caller, and nothing enforces that their sum stays
// within USABLE_WIDTH: a table sized for a wider column would silently overrun the current one, pushing ink
// past the right margin while the LEFT margin measures correctly - a page that looks lopsided rather than
// obviously broken. Scaling here means a table can never outrun its column no matter what a caller passes,
// including future callers.
export function fittedColWidths(table: Table): number[] {
  const sum = table.colWidths.reduce((a, b) => a + b, 0);
  if (!(sum > USABLE_WIDTH)) return table.colWidths;
  const k = USABLE_WIDTH / sum;
  return table.colWidths.map((w) => w * k);
}

function layoutTable(table: Table): { colX: number[]; colW: number[]; totalW: number; rows: LaidRow[] } {
  const colW = fittedColWidths(table);
  const colX: number[] = [];
  let x = MARGIN_X;
  for (const w of colW) {
    colX.push(x);
    x += w;
  }
  const totalW = x - MARGIN_X;
  const layRow = (cells: string[], isHeader: boolean): LaidRow => {
    const size = isHeader ? TABLE_HEADER_SIZE : BODY_SIZE;
    const bold = isHeader;
    const wrapped = cells.map((c, i) => wrap(c, (colW[i] ?? USABLE_WIDTH) - 2 * CELL_PAD_X, size, bold));
    const lineCount = Math.max(1, ...wrapped.map((w) => w.length));
    const height = lineCount * TABLE_ROW_LEAD + 2 * ROW_PAD_Y;
    return { cells: wrapped, height, isHeader };
  };
  const rows: LaidRow[] = [layRow(table.headers, true)];
  for (const r of table.rows) rows.push(layRow(r, false));
  return { colX, colW, totalW, rows };
}

// paintRow draws one table row band with its top edge at topY: a fill (tint for header, zebra for odd body
// rows), the cell text (bold accent-dk for the header, ink for the body; right-aligned for numeric cols),
// and a bottom hairline. Column separators and the outer frame are drawn by the table element across the
// whole block, not per row.
function paintRow(row: LaidRow, table: Table, colX: number[], colW: number[], totalW: number, topY: number, zebra: boolean): string {
  const size = row.isHeader ? TABLE_HEADER_SIZE : BODY_SIZE;
  const bottom = topY - row.height;
  let out = "";
  // Background fill.
  if (row.isHeader) out += fillRect(MARGIN_X, bottom, totalW, row.height, TINT);
  else if (zebra) out += fillRect(MARGIN_X, bottom, totalW, row.height, ZEBRA);
  // Cell text.
  const numeric = table.numericCols ?? [];
  for (let col = 0; col < row.cells.length; col++) {
    const lines = row.cells[col] ?? [];
    const cellLeft = (colX[col] ?? MARGIN_X) + CELL_PAD_X;
    const cellRight = (colX[col] ?? MARGIN_X) + (colW[col] ?? USABLE_WIDTH) - CELL_PAD_X;
    const rightAlign = !row.isHeader && numeric[col] === true;
    for (let li = 0; li < lines.length; li++) {
      const baseline = topY - ROW_PAD_Y - size - li * TABLE_ROW_LEAD;
      const text = lines[li] ?? "";
      if (text.length === 0) continue;
      if (row.isHeader) out += textRun(cellLeft, baseline, text, size, ACCENT_DK, true);
      else if (rightAlign) out += rightAlignedRun(cellRight, baseline, text, size, INK, false);
      else out += textRun(cellLeft, baseline, text, size, INK, false);
    }
  }
  // Bottom hairline of the row.
  out += hRule(MARGIN_X, MARGIN_X + totalW, bottom, RULE, 0.5);
  return out;
}

// tableElements turns a table into per-row Elements (header repeated at the top of a continued page is
// handled by the paginator re-emitting a header element when a table is split). Each row is its own
// element; the FIRST row element also paints the table's top hairline + left/right frame for its band, and
// every body element paints its column separators. The outer left/right frame is drawn per-row band (a
// short vertical segment) so a split table stays framed on each page.
function tableElements(table: Table): Element[] {
  const { colX, colW, totalW, rows } = layoutTable(table);
  const els: Element[] = [];
  const frameAndSeps = (topY: number, height: number): string => {
    let out = "";
    const bottom = topY - height;
    // left + right frame for this band.
    out += vRule(MARGIN_X, topY, bottom, RULE, 0.5);
    out += vRule(MARGIN_X + totalW, topY, bottom, RULE, 0.5);
    // interior column separators (skip the first left edge).
    for (let c = 1; c < colX.length; c++) out += vRule(colX[c] as number, topY, bottom, RULE, 0.5);
    return out;
  };
  for (let idx = 0; idx < rows.length; idx++) {
    const row = rows[idx] as LaidRow;
    const zebra = !row.isHeader && idx % 2 === 0; // header is idx 0; first body row (idx 1) is plain, idx 2 zebra...
    els.push({
      height: row.height,
      paint: (topY: number) => {
        let out = "";
        // The header row paints a top hairline for the table.
        if (row.isHeader) out += hRule(MARGIN_X, MARGIN_X + totalW, topY, RULE, 0.5);
        out += paintRow(row, table, colX, colW, totalW, topY, zebra);
        out += frameAndSeps(topY, row.height);
        return out;
      },
    });
  }
  return els;
}

// blocksToElements flattens the block list into a flat element list, tagging table boundaries so the
// paginator can repeat a table's header row at the top of a continued page. We return elements plus, for
// each element, an optional "tableHeader" element to repeat when a break falls mid-table.
interface TaggedElement {
  el: Element;
  tableHeaderRepeat?: Element; // when this element is a continued table-body row, the header to re-emit on a page break
  isTableHeader?: boolean; // this element IS a table's header row, so it must never be the last thing on a page
}

export function blocksToElements(blocks: Block[]): TaggedElement[] {
  const out: TaggedElement[] = [];
  for (const b of blocks) {
    if (b.kind === "heading") out.push({ el: headingElement(b.text) });
    else if (b.kind === "para") for (const e of paraElements(b.text)) out.push({ el: e });
    else if (b.kind === "caption") for (const e of captionElements(b.text)) out.push({ el: e });
    else if (b.kind === "spacer") out.push({ el: spacerElement(b.height) });
    else {
      const els = tableElements(b.table);
      const headerEl = els[0]; // the header row element, to repeat across a page break
      els.forEach((el, idx) => {
        out.push({ el, ...(idx > 0 && headerEl ? { tableHeaderRepeat: headerEl } : {}), ...(idx === 0 ? { isTableHeader: true } : {}) });
      });
    }
  }
  return out;
}

// paginateContent slices the tagged elements into pages of {topY, content-string} given the usable content
// band on a content page. When an element does not fit on the current page, a new page begins; if that
// element is a continued table-body row, the table header is re-emitted at the top of the new page first.
// Returns one painted content fragment per content page (chrome is added later).
export function paginateContent(tagged: TaggedElement[]): string[] {
  const pages: string[] = [];
  let buf = "";
  let y = CONTENT_TOP;
  const usable = CONTENT_TOP - FOOTER_BAND;
  const flush = (): void => {
    pages.push(buf);
    buf = "";
    y = CONTENT_TOP;
  };
  for (let ti = 0; ti < tagged.length; ti++) {
    const t = tagged[ti] as TaggedElement;
    const h = t.el.height;
    // KEEP A TABLE HEADER WITH ITS FIRST ROW. A header row is an element like any other, so placing it
    // whenever it fits can leave the first body row to start a new page: the reader meets the header alone
    // above dead space at the foot of one page and again at the top of the next. Breaking BEFORE the header
    // costs the same whitespace but spends it where it reads as a page break rather than as a mistake.
    const next = tagged[ti + 1];
    if (t.isTableHeader === true && next !== undefined && buf.length > 0 && y - h - next.el.height < FOOTER_BAND) {
      flush();
    }
    // If it doesn't fit and we've placed something, start a new page.
    if (y - h < FOOTER_BAND && buf.length > 0) {
      flush();
      // Re-emit a table header at the top of the continued page. ASSUMPTION: a repeated table header is
      // always shorter than the content band (it is a single row by construction), so the re-emit cannot
      // itself overflow FOOTER_BAND; a pathologically tall header (many wrapped lines) is out of scope.
      if (t.tableHeaderRepeat) {
        buf += t.tableHeaderRepeat.paint(y);
        y -= t.tableHeaderRepeat.height;
      }
    }
    // An element taller than a whole page (pathological) is placed at the top and allowed to overflow the
    // band; pagination stays arithmetic and the content never silently vanishes.
    if (h > usable && buf.length === 0) {
      buf += t.el.paint(y);
      flush();
      continue;
    }
    buf += t.el.paint(y);
    y -= h;
  }
  if (buf.length > 0) flush();
  if (pages.length === 0) pages.push(""); // always at least one content page
  return pages;
}
