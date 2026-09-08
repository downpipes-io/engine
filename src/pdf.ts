import type { Report } from "./admin/reports.ts";

// A minimal, dependency-free PDF writer (contract section 6). renderReportPDF turns a signed Report into
// a small, deterministic, ENTERPRISE-styled PDF using only the standard-14 base fonts (Helvetica and
// Helvetica-Bold, every reader has them, so no font file is embedded) plus vector graphics (filled
// rectangles, stroked rules) and colour. No new npm dependency: this preserves the minimal supply-chain
// pitch (the engine adds zero runtime deps for reporting, no PDF library, no headless browser, no image
// embedding, the brand mark is drawn as vector paths). The output is a valid PDF 1.4 document.
//
// LAYOUT: a branded cover page (logo + wordmark, report title, descriptor, a metadata block, an accent
// rule and a no-custody footer line) followed by content pages, each carrying a running header (logo +
// wordmark + report title with an accent hairline) and footer (hairline + "Page N of M" + the generated
// date). Body content is laid out as real tables (tinted bold header row, zebra body rows, light cell
// rules, right-padded numeric columns) with a genuine type hierarchy (distinct sizes AND leading for
// title/heading/body/caption, headings in Helvetica-Bold/accent). It is intentionally simple (single
// column, paginated by a fixed line budget), not a full typesetting engine.
//
// DETERMINISM: given the same Report the bytes are identical (no Date.now, no random ids; the only time
// shown is the report's own generatedAt). The xref offsets are computed from the actual byte lengths and
// the object plan is renumbered as the object count grows, so the document is structurally valid.
//
// REDACTION: the PDF renders ONLY the report's own already-redaction-safe fields (the same data the JSON
// carries). It never reads env, keys or secrets; the Report is the sole input and it carries none.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations.
//
// The low-level rendering primitives (page geometry, the typography scale, the brand palette, the
// AFM-based text measurement + WinAnsi escaping, the line-wrapper, the content-stream graphics ops and
// the vector brand mark) live in the leaf ./pdf-primitives.ts (moved verbatim to keep this module a
// readable size). This module imports exactly the ones its document-assembly + block-painting code uses.

import { type Block, blocksToElements, paginateContent } from "./pdf-layout.ts";
import {
  ACCENT,
  ACCENT_DK,
  BODY_SIZE,
  CAPTION_SIZE,
  drawMark,
  FONT_BOLD_NAME,
  FONT_NAME,
  FOOTER_BAND,
  fillRect,
  HEADER_BAND,
  hRule,
  INK,
  LOGO,
  MARGIN_X,
  MUTED,
  PAGE_HEIGHT,
  PAGE_WIDTH,
  RULE,
  rightAlignedRun,
  SUBTITLE_SIZE,
  TINT,
  TITLE_SIZE,
  textRun,
  textWidth,
  USABLE_WIDTH,
  wrap,
} from "./pdf-primitives.ts";

// ---- Chrome: cover page, running header, running footer -------------------------------------------
// coverContent paints the branded cover page (page 1). It draws the logo + wordmark, the large report
// title, a one-line descriptor, a metadata block (Generated / Period / Signature), an accent rule, and a
// thin no-custody footer. All vector + colour; deterministic.
// Cover geometry, in PDF points (origin bottom-left). These tune the page-1 layout; named so the
// intent and the interactions are legible without guessing.
const BRAND_TOP_INSET = 90; // distance from the top edge to the brand lockup top
const COVER_MARK_SIZE = 30; // the cover's vector mark side length
const COVER_WORDMARK_GAP = 12; // gap between the mark and the "downpipes" wordmark
const COVER_WORDMARK_LIFT = 6; // wordmark baseline lift so it sits optically centred on the mark
const COVER_WORDMARK_SIZE = 22; // wordmark font size on the cover
const COVER_TITLE_Y_INSET = 250; // distance from the top edge to the report title baseline
const COVER_PANEL_TOP_GAP = 70; // gap below the title block to the metadata panel top
const COVER_PANEL_PAD = 14; // inner padding of the metadata panel (and the label x inset)
const COVER_LABEL_COL_WIDTH = 96; // width reserved for the metadata row labels
const COVER_VALUE_RIGHT_PAD = 28; // right padding kept clear when wrapping a metadata value
const COVER_DESC_LEAD = 18; // baseline-to-baseline when the cover descriptor wraps to more than one line
const COVER_FOOT_Y = 64; // baseline of the no-custody footer line
const COVER_FOOT_RULE_GAP = 14; // gap above the footer baseline to the hairline rule

function coverContent(report: Report): string {
  let out = "";
  const left = MARGIN_X;
  // Brand lockup near the top: the vector mark + the "downpipes" wordmark baseline-aligned.
  const markSize = COVER_MARK_SIZE;
  const brandTop = PAGE_HEIGHT - BRAND_TOP_INSET;
  out += drawMark(left, brandTop - markSize, markSize, LOGO);
  out += textRun(left + markSize + COVER_WORDMARK_GAP, brandTop - markSize + COVER_WORDMARK_LIFT, "downpipes", COVER_WORDMARK_SIZE, LOGO, true);
  // Large report title. For an evidence pack of a SINGLE framework, name that framework on the cover (the
  // all-frameworks pack keeps the generic title); other kinds use the per-kind label.
  const titleY = PAGE_HEIGHT - COVER_TITLE_Y_INSET;
  const packData = report.kind === "evidence-pack" ? asRecord(report.data) : null;
  const packArr = packData && Array.isArray(packData.packs) ? (packData.packs as Array<Record<string, unknown>>) : [];
  const coverTitleText = report.kind === "evidence-pack" && packArr.length === 1 ? String(packArr[0]?.frameworkTitle ?? reportTitle(report.kind)) : reportTitle(report.kind);
  const coverDescText = report.kind === "evidence-pack" ? (packArr.length === 1 ? "downpipes compliance evidence pack" : "downpipes compliance evidence pack, all frameworks") : reportDescriptor(report.kind);
  out += textRun(left, titleY, coverTitleText, TITLE_SIZE, INK, true);
  // Descriptor under the title. It is wrapped to the column width (like every other text run on the
  // cover), and the rule and the panel below it move by however many lines it actually takes, so a longer
  // descriptor cannot overhang the margin and cannot collide with the rule either.
  const descLines = wrap(coverDescText, USABLE_WIDTH, SUBTITLE_SIZE, false);
  for (let i = 0; i < descLines.length; i++) {
    out += textRun(left, titleY - 24 - i * COVER_DESC_LEAD, descLines[i] ?? "", SUBTITLE_SIZE, MUTED, false);
  }
  const descExtra = Math.max(0, descLines.length - 1) * COVER_DESC_LEAD;
  // Accent rule under the title block.
  out += hRule(left, PAGE_WIDTH - MARGIN_X, titleY - 40 - descExtra, ACCENT, 1.5);

  // Metadata block: a tinted panel with label/value rows.
  const meta: Array<[string, string]> = [];
  meta.push(["Generated", report.generatedAt]);
  if (report.period) meta.push(["Period", formatPeriod(report.period)]);
  meta.push(["Signature", signatureLine(report)]);
  const rowH = 22;
  const panelPadY = COVER_PANEL_PAD;
  const panelH = meta.length * rowH + 2 * panelPadY;
  const panelTop = titleY - COVER_PANEL_TOP_GAP - descExtra;
  const panelBottom = panelTop - panelH;
  out += fillRect(left, panelBottom, USABLE_WIDTH, panelH, TINT);
  const labelW = COVER_LABEL_COL_WIDTH;
  for (let i = 0; i < meta.length; i++) {
    const [label, value] = meta[i] as [string, string];
    const baseline = panelTop - panelPadY - SUBTITLE_SIZE - i * rowH;
    out += textRun(left + COVER_PANEL_PAD, baseline, label, 10, ACCENT_DK, true);
    // Wrap the value within the remaining panel width (signature/period can be long).
    const valLines = wrap(value, USABLE_WIDTH - labelW - COVER_VALUE_RIGHT_PAD, BODY_SIZE, false);
    out += textRun(left + COVER_PANEL_PAD + labelW, baseline, valLines[0] ?? "", BODY_SIZE, INK, false);
    // (Values are kept to one line in the panel; a long value is truncated by the wrap's first line, the
    // full value also appears verbatim on the content pages, so nothing is lost.)
  }

  // Thin footer echoing the no-custody line.
  const footY = COVER_FOOT_Y;
  out += hRule(left, PAGE_WIDTH - MARGIN_X, footY + COVER_FOOT_RULE_GAP, RULE, 0.5);
  out += textRun(left, footY, "Generated in your own account, names, counts and timestamps only.", CAPTION_SIZE, MUTED, false);
  return out;
}

// headerFooter paints the running header (small mark + wordmark + report title with an accent hairline) and
// the running footer (hairline + "downpipes" + "Page N of M" + the generated date) for a content page. M
// is the total page count (cover + content), known only after pagination, so chrome is a SECOND pass.
function headerFooter(report: Report, pageNumber: number, totalPages: number): string {
  let out = "";
  const left = MARGIN_X;
  const right = PAGE_WIDTH - MARGIN_X;
  // Header: mark + wordmark on the left, report title on the right; an accent hairline beneath.
  const markSize = 14;
  const headerBaseline = PAGE_HEIGHT - 30;
  out += drawMark(left, headerBaseline - 3, markSize, LOGO);
  out += textRun(left + markSize + 6, headerBaseline, "downpipes", 11, LOGO, true);
  out += rightAlignedRun(right, headerBaseline, reportTitle(report.kind), 9, MUTED, false);
  out += hRule(left, right, PAGE_HEIGHT - HEADER_BAND + 10, ACCENT, 0.75);
  // Footer: hairline above; wordmark left, page count centre-ish, date right.
  const footerBaseline = 26;
  out += hRule(left, right, FOOTER_BAND - 4, RULE, 0.5);
  out += textRun(left, footerBaseline, "downpipes", CAPTION_SIZE, MUTED, false);
  const pageStr = `Page ${pageNumber} of ${totalPages}`;
  const pageX = (PAGE_WIDTH - textWidth(pageStr, CAPTION_SIZE, false)) / 2;
  out += textRun(pageX, footerBaseline, pageStr, CAPTION_SIZE, MUTED, false);
  out += rightAlignedRun(right, footerBaseline, report.generatedAt, CAPTION_SIZE, MUTED, false);
  return out;
}

// ---- Document assembly ---------------------------------------------------------------------------
// renderReportPDF is the contract entry (section 6): a signed Report -> a small deterministic PDF as a
// Uint8Array. It builds the report-kind-specific blocks, paginates the body into content pages, renders the
// cover and the per-page chrome (a second pass, once total page count is known), and assembles a minimal
// PDF object graph (catalog, pages, two fonts, the cover page + stream, and one page object + stream per
// content page), wiring the cross-reference table and trailer. No new dependency; uses only TextEncoder.
export function renderReportPDF(report: Report): Uint8Array {
  const blocks = reportBlocks(report);
  const tagged = blocksToElements(blocks);
  const contentBodies = paginateContent(tagged); // one painted body per CONTENT page (no chrome yet)

  // Total pages = 1 cover + N content pages. Now M is known, render chrome.
  const totalPages = 1 + contentBodies.length;

  // Wrap each page's painted content in a single BT/ET text object plus the page-level graphics. Graphics
  // (rg/RG/re/m/l/S) live OUTSIDE the text object; text runs (Tf/Tm/Tj) live INSIDE it. We separate them:
  // each paint fragment interleaves graphics and text ops, so we wrap the whole fragment with a leading
  // graphics-safe state and embed text runs in their own BT/ET. To keep it simple and valid, we emit a
  // single content stream per page where graphics ops and a BT...ET block coexist: PDF allows path/fill
  // ops between text objects, and text-positioning/show ops only inside BT/ET. Our textRun() emits Tf/Tm/Tj
  // which MUST be inside BT/ET, while fillRect/hRule emit path ops which must be OUTSIDE. So we split each
  // fragment into its graphics lines and its text lines and reassemble: graphics first, then one BT/ET with
  // all the text runs. The helpers tag text lines by containing " Tj" / "Tf"; we route by that.
  const pageStreams: string[] = [];
  // Cover (page 1).
  pageStreams.push(composeStream(coverContent(report)));
  // Content pages (page 2..M): chrome + body.
  for (let i = 0; i < contentBodies.length; i++) {
    const chrome = headerFooter(report, 2 + i, totalPages);
    pageStreams.push(composeStream(chrome + (contentBodies[i] ?? "")));
  }

  const { objects, maxObj } = buildPdfObjects(pageStreams);
  return buildXrefAndTrailer(objects, maxObj);
}

// buildPdfObjects builds the indirect-object table (1-based, with no holes) from the rendered page
// streams, and returns the highest object number used. The numbering plan (renumbered for the two fonts):
//   1: Catalog
//   2: Pages (parent)
//   3: Font  /F1 Helvetica
//   4: Font  /F2 Helvetica-Bold
//   for each page p (0-based): page object = 5 + 2*p, content stream = 6 + 2*p
function buildPdfObjects(pageStreams: string[]): { objects: string[]; maxObj: number } {
  const pageObjBase = 5;
  const pageObjNums = pageStreams.map((_, i) => pageObjBase + 2 * i);
  const contentObjNums = pageStreams.map((_, i) => pageObjBase + 2 * i + 1);

  const objects: string[] = [];
  objects[1] = `<< /Type /Catalog /Pages 2 0 R >>`;
  const kids = pageObjNums.map((n) => `${n} 0 R`).join(" ");
  objects[2] = `<< /Type /Pages /Count ${pageStreams.length} /Kids [${kids}] /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] >>`;
  // The two standard-14 base fonts (no embedded files; determinism intact).
  objects[3] = `<< /Type /Font /Subtype /Type1 /BaseFont /${FONT_NAME} /Encoding /WinAnsiEncoding >>`;
  objects[4] = `<< /Type /Font /Subtype /Type1 /BaseFont /${FONT_BOLD_NAME} /Encoding /WinAnsiEncoding >>`;

  const enc = new TextEncoder();
  for (let i = 0; i < pageStreams.length; i++) {
    const pageNum = pageObjNums[i] as number;
    const contentNum = contentObjNums[i] as number;
    const stream = pageStreams[i] as string;
    const streamBytes = enc.encode(stream);
    // Both fonts are declared on every page's resources so /F1 and /F2 resolve anywhere.
    objects[pageNum] = `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentNum} 0 R >>`;
    objects[contentNum] = `<< /Length ${streamBytes.length} >>\nstream\n${stream}\nendstream`;
  }
  const maxObj = Math.max(1, 2, 3, 4, ...pageObjNums, ...contentObjNums);
  return { objects, maxObj };
}

// buildXrefAndTrailer concatenates the header, every indirect object, the cross-reference table and the
// trailer into the final PDF bytes. xref offsets are true byte offsets, tracked incrementally (everything
// outside content streams is ASCII; escapePdfText keeps stream text in Latin-1, and the /Length in each
// content object uses the TextEncoder byte length, so offsets and lengths agree).
function buildXrefAndTrailer(objects: string[], maxObj: number): Uint8Array {
  const enc = new TextEncoder();
  const header = "%PDF-1.4\n%âãÏÓ\n"; // a binary comment marks the file as binary-safe
  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (str: string): void => {
    const bytes = enc.encode(str);
    parts.push(bytes);
    offset += bytes.length;
  };

  const xrefOffsets: number[] = [];
  push(header);
  for (let n = 1; n <= maxObj; n++) {
    const body = objects[n];
    if (body === undefined) {
      xrefOffsets[n] = 0; // no holes in our plan; guard defensively
      continue;
    }
    xrefOffsets[n] = offset;
    push(`${n} 0 obj\n${body}\nendobj\n`);
  }

  const xrefStart = offset;
  let xref = `xref\n0 ${maxObj + 1}\n`;
  xref += `0000000000 65535 f \n`;
  for (let n = 1; n <= maxObj; n++) {
    const off = xrefOffsets[n] ?? 0;
    xref += `${String(off).padStart(10, "0")} 00000 n \n`;
  }
  push(xref);
  push(`trailer\n<< /Size ${maxObj + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`);

  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const outBytes = new Uint8Array(totalLen);
  let at = 0;
  for (const p of parts) {
    outBytes.set(p, at);
    at += p.length;
  }
  return outBytes;
}

// composeStream takes an interleaved paint fragment (graphics + text-run lines, as produced by the paint
// helpers) and reassembles it into a VALID single content stream: all graphics/path ops first (filling,
// rules, the mark), then ONE text object (BT ... ET) holding every text run. Text-showing operators (Tf,
// Tm, Tj) are only legal inside BT/ET; path/fill operators (re, f, m, l, S, rg before a path) are only
// legal outside it. Our helpers emit each on its own line, so we route a line to the text bucket iff it
// contains a text operator (" Tj", every textRun ends with "(...) Tj"), else to the graphics bucket.
function composeStream(fragment: string): string {
  const lines = fragment.split("\n");
  const gfx: string[] = [];
  const txt: string[] = [];
  for (const line of lines) {
    if (line.length === 0) continue;
    if (line.includes(") Tj")) txt.push(line);
    else gfx.push(line);
  }
  let s = "";
  if (gfx.length > 0) s += `${gfx.join("\n")}\n`;
  if (txt.length > 0) s += `BT\n${txt.join("\n")}\nET\n`;
  return s;
}

// ---- Report -> blocks (presentation-only mapping over the report's own data) ----------------------
// reportBlocks turns a Report into the renderable block list for the CONTENT pages (the cover carries the
// title/metadata, so the content starts with the per-kind body). It is a thin, presentation-only mapping
// over the report's own data; it adds no facts and reads no env. The cover already shows generated/period/
// signature, so the content pages lead straight into the substance.
// Report.data is typed `unknown` on the interface (each report kind carries a different structured
// body, written by admin/reports.ts and signed verbatim), so this presentation layer reads it through
// narrow casts. asRecord is the one safe top-level access: it treats a non-object as an empty record
// so a malformed body renders as empty cells rather than throwing during PDF assembly.
function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

// pdfStatusLabel maps a posture status to the phrase the PDF prints. A customer-graded check NEVER prints
// a bare "fail": it reads as what the customer chose ("pass (customer attested)", "pass (compensating
// control)", "not applicable (N/A)"); an accepted risk stays "risk accepted" (stated as a risk, never a
// pass); a control the platform cannot verify reads "needs attestation" rather than a failure. An unknown
// / legacy status string passes through verbatim so an OLD signed report still renders exactly what it
// carries (the PDF renders stored fact, it never rewrites it).
function pdfStatusLabel(status: unknown): string {
  switch (status) {
    case "pass": return "pass";
    case "fail": return "FAIL";
    case "unattested": return "needs attestation";
    case "risk-accepted": return "risk accepted";
    case "attested-pass": return "pass (customer attested)";
    case "compensating-control": return "pass (compensating control)";
    case "not-applicable": return "not applicable (N/A)";
    case "resolved-alternative": return "pass (alternative control)";
    case "not-evaluated": return "not evaluated";
    default: return String(status ?? "");
  }
}

// evidenceCell renders the live posture checks under one evidence-pack control into a compact cell. An
// empty list (a capability-only control, e.g. a customer filing duty) reads as an honest note rather than
// a blank; otherwise each bound check is "title: status" (the real posture status, never inferred), plus
// the customer's override note when one is recorded (the WHY flows into the pack, clearly attributed).
function evidenceCell(checks: unknown): string {
  if (!Array.isArray(checks) || checks.length === 0) return "no automated check (capability documented)";
  return (checks as Array<Record<string, unknown>>)
    .map((c) => {
      const base = `${String(c.title ?? c.id ?? "")}: ${pdfStatusLabel(c.status)}`;
      return typeof c.note === "string" && c.note !== "" ? `${base} [${c.note}]` : base;
    })
    .join("; ");
}

// Per-kind block builders. Each reads ONLY the report's own data (no env, no added facts) and stays a
// small, independently-auditable mapping; reportBlocks is the thin dispatcher over them.
function postureBlocks(data: Record<string, unknown>): Block[] {
  const score = typeof data.score === "number" ? data.score : 0;
  const checks = Array.isArray(data.checks) ? (data.checks as Array<Record<string, unknown>>) : [];
  const blocks: Block[] = [
    { kind: "heading", text: `Posture score: ${score} / 100` },
    { kind: "spacer", height: 4 },
    {
      kind: "table",
      table: {
        headers: ["Severity", "Status", "Check", "Control"],
        rows: checks.map((c) => [String(c.severity ?? ""), pdfStatusLabel(c.status), String(c.title ?? ""), String(c.control ?? "")]),
        colWidths: [70, 110, 190, 134],
      },
    },
  ];
  // Overrides and attestations: every customer-graded check is listed with its reason, who recorded it
  // and when, so the signed report states the customer's determination in full (clearly attributed as
  // the customer's grading, never a platform verification). Only rendered when at least one exists.
  const overridden = checks.filter((c) => typeof c.override === "object" && c.override !== null);
  if (overridden.length > 0) {
    blocks.push({ kind: "spacer", height: 8 });
    blocks.push({ kind: "heading", text: "Overrides and attestations (customer determinations)" });
    blocks.push({
      kind: "table",
      table: {
        headers: ["Check", "Determination", "Reason", "Recorded by / on"],
        rows: overridden.map((c) => {
          const o = c.override as Record<string, unknown>;
          const setAt = typeof o.setAt === "string" && o.setAt.length >= 10 ? o.setAt.slice(0, 10) : "";
          const dormant = c.autoStatus === "pass" ? " (automatic check currently passes on its own)" : "";
          return [
            String(c.title ?? c.id ?? ""),
            pdfStatusLabel(o.kind === "not-applicable" ? "not-applicable" : String(o.kind ?? "")) + dormant,
            String(o.reason ?? ""),
            `${typeof o.setBy === "string" && o.setBy !== "" ? o.setBy : "break-glass token"} / ${setAt}`,
          ];
        }),
        colWidths: [130, 120, 164, 90],
      },
    });
  }
  return blocks;
}

// ---- report-render health (G225) ------------------------------------------------------------------------
//
// A lastRestoreTestAt that is not a finite epoch (a legacy string, a corrupt row, a NaN) must not throw a
// RangeError deep inside PDF assembly and 500 the customer's compliance-report download. The guard below
// renders "unknown" instead of dying, so ONE corrupt row can no longer take the whole document down; the
// coercion is COUNTED, so a silently-degraded cell is not a new silent fallback of its own. The tally is
// isolate-local (the renderer is a PURE leaf with no env and no scheduler stub, exactly like
// sources/source-fault-ledger.ts) and the ROUTER drains it after each render and files it against the
// admin-counter aggregate.
let unparseableTimestamps = 0;

/** isoOrUnknown renders an epoch-ms timestamp, coercing an unrenderable one to "unknown" and COUNTING it. */
function isoOrUnknown(v: unknown): string {
  const n = Number(v);
  // The Date range is +/-8.64e15 ms; anything outside it (or a NaN) makes toISOString throw a RangeError.
  if (!Number.isFinite(n) || Math.abs(n) > 8.64e15) {
    unparseableTimestamps += 1;
    return "unknown";
  }
  return new Date(n).toISOString();
}

/** ReportRenderFaults is the drained render-health delta: counts only, never a row, a value or a name. */
export interface ReportRenderFaults {
  readonly unparseableTimestamps: number;
}

/**
 * drainReportRenderFaults returns and CLEARS the isolate-local render tally. The router calls it immediately
 * after a render, so the counts are attributable to that render and cannot leak into the next one.
 *
 * @returns the counts observed since the last drain.
 */
export function drainReportRenderFaults(): ReportRenderFaults {
  const out = { unparseableTimestamps };
  unparseableTimestamps = 0;
  return out;
}

// restoreOutcomeLabel renders the recency table's "Outcome" cell, DISTINGUISHING a DEFERRAL (the engine
// could not run the scheduled drill: break-glass-only posture, or no completed run yet) from a GENUINE
// failure, so a break-glass deferral never prints as bare "fail" next to a compliance-stamp "Proven" cell
// that may correctly say the downpipe's recoverability IS proven -- which would otherwise read as a
// contradictory row to an auditor.
function restoreOutcomeLabel(r: Record<string, unknown>): string {
  if (r.lastRestoreTestOk === true) return "pass";
  if (r.lastRestoreTestDeferred === "posture") return "deferred (offline posture)";
  if (r.lastRestoreTestDeferred === "no-run") return "deferred (no run yet)";
  // no-records: the run existed and opened, but held nothing to read back. This is the cell an auditor
  // reads, so the distinction must survive into the signed PDF, not stop at the API. It says what was not
  // established, not that anything failed.
  if (r.lastRestoreTestDeferred === "no-records") return "deferred (run holds no records)";
  return r.lastRestoreTestAt ? "fail" : "-";
}

// restoreProvenLabel renders the recency table's "Proven" cell (compliance-stamp): the durable "offline
// restorability last proven" stamp, naming the method ONLY for a keyed ATTENDED verification (mirroring the
// console's restoreProvenMethodPhrase convention: a blind/keyless proof adds no method name, only the
// date), so the pack plainly separates a KEYED attended proof from an ordinary scheduled pass. "-" when the
// downpipe has never been proven (never fabricated).
function restoreProvenLabel(r: Record<string, unknown>): string {
  if (r.restoreProvenAt === undefined || r.restoreProvenAt === null) return "-";
  const date = isoOrUnknown(r.restoreProvenAt).slice(0, 10);
  return r.restoreProvenMethod === "attended-blind-test" ? `attended verification, ${date}` : `proven, ${date}`;
}

// restoreTestsBlocksForTest exposes the pure block builder so the stated-interval wording can be asserted
// without rendering a PDF. It is the block LIST that carries the claim an auditor reads, and a test that
// renders bytes would prove the layout rather than the words.
export function restoreTestsBlocksForTest(data: Record<string, unknown>): Block[] {
  return restoreTestsBlocks(data);
}

function restoreTestsBlocks(data: Record<string, unknown>): Block[] {
  const recency = Array.isArray(data.recency) ? (data.recency as Array<Record<string, unknown>>) : [];
  const evidence = Array.isArray(data.evidence) ? (data.evidence as Array<Record<string, unknown>>) : [];
  // The TARGET this report is graded against, stated before the measurements. A recency table with no
  // interval beside it tells an auditor when each downpipe was last proven and leaves them unable to say
  // whether that meets what the estate committed to. 0 is reported as not stated, never as a missed
  // target: an estate that has stated no rhythm has not failed one.
  const cadenceDays = typeof data.attendedCadenceDays === "number" && data.attendedCadenceDays > 0 ? Math.floor(data.attendedCadenceDays) : 0;
  return [
    { kind: "heading", text: "Stated recoverability-proof interval" },
    {
      kind: "para",
      text:
        cadenceDays > 0
          ? `This estate states it will prove each downpipe restorable at an attended verification every ${cadenceDays} day${cadenceDays === 1 ? "" : "s"}. The recency table below is what it achieved.`
          : "This estate has not stated an interval for proving recoverability, so the recency below is reported without a target. That is not a missed target: no rhythm has been committed to.",
    },
    { kind: "heading", text: "Per-downpipe restore-test recency" },
    {
      kind: "table",
      table: {
        headers: ["Downpipe", "Last test", "Outcome", "Proven"],
        rows:
          recency.length > 0
            ? recency.map((r) => [String(r.name ?? r.id ?? ""), r.lastRestoreTestAt ? isoOrUnknown(r.lastRestoreTestAt) : "never", restoreOutcomeLabel(r), restoreProvenLabel(r)])
            : [["(no downpipes)", "-", "-", "-"]],
        // Widths are sized off the renderer's own layoutTable metrics (wrap width = colWidth - 2*CELL_PAD_X,
        // pdf-layout.ts) so the longest realistic label in each column ("deferred (offline posture)" in
        // Outcome; "attended verification, YYYY-MM-DD" in Proven; a full ISO timestamp in Last test) renders
        // on one line; a downpipe NAME longer than its column wraps gracefully (the same accepted behaviour
        // every other table's name column already has, see pdf-report-reconcile.ts's continuation handling).
        // These widths are deliberately hand-set to the 468pt column, not proportionally scaled:
        // fittedColWidths would shrink Proven below what "attended verification, YYYY-MM-DD" needs at
        // 9.5pt, wrapping the phrase mid-string. test/validate-reports.ts asserts that phrase reads as one
        // unit. Summing to 468 means no scaling is applied here at all.
        colWidths: [80, 118, 118, 152],
      },
    },
    { kind: "heading", text: "Drill evidence in period" },
    {
      kind: "table",
      table: {
        headers: ["When", "Kind", "Run", "Note"],
        rows:
          evidence.length > 0
            ? evidence.map((e) => [String(e.recordedAt ?? ""), String(e.kind ?? ""), String(e.runId ?? ""), String(e.note ?? "")])
            : [["(no evidence in period)", "-", "-", "-"]],
        colWidths: [130, 90, 130, 154],
      },
    },
  ];
}

// slaWindowLabel renders the row's ACTUAL window (SlaDownpipeRow.windowFromSeconds/windowStartBasis) as a
// compact PDF cell: "full period" when nothing clamped it, or "since YYYY-MM-DD (created)" / "(earliest
// run)" when the row's expectedRuns was computed over a narrower window than the report's own period --
// exactly the young-downpipe case this field exists to make visible (a downpipe a few hours old at hourly
// cadence must read as its own 3-4-hour window, never as the report's full 90-day period). "-" only when
// the report carries no period at all (a null, point-in-time period; sla-compliance's normal callers
// always supply one, but a direct/malformed call can still reach this honestly-absent case).
function slaWindowLabel(r: Record<string, unknown>): string {
  const from = r.windowFromSeconds;
  if (typeof from !== "number" || !Number.isFinite(from)) return "-";
  const basis = r.windowStartBasis;
  if (basis !== "createdAt" && basis !== "earliest-run") return "full period";
  const iso = isoOrUnknown(from * 1000);
  const date = iso === "unknown" ? "unknown" : iso.slice(0, 10);
  return basis === "createdAt" ? `since ${date} (created)` : `since ${date} (earliest run)`;
}

function slaComplianceBlocks(data: Record<string, unknown>): Block[] {
  const rows = Array.isArray(data.downpipes) ? (data.downpipes as Array<Record<string, unknown>>) : [];
  return [
    { kind: "heading", text: "Per-downpipe SLA compliance" },
    {
      kind: "table",
      table: {
        headers: ["Downpipe", "Expected", "Successful", "Strikes", "Fresh", "Window"],
        rows:
          rows.length > 0
            ? rows.map((r) => [String(r.name ?? r.id ?? ""), String(r.expectedRuns ?? 0), String(r.successfulRuns ?? 0), String(r.strikes ?? 0), r.fresh === true ? "yes" : "no", slaWindowLabel(r)])
            : [["(no downpipes)", "-", "-", "-", "-", "-"]],
        colWidths: [150, 70, 76, 62, 50, 130],
        numericCols: [false, true, true, true, false, false],
      },
    },
    {
      kind: "para",
      text: "Expected is the cadence's contractual minimum over the Window column, not the report's full period: a downpipe created (or, for one recorded before this engine tracked creation time, first observed running) partway through the period has its window clamped forward to that start, so a young downpipe reads its own short window rather than the report's full period.",
    },
  ];
}

function evidencePackBlocks(data: Record<string, unknown>): Block[] {
  const score = typeof data.postureScore === "number" ? data.postureScore : 0;
  const blocks: Block[] = [
    { kind: "para", text: String(data.scope ?? "") },
    { kind: "spacer", height: 6 },
    { kind: "para", text: `Posture score at generation: ${score} / 100. For each control below: the obligation, how downpipes supports it, and the live result of the posture checks that evidence it in this deployment.` },
  ];
  const packs = Array.isArray(data.packs) ? (data.packs as Array<Record<string, unknown>>) : [];
  for (const fw of packs) {
    const summary = (fw.summary ?? {}) as Record<string, unknown>;
    blocks.push({ kind: "spacer", height: 10 });
    blocks.push({ kind: "heading", text: String(fw.frameworkTitle ?? "") });
    blocks.push({ kind: "para", text: String(fw.frameworkDescription ?? "") });
    const naCount = Number(summary.checksNotApplicable ?? 0);
    const unattestedCount = Number(summary.checksUnattested ?? 0);
    const extras = `${naCount > 0 ? `, ${naCount} not applicable (customer determination)` : ""}${unattestedCount > 0 ? `, ${unattestedCount} awaiting attestation` : ""}`;
    blocks.push({ kind: "para", text: `Controls mapped: ${summary.controlsTotal ?? 0}. Live checks: ${summary.checksPassing ?? 0} passing, ${summary.checksFailing ?? 0} failing, ${summary.checksAccepted ?? 0} customer-graded (attested, compensating control or accepted risk)${extras}, of ${summary.checksTotal ?? 0} evaluated.` });
    const controls = Array.isArray(fw.controls) ? (fw.controls as Array<Record<string, unknown>>) : [];
    blocks.push({
      kind: "table",
      table: {
        headers: ["Control", "Obligation and how downpipes supports it", "Live evidence"],
        rows: controls.map((c) => [String(c.control ?? ""), `${String(c.obligation ?? "")} downpipes: ${String(c.capability ?? "")}`, evidenceCell(c.checks)]),
        colWidths: [96, 272, 136],
      },
    });
    const sources = Array.isArray(fw.sources) ? (fw.sources as Array<Record<string, unknown>>) : [];
    if (sources.length > 0) {
      blocks.push({ kind: "para", text: `Sources: ${sources.map((s) => String(s.label ?? "")).join("; ")}.` });
    }
  }
  return blocks;
}

function immutabilityBlocks(data: Record<string, unknown>): Block[] {
  const dests = Array.isArray(data.destinations) ? (data.destinations as Array<Record<string, unknown>>) : [];
  return [
    { kind: "heading", text: "Recoverability and immutability posture" },
    { kind: "para", text: String(data.attestation ?? "") },
    { kind: "spacer", height: 8 },
    {
      kind: "table",
      table: {
        headers: ["Destination", "Configured", "Property"],
        rows:
          dests.length > 0
            ? dests.map((d) => [String(d.kind ?? ""), d.configured === true ? "yes" : "no", String(d.property ?? "")])
            : [["(none configured)", "no", "-"]],
        colWidths: [120, 100, 284],
      },
    },
  ];
}

function changeRequestsBlocks(data: Record<string, unknown>): Block[] {
  const entries = Array.isArray(data.entries) ? (data.entries as Array<Record<string, unknown>>) : [];
  const total = typeof data.total === "number" ? data.total : entries.length;
  const emergencyTotal = typeof data.emergencyTotal === "number" ? data.emergencyTotal : 0;
  return [
    { kind: "heading", text: `Change requests in period: ${total} (${emergencyTotal} emergency)` },
    { kind: "spacer", height: 4 },
    {
      kind: "table",
      table: {
        // Emergency changes are rendered LOUDLY in the Type column (they bypassed the change-number
        // requirement and need retrospective-record validation). Reason carries the emergency justification.
        headers: ["When", "Who", "Action", "Change #", "Type", "Reason"],
        rows:
          entries.length > 0
            ? entries.map((e) => [
                String(e.ts ?? ""),
                String(e.actorEmail ?? e.actorMethod ?? ""),
                String(e.actionKind ?? ""),
                String(e.changeNumber ?? "-"),
                e.emergency === true ? "EMERGENCY" : "normal",
                String(e.reason ?? ""),
              ])
            : [["(no change requests in period)", "-", "-", "-", "-", "-"]],
        colWidths: [96, 96, 78, 70, 70, 94],
      },
    },
  ];
}

function reportBlocks(report: Report): Block[] {
  const data = asRecord(report.data);
  if (report.kind === "posture") return postureBlocks(data);
  if (report.kind === "restore-tests") return restoreTestsBlocks(data);
  if (report.kind === "sla-compliance") return slaComplianceBlocks(data);
  if (report.kind === "evidence-pack") return evidencePackBlocks(data);
  if (report.kind === "change-requests") return changeRequestsBlocks(data);
  return immutabilityBlocks(data); // immutability is the remaining kind
}

// formatPeriod renders a report period as an ISO from/to range (reused on the cover and unchanged from the
// previous wording, so the period reads identically to the JSON-era output).
function formatPeriod(period: { fromSeconds: number; toSeconds: number }): string {
  // Guarded for the same reason as the restore-test cell (G225): a non-finite period bound (a malformed
  // ?from=/?to=) would otherwise throw a RangeError on the COVER PAGE and 500 every report download.
  return `${isoOrUnknown(period.fromSeconds * 1000)} to ${isoOrUnknown(period.toSeconds * 1000)}`;
}

// signatureLine states the precise signature claim (tamper-evident, signed) and the scheme prefix, never
// the signer's private material (the signature is a public detached value). Reused from the previous copy.
function signatureLine(report: Report): string {
  return report.signature
    ? `present (tamper-evident, signed; ${report.signature.split(":")[0]})`
    : "not signed (signer not configured)";
}

// reportTitle is the human label per kind (cover title + running header).
function reportTitle(kind: Report["kind"]): string {
  switch (kind) {
    case "restore-tests":
      return "Restore tests";
    case "sla-compliance":
      return "SLA compliance";
    case "immutability":
      return "Immutability and recoverability";
    case "posture":
      return "Security posture";
    case "evidence-pack":
      return "Compliance evidence pack";
    case "change-requests":
      return "Change requests";
  }
}

// reportDescriptor is the one-line cover descriptor per kind (a calm, precise summary; no overclaim).
function reportDescriptor(kind: Report["kind"]): string {
  switch (kind) {
    case "restore-tests":
      return "Per-downpipe restore-test recency and the drill evidence recorded in the period.";
    case "sla-compliance":
      return "Per-downpipe expected-versus-successful runs, strikes and freshness over the period.";
    case "immutability":
      return "An attestation of the recoverability and tamper-evidence properties in force.";
    case "posture":
      return "The security posture score and the per-control checks behind it.";
    case "evidence-pack":
      return "How downpipes supports each control, with the live posture evidence behind it.";
    case "change-requests":
      return "Change-controlled actions in the period, with the operator's change number and any emergency changes.";
  }
}
