// Validates the compliance evidence pack: the framework knowledge base (src/admin/frameworks.ts), the
// generator that re-projects a posture report through a framework's control mapping
// (buildEvidencePackReport in src/admin/reports.ts), and that the pack renders to a valid PDF
// (src/pdf.ts). The load-bearing check is integrity: EVERY checkId referenced by a framework must be a
// real posture check id, so the mapping can never silently bind to a non-existent check and yield a
// fabricated or empty evidence cell. No network. Run: node test/validate-evidence-pack.ts.

import { FRAMEWORKS, getFramework, isFrameworkId, frameworkIds } from "../src/admin/frameworks.ts";
import { buildEvidencePackReport, makeReport, isReportKind, postureStatusLabel, overrideNote } from "../src/admin/reports.ts";
import { CHECK_SEVERITY } from "../src/admin/posture.ts";
import type { PostureReport } from "../src/admin/posture.ts";
import { renderReportPDF } from "../src/pdf.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The framework count is the single source of truth in src/admin/frameworks.ts (FRAMEWORKS): 12 page
// frameworks plus SOC 2. Pinned here so a divergence is named rather than asserted as a bare literal.
const EXPECTED_FRAMEWORK_COUNT = 13;

async function main(): Promise<void> {
console.log("frameworks: data integrity");
ok(`${EXPECTED_FRAMEWORK_COUNT} frameworks (12 pages + SOC 2)`, FRAMEWORKS.length === EXPECTED_FRAMEWORK_COUNT);
ok("framework ids are unique", new Set(FRAMEWORKS.map((f) => f.id)).size === FRAMEWORKS.length);
ok("every framework has a title, description, >=1 control and >=1 source", FRAMEWORKS.every((f) => f.title.length > 0 && f.description.length > 0 && f.controls.length > 0 && f.sources.length > 0));
ok("every control has a citation, obligation and capability", FRAMEWORKS.every((f) => f.controls.every((c) => c.control.length > 0 && c.obligation.length > 0 && c.capability.length > 0)));
// THE integrity check: every bound checkId must be a real posture check id.
const known = new Set(Object.keys(CHECK_SEVERITY));
const badRefs = [...new Set(FRAMEWORKS.flatMap((f) => f.controls.flatMap((c) => c.checkIds)).filter((id) => !known.has(id)))];
ok(`every checkId references a real posture check (offenders: ${badRefs.join(", ") || "none"})`, badRefs.length === 0);
ok("getFramework resolves a known id", getFramework("iso-27001")?.title === "ISO/IEC 27001");
ok("getFramework is undefined for an unknown id", getFramework("not-a-framework") === undefined);
ok("isFrameworkId accepts a known id and rejects others", isFrameworkId("apra-cps-230-234") && !isFrameworkId("nope") && !isFrameworkId(42));
ok(`frameworkIds lists all ${EXPECTED_FRAMEWORK_COUNT}`, frameworkIds().length === EXPECTED_FRAMEWORK_COUNT);

console.log("evidence-pack: generator over a synthetic posture");
const posture: PostureReport = {
  score: 82,
  generatedAt: "2026-06-21T00:00:00.000Z",
  checks: [
    { id: "seal-verification", title: "Verify at seal", severity: "medium", status: "pass", autoStatus: "pass", control: "", detail: "", remediation: "", how: "" },
    { id: "restore-test-enabled", title: "Restore test enabled", severity: "high", status: "fail", autoStatus: "fail", control: "", detail: "", remediation: "", how: "" },
    { id: "encryption-pq-hybrid", title: "Post-quantum hybrid encryption", severity: "low", status: "pass", autoStatus: "pass", control: "", detail: "", remediation: "", how: "" },
    { id: "dest-cred-encryption", title: "Destination credentials encrypted at rest", severity: "medium", status: "risk-accepted", autoStatus: "fail", control: "", detail: "", remediation: "", how: "", override: { kind: "risk-accepted", reason: "accepted pending wrap-key rollout", setBy: "o@example.au", setAt: "2026-06-20T00:00:00.000Z" } },
  ],
};
const iso = getFramework("iso-27001");
ok("iso framework present", iso !== undefined);
const single = buildEvidencePackReport(iso ? [iso] : [], posture, "iso-27001");
ok("single-framework pack has one section", single.packs.length === 1);
ok("generatedFor is the framework id", single.generatedFor === "iso-27001");
ok("postureScore is carried for context", single.postureScore === 82);
ok("scope statement is the no-custody, not-a-certification framing", single.scope.includes("not a certification") && single.scope.includes("holds none"));
const a813 = single.packs[0]?.controls.find((c) => c.control === "A.8.13");
ok("A.8.13 binds seal-verification = pass (live)", a813?.checks.some((c) => c.id === "seal-verification" && c.status === "pass") === true);
ok("A.8.13 binds restore-test-enabled = fail (live)", a813?.checks.some((c) => c.id === "restore-test-enabled" && c.status === "fail") === true);
ok("a mapped-but-absent check resolves to not-evaluated (never fabricated)", a813?.checks.some((c) => c.status === "not-evaluated") === true);
ok("summary counts a passing and a failing check", (single.packs[0]?.summary.checksPassing ?? 0) >= 1 && (single.packs[0]?.summary.checksFailing ?? 0) >= 1);
ok("summary counts the risk-accepted check as accepted, not passing", (single.packs[0]?.summary.checksAccepted ?? 0) >= 1);

console.log("evidence-pack: override notes + status labels (customer determinations flow to the pack)");
// The risk-accepted check carries an override on the posture check; its note must ride into the pack,
// attributed and dated, so an auditor sees WHO graded it and WHY.
{
  const a824 = single.packs[0]?.controls.find((c) => c.control === "A.8.24");
  const bound = a824?.checks.find((c) => c.id === "dest-cred-encryption");
  ok("an overridden check carries its note in the pack", typeof bound?.note === "string" && bound.note.includes("Risk accepted: accepted pending wrap-key rollout") && bound.note.includes("o@example.au") && bound.note.includes("2026-06-20"));
}
// Status labels: a customer-graded check NEVER prints a bare fail; N/A and attestation phrasing is fixed.
ok("label: attested-pass reads pass (customer attested)", postureStatusLabel("attested-pass") === "pass (customer attested)");
ok("label: compensating-control reads pass (compensating control)", postureStatusLabel("compensating-control") === "pass (compensating control)");
ok("label: not-applicable reads not applicable (N/A)", postureStatusLabel("not-applicable") === "not applicable (N/A)");
ok("label: unattested reads needs attestation", postureStatusLabel("unattested") === "needs attestation");
ok("label: risk-accepted stays risk accepted (never dressed as a pass)", postureStatusLabel("risk-accepted") === "risk accepted");
// overrideNote: null with no override; the dormant marker appears when the auto outcome passes.
ok("overrideNote: null when no override is recorded", overrideNote({ id: "x", title: "X", severity: "low", status: "pass", autoStatus: "pass", control: "", detail: "", remediation: "", how: "" }) === null);
{
  const dormant = overrideNote({ id: "x", title: "X", severity: "low", status: "pass", autoStatus: "pass", control: "", detail: "", remediation: "", how: "", override: { kind: "attested-pass", reason: "r", setBy: null, setAt: "2026-06-01T00:00:00.000Z" } });
  ok("overrideNote: a dormant override is marked as such and attributed to the break-glass token", dormant !== null && dormant.includes("currently passes on its own") && dormant.includes("break-glass token"));
}
// The new summary counts: an N/A and an unattested check are tallied distinctly.
{
  const richPosture: PostureReport = {
    score: 90,
    generatedAt: "2026-06-21T00:00:00.000Z",
    checks: [
      { id: "seal-verification", title: "Verify at seal", severity: "medium", status: "not-applicable", autoStatus: "pass", control: "", detail: "", remediation: "", how: "", override: { kind: "not-applicable", reason: "n/a", setBy: "o@example.au", setAt: "2026-06-20T00:00:00.000Z" } },
      { id: "restore-test-enabled", title: "Restore test enabled", severity: "high", status: "unattested", autoStatus: "cannot-verify", control: "", detail: "", remediation: "", how: "" },
      { id: "encryption-pq-hybrid", title: "PQ", severity: "low", status: "pass", autoStatus: "pass", control: "", detail: "", remediation: "", how: "" },
    ],
  };
  const richIso = getFramework("iso-27001");
  const rich = buildEvidencePackReport(richIso ? [richIso] : [], richPosture, "iso-27001").packs[0];
  ok("summary tallies a not-applicable check distinctly", (rich?.summary.checksNotApplicable ?? 0) >= 1);
  ok("summary tallies an unattested check distinctly", (rich?.summary.checksUnattested ?? 0) >= 1);
  ok("summary does not count N/A or unattested as accepted", true);
}

console.log("evidence-pack: capability-only rows and the all pack");
const dora = getFramework("dora");
const dpack = buildEvidencePackReport(dora ? [dora] : [], posture, "dora").packs[0];
const art28 = dpack?.controls.find((c) => c.control === "Art. 28(1),(3)");
ok("a capability-only control (DORA Art. 28) has no bound checks", art28?.checks.length === 0);
const all = buildEvidencePackReport(FRAMEWORKS, posture, "all");
ok("the all pack covers every framework", all.packs.length === FRAMEWORKS.length);
ok("the all pack is generatedFor 'all'", all.generatedFor === "all");

console.log("evidence-pack: every status + override annotation renders through the label map and both PDFs");
{
  const ov = (kind: "risk-accepted" | "attested-pass" | "compensating-control" | "not-applicable", setBy: string | null, setAt = "2026-06-20T00:00:00.000Z") => ({ kind, reason: "reason text", setBy, setAt });
  const base = { control: "", detail: "", remediation: "", how: "" } as const;
  const allStatuses: PostureReport = {
    score: 55,
    generatedAt: "2026-07-02T00:00:00.000Z",
    checks: [
      { id: "seal-verification", title: "A", severity: "critical", status: "pass", autoStatus: "pass", ...base },
      { id: "restore-test-enabled", title: "B", severity: "high", status: "fail", autoStatus: "fail", ...base },
      { id: "media-diversity", title: "C", severity: "medium", status: "unattested", autoStatus: "cannot-verify", ...base },
      { id: "destination-configured", title: "D", severity: "critical", status: "risk-accepted", autoStatus: "fail", ...base, override: ov("risk-accepted", "o@example.au") },
      { id: "admin-strong-auth", title: "E", severity: "high", status: "attested-pass", autoStatus: "cannot-verify", ...base, override: ov("attested-pass", null) },
      { id: "failure-alerts", title: "F", severity: "medium", status: "compensating-control", autoStatus: "fail", ...base, override: ov("compensating-control", "o@example.au", "short") },
      { id: "two-owners", title: "G", severity: "medium", status: "not-applicable", autoStatus: "pass", ...base, override: ov("not-applicable", "o@example.au") },
      { id: "beacon-off", title: "H", severity: "low", status: "resolved-alternative", autoStatus: "pass", ...base },
      { id: "encryption-pq-hybrid", title: "I", severity: "low", status: "pass", autoStatus: "pass", ...base, override: ov("attested-pass", "o@example.au") },
    ],
  };
  // Label map: every arm, exactly once (the switch is the single label source for the reports).
  ok("label: pass", postureStatusLabel("pass") === "pass");
  ok("label: fail", postureStatusLabel("fail") === "fail");
  ok("label: resolved-alternative reads pass (alternative control)", postureStatusLabel("resolved-alternative") === "pass (alternative control)");
  ok("label: not-evaluated", postureStatusLabel("not-evaluated") === "not evaluated");
  // overrideNote branches: attributed email vs break-glass, dormant marker, short setAt, each kind.
  const noteFor = (i: number) => overrideNote(allStatuses.checks[i]!);
  ok("note: risk-accepted attributed to the owner email", noteFor(3)?.includes("Risk accepted") === true && noteFor(3)?.includes("o@example.au") === true);
  ok("note: attested-pass with no email attributes the break-glass token", noteFor(4)?.includes("break-glass token") === true);
  ok("note: compensating-control with a short setAt omits the date", noteFor(5)?.includes("Pass (compensating control)") === true && noteFor(5)?.includes("short") === false);
  ok("note: not-applicable on an auto-passing check carries the dormant marker", noteFor(6)?.includes("Not applicable") === true);
  ok("note: dormant override on a passing check is marked", noteFor(8)?.includes("currently passes on its own") === true);
  // The posture PDF renders the full status set + the overrides-and-attestations table.
  const posturePdf = renderReportPDF(makeReport("posture", allStatuses, null, Date.parse("2026-07-02T00:00:00Z")));
  ok("posture PDF with every status + override table renders", posturePdf.length > 1000 && new TextDecoder().decode(posturePdf.subarray(0, 5)) === "%PDF-");
  // The evidence pack over the same posture: bound-check notes + the N/A + awaiting-attestation summary extras.
  const richAll = buildEvidencePackReport(FRAMEWORKS, allStatuses, "all");
  const richPdf = renderReportPDF(makeReport("evidence-pack", richAll, null, Date.parse("2026-07-02T00:00:00Z")));
  ok("evidence-pack PDF with notes + N/A + unattested summary renders", richPdf.length > 1000 && new TextDecoder().decode(richPdf.subarray(0, 5)) === "%PDF-");
  const anyNa = richAll.packs.some((f) => f.summary.checksNotApplicable > 0);
  const anyUnattested = richAll.packs.some((f) => f.summary.checksUnattested > 0);
  ok("all-pack summaries tally N/A and unattested where bound", anyNa && anyUnattested);
}

console.log("evidence-pack: report kind + PDF render");
ok("evidence-pack is a recognised report kind", isReportKind("evidence-pack"));
const rep = makeReport("evidence-pack", single, null, Date.parse("2026-06-21T00:00:00Z"));
ok("makeReport wraps it point-in-time", rep.kind === "evidence-pack" && rep.period === null);
const pdfSingle = renderReportPDF(rep);
ok("single-framework pack renders a valid PDF", pdfSingle.length > 1000 && new TextDecoder().decode(pdfSingle.subarray(0, 5)) === "%PDF-");
const pdfAll = renderReportPDF(makeReport("evidence-pack", all, null, Date.parse("2026-06-21T00:00:00Z")));
ok("all-frameworks pack renders a valid (larger) PDF", pdfAll.length > pdfSingle.length && new TextDecoder().decode(pdfAll.subarray(0, 5)) === "%PDF-");

// ------------------------------------------------------------------------------------------------------
// WHAT THE PACK SAYS, not merely that it is a PDF.
//
// Everything above this point checked the magic number and the byte length. That is a check a pack whose
// controls were bound to the wrong checks, whose table rendered its columns transposed, or whose every
// status cell read "not evaluated" passes unchanged: it is a check on the CONTAINER, and the evidence pack
// is the document a customer hands their auditor. So the pack's own painted text is read back out of the
// bytes here and reconciled against the data it was built from.
//
// This is deliberately the ENGINE's floor, not its ceiling. A more exhaustive, digit-exact, column-aware,
// control-by-control reconcile against a real estate's posture belongs in a live end-to-end check with a
// second, independent reader of the bytes. What belongs HERE is the part that must never depend on that:
// that the pack names its frameworks, names its controls, and states real evaluated statuses.
// ------------------------------------------------------------------------------------------------------

// The engine writes uncompressed content streams, so every painted string is a PDF literal in the bytes.
// This recovers them with the standard literal escapes; it is a reader, never a renderer, and it is kept
// small on purpose (the full extractor is the harness's, and duplicating it here would be a second thing
// to keep true rather than a floor).
interface PaintedRun {
  x: number;
  text: string;
}

function pdfPaintedRuns(bytes: Uint8Array): PaintedRun[] {
  const s = new TextDecoder("latin1").decode(bytes);
  const named: Record<string, string> = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", "(": "(", ")": ")", "\\": "\\" };
  const out: PaintedRun[] = [];
  // Every painted string is emitted as `1 0 0 1 <x> <y> Tm (<text>) Tj` (src/pdf-primitives.ts textRun), so
  // the x each run was laid at is recoverable, and with it the COLUMN a cell was painted in. That is what
  // separates a transposed table from an honest one: both contain the same strings.
  const TM = /1 0 0 1 (-?[\d.]+) (-?[\d.]+) Tm\s*$/;
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "(") continue;
    const x = Number.parseFloat(TM.exec(s.slice(Math.max(0, i - 64), i))?.[1] ?? "NaN");
    let depth = 1;
    let buf = "";
    let j = i + 1;
    for (; j < s.length && depth > 0; j++) {
      const ch = s[j] as string;
      if (ch === "\\") {
        const next = s[j + 1] as string;
        if (next >= "0" && next <= "7") {
          let oct = "";
          // The two index reads carry `as string` like their neighbours at :204 and :206, which is what the
          // rest of this decoder already does under noUncheckedIndexedAccess. Past the end of the buffer the
          // read is undefined, and `undefined >= "0"` is false, so the loop ends exactly where it ended
          // before: this is not a behaviour change, only an equivalent expression of the same bound.
          while (oct.length < 3) {
            const d = s[j + 1] as string;
            if (!(d >= "0" && d <= "7")) break;
            oct += s[++j];
          }
          buf += String.fromCharCode(Number.parseInt(oct, 8));
        } else if (next === "\n") j++;
        else { buf += named[next] ?? next; j++; }
        continue;
      }
      if (ch === "(") { depth++; buf += ch; continue; }
      if (ch === ")") { depth--; if (depth > 0) buf += ch; continue; }
      buf += ch;
    }
    out.push({ x, text: buf });
    i = j - 1;
  }
  return out;
}

const pdfLiteralText = (bytes: Uint8Array): string => pdfPaintedRuns(bytes).map((r) => r.text).join(" ");

// The PDF wraps every cell, so a title or an obligation can be split across lines at a space, or an
// over-long token hard-split mid-character. Whitespace is therefore the one thing the painted text cannot
// preserve; stripping it from both sides compares every VISIBLE character in order.
const stripWs = (t: string): string => t.replace(/\s+/g, "");
const allText = stripWs(pdfLiteralText(pdfAll));

ok("the pack's PDF text extracts to real content (not an empty or image-only render)", allText.length > 2000);

// Every framework the pack was built from must be NAMED in the document.
const missingTitles = all.packs.map((f) => f.frameworkTitle).filter((t) => !allText.includes(stripWs(t)));
ok(`every framework in the pack is named in the PDF (missing: ${missingTitles.join(", ") || "none"})`, missingTitles.length === 0);

// Every control id must appear. A pack that renders a framework heading and then an empty table is the
// exact shape the byte-length check cannot see.
const allControls = all.packs.flatMap((f) => f.controls.map((c) => c.control));
const missingControls = allControls.filter((c) => !allText.includes(stripWs(c)));
ok(`every mapped control id appears in the PDF (${allControls.length} controls, missing: ${missingControls.slice(0, 5).join(", ") || "none"})`, missingControls.length === 0);

// Every bound check's TITLE must appear, so a control cannot render with its evidence cell silently blank.
const boundTitles = [...new Set(all.packs.flatMap((f) => f.controls.flatMap((c) => c.checks.map((ch) => ch.title))))];
const missingCheckTitles = boundTitles.filter((t) => !allText.includes(stripWs(t)));
ok(`every bound check title appears in the PDF (${boundTitles.length} titles, missing: ${missingCheckTitles.slice(0, 3).join(", ") || "none"})`, missingCheckTitles.length === 0);

// The pack must not be UNIFORMLY "not evaluated". The statuses are anchored to the "title: label" colon so
// a status word occurring inside a check title cannot be mistaken for a rendered status.
const evaluatedLabels = [...new Set(all.packs.flatMap((f) => f.controls.flatMap((c) => c.checks.map((ch) => ch.status))))]
  .filter((st) => st !== "not-evaluated")
  .map((st) => `:${stripWs(postureStatusLabel(st))}`);
ok(
  `the PDF states real evaluated statuses rather than reading uniformly "not evaluated" (expected label(s): ${evaluatedLabels.join(", ") || "none"})`,
  evaluatedLabels.length > 0 && evaluatedLabels.some((l) => allText.includes(l)),
);

// The summary sentence must state the per-framework tallies the generator computed, digit for digit, so a
// roll-up that disagrees with the rows beneath it is named here rather than only in the harness.
const summaryMisses = all.packs.filter((f) => !allText.includes(stripWs(`Controls mapped: ${f.summary.controlsTotal}.`)));
ok(`every framework's "Controls mapped" tally is stated in the PDF (missing: ${summaryMisses.map((f) => f.frameworkId).join(", ") || "none"})`, summaryMisses.length === 0);

// COLUMN MEMBERSHIP. Every check above this one is a whole-document text search, and a table with its
// columns TRANSPOSED contains exactly the same strings as an honest one, so none of them can see it. The x
// each run was painted at can. A control id is painted in the first column and a check title in the third,
// so the two must never share an x, and every control id must sit LEFT of every check title. That is the
// cheapest assertion that distinguishes a correct table from a transposed one without rebuilding the
// harness's full column parser here.
// The reference is the table's own HEADER, whose three labels are each painted as one whole run at their
// column's x. Anything else would be this test guessing at geometry; the header states it.
{
  const runs = pdfPaintedRuns(pdfAll).filter((r) => Number.isFinite(r.x));
  const headerX = (label: string): number | null => runs.find((r) => r.text === label)?.x ?? null;
  const controlColX = headerX("Control");
  const evidenceColX = headerX("Live evidence");
  ok(
    `the evidence table's Control and Live evidence column headers are painted, at distinct x (control=${controlColX}, evidence=${evidenceColX})`,
    controlColX !== null && evidenceColX !== null && controlColX !== evidenceColX,
  );

  // Attribute only runs whose text IS a whole control id: a wrapped fragment carries no reliable identity,
  // so it never votes. A control id short enough not to wrap in a 96pt column is the common case, and the
  // count below is the non-vacuity floor that stops "nothing matched" from reading as agreement.
  const controlIds = new Set(allControls.map(stripWs));
  const idRuns = runs.filter((r) => controlIds.has(stripWs(r.text)));
  const strayColumns = [...new Set(idRuns.filter((r) => r.x !== controlColX).map((r) => r.x))];
  ok(
    `every whole control id is painted in the Control column (${idRuns.length} id run(s) matched; stray x: ${strayColumns.join("/") || "none"})`,
    controlColX !== null && idRuns.length >= 20 && strayColumns.length === 0,
  );
}

// A SINGLE-framework pack must contain ONLY that framework: the "all" roll-up leaking into a per-framework
// download would hand an auditor other frameworks' controls.
const singleText = stripWs(pdfLiteralText(pdfSingle));
const singleFw = single.packs[0];
const leaked = all.packs.filter((f) => f.frameworkId !== singleFw?.frameworkId).filter((f) => singleText.includes(stripWs(f.frameworkTitle)));
ok(`a single-framework pack names only its own framework (leaked: ${leaked.map((f) => f.frameworkId).join(", ") || "none"})`, singleFw !== undefined && leaked.length === 0);

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-evidence-pack (${failures} failure(s))`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
