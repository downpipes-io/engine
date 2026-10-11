// Lists surviving mutants from a Stryker JSON report: file:line, operator, replacement, source line.
import { readFileSync } from "node:fs";
const reportPath = process.argv[2];
if (!reportPath) {
  console.error("usage: node survivors.mjs <stryker-report.json>");
  process.exit(2);
}
const report = JSON.parse(readFileSync(reportPath, "utf8"));
for (const [file, f] of Object.entries(report.files)) {
  const lines = f.source.split("\n");
  for (const m of f.mutants) {
    if (m.status !== "Survived") continue;
    const l = m.location.start.line;
    console.log(`${file}:${l}\t${m.mutatorName}\t${(m.replacement ?? "").replace(/\s+/g, " ").slice(0, 60)}\t| ${lines[l - 1].trim().slice(0, 110)}`);
  }
}
