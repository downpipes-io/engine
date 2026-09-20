// support-pack-fault-run.ts -- the RUNNER for support-pack-fault-oracle.ts. It is its own file because the probe set imports
// the oracle's types and the oracle would otherwise have to import the probes back: a cycle whose two
// top-level awaits deadlock rather than fail, which is exactly the "verification that silently does not
// verify" shape. The runner is the only module that knows about both.
//
//   node tools/support-corpus/support-pack-fault-run.ts [--only <n|substring>] [--diff <n>]

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { score, type Verdict } from "./support-pack-fault-oracle.ts";
import { PROBES } from "./support-pack-fault-probes.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

// coverage compares the probe ordinals to the numbered rows of the defect table this oracle exists to score.
// A table row with no probe is NOT a clean verdict and must not be absorbed into one, so it is NAMED. An
// absent table is reported CANNOT-CHECK rather than passed over: this tool runs from a standalone engine
// checkout too, where the table simply is not there, and a missing file must never read as full coverage.
function coverage(probed: number[]): void {
  const candidates = [
    join(HERE, "..", "..", "..", "TRACKER", "plans", "BOUNDARIES-AND-ACCUMULATION-2026-08-11.md"),
    join(HERE, "..", "..", "..", "..", "TRACKER", "plans", "BOUNDARIES-AND-ACCUMULATION-2026-08-11.md"),
  ];
  let text: string | undefined;
  for (const c of candidates) {
    try {
      text = readFileSync(c, "utf8");
      break;
    } catch {
      // not this one
    }
  }
  if (text === undefined) {
    console.log("COVERAGE AGAINST THE TABLE: CANNOT-CHECK. The defect table was not found beside this checkout, so this run says nothing about whether the probe set is complete.");
    return;
  }
  const rows = [...text.matchAll(/^\| (\d+) \|/gm)].map((m) => Number(m[1]));
  const missing = rows.filter((n) => !probed.includes(n));
  console.log(`COVERAGE AGAINST THE TABLE: ${rows.length} numbered row(s); ${probed.length} probed; ${missing.length} NOT PROBED${missing.length > 0 ? `: ${missing.join(", ")}` : ""}.`);
}

async function main(): Promise<void> {
  const only = arg("--only");
  const probes = only !== undefined ? PROBES.filter((p) => String(p.n) === only || p.what.includes(only)) : PROBES;
  if (probes.length === 0) {
    console.log("REFUSE: the probe set is EMPTY. A sweep that visits nothing must fail rather than pass.");
    process.exit(2);
  }
  const { scored } = await score(probes);

  const tally: Record<Verdict, number> = { DIAGNOSABLE: 0, PARTIAL: 0, SILENT: 0, "NOT-APPLICABLE": 0 };
  for (const s of scored) {
    tally[s.verdict]++;
    const head = `${String(s.n).padStart(2)} [${s.verdict}] (${s.where}, ${s.diff.length} differing path(s))`;
    console.log(`${head} ${s.what}`);
    if (s.reason !== undefined) console.log(`     NOT APPLICABLE BECAUSE: ${s.reason}`);
    for (const c of s.cannotSay) console.log(`     cannot say: ${c}`);
    if (s.note !== undefined) console.log(`     note: ${s.note}`);
    const showDiff = arg("--diff");
    if (showDiff !== undefined && String(s.n) === showDiff) for (const d of s.diff) console.log(`       ${d}`);
  }

  const adjudicated = scored.length;
  if (adjudicated === 0) {
    console.log("REFUSE: zero probes adjudicated.");
    process.exit(2);
  }
  const counted = adjudicated - tally["NOT-APPLICABLE"];
  console.log(`\nSCORE, WITH ITS DENOMINATOR: ${tally.DIAGNOSABLE} DIAGNOSABLE / ${tally.PARTIAL} PARTIAL / ${tally.SILENT} SILENT of ${counted} COUNTED, plus ${tally["NOT-APPLICABLE"]} NOT-APPLICABLE, over a PROBE SET of ${adjudicated}.`);
  console.log(`DEFECTS PRODUCING A PACK INDISTINGUISHABLE FROM A HEALTHY ONE: ${tally.SILENT}.`);
  // AND THE PROBE SET IS COMPARED TO THE TABLE IT CLAIMS TO COVER, because "over a defect table of N" was N =
  // the probe set's own size, which is true of a run that probes nothing new for ever. The table GREW from 45
  // to 50 inside one hour on 2026-08-13 and again to 51 while another pass was landing, so a denominator
  // that quietly means "however many probes exist" turns every future addition into an invisible gap. Only
  // meaningful on the whole set: a --only run is deliberately partial and says nothing about coverage.
  if (only === undefined) coverage(scored.map((s2) => s2.n));
  process.exit(0);
}

await main();
