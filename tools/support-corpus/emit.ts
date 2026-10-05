// Emit the labelled fault->bundle corpus (JSONL) for the support tooling scorer.
//
//   node tools/support-corpus/emit.ts --out /path/to/dir [--only <id-substring>]
//
// Writes <out>/support-corpus.jsonl (one CorpusRow per scenario) and prints a per-scenario
// CAPTURE verdict (the evidence-in-pack half of the coverage matrix). Exits non-zero when any
// scenario's capture assertion fails, any bundle's hybrid signature fails to re-verify, or any
// pack contradicts itself (coherence.ts), and it declares its verdict through the verdict guard,
// so a run that stops before the tally cannot read as a pass.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { verdictReached } from "../../test/lib/verdict-guard.ts";
import { COHERENCE_RULES, coherenceFindings, type CoherenceRule } from "./coherence.ts";
import { emitScenario, emitSealedBandCheck, makeKeys, type Scenario } from "./harness.ts";
import { CORE_SCENARIOS } from "./scenarios-core.ts";
import { DOMAIN_SCENARIOS } from "./scenarios-domains.ts";
import { DOMAIN_B_SCENARIOS } from "./scenarios-domains-b.ts";
import { HEALTHY_VARIANT_SCENARIOS } from "./scenarios-healthy-variants.ts";
import { MULTI_FAULT_SCENARIOS } from "./scenarios-multi.ts";
import { FIXROUND_SCENARIOS } from "./scenarios-fixround.ts";
import { CAP_TRUNCATION_SCENARIOS } from "./scenarios-captrunc.ts";

const ALL: Scenario[] = [...CORE_SCENARIOS, ...DOMAIN_SCENARIOS, ...DOMAIN_B_SCENARIOS, ...HEALTHY_VARIANT_SCENARIOS, ...MULTI_FAULT_SCENARIOS, ...FIXROUND_SCENARIOS, ...CAP_TRUNCATION_SCENARIOS];

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const outDir = arg("--out") ?? "corpus-out";
  const only = arg("--only");
  const scenarios = only !== undefined ? ALL.filter((s) => s.id.includes(only)) : ALL;
  const ids = new Set<string>();
  for (const s of scenarios) {
    if (ids.has(s.id)) throw new Error(`duplicate scenario id: ${s.id}`);
    ids.add(s.id);
  }

  mkdirSync(outDir, { recursive: true });
  const keys = await makeKeys();
  const lines: string[] = [];
  let captureFailures = 0;
  let signatureFailures = 0;

  let coherenceFailures = 0;
  let controlBundle: Record<string, unknown> | undefined;
  for (const s of scenarios) {
    const r = await emitScenario(s, keys);
    lines.push(JSON.stringify(r.row));
    if (controlBundle === undefined && s.id === "healthy.kv-baseline") controlBundle = r.row.innerBody as Record<string, unknown>;
    const sig = r.signatureVerified ? "sig-ok" : "SIG-FAIL";
    if (!r.signatureVerified) signatureFailures++;
    if (r.coherence.length > 0) coherenceFailures++;
    if (r.captureFailures.length === 0 && r.coherence.length === 0) {
      console.log(`  ok   [${sig}] ${s.id} -- captured, coherent`);
    } else {
      if (r.captureFailures.length > 0) captureFailures++;
      console.log(`  FAIL [${sig}] ${s.id}`);
      for (const f of r.captureFailures) console.log(`         capture: ${f}`);
      for (const f of r.coherence) console.log(`         coherence: ${f}`);
    }
  }

  // THE COHERENCE CHECK MUST BE ABLE TO FAIL. Plant each contradiction into a copy of the healthy baseline pack
  // and require the rule that names it to fire. A check that never fires on these is not checking anything, and
  // every "coherent" line above would be a reading of a dead rule.
  if (controlBundle === undefined) {
    // An --only run that skipped the baseline still gets its control: emit the baseline pack for the control alone.
    const baseline = ALL.find((x) => x.id === "healthy.kv-baseline");
    if (baseline !== undefined) controlBundle = (await emitScenario(baseline, keys)).row.innerBody as Record<string, unknown>;
  }
  const controlFailures = coherenceControl(controlBundle);
  if (controlFailures.length === 0) console.log(`  ok   coherence-control -- every rule fires on its planted contradiction (${COHERENCE_RULES.length} rules)`);
  else {
    console.log("  FAIL coherence-control");
    for (const f of controlFailures) console.log(`         control: ${f}`);
  }

  // The ENVELOPE-level capture: one sealed emission per run, asserting the clear-signed band
  // manifest contract (presence, kind, carried-key signature, fingerprint, bodySha256 binding,
  // volumes/licence agreement with the inner bundle, envelope v). The per-scenario loop above
  // exercises signedSupportBundle only, so this is the corpus's only proof of the sealed path.
  const sealedFailures = await emitSealedBandCheck();
  if (sealedFailures.length === 0) {
    console.log("  ok   sealed-band-manifest -- envelope captured");
  } else {
    console.log("  FAIL sealed-band-manifest");
    for (const f of sealedFailures) console.log(`         envelope: ${f}`);
  }

  const outPath = join(outDir, "support-corpus.jsonl");
  writeFileSync(outPath, lines.join("\n") + "\n");
  console.log(`\n${scenarios.length} scenarios -> ${outPath}`);
  console.log(
    `capture failures: ${captureFailures}; coherence failures: ${coherenceFailures}; signature failures: ${signatureFailures}; sealed-envelope failures: ${sealedFailures.length}; coherence-control failures: ${controlFailures.length}`,
  );
  const failures = captureFailures + coherenceFailures + signatureFailures + sealedFailures.length + controlFailures.length;
  // checks: one per scenario plus the sealed-envelope capture and the coherence control.
  verdictReached(failures, scenarios.length + 2);
  process.exit(failures === 0 ? 0 : 1);
}

type Dict = Record<string, unknown>;

/** Plant one contradiction per rule into copies of the healthy pack; return the rules that did not fire. */
function coherenceControl(healthy: Dict | undefined): string[] {
  if (healthy === undefined) return ["the healthy.kv-baseline scenario is missing, so the control has no pack to plant into"];
  const clone = (): Dict => JSON.parse(JSON.stringify(healthy)) as Dict;
  const fails: string[] = [];
  const clean = coherenceFindings(clone(), false);
  if (clean.length > 0) fails.push(`the unplanted healthy pack is not coherent: ${clean.map((f) => f.rule).join(", ")}`);
  const gen = Date.parse(String(healthy.generatedAt));
  const plants: Array<[CoherenceRule, boolean, (b: Dict) => void]> = [
    ["version-drift", false, (b) => ((b.engine as Dict).deployBaseline = { version: "0.0.1", cfVersionId: "x", at: 0 })],
    ["healthy-preflight", false, (b) => (((b.preflight as Dict).items as Dict[]).find((i) => i.id === "destination")!.status = "failed")],
    ["dest-refusal-vs-healthy-dest", true, (b) => ((b.runs as Record<string, Dict[]>).dp1![0] = { runId: "01X", index: 8, startedAt: new Date(gen - 20 * 60_000).toISOString(), status: "failed", error: "destination rejected the write (AccessDenied)" })],
    ["dest-refusal-unrecorded", true, (b) => ((b.runs as Record<string, Dict[]>).dp1![0] = { runId: "01X", index: 8, startedAt: new Date(gen - 20 * 60_000).toISOString(), status: "failed", error: "destination rejected the write (SlowDown)" })],
    [
      "overdue-unexplained",
      true,
      (b) => {
        (b.downpipes as Dict[])[0]!.nextRunAt = gen - 3 * 86_400_000;
        for (const t of (b.scheduler as Dict).ticks as Dict[]) t.due = 0;
      },
    ],
    [
      "cron-verified-ticks-stale",
      true,
      (b) => {
        for (const t of (b.scheduler as Dict).ticks as Dict[]) t.at = gen - 3 * 86_400_000;
      },
    ],
    [
      "cron-work-after-last-tick",
      true,
      (b) => {
        for (const t of (b.scheduler as Dict).ticks as Dict[]) t.at = gen - 3 * 86_400_000;
      },
    ],
    [
      "tick-dispatch-unexplained",
      true,
      (b) => {
        const ticks = (b.scheduler as Dict).ticks as Dict[];
        ticks[ticks.length - 1]!.dispatched = 1;
      },
    ],
    ["next-run-off-cadence", false, (b) => ((b.downpipes as Dict[])[0]!.nextRunAt = gen + 6 * 3_600_000)],
    ["audit-behind-events", true, (b) => (b.configEvents as Dict[]).push({ seq: 99, at: new Date(gen).toISOString(), action: "role-change" })],
    ["runlog-counter", false, (b) => (((b.scheduler as Dict).runlog as Dict).counter = 9)],
  ];
  const covered = new Set(plants.map(([r]) => r));
  for (const r of COHERENCE_RULES) if (!covered.has(r)) fails.push(`rule ${r} has no planted control`);
  for (const [rule, isFault, plant] of plants) {
    const b = clone();
    plant(b);
    if (!coherenceFindings(b, isFault).some((f) => f.rule === rule)) fails.push(`rule ${rule} did not fire on its planted contradiction`);
  }
  return fails;
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
