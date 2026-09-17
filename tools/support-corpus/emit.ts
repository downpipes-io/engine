// Emit the labelled fault->bundle corpus (JSONL) for the diagnostics-bot scorer.
//
//   node tools/support-corpus/emit.ts --out /path/to/dir [--only <id-substring>]
//
// Writes <out>/support-corpus.jsonl (one CorpusRow per scenario) and prints a per-scenario
// CAPTURE verdict (the evidence-in-pack half of the coverage matrix). Exits non-zero when any
// scenario's capture assertion fails or any bundle's hybrid signature fails to re-verify.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
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

  for (const s of scenarios) {
    const r = await emitScenario(s, keys);
    lines.push(JSON.stringify(r.row));
    const sig = r.signatureVerified ? "sig-ok" : "SIG-FAIL";
    if (!r.signatureVerified) signatureFailures++;
    if (r.captureFailures.length === 0) {
      console.log(`  ok   [${sig}] ${s.id} -- captured`);
    } else {
      captureFailures++;
      console.log(`  FAIL [${sig}] ${s.id}`);
      for (const f of r.captureFailures) console.log(`         capture: ${f}`);
    }
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
  console.log(`capture failures: ${captureFailures}; signature failures: ${signatureFailures}; sealed-envelope failures: ${sealedFailures.length}`);
  process.exit(captureFailures === 0 && signatureFailures === 0 && sealedFailures.length === 0 ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
