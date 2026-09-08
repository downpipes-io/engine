// Vendor the authoritative NIST ACVP known-answer vectors that enable the FIPS 203 /
// FIPS 204 standard-conformance anchor in test/validate-acvp.ts. It is intentionally minimal and HONEST:
//
//   - If a network is reachable, it downloads the ML-KEM-1024 (FIPS 203) and ML-DSA-87
//     (FIPS 204) internalProjection.json files from NIST's public ACVP-Server repo and
//     writes them to test/vectors/acvp/. These internalProjection.json files carry the
//     expected outputs (ek/dk/c/k, pk/sk/signature, and the sigVer verdicts), which is
//     exactly what the anchor asserts.
//   - If there is no network (the build environment here has none), it does NOT fabricate
//     anything. It prints the canonical sources and the exact target paths, then exits 0
//     so it can be wired anywhere without breaking a pipeline. validate-acvp.ts then
//     stays in its honest "SKIPPED -- no ACVP vectors vendored" mode and the suite passes
//     on the Go-reference + determinism anchors alone.
//
// NOTHING in this script is a NIST validation; it only places NIST's published test
// vectors where the engine can run them. ACVP *validation* is a NIST/lab process.
//
// Usage: node scripts/fetch-acvp.mjs

import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "test", "vectors", "acvp");

// Authoritative sources. The ACVP-Server repo publishes the generated vectors with their
// expected outputs under gen-val/json-files/<algo-mode-FIPS2xx>/internalProjection.json.
// We pull the FIPS203/FIPS204 internal-projection files; the harness filters each to the
// ML-KEM-1024 / ML-DSA-87 parameter set, so the raw multi-parameter file can be dropped in
// unedited and several files for the same algorithm can be concatenated by hand if desired.
const RAW = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files";
const TARGETS = [
  {
    name: "ML-KEM-1024.json",
    // encapDecap covers encapsulation (AFT) + decapsulation (VAL); keyGen is a separate dir.
    urls: [
      `${RAW}/ML-KEM-encapDecap-FIPS203/internalProjection.json`,
      `${RAW}/ML-KEM-keyGen-FIPS203/internalProjection.json`,
    ],
  },
  {
    name: "ML-DSA-87.json",
    urls: [
      `${RAW}/ML-DSA-sigGen-FIPS204/internalProjection.json`,
      `${RAW}/ML-DSA-sigVer-FIPS204/internalProjection.json`,
      `${RAW}/ML-DSA-keyGen-FIPS204/internalProjection.json`,
    ],
  },
];

function guidance() {
  console.log("");
  console.log("No ACVP vectors were fetched. To enable the FIPS 203 / FIPS 204 standard");
  console.log("conformance anchor OFFLINE, obtain the NIST ACVP internalProjection.json files");
  console.log("from  https://github.com/usnistgov/ACVP-Server  under  gen-val/json-files/ :");
  for (const t of TARGETS) {
    console.log(`  ${t.name}:`);
    for (const u of t.urls) console.log(`     ${u}`);
  }
  console.log("and save them (any one of the listed files for each algorithm is enough to");
  console.log("activate that direction; the harness filters to ML-KEM-1024 / ML-DSA-87) at:");
  console.log(`  ${join(outDir, "ML-KEM-1024.json")}`);
  console.log(`  ${join(outDir, "ML-DSA-87.json")}`);
  console.log("Then run:  node test/validate-acvp.ts");
}

async function fetchFirst(urls) {
  // Returns the first URL body that fetches, or null if none reachable.
  if (typeof fetch !== "function") return null;
  for (const u of urls) {
    try {
      const res = await fetch(u, { redirect: "follow" });
      if (res.ok) {
        const text = await res.text();
        // Sanity: must look like ACVP JSON with testGroups; otherwise treat as a miss so
        // we never write a 404 page or a renamed/empty file as if it were a vector set.
        if (text.includes("testGroups") || text.trimStart().startsWith("[")) return text;
      }
    } catch {
      // try the next url
    }
  }
  return null;
}

async function main() {
  mkdirSync(outDir, { recursive: true });
  let wrote = 0;
  let networkSeen = false;
  for (const t of TARGETS) {
    const dest = join(outDir, t.name);
    if (existsSync(dest)) {
      console.log(`exists, leaving in place: ${dest}`);
      continue;
    }
    const body = await fetchFirst(t.urls);
    if (body === null) continue;
    networkSeen = true;
    writeFileSync(dest, body);
    console.log(`vendored: ${dest} (${body.length} bytes)`);
    wrote++;
  }
  if (wrote > 0) {
    console.log(`\nDone. Run \`node test/validate-acvp.ts\` to activate the standard anchor.`);
  } else {
    if (!networkSeen) console.log("No network reachable (offline build environment).");
    guidance();
  }
  // Always succeed: vendoring is optional; absence is handled honestly by the harness.
  process.exit(0);
}

main().catch((e) => {
  // Even on an unexpected error, fail soft with guidance -- this is a convenience vendoring
  // script, not a gate.
  console.error("fetch-acvp: unexpected error:", e && e.message ? e.message : e);
  guidance();
  process.exit(0);
});
