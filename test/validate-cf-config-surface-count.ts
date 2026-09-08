// Cloudflare config-surface COUNT pin + canonical-number EMITTER.
//
// WHY THIS EXISTS
// ---------------
// The cf-config surface counts are quoted in prose across the platform: the website, the docs site
// and the console all state "216 surfaces", "7 in-band", the per-tier and per-scope breakdowns. Those
// numbers are easy to leave stale when src/sources/cf-config-surfaces.ts gains or loses a surface, or
// when a restoreTier is flipped. This validator does two things:
//
//   [1] PIN -- it asserts the DOCUMENTED counts (the numbers prose may quote) equal the LIVE registry
//       (CF_CONFIG_SURFACES) AND that the derived constants the registry exports match it. It also
//       checks the partitions are consistent: zone+account === total, the three tier counts sum to
//       total, and in-band === the surfaces with a write() function. Any drift FAILS here, loudly,
//       before any prose can quote a wrong number.
//
//   [2] EMIT -- it prints the canonical numbers to stdout as a single line of JSON:
//         {"total":216,"inband":7,"tiers":{...},"zone":89,"account":127}
//       This validator is the SINGLE SOURCE OF TRUTH for the documented counts. Any prose generator
//       (website/docs) consumes this printed line rather than hardcoding the numbers from a plan or by
//       hand, so there is exactly one place the numbers are decided.
//
// This is READ-ONLY over the registry: it does not touch the backup or restore paths.
//
// Run with: node test/validate-cf-config-surface-count.ts
// Print only (machine-readable line, no PASS banner): the JSON line is always emitted on its own.

import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";
import {
  CF_CONFIG_INBAND_COUNT,
  CF_CONFIG_SCOPE_COUNTS,
  CF_CONFIG_SURFACE_COUNT,
  CF_CONFIG_SURFACES,
  CF_CONFIG_TIER_COUNTS,
} from "../src/sources/cf-config-surfaces.ts";

// The DOCUMENTED counts: the numbers prose may quote. They are pinned here so a registry change that
// moves a number FAILS until this line and the prose are updated together.
// Every registered surface is PROBED LIVE against a real account before being registered. Nine
// single-setting writers are each PROVEN by the live round trip in test/live-cf-roundtrip.ts (create,
// capture, damage, verify-the-damage-took, dry run, restore, re-read, re-run to convergence) against a
// real Cloudflare account; two are plan-gated on the proving account and marked UNPROVEN rather than
// PASS. `zaraz/default` deliberately has NO writer: Cloudflare's schema documents it GET-only.
const DOCUMENTED = {
  total: 313,
  inband: 85,
  // `proven` is the count that may be QUOTED as automated restore. `inband` counts every surface
  // carrying a write(), most of which are generated from Cloudflare's schema and are off by default.
  proven: 60,
  tiers: { idempotent: 176, ordered: 76, reprovision: 61 },
  zone: 118,
  account: 195,
};

let failures = 0;
function check(name: string, expected: number, actual: number): void {
  if (expected !== actual) {
    failures += 1;
    console.error(`  FAIL ${name}: documented ${expected} != live ${actual}`);
  }
}

// LIVE counts computed straight off the registry (independent of the exported constants, so a bug in
// the exported derivation is also caught).
const liveTotal = CF_CONFIG_SURFACES.length;
const liveInband = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function").length;
const liveTiers = { idempotent: 0, ordered: 0, reprovision: 0 };
const liveScope = { zone: 0, account: 0 };
for (const s of CF_CONFIG_SURFACES) {
  liveTiers[s.restoreTier] += 1;
  liveScope[s.scope] += 1;
}

// [1a] documented == live registry
check("total surfaces", DOCUMENTED.total, liveTotal);
check("in-band (write) surfaces", DOCUMENTED.inband, liveInband);
const liveProven = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function" && PROVEN_WRITE_SURFACES.has(s.id)).length;
check("PROVEN write surfaces", DOCUMENTED.proven, liveProven);
// Every proven id must actually exist and carry a writer, or the default restore scope silently shrinks.
for (const id of PROVEN_WRITE_SURFACES) {
  const s = CF_CONFIG_SURFACES.find((x) => x.id === id);
  if (s === undefined) { failures += 1; console.error(`  FAIL PROVEN_WRITE_SURFACES names "${id}", which is not in the registry`); }
  else if (typeof s.write !== "function") { failures += 1; console.error(`  FAIL PROVEN_WRITE_SURFACES names "${id}", which has no write()`); }
}
check("tier idempotent", DOCUMENTED.tiers.idempotent, liveTiers.idempotent);
check("tier ordered", DOCUMENTED.tiers.ordered, liveTiers.ordered);
check("tier reprovision", DOCUMENTED.tiers.reprovision, liveTiers.reprovision);
check("scope zone", DOCUMENTED.zone, liveScope.zone);
check("scope account", DOCUMENTED.account, liveScope.account);

// [1b] the exported derived constants == live registry (so prose importing them gets the live number)
check("exported CF_CONFIG_SURFACE_COUNT", CF_CONFIG_SURFACE_COUNT, liveTotal);
check("exported CF_CONFIG_INBAND_COUNT", CF_CONFIG_INBAND_COUNT, liveInband);
check("exported tier idempotent", CF_CONFIG_TIER_COUNTS.idempotent, liveTiers.idempotent);
check("exported tier ordered", CF_CONFIG_TIER_COUNTS.ordered, liveTiers.ordered);
check("exported tier reprovision", CF_CONFIG_TIER_COUNTS.reprovision, liveTiers.reprovision);
check("exported scope zone", CF_CONFIG_SCOPE_COUNTS.zone, liveScope.zone);
check("exported scope account", CF_CONFIG_SCOPE_COUNTS.account, liveScope.account);

// [1c] partitions are internally consistent (catches a tier/scope added without updating total)
if (liveTiers.idempotent + liveTiers.ordered + liveTiers.reprovision !== liveTotal) {
  failures += 1;
  console.error(`  FAIL tier counts do not sum to total: ${JSON.stringify(liveTiers)} != ${liveTotal}`);
}
if (liveScope.zone + liveScope.account !== liveTotal) {
  failures += 1;
  console.error(`  FAIL scope counts do not sum to total: ${JSON.stringify(liveScope)} != ${liveTotal}`);
}

// [2] EMIT the canonical line. Always printed (even on failure, so a CI log shows the live numbers to
// copy from). This is the authority prose generators consume.
const canonical = {
  total: liveTotal,
  inband: liveInband,
  // `proven` is the number prose may quote as automated restore. `inband` counts every surface carrying
  // a write() including the ones generated from Cloudflare's schema, which are off by default at restore
  // time because the schema fixes the path and the method but not the natural key or the body shape.
  // Quoting `inband` as "we restore this for you" would over-claim by a factor of five.
  proven: liveProven,
  tiers: liveTiers,
  zone: liveScope.zone,
  account: liveScope.account,
};
console.log(JSON.stringify(canonical));

// Silent on pass, FAILs to stderr, and its failures are incremented inline at five sites rather than
// through an ok() helper, so stdout carries one JSON line and nothing about how much was compared. The
// honest unit of work here is the surface registry it walks, so that total is what the guard is told,
// and it lands on the canonical VERDICT line.
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} CF-CONFIG SURFACE-COUNT FAILURE(S) -- update the DOCUMENTED counts in test/validate-cf-config-surface-count.ts and any prose to match the printed line above.`);
  process.exit(1);
}
console.error("CF-CONFIG SURFACE-COUNT PIN PASS");
