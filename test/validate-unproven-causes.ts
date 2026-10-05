// Every writer is either PROVEN or has a recorded cause. Never both, never neither.
//
// WHY THIS EXISTS
// ---------------
// The rule for this work has been: a surface that passes the live round trip moves into
// PROVEN_WRITE_SURFACES, and one that fails has its writer removed with the reason recorded. The first
// half was data and therefore gated. The second half was prose, in two places that cannot gate: comments
// in the writer module, and a markdown ledger in a directory that is not under version control.
//
// So "every unproven writer has a recorded cause" was a claim nobody could check, and it was false. Four
// surfaces (zone-hold, tiered-caching, custom-nameserver-usage, dlp-settings) carried a writer, no create
// body and no ledger row, and had simply never been attempted. Nothing distinguished them from surfaces
// that HAD been attempted and refused, because an absent cause and an entitlement cause look the same
// from the outside: both are just an id missing from the proven set.
//
// WHAT IT CHECKS
// --------------
//   1. Every surface carrying a write() is either proven or has a cause. No writer sits in the available
//      set with no evidence either way.
//   2. No surface is both proven and caused. A cause for a proven surface is stale text that will be read
//      as current, which is how a figure repinned in one place and left in another reads as agreement.
//   3. No cause names a surface that has no writer, or does not exist. Both mean the registry moved and
//      the cause was left behind, pointing at nothing.
//   4. Causes are non-trivial. "unknown" and an empty string satisfy a Map and record nothing, and the
//      point of this file is that the absence of evidence must not be able to masquerade as evidence.
//
// WHAT IT DELIBERATELY DOES NOT CHECK
// -----------------------------------
// Whether the cause is TRUE. Only a live run against the account in question can say that, and this
// campaign has twice found an entitlement verdict that was actually our own malformed request. What a
// gate can enforce is that a claim exists and is attributable; whether it still holds is what re-running
// the live harnesses is for.
//
//   node test/validate-unproven-causes.ts

import { readFileSync } from "node:fs";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { NO_LIVE_ROUTE_HERE, PROVEN_WRITE_SURFACES, UNPROVEN_WRITE_CAUSES } from "../src/sources/cf-config-write-generated.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const withWriter = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function");
const writerIds = new Set(withWriter.map((s) => s.id));
const allIds = new Set(CF_CONFIG_SURFACES.map((s) => s.id));

console.log(`-- ${withWriter.length} writers: ${PROVEN_WRITE_SURFACES.size} proven, ${UNPROVEN_WRITE_CAUSES.size} with a recorded cause --`);

const uncaused = withWriter.filter((s) => !PROVEN_WRITE_SURFACES.has(s.id) && !UNPROVEN_WRITE_CAUSES.has(s.id));
ok(
  uncaused.length === 0
    ? "every unproven writer has a recorded cause"
    : `every unproven writer has a recorded cause (missing: ${uncaused.map((s) => s.id).join(", ")})`,
  uncaused.length === 0,
);

const both = [...UNPROVEN_WRITE_CAUSES.keys()].filter((id) => PROVEN_WRITE_SURFACES.has(id));
ok(both.length === 0 ? "no surface is both proven and caused" : `no surface is both proven and caused (both: ${both.join(", ")})`, both.length === 0);

const danglingNoWriter = [...UNPROVEN_WRITE_CAUSES.keys()].filter((id) => allIds.has(id) && !writerIds.has(id));
ok(
  danglingNoWriter.length === 0
    ? "no cause names a surface that has no writer"
    : `no cause names a surface that has no writer (${danglingNoWriter.join(", ")})`,
  danglingNoWriter.length === 0,
);

const danglingUnknown = [...UNPROVEN_WRITE_CAUSES.keys()].filter((id) => !allIds.has(id));
ok(
  danglingUnknown.length === 0
    ? "no cause names a surface that does not exist"
    : `no cause names a surface that does not exist (${danglingUnknown.join(", ")})`,
  danglingUnknown.length === 0,
);

const trivial = [...UNPROVEN_WRITE_CAUSES.entries()].filter(([, why]) => why.trim().length < 12 || /^(unknown|tbd|todo|n\/a)$/i.test(why.trim()));
ok(
  trivial.length === 0 ? "every cause says something" : `every cause says something (trivial: ${trivial.map(([id]) => id).join(", ")})`,
  trivial.length === 0,
);

// --- records that outlive their subject ------------------------------------------------------------
//
// The autoprove vector is the other place a record is kept per surface, and it dangles the same way. A
// create body for a surface the registry no longer has is dead weight that reads as coverage: the vector
// held 69 bodies, which invites "69 surfaces are exercised", and one of them named `waf-overrides`, a
// surface deleted after Cloudflare answered HTTP 410 "This API has been deprecated" for every caller on
// every plan. The body sat there after its subject was gone, and nothing could say so.
//
// This is the same shape as a cause naming a surface that does not exist, so it is asserted here rather
// than in a gate of its own: both are a record about a surface, kept in a different file from the
// registry, with nothing tying the two lifetimes together.
const vectorPath = new URL("./vectors/cf-config/autoprove-bodies.json", import.meta.url);
const vectorRaw = JSON.parse(readFileSync(vectorPath, "utf8")) as Record<string, unknown>;
const bodyHolder = (vectorRaw.bodies ?? vectorRaw) as Record<string, unknown>;
const bodyIds = Object.keys(bodyHolder);
const orphanBodies = bodyIds.filter((id) => !allIds.has(id));
ok(
  orphanBodies.length === 0
    ? `every autoprove create body names a real surface (${bodyIds.length} bodies)`
    : `every autoprove create body names a real surface (orphans: ${orphanBodies.join(", ")})`,
  orphanBodies.length === 0,
);

// --- the EXEMPTION list from the live coverage check ------------------------------------------------
//
// NO_LIVE_ROUTE_HERE names proven surfaces that no live harness re-exercises. The live suite reads it and
// fails when a proven surface is neither exercised nor exempt, which is the check that catches a proof
// quietly ceasing to be one.
//
// That check needs a real Cloudflare account, so it runs when someone remembers. The exemption list does
// not: it can rot offline, at which point the live check is weaker than it reads. An entry naming a
// surface that is no longer proven exempts nothing, and an entry that is ALSO in the cause ledger claims
// the surface is proven-but-unexercised and unproven at once. Both are checkable here, in `validate`.
const notProven = [...NO_LIVE_ROUTE_HERE.keys()].filter((id) => !PROVEN_WRITE_SURFACES.has(id));
ok(
  notProven.length === 0 ? "every live-coverage exemption names a PROVEN surface" : `every live-coverage exemption names a PROVEN surface (stale: ${notProven.join(", ")})`,
  notProven.length === 0,
);

const bothLists = [...NO_LIVE_ROUTE_HERE.keys()].filter((id) => UNPROVEN_WRITE_CAUSES.has(id));
ok(
  bothLists.length === 0 ? "no surface is both live-exempt and unproven" : `no surface is both live-exempt and unproven (${bothLists.join(", ")})`,
  bothLists.length === 0,
);

const thinReason = [...NO_LIVE_ROUTE_HERE.entries()].filter(([, why]) => why.trim().length < 12 || /^(unknown|tbd|todo|n\/a)$/i.test(why.trim()));
ok(
  thinReason.length === 0 ? "every live-coverage exemption states a reason" : `every live-coverage exemption states a reason (thin: ${thinReason.map(([id]) => id).join(", ")})`,
  thinReason.length === 0,
);

console.log(failures === 0 ? "\nUNPROVEN CAUSE LEDGER PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
