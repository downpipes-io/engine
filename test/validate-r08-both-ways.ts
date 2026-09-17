// validate-r08-both-ways.ts -- both-ways proof at the unit level, for the Secrets Store binding shape.
//
// WHY THIS FILE, SEPARATE FROM validate-router-sources.ts. That file proves enumerateBoundSources itself
// classifies the fixture correctly. This file goes one step further and proves the THREE DOWNSTREAM
// SURFACES a harness detector (spec/journeys/r08-secrets-binding-enumeration.spec.ts in the workspace's
// private test repo) reads live against crud -- CELL-03 (GET /admin/setup-state boundSourceCount), CELL-04 (the
// preflight-vs-discover contradiction), CELL-05 (GET /admin/status sourcesDetachedCount, the
// operator-visible Overview banner) -- by driving each surface's OWN formula, copied verbatim from its
// call site, over a fixture built to the MEASURED live shape: the real crud Secrets Store binding is
// typeof "object" and answers typeof "function" for every one of the twelve method names
// enumerateBoundSources's duck-type ladder checks at once -- a generic, property-name-agnostic capability
// stub, unlike every other live binding on the same estate, each of which matches exactly one coherent
// capability group. It exercises the REAL exported functions (enumerateBoundSources, planRosterReattach)
// and the REAL predicate each route runs, not a re-description of them.
//
//   CELL-03 proxy: boundSourceCount = bound.kv.length + bound.r2.length + bound.d1.length +
//     bound.secrets.length, exactly router-destinations.ts:388's line, checked against the floor of
//     bindings this fixture declares.
//   CELL-04 proxy: preflight-probes.ts:467's own predicate, `bag[b] === undefined || bag[b] === null`,
//     against the SAME env bag enumerateBoundSources read, checked for agreement with
//     bound.secrets.includes(binding).
//   CELL-05 proxy: router-status.ts:61-66's own composition, planRosterReattach(configs, liveNames) where
//     liveNames is the union of every enumerateBoundSources tier, checked against a roster naming the
//     fixture's secrets binding.
//
// Run:
//   node test/validate-r08-both-ways.ts
//
// BOTH-WAYS: run this file twice by hand -- once against src/admin/router-sources.ts as committed (expect
// PASS, exit 0) and once with the multi-group-stub check removed (reverted to just the DO/email/service
// exclusion ladder, expect FAIL, exit 1) -- to prove the assertions below actually discriminate the defect
// rather than passing vacuously.

import { enumerateBoundSources } from "../src/admin/router-sources.ts";
import { planRosterReattach } from "../src/admin/roster-reattach.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const noop = () => undefined;
  const kv = { get: noop, put: noop, list: noop, getWithMetadata: noop };
  // The measured live shape: a Secrets Store binding that answers direct env[binding] access (bag[b] !==
  // undefined/null, the preflight-probes.ts:467 predicate), is typeof "object" (not "function"), and
  // answers typeof "function" for every method name the duck-type ladder checks (a generic capability
  // stub, own property list empty), not merely .get.
  const genericStubSecret: Record<string, unknown> = {};
  for (const m of ["get", "put", "list", "head", "createMultipartUpload", "getWithMetadata", "prepare", "batch", "exec", "idFromName", "send"]) genericStubSecret[m] = noop;
  const binding = "SRC_SECRET";
  const env = { SRC_KV: kv, [binding]: genericStubSecret } as unknown as Env;
  const bag = env as unknown as Record<string, unknown>;

  const bound = enumerateBoundSources(env);

  // ---- CELL-03 proxy: GET /admin/setup-state boundSourceCount (router-destinations.ts:386-388) --------
  const boundSourceCount = bound.kv.length + bound.r2.length + bound.d1.length + bound.secrets.length;
  const declaredFloor = 2; // SRC_KV + SRC_SECRET, the two bindings this fixture declares
  ok(
    `CELL-03 proxy: boundSourceCount (${boundSourceCount}) reaches the declared floor (${declaredFloor}) -- SRC_SECRET is not silently dropped from the setup-ladder count`,
    boundSourceCount >= declaredFloor,
  );

  // ---- CELL-04 proxy: preflight-probes.ts:467 vs GET /admin/sources/discover's bound.secrets ----------
  const preflightSaysPresent = !(bag[binding] === undefined || bag[binding] === null);
  const discoverSaysPresent = bound.secrets.includes(binding);
  ok("CELL-04 proxy setup: the direct env-access leg (preflight's own predicate) finds the binding present", preflightSaysPresent === true);
  ok(
    `CELL-04 proxy: no contradiction -- preflight (present=${preflightSaysPresent}) and discover (present=${discoverSaysPresent}) agree about ${binding}`,
    preflightSaysPresent === discoverSaysPresent,
  );

  // ---- CELL-05 proxy: GET /admin/status sourcesDetachedCount (router-status.ts:61-66) -------------------
  const liveNames = new Set<string>([...bound.kv, ...bound.r2, ...bound.d1, ...bound.secrets]);
  const roster = [{
    id: "rg-r08-proxy",
    source: { type: "secrets" as const, secrets: [{ name: "probe", binding, storeId: "store-1" }], include: [], exclude: [] },
  }];
  const plan = planRosterReattach(roster, liveNames);
  const sourcesDetachedCount = plan.toAttach.length + plan.unreconstructable.length;
  ok(
    `CELL-05 proxy: sourcesDetachedCount stays 0 for a live, readable ${binding} binding -- no false-alarm Overview banner`,
    sourcesDetachedCount === 0,
  );

  console.log(failures === 0 ? "\nBOTH-WAYS PROXY PASS" : `\nBOTH-WAYS PROXY FAIL (${failures})`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((err: unknown) => {
  console.error("validate-r08-both-ways crashed:", err);
  process.exit(1);
});
