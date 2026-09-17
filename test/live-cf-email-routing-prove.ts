// LIVE round trip for `email-routing`, the one surface whose shape fits neither existing prover.
//
// live-cf-autoprove.ts proves COLLECTIONS and live-cf-singleton-prove.ts proves ONE-OBJECT surfaces.
// email-routing reads `{ settings, rules }`, so it falls through both: autoprove's create/delete loop has
// no collection to address, and the singleton prober has no two-valued scalar to flip that is not either
// server state or the `enabled` switch this writer deliberately leaves alone.
//
// It gets its own file rather than a special case inside one of those, because the loop it needs is
// genuinely different: the damage is to the RULES, and the settings half rides along.
//
// THE LOOP
//   1. create a rule through Cloudflare directly       something for the snapshot to hold
//   2. snapshot = read()                               what a backup would contain
//   3. delete the rule through Cloudflare directly     the loss
//   4. write(snapshot)                                 the restore under test
//   5. read + compare                                  did the rule come back, matching
//   6. perturb the rule, write(snapshot) again         the UPDATE path, which a create never exercises
//   7. write(snapshot) once more                       convergence: a second restore changes nothing
//
// Step 7 is the one that catches a writer that "works" by duplicating. Step 6 is the one a
// restore-after-delete can never reach, because a delete leaves nothing to update.
//
// THE CATCH-ALL IS NOT TOUCHED. It belongs to the `email-routing-catch-all` surface and the writer under
// test filters it from both sides. This harness asserts that filtering held, because the failure would be
// silent: the catch-all reported as a live-only rule on every run, forever.
//
// SAFETY: it creates one rule with a marker address and deletes it in a finally on every path. The zone's
// existing rules are never modified. Gated on DOWNPIPE_LIVE_CF=1, and it refuses a non-default kit
// without DOWNPIPE_CF_ALLOW_DAMAGE like the other harnesses that write.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-email-routing-prove.ts

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { announceKit, kitDir, requireDamagePermission } from "./cf-kit.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { jsonEqual } from "../src/sources/cf-config-shared.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

if (process.env.DOWNPIPE_LIVE_CF !== "1") {
  console.log("LIVE EMAIL-ROUTING PROOF SKIPPED: set DOWNPIPE_LIVE_CF=1 to run it against a real account");
  verdictSkipped("LIVE EMAIL-ROUTING PROOF SKIPPED: set DOWNPIPE_LIVE_CF=1 to run it against a real account");
  process.exit(0);
}
const refusal = requireDamagePermission();
if (refusal !== "") {
  console.error(`REFUSING: ${refusal}`);
  process.exit(1);
}

const KEYS = kitDir();
const kit = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();
announceKit("live-cf-email-routing-prove");

const api = makeCfApi(kit("cf-api-token.txt"));
const ids = { accountId: kit("account-id.txt"), zoneId: kit("zone-id.txt") };
const surface = CF_CONFIG_SURFACES.find((s) => s.id === "email-routing");
if (surface === undefined || typeof surface.write !== "function") {
  console.error("FAIL email-routing has no writer");
  process.exit(1);
}

const RULES = `/zones/${ids.zoneId}/email/routing/rules`;
const MARKER = "dp-roundtrip@onlytims.shop";
type Rule = Record<string, unknown>;
const readAll = async (): Promise<{ settings: unknown; rules: Rule[] }> => (await surface.read(api, ids, undefined)) as { settings: unknown; rules: Rule[] };
const ours = (rs: Rule[]): Rule | undefined => rs.find((r) => JSON.stringify(r.matchers ?? "").includes(MARKER));

let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail === "" ? "" : ` (${detail})`}`);
  if (!cond) failures++;
}

let createdId = "";
try {
  // 1. create
  const made = (await api.send("POST", RULES, {
    name: "dp roundtrip",
    enabled: false,
    matchers: [{ type: "literal", field: "to", value: MARKER }],
    actions: [{ type: "drop" }],
  })) as Rule | null;
  createdId = typeof made?.id === "string" ? made.id : "";
  ok("a rule can be created to prove against", createdId !== "");
  if (createdId === "") throw new Error("no rule to work with");

  // 2. snapshot
  const snapshot = await readAll();
  ok("the snapshot holds the created rule", ours(snapshot.rules) !== undefined);
  ok("the snapshot also holds the catch-all (the surface captures it even though the writer skips it)", snapshot.rules.some((r) => r.priority === 2147483647));

  // 3. the loss
  await api.send("DELETE", `${RULES}/${createdId}`, undefined);
  ok("the rule is gone before the restore", ours((await readAll()).rules) === undefined);

  // 4 + 5. restore and compare
  const res = await surface.write(api, ids, snapshot, { dryRun: false }, undefined);
  ok("the restore reported no per-item skips", res.skipped.length === 0, JSON.stringify(res.skipped).slice(0, 160));
  const back = await readAll();
  const restored = ours(back.rules);
  ok("the rule came back", restored !== undefined);
  if (restored !== undefined) {
    ok("its matchers came back unchanged", jsonEqual(restored.matchers, ours(snapshot.rules)?.matchers));
    ok("its actions came back unchanged", jsonEqual(restored.actions, ours(snapshot.rules)?.actions));
    createdId = typeof restored.id === "string" ? restored.id : createdId;
  }

  // THE CATCH-ALL MUST NOT BE REPORTED AS LIVE-ONLY. The writer filters it from both sides; if it ever
  // filtered only the snapshot side, the additive contract would name the catch-all as a live-only rule
  // on every run forever, and the noise would be indistinguishable from a real finding.
  const mentionsCatchAll = JSON.stringify(res).includes("2147483647");
  ok("the catch-all is not reported as a live-only rule", !mentionsCatchAll);

  // 6. the UPDATE path: change the rule, restore, and it must be updated in place rather than duplicated.
  await api.send("PUT", `${RULES}/${createdId}`, {
    name: "dp roundtrip perturbed",
    enabled: false,
    matchers: [{ type: "literal", field: "to", value: MARKER }],
    actions: [{ type: "drop" }],
  });
  const res2 = await surface.write(api, ids, snapshot, { dryRun: false }, undefined);
  ok("the perturbed rule restored without skips", res2.skipped.length === 0, JSON.stringify(res2.skipped).slice(0, 160));
  const afterUpdate = await readAll();
  ok("the update did not duplicate the rule", afterUpdate.rules.filter((r) => JSON.stringify(r.matchers ?? "").includes(MARKER)).length === 1);
  ok("the name came back to the snapshot value", ours(afterUpdate.rules)?.name === "dp roundtrip");

  // 7. convergence
  const res3 = await surface.write(api, ids, snapshot, { dryRun: false }, undefined);
  ok("a second restore changes nothing (converged)", res3.applied === 0, `applied ${res3.applied}`);
} catch (e) {
  console.error(`  FAIL threw: ${(e as Error).message.replace(/\s+/g, " ").slice(0, 200)}`);
  failures++;
} finally {
  // Never leave the probe rule behind. Re-read rather than trusting the id, because the restore
  // re-created the rule with a NEW id and the one we started with no longer exists.
  try {
    const left = ours((await readAll()).rules);
    if (left !== undefined && typeof left.id === "string") await api.send("DELETE", `${RULES}/${left.id}`, undefined);
    const stillThere = ours((await readAll()).rules);
    if (stillThere !== undefined) {
      console.error(`\n*** THE PROBE RULE WAS LEFT ON THE ZONE: ${String(stillThere.id)} ***`);
      failures++;
    }
  } catch (e) {
    console.error(`\n*** CLEANUP FAILED, CHECK THE ZONE BY HAND: ${(e as Error).message.slice(0, 120)} ***`);
    failures++;
  }
}

if (failures === 0) console.log("LIVE-PROVED: email-routing");
console.log(failures === 0 ? "\nEMAIL-ROUTING ROUND TRIP PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
