// The generated writer table and the proven/available contract, pinned OFFLINE.
//
// WHY THIS EXISTS
// ---------------
// 30 of the 47 surfaces carrying a write() were generated from Cloudflare's published schema. This
// validator enforces, offline, that an unproven writer never runs unless an operator names it
// explicitly: resolveCfConfigSurfaces must default to only the proven set, so a restore that names no
// scope never reaches a writer whose natural key has not been tested against real data.
//
// No network, no credentials, no live account. Run: node test/validate-cf-config-write-generated.ts

import { resolveCfConfigSurfaces } from "../src/admin/approvals.ts";
import { CF_CONFIG_SURFACES, surfaceById } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const withWriter = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function");
const writerIds = new Set(withWriter.map((s) => s.id));
const proven = [...PROVEN_WRITE_SURFACES];

console.log("-- the registry side --");
ok("some surfaces carry a writer, so these assertions are not vacuous", withWriter.length > 0);
ok("some are proven, so the default scope is not empty", proven.length > 0);
ok("there are MORE writers than proven ones, so the split is real and not a rename", withWriter.length > proven.length);

// A generated writer attached to an ordered or reprovision surface would be a category error: those
// tiers exist because a flat item-by-item apply cannot restore them safely, and attachGenerated is
// supposed to skip them.
const misTiered = withWriter.filter((s) => s.restoreTier !== "idempotent");
ok(`no surface with a writer is ordered or reprovision (found ${misTiered.map((s) => `${s.id}:${s.restoreTier}`).join(", ") || "none"})`, misTiered.length === 0);

console.log("\n-- PROVEN_WRITE_SURFACES is honest about itself --");
const ghosts = proven.filter((id) => surfaceById(id) === undefined);
ok(`every proven id exists in the registry (ghosts: ${ghosts.join(", ") || "none"})`, ghosts.length === 0);
const provenWithoutWriter = proven.filter((id) => !writerIds.has(id));
ok(`every proven id actually carries a write() (missing: ${provenWithoutWriter.join(", ") || "none"})`, provenWithoutWriter.length === 0);
ok("proven is a strict SUBSET of the surfaces carrying a writer", proven.every((id) => writerIds.has(id)) && proven.length < withWriter.length);

console.log("\n-- the default restore scope, which is the safety property --");
const def = resolveCfConfigSurfaces();
ok("the default resolves to exactly the proven set", def.length === proven.length && def.every((id) => PROVEN_WRITE_SURFACES.has(id)));
const unproven = withWriter.map((s) => s.id).filter((id) => !PROVEN_WRITE_SURFACES.has(id));
ok(`no UNPROVEN writer is reachable by default (${unproven.length} unproven, none in the default)`, unproven.every((id) => !def.includes(id)));
ok("the default is sorted and deduped, so the plan hash is stable under registry order", JSON.stringify(def) === JSON.stringify([...new Set(def)].sort()));

console.log("\n-- an explicit allow-list can only NARROW --");
if (unproven.length > 0) {
  const named = resolveCfConfigSurfaces([unproven[0]!]);
  ok("naming an unproven writer DOES reach it, so the opt-in is real and not decorative", named.includes(unproven[0]!));
  ok("naming one surface returns exactly that surface", named.length === 1);
}
const bogus = resolveCfConfigSurfaces(["account-members", "not-a-real-surface"]);
ok("naming an ordered surface and a nonexistent one grants neither", bogus.length === 0);
const everything = resolveCfConfigSurfaces(withWriter.map((s) => s.id));
ok("naming every writer reaches every writer, and is WIDER than the default", everything.length === withWriter.length && everything.length > def.length);
ok("an empty allow-list grants nothing, rather than falling back to the default", resolveCfConfigSurfaces([]).length === 0);

console.log("\n-- a SHAPE-CHANGING reader must not leave its writer diffing unlike shapes --");
// writeListSpec paginates listPath itself unless the spec supplies readLive. That is fine for a reader
// that only changes the PAGE SIZE (listCapped): the writer's paginateAdaptive discovers the same cap and
// lands on the same data, which two proven surfaces demonstrate. It is NOT fine for a reader that changes
// the SHAPE of what comes back. gateway-lists sub-reads each list's items, so the writer's live view had
// no `items` key at all, every list looked changed on every run, and the nested guard could not see the
// entries it exists to protect. The restore worked correctly each time and simply never converged, which
// is why nothing caught it from the outside.
//
// This gate is structural and reads the registry source, because the failure is a MISSING option and
// there is nothing to observe at runtime when it is absent: the writer just quietly diffs the wrong thing.
{
  const fs = await import("node:fs");
  const readSrc = ["cf-config-registry-core.ts", "cf-config-registry-expanded.ts", "cf-config-registry-gaps.ts", "cf-config-registry-gaps2.ts"]
    .map((f) => fs.readFileSync(new URL(`../src/sources/${f}`, import.meta.url), "utf8"))
    .join("\n");
  const genSrc = fs.readFileSync(new URL("../src/sources/cf-config-write-generated.ts", import.meta.url), "utf8");

  // Readers that change the SHAPE of an item, not merely how many come per page.
  const SHAPE_CHANGING = ["listWithSub", "listEnvelope"];
  const shapeChanged = new Set<string>();
  for (const helper of SHAPE_CHANGING) {
    for (const m of readSrc.matchAll(new RegExp(`\\{ id: "([a-z0-9-]+)"[^\\n]*read: ${helper}\\(`, "g"))) shapeChanged.add(m[1]!);
  }
  ok(`the registry uses a shape-changing reader somewhere, so this gate is not vacuous (${shapeChanged.size} surface(s))`, shapeChanged.size > 0);

  // Which of those also carry a generated writer, and does that writer supply its own reader?
  const offenders: string[] = [];
  for (const id of shapeChanged) {
    const row = new RegExp(`\\{ id: "${id}", listPath[^\\n]*`).exec(genSrc);
    if (row === null) continue; // no generated writer: nothing to mismatch
    if (!/subCollection:|readLive/.test(row[0])) offenders.push(id);
  }
  ok(
    `every shape-changing surface with a generated writer supplies its own reader (offenders: ${offenders.join(", ") || "none"})`,
    offenders.length === 0,
  );

  // And prove the mechanism is actually in use, so the assertion above cannot pass by everything opting out.
  ok("gateway-lists carries the subCollection that makes its writer read live the surface's way", /\{ id: "gateway-lists", listPath[^\n]*subCollection:/.test(genSrc));
}

console.log("\n-- the restore plan gates on the same function, not a second copy --");
// A structural check rather than a behavioural one: restore-plan.ts must import the resolver rather than
// re-derive the set, because two code paths agreeing today is not the same as them being the same set.
const planSrc = await import("node:fs").then((fs) => fs.readFileSync(new URL("../src/admin/restore-plan.ts", import.meta.url), "utf8"));
ok("restore-plan.ts imports resolveCfConfigSurfaces rather than re-deriving the set", planSrc.includes("resolveCfConfigSurfaces"));
// Pin the GATE, not the mere presence of the string. `allowedSurfaces.has(rec.name)` appears twice in
// that file, once in the gate and once in the branch that explains why a surface was excluded, so the
// condition must guard the configPlan.push itself, not merely be near a mention of it.
const gated = /if\s*\([^)]*allowedSurfaces\.has\(rec\.name\)[^)]*\)\s*\{\s*configPlan\.push/.test(planSrc.replace(/\n\s*/g, " "));
ok("the configPlan.push is guarded by the resolved allow-list, not merely near a mention of it", gated);
ok("a surface outside the allow-list is reported out of band, not silently dropped", planSrc.includes("outside the approved surface list"));

console.log(failures === 0 ? "\nCF-CONFIG GENERATED-WRITER CONTRACT PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
