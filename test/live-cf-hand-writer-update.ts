// LIVE: do the HAND-WRITTEN list writers actually UPDATE in place?
//
// WHY THIS EXISTS
// ---------------
// A writer proven by create-delete-restore has never had its update path called: the object is gone before
// the restore, so the restore creates. observability-saved-queries shipped past that harness with a PUT
// that answers 404, reporting "converged", because the failing update was caught as a per-item skip and
// `applied` stayed 0.
//
// live-cf-autoprove.ts now has an update leg, but it only covers surfaces in the create-bodies vector.
// The hand-written list writers are not in it, and they are the flagship surfaces: DNS records, firewall
// access rules at both scopes, and account rule lists. Their update paths were unverified.
//
// The shape here is the one the autoprove leg uses: create, capture, PERTURB the live object, restore the
// snapshot over it, and assert the update applied, the field came back, and exactly one copy exists.
// Perturbing a NON-IDENTIFYING field matters: change something preferredKey builds the key from and the
// writer correctly creates a second object, which reads as a writer defect and is the test's fault.
//
// MUTATES a real account, so DOWNPIPE_LIVE_CF=1, and everything it creates is deleted.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-hand-writer-update.ts

import { existsSync } from "node:fs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { announceKit, kitDir } from "./cf-kit.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { stripStamped } from "../src/sources/cf-config-shared.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
// kitDir(), not a hardcoded path. This file spelled the directory as one joined string rather than as
// separate segments, so a sweep that made every other harness kit-aware missed it, and it went on reading
// the throwaway account's credentials while the suite around it was pointed somewhere else. A run asked to
// use one account silently used two, and nothing in the output said so.
const D = kitDir();
if (process.env.DOWNPIPE_LIVE_CF !== "1" || !existsSync(join(D, "cf-api-token.txt"))) {
  console.log("SKIP live-cf-hand-writer-update: needs DOWNPIPE_LIVE_CF=1 and live credentials");
  verdictSkipped("SKIP live-cf-hand-writer-update: needs DOWNPIPE_LIVE_CF=1 and live credentials");
  process.exit(0);
}
  announceKit("live-cf-hand-writer-update");
const rd = (f: string) => readFileSync(join(D, f), "utf8").trim();
const api = makeCfApi(rd("cf-api-token.txt"));
const ids = { accountId: rd("account-id.txt"), zoneId: rd("zone-id.txt") };
const Z = ids.zoneId;
// Each: surface, the live collection path, a create body, and the field to perturb (non-identifying).
let failures = 0;
// Verified ids, for the suite's coverage check. Same one-line contract as the singleton prover.
const liveProved: string[] = [];
const CASES: Array<[string, string, Record<string, unknown>, string]> = [
  ["dns", `/zones/${Z}/dns_records`, { type: "TXT", name: "dp-upd.example.com", content: "original", ttl: 300 }, "content"],
  ["firewall-access-rules", `/zones/${Z}/firewall/access_rules/rules`, { mode: "block", configuration: { target: "ip", value: "203.0.113.9" }, notes: "original" }, "notes"],
  ["account-firewall-access-rules", `/accounts/${ids.accountId}/firewall/access_rules/rules`, { mode: "block", configuration: { target: "ip", value: "203.0.113.11" }, notes: "original" }, "notes"],
  ["account-rule-lists", `/accounts/${ids.accountId}/rules/lists`, { name: "dp_upd_list", kind: "ip", description: "original" }, "description"],
];
for (const [id, coll, body, field] of CASES) {
  const s = CF_CONFIG_SURFACES.find((x) => x.id === id)!;
  const marker = String(body.name ?? (body.configuration as Record<string, unknown>)?.value ?? "");
  const key = (o: Record<string, unknown>) => String(o.id ?? o.name ?? "");
  const mine = async () => ((await s.read(api, ids as never, undefined as never)) as Array<Record<string, unknown>>).filter((o) => JSON.stringify(o).includes(marker));
  for (const o of await mine()) await api.send("DELETE", `${coll}/${key(o)}`, undefined).catch(() => undefined);
  await api.send("POST", coll, body);
  const snap = (await s.read(api, ids as never, undefined as never)) as Array<Record<string, unknown>>;
  const before = (await mine())[0]!;
  // PERTURB a non-identifying field on the LIVE object, then restore the snapshot over it.
  // Perturb with the FULL stripped object first, then fall back to just the changed field. Rule lists
  // refuse a full body with filters.api.invalid_json: their update takes a narrow shape. That is a fact
  // about the endpoint, not about the writer, and the fallback keeps it from ending the run.
  let perturbed = false;
  for (const [m, b] of [["PATCH", { ...stripStamped(before), [field]: "perturbed" }], ["PUT", { ...stripStamped(before), [field]: "perturbed" }], ["PUT", { [field]: "perturbed" }], ["PATCH", { [field]: "perturbed" }]] as Array<["PATCH" | "PUT", Record<string, unknown>]>) {
    try { await api.send(m, `${coll}/${key(before)}`, b); perturbed = true; break; } catch { /* next shape */ }
  }
  if (!perturbed) { failures++; console.log(`  ${id.padEnd(30)} could not perturb the live object, update path not reachable here`); for (const o of await mine()) await api.send("DELETE", `${coll}/${key(o)}`, undefined).catch(() => undefined); continue; }
  const dmg = (await mine())[0];
  const changed = dmg !== undefined && String(dmg[field]) === "perturbed";
  const res = await s.write!(api, ids as never, snap, { dryRun: false }, undefined as never);
  const after = await mine();
  const ok = after.length === 1 && String(after[0]![field]) === String(body[field] ?? body.content);
  const verified = changed && ok && after.length === 1;
  if (!verified) failures++;
  else liveProved.push(id);
  console.log(`  ${id.padEnd(30)} damaged=${changed} applied=${res.applied} copies=${after.length} restored=${ok} ${verified ? "UPDATE VERIFIED" : "NOT VERIFIED"}`);
  for (const o of await mine()) await api.send("DELETE", `${coll}/${key(o)}`, undefined).catch(() => undefined);
}

console.log(`LIVE-PROVED: ${liveProved.sort().join(",")}`);
console.log(failures === 0 ? "\nHAND-WRITTEN WRITER UPDATE PATH PASS" : `\n${failures} writer(s) did not update in place`);
verdictReached(failures);
if (failures > 0) process.exit(1);
