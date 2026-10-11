// The site-fault legend names, for each site whose fix class undermines the rest of the pack, the pack evidence
// it undermines. The support pack carries that list on the site's row, so a reader of the pack needs no copy of
// the legend.
//
// What this proves:
//   - a site in the storage-health or engine-defect class has an `undermines` list; the list may be empty (the
//     entry names no pack section, so the whole pack needs review);
//   - a site in any other class has no `undermines` field;
//   - each name is a short pack path token;
//   - the pack row for every site carries exactly its legend entry's `undermines`, and carries no key when the
//     entry has none.
//
// Run: node test/validate-site-fault-legend-undermines.ts

import { SITE_FAULT_LEGEND, type SiteFaultLegendEntry } from "../src/admin/site-fault-legend.ts";
import { fetchSiteFaults } from "../src/admin/site-faults.ts";
import { ok, tally } from "./lib/site-fault-proof.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const UNDERMINING = new Set(["storage-health", "engine-defect"]);
const PATH_TOKEN = /^[A-Za-z][A-Za-z0-9]*(?:\[\])?(?:\.[A-Za-z][A-Za-z0-9]*(?:\[\])?)*$/;

async function main(): Promise<void> {
  const ids = Object.keys(SITE_FAULT_LEGEND);
  const entry = (id: string): SiteFaultLegendEntry => (SITE_FAULT_LEGEND as Record<string, SiteFaultLegendEntry>)[id] as SiteFaultLegendEntry;

  console.log("the legend:");
  const missing = ids.filter((id) => UNDERMINING.has(entry(id).fixClass) && !Array.isArray(entry(id).undermines));
  ok(`every undermining site has an undermines list (missing: ${missing.join(", ") || "none"})`, missing.length === 0);
  const stray = ids.filter((id) => !UNDERMINING.has(entry(id).fixClass) && entry(id).undermines !== undefined);
  ok(`no harmless site has an undermines field (stray: ${stray.join(", ") || "none"})`, stray.length === 0);
  const bad = ids.flatMap((id) => (entry(id).undermines ?? []).filter((t) => typeof t !== "string" || t.length > 64 || !PATH_TOKEN.test(t)).map((t) => `${id}:${t}`));
  ok(`every undermines name is a pack path token (bad: ${bad.join(", ") || "none"})`, bad.length === 0);
  ok("the rate limiter's health read undermines rateLimitDoHealth", entry("ratelimit.health-read").undermines?.join() === "rateLimitDoHealth");
  ok("the replica floor write undermines the replication evidence", entry("sched.replica-floor-write").undermines?.join() === "downpipes[].replication");
  ok("the member-invite body site undermines nothing by name", Array.isArray(entry("admin.member-invite-body").undermines) && entry("admin.member-invite-body").undermines?.length === 0);

  console.log("the pack row:");
  const faults: Record<string, { count: number; firstAt: number; lastAt: number; lastCls: string }> = {};
  for (const id of ids) faults[id] = { count: 1, firstAt: 1_000, lastAt: 2_000, lastCls: "error" };
  const scheduler = { fetch: async () => Response.json({ faults }) } as unknown as DurableObjectStub;
  const rows = (await fetchSiteFaults(scheduler)) as unknown as Array<Record<string, unknown>>;
  ok(`the pack carries a row for each of the ${ids.length} legend sites`, rows.length === ids.length);
  const wrong = rows.filter((r) => JSON.stringify(r.undermines) !== JSON.stringify(entry(r.id as string).undermines) || ("undermines" in r) !== (entry(r.id as string).undermines !== undefined));
  ok(`each row's undermines equals its legend entry's, and is absent when the entry has none (wrong: ${wrong.map((r) => r.id).join(", ") || "none"})`, wrong.length === 0);

  const { failures, checks } = tally();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-site-fault-legend-undermines (${failures} failure(s) of ${checks})`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
