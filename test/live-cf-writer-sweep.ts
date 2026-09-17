// LIVE writer sweep: validate EVERY surface that carries a write(), without needing to create an
// object, mutate anything, or hold an entitlement.
//
// WHY THIS EXISTS
// ---------------
// The full round trip in live-cf-roundtrip.ts is the strongest proof available, and it needs a
// surface-specific create body plus a plan that includes the product. On a Free account that reaches a
// handful of surfaces. Treating that as the only form of validation was wrong: two weaker but genuine
// tests run against every writer on any plan, and between them they catch the failure modes that
// actually corrupt data.
//
// TEST 1, CONVERGENCE. Read the live surface, feed that exact data back as the snapshot, and assert
// write() reports ZERO changes and applies NOTHING.
//
//   This is the important one. writeList matches a snapshot item to its live counterpart by server id
//   and by the surface's natural key. If the natural key does not match the surface's OWN read output,
//   the item reads as missing and the writer CREATES a duplicate. Feeding a surface its own live data is
//   the exact condition under which a correct writer must do nothing, so a wrong key shows up here as a
//   spurious add. No mutation, no entitlement, and it is meaningful on any surface that has at least one
//   live item.
//
// TEST 2, SYNTHETIC DRY RUN. Build a snapshot the live account does not contain and assert the dry run
// reports it as an add and applies NOTHING.
//
//   Weaker, but it runs on an EMPTY collection, which is most of them on a fresh account. It proves the
//   path resolves, the diff engine reaches the surface, the natural key is computable from an item, and
//   dryRun is honest. A writer that throws on a path typo fails here rather than in a customer's
//   restore.
//
// WHAT NEITHER TEST PROVES: that Cloudflare ACCEPTS the write body. Only a real apply does that, which
// is what the full round trip is for. A surface passing here is validated, not proven, and the two words
// are kept distinct everywhere.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-writer-sweep.ts

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { kitDir } from "./cf-kit.ts";
import { CF_CONFIG_SURFACES, makeCfApi } from "../src/sources/cf-config-surfaces.ts";
import { PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const KEYS = kitDir();
const read = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();

type Verdict = "CONVERGES" | "DRY-RUN-OK" | "KEY-MISMATCH" | "UNREADABLE" | "THREW";
const results: Array<{ id: string; verdict: Verdict; detail: string }> = [];

// syntheticItem builds an object the live account cannot already contain, shaped so that whichever
// field the writer's natural key prefers, it finds one.
function syntheticItem(tag: string): Record<string, unknown> {
  return { id: `synthetic-${tag}`, name: `synthetic-${tag}`, title: `synthetic-${tag}`, description: "downpipes writer sweep", enabled: false };
}

async function main(): Promise<void> {
  if (process.env.DOWNPIPE_LIVE_CF !== "1") {
    console.log("SKIP live-cf-writer-sweep: set DOWNPIPE_LIVE_CF=1 to run");
    verdictSkipped("SKIP live-cf-writer-sweep: set DOWNPIPE_LIVE_CF=1 to run");
    return;
  }
  if (!existsSync(join(KEYS, "cf-api-token.txt"))) {
    console.log(`SKIP live-cf-writer-sweep: no credentials at ${KEYS}`);
    verdictSkipped(`SKIP live-cf-writer-sweep: no credentials at ${KEYS}`);
    return;
  }
  const api = makeCfApi(read("cf-api-token.txt"));
  const ids = { accountId: read("account-id.txt"), zoneId: read("zone-id.txt") };
  const tag = `s${Date.now().toString(36)}`;

  const writers = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function");
  console.log(`sweeping ${writers.length} surfaces that carry a write()\n`);

  for (const s of writers) {
    try {
      let live: unknown;
      try {
        live = await s.read(api, ids);
      } catch (e) {
        results.push({ id: s.id, verdict: "UNREADABLE", detail: (e as Error).message.slice(0, 70) });
        continue;
      }

      // TEST 1: convergence. Only meaningful when the surface actually has items; an empty list
      // converges trivially and proves nothing about the key.
      const hasItems = Array.isArray(live) ? live.length > 0 : live !== null && live !== undefined;
      if (hasItems) {
        const back = await s.write!(api, ids, live, { dryRun: true });
        // A live-only "remove" is F9 reporting, not a change the writer would apply. Only adds and
        // changes mean the writer failed to recognise the account's own data.
        const wouldWrite = back.changes.filter((c) => c.action !== "remove");
        if (wouldWrite.length === 0) {
          results.push({ id: s.id, verdict: "CONVERGES", detail: Array.isArray(live) ? `${live.length} live item(s) all recognised` : "singleton recognised" });
          continue;
        }
        results.push({
          id: s.id,
          verdict: "KEY-MISMATCH",
          detail: `feeding the surface its OWN data would write ${wouldWrite.length} item(s): ${wouldWrite.slice(0, 2).map((c) => `${c.action} ${c.path}`).join("; ")}`,
        });
        continue;
      }

      // TEST 2: synthetic dry run against an empty collection.
      const synthetic = Array.isArray(live) ? [syntheticItem(tag)] : syntheticItem(tag);
      const dry = await s.write!(api, ids, synthetic, { dryRun: true });
      const adds = dry.changes.filter((c) => c.action === "add").length;
      if (dry.applied !== 0) {
        results.push({ id: s.id, verdict: "THREW", detail: "dry run APPLIED something, which it must never do" });
      } else if (adds >= 1 || dry.skipped.length > 0) {
        results.push({ id: s.id, verdict: "DRY-RUN-OK", detail: adds >= 1 ? "empty live, synthetic item reads as an add" : `refused cleanly: ${dry.skipped[0]?.cls}` });
      } else {
        results.push({ id: s.id, verdict: "THREW", detail: "dry run reported neither a change nor a refusal" });
      }
    } catch (e) {
      results.push({ id: s.id, verdict: "THREW", detail: (e as Error).message.slice(0, 70) });
    }
  }

  const by = (v: Verdict) => results.filter((r) => r.verdict === v);
  for (const v of ["KEY-MISMATCH", "THREW", "UNREADABLE", "CONVERGES", "DRY-RUN-OK"] as Verdict[]) {
    const rs = by(v);
    if (rs.length === 0) continue;
    console.log(`${v} (${rs.length}):`);
    for (const r of rs) console.log(`   ${r.id.padEnd(38)} ${r.detail}`);
    console.log("");
  }

  const proven = results.filter((r) => PROVEN_WRITE_SURFACES.has(r.id));
  console.log(`of the ${proven.length} PROVEN surfaces, ${proven.filter((r) => r.verdict === "CONVERGES" || r.verdict === "DRY-RUN-OK").length} also pass this sweep (a control: a proven writer must never fail here)`);

  const bad = by("KEY-MISMATCH").length + by("THREW").length;
  console.log(bad === 0 ? "\nWRITER SWEEP PASS" : `\n${bad} WRITER SWEEP FAILURE(S)`);
  verdictReached(bad);
  if (bad > 0) process.exit(1);
}

await main();
