// LIVE idempotence sweep: capture every writable surface, then dry-run its own snapshot back at it.
//
// WHY THIS EXISTS
// ---------------
// An identical snapshot must be a clean no-op. If a writer reports changes or skips when live and
// snapshot are the same bytes, then a real restore would churn, refuse, or destroy, and none of those is
// what the operator asked for. It is the cheapest possible question to ask a writer and it catches a
// whole class of defect that the round-trip harness does not.
//
// It exists because two defects hid from everything else on this branch:
//
//   1. writeRulesets paginated the ruleset index at the registry default, which Cloudflare refuses above
//      50, so the WRITE path of both flagship WAF surfaces threw on every account. The READ half had been
//      fixed for exactly this. The write half was missed because the auto-prove sweep only covers
//      GENERATED writers, and these two are hand-written and predate it, so they were carried as proven
//      on a proof that never touched that line.
//   2. writeSingleSetting assumed every zone setting carries its value under `value`. auto_origin_tls_kex
//      carries it under `enabled` and refuses {value: ...} outright, so that surface skipped on every
//      restore, including when nothing had changed.
//
// Both showed up here in one run, and neither could have shown up in a test that only exercises surfaces
// with a synthesised create body.
//
// WHAT A FAILURE MEANS
// --------------------
// READ THREW      the surface cannot capture. Usually an account entitlement, sometimes ours.
// WRITE THREW     the writer cannot run at all. Always ours.
// NOT A NO-OP     the writer thinks live differs from itself. Always ours, and the most dangerous of the
//                 three, because it means a restore acts when it should have done nothing.
//
// A NO-OP AGAINST AN EMPTY COLLECTION IS NOT A PASS, and this harness used to record it as one. The
// writer had nothing to compare, so it could not have found a difference however broken it was. Those are
// counted as VACUOUS and named. The number that matters is "clean against real data", which on this
// account is a small fraction of the writers.
//
// Entitlement refusals on the read are reported but do not fail the run: they are a fact about the
// proving account, and a Free account cannot read Spectrum or DEX no matter how correct the code is. A
// WRITE that throws, or any writer that is not a no-op against its own snapshot, fails.
//
// This MUTATES NOTHING. Every write is dryRun: true. It is still gated on DOWNPIPE_LIVE_CF=1 because it
// reads a real account with real credentials, and it is deliberately not in the `validate` aggregate.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-idempotence.ts

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { announceKit, kitDir } from "./cf-kit.ts";
import { classifyRefusal } from "./cf-refusal.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { GENERATED_KEY_FIELDS, PROVEN_WRITE_SURFACES, resolveServerIdField } from "../src/sources/cf-config-write-generated.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

// The kit is selectable (DOWNPIPE_CF_KIT); see test/cf-kit.ts for which harnesses are safe against
// a real account and which are not.
const KEYS = kitDir();
const read = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();


// One shared classifier, so the same Cloudflare message cannot mean different things in different
// harnesses. This file and live-cf-idempotence.ts used to carry character-identical copies of one pattern
// and live-cf-autoprove.ts a different, narrower one.
const isAccountRefusal = (m: string): boolean => classifyRefusal(m) === "account";

async function main(): Promise<void> {
  if (process.env.DOWNPIPE_LIVE_CF !== "1" || !existsSync(join(KEYS, "cf-api-token.txt"))) {
    console.log("SKIP live-cf-idempotence: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    verdictSkipped("SKIP live-cf-idempotence: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    return;
  }
  announceKit("live-cf-idempotence");
  const api = makeCfApi(read("cf-api-token.txt"));
  const ids = { accountId: read("account-id.txt"), zoneId: read("zone-id.txt") };

  const writers = CF_CONFIG_SURFACES.filter((s) => typeof s.write === "function");
  const failures: string[] = [];
  const accountLimited: string[] = [];
  const vacuous: string[] = [];
  // Findings that did NOT reproduce on a re-read. Reported loudly rather than dropped: a run that hit
  // interference is a run whose other results are also suspect.
  const transient: string[] = [];
  let clean = 0;

  for (const s of writers) {
    const tag = PROVEN_WRITE_SURFACES.has(s.id) ? "PROVEN" : "avail ";
    let snap: unknown;
    try {
      snap = await s.read(api, ids, undefined);
    } catch (e) {
      const m = (e as Error).message;
      if (isAccountRefusal(m)) accountLimited.push(`${s.id}: read refused by the account`);
      else failures.push(`${tag} ${s.id}: READ THREW ${m.replace(/\s+/g, " ").slice(0, 110)}`);
      continue;
    }
    // A surface that archived a marker has nothing to feed back; that is the read sweep's business.
    if (snap !== null && typeof snap === "object" && !Array.isArray(snap) && "_unavailable" in (snap as object)) {
      accountLimited.push(`${s.id}: read returned an unavailable marker`);
      continue;
    }
    // CAN THE WRITER ADDRESS AN ITEM AT ALL? A collection whose items carry no id, no *_id and no declared
    // keyField cannot be updated: writeListSpec skips every changed item with "no id to update in place",
    // so the writer creates on a restore-after-delete and silently does nothing on a restore-over-live.
    // That is invisible to the no-op check below, because a writer that cannot update also cannot churn.
    //
    // Two surfaces shipped in exactly that state (both custom-page-assets) and were only caught because a
    // real account let the create succeed. This asks the question directly, using the writer's OWN resolver
    // and the real declarations rather than a second copy of either.
    if (Array.isArray(snap) && snap.length > 0 && typeof snap[0] === "object" && snap[0] !== null) {
      const first = snap[0] as Record<string, unknown>;
      if (resolveServerIdField(first) === "" && !GENERATED_KEY_FIELDS.has(s.id)) {
        failures.push(`${tag} ${s.id}: NOT ADDRESSABLE, items carry no id and no keyField is declared, so the writer can create but never update (keys: ${Object.keys(first).slice(0, 6).join(",")})`);
        continue;
      }
    }
    try {
      const r = await s.write?.(api, ids, snap, { dryRun: true }, undefined);
      if (r === undefined) continue;
      if (r.changes.length === 0 && r.skipped.length === 0) {
        // A no-op against an EMPTY collection is not evidence of anything. The writer had nothing to
        // compare, so it could not have found a difference however broken it was. Counting that as clean
        // is the vacuous pass the capture-completeness harness was built to refuse, and this older sweep
        // was still making it: removing a field from SERVER_STAMPED, which genuinely breaks convergence
        // for secondary-dns-acls, changed nothing here because that surface is empty on this account.
        if (Array.isArray(snap) && snap.length === 0) vacuous.push(s.id);
        else clean++;
        continue;
      }
      // A skip whose cause is the account rather than the writer is not a defect. Everything else is.
      const onlyAccount = r.changes.length === 0 && r.skipped.every((k) => k.cls === "entitlement");
      if (onlyAccount) {
        accountLimited.push(`${s.id}: ${r.skipped[0]?.reason?.slice(0, 70) ?? "entitlement"}`);
        continue;
      }
      // RE-CHECK BEFORE CALLING IT A DEFECT. Real churn is deterministic: the writer's own rule says live
      // differs from itself, and re-reading changes nothing. Interference is not: another process writing
      // to the same account between this harness's read and the writer's read produces the identical
      // symptom, and it is convincing.
      //
      // Both false alarms were on PROVEN surfaces and both cleared on a second run: secondary-dns-acls had
      // an in-flight create from a concurrent suite, and gateway-logging had an orphaned stage still
      // running after its parent was killed. Each read exactly like "a restore acts when it should have
      // done nothing", which this file calls the most dangerous of the three failures.
      //
      // One extra read per FINDING, never per surface, which is the cheapest place to spend it.
      //
      // ONE re-check, not a retry loop. Interference that is still ongoing can survive it, so this reduces
      // false defects rather than eliminating them, and the transient bucket says re-run rather than
      // claiming the run is now trustworthy.
      //
      // The re-check is caught SEPARATELY. Letting it fall to the outer catch labelled a failed re-READ as
      // "WRITE THREW", which is the wrong half of the operation and would send the next person looking at
      // the writer for a fault in the read.
      let reproduced = true;
      try {
        const snap2 = await s.read(api, ids, undefined);
        const r2 = await s.write?.(api, ids, snap2, { dryRun: true }, undefined);
        reproduced = !(r2 !== undefined && r2.changes.length === 0 && r2.skipped.length === 0);
      } catch (e) {
        // The re-check itself could not run. That is not evidence either way, so the original finding
        // stands and says so rather than being upgraded or dropped on a failed second look.
        failures.push(`${tag} ${s.id}: NOT A NO-OP, and the re-check could not run: ${(e as Error).message.replace(/\s+/g, " ").slice(0, 80)}`);
        continue;
      }
      if (!reproduced) {
        transient.push(`${s.id}: reported a non-no-op that did NOT reproduce on re-read (another process was writing to this account)`);
        continue;
      }
      failures.push(
        `${tag} ${s.id}: NOT A NO-OP against its own snapshot (changes=${r.changes.length}, skipped=${r.skipped.map((k) => k.cls).join(",") || "none"})`,
      );
    } catch (e) {
      failures.push(`${tag} ${s.id}: WRITE THREW ${(e as Error).message.replace(/\s+/g, " ").slice(0, 110)}`);
    }
  }

  console.log(`-- ${writers.length} writers swept --`);
  console.log(`  clean no-op          ${clean} (against real data)`);
  console.log(`  VACUOUS              ${vacuous.length} (the collection is empty, so a no-op proves nothing; NOT a pass)`);
  console.log(`  account-limited      ${accountLimited.length} (reported, not failed)`);
  for (const a of accountLimited.sort()) console.log(`     ${a}`);
  // Reported even when zero is the interesting number, because a run that hit interference is a run whose
  // other results are also suspect, and silently absorbing that would make this harness the thing it
  // exists to refuse: a green that describes a run nobody can trust.
  if (transient.length > 0) {
    console.log(`  DID NOT REPRODUCE    ${transient.length} (something else was writing to this account DURING this run)`);
    for (const t of transient) console.log(`     ${t}`);
    console.log("     Re-run with nothing else touching the account before trusting anything above.");
  }
  console.log(`  DEFECTS              ${failures.length}`);
  for (const f of failures.sort()) console.log(`     ${f}`);

  console.log(failures.length === 0 ? "\nCF-CONFIG LIVE IDEMPOTENCE PASS" : `\n${failures.length} FAILURE(S)`);
  verdictReached(failures.length);
  if (failures.length > 0) process.exit(1);
}

await main();
