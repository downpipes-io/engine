// LIVE capture completeness: does the archive hold everything the surface actually has?
//
// WHY THIS EXISTS
// ---------------
// The worst defects this check catches share this shape, and neither is visible from any other check.
// gateway-lists archived `count: 3` and none of the three values, which for a Zero Trust
// allowlist is the entire security-relevant content. rum-site-info archived a list of opaque site tags
// while the host, the site token and the snippet lived at the per-item endpoint. Both surfaces READ
// cleanly, reported no fault, and produced an archive from which nothing could be rebuilt.
//
// Nothing else catches this. The read sweep asks "did it read"; the idempotence sweep asks "does the
// writer converge"; the drift guard asks "are our endpoints in Cloudflare's schema". All three pass on a
// surface that captured a count and threw the contents away.
//
// THE VACUOUS-DETECTOR TRAP, WHICH IS WHY THIS REPORTS FOUR OUTCOMES AND NOT TWO
// -----------------------------------------------------------------------------
// A detector that only classifies whatever data exists reports "no gap" when the account holds no
// instance of the surface: there is nothing to inspect, and the absence of evidence reads as evidence of
// absence. Such a detector only answers once something exists to look at.
//
// So a surface with nothing in it is NOT reported clean here. It is counted separately and never called a
// pass. A green line in this harness means "we looked at real data and it was complete", never "we looked
// and there was nothing there".
//
// "NOTHING THERE" IS NOT THE SAME AS "WE COULD NOT LOOK"
// -------------------------------------------------------
// Folding both into one `notObservable` bucket hides the distinction: a surface whose read is REFUSED
// would disappear into the same total as a surface the account simply does not use, and the refusal is
// the one an operator can act on. A refused read is its own outcome, named surface by surface with the
// closed transport class of the refusal, and it is never called "nothing configured".
//
// The classes matter more than they look. A `page-rules` read refused with Cloudflare code 1011 is a TOKEN
// CLASS gate (the endpoint declines account-owned tokens and reads normally under a user-owned one), not a
// missing permission, and the two want opposite remedies. Reporting them as one number said neither.
//
// WHAT IT CHECKS
// --------------
//   1. A COUNT WITHOUT ITS CONTENTS. An item carrying count/num_items/total and no corresponding array is
//      claiming to know how many of something it has while archiving none of them.
//   2. AN IDENTIFIER WITHOUT ITS OBJECT. A list of primitives is a list of names for things that were not
//      captured.
//
// WHY IT DECLARES A CHECK COUNT
// -----------------------------
// `verdictReached(gaps.length)` alone cannot pass: the guard refuses a verdict declared with no check
// count and no assertion lines. A sweep that observed nothing but reported zero gaps would otherwise
// reach a false pass by having nothing to say, which is a gate that cannot fail rather than one that can
// meaningfully pass. So this file declares its own check count, and that count is deliberately the
// surfaces a real completeness judgement was made on (complete plus gaps), NOT the total swept: a run
// that observed nothing has checked nothing, and the guard is right to refuse it.
//
// Read-only: it issues GETs through each surface's own read() and writes nothing. Still gated on
// DOWNPIPE_LIVE_CF=1 because it reads a real account with real credentials, and deliberately not in the
// `validate` aggregate. The pure reporting half IS gated, without a credential, by
// test/validate-cf-capture-completeness-report.ts.
//
// SEED MODE (--seed) turns "nothing configured" into an answer where it can.
//
// 145 surfaces read as an empty list on the proving account, so their capture has never been exercised
// against real data at all. For 42 of those the autoprove vector already carries a create body. Seed mode
// creates one object, re-reads through the surface's own read(), applies the same completeness rules, and
// deletes it again. A surface that was merely unobserved becomes either verified or a named gap.
//
// It MUTATES, which is why it is behind its own flag rather than on by default, and why every create is
// swept in a finally. A create that fails is not a defect and is not reported as one: most of these
// surfaces are entitlement-blocked on a Free account, which is a fact about the account.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-capture-completeness.ts          read-only
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-capture-completeness.ts --seed   create, verify, delete

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { announceKit, kitDir } from "./cf-kit.ts";
import { itemKey } from "./cf-item-key.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { CF_CONFIG_SURFACES } from "../src/sources/cf-config-surfaces.ts";
import { classifySourceFaultStatus } from "../src/sources/source-fault-ledger.ts";
import { isEntryPoint, verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

// The kit is selectable (DOWNPIPE_CF_KIT); see test/cf-kit.ts for which harnesses are safe against
// a real account and which are not.
const KEYS = kitDir();
const read = (f: string): string => readFileSync(join(KEYS, f), "utf8").trim();

// A field that counts something. If an item carries one of these and no array beside it, the contents it
// is counting are not in the archive.
const COUNT_FIELD = /^(count|num_items|num_referencing_filters|total|total_count|item_count|rule_count|members?_count|size)$/i;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * CaptureOutcome is the CLOSED verdict on one surface's read. The four arms exist because the four
 * situations want four different things from a reader, and collapsing any two of them would report
 * a refusal as an empty account.
 *   complete   - we looked at real data and the capture holds it. The only arm that is a pass.
 *   gap        - we looked at real data and the capture is short of it. The only arm that fails.
 *   empty      - the account holds nothing here. Not a pass and not a failure: nothing was judged.
 *   unreadable - we could not look at all. Not a pass and not a failure HERE, because a Free account
 *                legitimately refuses many surfaces, but it is named so it is actionable rather than
 *                absorbed into the empty count.
 */
export type CaptureOutcome = { kind: "complete" } | { kind: "gap"; reason: string } | { kind: "empty" } | { kind: "unreadable"; reason: string };

/**
 * classifyCaptureOutcome applies the completeness rules to one surface's read output.
 *
 * @param out - what the surface's own read() returned.
 * @returns the closed outcome for that surface.
 */
export function classifyCaptureOutcome(out: unknown): CaptureOutcome {
  if (out === null) return { kind: "empty" };
  // A read that answered with an incompleteness marker did not show us the surface. Treating it the
  // same as "nothing to look at" would conflate it with a genuinely empty account, which this arm avoids.
  if (isPlainObject(out) && "_unavailable" in out) return { kind: "unreadable", reason: "the read returned an unavailable marker" };
  const wasArray = Array.isArray(out);
  if (!wasArray && !isPlainObject(out)) return { kind: "complete" };
  const items = wasArray ? (out as unknown[]) : [out];
  if (items.length === 0) return { kind: "empty" };
  for (const it of items) {
    if (wasArray && !isPlainObject(it)) return { kind: "gap", reason: `list holds ${typeof it} identifiers, not objects (e.g. ${JSON.stringify(it).slice(0, 40)})` };
    if (!isPlainObject(it)) continue;
    const counts = Object.keys(it).filter((k) => COUNT_FIELD.test(k) && typeof it[k] === "number" && (it[k] as number) > 0);
    if (counts.length > 0 && !Object.values(it).some((v) => Array.isArray(v))) {
      return { kind: "gap", reason: `carries ${counts.map((k) => `${k}=${it[k] as number}`).join(", ")} but no array holding what it counts` };
    }
  }
  return { kind: "complete" };
}

/** CaptureTally is the per-outcome accumulation of a sweep. Every list holds surface ids (or "id: reason"). */
export interface CaptureTally {
  complete: string[];
  gaps: string[];
  empty: string[];
  unreadable: string[];
  seeded: string[];
  seedFailed: string[];
}

/** CaptureReport is what a sweep reports: the lines to print, and the two numbers the verdict guard needs. */
export interface CaptureReport {
  lines: string[];
  failures: number;
  /** how many surfaces a real completeness judgement was made on. Zero means the sweep judged nothing. */
  checks: number;
}

/**
 * reportCapture turns a tally into the printable report and the verdict numbers. It is pure and exported
 * so the reporting half is gated WITHOUT a live account (validate-cf-capture-completeness-report.ts):
 * the defect it closes was in the reporting, not in the reading, and a check that needs a credential to
 * run is a check that does not run.
 *
 * @param t - the accumulated per-outcome lists.
 * @param total - how many surfaces the sweep walked.
 * @param seed - whether seed mode ran, which adds its own two lines.
 * @returns the lines to print plus the failure and check counts.
 */
export function reportCapture(t: CaptureTally, total: number, seed = false): CaptureReport {
  const lines: string[] = [];
  lines.push(`-- ${total} surfaces --`);
  lines.push(`  complete, on real data   ${t.complete.length}`);
  lines.push(`  nothing configured       ${t.empty.length} (nothing on this account to inspect; NOT a pass)`);
  // The refused set is NAMED in full. It is small, it is the actionable one, and printing only its size is
  // what let a surface nobody could read sit inside a number that read as "this account does not use it".
  lines.push(`  UNREADABLE               ${t.unreadable.length} (we could not look; NOT a pass and NOT an empty account)`);
  for (const u of [...t.unreadable].sort()) lines.push(`     ${u}`);
  if (seed) lines.push(`  made observable by seeding ${t.seeded.length}${t.seedFailed.length > 0 ? `, ${t.seedFailed.length} could not be created (usually an account entitlement, not a defect)` : ""}`);
  lines.push(`  GAPS                     ${t.gaps.length}`);
  for (const g of [...t.gaps].sort()) lines.push(`     ${g}`);
  lines.push(t.gaps.length === 0 ? "\nCF-CONFIG CAPTURE COMPLETENESS PASS" : `\n${t.gaps.length} CAPTURE GAP(S)`);
  // checks counts ONLY the surfaces judged on real data. An `empty` or `unreadable` surface was not judged,
  // so counting it here would let a sweep that looked at nothing declare a confident pass over 313 surfaces.
  return { lines, failures: t.gaps.length, checks: t.complete.length + t.gaps.length };
}

async function main(): Promise<void> {
  if (process.env.DOWNPIPE_LIVE_CF !== "1" || !existsSync(join(KEYS, "cf-api-token.txt"))) {
    console.log("SKIP live-cf-capture-completeness: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    verdictSkipped("SKIP live-cf-capture-completeness: needs DOWNPIPE_LIVE_CF=1 and live credentials");
    return;
  }
  announceKit("live-cf-capture-completeness");
  const api = makeCfApi(read("cf-api-token.txt"));
  const ids = { accountId: read("account-id.txt"), zoneId: read("zone-id.txt") };

  const t: CaptureTally = { complete: [], gaps: [], empty: [], unreadable: [], seeded: [], seedFailed: [] };

  const SEED = process.argv.includes("--seed");
  const vector: Record<string, { path: string; body: Record<string, unknown> | null }> = SEED
    ? JSON.parse(readFileSync(new URL("./vectors/cf-config/autoprove-bodies.json", import.meta.url), "utf8"))
    : {};
  const resolvePath = (t2: string): string => t2.replace("/accounts/{}", `/accounts/${ids.accountId}`).replace("/zones/{}", `/zones/${ids.zoneId}`);

  for (const s of CF_CONFIG_SURFACES) {
    let out: unknown;
    try {
      out = await s.read(api, ids, undefined);
    } catch (e) {
      // The closed transport class, never the Cloudflare message: it separates an expired token (401) from
      // a missing scope (403) from a deprecated endpoint (404) from an outage (5xx), which is the whole
      // reason a refusal is worth naming. Nothing here can carry a credential or a customer value.
      t.unreadable.push(`${s.id}: read refused (${classifySourceFaultStatus(e)})`);
      continue;
    }
    let outcome = classifyCaptureOutcome(out);
    if (outcome.kind === "empty" && SEED && vector[s.id]?.body != null) {
      // Nothing to look at, but we can make something. Create, re-read, classify, and always delete.
      const coll = resolvePath(vector[s.id]!.path);
      let createdKey = "";
      try {
        const raw = (await api.send("POST", coll, vector[s.id]!.body)) as unknown;
        const made = (Array.isArray(raw) ? raw[0] : raw) as Record<string, unknown> | null;
        // itemKey, not a hand-rolled id-or-name: the order matters and this file got it wrong once
        // already, deleting at a name-shaped path for collections that key on network_id or sitekey.
        if (isPlainObject(made)) createdKey = itemKey(made);
        outcome = classifyCaptureOutcome(await s.read(api, ids, undefined));
        if (outcome.kind !== "empty") t.seeded.push(s.id);
      } catch {
        t.seedFailed.push(s.id);
      } finally {
        if (createdKey !== "") await api.send("DELETE", `${coll}/${createdKey}`, undefined).catch(() => undefined);
      }
    }
    if (outcome.kind === "complete") t.complete.push(s.id);
    else if (outcome.kind === "gap") t.gaps.push(`${s.id}: ${outcome.reason}`);
    else if (outcome.kind === "unreadable") t.unreadable.push(`${s.id}: ${outcome.reason}`);
    else t.empty.push(s.id);
  }

  const report = reportCapture(t, CF_CONFIG_SURFACES.length, SEED);
  for (const line of report.lines) console.log(line);
  verdictReached(report.failures, report.checks);
  if (report.failures > 0) process.exit(1);
}

// isEntryPoint, not a bare call: this module now EXPORTS its reporting half so a non-live validator can
// gate it, and an import must not fire a live sweep (nor declare a verdict on the importer's behalf,
// which would disarm the guard for the file that imported it).
if (isEntryPoint(import.meta.url)) await main();
