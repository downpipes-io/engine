// The whole live Cloudflare suite, in one run, in the order the harnesses actually depend on.
//
// WHY THIS EXISTS
// ---------------
// Six live harnesses were built one at a time, each answering a question the previous ones could not.
// None is in CI (they need a real account and real credentials), so they run only when someone remembers
// they exist, in whatever order they happen to think of. That is how the last two capture defects went
// undetected for as long as they did: the check that would have caught them had not been written yet, and
// once written it lived in a scratch directory.
//
// This is the entry point. It also encodes the ORDER, which is not arbitrary:
//
//   1. capture-completeness   READ-ONLY. Does the archive hold everything the surface has? Ask before
//                             anything mutates, so the answer describes the account as found.
//   2. idempotence            READ-ONLY (every write is dryRun). Does each writer no-op against its own
//                             snapshot? A writer that fails here cannot be trusted to restore anything.
//   3. hand-writer-update     MUTATES. Do the hand-written list writers update in place?
//   4. singleton-prove        MUTATES. Do one-object surfaces survive damage and restore from the snapshot?
//   5. autoprove              MUTATES. Full create, capture, delete, restore, converge, update per surface.
//
// Read-only first, mutating second, and the cheapest question before the most expensive one. A failure in
// 1 or 2 makes 3 and 4 harder to interpret, so this stops rather than pressing on.
//
// WHAT IS NOT HERE
// ----------------
// live-cf-roundtrip.ts and live-cf-writer-sweep.ts, deliberately. Both predate the others and their
// coverage is now a subset of autoprove's, which does the same loop plus the update leg. They stay in the
// tree because they take a hand-written bodies file and are useful for one-off work on a single surface,
// but running them here would mutate the same objects twice for no extra answer.
//
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-suite.ts
//   DOWNPIPE_LIVE_CF=1 node test/live-cf-suite.ts --seed    passes --seed to the completeness harness

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LIVE_ROUTE_ELSEWHERE, NO_LIVE_ROUTE_HERE, PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";
import { cfWriterFingerprints } from "../src/sources/cf-config-writer-fingerprint.ts";
import { announceKit, kitDir, kitName } from "./cf-kit.ts";
import { appendRows, engineLedgerPath, type ProofRow } from "./lib/cf-restore-proofs.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";

const KEYS = kitDir();

// ONE SUITE AT A TIME PER ACCOUNT.
//
// Two runs of this suite against the same account produce false defects, and the false defect is
// convincing. Measured, by doing it: a second suite was started while the first was still going, and the
// first's autoprove had a secondary-dns-acls item in flight (created, not yet deleted) when the second's
// idempotence stage read the collection. It reported "PROVEN secondary-dns-acls: NOT A NO-OP against its
// own snapshot", which is exactly what a real churn defect looks like, and the surface is entirely fine.
//
// The stages are ordered read-only-then-mutating precisely so a run's own writes do not confuse its own
// reads. That ordering is worth nothing if a second run is writing underneath it.
//
// The lock is keyed by ACCOUNT, not by machine, because the account is the shared resource. It is a plain
// file with the owning pid and a timestamp; a lock older than the stale window is taken over with a loud
// line rather than blocking forever on a crashed run, since a suite that refuses to start for a stale
// reason would just be worked around.
const LOCK_STALE_MS = 45 * 60 * 1000;
const lockPath = join(tmpdir(), `downpipes-live-cf-${createHash("sha256").update(readFileSync(join(KEYS, "account-id.txt"), "utf8").trim()).digest("hex").slice(0, 16)}.lock`);
if (existsSync(lockPath)) {
  let held: { pid?: number; startedAt?: number } = {};
  try {
    held = JSON.parse(readFileSync(lockPath, "utf8")) as typeof held;
  } catch {
    held = {};
  }
  const age = Date.now() - (held.startedAt ?? 0);
  if (age < LOCK_STALE_MS) {
    console.error(`REFUSING: another live suite is already running against this account (pid ${held.pid ?? "?"}, started ${Math.round(age / 1000)}s ago).`);
    console.error("  Two suites on one account produce FALSE defects: one run's in-flight create is the other run's churn.");
    console.error(`  If that run is dead, remove ${lockPath} and start again.`);
    process.exit(1);
  }
  console.log(`[live-cf-suite] taking over a stale lock (${Math.round(age / 60000)} minutes old, pid ${held.pid ?? "?"})`);
}
writeFileSync(lockPath, JSON.stringify({ pid: process.pid, startedAt: Date.now() }), "utf8");
const releaseLock = (): void => {
  try {
    rmSync(lockPath, { force: true });
  } catch {
    /* best effort: a stale lock is taken over above */
  }
};
process.on("exit", releaseLock);
process.on("SIGINT", () => { releaseLock(); process.exit(130); });

const STAGES: Array<{ script: string; what: string; mutates: boolean; args?: string[] }> = [
  { script: "test/live-cf-capture-completeness.ts", what: "does the archive hold everything the surface has", mutates: false, args: process.argv.includes("--seed") ? ["--seed"] : [] },
  { script: "test/live-cf-idempotence.ts", what: "does every writer no-op against its own snapshot", mutates: false },
  { script: "test/live-cf-hand-writer-update.ts", what: "do the hand-written writers update in place", mutates: true },
  { script: "test/live-cf-singleton-prove.ts", what: "do one-object surfaces survive damage and restore", mutates: true },
  // email-routing needs its own stage even though the singleton prober already reports it PROVED. The
  // prober reaches it by flipping a boolean in the SETTINGS half, which is real but is not the half that
  // matters: the rules are what a customer loses and what no other harness restores. Counting the surface
  // as covered on the settings flip alone would let the rules writer rot behind a green line, which is the
  // partial-coverage version of the vacuous pass this suite exists to refuse.
  { script: "test/live-cf-email-routing-prove.ts", what: "does the email-routing RULES half restore, update and converge", mutates: true },
  { script: "test/live-cf-autoprove.ts", what: "full round trip per surface, including the update leg", mutates: true },
];

if (process.env.DOWNPIPE_LIVE_CF !== "1" || !existsSync(join(KEYS, "cf-api-token.txt"))) {
  console.log("SKIP live-cf-suite: needs DOWNPIPE_LIVE_CF=1 and live credentials");
  verdictSkipped("SKIP live-cf-suite: needs DOWNPIPE_LIVE_CF=1 and live credentials");
  process.exit(0);
}
  announceKit("live-cf-suite");

// --seed on the completeness stage MUTATES (it creates an object to observe, then deletes it), so say so
// rather than let the "READ-ONLY" label above quietly become untrue.
if (process.argv.includes("--seed")) console.log("note: --seed makes stage 1 create and delete objects, so no stage in this run is read-only\n");

let failed = "";
// A SKIPPED STAGE IS NOT A PASSED STAGE. Each harness exits 0 when it declines to run, which is right: a
// missing entitlement or a kit it may not damage is not a failure. But the suite then printed "PASS (all
// stages)" over a run where a stage had done nothing, which is the vacuous pass this whole suite was built
// to refuse, sitting in the summary line of the thing that refuses it.
//
// Detected from the output rather than the exit code, because the exit code cannot distinguish them.
const skipped: string[] = [];
const provedThisRun = new Set<string>();
for (const [i, stage] of STAGES.entries()) {
  console.log(`\n=== ${i + 1}/${STAGES.length}  ${stage.script}${stage.mutates ? "  [MUTATES]" : "  [read-only]"}`);
  console.log(`    ${stage.what}`);
  const r = spawnSync("node", [stage.script, ...(stage.args ?? [])], { encoding: "utf8", env: process.env });
  process.stdout.write(r.stdout ?? "");
  process.stderr.write(r.stderr ?? "");
  if (r.status === 0 && /^SKIP /m.test(r.stdout ?? "")) skipped.push(stage.script);
  // Collect what this stage says it PROVED, for the coverage check below.
  for (const m of (r.stdout ?? "").matchAll(/^LIVE-PROVED: ([^\n]*)$/gm)) {
    for (const id of (m[1] ?? "").split(",").map((x) => x.trim())) if (id !== "") provedThisRun.add(id);
  }
  if (r.status !== 0) {
    failed = stage.script;
    // Stop rather than press on. A failure in an earlier stage changes how a later one should be read: an
    // account whose capture is incomplete, or whose writers do not converge, will produce round-trip
    // results that are hard to attribute, and chasing those wastes the run.
    console.log(`\nSTOPPING: ${stage.script} failed, and the stages after it would be hard to interpret against that.`);
    break;
  }
}

// IS EVERY PROVEN SURFACE STILL BEING PROVED?
//
// A proof is a claim about the past. What keeps it true is a harness that re-runs it, and until this check
// existed nothing asked whether one still did. dns-settings stopped being re-proved the moment the refusal
// classifier learnt one more phrase: the prober hit a plan-gated field first, reported the surface as
// account-limited, and every harness stayed green because account-limited is reported rather than failed.
// The published count did not move. Nothing could have noticed except this question.
//
// NO_LIVE_ROUTE_HERE is the declared exemption list, carrying a reason per surface, so this cannot be
// satisfied by quietly widening it: an addition is a visible edit to engine source with a stated cause.
//
// It only runs when every stage ran. A skipped or failed stage means the union is incomplete, and
// reporting "these proofs are unexercised" off a partial run would be a false accusation.
let coverageGap: string[] = [];
if (failed === "" && skipped.length === 0) {
  coverageGap = [...PROVEN_WRITE_SURFACES]
    .filter((id) => !provedThisRun.has(id) && !NO_LIVE_ROUTE_HERE.has(id) && !LIVE_ROUTE_ELSEWHERE.has(id))
    .sort();
}

// BANK WHAT THIS RUN PROVED.
//
// Everything above this line was already here and already correct. The union is computed, the gap fails the
// suite, and none of it left a trace: no committed record anywhere showed
// this file had ever run. From outside the terminal it ran in, a run that proved
// fifty surfaces and a run that never happened were the same event, which is why the restore promise had no
// honest number attached to it.
//
// So the union is written down, with the fingerprint of the writer each proof went through. See
// test/lib/cf-restore-proofs.ts for what a row has to satisfy to be counted later; the short form is that
// the fingerprint is what lets the number FALL when a writer is edited, rather than accumulating forever.
//
// ONLY ON A CLEAN, COMPLETE RUN. A partial union banked as evidence is worse than no evidence: it records
// surfaces as proved on a run whose earlier stage failed, and the whole ordering of this suite exists
// because a failure upstream makes the results after it hard to attribute.
//
// A LEDGER FAILURE IS LOUD AND NOT FATAL, following the harness's own rule for this: the run's finding is
// about Cloudflare, and losing the record of it should never be reported as a product defect. But a lost
// row and a written one must never read the same at the only place a human looks, so the failure prints in
// a fixed shape one grep finds.
if (failed === "" && skipped.length === 0 && provedThisRun.size > 0) {
  try {
    const fps = await cfWriterFingerprints();
    const head = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" });
    const dirty = spawnSync("git", ["status", "--porcelain"], { encoding: "utf8" });
    const sha = head.status === 0 ? (head.stdout ?? "").trim() : "";
    const provedAt = new Date().toISOString();
    const rows: ProofRow[] = [];
    for (const surface of [...provedThisRun].sort()) {
      const fp = fps.get(surface);
      // A surface a stage claims to have proved but that this checkout has no writer for is a mismatch
      // between the harness and the registry, and banking it would put a row in the ledger that can never
      // be graded. Reported by name rather than dropped.
      if (fp === undefined) {
        console.log(`[ledger] NOT BANKED ${surface}: a stage reported it PROVED and this checkout has no writer for it`);
        continue;
      }
      rows.push({
        surface,
        kind: "engine-api",
        provedAt,
        prover: "test/live-cf-suite.ts",
        repo: "engine",
        engineSha: sha,
        engineTreeDirty: dirty.status === 0 && (dirty.stdout ?? "").trim() !== "",
        kit: kitName(),
        writerFingerprint: fp.fingerprint,
      });
    }
    const path = engineLedgerPath();
    appendRows(path, rows);
    console.log(`\n[ledger] banked ${rows.length} engine-api proof row(s) at ${path}`);
    console.log(`[ledger] engine ${sha === "" ? "sha unavailable" : sha}${dirty.status === 0 && (dirty.stdout ?? "").trim() !== "" ? " (TREE DIRTY, so the sha does not describe what ran)" : ""}, kit ${kitName()}, ${provedAt}`);
    console.log("[ledger] COMMIT THIS FILE. A proof nobody can read is the state this ledger exists to end.");
  } catch (e) {
    console.log(`[ledger] LEDGER APPEND REFUSED: this run has NO rows for the ${provedThisRun.size} surface(s) it just proved: ${e instanceof Error ? e.message : String(e)}`);
  }
}

if (failed === "") {
  const ran = STAGES.length - skipped.length;
  console.log(`\nLIVE CF SUITE PASS: ${ran} of ${STAGES.length} stages RAN`);
  console.log(`  proofs re-exercised this run: ${provedThisRun.size} of ${PROVEN_WRITE_SURFACES.size} (${NO_LIVE_ROUTE_HERE.size} with no live route anywhere, ${LIVE_ROUTE_ELSEWHERE.size} proved by a prover outside this repo)`);
  for (const [id, claim] of LIVE_ROUTE_ELSEWHERE) {
    if (!provedThisRun.has(id)) console.log(`     ${id}: not exercised HERE, and not expected to be. ${claim.repo}/${claim.prover} banks it as ${claim.banks}, since ${claim.since}`);
  }
  if (skipped.length > 0) {
    console.log("  coverage NOT checked: a stage was skipped, so the union is incomplete and a gap here would be a false accusation.");
  } else if (coverageGap.length > 0) {
    console.error(`\n  ${coverageGap.length} PROVEN surface(s) were NOT re-exercised and are not exempt:`);
    for (const id of coverageGap) console.error(`     ${id}`);
    console.error("  Either a harness stopped covering them, or they belong in NO_LIVE_ROUTE_HERE with a reason.");
  }
  if (skipped.length > 0) {
    console.log(`  ${skipped.length} stage(s) SKIPPED and proved nothing:`);
    for (const sk of skipped) console.log(`     ${sk}`);
  }
} else {
  console.log(`\nLIVE CF SUITE FAILED at ${failed}`);
}
// A coverage gap FAILS the suite. It is the only signal that a proof has quietly stopped being a proof,
// and reporting it without failing would put it in the same category as the account-limited lines that
// hid the dns-settings regression for two days.
verdictReached(coverageGap.length);
if (failed !== "" || coverageGap.length > 0) process.exit(1);
