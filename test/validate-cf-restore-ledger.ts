// THE RESTORE PROOF LEDGER GATE: is every banked cf-config restore proof still a proof, and can this gate
// still tell when one is not?
//
// WHY THIS EXISTS. A ledger nobody re-derives becomes the next thing that rots. The harness's refusal
// ledger guards against a refusal whose stated cause has quietly stopped being true by making every
// refusal carry a probe that expires it. PROVEN_WRITE_SURFACES needs the same protection in the other
// direction: it is a set of ids, and an id does not notice when its writer is rewritten, so a surface's
// membership can sit untouched while the writer underneath it changes.
//
// So this runs in CI, on every engine commit, and it is the thing that goes red WITHOUT ANYONE LOOKING. It
// needs no credentials and no account: it re-derives every fingerprint from the checkout in front of it and
// compares them against what the rows say they were proved against.
//
// THE CHANGE THAT MAKES IT RED, named rather than implied: editing a writer, or any file on the console
// restore path, under a banked row. Do that and the row's fingerprint stops matching, the row stops
// counting, and this exits 1 naming the surface and both digests. That is the whole mechanism. It is proved
// below rather than asserted, by mutating a fingerprint map and requiring the refusal.
//
// WHAT IT DOES NOT DO. It does not fail on a LOW count. The ledger ships empty, and a gate that refused to
// pass until somebody drove a live suite would be red on arrival for every unrelated commit in the repo.
// The count is PUBLISHED here on every run instead, which is the honest half: the three numbers are printed
// whether anyone asks or not. The enforcement is against a proof that has gone stale, which is the failure
// that matters here.
//
// ANTI-VACUITY. Every refusal cause must be REACHED by something on every run, and the rows that reach them
// are minted here at run time from the real, current fingerprints rather than pinned. A pinned hash in a
// fixture would have to be re-pinned on every legitimate writer edit, which is the hand-maintained pin this
// whole design refuses. A gate whose failing branches are unreachable is a gate that cannot fail.
//
// House style: Australian English, no em dashes, no rule-of-three.

import { rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cfConfigCatalogue } from "../src/sources/cf-config-catalogue.ts";
import { LIVE_ROUTE_ELSEWHERE, NO_LIVE_ROUTE_HERE, PROVEN_WRITE_SURFACES } from "../src/sources/cf-config-write-generated.ts";
import { cfWriterFingerprints } from "../src/sources/cf-config-writer-fingerprint.ts";
import {
  appendRows,
  EXPIRY_DAYS,
  engineLedgerPath,
  judgeProofs,
  LIVE_KINDS,
  type ProofRow,
  productPathFingerprintFrom,
  type RefusalCause,
  readLedger,
  unprovenRemainder,
} from "./lib/cf-restore-proofs.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const ENGINE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const failures: string[] = [];
let checks = 0;
const check = (ok: boolean, what: string): void => {
  checks++;
  if (ok) console.log(`  ok    ${what}`);
  else {
    console.log(`  FAIL  ${what}`);
    failures.push(what);
  }
};

// ---- 1. THE DENOMINATOR IS DERIVED ------------------------------------------------------------------
//
// The same rule the capture-completeness check applies: the
// in-band set comes from cfConfigCatalogue(), evaluated. A number written down anywhere is a second copy
// that drifts, and it drifts silently because both halves are integers.
const catalogue = cfConfigCatalogue();
const inBand = catalogue.filter((s) => s.inBand).map((s) => s.id);
console.log(`\n-- the denominator, derived from cfConfigCatalogue() --`);
console.log(`  catalogue ${catalogue.length} surfaces, ${inBand.length} in band`);
check(inBand.length > 0, "the catalogue reports a non-zero in-band set, so the denominator grades something");
check(
  inBand.length === PROVEN_WRITE_SURFACES.size && inBand.every((id) => PROVEN_WRITE_SURFACES.has(id)),
  "the in-band set is exactly PROVEN_WRITE_SURFACES, so a restore count and a capture count share one denominator",
);

// ---- 2. THE FINGERPRINTS ----------------------------------------------------------------------------
const fps = await cfWriterFingerprints();
const again = await cfWriterFingerprints();
const productPath = await productPathFingerprintFrom(ENGINE_ROOT);
console.log(`\n-- writer fingerprints --`);
const missing = inBand.filter((id) => !fps.has(id));
check(missing.length === 0, `every in-band surface has a writer fingerprint${missing.length === 0 ? "" : `, and ${missing.length} do not: ${missing.join(", ")}`}`);
const unstable = inBand.filter((id) => fps.get(id)?.fingerprint !== again.get(id)?.fingerprint);
check(unstable.length === 0, `a fingerprint is the same twice in one process${unstable.length === 0 ? "" : `, and ${unstable.length} are not`}`);
// DISTINCTNESS IS THE POSITIVE CONTROL. A fingerprint function that collapsed to a constant would satisfy
// every other assertion here: stable, present, matching. Sixty surfaces sharing ten writer bodies must
// still produce sixty different digests, and they only can if the per-surface half is really in the basis.
const distinct = new Set(inBand.map((id) => fps.get(id)?.fingerprint)).size;
check(distinct === inBand.length, `all ${inBand.length} in-band fingerprints differ (${distinct} distinct), so the per-surface spec is really in the basis and not just the shared writer body`);
const declaresNothing = inBand.filter((id) => fps.get(id)?.declaresNothing === true);
console.log(`  ${declaresNothing.length} writer(s) publish no facts about themselves, so their fingerprint is their source alone: ${declaresNothing.join(", ")}`);
check(/^sha256:[0-9a-f]{64}$/.test(productPath), "the console restore path digests to a sha256, so a console-product row has something to be compared against");

// ---- 3. THE REAL LEDGER ------------------------------------------------------------------------------
const ledgerPath = engineLedgerPath();
let ledgerRows: ProofRow[] = [];
let readOk = true;
try {
  ledgerRows = readLedger(ledgerPath).rows;
} catch (e) {
  readOk = false;
  failures.push(`the ledger at ${ledgerPath} did not read: ${e instanceof Error ? e.message : String(e)}`);
  checks++;
  console.log(`  FAIL  the ledger at ${ledgerPath} did not read: ${e instanceof Error ? e.message : String(e)}`);
}
if (readOk) {
  const verdict = judgeProofs(ledgerRows, fps, productPath);
  console.log(`\n-- ${ledgerPath} --`);
  console.log(`  rows banked                      ${ledgerRows.length}`);
  console.log(`  rows that COUNT today            ${verdict.judged.filter((j) => j.counted).length}`);
  for (const j of verdict.refused) console.log(`  REFUSED  ${j.row.surface} (${j.row.kind}): ${j.cause}, ${j.detail}`);
  // STALE IS THE FAILURE, not a low count. A row whose fingerprint no longer matches is a claim about a
  // writer that no longer exists, and it is the only thing here that says something went wrong rather than
  // that something has not been done yet.
  check(verdict.stale.length === 0, `no banked proof has gone stale under a code change${verdict.stale.length === 0 ? "" : `, and ${verdict.stale.length} has: ${verdict.stale.map((j) => j.row.surface).join(", ")}`}`);
  const structurallyBad = verdict.refused.filter((j) => j.cause === "malformed" || j.cause === "not-in-band");
  check(structurallyBad.length === 0, `every banked row is well formed and names an in-band surface${structurallyBad.length === 0 ? "" : `, and ${structurallyBad.length} do not`}`);
  check(verdict.lapsed.length === 0, `every LIVE_ROUTE_ELSEWHERE exemption is still backed${verdict.lapsed.length === 0 ? "" : `, and ${verdict.lapsed.length} has lapsed: ${verdict.lapsed.map((l) => `${l.surface} (${l.detail})`).join("; ")}`}`);

  // ---- THE THREE NUMBERS, PUBLISHED ON EVERY RUN ---------------------------------------------------
  //
  // Printed rather than gated, because the honest reading of the restore promise is not one number and
  // never was. A single figure here would have to pick one of these three and would be read as all of them.
  const engineApi = verdict.countedByKind.get("engine-api") ?? [];
  const consoleProduct = verdict.countedByKind.get("console-product") ?? [];
  console.log(`\n-- the cf-config restore promise, counted from the ledger rather than from prose --`);
  console.log(`  proven through the PRODUCT and current   ${consoleProduct.length} of ${inBand.length}`);
  console.log(`  proven through the ENGINE API and current ${engineApi.length} of ${inBand.length}`);
  console.log(`  proven either way and current            ${verdict.countedAnyKind.length} of ${inBand.length}`);
  console.log(`  exempt: no live route anywhere            ${NO_LIVE_ROUTE_HERE.size}`);
  console.log(`  exempt: a prover outside this repo        ${LIVE_ROUTE_ELSEWHERE.size}`);
  console.log(`  neither counted nor exempt               ${unprovenRemainder(verdict).length}`);
  console.log(`  a proof stands for ${EXPIRY_DAYS} days, or until its writer changes, whichever comes first`);
}

// ---- 4. CAN THIS GATE STILL FAIL? --------------------------------------------------------------------
//
// Every refusal cause driven, on every run, off rows minted from the CURRENT fingerprints. Nothing here is
// pinned, so nothing here has to be re-pinned when a writer legitimately changes.
console.log(`\n-- can this gate still tell a proof from a claim? --`);
const subject = inBand[0]!;
const good = fps.get(subject)!.fingerprint;
const now = new Date("2026-08-08T00:00:00Z");
const base: ProofRow = {
  surface: subject,
  kind: "engine-api",
  provedAt: "2026-08-07T00:00:00Z",
  prover: "test/live-cf-suite.ts",
  repo: "engine",
  engineSha: "",
  engineTreeDirty: false,
  kit: "synthetic",
  writerFingerprint: good,
};
const otherFingerprint = `sha256:${"0".repeat(64)}`;
const cases: Array<{ row: ProofRow; expect: RefusalCause | "counted"; what: string }> = [
  { row: { ...base }, expect: "counted", what: "a fresh row against the current writer COUNTS" },
  { row: { ...base, writerFingerprint: otherFingerprint }, expect: "writer-changed", what: "a row whose writer has changed since it was proved does NOT count" },
  { row: { ...base, provedAt: "2020-01-01T00:00:00Z" }, expect: "expired", what: `a row older than ${EXPIRY_DAYS} days does NOT count` },
  { row: { ...base, kind: "reasoned" }, expect: "not-a-live-kind", what: "a row of a kind nobody drove does NOT count, however confident it sounds" },
  { row: { ...base, surface: "not-a-surface" }, expect: "not-in-band", what: "a row naming a surface the catalogue does not carry in band does NOT count" },
  { row: { ...base, provedAt: "whenever" }, expect: "malformed", what: "a row with an undateable provedAt does NOT count" },
  { row: { ...base, kind: "console-product" }, expect: "malformed", what: "a console-product row with no product-path fingerprint does NOT count" },
  {
    row: { ...base, kind: "console-product", productPathFingerprint: productPath },
    expect: "counted",
    what: "a console-product row carrying the current console restore path COUNTS",
  },
  {
    row: { ...base, kind: "console-product", productPathFingerprint: otherFingerprint },
    expect: "product-path-changed",
    what: "a console-product row whose plan, diff-summary and approval layer has changed does NOT count, even with an untouched writer",
  },
];
const reached = new Set<string>();
for (const c of cases) {
  const v = judgeProofs([c.row], fps, productPath, now);
  const j = v.judged[0]!;
  const got = j.counted ? "counted" : (j.cause as string);
  reached.add(got);
  check(got === c.expect, `${c.what} (got ${got})`);
}
for (const cause of [...LIVE_KINDS].length > 0 ? ["counted", "writer-changed", "expired", "not-a-live-kind", "not-in-band", "malformed", "product-path-changed"] : []) {
  check(reached.has(cause), `the "${cause}" verdict is still reachable, so this gate can still produce it`);
}

// A RE-RUN THAT PROVES LESS MUST MAKE THE COUNT FALL, driven against the real append rather than described.
// This is the branch that decides whether the ledger is a measure or a scoreboard, and it turns entirely on
// appendRows keying by (surface, prover) rather than by (surface, kind): a refuting row keyed by kind would
// land beside the green one instead of over it, and the surface would stay counted through the very run
// that refuted it.
{
  const scratch = join(ENGINE_ROOT, "ledger", ".supersede-selfcheck.json");
  try {
    const proved: ProofRow = { ...base, kind: "console-product", prover: "spec/journeys/cf-config-roundtrip.spec.ts", repo: "harness", productPathFingerprint: productPath };
    appendRows(scratch, [proved]);
    const afterProof = judgeProofs(readLedger(scratch).rows, fps, productPath, now);
    check(afterProof.countedAnyKind.length === 1, "a proving run banks a row that counts");
    const refuted: ProofRow = { ...proved, kind: "console-product-refuted", provedAt: new Date(now.getTime() - 1000).toISOString() };
    appendRows(scratch, [refuted]);
    const afterRefusal = readLedger(scratch).rows;
    check(afterRefusal.length === 1, `the refuting row REPLACED the proving one rather than joining it (${afterRefusal.length} row(s) left)`);
    check(judgeProofs(afterRefusal, fps, productPath, now).countedAnyKind.length === 0, "after a refuting re-run the surface stops counting, so the number falls");
    check(!LIVE_KINDS.has("console-product-refuted"), "a refuted row's kind is not a live kind, so it can never be counted by a later reader either");
  } finally {
    rmSync(scratch, { force: true });
  }
}

// AN EXEMPTION THAT NOTHING BACKS, AGED PAST THE WINDOW, LAPSES. Driven against a clock far enough forward
// that every LIVE_ROUTE_ELSEWHERE claim has outlived its window with no row behind it.
const farFuture = new Date(Date.parse("2026-07-31T00:00:00Z") + (EXPIRY_DAYS + 2) * 86_400_000);
const lapsedThen = judgeProofs([], fps, productPath, farFuture);
check(
  lapsedThen.lapsed.length === LIVE_ROUTE_ELSEWHERE.size,
  `an exemption claiming a prover elsewhere lapses when no row of its kind is ever banked (${lapsedThen.lapsed.length} of ${LIVE_ROUTE_ELSEWHERE.size} lapsed at +${EXPIRY_DAYS + 2} days)`,
);
// And it does NOT lapse while a counting row of its own kind exists, or the check would just be a clock.
const elsewhereId = [...LIVE_ROUTE_ELSEWHERE.keys()][0];
if (elsewhereId !== undefined) {
  const backedRow: ProofRow = {
    ...base,
    surface: elsewhereId,
    kind: "console-product",
    provedAt: new Date(farFuture.getTime() - 86_400_000).toISOString(),
    prover: "spec/journeys/cf-config-roundtrip.spec.ts",
    repo: "harness",
    writerFingerprint: fps.get(elsewhereId)!.fingerprint,
    productPathFingerprint: productPath,
  };
  const backed = judgeProofs([backedRow], fps, productPath, farFuture);
  check(!backed.lapsed.some((l) => l.surface === elsewhereId), `a live row of the declared kind keeps ${elsewhereId}'s exemption standing, so the lapse check is evidence-driven and not merely a clock`);
}

// ---- 5. THE EXEMPTION LISTS ARE DISJOINT AND HONEST ---------------------------------------------------
console.log(`\n-- the two exemption lists --`);
const both = [...LIVE_ROUTE_ELSEWHERE.keys()].filter((id) => NO_LIVE_ROUTE_HERE.has(id));
check(both.length === 0, `no surface claims both "no live route anywhere" and "proved elsewhere"${both.length === 0 ? "" : `: ${both.join(", ")}`}`);
const notProven = [...LIVE_ROUTE_ELSEWHERE.keys()].filter((id) => !PROVEN_WRITE_SURFACES.has(id));
check(notProven.length === 0, `every LIVE_ROUTE_ELSEWHERE entry is a proven surface${notProven.length === 0 ? "" : `: ${notProven.join(", ")}`}`);
for (const [id, claim] of LIVE_ROUTE_ELSEWHERE) {
  check(!Number.isNaN(Date.parse(claim.since)), `${id}'s exemption carries a parseable since date, so it can be aged`);
  check(LIVE_KINDS.has(claim.banks), `${id}'s exemption names a live ledger kind (${claim.banks}), so something could satisfy it`);
  check(claim.prover.trim() !== "" && claim.repo.trim() !== "", `${id}'s exemption names a prover and a repo, so the claim can be checked by hand as well as by clock`);
}

console.log(failures.length === 0 ? `\nCF RESTORE LEDGER PASS: ${checks} checks` : `\n${failures.length} FAILURE(S) of ${checks} checks`);
for (const f of failures) console.log(`  - ${f}`);
verdictReached(failures.length);
if (failures.length > 0) process.exit(1);
