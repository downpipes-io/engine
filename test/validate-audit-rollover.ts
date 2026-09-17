// PROOF 13 / 14 + the CSV formula-injection block for the D4 audit validator (split out of
// validate-audit.ts, finding engine-test-001-01): retention rollover (P4) verifies intact-from-
// earliest after a rollover; the post-rollover chain shape verifies from a non-genesis baseline
// (unit); and toCSV neutralises spreadsheet formula triggers per the OWASP CSV-injection guidance.

import { AUDIT_ROLLOVER_KEY } from "../src/sched/scheduler-do.ts";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyChain, auditHash, buildEvent, auditKey, AUDIT_PREFIX, GENESIS_PREV_HASH, AUDIT_CAP, AUDIT_NEAR_CAP_FRACTION, toCSV, type AuditEvent, type AuditDraft } from "../src/admin/audit.ts";
import type { Ctx } from "./validate-audit-harness.ts";
import { OWNER } from "./validate-audit-harness.ts";

export async function runRollover(ctx: Ctx): Promise<void> {
  const { ok, call, sched } = ctx;

  // ---- PROOF 13: RETENTION ROLLOVER (P4); verify reports intact-from-earliest after a rollover ---
  {
    // A rollover prunes the OLDEST entries once the retained count would exceed AUDIT_CAP. Driving
    // 10000+ real appends here would be slow; instead reproduce a rollover's STORAGE EFFECT on the
    // real chain this suite built (delete the oldest few audit keys and write the auditRollover
    // record exactly as the DO's rollOverAudit does), then exercise the REAL GET /admin/audit/verify
    // route. This proves the verify-from-earliest path: the chain is reported intact even though
    // genesis is gone, with the earliest retained seq and the rolled-over count surfaced (not a
    // spurious break), which is the honest retention behaviour the cap is for.
    const before = sched.storage.rawKeys(AUDIT_PREFIX);
    ok("there are enough entries to roll over a few", before.length >= 4);
    const PRUNE = 3;
    const prunedKeys = before.slice(0, PRUNE);
    const prunedSeqs = prunedKeys.map((k) => sched.storage.rawGet<AuditEvent>(k)!.seq);
    for (const k of prunedKeys) sched.storage.rawDelete(k);
    const survivors = sched.storage.rawKeys(AUDIT_PREFIX);
    const newEarliest = sched.storage.rawGet<AuditEvent>(survivors[0]!)!.seq;
    // Write the rollover record the way rollOverAudit would (earliest retained seq + cumulative
    // pruned count), via the exported key so this is not coupled to a magic-string literal.
    sched.storage.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: newEarliest, rolledOverCount: PRUNE });

    // Sanity: the surviving chain no longer starts at genesis (its first entry's prevHash links to a
    // now-pruned predecessor), so a genesis-expecting verify WOULD wrongly flag it; the rollover-aware
    // route must not.
    const firstSurvivor = sched.storage.rawGet<AuditEvent>(survivors[0]!)!;
    ok("post-rollover the earliest retained entry no longer links to genesis", firstSurvivor.prevHash !== GENESIS_PREV_HASH && newEarliest > Math.min(...prunedSeqs));

    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as {
      intact: boolean; checkedThrough: number; earliestSeq: number; rolledOver: boolean; rolledOverCount: number; brokenAt?: number;
    };
    ok("verify reports the rolled-over chain INTACT (does not fail because genesis is gone)", verify.intact === true);
    ok("verify reports rolledOver true after a rollover", verify.rolledOver === true);
    ok("verify reports the rolled-over count", verify.rolledOverCount === PRUNE);
    ok("verify reports the earliest RETAINED seq (the new baseline)", verify.earliestSeq === newEarliest);
    ok("verify still reports the head as checkedThrough", verify.checkedThrough >= newEarliest);

    // Independent re-verification of the retained set with expectGenesis:false agrees it is intact,
    // and (the guard rail) the DEFAULT expectGenesis:true flags the missing genesis as a break at the
    // new first entry, proving the relaxation is gated on a declared rollover and tamper-evidence
    // within the retained set is not silently weakened.
    const retainedAscending = survivors.map((k) => sched.storage.rawGet<AuditEvent>(k)!);
    const asRollover = await verifyChain(retainedAscending, { expectGenesis: false });
    ok("independent verify (expectGenesis:false) agrees the retained chain is intact", asRollover.intact === true && asRollover.earliestSeq === newEarliest);
    const asGenesis = await verifyChain(retainedAscending);
    ok("default verify (expectGenesis) DETECTS the missing genesis (relaxation is gated)", asGenesis.intact === false && asGenesis.brokenAt === newEarliest);

    // The two checks above are NOT independent of each other, and the word "independent" on the one
    // before them was doing work it had not earned: both are verifyChain, the very function the route
    // calls, run a second time with a different option. If the rollover relaxation ever skipped the
    // CONTENT check along with the genesis link, both would still report intact and say so twice.
    //
    // auditHash was imported into this file and never called, which is the unfinished intent that gap
    // is made of. Driving it gives the retained slice a check that does not enter verifyChain's control
    // flow at all: recompute each retained entry's digest from its own fields, and walk the links by
    // hand. The POPULATION is asserted first, because "no retained entry fails to recompute" is also
    // true of an empty retained set, and the link count is asserted against the walk so a loop that
    // examined nothing cannot read as clean.
    {
      ok(`the retained set is large enough to have links to check (${retainedAscending.length} entries)`, retainedAscending.length >= 2);
      let recomputed = 0;
      let linked = 0;
      const badDigest: number[] = [];
      const badLink: number[] = [];
      for (let i = 0; i < retainedAscending.length; i++) {
        const e = retainedAscending[i]!;
        recomputed++;
        if ((await auditHash(e)) !== e.hash) badDigest.push(e.seq);
        if (i > 0) {
          linked++;
          if (e.prevHash !== retainedAscending[i - 1]!.hash) badLink.push(e.seq);
        }
      }
      ok(`the hand walk recomputed every retained entry and every link (${recomputed} digests, ${linked} links)`, recomputed === retainedAscending.length && linked === retainedAscending.length - 1 && linked >= 1);
      ok(`every retained entry's stored hash recomputes from its own fields, without verifyChain${badDigest.length === 0 ? "" : ` (mismatched at ${badDigest.join(", ")})`}`, badDigest.length === 0);
      ok(`every retained entry links to its predecessor's stored hash, without verifyChain${badLink.length === 0 ? "" : ` (broken at ${badLink.join(", ")})`}`, badLink.length === 0);

      // The matched refuter: the hand walk must be ABLE to disagree. Without it the three cells above
      // would read identically if auditHash returned the stored hash for anything it was handed.
      const edited = { ...retainedAscending[retainedAscending.length - 1]!, actorEmail: "tamper@example.test" };
      ok("REFUTER: an in-place edit of a retained entry makes the hand recomputation DISAGREE", (await auditHash(edited)) !== edited.hash);
    }
    // PROOF 13 and 14 are terminal (no later proof reads this suite's chain), so the pruned entries
    // are left pruned; clear only the rollover record so the suite ends in a clean state.
    sched.storage.rawDelete(AUDIT_ROLLOVER_KEY);
  }

  // ---- PROOF 14: the post-rollover chain shape verifies from a non-genesis baseline (unit) -------
  {
    // Build a fresh, fully-linked chain of real entries with buildEvent, then take a TAIL slice as the
    // "retained after rollover" set: its first entry has seq > 1 and a prevHash linking to a pruned
    // predecessor. expectGenesis:false verifies it intact from that baseline; the default catches it.
    // This isolates the verify logic from the DO/storage, complementing PROOF 13's route-level test.
    const chain: AuditEvent[] = [];
    let prev: AuditEvent | null = null;
    for (let i = 1; i <= 6; i++) {
      const draft: AuditDraft = { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "engine-state", field: "engineVersion", detail: `0.0.${i}` } };
      const e = await buildEvent(draft, i, "2026-06-07T00:00:00.000Z", prev);
      chain.push(e);
      prev = e;
    }
    const retained = chain.slice(3); // seqs 4,5,6; first prevHash = entry3.hash (not genesis)
    const v = await verifyChain(retained, { expectGenesis: false });
    ok("synthetic post-rollover slice verifies intact from its baseline", v.intact === true && v.earliestSeq === 4 && v.checkedThrough === 6);
    const vg = await verifyChain(retained); // default expects genesis
    ok("the same slice is flagged when genesis is expected (gating proof)", vg.intact === false && vg.brokenAt === 4);
    // A tamper inside the retained slice is still caught under expectGenesis:false (no weakening).
    const tampered = retained.map((e) => ({ ...e }));
    tampered[1]!.outcome = "denied";
    const vt = await verifyChain(tampered, { expectGenesis: false });
    ok("an in-place edit inside the retained slice is still detected (expectGenesis:false)", vt.intact === false && vt.brokenAt === 5);
    // And auditKey/AUDIT_PREFIX agree with the DO's storage-key scheme the prune relied on.
    ok("auditKey is the prefixed zero-padded seq the rollover prune scans", auditKey(4).startsWith(AUDIT_PREFIX) && auditKey(4) < auditKey(5));
    // The near-cap math status uses matches the DO threshold (a count at the threshold is near-cap).
    const threshold = Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION);
    ok("near-cap threshold is AUDIT_CAP * fraction, floored", threshold === Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION) && threshold < AUDIT_CAP);
  }

  // CSV FORMULA INJECTION (OWASP CSV-injection guidance: https://owasp.org/www-community/attacks/CSV_Injection).
  // The raw passthrough columns (actorEmail / actorSubject / sourceIp are IdP-claim and edge-header derived)
  // are exported via toCSV; a cell beginning with a formula trigger (= + - @ tab CR NUL) must be neutralised
  // with a leading quote BEFORE the RFC-4180 quote-wrap so a spreadsheet does not evaluate it on open.
  // Exercises toCSV directly with crafted raw cells.
  {
    const evil = '=HYPERLINK("https://evil.example","x")';
    const ev: AuditEvent = {
      seq: 1,
      ts: "2026-06-19T00:00:00.000Z",
      actorSubject: "+csv",
      actorEmail: evil,
      actorMethod: "access",
      sourceIp: "@SUM(1)",
      action: "downpipe-create",
      outcome: "success",
      target: { kind: "access-policy" },
      prevHash: GENESIS_PREV_HASH,
      hash: "deadbeef",
    };
    const csv = toCSV([ev], { headSeq: 1, headHash: "deadbeef" });
    ok("CSV neutralises a leading '=' (actorEmail) with a quote", csv.includes(`"'=HYPERLINK`));
    ok("CSV neutralises a leading '@' (sourceIp) with a quote", csv.includes(`"'@SUM(1)"`));
    ok("CSV neutralises a leading '+' (actorSubject) with a quote", csv.includes(`"'+csv"`));
    ok("CSV leaves no bare formula trigger at a cell start", !csv.includes(`,"=HYPERLINK`) && !csv.includes(`,"@SUM`));

    // The trailing head row must carry exactly 11 comma-separated cells (matching the 11-column
    // header) so a position-based verifier reads the head hash from the hash column (index 10), not
    // from prevHash. A dropped trailing cell would misalign the parse; this assertion catches it.
    const headLine = csv.trimEnd().split("\r\n").at(-1) ?? "";
    const headCells = headLine.split(",");
    ok("CSV head row splits into exactly 11 fields", headCells.length === 11);
    ok("CSV head row carries headHash in the hash column (index 10)", headCells[10] === `"deadbeef"`);

    // A value beginning with a NUL (\x00) is also a formula trigger and must be quoted. The old guard's
    // character class did not cover NUL robustly (a fragile literal control byte that an editor or copy
    // through a tool can silently drop), so a NUL-prefixed cell could ride into the export unneutralised.
    const nulEvent: AuditEvent = {
      seq: 2,
      ts: "2026-06-19T00:00:00.000Z",
      actorSubject: null,
      actorEmail: "\x00=cmd|'/c calc'!A1",
      actorMethod: "access",
      sourceIp: null,
      action: "downpipe-create",
      outcome: "success",
      target: { kind: "access-policy" },
      prevHash: GENESIS_PREV_HASH,
      hash: "deadbeef",
    };
    const nulCsv = toCSV([nulEvent], { headSeq: 2, headHash: "deadbeef" });
    ok("CSV neutralises a leading NUL (\\x00) with a quote before the NUL", nulCsv.includes(`"'\x00=cmd`));
    ok("CSV leaves no bare NUL at a cell start", !nulCsv.includes(`,"\x00=cmd`));

    // dest-change target rendering (WS-D config-change): the CSV column describes each op REDACTION-SAFELY
    // (op + operator labels + closed flags/ints only, never a secret), exercising every describeTarget arm.
    const de = (seq: number, action: "dest-config-set" | "dest-config-cleared", outcome: "success" | "failed", target: AuditEvent["target"]): AuditEvent => ({ seq, ts: "2026-06-19T00:00:00.000Z", actorSubject: null, actorEmail: null, actorMethod: "engine", sourceIp: null, action, outcome, target, prevHash: GENESIS_PREV_HASH, hash: "h" });
    const destCsv = toCSV(
      [
        de(10, "dest-config-cleared", "success", { kind: "dest-change", op: "remove", id: "d1", fromDefaultId: "d1", toDefaultId: "d2", force: true, uncoveredOriginRunCount: 3 }),
        de(11, "dest-config-cleared", "success", { kind: "dest-change", op: "remove", id: "d3" }),
        de(12, "dest-config-set", "failed", { kind: "dest-change", op: "set", id: "d4", rejectReason: "endpoint-not-https" }),
        de(13, "dest-config-set", "success", { kind: "dest-change", op: "default", id: "d5", fromDefaultId: "d0", toDefaultId: "d5" }),
        de(14, "dest-config-cleared", "success", { kind: "dest-change", op: "clear", id: "d6", fromDefaultId: "d6", toDefaultId: "d7" }),
        de(15, "dest-config-cleared", "success", { kind: "dest-change", op: "clear" }),
        de(16, "dest-config-set", "success", { kind: "dest-change", op: "set", id: "d8" }),
        de(17, "dest-config-set", "success", { kind: "dest-change", op: "set" }),
      ],
      { headSeq: 17, headHash: "h" },
    );
    ok("CSV renders a FORCED dest removal with the promotion + orphan count (no secret)", destCsv.includes("destination removed d1 (default d1 -> d2) [FORCED, 3 run(s) had no other proven copy]"));
    ok("CSV renders a plain dest removal (no promotion, not forced)", destCsv.includes("destination removed d3"));
    ok("CSV renders a REJECTED dest set with its reason class", destCsv.includes("destination set REJECTED (endpoint-not-https)"));
    ok("CSV renders a default repoint", destCsv.includes("default destination -> d5"));
    ok("CSV renders a clear WITH promotion + a bare set with id", destCsv.includes("destination cleared (default d6 -> d7)") && destCsv.includes("destination set d8"));

    // The guard must keep NUL in its leading-character class as the readable \x00 escape (matching the
    // \t / \r convention), not a fragile literal NUL byte. Asserting the source representation catches a
    // silent drop of NUL coverage that a behavioural check alone could miss if a literal byte were used.
    const auditSrc = readFileSync(fileURLToPath(new URL("../src/admin/audit.ts", import.meta.url)), "utf8");
    ok("audit.ts CSV guard includes NUL as the \\x00 escape, not a literal NUL byte", auditSrc.includes(String.raw`\r\x00]`) && !auditSrc.includes(String.fromCharCode(0)));
  }
}
