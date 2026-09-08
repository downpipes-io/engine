// Prove D4, the tamper-evident hash-chained audit log, end to end and SERVER-SIDE, with
// in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-audit.ts
//
// What this proves (the D4 claims the task pins):
//  - the hash chain VERIFIES: a clean log of recorded events reports intact through the head;
//  - a TAMPERED entry is DETECTED at N: editing one stored entry breaks verify at that seq, and
//    so does deleting/reordering an entry (the prevHash link breaks);
//  - a SEQUENCE GAP is DETECTED even when the hashes are re-linked around the hole: deleting a
//    middle entry and re-chaining its successor's prevHash/hash still leaves a seq gap, which
//    verify reports at the entry after the hole (the "any deletion is detectable" claim made true);
//  - REDACTION BY CONSTRUCTION holds: driving real privileged actions through the router writes
//    NO key, value, secret, or private fingerprint into any entry, and the recorder type has no
//    free-form field a secret could ride in;
//  - MAKER and CHECKER are both recorded for a restore (maker != checker), distinct identities;
//  - DENIED attempts are recorded (a Viewer refused an apply, a non-Owner refused a role write);
//  - the first-class events are recorded from the routes that perform them (restore-apply,
//    downpipe create/delete, role change, the two intent markers);
//  - engine-OBSERVED events fire on a GET /admin/status presence transition (false -> true) and
//    on an engineVersion change, with actorMethod "engine" and no human actor;
//  - the export carries the chain HEAD HASH (so an external verifier can detect truncation), in
//    both JSON and CSV.
//
// The Access path is driven with a forged-but-correctly-signed RS256 JWT verified against a
// controlled JWKS served by a stubbed global fetch, so authorise() runs its REAL verification and
// resolves a REAL verified identity at a chosen role (the same technique as validate-rbac.ts),
// exercising the production router + DO code path rather than a shim.
//
// SIZE SPLIT (engine-test-001-01): the in-memory DO doubles, the scheduler builder, the forged-JWT
// plumbing, the secret-marker constants and the per-run context live in validate-audit-harness.ts;
// the PROOF blocks are grouped into sibling modules (-events / -records / -chain / -redaction /
// -rollover). This file is the thin orchestrator: it builds ONE shared context (one live DO + audit
// chain) and CALLS each group in the original order, so the full suite still runs against the same
// state with the same assertions.

import { buildContext } from "./validate-audit-harness.ts";
import { runEvents } from "./validate-audit-events.ts";
import { runRecords } from "./validate-audit-records.ts";
import { runChain } from "./validate-audit-chain.ts";
import { runRedaction } from "./validate-audit-redaction.ts";
import { runRollover } from "./validate-audit-rollover.ts";
import { runExportComplete } from "./validate-audit-export-complete.ts";
import { runTamper } from "./validate-audit-tamper.ts";
import { runDigestCoverage } from "./validate-audit-digest-coverage.ts";
import { AUDIT_ACTIONS } from "../src/admin/audit-types.ts";
import { isAuditAction } from "../src/sched/scheduler-helpers.ts";

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();

  // The stubbed globalThis.fetch is restored in the finally so an uncaught throw in any proof below
  // cannot leave the stub installed for code that runs after (e.g. a multi-file test runner).
  try {
    // PROOF 1/1b/2/2b: first-class events recorded from the routes, source IP on commit-point
    // successes, denied attempts recorded, the support credential lifecycle audited + DO-re-checked.
    await runEvents(ctx);
    // PROOF 3/4/5: restore-apply records the maker + plan hash, maker != checker (incl. subject axis
    // and backward-compatible hashing), the intent markers.
    await runRecords(ctx);
    // PROOF 6/7/8/9/9b: engine-observed events, the chain verifies, tampered/deleted/seq-gap detection.
    await runChain(ctx);
    // PROOF 10/11/12: redaction holds, the export carries the head hash (JSON + CSV), filtered reads.
    await runRedaction(ctx);
    // PROOF 13/14 + CSV formula injection: retention rollover, non-genesis baseline verify, CSV neutralisation.
    await runRollover(ctx);
    // PROOF EXPORT-COMPLETE (finding F-W4-4): the compliance export is COMPLETE past AUDIT_PAGE_MAX (JSON +
    // CSV), the exported chain re-verifies, and the paged-view / bounded-probe caps stay separate. Runs on
    // its OWN fresh DO, so it is placed after the shared-chain proofs (rollover prunes the shared chain).
    await runExportComplete(ctx);
    // AUDIT-TAMPER: the seven cells
    // (positive control, alteration, deletion, insertion, reorder, tail-truncation, telemetry) driven against a
    // HARNESS-OWNED independent oracle, plus the net-new tail-truncation anchor cell and the best-effort telemetry
    // bound. Runs on its OWN fresh DOs, so it never perturbs the shared-chain proofs above.
    await runTamper(ctx);
    // PROOF DIGEST-COVERAGE: every field an entry CARRIES is a field the chain hash COMMITS TO, derived
    // from the runtime object rather than from a list. auditHash and the independent oracle both hash a
    // HAND-KEPT allowlist, so a field added to AuditEvent later sits outside the digest and both agree
    // it is fine. Builds its own events, so it perturbs no state.
    await runDigestCoverage(ctx);

    // PROOF: the isAuditAction query guard is in lockstep with the AuditAction union. The guard now
    // iterates AUDIT_ACTIONS, the same const array the union derives from, so every member must be
    // accepted (no missing variant silently widens the action filter to ALL actions) and an unknown
    // value must be rejected. This enforces the "lockstep" claim rather than asserting it in a comment.
    let allAccepted = true;
    for (const a of AUDIT_ACTIONS) {
      if (!isAuditAction(a)) {
        allAccepted = false;
        ctx.ok(`isAuditAction accepts every AuditAction member (missing: ${a})`, false);
      }
    }
    ctx.ok("isAuditAction accepts every AuditAction member", allAccepted);
    ctx.ok("isAuditAction rejects an unknown action value", !isAuditAction("not-a-real-action"));
    ctx.ok("isAuditAction rejects an outcome value (does not bleed across enums)", !isAuditAction("success"));
  } finally {
    globalThis.fetch = realFetch;
  }

  const failures = ctx.getFailures();
  console.log(failures === 0 ? "\nAUDIT (D4) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
