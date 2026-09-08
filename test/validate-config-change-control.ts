// Prove the OPT-IN dual-control change-control gate for CONFIG mutations, end to end and SERVER-SIDE.
// No network, no deploy, no cost. Run:
//   node test/validate-config-change-control.ts
//
// What this proves (every security bullet the task pins):
//  - GATE OFF (the default) == current behaviour: a config mutation applies INLINE, the state changes
//    immediately, and NO pending change record is created (no friction, byte-identical path);
//  - GATE ON queues: a config mutation is VALIDATED then recorded as a PENDING change (202 + id) WITHOUT
//    committing the state write, and the pending record carries the correct plain-English diff (current
//    config -> the would-be config, reusing the config-history diff);
//  - PROPOSE-TIME VALIDATION: a bad/unauthorised request is rejected at PROPOSE time (a 4xx), NOT deferred
//    into a pending record that fails on approve;
//  - MAKER != CHECKER: the proposer cannot approve their OWN change (403/refusal), at the router AND in
//    the DO (defence in depth);
//  - MISSING WRITE CAP: a caller WITHOUT the write capability the original mutation requires cannot
//    approve (refused), even though they could read the inbox;
//  - CLEAN APPROVE APPLIES via the REAL validated path, records BOTH actors (proposer + approver), and the
//    applied change auto-snapshots into config history;
//  - REJECT discards (no apply; audited);
//  - SUPERSEDED BASE: a pending change whose base config MOVED since it was proposed is rejected as
//    superseded and does NOT apply stale (TOCTOU defence); a tampered contentHash is also refused;
//  - OWNER-ONLY TOGGLE: only an Owner may flip requireConfigApproval; the break-glass owner can always
//    toggle it (no deadlock);
//  - NO ESCALATION AT APPLY: a pending role/group-role change still obeys requireGrantWithinAuthority at
//    APPLY time (the proposer's ceiling is enforced when the change is replayed), so a proposer who could
//    not grant a capability inline cannot smuggle it through the queue;
//  - AUDIT: propose/approve/reject/supersede are recorded in the hash-chained audit with both actors, and
//    the chain still VERIFIES.
//
// This test reuses the validate-rbac/validate-dualcontrol idiom: a forged-but-correctly-signed RS256
// Access JWT + an in-memory SchedulerDO driven through the PRODUCTION handleAdmin, so the REAL
// authorisation, role resolution, gate dispatch, dual-control state and audit chain all run. No data
// backup machinery is needed (config mutations never touch the archive).
//
// SIZE SPLIT: the in-memory DO doubles, the scheduler builders, the forged-JWT
// plumbing and the per-run context live in validate-config-change-control-harness.ts; the PROOF blocks are
// grouped into sibling modules (-gate / -queue / -lifecycle / -policies / -audit-scale). This file is the
// thin orchestrator: it builds ONE shared context (one live DO + audit chain) and CALLS each group in the
// original order, so the full suite still runs against the same state with the same assertions.

import { buildContext, type Shared } from "./validate-config-change-control-harness.ts";
import { runGate } from "./validate-config-change-control-gate.ts";
import { runQueue } from "./validate-config-change-control-queue.ts";
import { runLifecycle } from "./validate-config-change-control-lifecycle.ts";
import { runPolicies } from "./validate-config-change-control-policies.ts";
import { runAuditAndScale } from "./validate-config-change-control-audit-scale.ts";

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  // Mutable state threaded between the dependent groups (PROOF 3 queues a downpipe whose id PROOF 5/6/7
  // approve). Set by runQueue, read by the groups that follow it.
  const shared: Shared = { queuedDownpipeId: "" };

  // The groups run inside try/finally so an assertion throw still restores the patched global fetch (a
  // leaked stub would corrupt any later in-process test if this validator were ever imported into a
  // shared runner).
  try {
    // PROOF 0/1/2: module invariants, gate-off inline path, owner-only toggle.
    await runGate(ctx);
    // PROOF 3/4/5/5b/6/7: queue under the gate, propose-time validation, maker != checker, missing cap, clean approve.
    await runQueue(ctx, shared);
    // PROOF 8/9/10/11/12: reject, superseded base + tamper, no escalation at apply, DO-side defence, bare-token cannot propose.
    await runLifecycle(ctx);
    // PROOF 14(webhook)/15/16/17/18/19: webhook gate + redaction, expiry gate, identity tamper, dry-run no-side-effect, custom-role apply.
    await runPolicies(ctx);
    // PROOF AUDIT-VERIFY (runs last) + large-keyspace PROOF 14: audit chain verifies, full-keyspace dry-run rollback at tenant scale.
    await runAuditAndScale(ctx);
  } finally {
    globalThis.fetch = realFetch;
  }
  const failures = ctx.getFailures();
  console.log(failures === 0 ? "\nCONFIG CHANGE-CONTROL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
