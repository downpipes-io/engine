// Prove OWNER-ACTION DUAL CONTROL end to end and SERVER-SIDE: when the customer has dual change control
// ENABLED (the SAME requireConfigApproval toggle the config-change gate reads), the high-blast-radius OWNER
// operations a single compromised/coerced owner could use to STEAL data or BREAK the system require a SECOND
// owner's approval. No network, no deploy, no cost. Run:
//   node test/validate-owner-action-dualcontrol.ts
//
// What this proves, for EACH gated op (the task's matrix):
//  - GATE ON, ONE OWNER  => 202 + a pending owner action, the op is NOT executed (no state change);
//  - SELF-APPROVAL refused (the maker cannot approve their own action), at the DO (defence in depth);
//  - A SECOND owner approves => the op executes (DO-executed ops run on approve; router-executed ops ARM
//    then run on the token re-submit + consume);
//  - ROUTER-BYPASS: driving the DO directly (bypassing the router) is STILL gated (the DO is the authority);
//  - BREAK-GLASS: the bare-token owner cannot PROPOSE/APPROVE an owner action (needs an attributable identity),
//    and when it toggles the gate the toggle is attributed;
//  - GATE OFF (the default) => the op executes directly, byte-equivalent to before (no regression).
//  - The ROUTER-EXECUTED ops (update/apply, update/settle, sources/attach, support-credential mint) CANNOT
//    run on one owner when ON: the first call returns 202 WITHOUT consuming the one-shot token / running the
//    privileged op, and the DO's gate-check + single-use consume enforce the approval the router cannot skip.
//
// Test setup: the validate-config-change-control idiom, a forged-but-correctly-signed RS256 Access JWT + an
// in-memory SchedulerDO driven through the PRODUCTION handleAdmin (so the REAL authorisation, role
// resolution, owner-action gate, approval state and audit chain all run) AND driven DIRECTLY at the DO stub
// (to prove the router cannot bypass the DO gate). The DO-executed ops (destinations / IdP / break-glass /
// discovery) actually EXECUTE on approve (they only write DO storage; no external I/O), so an approved
// execution is proven by the state change, not a shim. The router-executed ops are proven at the gate
// boundary (the deploy/mint itself needs network, but the dual-control GATE, record / arm / consume /
// single-use, is fully exercised; the privileged op runs only once an approved record exists).
//
// This file is a THIN ORCHESTRATOR: the harness (the JWT/JWKS shim, the in-memory DO, the shared closures) and
// each cohesive proof group live in sibling modules, each exporting a run() the orchestrator calls IN ORDER.
// The single shared ok()/failures accumulator (in the harness) keeps the final tally byte-faithful to before.

import { buildContext, failureCount } from "./validate-owner-action-dualcontrol-harness.ts";
import { run as runInternals } from "./validate-owner-action-dualcontrol-internals.ts";
import { run as runS1bTwoOwner } from "./validate-owner-action-dualcontrol-s1b-twoowner.ts";
import { run as runDoExecuted } from "./validate-owner-action-dualcontrol-do-executed.ts";
import { run as runRouterExecuted } from "./validate-owner-action-dualcontrol-router-executed.ts";
import { run as runRedaction } from "./validate-owner-action-dualcontrol-redaction.ts";
import { run as runExecState } from "./validate-owner-action-dualcontrol-execstate.ts";

async function main(): Promise<void> {
  const ctx = await buildContext();

  try {
    // PROOF 0 + PROOF 1 + PROOF S1b (one owner): the single-owner phase, before the second owner is granted.
    await runInternals(ctx);
    // PROOF S1b (two owners): grants the second owner + operator, then the two-owner auto-apply guarantees.
    await runS1bTwoOwner(ctx);
    // PROOF 2 + PROOF 3: turn the gate ON, then every DO-executed op via the DO stub (the router-bypass proof).
    await runDoExecuted(ctx);
    // PROOF 3.5 + 3.6 + 5 + 6 + 6.5: the router end-to-end path, the asymmetric off switch, the router-executed
    // gate (record / arm / single-use consume), and the settle KEEP/ROLLBACK mapping.
    await runRouterExecuted(ctx);
    // PROOF 4 + 7 + 8 + 9 + 10 + 11: secret redaction, the break-glass refusal, the non-owner approve refusal,
    // the tampered-record integrity refusal, the gate-off regression, and the audit-chain verification.
    await runRedaction(ctx);
    // AUTH-44 + AUTH-46: the execute-time single-use guard (second-approve-on-executed) and the live
    // proposer-authority re-check at execute (a proposer demoted from owner cannot have their action run).
    await runExecState(ctx);
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  const failures = failureCount();
  console.log(failures === 0 ? "\nOWNER-ACTION DUAL-CONTROL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
