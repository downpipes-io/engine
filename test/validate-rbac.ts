// Prove the engine governance backbone: whoami and server-side RBAC + the last-Owner guard,
// end to end and SERVER-SIDE, with in-memory doubles only. No network, no
// deploy, no cost. Run:
//   node test/validate-rbac.ts
//
// What this proves (the launch-gate claims):
//  - the role table bootstraps the first authenticated Access caller as Owner;
//  - role grant and revoke work, keyed by the verified email, Owner-gated;
//  - the per-route role matrix is enforced AT THE ROUTER on the verified identity's role
//    (a Viewer cannot mutate, an Operator cannot apply a restore), returning a JSON 403 that is
//    distinct from the plaintext 401;
//  - a DIRECT-API restore apply (confirm:true) by an Operator is refused server-side, i.e.
//    bypassing the SPA does not bypass the control (the hard rule);
//  - the last-Owner guard refuses demotion or removal of the only Owner, in the
//    DO, inside the storage read-modify-write;
//  - the DO re-checks Owner independently of the router (defence in depth);
//  - whoami reports the verified method/email/role/session-expiry/isOnlyOwner.
//
// The Access path is driven with a forged-but-correctly-signed RS256 JWT verified against a
// controlled JWKS served by a stubbed global fetch, so authorise() runs its REAL verification
// and resolves a REAL verified identity at a chosen role (the same technique as
// validate-access.ts), exercising the production code path rather than a shim.
//
// This file is a THIN ORCHESTRATOR: the proofs now live in sibling
// modules (validate-rbac-bootstrap/-matrix/-accessadmin/-breakglass), built over the shared harness in
// validate-rbac-harness.ts. main() builds one context (the shared scheduler, signer, ok() reporter)
// and calls each group in the SAME order as the original single-file suite, so the full vector set
// still runs from `node test/validate-rbac.ts` with every assertion preserved.

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { type Counter, type Ctx, makeOk, makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { runBootstrap } from "./validate-rbac-bootstrap.ts";
import { runMatrix } from "./validate-rbac-matrix.ts";
import { runAccessAdmin } from "./validate-rbac-accessadmin.ts";
import { runBreakGlass } from "./validate-rbac-breakglass.ts";

async function main(): Promise<void> {
  const counter: Counter = { failures: 0 };
  const ok = makeOk(counter);

  // The signer mints the forged-but-real Access JWTs and stubs global fetch at the controlled JWKS so
  // authorise() verifies for real; restoreFetch() puts the real fetch back at the end.
  const signer = await makeSigner();

  // call drives handleAdmin as a given Access identity (the engine resolves the role from the
  // DO table keyed by the email). path is the admin sub-path; an optional JSON body for POSTs.
  const sched = makeScheduler();
  const accessEnv = (): Env =>
    ({
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
    }) as unknown as Env;

  async function call(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
    const assertion = await signer.tokenFor(email);
    const init: RequestInit = {
      method,
      headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    };
    return handleAdmin(new Request(`https://engine.example${path}`, init), accessEnv());
  }

  const ctx: Ctx = { ok, signer, sched, accessEnv, call };

  // Run the groups in the original order. PROOFs 1..10b are STATEFUL over the shared `sched` (the role
  // table mutates across them), so they share `ctx` and run in sequence; PROOFs 11..13 are
  // self-contained (each its own fresh scheduler) and take only the signer.
  // Restore the stubbed global fetch in a finally: if any group throws
  // before the groups finish, the real fetch is still put back so a shared test runner is not left with
  // the stub installed.
  try {
    await runBootstrap(ctx);
    await runMatrix(ctx);
    await runAccessAdmin(ctx);
    await runBreakGlass(ok, signer);
  } finally {
    signer.restoreFetch();
  }

  console.log(counter.failures === 0 ? "\nRBAC + WHOAMI + LAST-OWNER VECTORS PASS" : `\n${counter.failures} FAILURE(S)`);
  if (counter.failures > 0) process.exitCode = 1;
  if (counter.failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
