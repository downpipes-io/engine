// validate-control-plane-bridge-actor-method: the control-plane-reconciled bridge row must record how the caller
// authenticated.
//
// writeReconcileBridge (src/sched/scheduler-do-control-plane.ts) writes the first row of the new audit chain for
// the break-glass reconcile, the break-glass authority restore and the Owner estate import. It hard-coded
// actorMethod "token". The estate import refuses the token and runs only for an authenticated Owner, so its row
// named the Owner's email beside the wrong method.
//
// This validator drives the real SchedulerDO. It proves:
//  - an estate import by an Access Owner writes a bridge row with actorMethod "access";
//  - an estate import by a passkey Owner writes a bridge row with actorMethod "passkey";
//  - the break-glass reconcile still writes a bridge row with actorMethod "token".
//
// Run: node test/validate-control-plane-bridge-actor-method.ts

import { makeConfig, makeScheduler } from "./validate-scheduler-shared.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const bridgeRow = (rows: AuditEvent[]): AuditEvent | undefined => rows.find((e) => e.action === "control-plane-reconciled" && e.outcome === "success");

async function main(): Promise<void> {
  // The export: one downpipe and a bootstrapped Owner on a source engine.
  const src = makeScheduler();
  await src.stub.addDownpipe(makeConfig("dp-bridge"));
  await src.stub.whoami("owner@example.com", "subj-owner", "access", null);
  const exp = await src.stub.buildControlPlaneExport();

  for (const method of ["access", "passkey"] as const) {
    const email = `${method}-owner@example.com`;
    const subject = `subj-${method}-owner`;
    const dst = makeScheduler();
    await dst.stub.whoami(email, subject, method, null); // bootstrap the fresh engine's own Owner
    await dst.stub.importControlPlaneDefinition(exp, false, { method, email, subject, groups: [], sourceIp: "203.0.113.40" });
    const row = bridgeRow(await dst.stub.listAuditEntries());
    console.log(`  import by ${method}: actorMethod=${JSON.stringify(row?.actorMethod ?? null)} actorEmail=${JSON.stringify(row?.actorEmail ?? null)}`);
    ok(`import by a ${method} Owner: a bridge row is written`, row !== undefined);
    ok(`import by a ${method} Owner: the bridge row records actorMethod "${method}"`, row?.actorMethod === method);
    ok(`import by a ${method} Owner: the bridge row names the Owner`, row?.actorEmail === email);
  }

  // The break-glass reconcile on a wiped plane keeps the token method.
  const wiped = makeScheduler();
  await wiped.stub.reconcileControlPlane(exp, { method: "token", email: null, subject: null, groups: [] });
  const tokenRow = bridgeRow(await wiped.stub.listAuditEntries());
  ok("reconcile by the break-glass token: the bridge row records actorMethod \"token\"", tokenRow?.actorMethod === "token");

  console.log(failures === 0 ? "\nVALIDATE-CONTROL-PLANE-BRIDGE-ACTOR-METHOD VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
