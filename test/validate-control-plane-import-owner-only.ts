// validate-control-plane-import-owner-only: the estate import routes are for an Owner, not for every holder of
// access.policy.
//
// POST /admin/control-plane/import and /import-sealed install downpipes, destinations and the default
// destination on a fresh engine. The same writes made directly (POST /admin/destinations) need keys.ceremony,
// which only an Owner holds. An access-admin holds access.policy (a people-only role) and must not be able to
// reach the import. This validator drives the real router spoke with a built-in access-admin caller and a built-in
// owner caller:
//  - access-admin: both import routes answer 403 naming keys.ceremony;
//  - owner: both routes pass the gate (a body that is not an export answers 400, not 403).
//
// Run: node test/validate-control-plane-import-owner-only.ts

import { handleIdentity } from "../src/admin/router-identity.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeScheduler(): DurableObjectStub {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  return { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init)) } as unknown as DurableObjectStub;
}

const callerOf = (role: Caller["role"]): Caller => ({ method: "access" as Caller["method"], email: `${role}@import.example`, subject: `subj-${role}`, role, groups: [] });

async function post(scheduler: DurableObjectStub, caller: Caller, sub: string): Promise<Response> {
  const ctx = {
    req: new Request(`https://engine.import.example/admin${sub}`, { method: "POST", body: JSON.stringify({}), headers: { "content-type": "application/json" } }),
    env: {} as unknown as Env,
    url: new URL(`https://engine.import.example/admin${sub}`),
    scheduler,
    caller,
    sub,
    sourceIp: null,
    runtime: undefined,
    verdict: { ok: true, method: caller.method, email: caller.email, subject: caller.subject, exp: 1_900_000_000, groups: caller.groups },
    isOnlyOwner: false,
    roleSource: "builtin",
    customRole: undefined,
  } as unknown as RouterCtx;
  return (await handleIdentity(ctx))!;
}

async function main(): Promise<void> {
  for (const sub of ["/control-plane/import", "/control-plane/import-sealed"]) {
    const scheduler = makeScheduler();
    const admin = await post(scheduler, callerOf("access-admin"), sub);
    const body = (await admin.json()) as { required?: string };
    console.log(`  ${sub} as access-admin: status=${admin.status} required=${body.required ?? "-"}`);
    ok(`${sub}: an access-admin is refused 403`, admin.status === 403);
    ok(`${sub}: the refusal names keys.ceremony`, body.required === "keys.ceremony");
    const owner = await post(makeScheduler(), callerOf("owner"), sub);
    console.log(`  ${sub} as owner: status=${owner.status}`);
    ok(`${sub}: an Owner passes the gate (a non-export body answers 400)`, owner.status === 400);
  }
  console.log(failures === 0 ? "\nVALIDATE-CONTROL-PLANE-IMPORT-OWNER-ONLY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
