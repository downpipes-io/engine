// validate-passkey-login-failure-ip: a failed passkey login/finish must record the edge source IP on its
// authn-failure audit row, and a client must not be able to choose that IP.
//
// The DO appends an authn-failure row for every failed login/finish (scheduler-do-routing-identity.ts). The
// router stripped every client sourceIp off the inbound body and forwarded no server-read IP either, so the row
// always read sourceIp: null. The SSO callback rows already carry the edge address.
//
// This validator drives the production handleAdmin router into a real SchedulerDO. It proves:
//  - a failed login/finish with a CF-Connecting-IP header writes an authn-failure row with that IP;
//  - a client-supplied sourceIp in the body never reaches the row, with or without the edge header;
//  - with no edge header the row records null (an absent address stays absent);
//  - the row still names no actor.
//
// Run: node test/validate-passkey-login-failure-ip.ts

import type { AuditEvent } from "../src/admin/audit.ts";
import { makeScheduler, post } from "./validate-passkey-harness.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EDGE_IP = "198.51.100.23";
const FORGED_IP = "192.0.2.99";

// failedLogin sends one login/finish that cannot verify (no such challenge) and returns the authn-failure
// row it appended. Each call uses a fresh DO, so the per-minute coalescing window never hides a row.
async function failedLogin(body: Record<string, unknown>, ip: string | null): Promise<{ status: number; ok: unknown; row: AuditEvent | undefined }> {
  const { env, storage } = makeScheduler();
  const res = await post(env, "/admin/auth/login/finish", { challengeId: "no-such-challenge", credential: { id: "AA", response: {} }, ...body }, { ip });
  const rows = [...(await storage.list<AuditEvent>({ prefix: "audit:" })).values()];
  return { status: res.status, ok: res.json.ok, row: rows.find((r) => r.action === "authn-failure") };
}

async function main(): Promise<void> {
  const withIp = await failedLogin({}, EDGE_IP);
  ok("a failed login/finish answers 200 with ok:false", withIp.status === 200 && withIp.ok === false);
  ok("the failed login/finish appends an authn-failure row", withIp.row !== undefined);
  console.log(`  row sourceIp: ${JSON.stringify(withIp.row?.sourceIp ?? null)}`);
  ok("the authn-failure row records the edge CF-Connecting-IP", withIp.row?.sourceIp === EDGE_IP);
  ok("the authn-failure row still names no actor", withIp.row?.actorEmail === null && withIp.row?.actorSubject === null);

  const forgedWithIp = await failedLogin({ sourceIp: FORGED_IP }, EDGE_IP);
  ok("a client sourceIp in the body does not replace the edge IP", forgedWithIp.row?.sourceIp === EDGE_IP);

  const forgedNoIp = await failedLogin({ sourceIp: FORGED_IP }, null);
  ok("with no edge header, a client sourceIp in the body is not recorded", forgedNoIp.row !== undefined && forgedNoIp.row.sourceIp === null);

  console.log(failures === 0 ? "\nVALIDATE-PASSKEY-LOGIN-FAILURE-IP VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
