// validate-support-pull-audit: a vendor diagnostics pull is a first-class event in the hash-chained audit log.
//
// WHY THIS FILE EXISTS. The security attestation says support access is "written to the customer's own audit
// log". The GRANT always was: /ingest-credential/set appends support-credential-grant at the commit point.
// Each PULL was not. handleSupportPull (src/admin/support-ingest.ts) recorded a pull only on the grant's
// rolling trail of the last 50 pulls. That trail is best-effort, rolls over, and is not hash-chained. So an
// auditor who asked "when did the vendor read our diagnostics?" could not answer from the tamper-evident log.
//
// WHAT IS GRADED, on a REAL SchedulerDO over MockStorage (the rig validate-ingest-pull-rate-limit.ts uses):
//   - an owner grants a diagnostics credential through the DO's own route, so the grant event is real;
//   - one served GET /support/diagnostics appends exactly one support-diagnostics-pulled event after it;
//   - the event names the credential by its PUBLIC clientId, carries the source IP, and never the secret;
//   - a second served pull appends a second event (per pull, not per grant);
//   - the chain still verifies with the new events on it.
// CONTROLS, so the file cannot pass against a build that writes an event on every request:
//   - a refused pull (a wrong secret, or no bearer) appends nothing;
//   - an audit-feed pull (the customer's own SIEM collector, not support access) appends nothing.
//
// Run: node test/validate-support-pull-audit.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { handleSupportPull, mintIngestCredential } from "../src/admin/support-ingest.ts";
import { callerHeaders } from "../src/admin/router-audit.ts";
import { AUDIT_ACTIONS } from "../src/admin/audit-types.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EMPTY_ENV = {} as unknown as Env;
const VENDOR_IP = "198.51.100.23";
// The bare-token caller resolves to owner in the DO (roleForCaller's method==="token" branch).
const OWNER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };

function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)),
  } as unknown as DurableObjectStub;
}

function pull(scope: "audit-feed" | "diagnostics", bearer: string | null): Request {
  const headers: Record<string, string> = { "CF-Connecting-IP": VENDOR_IP };
  if (bearer !== null) headers["Authorization"] = `Bearer ${bearer}`;
  return new Request(`https://engine.example/support/${scope}`, { headers });
}

async function exportAudit(stub: DurableObjectStub): Promise<{ text: string; events: AuditEvent[] }> {
  const resp = await stub.fetch("https://do/audit/export");
  const text = await resp.text();
  return { text, events: (JSON.parse(text) as { events: AuditEvent[] }).events };
}

async function grantCredential(stub: DurableObjectStub, scope: "diagnostics" | "audit-feed"): Promise<{ clientId: string; secret: string }> {
  const minted = await mintIngestCredential(scope, null, 3600);
  const resp = await stub.fetch("https://do/ingest-credential/set", { method: "POST", body: JSON.stringify({ scope, grant: minted.grant }), headers: callerHeaders(OWNER) });
  if (!resp.ok) throw new Error(`grant failed: ${resp.status} ${await resp.text()}`);
  return { clientId: minted.clientId, secret: minted.secret };
}

const pulled = (events: AuditEvent[]): AuditEvent[] => events.filter((e) => e.action === "support-diagnostics-pulled");

async function main(): Promise<void> {
  console.log("the action is in the closed vocabulary:");
  ok("support-diagnostics-pulled is a member of AUDIT_ACTIONS", (AUDIT_ACTIONS as readonly string[]).includes("support-diagnostics-pulled"));

  console.log("\na served diagnostics pull is on the chain:");
  const stub = asStub(new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState));
  const diag = await grantCredential(stub, "diagnostics");
  const before = await exportAudit(stub);
  const grantEvent = before.events.find((e) => e.action === "support-credential-grant" && e.target.kind === "supportcredential" && e.target.clientId === diag.clientId);
  ok("FLOOR: the grant itself is on the chain (the part that was always audited)", grantEvent !== undefined);
  ok("FLOOR: no pull event exists before any pull", pulled(before.events).length === 0);

  const resp = await handleSupportPull(pull("diagnostics", `${diag.clientId}.${diag.secret}`), EMPTY_ENV, stub);
  ok(`the diagnostics pull is served (status ${resp.status})`, resp.status === 200);
  const after = await exportAudit(stub);
  const events = pulled(after.events);
  // THE ASSERTION THE OLD BEHAVIOUR FAILED: nothing reached the chain for a served pull.
  ok(`exactly one support-diagnostics-pulled event is on the chain (${events.length})`, events.length === 1);
  const e = events[0];
  ok("it follows the grant event", e !== undefined && grantEvent !== undefined && e.seq > grantEvent.seq);
  ok("its outcome is success", e?.outcome === "success");
  ok("its target is the diagnostics credential, by PUBLIC clientId", e?.target.kind === "supportcredential" && e.target.scope === "diagnostics" && e.target.clientId === diag.clientId);
  ok("its actor is the credential, named by clientId, with no email", e?.actorSubject === `support-credential:${diag.clientId}` && e.actorEmail === null && e.actorMethod === "token");
  ok("it carries the puller's source IP", e?.sourceIp === VENDOR_IP);
  ok("the secret never reaches the exported log", !after.text.includes(diag.secret));

  await handleSupportPull(pull("diagnostics", `${diag.clientId}.${diag.secret}`), EMPTY_ENV, stub);
  ok("a second served pull appends a second event (one per pull)", pulled((await exportAudit(stub)).events).length === 2);

  console.log("\ncontrols: nothing else writes the event:");
  const beforeRefused = (await exportAudit(stub)).events.length;
  const wrong = await handleSupportPull(pull("diagnostics", `${diag.clientId}.dps_wrong-secret`), EMPTY_ENV, stub);
  const none = await handleSupportPull(pull("diagnostics", null), EMPTY_ENV, stub);
  ok(`CONTROL: refused pulls answer 401 (${wrong.status}, ${none.status})`, wrong.status === 401 && none.status === 401);
  ok("CONTROL: a refused pull appends no audit event", (await exportAudit(stub)).events.length === beforeRefused);

  const feed = await grantCredential(stub, "audit-feed");
  const beforeFeed = pulled((await exportAudit(stub)).events).length;
  const feedResp = await handleSupportPull(pull("audit-feed", `${feed.clientId}.${feed.secret}`), EMPTY_ENV, stub);
  ok(`CONTROL: an audit-feed pull is served (${feedResp.status})`, feedResp.status === 200);
  ok("CONTROL: an audit-feed pull appends no support-diagnostics-pulled event", pulled((await exportAudit(stub)).events).length === beforeFeed);

  const verify = (await (await stub.fetch("https://do/audit/verify")).json()) as { intact?: boolean; checkedThrough?: number };
  ok(`the chain still verifies with the pull events on it (intact through seq ${verify.checkedThrough})`, verify.intact === true);

  console.log(failures === 0 ? "\nSUPPORT PULL AUDIT PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
