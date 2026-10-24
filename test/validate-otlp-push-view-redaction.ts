// validate-otlp-push-view-redaction: GET /admin/otlp-push shows the OTLP push endpoint's path, query and fragment only to a
// caller who holds keys.ceremony (the Owner). A vendor intake takes its feed key as a path token or as a query
// parameter and stores it in the endpoint, and the view sits behind posture.read, a viewer-floor capability, so
// a reader without the Owner capability sees the scheme, host and port only, with endpointRedacted:true.
// Drives the real handleOtlpPush over a real SchedulerDO on in-memory storage.
//
// NEGATIVE CONTROLS: the Owner sees the full URL (so a route that dropped the path for everyone cannot
// pass), and an endpoint that is a bare scheme and host is returned unchanged with no flag. Run:
//   node test/validate-otlp-push-view-redaction.ts

import { handleOtlpPush } from "../src/admin/router-otlp-push.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 300)}`);
  }
}

const OWNER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const VIEWER: Caller = { method: "access", email: "v@example.au", subject: "subject-v@example.au", role: "viewer", groups: [] };

function makeStack(): { env: Env; stub: DurableObjectStub } {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(input instanceof Request ? input : input.toString(), init)) } as unknown as DurableObjectStub;
  return { env: { ADMIN_TOKEN: "t" } as unknown as Env, stub };
}

async function drive(s: { env: Env; stub: DurableObjectStub }, caller: Caller, method: "GET" | "POST", body?: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const url = new URL("https://engine.example/admin/otlp-push");
  const req = new Request(url, { method, headers: { "content-type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const ctx = { req, env: s.env, url, scheduler: s.stub, caller, sub: "/otlp-push", sourceIp: null, runtime: undefined } as unknown as RouterCtx;
  const resp = await handleOtlpPush(ctx);
  if (resp === null) return { status: 404, json: {} };
  return { status: resp.status, json: (await resp.json()) as Record<string, unknown> };
}

const httpSet = (endpoint: string): Record<string, unknown> => ({ endpoint, authHeaderName: "Authorization", authHeaderValue: "s", enabled: true });

async function main(): Promise<void> {
  const s = makeStack();
  const set = await drive(s, OWNER, "POST", httpSet("https://x.example/f?secret=abc#frag"));
  ok(`the Owner saves an endpoint carrying a query (status ${set.status})`, set.status === 200, set.json);

  const owner = await drive(s, OWNER, "GET");
  ok("negative control: the Owner sees the full endpoint, query and fragment", owner.json.endpoint === "https://x.example/f?secret=abc#frag", owner.json);
  ok("the Owner view carries no redaction flag", owner.json.endpointRedacted === undefined);

  // A credential in the URL PATH: the userinfo refusal tells operators to "use a path token".
  const tok = makeStack();
  await drive(tok, OWNER, "POST", httpSet("https://hooks.x.example:8443/v1/feeds/PATHTOKEN-9f3a/ingest"));
  const tokOwner = await drive(tok, OWNER, "GET");
  ok("negative control: the Owner sees the path token", String(tokOwner.json.endpoint).includes("PATHTOKEN-9f3a"), tokOwner.json);
  const tokViewer = await drive(tok, VIEWER, "GET");
  ok("the viewer view does not contain the path token", !JSON.stringify(tokViewer.json).includes("PATHTOKEN-9f3a"), tokViewer.json);
  ok("the viewer sees scheme, host and port for a path-token endpoint", tokViewer.json.endpoint === "https://hooks.x.example:8443", tokViewer.json);
  ok("the viewer view says the path-token endpoint was redacted", tokViewer.json.endpointRedacted === true, tokViewer.json);

  const viewer = await drive(s, VIEWER, "GET");
  ok(`a viewer can read the view (status ${viewer.status})`, viewer.status === 200);
  ok("the viewer view does not contain the query value", !JSON.stringify(viewer.json).includes("abc"), viewer.json);
  ok("the viewer view does not contain the fragment", !JSON.stringify(viewer.json).includes("frag"), viewer.json);
  ok("the viewer sees the scheme and host only", viewer.json.endpoint === "https://x.example", viewer.json);
  ok("the viewer view says the endpoint was redacted", viewer.json.endpointRedacted === true, viewer.json);
  ok("the rest of the view is intact for the viewer", viewer.json.present === true && viewer.json.authHeaderName === "Authorization" && viewer.json.enabled === true);

  const plain = makeStack();
  await drive(plain, OWNER, "POST", httpSet("https://x.example/"));
  const plainOwner = await drive(plain, OWNER, "GET");
  const plainViewer = await drive(plain, VIEWER, "GET");
  ok("negative control: a bare scheme-and-host endpoint is returned unchanged to a viewer", plainViewer.json.endpoint === plainOwner.json.endpoint && typeof plainViewer.json.endpoint === "string" && plainViewer.json.endpointRedacted === undefined, { owner: plainOwner.json, viewer: plainViewer.json });

  console.log(failures === 0 ? "\nOTLP PUSH VIEW REDACTION PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
