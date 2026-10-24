// validate-push-egress-allowlist: the operator egress allowlist (ASVS V13.2.4) governs the audit-log push
// (http, s3 and syslog-tls sinks) and the OTLP metrics push as it governs notification channels.
//
// Two boundaries are proved against a real SchedulerDO behind the real admin router:
//   - SAVE: with a list set, a push destination on a host outside it is refused 400; a host on it saves.
//   - SEND: a destination stored while no list was set is refused at delivery once a list excludes it, with
//     the closed reason egress-not-allowlisted and no request made.
// NEGATIVE CONTROL: every refusal is paired with the same submission accepted when no list is set (or the
// host is listed), so a route that refused everything cannot pass. Run: node test/validate-push-egress-allowlist.ts

import { handleAdmin } from "../src/admin/router.ts";
import { fetchOtlpPushConfig, deliverResolvedOtlpPush } from "../src/cron/otlp-push-pass.ts";
import { deliverResolvedPush, fetchPushConfig } from "../src/cron/siem-push-pass.ts";
import { buildSyntheticPushEvent } from "../src/cron/siem-push-shape.ts";
import type { Env } from "../src/env.d.ts";
import { pushTargetAllowed, readEgressAllowlist } from "../src/notify/push-egress.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const ADMIN_TOKEN = "push-egress-break-glass-token-1234567890";
const LISTED = "siem.example";
const OTHER = "other.example";

interface Stack {
  stub: DurableObjectStub;
  env: Env;
}
function makeStack(): Stack {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => dobj.fetch(new Request(input instanceof Request ? input : input.toString(), init)) } as unknown as DurableObjectStub;
  const namespace = { idFromName: (_n: string) => ({}) as unknown as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
  return { stub, env: { SCHEDULER: namespace, ADMIN_TOKEN } as unknown as Env };
}

async function call(env: Env, path: string, body: unknown): Promise<{ status: number; error: string }> {
  const resp = await handleAdmin(
    new Request(`https://engine.push-egress.example${path}`, { method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body) }),
    env,
  );
  let error = "";
  try {
    const j = (await resp.json()) as { error?: unknown };
    error = typeof j.error === "string" ? j.error : "";
  } catch {
    /* a non-JSON body leaves error empty */
  }
  return { status: resp.status, error };
}

const setList = (env: Env, hosts: string[]): Promise<{ status: number; error: string }> => call(env, "/admin/config/egress-allowlist", { egressAllowlist: hosts });

function httpBody(host: string): Record<string, unknown> {
  return { endpoint: `https://${host}/ingest`, format: "raw-json", authHeaderName: "Authorization", authHeaderValue: "s", enabled: true };
}
function s3Body(host: string): Record<string, unknown> {
  return { sink: "s3", format: "raw-json", enabled: true, s3Target: { endpoint: `https://${host}`, bucket: "audit", region: "us-east-1", accessKeyId: "AKIA", secretAccessKey: "secret" } };
}
function syslogBody(host: string): Record<string, unknown> {
  return { sink: "syslog-tls", format: "cef", enabled: true, syslog: { host, port: 6514 } };
}
function otlpBody(host: string): Record<string, unknown> {
  return { endpoint: `https://${host}/v1/metrics`, authHeaderName: "Authorization", authHeaderValue: "s", enabled: true };
}

const SURFACES: Array<{ name: string; path: string; body: (host: string) => Record<string, unknown> }> = [
  { name: "siem http", path: "/admin/push", body: httpBody },
  { name: "siem s3", path: "/admin/push", body: s3Body },
  { name: "siem syslog-tls", path: "/admin/push", body: syslogBody },
  { name: "otlp", path: "/admin/otlp-push", body: otlpBody },
];

async function main(): Promise<void> {
  const realFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    calls.push(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    return new Response("ok", { status: 200 });
  }) as typeof fetch;

  try {
    console.log("\nSAVE boundary\n");
    for (const surface of SURFACES) {
      // Negative control: no list set, the off-list host saves.
      const open = makeStack();
      const control = await call(open.env, surface.path, surface.body(OTHER));
      ok(`${surface.name}: negative control, no allowlist set, ${OTHER} is not refused (status ${control.status})`, control.status < 400);

      const limited = makeStack();
      ok(`${surface.name}: allowlist set`, (await setList(limited.env, [LISTED])).status === 200);
      const refused = await call(limited.env, surface.path, surface.body(OTHER));
      ok(`${surface.name}: ${OTHER} outside the list is refused 400 (status ${refused.status})`, refused.status === 400);
      const permitted = await call(limited.env, surface.path, surface.body(LISTED));
      ok(`${surface.name}: ${LISTED} on the list is not refused (status ${permitted.status})`, permitted.status < 400);
    }

    console.log("\nSEND boundary\n");
    for (const surface of SURFACES.filter((x) => x.path === "/admin/push")) {
      // A destination stored while no list is set, then a list that excludes it: every audit-log push sink.
      const s = makeStack();
      ok(`${surface.name} destination saved with no list`, (await call(s.env, "/admin/push", surface.body(OTHER))).status < 400);
      const meta = { afterSeq: 0, nextAfterSeq: 0, headSeq: 0, headHash: "" };
      const control = await fetchPushConfig(s.stub as never, undefined);
      ok(`${surface.name}: config read back`, control !== null);
      calls.length = 0;
      const before = await deliverResolvedPush(control!, [buildSyntheticPushEvent()], meta);
      ok(`${surface.name}: negative control, no list, the send is not refused as egress (reason ${String(before.reason)})`, before.reason !== "egress-not-allowlisted");
      ok(`${surface.name}: setting a list that excludes the stored host`, (await setList(s.env, [LISTED])).status === 200);
      const cfg = await fetchPushConfig(s.stub as never, undefined);
      calls.length = 0;
      const after = await deliverResolvedPush(cfg!, [buildSyntheticPushEvent()], meta);
      ok(`${surface.name}: the send is refused with egress-not-allowlisted`, after.ok === false && after.reason === "egress-not-allowlisted");
      ok(`${surface.name}: no request left the engine for the refused target`, !calls.some((u) => u.includes(OTHER)));
    }
    {
      const s = makeStack();
      ok("otlp destination saved with no list", (await call(s.env, "/admin/otlp-push", otlpBody(OTHER))).status < 400);
      const control = await fetchOtlpPushConfig(s.stub as never, undefined);
      ok("otlp: config read back", control !== null);
      const before = await deliverResolvedOtlpPush(control!, [], Date.now());
      ok(`otlp: negative control, no list, the send is not refused as egress (reason ${String(before.reason)})`, before.reason !== "egress-not-allowlisted");
      ok("otlp: setting a list that excludes the stored host", (await setList(s.env, [LISTED])).status === 200);
      const cfg = await fetchOtlpPushConfig(s.stub as never, undefined);
      calls.length = 0;
      const after = await deliverResolvedOtlpPush(cfg!, [], Date.now());
      ok("otlp: the send is refused with egress-not-allowlisted", after.ok === false && after.reason === "egress-not-allowlisted");
      ok("otlp: no request left the engine for the refused target", !calls.some((u) => u.includes(OTHER)));
    }
    console.log("\nMISSING allowlist in the DO answer\n");
    {
      // The DO answers an egressAllowlist with every push config read and with the allowlist read. An answer
      // without the field must refuse, never read as "no list" (which would allow every host).
      const s = makeStack();
      ok("siem http destination saved for the missing-list case", (await call(s.env, "/admin/push", httpBody(OTHER))).status < 400);
      ok("otlp destination saved for the missing-list case", (await call(s.env, "/admin/otlp-push", otlpBody(OTHER))).status < 400);
      const stripped = {
        fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
          const resp = await s.stub.fetch(input as RequestInfo, init);
          const j = (await resp.json()) as Record<string, unknown>;
          delete j.egressAllowlist;
          return new Response(JSON.stringify(j), { status: resp.status, headers: { "content-type": "application/json" } });
        },
      };
      const refuses = async (label: string, f: () => Promise<unknown>): Promise<void> => {
        let threw = false;
        try {
          await f();
        } catch {
          threw = true;
        }
        ok(label, threw);
      };
      ok("negative control: the intact siem config reads", (await fetchPushConfig(s.stub as never, undefined)) !== null);
      ok("negative control: the intact otlp config reads", (await fetchOtlpPushConfig(s.stub as never, undefined)) !== null);
      ok("negative control: the intact allowlist reads as an empty list", (await readEgressAllowlist(s.stub as never)).length === 0);
      await refuses("siem: a push config answer without egressAllowlist is refused", () => fetchPushConfig(stripped as never, undefined));
      await refuses("otlp: a push config answer without egressAllowlist is refused", () => fetchOtlpPushConfig(stripped as never, undefined));
      await refuses("save: an allowlist answer without egressAllowlist is refused", () => readEgressAllowlist(stripped as never));
      // An element that is not a string refuses too: dropping it would turn [1, 2] into an empty list, which allows every host.
      const answering = (value: unknown) => ({
        fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
          const resp = await s.stub.fetch(input as RequestInfo, init);
          const j = (await resp.json()) as Record<string, unknown>;
          j.egressAllowlist = value;
          return new Response(JSON.stringify(j), { status: resp.status, headers: { "content-type": "application/json" } });
        },
      });
      ok("negative control: a list of strings reads through the siem reader unchanged", (await fetchPushConfig(answering([LISTED]) as never, undefined))?.egressAllowlist?.[0] === LISTED);
      ok("negative control: an empty list reads through the otlp reader as an empty list", (await fetchOtlpPushConfig(answering([]) as never, undefined))?.egressAllowlist?.length === 0);
      for (const bad of [[1, 2], ["ok", 1], "ok", null]) {
        const shown = JSON.stringify(bad);
        await refuses(`siem: an egressAllowlist of ${shown} is refused`, () => fetchPushConfig(answering(bad) as never, undefined));
        await refuses(`otlp: an egressAllowlist of ${shown} is refused`, () => fetchOtlpPushConfig(answering(bad) as never, undefined));
        await refuses(`save: an egressAllowlist of ${shown} is refused`, () => readEgressAllowlist(answering(bad) as never));
      }
    }
    console.log("\nUNPARSEABLE target\n");
    {
      // An unparseable stored URL is refused whether or not a list is set, and no request is made for it.
      ok("negative control: a parseable URL with no list is allowed", pushTargetAllowed("https://siem.example/ingest", "url", undefined));
      ok("an unparseable URL with no list is refused", !pushTargetAllowed("not a url", "url", undefined));
      ok("an unparseable URL with a list is refused", !pushTargetAllowed("not a url", "url", [LISTED]));
      const s = makeStack();
      ok("siem http destination saved for the unparseable case", (await call(s.env, "/admin/push", httpBody(OTHER))).status < 400);
      const cfg = await fetchPushConfig(s.stub as never, undefined);
      calls.length = 0;
      const sent = await deliverResolvedPush({ ...cfg!, endpoint: "not a url" }, [buildSyntheticPushEvent()], { afterSeq: 0, nextAfterSeq: 0, headSeq: 0, headHash: "" });
      ok("siem: a stored endpoint that does not parse is refused with egress-not-allowlisted", sent.ok === false && sent.reason === "egress-not-allowlisted");
      ok("siem: no request was made for the unparseable endpoint", calls.length === 0);
      const o = makeStack();
      ok("otlp destination saved for the unparseable case", (await call(o.env, "/admin/otlp-push", otlpBody(OTHER))).status < 400);
      const ocfg = await fetchOtlpPushConfig(o.stub as never, undefined);
      calls.length = 0;
      const osent = await deliverResolvedOtlpPush({ ...ocfg!, endpoint: "not a url" }, [], Date.now());
      ok("otlp: a stored endpoint that does not parse is refused with egress-not-allowlisted", osent.ok === false && osent.reason === "egress-not-allowlisted");
      ok("otlp: no request was made for the unparseable endpoint", calls.length === 0);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nPUSH EGRESS ALLOWLIST PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
