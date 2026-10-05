// One console-floor scenario, run in its own process by test/validate-console-floor-refusal.ts. It is a helper,
// not a validator: it prints one JSON result line and the validator grades it.
//
// It drives the REAL admin router (handleAdmin) over an in-memory SchedulerDO, with the bare-token break-glass
// caller, against a signed channel the validator built with tools/publish-channel.mjs. Every fetch is stubbed:
// the channel host serves the channel, its .sig and both artefacts, and the Cloudflare API answers the console
// script's reads and writes. Each Cloudflare call is recorded, so the validator can count the writes.
//
// The running engine version is the ENGINE_VERSION the engine source declares. With a version argument, a load
// hook rewrites that one literal in src/format/version.ts before any engine module loads, so this process runs
// as an engine of that version. The result reports the ENGINE_VERSION the router actually imported, so the
// validator can refuse a run whose override did not take. With "-" the source is left as it is.
//
// Run: node test/console-floor-scenario.ts <fixture-dir> <engine-version | ->

import { registerHooks } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
const override = process.argv[3];
if (!dir || !override) throw new Error("usage: node test/console-floor-scenario.ts <fixture-dir> <engine-version | ->");
const FIXTURE: string = dir;

let rewrote = false;
if (override !== "-") {
  if (!/^\d+\.\d+\.\d+$/.test(override)) throw new Error(`not a semver: ${override}`);
  registerHooks({
    load(url, context, nextLoad) {
      const r = nextLoad(url, context);
      if (url.endsWith("/src/format/version.ts")) {
        const src = typeof r.source === "string" ? r.source : new TextDecoder().decode(r.source as Uint8Array);
        const re = /export const ENGINE_VERSION = "[^"]*";/;
        if (!re.test(src)) throw new Error("console-floor-scenario: the ENGINE_VERSION declaration was not found, so the override cannot apply");
        rewrote = true;
        return { ...r, source: src.replace(re, `export const ENGINE_VERSION = "${override}";`) };
      }
      return r;
    },
  });
}

const CHANNEL_URL = "https://update.downpipes.io/stable.json";
const DEPLOY_TOKEN = "cf_deploy_token_0123456789abcdef";

interface CfCall {
  method: string;
  path: string;
}

async function main(): Promise<void> {
  const { handleAdmin } = await import("../src/admin/router.ts");
  const { SchedulerDO } = await import("../src/sched/scheduler-do.ts");
  const { ENGINE_VERSION } = await import("../src/format/version.ts");
  const { MockStorage } = await import("./mock-storage.ts");

  const channel = readFileSync(join(FIXTURE, "channel.json"));
  const sig = readFileSync(join(FIXTURE, "channel.json.sig"), "utf8");
  const signerPublic = readFileSync(join(FIXTURE, "update-signer-public.txt"), "utf8").trim();
  const doc = JSON.parse(new TextDecoder().decode(channel)) as { components: { engine: { url: string }; console: { url: string } } };
  const artefacts = new Map<string, Uint8Array>([
    [doc.components.engine.url, new Uint8Array(readFileSync(join(FIXTURE, "engine.mjs")))],
    [doc.components.console.url, new Uint8Array(readFileSync(join(FIXTURE, "console.json")))],
  ]);

  // The Cloudflare API: every call recorded. The console script's deploy state is stateful so the control's
  // post-promote confirmation read sees what was deployed; the ownership proof reads its settings.
  const cfCalls: CfCall[] = [];
  const unexpected: string[] = [];
  let consoleLive = "cv-live-0";
  let uploads = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? "GET";
    if (url === CHANNEL_URL) return new Response(new Uint8Array(channel), { status: 200 });
    if (url === `${CHANNEL_URL}.sig`) return new Response(sig, { status: 200 });
    const art = artefacts.get(url);
    if (art) return new Response(new Uint8Array(art), { status: 200 });
    const u = new URL(url);
    if (u.hostname === "api.cloudflare.com") {
      cfCalls.push({ method, path: u.pathname });
      const json = (body: unknown): Response => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
      const consoleScript = /\/workers\/scripts\/downpipe-console\//.test(u.pathname);
      if (consoleScript && method === "GET" && u.pathname.endsWith("/settings")) return json({ success: true, result: { bindings: [{ type: "service", name: "ENGINE", service: "downpipe-engine" }, { type: "assets", name: "ASSETS" }], compatibility_date: "2024-01-01" } });
      if (consoleScript && method === "GET" && u.pathname.endsWith("/deployments")) return json({ success: true, result: { deployments: [{ id: "cd-1", versions: [{ version_id: consoleLive, percentage: 100 }] }] } });
      if (consoleScript && method === "POST" && u.pathname.endsWith("/assets-upload-session")) return json({ success: true, result: { jwt: "session-is-completion", buckets: [] } });
      if (method === "POST" && /\/workers\/assets\/upload/.test(u.pathname)) return json({ success: true, result: { jwt: "completion-jwt" } });
      if (consoleScript && method === "POST" && u.pathname.endsWith("/versions")) return json({ success: true, result: { id: `cv-new-${++uploads}` } });
      if (consoleScript && method === "POST" && u.pathname.endsWith("/deployments")) {
        const posted = JSON.parse(String(init?.body)) as { versions?: { version_id?: string }[] };
        consoleLive = posted.versions?.[0]?.version_id ?? consoleLive;
        return json({ success: true });
      }
      return json({ success: false, errors: [{ code: 10000, message: "unexpected call in test" }] });
    }
    unexpected.push(`${method} ${url}`);
    return new Response("unexpected network fetch in test", { status: 404 });
  }) as typeof fetch;

  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (i: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(i, init)) } as unknown as DurableObjectStub;
  const env = {
    SCHEDULER: { idFromName: () => ({}), get: () => stub },
    ADMIN_TOKEN: "bg-token-console-floor",
    CF_ACCOUNT_ID: "acct-console-floor",
    WORKER_NAME: "downpipe-engine",
    UPDATE_CHANNEL_URL: CHANNEL_URL,
    UPDATE_SIGNER_PUBLIC: signerPublic,
    DEST_R2: {},
  } as unknown as import("../src/env.d.ts").Env;
  const call = async (method: "GET" | "POST", path: string, body?: unknown): Promise<{ status: number; body: Record<string, unknown> }> => {
    const init: RequestInit = { method, headers: { authorization: "Bearer bg-token-console-floor", ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
    const r = await handleAdmin(new Request(`https://engine.example${path}`, init), env);
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  const writes = (): number => cfCalls.filter((c) => c.method !== "GET").length;

  const updates = await call("GET", "/admin/updates");
  const planConsole = await call("POST", "/admin/update/apply", { components: ["console"] });
  const planBoth = await call("POST", "/admin/update/apply", { components: ["engine", "console"] });
  const writesBeforeLive = writes();
  const live = await call("POST", "/admin/update/apply", { components: ["console"], dryRun: false, token: DEPLOY_TOKEN });
  const status = await call("GET", "/admin/update/status");
  const refusedAudit = await call("GET", "/admin/audit?action=update-refused");
  const appliedAudit = await call("GET", "/admin/audit?action=update-applied");

  process.stdout.write(
    `${JSON.stringify({
      override,
      rewrote,
      engineVersion: ENGINE_VERSION,
      updates: updates.body,
      planConsole,
      planBoth,
      writesBeforeLive,
      live,
      writesAfterLive: writes(),
      cfCalls,
      status: status.body,
      refusedAudit: refusedAudit.body,
      appliedAudit: appliedAudit.body,
      unexpected,
    })}\n`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
