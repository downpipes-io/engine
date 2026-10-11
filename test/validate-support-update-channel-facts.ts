// Prove the support pack and the on-demand update check say WHY a channel fetch failed.
//
// A well-formed but wrong UPDATE_CHANNEL_URL path makes the channel fetch answer 404. The pack then showed
// channelBaseValid true and channelIssue fetch-failed with no HTTP status, no word on whether the channel or
// its signature failed, and no updateFaults row (only the apply path wrote one). A reader could not tell a
// customer misconfiguration from an engine defect. This drives the real checkUpdates (through the real
// fetchUpdateStatus projection and the real GET /admin/updates route) with a stubbed network.
//
// Run:  node test/validate-support-update-channel-facts.ts

import { ed25519 } from "@noble/curves/ed25519.js";
import { handleUpdates } from "../src/admin/router-updates.ts";
import { fetchUpdateStatus } from "../src/admin/support-sections-runs.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { UPDATE_CHANNEL_SHIPPED_URL } from "../src/lib/outbound.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const signerPublic = b64urlEncode(concat(ed25519.getPublicKey(crypto.getRandomValues(new Uint8Array(32))), new Uint8Array(mldsaKeygen().publicKey)));
const WRONG_URL = "https://update.downpipes.io/not-the-channel.json";

type Posted = Record<string, unknown>;
function scheduler(posted: Posted[]): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/diag/update-faults" && init?.method === "POST") {
        for (const r of (JSON.parse(String(init.body)) as { rows: Posted[] }).rows) posted.push(r);
        return new Response("{}");
      }
      if (url.pathname === "/update-faults") return new Response(JSON.stringify({ faults: [] }));
      if (url.pathname === "/update-status") return new Response(JSON.stringify({}));
      if (url.pathname === "/sources/discovery-config") return new Response(JSON.stringify({ config: null }));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

const realFetch = globalThis.fetch;
function stub(answer: (u: string) => Response): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => answer(String(input instanceof Request ? input.url : input))) as typeof fetch;
}

async function pack(env: Env): Promise<Record<string, unknown>> {
  const u = (await fetchUpdateStatus(env, scheduler([]))) as Record<string, unknown>;
  return (u.available ?? {}) as Record<string, unknown>;
}

async function main(): Promise<void> {
  console.log("validate-support-update-channel-facts\n");
  const env = { UPDATE_CHANNEL_URL: WRONG_URL, UPDATE_SIGNER_PUBLIC: signerPublic } as unknown as Env;

  // 1. Channel answers 404 (wrong path).
  stub(() => new Response("not found", { status: 404 }));
  const a = await pack(env);
  ok("channelIssue is still fetch-failed", a.channelIssue === "fetch-failed");
  ok("fetchStatus is 404", a.fetchStatus === 404);
  ok("fetchTarget is channel", a.fetchTarget === "channel");
  ok("channelUrlIsShipped is false for a different path", a.channelUrlIsShipped === false);
  ok("the pack never carries the URL", !JSON.stringify(a).includes("not-the-channel") && !JSON.stringify(a).includes("update.downpipes.io"));

  // 2. The shipped URL gives channelUrlIsShipped true.
  const shipped = await pack({ ...env, UPDATE_CHANNEL_URL: UPDATE_CHANNEL_SHIPPED_URL } as Env);
  ok("channelUrlIsShipped is true for the shipped URL", shipped.channelUrlIsShipped === true && shipped.fetchStatus === 404);

  // 3. Channel fine, signature 404: the target is the signature.
  stub((u) => (u.endsWith(".sig") ? new Response("no", { status: 404 }) : new Response("{}", { status: 200 })));
  const s = await pack(env);
  ok("a missing signature reports fetchTarget signature, status 404", s.fetchTarget === "signature" && s.fetchStatus === 404);

  // 4. Transport failure: status 0.
  globalThis.fetch = (async () => {
    throw new TypeError("network down");
  }) as typeof fetch;
  const t = await pack(env);
  ok("a transport failure reports fetchStatus 0, target channel", t.fetchStatus === 0 && t.fetchTarget === "channel" && t.channelIssue === "fetch-failed");

  // 5. The on-demand check (GET /admin/updates) writes the update-fault row.
  stub(() => new Response("not found", { status: 404 }));
  const posted: Posted[] = [];
  const ctx = { req: new Request("https://x/admin/updates"), env, url: new URL("https://x/admin/updates"), scheduler: scheduler(posted), sub: "/updates", method: "GET" } as never;
  const resp = await handleUpdates(ctx);
  ok("GET /admin/updates still answers 200", resp !== null && resp.status === 200);
  const row = posted[0];
  ok("the on-demand check recorded exactly one updateFaults row", posted.length === 1);
  ok("the row is component channel, step channel-fetch, httpStatus 404", row?.component === "channel" && row?.step === "channel-fetch" && row?.httpStatus === 404);
  ok("the row carries no URL", !JSON.stringify(row ?? {}).includes("update.downpipes.io"));

  // 6. A healthy-or-unconfigured engine records no row.
  const none: Posted[] = [];
  await handleUpdates({ ...(ctx as object), env: {} as Env, scheduler: scheduler(none) } as never);
  ok("an engine with no channel configured records no row", none.length === 0);

  globalThis.fetch = realFetch;
  verdictReached(failures);
  if (failures > 0) {
    console.log(`\n${failures} FAILED`);
    process.exit(1);
  }
  console.log("\nall ok");
}

declare const process: { exit(code?: number): never };
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
