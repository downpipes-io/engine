// Unit-prove the first-Owner bootstrap email (src/admin/router-auth-flow.ts sendBootstrapLink): the
// no-oracle generic 200 on every path, a single best-effort send only when fully configured, and the
// branded HTML twin (doctype + wordmark + the set-up link as a button) that carries NO vendor sign-off,
// because a self-hosted engine mails its own owner, never on Maelstrom's behalf. The route's mint and
// no-oracle response shaping are covered by the RBAC break-glass validators; here the focus is the email
// the rightful owner receives, which had no test of its own before the HTML re-theme.
//
// Run:
//   node test/validate-bootstrap-email.ts

import { sendBootstrapLink, BOOTSTRAP_SUBJECT } from "../src/admin/router-auth-flow.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// recordingEmail: the in-memory EMAIL binding double; records every message send() is handed so the
// bootstrap body (text and html) is assertable without a live send.
function recordingEmail(): { binding: { send(m: unknown): Promise<{ messageId: string }> }; sent: Array<Record<string, unknown>> } {
  const sent: Array<Record<string, unknown>> = [];
  return { sent, binding: { async send(m: unknown): Promise<{ messageId: string }> { sent.push(m as Record<string, unknown>); return { messageId: "rec-1" }; } } };
}

// mintingScheduler: a DurableObjectStub double whose only call from sendBootstrapLink is the bootstrap
// mint. It answers every fetch with the given token (a string mints the invite, null models the closed
// path where an Owner already exists), so the test does not depend on the mint URL shape.
function mintingScheduler(token: string | null): DurableObjectStub {
  return {
    fetch: (): Promise<Response> => Promise.resolve(new Response(JSON.stringify({ token }), { status: 200, headers: { "content-type": "application/json" } })),
  } as unknown as DurableObjectStub;
}

const post = (): Request => new Request("https://engine.acme.example/admin/auth/bootstrap/send", { method: "POST" });

async function main(): Promise<void> {
  // 1. Fully configured: one send, the pinned owner as recipient, the fixed subject, the link in the
  //    text part, and a branded html part with the link as a button and no vendor sign-off.
  {
    const rec = recordingEmail();
    const env = { EMAIL: rec.binding, BOOTSTRAP_OWNER_EMAIL: "owner@acme.example", CONSOLE_ORIGIN: "https://console.acme.example", EMAIL_FROM: "no-reply@acme.example" } as unknown as Env;
    const resp = await sendBootstrapLink(env, mintingScheduler("tok-abc"), post());
    const body = (await resp.json()) as { ok?: boolean };
    ok("bootstrap: answers the generic 200", resp.status === 200 && body.ok === true);
    ok("bootstrap: sends exactly one message", rec.sent.length === 1);
    const m = rec.sent[0]!;
    ok("bootstrap: to the pinned owner, from the configured sender", m.to === "owner@acme.example" && m.from === "no-reply@acme.example");
    ok("bootstrap: uses the fixed subject", m.subject === BOOTSTRAP_SUBJECT);
    ok("bootstrap: text carries the set-up link", typeof m.text === "string" && (m.text as string).includes("https://console.acme.example/#/register?invite=tok-abc"));
    const html = (m.html ?? "") as string;
    ok("bootstrap: html is the branded card", typeof m.html === "string" && html.includes("<!doctype html>") && html.includes(">downpipes</div>"));
    ok("bootstrap: html shows the link as a button", html.includes('dp-btn" bgcolor') && html.includes("register?invite=tok-abc"));
    ok("bootstrap: html carries NO vendor sign-off (engine mail)", !/Maelstrom/.test(html));
  }
  // 2. No-oracle: an unconfigured owner address still answers the generic 200, and sends nothing.
  {
    const rec = recordingEmail();
    const env = { EMAIL: rec.binding, CONSOLE_ORIGIN: "https://console.acme.example", EMAIL_FROM: "no-reply@acme.example" } as unknown as Env;
    const resp = await sendBootstrapLink(env, mintingScheduler("tok-abc"), post());
    ok("bootstrap: unconfigured owner still answers 200", resp.status === 200);
    ok("bootstrap: unconfigured owner sends nothing", rec.sent.length === 0);
  }
  // 3. No-oracle: the mint returns null (an Owner already exists), so the path is closed: generic 200,
  //    and nothing is sent.
  {
    const rec = recordingEmail();
    const env = { EMAIL: rec.binding, BOOTSTRAP_OWNER_EMAIL: "owner@acme.example", CONSOLE_ORIGIN: "https://console.acme.example", EMAIL_FROM: "no-reply@acme.example" } as unknown as Env;
    const resp = await sendBootstrapLink(env, mintingScheduler(null), post());
    ok("bootstrap: closed path (mint null) answers 200", resp.status === 200);
    ok("bootstrap: closed path sends nothing", rec.sent.length === 0);
  }

  console.log(failures === 0 ? "\nBOOTSTRAP-EMAIL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
