// validate-passkey-enrol-alert: a passkey SELF-ADD fires the auth-credential-change alert (ASVS V6.3.7).
//
// WHY THIS FILE EXISTS. Revoking a passkey fired auth-credential-change; enrolling a NEW one on an already
// enrolled account, which changes that account's sign-in details just as much, fired nothing. An attacker
// who has one session could quietly add their own credential and the owner would never hear. The alert is
// gated on the DO's proven enrolmentPath, so a bootstrap or an invite redemption (onboarding, not a change)
// stays silent, and on the DO's own body, never the client's.
//
// The oracle is the one the existing suite uses for "the alert was routed": the alert resolves zero channels
// and so bumps alert-emit-credential-change-no-channel, read out of the counters the real recorder writes to.
// Every silence below is paired with the positive case above it, so a missing bump is a decision and not a
// probe that never reached the route.

import { handlePasskey } from "../src/admin/router-auth-flow.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function makeScheduler(finish: unknown, opts?: { rawFinish?: string }) {
  const bumps: string[] = []; const paths: string[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input)); paths.push(url.pathname);
      const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
      if (url.pathname.endsWith("/passkey/register/finish")) return opts?.rawFinish !== undefined ? new Response(opts.rawFinish, { headers: { "content-type": "application/json" } }) : json(finish);
      if (url.pathname.endsWith("/passkey/session/issue")) return json({ ok: true, token: "tok.mac" });
      if (url.pathname === "/rate-check") return json({ allowed: true }); // the auth limiter fails CLOSED on a malformed verdict, so answer it properly
      if (url.pathname === "/notify/resolve") return json({ now: [] });
      if (url.pathname === "/diag/admin-counters" || url.pathname === "/admin-counters") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { bumps?: Record<string, number> };
        for (const n of Object.keys(body.bumps ?? {})) bumps.push(n);
        return json({});
      }
      return json({});
    },
  };
  return { stub, bumps, paths };
}

async function drive(finish: unknown, opts?: { rawFinish?: string }) {
  const { stub, bumps, paths } = makeScheduler(finish, opts);
  const env = { CONSOLE_ORIGIN: "https://console.example", SCHEDULER: { idFromName: () => "id", get: () => stub } } as unknown as Env; // CONSOLE_ORIGIN: without it every ceremony 501s before the DO is reached
  const req = new Request("https://engine.example/admin/auth/register/finish", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.9" }, body: JSON.stringify({ email: "a@b.test", credential: {} }) });
  const resp = await handlePasskey(req, env, "register/finish", undefined);
  await new Promise((r) => setTimeout(r, 10)); // the bumps are void-ed, best-effort writes
  return { resp, body: await resp.text(), bumps, paths };
}

const BASE = { ok: true, email: "a@b.test", bootstrapped: false, role: "viewer", recoveryCodes: [], recoveryCodesPending: true };

async function main(): Promise<void> {
  console.log("\npositive: a self-add fires the credential-change alert");
  const selfAdd = await drive({ ...BASE, enrolmentPath: "self-add" });
  ok("the self-add enrolment routed auth-credential-change (credential-change bumped no-channel)", selfAdd.bumps.includes("alert-emit-credential-change-no-channel"));
  if (!selfAdd.bumps.includes("alert-emit-credential-change-no-channel")) console.log("   paths hit:", [...new Set(selfAdd.paths)].join(", "), "| bumps:", selfAdd.bumps.join(", "));
  ok("the client response is the DO's finish body, byte for byte (the alert changed nothing the client sees)", JSON.parse(selfAdd.body).ok === true && JSON.parse(selfAdd.body).enrolmentPath === "self-add");

  console.log("\nnegative controls: onboarding and failure paths stay silent");
  for (const [label, finish, raw] of [
    ["an invite redemption", { ...BASE, enrolmentPath: "invite" }, undefined],
    ["the bootstrap (first Owner)", { ...BASE, bootstrapped: true, role: "owner", enrolmentPath: "bootstrap" }, undefined],
    ["a failed finish (ok:false)", { ok: false, reason: "assertion-invalid", errorId: "e1" }, undefined],
    ["a non-JSON body from the DO", undefined, "not json at all"],
  ] as [string, unknown, string | undefined][]) {
    const r = await drive(finish, raw !== undefined ? { rawFinish: raw } : undefined);
    ok(`${label}: NO credential-change alert`, !r.bumps.includes("alert-emit-credential-change-no-channel"));
  }

  console.log(failures === 0 ? "\nPASSKEY ENROL ALERT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
