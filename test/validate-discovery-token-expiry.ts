// validate-discovery-token-expiry: the read-only discovery token is a STANDING backend credential, so it is
// term-limited (ASVS V13.2.1). Through the real router: a token whose verify record carries no expiry is
// refused 400 naming the expiry and nothing reaches the scheduler; one that expires 30 days out is accepted,
// stored, and registered in the credential lifecycle registry with its public id and expiry; one 400 days
// out is refused. The accepted case is the control that proves the refusals are the term limit and not the
// harness. The token VALUE never appears in the registry row.
import { verdictReached } from "./lib/verdict-guard.ts";
import { buildContext, OWNER } from "./validate-config-change-control-harness.ts";

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"; // shape-valid, never a real credential

// installCfStub answers the two Cloudflare calls the route makes (list accounts; verify the token) and
// delegates everything else (the harness's own JWKS stub) to the fetch it replaced.
function installCfStub(expiresOn: string | null): { calls: string[]; restore: () => void } {
  const prior = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith("https://api.cloudflare.com/client/v4/accounts?")) {
      calls.push("accounts");
      return new Response(JSON.stringify({ success: true, result: [{ id: "acct-1", name: "Acme" }] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (url.endsWith("/tokens/verify")) {
      calls.push(url.includes("/user/") ? "verify-user" : "verify-account");
      return new Response(JSON.stringify({ success: true, result: { id: "tok-public-id", status: "active", ...(expiresOn !== null ? { expires_on: expiresOn } : {}) } }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return prior(input, init);
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = prior; } };
}

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { ok, call } = ctx;
  try {
    const iso = (daysOut: number): string => new Date(Date.now() + daysOut * 24 * 60 * 60 * 1000).toISOString();
    const post = async (body: unknown): Promise<{ status: number; body: Record<string, unknown> }> => {
      const r = await call(OWNER, "POST", "/admin/sources/discovery-token", body);
      let parsed: Record<string, unknown> = {};
      try { parsed = (await r.json()) as Record<string, unknown>; } catch { /* non-JSON */ }
      return { status: r.status, body: parsed };
    };
    const status = async (): Promise<{ present?: boolean }> => (await (await call(OWNER, "GET", "/admin/sources/discovery-status")).json()) as { present?: boolean };
    const expiryRows = async (): Promise<Array<{ id: string; expiresAt?: string; tokenRef?: string; label?: string }>> => {
      const r = await call(OWNER, "GET", "/admin/expiry");
      const body = (await r.json()) as Array<{ id: string; expiresAt?: string; tokenRef?: string; label?: string }>;
      return Array.isArray(body) ? body : [];
    };

    console.log("\n(a) a token with NO expiry is refused, named, and never reaches the scheduler");
    {
      const stub = installCfStub(null);
      let res: { status: number; body: Record<string, unknown> };
      try { res = await post({ token: TOKEN }); } finally { stub.restore(); }
      ok("(a) 400", res.status === 400);
      ok("(a) the refusal names the expiry and the 90-day limit", /expiry/i.test(String(res.body.error ?? "")) && String(res.body.error ?? "").includes("90"));
      ok("(a) the verify was asked", stub.calls.includes("verify-user") || stub.calls.includes("verify-account"));
      ok("(a) nothing was stored", (await status()).present !== true);
    }
    console.log("\n(b) CONTROL: a token expiring 30 days out is accepted, stored and registered with its id and expiry");
    {
      const when = iso(30);
      const stub = installCfStub(when);
      let res: { status: number; body: Record<string, unknown> };
      try { res = await post({ token: TOKEN }); } finally { stub.restore(); }
      ok("(b) 200", res.status === 200);
      ok("(b) the discovery config is present", (await status()).present === true);
      const rows = await expiryRows();
      const row = rows.find((r) => r.id === "discovery-token");
      ok("(b) the registry carries id discovery-token with the accepted expiry", row !== undefined && row.expiresAt === when);
      ok("(b) the row references the public token id, never the value", row?.tokenRef === "tok-public-id" && !JSON.stringify(rows).includes(TOKEN));
    }
    console.log("\n(c) a token expiring 400 days out is refused");
    {
      const stub = installCfStub(iso(400));
      let res: { status: number; body: Record<string, unknown> };
      try { res = await post({ token: TOKEN }); } finally { stub.restore(); }
      ok("(c) 400 naming the limit", res.status === 400 && String(res.body.error ?? "").includes("90"));
    }
    console.log("\n(d) clearing the token removes its registry row");
    {
      const res = await post({ token: null });
      ok("(d) clear is 200", res.status === 200);
      ok("(d) the discovery-token row is gone", !(await expiryRows()).some((r) => r.id === "discovery-token"));
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  const failures = ctx.getFailures();
  console.log(failures === 0 ? "\nDISCOVERY TOKEN EXPIRY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
