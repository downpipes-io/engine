// Shared harness for validate-idp-web-prior-token.ts and validate-idp-web-prior-token-no-ip.ts:
// a stubbed scheduler DO that answers handleSaml's ACS forward and records the body it was given, the same
// shape test/validate-idp-wiring.ts uses for handleSaml/handleOidc.

import { handleSaml, SAML_TXN_COOKIE } from "../../src/admin/router-idp-web.ts";
import { SESSION_COOKIE_NAME } from "../../src/admin/session.ts";
import type { Env } from "../../src/env.d.ts";

export const CONSOLE_ORIGIN = "https://downpipe-console.example";
export const PRIOR_TOKEN = "prior.v3.session.token";

function fakeEnv(handler: (req: Request) => Promise<Response>): Env {
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = new Request(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url, init);
      if (req.url === "https://scheduler.internal/rate-check") return Promise.resolve(new Response(JSON.stringify({ allowed: true }), { headers: { "content-type": "application/json" } }));
      return handler(req);
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, CONSOLE_ORIGIN } as unknown as Env;
}
const jsonResp = (o: unknown): Response => new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } });

// acsRequest builds the ACS POST a real IdP form-submit sends, with an existing session cookie present and
// CF-Connecting-IP either present or withheld.
function acsRequest(withSourceIp: boolean): Request {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", cookie: `${SAML_TXN_COOKIE}=bind1; ${SESSION_COOKIE_NAME}=${PRIOR_TOKEN}` };
  if (withSourceIp) headers["CF-Connecting-IP"] = "192.0.2.44";
  return new Request("https://x/admin/saml/acs/work-idp", { method: "POST", headers, body: "SAMLResponse=PHNhbWw%2B&RelayState=rs" });
}

// forwardedBody drives handleSaml's acs branch and returns exactly the JSON body it forwarded to the DO.
export async function forwardedBody(withSourceIp: boolean): Promise<{ priorToken?: string; sourceIp?: string }> {
  let body: { priorToken?: string; sourceIp?: string } = {};
  const env = fakeEnv(async (req) => {
    body = (await req.json()) as typeof body;
    return jsonResp({ ok: true, token: "saml.v3.token", returnTo: "/secure" });
  });
  await handleSaml(acsRequest(withSourceIp), env, "acs/work-idp");
  return body;
}
