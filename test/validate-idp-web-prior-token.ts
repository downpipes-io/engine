// validate-idp-web-prior-token: with CF-Connecting-IP and a session cookie present, the SAML ACS forward
// carries both sourceIp and priorToken to the scheduler DO.
//
// priorToken is the caller's existing session. The DO revokes it once the new session is minted.
// The forward is built in src/admin/router-idp-web.ts. The companion file
// validate-idp-web-prior-token-no-ip.ts covers the case where the header is absent.
//
// THIS FILE PROVES, against the real handleSaml edge function with a stubbed scheduler DO recording the
// forwarded ACS body, that both fields reach the DO.
//
// Run: node test/validate-idp-web-prior-token.ts

import { verdictReached } from "./lib/verdict-guard.ts";
import { forwardedBody, PRIOR_TOKEN } from "./lib/idp-web-prior-token-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

async function main(): Promise<void> {
  console.log("-- CF-Connecting-IP present, a session cookie present --");
  const withIp = await forwardedBody(true);
  ok(`the forward carries CF-Connecting-IP (got ${JSON.stringify(withIp)})`, withIp.sourceIp === "192.0.2.44");
  ok(`the forward carries priorToken, the session the DO must revoke once the new one is minted (got ${JSON.stringify(withIp)})`, withIp.priorToken === PRIOR_TOKEN);

  console.log(failures === 0 ? "\nVERDICT: PASS failures=0\n" : `\nVERDICT: FAIL failures=${failures}\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
