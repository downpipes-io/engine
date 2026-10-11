// validate-idp-web-prior-token-no-ip: the SAML ACS forward carries priorToken whenever a session cookie is
// present, whether or not CF-Connecting-IP arrived.
//
// CF-Connecting-IP is an edge property and is absent in some proxied or test deployments. The revocation
// of a caller's prior session on re-authentication must not depend on it. If priorToken were dropped, the
// DO would never revoke the old session and it would stay live after a fresh SAML sign-in.
// The companion file validate-idp-web-prior-token.ts covers the case where the header is present.
//
// THIS FILE PROVES, against the real handleSaml edge function with a stubbed scheduler DO, that the
// forward carries priorToken and no sourceIp when the header is absent.
//
// Run: node test/validate-idp-web-prior-token-no-ip.ts

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
  console.log("-- without CF-Connecting-IP, priorToken is still forwarded so the prior session is");
  console.log("-- revoked --");
  const withoutIp = await forwardedBody(false);
  ok(`CONTROL: CF-Connecting-IP is genuinely absent from this forward (got ${JSON.stringify(withoutIp)})`, withoutIp.sourceIp === undefined);
  ok(
    `priorToken is forwarded even without CF-Connecting-IP (got ${JSON.stringify(withoutIp)})`,
    withoutIp.priorToken === PRIOR_TOKEN,
  );

  console.log(failures === 0 ? "\nVERDICT: PASS failures=0\n" : `\nVERDICT: FAIL failures=${failures}\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
