// Real-world-IdP interop + anti-regression corpus for the native SAML SP (IDP-1/2/4).
// It drives the SAME production pipeline the other SAML validators do (verifySamlResponse, verifyXmlSignature)
// with REAL key material and synthetic, in-repo signed fixtures, proving:
//
//   IDP-1 (Response-level / envelope signature): Okta / Entra / OneLogin sign the samlp:Response ELEMENT, not
//     the inner Assertion. A Response-signed message (unsigned assertion) MUST now verify - AND, the critical
//     anti-XSW binding, the consumed assertion MUST be the single direct child covered by the verified Response
//     signature, never an attacker-chosen one. The negative vectors prove the Response-level path opened NO
//     wrapping bypass: a Response-signed message with a second/forged/duplicate-ID assertion, or whose verified
//     content is not the consumed assertion, MUST reject.
//
//   IDP-2 (ec:InclusiveNamespaces PrefixList + inherited namespaces): an ADFS/Shibboleth-style assertion that
//     declares xsi:/xs: on the Assertion, uses xsi:type="xs:string" inside an AttributeValue, and signs with an
//     exc-c14n# Transform carrying <ec:InclusiveNamespaces PrefixList="xs"/> MUST now verify. The negative twin:
//     the SAME assertion signed WITHOUT the PrefixList (so the digest was computed over the inclusive form but
//     the document omits the list) MUST reject (a forged/mismatched list cannot be smuggled).
//
//   IDP-4 (signing-cert validity window): a signature made under a cert whose validity window has ENDED (or has
//     not yet BEGUN) MUST reject even though the signature itself is cryptographically valid; a window that
//     comfortably contains nowMs MUST verify; and the clock-skew tolerance is exercised at the boundary.
//
// Every fixture is built by SIGNING a real baseline and (for the red vectors) MUTATING it, so each reject is a
// reject of an otherwise-cryptographically-valid document. The signing machinery mirrors validate-saml-xsw.ts
// / validate-saml-response.ts EXACTLY (envelopedCopy + c14n digest + SignedInfo sign + a real self-signed
// cert), so the GREEN controls are honest (a c14n/signing bug breaks a control, never hides a red).
//
// STRUCTURE: the shared harness + tree builders + the enveloped signer + the cert builder + the fixed reference
// constants live in saml-interop-fixtures.ts; the suite is split into three group modules (idp1 / idp2 / idp4)
// that each export run(h, keys). This file is the THIN ORCHESTRATOR: it generates the key material once, builds
// the shared harness and calls each group in the original order, so running this one file still executes the
// full suite.
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins beyond the harness exit code.

import { makeHarness, buildCertPem, type Keys } from "./saml-interop-fixtures.ts";
import { run as runIdp1 } from "./validate-saml-interop-idp1.ts";
import { run as runIdp2 } from "./validate-saml-interop-idp2.ts";
import { run as runIdp4 } from "./validate-saml-interop-idp4.ts";

declare const process: { exit(code?: number): never; exitCode?: number };

async function main(): Promise<void> {
  console.log("SAML real-world IdP interop + anti-regression corpus\n");

  // ---- keys + a self-signed cert wrapping the LEGIT key, valid window comfortably containing NOW ----
  const rsa = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  // Valid.. (NOW = is inside).
  const certPem = await buildCertPem(rsaSpki, rsa.privateKey, "idp.example.com", "20260101000000Z", "20360101000000Z");

  // A second, unrelated key (attacker / non-pinned).
  const rsaAtk = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const keys: Keys = { rsa, rsaSpki, certPem, rsaAtk };

  // ---- the shared harness (counters owned here; each group calls h.ok) ----
  const state = { passed: 0, fails: [] as string[] };
  const h = makeHarness(state);

  // ---- run each group in the original order ----
  await runIdp1(h, keys);
  await runIdp2(h, keys);
  await runIdp4(h, keys);

  // ---- summary ----
  console.log("");
  if (state.fails.length > 0) process.exitCode = 1;
  if (state.fails.length > 0) {
    console.log("SAML REAL-WORLD CORPUS: " + state.passed + " passed, " + state.fails.length + " FAILED");
    for (const f of state.fails) console.log("   FAILED: " + f);
    process.exit(1);
  }
  console.log("SAML REAL-WORLD CORPUS PASS (" + state.passed + " checks)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
