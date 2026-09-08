// Adversarial validator for the SAML ACS response verifier (src/admin/saml/response.ts) - the security-critical
// module that ties the hardened parser -> the XML-DSig verifier -> the assertion consumer in the correct order.
// A mistake there is a SILENT SAML auth bypass, so this validator drives the WHOLE production pipeline end to
// end with REAL key material: it generates an RSA-2048 key, builds a real self-signed X.509 certificate wrapping
// its public key (so the PEM -> SPKI DER walk in response.ts is exercised for real), builds a samlp:Response
// carrying a saml:Assertion, signs the Assertion with a genuine ENVELOPED XML-DSig the way validate-saml-dsig.ts
// builds its happy-path signature (mirroring its envelopedCopy + c14n digest + SignedInfo sign), serialises the
// tree to an XML STRING, base64-encodes it as the POST SAMLResponse field, and calls verifySamlResponse.
//
//   GREEN: a valid signed Response yields the principal (subject == samlSubject(...), email, groups).
//   GREEN: pemToSpki(selfSignedCertPem) byte-equals the directly exported SPKI (the DER walk is honest).
//   RED (each MUST reject): an UNSIGNED assertion; a signature by a NON-pinned key; TWO Assertions (XSW); a
//     Status != Success; a wrong @Destination; a wrong @InResponseTo (and an absent one with
//     allowIdpInitiated=false); an EncryptedAssertion present; a TAMPERED assertion (post-sign mutation); and
//     the classic XSW where a SECOND unsigned Assertion is injected as a sibling of the signed one.
//
// Because the test computes the digest and signs using the SAME c14n module the verifier's dsig path uses, the
// happy path is HONEST (a c14n bug would break the green path, not hide a red one). The XML round-trips through
// the production parser (string -> parseXml), so the test also proves the serialiser/parser agree on the bytes
// the signature covers.
//
// OUT OF SCOPE here (tested SEPARATELY): SAML assertion REPLAY prevention (one-time-use, ASVS V3.5) is an
// ACS/DO-layer concern, not a verifySamlResponse concern. verifySamlResponse is a pure function over a single
// document and cannot remember a previously-consumed assertionId; the DO-level SEEN_ASSERTION_PREFIX cache that
// rejects a second use of the same assertionId within its validity window is exercised end-to-end through the
// real ACS route in validate-saml-wiring.ts (the "assertion-replay" case).
//
// STRUCTURE: the shared fixtures + the enveloped signer + the cert builder live in saml-response-fixtures.ts;
// the suite is split into four group modules (spki / happy / red / structural) that each export run(h, keys).
// This file is the THIN ORCHESTRATOR: it generates the key material once, builds the shared harness and calls
// each group in the original order, so running this one file still executes the full suite.
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins beyond the harness exit code.

import { makeHarness, buildSelfSignedCertPem, type Keys } from "./saml-response-fixtures.ts";
import { run as runSpki } from "./validate-saml-response-spki.ts";
import { run as runHappy } from "./validate-saml-response-happy.ts";
import { run as runRed } from "./validate-saml-response-red.ts";
import { run as runStructural } from "./validate-saml-response-structural.ts";

// This validator runs under Node (strip-types); the project tsconfig ships Workers types only (no @types/node).
// Declare the single Node global we use so the file is tsc-clean under those flags. console is the WebWorker
// global.
declare const process: { exit(code?: number): never; exitCode?: number };

async function main(): Promise<void> {
  console.log("SAML ACS response verifier vectors\n");

  // ---- keys + a real self-signed cert wrapping the legit key ----
  const rsa = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  const certPem = await buildSelfSignedCertPem(rsaSpki, rsa.privateKey, "idp.example.com");

  // A SECOND, unrelated key + its self-signed cert (the attacker / non-pinned key).
  const rsaOther = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rsaOtherSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsaOther.publicKey));
  const certOtherPem = await buildSelfSignedCertPem(rsaOtherSpki, rsaOther.privateKey, "attacker.example.com");

  const keys: Keys = { rsa, rsaSpki, certPem, rsaOther, rsaOtherSpki, certOtherPem };

  // ---- the shared harness (counters owned here; each group calls h.ok) ----
  const state = { passed: 0, fails: [] as string[] };
  const h = makeHarness(state);

  // ---- run each group in the original order ----
  await runSpki(h, keys);
  await runHappy(h, keys);
  await runRed(h, keys);
  await runStructural(h, keys);

  // ---- summary ----
  console.log("");
  if (state.fails.length > 0) process.exitCode = 1;
  if (state.fails.length > 0) {
    console.log("SAML RESPONSE VECTORS: " + state.passed + " passed, " + state.fails.length + " FAILED");
    for (const f of state.fails) console.log("   FAILED: " + f);
    process.exit(1);
  }
  console.log("SAML RESPONSE VECTORS PASS (" + state.passed + " checks)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
