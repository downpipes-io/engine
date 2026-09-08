// Adversarial validator for the enveloped XML-DSig verifier (src/admin/saml/dsig.ts). It runs a REAL
// happy-path round trip - generate an RSA-2048 (and an ECDSA P-256) key, build a SAML-Assertion-shaped tree
// with an ID, compute the Reference digest as SHA-256 of exc-c14n#(enveloped(assertion)), build SignedInfo,
// canonicalise and SIGN it with the private key, embed the Signature, then verifyXmlSignature with the
// PUBLIC key and assert ok - then a RED corpus where each crafted document MUST reject:
//   two ds:Signature elements; SignedInfo with two References; a duplicate ID (two elements same ID);
//   SignatureMethod rsa-sha1; an unknown/extra Transform; an UNSIGNED assertion (no Signature); a tampered
//   assertion (digest mismatch); a KeyInfo carrying a DIFFERENT cert than the pinned key (must be IGNORED ->
//   verify against the pinned key fails); a void/empty-canon attempt; plus: a non-fragment Reference URI, a
//   sha1 DigestMethod, an EC signature verified against the wrong pinned key, and the SignedInfo signature
//   verifying only when BOTH digest and signature are intact.
//
// The verifier under test is the production path. Because the test computes the digest and signs using the
// SAME c14n module the verifier uses, the round trip is HONEST (a c14n bug would break the happy path, not
// hide). Run: node test/validate-saml-dsig.ts
//
// The vectors are split across sibling modules (the single main() exceeded a line-count limit). The
// shared harness, builders and the signing helper live in
// ./validate-saml-dsig-shared.ts; the happy-path group in ./validate-saml-dsig-happy.ts; the red corpus in
// ./validate-saml-dsig-red.ts. This orchestrator generates the keys once and calls each group in order, so a
// single `node test/validate-saml-dsig.ts` still runs the full suite with the same assertions in the same
// order.
//
// Node 25 strip-types; Web Crypto only (global crypto.subtle), no Node builtins beyond the harness exit code.

import { newHarness, generateVectorKeys } from "./validate-saml-dsig-shared.ts";
import { runHappyPath } from "./validate-saml-dsig-happy.ts";
import { runRedCorpus } from "./validate-saml-dsig-red.ts";

// This validator runs under Node (strip-types); the project tsconfig ships Workers types only (no
// @types/node). Declare the single Node global we use (process.exit) so the file is tsc-clean under those
// flags. console is provided by the WebWorker lib already.
declare const process: { exit(code?: number): never; exitCode?: number };

async function main(): Promise<void> {
  console.log("XML-DSig enveloped verifier vectors\n");

  const h = newHarness();
  const keys = await generateVectorKeys();

  // Happy path: a well-formed signature verifies.
  await runHappyPath(h, keys);

  // Red corpus: every tampered or malformed signature is rejected.
  await runRedCorpus(h, keys);

  // Summary.
  console.log("");
  if (h.fails.length > 0) process.exitCode = 1;
  if (h.fails.length > 0) {
    console.log("SAML DSig VECTORS: " + h.passed + " passed, " + h.fails.length + " FAILED");
    for (const f of h.fails) console.log("   FAILED: " + f);
    process.exit(1);
  }
  console.log("SAML DSig VECTORS PASS (" + h.passed + " checks)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
