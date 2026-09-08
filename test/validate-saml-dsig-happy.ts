// Happy-path vectors for the SAML XML-DSig verifier: a REAL RSA-2048 + SHA-256 enveloped round trip (raw SPKI,
// pre-imported CryptoKey, and requireReferenceIsTarget) plus an ECDSA P-256 round trip and the wrong-family
// rejection. Extracted from test/validate-saml-dsig.ts. Same assertions, same order.

import {
  type Harness,
  type VectorKeys,
  buildAssertion,
  expectOk,
  expectFail,
  signAssertion,
  SIG_RSA_SHA256,
  SIG_ECDSA_SHA256,
} from "./validate-saml-dsig-shared.ts";
import { ab } from "../src/crypto/bytes.ts";

export async function runHappyPath(h: Harness, k: VectorKeys): Promise<void> {
  console.log("happy path:\n");
  {
    const signed = await signAssertion(buildAssertion(k.ID), k.ID, k.rsa.privateKey, "RSA", "SHA-256", SIG_RSA_SHA256);
    await expectOk(h, signed, k.rsaSpki, undefined, "RSA-2048 + SHA-256 enveloped signature verifies (raw SPKI)");
    // The same, passing an already-imported CryptoKey instead of raw SPKI.
    const importedPub = await crypto.subtle.importKey("spki", ab(k.rsaSpki), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    await expectOk(h, signed, importedPub, undefined, "same signature verifies when the pinned key is a pre-imported CryptoKey");
    // requireReferenceIsTarget: the Reference covers the assertion we handed in.
    await expectOk(h, signed, k.rsaSpki, { requireReferenceIsTarget: true }, "requireReferenceIsTarget passes when the Reference covers the target");
  }
  {
    const signed = await signAssertion(buildAssertion(k.ID), k.ID, k.ec.privateKey, "EC", "SHA-256", SIG_ECDSA_SHA256);
    await expectOk(h, signed, k.ecSpki, undefined, "ECDSA P-256 + SHA-256 enveloped signature verifies");
    // wrong curve/key family pinned -> fails (EC signature, RSA pinned key import path mismatch).
    await expectFail(h, signed, k.rsaSpki, undefined, "ECDSA signature does NOT verify against an RSA pinned key");
  }
}
