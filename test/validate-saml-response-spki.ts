// SPKI extraction (unit) group of the SAML ACS response verifier suite. Split out of validate-saml-response.ts;
// the orchestrator imports run() and calls it with the shared harness + keys. See saml-response-fixtures.ts.

import { pemToSpki } from "../src/admin/saml/response.ts";
import { ab, constantTimeEqual } from "../src/crypto/bytes.ts";
import { type Harness, type Keys, b64std } from "./saml-response-fixtures.ts";

export async function run(h: Harness, keys: Keys): Promise<void> {
  const { rsaSpki, certPem, rsaOtherSpki, certOtherPem } = keys;

  // ========================= SPKI EXTRACTION (unit) =========================
  console.log("pemToSpki DER walk:\n");
  {
    const r = pemToSpki(certPem);
    h.ok("pemToSpki extracts a SubjectPublicKeyInfo from a real self-signed cert", r.ok === true);
    if (r.ok) {
      h.ok("  -> extracted SPKI byte-equals the directly exported SPKI", constantTimeEqual(r.spki, rsaSpki));
      // The imported key actually works (Web Crypto accepts the extracted SPKI as an RSA verify key).
      let importOk = false;
      try {
        await crypto.subtle.importKey("spki", ab(r.spki), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
        importOk = true;
      } catch {
        importOk = false;
      }
      h.ok("  -> the extracted SPKI imports as a usable Web Crypto verify key", importOk);
    }
    // The second cert extracts a DIFFERENT SPKI (and equals its own export).
    const r2 = pemToSpki(certOtherPem);
    h.ok("pemToSpki on the second cert yields its own (different) SPKI", r2.ok === true && r2.ok && constantTimeEqual(r2.spki, rsaOtherSpki) && !constantTimeEqual(r2.spki, rsaSpki));
    // Malformed PEM inputs fail closed.
    h.ok("pemToSpki rejects a non-PEM string", pemToSpki("not a cert").ok === false);
    h.ok("pemToSpki rejects PEM armour wrapping non-base64", pemToSpki("-----BEGIN CERTIFICATE-----\n!!!notb64!!!\n-----END CERTIFICATE-----").ok === false);
    h.ok("pemToSpki rejects PEM armour wrapping non-DER bytes", pemToSpki("-----BEGIN CERTIFICATE-----\n" + b64std(new Uint8Array([1, 2, 3, 4])) + "\n-----END CERTIFICATE-----").ok === false);
  }
}
