// Emit a REAL signed + sealed support bundle from a given body JSON — for off-platform diagnosis testing
// with real cryptography. It uses the engine's ACTUAL crypto (hybrid Ed25519+ML-DSA-87 signature over the
// canonical body, then X25519+ML-KEM-1024 capsule + AES-256-GCM seal to a fresh vendor support key), the
// exact construction sealedSupportBundle uses. The point is to feed the diagnosis poller a bundle that is
// byte-for-byte the real thing (real PQ signature, real seal), not a hand-faked shape.
//
// Usage: node tools/emit-real-support-bundle.ts --body <body.json> --out <dir>
//   writes <dir>/bundle.json (sealed), <dir>/vendor-identity.b64, <dir>/signer-public.b64
//   and prints the signer fingerprint (the Gate-2 join key the poller registers).

import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadSigner, loadRecipientPublic } from "../src/keys-env.ts";
import { buildBandManifest } from "../src/admin/support-band-manifest.ts";
import { makeSupportRecipient } from "./generate-support-keypair.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { signerFingerprint } from "../src/format/writer.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { sealToRecipients, recipientFingerprint } from "../src/crypto/capsule.ts";
import { hkdfSha384, aesGcmSeal } from "../src/crypto/primitives.ts";
import { b64urlEncode, utf8, concat } from "../src/crypto/bytes.ts";

const INFO_SUPPORT_BUNDLE_KEY = "downpipe/engine support-bundle-key v1";
const AAD = "downpipe/engine support-bundle v1";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const bodyPath = arg("--body");
  const out = arg("--out");
  if (bodyPath === undefined || out === undefined) {
    console.error("usage: node tools/emit-real-support-bundle.ts --body <body.json> --out <dir>");
    process.exit(2);
    return;
  }
  const body = JSON.parse(readFileSync(bodyPath, "utf8")) as Record<string, unknown>;
  // Mirror sealedSupportBundle: the envelope `v` is the CONTENT-schema version and must TRACK the body
  // (hardcoding 1 wrapped v:2 bodies in a v:1 envelope -- a contract inconsistency the opener/bot would
  // never see from a real engine). The sealing-FORMAT version stays in the AAD/INFO strings ("...v1").
  const bundleV = (typeof body["v"] === "number" ? body["v"] : 2) as 1 | 2;

  // A real engine signer (64 random bytes -> hybrid signer), the same path the round-trip test uses.
  const signerB64 = b64urlEncode(concat(crypto.getRandomValues(new Uint8Array(32)), crypto.getRandomValues(new Uint8Array(32))));
  const signer = await loadSigner(signerB64);
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, canonicalJSON(body));
  const fp = await signerFingerprint({ ed: signer.edPublic, mldsa: signer.mldsaPublic });
  const signed = { kind: "downpipe-support-bundle-signed", v: bundleV, bundle: body, signature: b64urlEncode(sig), signerFingerprint: fp };

  // A real vendor support recipient + the real seal.
  const vendor = await makeSupportRecipient();
  const vendorPub = loadRecipientPublic(b64urlEncode(vendor.recipientPublic));
  const k = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = canonicalJSON(signed);
  const wraps = await sealToRecipients(k, [vendorPub], utf8(AAD), () => crypto.getRandomValues(new Uint8Array(16)));
  const dek = await hkdfSha384(k, new Uint8Array(0), utf8(INFO_SUPPORT_BUNDLE_KEY), 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await aesGcmSeal(dek, iv, plaintext, utf8(AAD));
  k.fill(0);
  // The clear-signed band manifest comes from the ENGINE's own helper, so this hand-rolled envelope can
  // never drift from what sealedSupportBundle emits (sealed path: bodySha256 over the raw ciphertext
  // bytes). buildBandManifest zeroes the signer's ML-DSA secret, so it runs AFTER the body signature.
  const band = await buildBandManifest(signed, signer, ct);
  const sealed = {
    kind: "downpipe-support-bundle-sealed",
    v: bundleV,
    generatedAt: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    recipientFingerprint: await recipientFingerprint(vendorPub.x25519, vendorPub.mlkemEk),
    capsule: wraps.map((w) => ({ fingerprint: w.fingerprint, kemCiphertext: b64urlEncode(w.kemCiphertext), sealed: b64urlEncode(w.sealed) })),
    iv: b64urlEncode(iv),
    ciphertext: b64urlEncode(ct),
    openWith: "downpipe vendor support identity (X25519+ML-KEM-1024)",
    ...band,
  };

  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "bundle.json"), JSON.stringify(sealed));
  writeFileSync(join(out, "vendor-identity.b64"), b64urlEncode(vendor.identity));
  writeFileSync(join(out, "signer-public.b64"), b64urlEncode(concat(signer.edPublic, signer.mldsaPublic)));
  console.log(`wrote a REAL sealed bundle to ${out}`);
  console.log(`signerFingerprint ${fp}`);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
