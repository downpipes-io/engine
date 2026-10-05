// Generate the VENDOR SUPPORT keypair, once, on the vendor's own machine.
//
// This is the key that makes confidential support bundles usable. It is a hybrid
// recipient keypair, the same X25519 + ML-KEM-1024 layout as a backup recipient key,
// in two halves:
//
//   PUBLIC  (x25519 pub(32) || ML-KEM-1024 ek(1568) = 1600 bytes)
//     The vendor gives this to customers. A customer sets it as VENDOR_SUPPORT_PUBLIC
//     on THEIR engine. From then on their support bundle is sealed to it, so only the
//     vendor can read the diagnostics. Setting it grants no access to anything in the
//     customer's account: it is only a wrapping key.
//
//   PRIVATE / IDENTITY  (x25519 scalar(32) || ML-KEM seed(64) = 96 bytes)
//     The vendor keeps this. It is the ONLY thing that can open a sealed support
//     bundle. It never leaves the vendor's machine, is never deployed to a server, and
//     is never synced to cloud storage. Keep it on an encrypted disk (FileVault) or in
//     a password manager. If it is lost, sealed bundles already in flight cannot be
//     opened (customers simply re-send, or fall back to the signed-plain path).
//
// The bytes are identical to scripts/generate-keys.ts makeRecipient and the console
// ceremony, so nothing about the format is special to support.
//
// Usage:
//   node tools/generate-support-keypair.ts                 # print both halves to stdout
//   node tools/generate-support-keypair.ts --out <dir>     # also write key files into <dir>

import { mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { webcrypto } from "node:crypto";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { recipientFingerprint } from "../src/crypto/capsule.ts";
import { isEntryPoint } from "../test/lib/verdict-guard.ts";

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  webcrypto.getRandomValues(out);
  return out;
}

// makeSupportRecipient generates one hybrid recipient: x25519 scalar(32) || ML-KEM-1024
// seed(64) private; x25519 pub(32) || ML-KEM ek(1568) public. Byte-identical to
// scripts/generate-keys.ts makeRecipient, so the engine seals to the public and the
// opener reads the private with no special casing.
async function makeSupportRecipient(): Promise<{ identity: Uint8Array; recipientPublic: Uint8Array; fingerprint: string }> {
  const xk = x25519.keygen();
  const mlkemSeed = randomBytes(64);
  const ek = ml_kem1024.keygen(mlkemSeed).publicKey;
  const identity = concat(xk.secretKey, mlkemSeed);
  const recipientPublic = concat(xk.publicKey, ek);
  // Match the recipient fingerprint the engine stamps on a sealed bundle so the vendor
  // can confirm at a glance that a bundle was sealed to this exact key.
  const fingerprint = await recipientFingerprint(xk.publicKey, ek);
  return { identity, recipientPublic, fingerprint };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2).filter((a) => a !== "");
  const outIdx = args.indexOf("--out");
  const outDir = outIdx >= 0 ? args[outIdx + 1] : undefined;
  if (outIdx >= 0 && (outDir === undefined || outDir.startsWith("--"))) {
    console.error("usage: node tools/generate-support-keypair.ts [--out <directory>]");
    process.exit(2);
  }

  const kp = await makeSupportRecipient();
  const publicB64 = b64urlEncode(kp.recipientPublic);
  const identityB64 = b64urlEncode(kp.identity);
  const generatedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  // Always print both halves, clearly labelled, so the values are usable even without a
  // file. The PRIVATE half is last so it is the most recent thing on screen, and the
  // warning sits right beside it.
  console.log("DOWNPIPES VENDOR SUPPORT KEYPAIR");
  console.log(`Generated ${generatedAt} on this machine.`);
  console.log(`Fingerprint: ${kp.fingerprint}`);
  console.log("");
  console.log("PUBLIC KEY  (give this to customers; they set it as VENDOR_SUPPORT_PUBLIC):");
  console.log(publicB64);
  console.log("");
  console.log("PRIVATE IDENTITY  (the vendor keeps this; it opens sealed bundles):");
  console.log(identityB64);
  console.log("");
  console.log("KEEP THE PRIVATE IDENTITY OFFLINE. It never leaves this machine, is never");
  console.log("deployed to a server, and is never synced to cloud storage. Store it on an");
  console.log("encrypted disk (FileVault) or in a password manager. Anyone who holds it can");
  console.log("open every support bundle sealed to the public half.");

  if (outDir !== undefined) {
    mkdirSync(outDir, { recursive: true });
    // The labelled key-file lines match the Go offline tool / generate-keys.ts format, so
    // the opener reads support-identity.key directly with --identity.
    writeFileSync(join(outDir, "support-identity.key"), `downpipe-identity-v1 ${identityB64}\n`, { mode: 0o600 });
    writeFileSync(join(outDir, "support-public.b64"), `${publicB64}\n`);
    writeFileSync(
      join(outDir, "support-keypair-readme.txt"),
      [
        "DOWNPIPES VENDOR SUPPORT KEYPAIR",
        `Generated ${generatedAt}.`,
        `Fingerprint: ${kp.fingerprint}`,
        "",
        "support-public.b64     PUBLIC. Give to customers; they set VENDOR_SUPPORT_PUBLIC.",
        "support-identity.key   PRIVATE. Keep offline. Opens sealed support bundles.",
        "",
        "The private identity never leaves this machine, is never deployed, and is never",
        "synced to cloud storage. Move support-identity.key to an encrypted disk or a",
        "password manager. Open a bundle with:",
        "  node tools/open-support-bundle.ts --identity support-identity.key bundle.json",
        "",
      ].join("\n"),
    );
    chmodSync(outDir, 0o700);
    console.log("");
    console.log(`wrote key files to ${outDir}`);
    console.log("  support-public.b64     PUBLIC  (give to customers)");
    console.log("  support-identity.key   PRIVATE (keep offline)");
  }
}

// Exported so a test can construct a real vendor support keypair through the same path
// the CLI uses, rather than re-deriving the layout by hand. The export is declared
// before the CLI runs so an importing test never triggers main().
export { makeSupportRecipient };

// Run the CLI only when invoked directly, not when imported by the round-trip test.
if (isEntryPoint(import.meta.url)) {
  void main();
}
