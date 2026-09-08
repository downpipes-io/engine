// Prove the engine loads its signer and recipient keys from the env (Secrets Store)
// encoding and that a loaded signer actually signs and verifies. Run with
// `node test/validate-keys-env.ts`.

import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { loadSigner, loadRecipients } from "../src/keys-env.ts";
import { hybridSign, hybridVerify } from "../src/crypto/sign.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  // Build the env encodings the Secrets Store would hold.
  const edSeed = randomBytes(32);
  const mldsaSeed = randomBytes(32);
  const mldsa = ml_dsa87.keygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));

  const xk = x25519.keygen();
  const ek = ml_kem1024.keygen(randomBytes(64)).publicKey;
  const breakGlassB64 = b64urlEncode(concat(xk.publicKey, ek));

  const signer = await loadSigner(signerPrivateB64);
  ok("edPublic matches the seed", b64urlEncode(signer.edPublic) === b64urlEncode(ed25519.getPublicKey(edSeed)));
  ok("mldsaPublic matches the secret", b64urlEncode(signer.mldsaPublic) === b64urlEncode(mldsa.publicKey));

  const msg = new TextEncoder().encode("env-loaded signer attestation");
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, msg);
  ok("loaded signer signs and verifies", await hybridVerify({ ed: signer.edPublic, mldsa: signer.mldsaPublic }, msg, sig));

  const recipients = loadRecipients(breakGlassB64);
  ok("break-glass recipient loaded", recipients.length === 1 && recipients[0]!.role === "break-glass" && recipients[0]!.pub.mlkemEk.length === 1568);

  // The SECOND recipient's role label. It is descriptive rather than behavioural (no open path branches on
  // it), but it is written into the sealed artefact's public recipient list and the offline reader renders
  // it in the one message a person reads mid-disaster: "this run needs one of: break-glass dpr1:X, <role>
  // dpr1:Y" (downpipe/internal/crypto/capsule.go, describeWanted).
  //
  // The second recipient's role must be honoured rather than hardcoded to "operational": the control-plane
  // export hands this helper the CONFIG recipient, and a hardcoded label would send an operator after a key
  // that does not open the archive and that a break-glass-only estate does not have.
  const twoDefault = loadRecipients(breakGlassB64, breakGlassB64);
  ok("the DEFAULT second role stays operational, so archive sealing is byte-identical", twoDefault[1]!.role === "operational");
  const twoConfig = loadRecipients(breakGlassB64, breakGlassB64, "config");
  ok("and an explicit role is honoured, which is what the control-plane export passes", twoConfig[1]!.role === "config");
  ok("the first recipient is break-glass either way", twoDefault[0]!.role === "break-glass" && twoConfig[0]!.role === "break-glass");

  console.log(failures === 0 ? "\nKEYS-ENV VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
