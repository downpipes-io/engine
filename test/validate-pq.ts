// Cross-implementation validator for the post-quantum primitives: prove the pinned
// @noble/post-quantum agrees with the Go reference on ML-KEM-1024 and ML-DSA-87,
// against the Go-produced mlkem-kat and mldsa-kat vectors. This is the load-bearing
// check before the engine is trusted to wrap masters and sign manifests. Run with
// `node test/validate-pq.ts` after `npm install`.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { b64urlDecode, b64urlEncode } from "../src/crypto/bytes.ts";
import { mlkemKeygen, mlkemDecapsulate, mlkemEncapsulate, mldsaVerify, mldsaSign, mldsaKeygen } from "../src/crypto/pq.ts";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, "vectors");

// The ML-KEM and ML-DSA known-answer vector shapes (base64url fields produced by the Go reference).
// Typing readKAT catches a renamed KAT field at the type-check step rather than a silent undefined.
interface MlkemKat {
  seed: string;
  encapKey: string;
  cipherText: string;
  sharedSecret: string;
}
interface MldsaKat {
  publicKey: string;
  message: string;
  signature: string;
}
function readKAT<T>(name: string): T {
  return JSON.parse(readFileSync(join(vectors, name, "kat.json"), "utf8")) as T;
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function main(): void {
  console.log("mlkem-kat (noble agrees with Go ML-KEM-1024):");
  const k = readKAT<MlkemKat>("mlkem-kat");
  const seed = b64urlDecode(k.seed);
  const { encapKey, decapKey } = mlkemKeygen(seed);
  // noble derives the SAME encapsulation key from the Go seed.
  ok("encapKey from seed matches Go", b64urlEncode(encapKey) === k.encapKey);
  // noble decapsulates the Go ciphertext to the SAME shared secret.
  const ss = mlkemDecapsulate(b64urlDecode(k.cipherText), decapKey);
  ok("decapsulate(Go ct) matches Go ss", b64urlEncode(ss) === k.sharedSecret);
  // and a noble-side round-trip to the Go-derived key works (engine encapsulate path).
  const enc = mlkemEncapsulate(encapKey);
  const back = mlkemDecapsulate(enc.cipherText, decapKey);
  ok("noble encapsulate/decapsulate round-trip", b64urlEncode(back) === b64urlEncode(enc.sharedSecret));

  console.log("mldsa-kat (noble verifies a Go ML-DSA-87 signature):");
  const d = readKAT<MldsaKat>("mldsa-kat");
  ok("noble.verify(Go pub, msg, Go sig)", mldsaVerify(b64urlDecode(d.publicKey), b64urlDecode(d.message), b64urlDecode(d.signature)));
  // noble sign -> noble verify (engine sign path internal consistency).
  const kp = mldsaKeygen();
  const msg = new TextEncoder().encode("engine sign self-check");
  const sig = mldsaSign(kp.secretKey, msg);
  ok("noble sign/verify round-trip", mldsaVerify(kp.publicKey, msg, sig));

  console.log("negative paths (the load-bearing rejection behaviour):");
  // (a) ML-KEM implicit rejection: a tampered ciphertext decapsulates to a DIFFERENT (pseudo-random) shared
  // secret rather than panicking. Flip a bit in the Go ciphertext and confirm the result diverges.
  const tamperedCt = b64urlDecode(k.cipherText);
  tamperedCt[0] = (tamperedCt[0] ?? 0) ^ 0x01;
  const ssTampered = mlkemDecapsulate(tamperedCt, decapKey);
  ok("decapsulate of a tampered ciphertext implicitly rejects (different shared secret, no panic)", b64urlEncode(ssTampered) !== k.sharedSecret);
  // (b) ML-DSA rejects a tampered signature.
  const tamperedSig = sig.slice();
  tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0x01;
  ok("verify rejects a tampered signature", !mldsaVerify(kp.publicKey, msg, tamperedSig));
  // (c) ML-DSA rejects a valid signature checked against the WRONG public key.
  const other = mldsaKeygen();
  ok("verify rejects a valid signature against the wrong public key", !mldsaVerify(other.publicKey, msg, sig));

  console.log(failures === 0 ? "\nALL PQ VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
