// validate-signer-rotation-explain.ts -- a root-signature failure caused by a SIGNER ROTATION (the
// archive was signed by a now-replaced signer) must be EXPLAINED as a rotation, not reported as a generic
// tamper failure. The reader compares the archive's signingKeyFingerprint hint to the current pinned
// verifier's fingerprint; on a mismatch it appends an actionable rotation hint (restore with the prior
// signer's public key). On a fingerprint MATCH (a genuine tamper, same signer) the message is unchanged.
// The signature still fails closed in BOTH cases; this only refines the message.
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { signerFingerprint, type Signer } from "../src/format/writer-root.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";

let pass = 0, fail = 0;
const ok = (d: string, c: boolean) => { console.log(`  ${c ? "ok  " : "FAIL"} ${d}`); c ? pass++ : fail++; };

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

async function mintSigner(): Promise<{ signer: Signer; verifier: { ed: Uint8Array; mldsa: Uint8Array } }> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const m = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: m.secretKey, mldsaPublic: m.publicKey };
  return { signer, verifier: { ed: edPublic, mldsa: m.publicKey } };
}

// storeWith builds a minimal in-memory ObjectStore holding just the root manifest and its signature, which
// is all openRun reads before the signature gate fires. A missing object throws, as the real store does.
function storeWith(rootBytes: Uint8Array, sig: Uint8Array): ObjectStore {
  const m = new Map<string, Uint8Array>([
    [`run/${RUN_ID}/root.manifest.json`, rootBytes],
    [`run/${RUN_ID}/root.manifest.json.sig`, utf8(b64urlEncode(sig))],
  ]);
  return { get: async (k: string) => { const v = m.get(k); if (v === undefined) throw new Error(`object ${k} is missing`); return v; } };
}

const dummyIdentity = { x25519: new Uint8Array(32), mlkemDk: new Uint8Array(64) } as never;

async function messageFromOpen(store: ObjectStore, verifier: { ed: Uint8Array; mldsa: Uint8Array }): Promise<string> {
  try {
    await openRun(store, RUN_ID, dummyIdentity, verifier);
    return "(no throw)";
  } catch (e) {
    return (e as Error).message;
  }
}

const A = await mintSigner();
const B = await mintSigner();

// ROTATION: root carries signer A's fingerprint and a valid A signature; opened under signer B (rotated).
{
  const fpA = await signerFingerprint(A.verifier);
  const rootBytes = utf8(JSON.stringify({ runId: RUN_ID, signingKeyFingerprint: fpA, formatVersion: "downpipe/0.1.0" }));
  const sig = await hybridSign(A.signer.edPrivate, A.signer.mldsaSecret, rootBytes);
  const msg = await messageFromOpen(storeWith(rootBytes, sig), B.verifier);
  ok("rotation: the failure names a SIGNER ROTATION, not a generic tamper", /signer rotation/.test(msg));
  ok("rotation: the message names the archive's signer fingerprint", msg.includes(fpA));
  ok("rotation: the message names the current pinned signer fingerprint", msg.includes(await signerFingerprint(B.verifier)));
  ok("rotation: the message keeps the base 'did not verify' cause", /did not verify under the operator-pinned signer/.test(msg));
}

// SAME SIGNER, corrupted signature: fingerprints match, so NO rotation hint (a genuine tamper).
{
  const fpA = await signerFingerprint(A.verifier);
  const rootBytes = utf8(JSON.stringify({ runId: RUN_ID, signingKeyFingerprint: fpA, formatVersion: "downpipe/0.1.0" }));
  const sig = await hybridSign(A.signer.edPrivate, A.signer.mldsaSecret, rootBytes);
  sig[0] = sig[0]! ^ 0xff; // corrupt the signature
  const msg = await messageFromOpen(storeWith(rootBytes, sig), A.verifier);
  ok("tamper (same signer): the failure is the plain message, NO false rotation hint", /did not verify under the operator-pinned signer/.test(msg) && !/signer rotation/.test(msg));
}

console.log(`\n${fail === 0 ? "SIGNER ROTATION EXPLAIN PASS" : "SIGNER ROTATION EXPLAIN: " + fail + " FAIL"}: ${pass} pass / ${fail} fail`);
if (fail > 0) process.exitCode = 1;
if (fail > 0) process.exit(1);
