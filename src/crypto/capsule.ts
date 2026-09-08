import { noteCryptoFault, noteFailStage, noteStreamFault } from "../format/integrity-fault-ledger.ts";
import { INFO_CAPSULE_DEM, INFO_RECIPIENT_SET } from "../format/version.ts";
import { b64urlDecode, concat, hexEncode, utf8 } from "./bytes.ts";
import { decapsulateHybrid, encapsulateHybrid, type HybridRecipientPrivate, type HybridRecipientPublic } from "./kem.ts";
import { mlkemKeygen } from "./pq.ts";
import { hkdfSha384, sha384 } from "./primitives.ts";
import { openStream, sealStream } from "./stream.ts";
import { x25519PublicFromScalar } from "./x25519.ts";

// The master capsule (SPEC 5.4): the run master wrapped to each recipient by hybrid
// KEM-DEM. The engine seals; the reader (drills, the validator) opens with a held
// identity. The DEM is AES-256-GCM in the STREAM with the run key commitment as AAD, so
// a swapped capsule fails authentication even on the unverified path.

/**
 * One recipient's wrap of the run master in the master capsule (SPEC 5.4): the recipient
 * fingerprint it is addressed to, the hybrid KEM ciphertext, and the STREAM-sealed 32-byte master.
 */
export interface CapsuleWrap {
  fingerprint: string; // dpr1:...
  kemCiphertext: Uint8Array; // 1600
  sealed: Uint8Array; // STREAM-sealed 32-byte master
}

/**
 * Computes a hybrid recipient's fingerprint (SPEC 7.6.1): the `dpr1:` prefix followed by the hex
 * SHA-384 of x25519(32) || ML-KEM-1024(1568).
 *
 * @param x25519Pub - the recipient's 32-byte X25519 public key.
 * @param mlkemEk - the recipient's 1568-byte ML-KEM-1024 encapsulation key.
 * @returns the `dpr1:`-prefixed hex fingerprint.
 */
export async function recipientFingerprint(x25519Pub: Uint8Array, mlkemEk: Uint8Array): Promise<string> {
  return `dpr1:${hexEncode(await sha384(concat(x25519Pub, mlkemEk)))}`;
}

/**
 * Derives the recovering identity's recipient fingerprint from its private parts, so the matching
 * capsule wrap can be selected.
 *
 * @param priv - the held hybrid recipient private identity (X25519 scalar and ML-KEM seed).
 * @returns the `dpr1:`-prefixed fingerprint of the public key the identity corresponds to.
 */
export async function identityFingerprint(priv: HybridRecipientPrivate): Promise<string> {
  const x = x25519PublicFromScalar(priv.x25519Scalar);
  const ek = mlkemKeygen(priv.mlkemSeed).encapKey;
  return recipientFingerprint(x, ek);
}

/**
 * Recovers the 32-byte run master from the master-capsule wraps using a held identity. It selects
 * the wrap addressed to the identity, decapsulates the hybrid KEM, derives the DEM key and
 * STREAM-opens the master.
 *
 * @param wraps - the master-capsule wraps, one per recipient.
 * @param priv - the held hybrid recipient private identity.
 * @param aad - the signed run key commitment, as raw bytes, bound as the DEM additional data.
 * @returns the recovered 32-byte master.
 * @throws Error when no wrap matches the held recipient, or when the recovered master is not 32
 *   bytes; the underlying STREAM open throws on an authentication failure.
 */
export async function openCapsule(wraps: CapsuleWrap[], priv: HybridRecipientPrivate, aad: Uint8Array): Promise<Uint8Array> {
  const want = await identityFingerprint(priv);
  for (const w of wraps) {
    if (w.fingerprint !== want) continue;
    const ss = await decapsulateHybrid(priv, w.kemCiphertext);
    const wrapKey = await hkdfSha384(ss, new Uint8Array(0), utf8(INFO_CAPSULE_DEM), 32);
    const master = await openStream(wrapKey, w.sealed, aad, 1);
    if (master.length !== 32) {
      // G111: the capsule DEM authenticated and yielded a master of the wrong size. That is a corrupt capsule,
      // not a wrong identity, and it looked identical to a tamper. Ints only.
      noteStreamFault({ leg: "decrypt-open", cls: "master-length-mismatch", receivedBytes: master.length, expectedBytes: 32 });
      noteFailStage("capsule-unwrap");
      throw new Error(`recovered master is ${master.length} bytes, want 32`);
    }
    return master;
  }
  // G012: THE most misdiagnosed key ticket. No wrap matches the identity we hold, which means the operator is
  // holding the WRONG recipient identity for this archive (a rotation, a restore from another tenant's run, a
  // break-glass key where an operational one is needed). It is NOT tamper and NOT a destination fault, and it
  // read as "integrity check failed" -- so support chased corruption while the customer simply held the wrong
  // key. The two FINGERPRINTS are of PUBLIC material (the class the pack already carries under keys.*), which
  // is exactly what lets support say "you are holding <held>, this archive is wrapped to <want>".
  noteCryptoFault({
    cls: "recipient-no-capsule-match",
    role: "recipient",
    heldFingerprint: want,
    ...(wraps[0]?.fingerprint !== undefined ? { wantFingerprint: wraps[0].fingerprint } : {}),
  });
  noteFailStage("capsule-unwrap");
  throw new Error(`no capsule wrap matches the held recipient ${want}`);
}

/**
 * Decodes the JSON master-capsule array (base64url ciphertext and sealed fields) into CapsuleWrap
 * values with their bytes decoded.
 *
 * @param arr - the master-capsule entries from the root manifest, each with base64url
 *   kemCiphertext and sealed strings.
 * @returns the decoded CapsuleWrap values.
 * @throws Error when a kemCiphertext or sealed field is not valid base64url.
 */
export function parseWraps(arr: Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>): CapsuleWrap[] {
  return arr.map((w) => ({ fingerprint: w.fingerprint, kemCiphertext: b64urlDecode(w.kemCiphertext), sealed: b64urlDecode(w.sealed) }));
}

/**
 * Wraps the 32-byte master to every recipient by hybrid KEM-DEM (SPEC 5.4), binding the run key
 * commitment as the DEM additional data. The engine holds only public recipient keys, so it can
 * wrap but never unwrap.
 *
 * @param master - the 32-byte run master to wrap.
 * @param recipients - the hybrid recipient public keys to wrap to.
 * @param aad - the run key commitment, as raw bytes, bound as the DEM additional data.
 * @param nonceFor - supplies a fresh 16-byte payload nonce for each wrap.
 * @returns one CapsuleWrap per recipient.
 */
export async function sealToRecipients(master: Uint8Array, recipients: HybridRecipientPublic[], aad: Uint8Array, nonceFor: () => Uint8Array): Promise<CapsuleWrap[]> {
  const wraps: CapsuleWrap[] = [];
  for (const r of recipients) {
    const enc = await encapsulateHybrid(r);
    const wrapKey = await hkdfSha384(enc.sharedSecret, new Uint8Array(0), utf8(INFO_CAPSULE_DEM), 32);
    const sealed = await sealStream(wrapKey, master, nonceFor(), aad);
    wraps.push({ fingerprint: await recipientFingerprint(r.x25519, r.mlkemEk), kemCiphertext: enc.cipherText, sealed });
  }
  return wraps;
}

/**
 * Computes the recipient-set hash that binds the exact recipient set into the signed root (SPEC
 * 7.6.1): the SHA-384 over the label, a 0x00 separator and the 1600-byte recipient encodings
 * sorted by raw bytes.
 *
 * @param recipients - the hybrid recipient public keys forming the set.
 * @returns the 48-byte SHA-384 recipient-set hash.
 */
export async function recipientSetHash(recipients: HybridRecipientPublic[]): Promise<Uint8Array> {
  const encs = recipients.map((r) => concat(r.x25519, r.mlkemEk));
  encs.sort((a, b) => compareBytes(a, b));
  return sha384(concat(utf8(INFO_RECIPIENT_SET), new Uint8Array([0x00]), ...encs));
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}
