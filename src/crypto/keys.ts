import { type CryptoKeyRole, noteCryptoFault } from "../format/integrity-fault-ledger.ts";
import { b64urlDecode } from "./bytes.ts";
import type { HybridRecipientPrivate } from "./kem.ts";
import type { HybridVerifier } from "./sign.ts";

// Key file parsing, matching the Go offline tool's labelled base64url line format
// ("<label> <base64url>") and the fixed sizes of the CNSA 2.0 suite.

/** Byte length of an Ed25519 public key (the verifier prefix). */
const ED25519_PUB_LEN = 32;
/** Byte length of an ML-DSA-87 public key. */
const MLDSA87_PUB_LEN = 2592;

/** The line label of a break-glass identity key file. Key-file format contract (Go offline tool interop); see parseKeyFile. */
export const LABEL_IDENTITY = "downpipe-identity-v1";
/** The line label of a recipient public key file. @knipignore Key-file format contract (Go offline tool interop); see parseKeyFile. */
export const LABEL_RECIPIENT = "downpipe-recipient-v1";
/** The line label of a signer public key file. Key-file format contract (Go offline tool interop); see parseKeyFile. */
export const LABEL_SIGNER_PUBLIC = "downpipe-signer-public-v1";
/** The line label of a signer private key file. @knipignore Key-file format contract (Go offline tool interop); see parseKeyFile. */
export const LABEL_SIGNER_PRIVATE = "downpipe-signer-private-v1";

/**
 * Parses a labelled base64url key file line ("<label> <base64url>") and decodes its payload,
 * matching the Go offline tool's format.
 *
 * @param text - the file contents (a single "<label> <base64url>" line, surrounding whitespace
 *   tolerated).
 * @param label - the exact label the file must carry.
 * @returns the decoded key bytes.
 * @throws Error when the line is not exactly a label and a token, or the label does not match; the
 *   base64url decode throws on a malformed payload.
 * Consumed by tools/open-support-bundle.ts (the offline support-bundle reader), which is outside knip's project scope, so knip cannot see the use; the tag suppresses the resulting false positive.
 */
export function parseKeyFile(text: string, label: string): Uint8Array {
  const parts = text.trim().split(/\s+/);
  if (parts.length !== 2 || parts[0] !== label) {
    // G012: the SWAPPED-LABEL paste. An operator who pastes the OPERATIONAL key file into the SIGNER slot (or
    // the reverse) sees every backup start failing with a coarse error, and the pack could not name the key
    // ROLE, let alone say the file was simply the wrong one. The label is the engine's own product vocabulary;
    // the file's contents never ride.
    noteCryptoFault({ cls: "key-wrong-label", role: roleOfLabel(label) });
    throw new Error(`not a ${label} file`);
  }
  try {
    return b64urlDecode(parts[1]!);
  } catch (e) {
    // The base64url payload would not decode: a truncated paste, a PEM header, standard-alphabet base64, a
    // stray character. Record the class + role and re-throw UNCHANGED (the caller's behaviour is untouched);
    // the payload, and the offending character the decoder's own message quotes, are DISCARDED here.
    noteCryptoFault({ cls: "key-malformed-b64url", role: roleOfLabel(label) });
    throw e;
  }
}

// roleOfLabel maps a key-file LABEL (an engine-owned literal, never customer input) to the closed key ROLE the
// diagnostic vocabulary uses. An unrecognised label is the verifier role: the labels are ours, so an unknown
// one is a code fault, not a customer value, and it must never become a free-text record field.
function roleOfLabel(label: string): CryptoKeyRole {
  const l = label.toLowerCase();
  if (l.includes("signer")) return "signer";
  if (l.includes("break-glass") || l.includes("breakglass")) return "break-glass";
  if (l.includes("operational")) return "operational";
  if (l.includes("recipient") || l.includes("identity")) return "recipient";
  return "verifier";
}

/**
 * Parses a 96-byte break-glass identity into its hybrid private parts: X25519 scalar(32) ||
 * ML-KEM seed(64).
 *
 * @param bytes - the 96-byte identity payload.
 * @returns the hybrid recipient private identity (scalar and seed as subarrays of the input).
 * @throws Error when the payload is not exactly 96 bytes.
 */
export function parseIdentity(bytes: Uint8Array): HybridRecipientPrivate {
  if (bytes.length !== 96) throw new Error(`identity is ${bytes.length} bytes, want 96`);
  return { x25519Scalar: bytes.subarray(0, 32), mlkemSeed: bytes.subarray(32, 96) };
}

/**
 * Parses a signer public key into its hybrid verifier parts: Ed25519(32) || ML-DSA-87 public.
 * The total payload length is checked so a wrong-length key surfaces a provisioning error here
 * rather than at verify time, matching Go's ParseVerifier.
 *
 * @param bytes - the signer public key payload.
 * @returns the hybrid verifier (Ed25519 and ML-DSA public keys as subarrays of the input).
 * @throws Error when the payload is not exactly Ed25519(32) || ML-DSA-87(2592) bytes.
 */
export function parseVerifier(bytes: Uint8Array): HybridVerifier {
  const want = ED25519_PUB_LEN + MLDSA87_PUB_LEN;
  if (bytes.length !== want) throw new Error(`signer public key is ${bytes.length} bytes, want ${want}`);
  return { ed: bytes.subarray(0, ED25519_PUB_LEN), mldsa: bytes.subarray(ED25519_PUB_LEN) };
}
