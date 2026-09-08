import { noteCryptoFault } from "../format/integrity-fault-ledger.ts";
import { ab } from "./bytes.ts";
import { mldsaSign, mldsaVerify } from "./pq.ts";

// The hybrid Ed25519 + ML-DSA-87 signature (SPEC 8.1): a detached signature is
// edSig(64) || mldsaSig(4627) = 4691 bytes, and BOTH halves must verify, so a forgery
// must break a classical AND a post-quantum scheme and neither half can be stripped.

const ED25519_SIG_LEN = 64;
const MLDSA_SIG_LEN = 4627;

/**
 * A hybrid signature verifier: the 32-byte Ed25519 public key and the 2592-byte ML-DSA-87 public
 * key. Both halves must verify for a signature to be accepted.
 */
export interface HybridVerifier {
  ed: Uint8Array; // 32, Ed25519 public key
  mldsa: Uint8Array; // 2592, ML-DSA-87 public key
}

/**
 * Verifies a hybrid signature over the exact message bytes, returning false unless BOTH the
 * Ed25519 and ML-DSA-87 halves verify. It is strictly boolean: a malformed verifier or signature
 * (a wrong-length Ed25519 key that importKey rejects, a wrong-length ML-DSA-87 key that noble's
 * verify throws on) is caught and treated as a non-verification, never propagated, keeping the
 * contract aligned with the Go reader's "did not verify" typed error rather than a crash.
 *
 * @param v - the hybrid verifier (Ed25519 and ML-DSA-87 public keys).
 * @param message - the exact message bytes the signature should cover.
 * @param signature - the detached hybrid signature, edSig(64) || mldsaSig.
 * @returns true only when both halves verify; false on any mismatch or on malformed input that is
 *   caught as a non-verification.
 */
export async function hybridVerify(v: HybridVerifier, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return (await hybridVerifyDetailed(v, message, signature)) === "ok";
}

/**
 * HybridVerifyVerdict is hybridVerify's boolean, un-collapsed (support-pack gap G218).
 *
 * WHY. hybridVerify returns a bare `false` for five completely different worlds, and the control-plane
 * recovery path renders ONE refusal code ("signature") for all of them -- so a support engineer holding the
 * pack could not separate "a truncated .sig file" (the artefact is fine; re-copy the signature) from "the
 * signer was ROTATED" (the artefact is fine; you are checking it against the wrong key) from "the export was
 * MODIFIED" (this is tamper). Those are three different incidents with three different responses, and the
 * worst of them is silently lumped in with the most benign.
 *
 * Splitting the two halves is genuinely diagnostic and not merely tidy. BOTH halves sign the SAME message
 * bytes, so each half is a witness for the other and the verdict is a 2x2, not a sequence. Tamper is the ONLY
 * world that can break both halves at once (altering the export invalidates both signatures), so a failure
 * that leaves EITHER half verifying is a failure of the KEY PAIR, and the artefact is proven intact:
 *
 *   ed ok,   ML-DSA no  -> mldsa-mismatch:        the damage is confined to the POST-QUANTUM half of the key
 *                          pair (a partial/mixed signer rotation, a rotted ML-DSA half of the verifier; the
 *                          noble verifier returns false for a corrupt right-length key rather than throwing,
 *                          so it lands here and not on verifier-invalid). NEVER tamper.
 *   ed no,   ML-DSA ok   -> ed25519-only-mismatch: the mirror image, and G202. The ML-DSA half verified these
 *                          exact bytes under the kit's own key, so the EXPORT IS PROVABLY INTACT and the damage
 *                          is confined to the CLASSICAL half of the key pair (bit rot, a partially-restored or
 *                          half-written signer.pub, a partial rotation). NEVER tamper. Returning
 *                          ed25519-mismatch here -- which is what short-circuiting on the classical half did --
 *                          told the customer their recovery artefact had been ATTACKED when their key file was
 *                          merely damaged, on the one path where the pack may be the only artefact left.
 *   ed no,   ML-DSA no   -> ed25519-mismatch:      the wrong key entirely, or a genuinely MODIFIED export.
 *                          Tamper lives here, and only here.
 *
 * The verdict is a DIAGNOSIS, never an authorisation: only "ok" means the signature verified, and every
 * other member (however benign its cause) is a refusal the caller must treat as one.
 */
export type HybridVerifyVerdict =
  | "ok"
  | "sig-decode" // the signature OBJECT is the wrong length: a truncated / half-written .sig. NOT tamper
  | "ed25519-mismatch" // NEITHER half verified: the wrong signer key, or the message was altered. The ONLY verdict tamper can reach
  | "ed25519-only-mismatch" // the POST-QUANTUM half verified and the classical half did not: a damaged/partially-restored Ed25519 half of the key, or a partial signer rotation. The export is provably intact. Never tamper
  | "mldsa-mismatch" // the classical half verified and the POST-QUANTUM half did not: a partial/mixed signer rotation, or a rotted ML-DSA half of the verifier. Never tamper
  | "verifier-invalid"; // the held VERIFIER would not import at all: the operator's KEY is corrupt, not the artefact

/**
 * hybridVerifyDetailed is hybridVerify with the verdict it throws away. Total: it never throws, and it
 * records the same crypto-fault classes hybridVerify always did, so the existing aggregate is unchanged.
 *
 * @param v - the hybrid verifier (Ed25519 and ML-DSA-87 public keys).
 * @param message - the exact message bytes the signature should cover.
 * @param signature - the detached hybrid signature, edSig(64) || mldsaSig.
 * @returns the closed verdict; "ok" only when BOTH halves verify.
 */
export async function hybridVerifyDetailed(v: HybridVerifier, message: Uint8Array, signature: Uint8Array): Promise<HybridVerifyVerdict> {
  try {
    if (signature.length !== ED25519_SIG_LEN + MLDSA_SIG_LEN) {
      // G087: a signature OBJECT of the wrong length is a MALFORMED signature file (a truncated / half-written
      // RUNLOG.sig, SHA384SUMS.sig or root.manifest.json.sig), which is a completely different ticket from a
      // signature that is well-formed and does not verify (a tamper, or a signer rotation). Both returned a
      // bare `false` and merged into one reason. verify-structural-fault is the "your signature object is
      // damaged, re-write it" arm; verify-mismatch below is the "this does not verify under your key" arm.
      noteCryptoFault({ cls: "verify-structural-fault", role: "verifier", lengthClass: signature.length });
      return "sig-decode";
    }
    const edSig = signature.subarray(0, ED25519_SIG_LEN);
    const mSig = signature.subarray(ED25519_SIG_LEN);
    const edKey = await crypto.subtle.importKey("raw", ab(v.ed), "Ed25519", false, ["verify"]);
    const edOK = await crypto.subtle.verify("Ed25519", edKey, ab(edSig), ab(message));
    const mldsaOK = mldsaVerify(v.mldsa, message, mSig);
    if (edOK && mldsaOK) return "ok";
    noteCryptoFault({ cls: "verify-mismatch", role: "verifier" });
    // G202: DO NOT SHORT-CIRCUIT ON THE CLASSICAL HALF. Both halves sign the SAME message bytes, so the half
    // that did NOT fail is a free discriminator, and returning "ed25519-mismatch" the instant the classical
    // half failed threw it away. The cost of keeping it is ONE ML-DSA verify on a path that has already
    // refused the artefact (a rare, manual recovery action), and what it buys is the difference between
    // "someone has attacked you" and "your key file has rotted, take another copy":
    //
    //   ed FAILS, ML-DSA PASSES -> the post-quantum half verified THESE EXACT EXPORT BYTES under the kit's own
    //                              key, so THE EXPORT IS PROVABLY INTACT and whatever is wrong is confined to
    //                              the CLASSICAL half of the key pair (a rotted or partially-restored
    //                              signer.pub, a half-written key file, a partial signer rotation). A modified
    //                              export cannot reach this verdict: altering the bytes breaks BOTH halves.
    //                              This is NEVER tamper.
    //   ed FAILS, ML-DSA FAILS  -> the wrong key entirely, or a genuinely ALTERED export. Tamper lives here,
    //                              and now ONLY here.
    if (!edOK) return mldsaOK ? "ed25519-only-mismatch" : "ed25519-mismatch";
    return "mldsa-mismatch";
  } catch {
    // A THROW inside verification (an unimportable public key, a malformed ML-DSA key) is structural: the held
    // VERIFIER is corrupt, not the archive. It used to be indistinguishable from a failed verification, which
    // is precisely the wrong diagnosis (the operator is told their backup is tampered when their key is bad).
    noteCryptoFault({ cls: "verify-structural-fault", role: "verifier" });
    return "verifier-invalid";
  }
}

/**
 * Produces a detached hybrid signature, edSig(64) || mldsaSig, over the message.
 *
 * @param edPrivate - the Ed25519 private key as a Web Crypto CryptoKey.
 * @param mldsaSecret - the ML-DSA-87 secret key bytes (the noble key form).
 * @param message - the message bytes to sign.
 * @returns the concatenated Ed25519 and ML-DSA-87 signature.
 */
export async function hybridSign(edPrivate: CryptoKey, mldsaSecret: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const edSig = new Uint8Array(await crypto.subtle.sign("Ed25519", edPrivate, ab(message)));
  const mSig = mldsaSign(mldsaSecret, message);
  const out = new Uint8Array(edSig.length + mSig.length);
  out.set(edSig);
  out.set(mSig, edSig.length);
  return out;
}
