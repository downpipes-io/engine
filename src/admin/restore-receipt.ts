import { b64urlDecode, b64urlEncode, constantTimeEqual, hexDecode, hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type HybridVerifier, hybridSign, hybridVerify } from "../crypto/sign.ts";
import type { Env } from "../env.d.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { Signer } from "../format/writer.ts";
import { loadSigner } from "../keys-env.ts";
import { log } from "../log.ts";
import { errId } from "./restore-sinks.ts";
import type { CfConfigSkipClass, RestoreDestFallback, RestoreReceipt, RestoreReceiptRecord } from "./restore-types.ts";

// RESTORE_RECEIPT_SIG_ALG is the signature algorithm label on a key-signed receipt: the same hybrid
// Ed25519 + ML-DSA-87 scheme the archive root is signed with (SPEC 8.1), so a verifier uses the SAME
// operator-pinned verifier (the signer's public halves) it already trusts for the manifest.
const RESTORE_RECEIPT_SIG_ALG = "ed25519+ml-dsa-87";

// receiptCore is the canonicalised, signed-and-hashed BODY of a receipt: every field EXCEPT the
// tamper-evidence fields (receiptSha384 / signature / signatureAlg), which are derived FROM it. Pulling
// the core out explicitly (rather than deleting fields from the full receipt) makes the hashed/signed set
// unambiguous and stable, exactly as auditHash reconstructs its hashed object. canonicalJSON sorts keys
// and forbids non-integer numbers, so the bytes are reproducible across the build and an external verify.
function receiptCore(r: RestoreReceipt): unknown {
  return {
    runId: r.runId,
    restoredAt: r.restoredAt,
    isLatest: r.isLatest,
    records: r.records.map((rec) => ({
      name: rec.name,
      sourceType: rec.sourceType,
      expectedSha384: rec.expectedSha384,
      // verifiedSha384 is null when a streamed readback could not be read back at all; canonicalJSON
      // encodes null, so the signed/hashed bytes commit to that honest "not verified" state too.
      verifiedSha384: rec.verifiedSha384,
      verified: rec.verified,
      via: rec.via,
      // The Stream id map, on the SAME terms as recordsSkipped and destFallback below: present ONLY when the
      // re-upload remapped, so a receipt with no remapped video canonicalises byte-for-byte as it did before
      // these fields existed and every receipt already anchored in the audit chain still verifies against its
      // recorded digest and signature. Inside the core rather than beside it because the map is the
      // operational key to finishing a video recovery, and a field outside the hash can be stripped.
      ...(rec.restoredId !== undefined ? { restoredId: rec.restoredId } : {}),
      ...(rec.remapped ? { remapped: rec.remapped } : {}),
    })),
    summary: {
      recordsRestored: r.summary.recordsRestored,
      bytesRestored: r.summary.bytesRestored,
      allVerified: r.summary.allVerified,
      // Present ONLY when non-zero. A restore that skipped nothing therefore produces the same canonical
      // bytes as before this field existed, so its digest and signature are unchanged and every receipt
      // already anchored in the audit chain still verifies against its recorded digest.
      ...(r.summary.recordsSkipped ? { recordsSkipped: r.summary.recordsSkipped } : {}),
      // The cf-config skip CLASSES are INSIDE the signed and hashed core, on the same terms: present only
      // when the Cloudflare API refused at least one item, absent otherwise. Inside rather than beside,
      // because the whole point of the field is that a receipt for an apply which wrote NOTHING (a token too
      // narrow for the surface, every item 401/403) must not hash the same as a receipt for a clean one. A
      // count that a tamperer could strip without breaking the digest would leave the defect exactly where
      // it was. canonicalJSON sorts the keys, so the closed class vocabulary encodes reproducibly.
      ...(r.summary.configSkipReasonCounts && Object.keys(r.summary.configSkipReasonCounts).length > 0
        ? { configSkipReasonCounts: r.summary.configSkipReasonCounts }
        : {}),
      // The shed tally, on the identical terms and for the identical reason: a receipt that claims a
      // clean restore must not hash the same as one that dropped a field. Absent when the restore was full
      // fidelity, so an unaffected receipt canonicalises byte-for-byte as before and still verifies.
      ...(r.summary.metadataFieldsDropped && Object.keys(r.summary.metadataFieldsDropped).length > 0
        ? { metadataFieldsDropped: r.summary.metadataFieldsDropped }
        : {}),
    },
    // The 3-2-1 walk, on the same terms as recordsSkipped: present ONLY when this restore was not served by
    // its first-choice destination, so a first-choice restore canonicalises byte-for-byte as it did before
    // this field existed and every receipt already anchored in the audit chain still verifies. It is INSIDE
    // the core because the claim it makes ("your primary refused, this came from a replica, and the replica
    // verified") is exactly the claim a tamperer would want to strip, and a field outside the hash can be
    // stripped without breaking anything. The reasons are the engine's own REASON_* literals and the ids are
    // the customer's own destination ids; canonicalJSON sorts the keys, so it encodes reproducibly.
    ...(r.destFallback !== undefined
      ? {
          destFallback: {
            servedAt: r.destFallback.servedAt,
            ...(r.destFallback.servedDestinationId !== undefined ? { servedDestinationId: r.destFallback.servedDestinationId } : {}),
            refused: r.destFallback.refused.map((d) => ({
              ...(d.destinationId !== undefined ? { destinationId: d.destinationId } : {}),
              reason: d.reason,
            })),
          },
        }
      : {}),
  };
}

// restoreReceiptDigestHex computes the canonical SHA-384 of a receipt's core (the value carried in
// receiptSha384 and anchored into the audit chain). It is the single definition both the builder and any
// verifier use, so the anchor and a re-derivation can never disagree on the bytes. Exported so the
// validator and the router can recompute the anchor hash from a returned receipt.
export async function restoreReceiptDigestHex(r: RestoreReceipt): Promise<string> {
  return hexEncode(await sha384(canonicalJSON(receiptCore(r))));
}

// verifyRestoreReceiptSignature re-derives the canonical receipt-core bytes, confirms they hash to the
// receipt's receiptSha384 (the digest the audit chain anchored), and, when a detached signature is
// present, verifies BOTH hybrid halves against the supplied verifier (the signer's public halves) over
// those exact bytes. It returns { hashOk, signatureOk }: hashOk is the audit-anchor proof (the receipt's
// content matches its stated digest), signatureOk is the key-signed proof (true only when a signature is
// present AND verifies; false when absent). A receipt with NO signature is still audit-anchored, so a
// caller treats hashOk as the tamper-evidence and signatureOk as an additional, optional assurance.
// Exported for the validator (and any console-side verify); it never throws (hybridVerify is total).
export async function verifyRestoreReceiptSignature(r: RestoreReceipt, verifier: HybridVerifier): Promise<{ hashOk: boolean; signatureOk: boolean }> {
  const core = canonicalJSON(receiptCore(r));
  // Compare the raw digest bytes in constant time. The anchor digest is not secret, but this is an
  // integrity-verification path, so a timing-safe compare matches the defensive posture of the rest of the
  // crypto code at near-zero cost. A malformed (odd-length) stated digest decodes to nothing and so fails
  // closed, preserving the prior "never throws" contract.
  const actual = await sha384(core);
  let hashOk = false;
  try {
    const expected = hexDecode(r.receiptSha384);
    hashOk = actual.length === expected.length && constantTimeEqual(actual, expected);
  } catch {
    hashOk = false;
  }
  let signatureOk = false;
  if (typeof r.signature === "string" && r.signature.length > 0) {
    try {
      signatureOk = await hybridVerify(verifier, core, b64urlDecode(r.signature));
    } catch {
      signatureOk = false;
    }
  }
  return { hashOk, signatureOk };
}

// makeRestoreReceipt assembles the signed / audit-anchored RestoreReceipt for an applied restore. It
// builds the body from the per-record entries gathered on the apply path, computes the summary
// (allVerified is true only when EVERY restored record verified, so a streamed readback mismatch makes it
// false), hashes the canonical core into receiptSha384 (the value the router anchors into the tamper-
// evident audit chain), and -- when the engine's signer key is reachable here (SIGNER_PRIVATE, the same
// key restore already loaded to verify the run) -- attaches a DETACHED HYBRID SIGNATURE over the exact
// canonical core bytes. A signing failure (or an absent signer) is NON-FATAL: the receipt is still
// returned, audit-anchored, just without a signature (the audit anchor is the tamper-evidence either
// way). The receipt is redaction-safe: it carries only record NAMES, source types, hashes, the via and
// counts -- never a value, a key, or a binding credential.
export async function makeRestoreReceipt(
  env: Env,
  runId: string,
  isLatest: boolean,
  records: RestoreReceiptRecord[],
  recordsRestored: number,
  bytesRestored: number,
  recordsSkipped = 0,
  configSkipReasonCounts: Partial<Record<CfConfigSkipClass, number>> = {},
  destFallback?: RestoreDestFallback,
  metadataFieldsDropped: Record<string, number> = {},
): Promise<RestoreReceipt> {
  // allVerified iff every record on the receipt matched its expected proof. An empty receipt (nothing
  // restored) is vacuously allVerified:true, but recordsRestored:0 makes that unambiguous to a reader.
  //
  // There is deliberately NO cf-config special case here. A cf-config surface that did not fully apply is a
  // receipt RECORD with verified:false (see the apply's config loop), so this one expression keeps its single
  // meaning and the flag falls out of it.
  const allVerified = records.every((rec) => rec.verified);
  const restoredAt = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"); // RFC-3339 millis, the manifest/audit form
  const receipt: RestoreReceipt = {
    runId,
    restoredAt,
    isLatest,
    records,
    summary: {
      recordsRestored,
      bytesRestored,
      allVerified,
      ...(recordsSkipped > 0 ? { recordsSkipped } : {}),
      ...(Object.keys(configSkipReasonCounts).length > 0 ? { configSkipReasonCounts } : {}),
      ...(Object.keys(metadataFieldsDropped).length > 0 ? { metadataFieldsDropped } : {}),
    },
    // Absent on the first-choice restore, which is every restore whose primary answered. See receiptCore.
    ...(destFallback !== undefined ? { destFallback } : {}),
    receiptSha384: "", // filled below over the canonical core
  };
  receipt.receiptSha384 = await restoreReceiptDigestHex(receipt);
  // Detached hybrid signature when the signer is reachable (it is, on the apply path: restore opened the
  // run with it). Sign the SAME canonical core bytes the digest is over, so a verifier checks one byte
  // string against both the hash and the signature. Any failure here degrades to an unsigned (but still
  // audit-anchored) receipt rather than failing the restore, which has already completed.
  try {
    if (typeof env.SIGNER_PRIVATE === "string" && env.SIGNER_PRIVATE.length > 0) {
      const signer: Signer = await loadSigner(env.SIGNER_PRIVATE);
      const core = canonicalJSON(receiptCore(receipt));
      const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, core);
      receipt.signature = b64urlEncode(sig);
      receipt.signatureAlg = RESTORE_RECEIPT_SIG_ALG;
    }
  } catch (e) {
    // Non-fatal: the receipt stays audit-anchored (its receiptSha384 goes into the chain) without a
    // key signature. Log coarsely; never leak the signer or fail the completed restore.
    log("error", `restore ${runId} receipt signing skipped (non-fatal) [err:${errId(e)}]`);
  }
  return receipt;
}
