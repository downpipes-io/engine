import { b64urlEncode, sha256Hex } from "../crypto/bytes.ts";
import { hybridSign } from "../crypto/sign.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import { signerFingerprint, type Signer } from "../format/writer.ts";
import { isTier } from "./licence.ts";
import { nowIso } from "./support-shared.ts";

// buildBandManifest emits the CLEAR-SIGNED band manifest that rides on the support-bundle envelope:
// the minimum cleartext support intake needs to join a pack to its
// customer-of-record and run the band check without opening the pack. Each field carries a stated
// constraint:
//   - kind is the domain label INSIDE the signed bytes, so these signed bytes can never be mistaken
//     for any other engine signature (a run root, a licence token, an export);
//   - bodySha256 (sealed form only) binds the manifest to THIS sealed body: the sha256 of the raw
//     ciphertext bytes, so a manifest lifted onto a different pack fails the binding;
//   - signerPublic carries the public keys because a fingerprint alone cannot verify a signature;
//     a verifier recomputes the fingerprint from these carried keys and matches it to a registry;
//   - volumes and licence are deliberately MINIMISED cleartext (no downpipe count, no asOf, no
//     byType, no zones): exactly what the band check needs and nothing else. volumes is null when
//     the estate was not measurable at capture, never zero-filled, so "unmeasured" cannot read as
//     "empty".
// The signer's ML-DSA secret is zeroed after signing, matching signedSupportBundle's idiom, so a
// caller must pass a freshly loaded signer.
//
// Kept separate from support.ts: a pure, self-contained leaf with no dependency on buildSupportBundle's
// internals beyond its already-signed output. Callers import it from here directly.
export async function buildBandManifest(
  signed: { bundle: Record<string, unknown>; signature: string; signerFingerprint: string },
  signer: Signer,
  ctBytes: Uint8Array | null,
): Promise<{ manifest: Record<string, unknown>; manifestSignature: string }> {
  // volumes rides only as the well-formed pair (safe integers, the canonical-JSON signability bound);
  // anything else -- a null rollup, an "error"-marked section, a malformed object -- collapses to null.
  const rawVolumes = signed.bundle["volumes"];
  let volumes: { totalProtectedBytes: number; accounts: number } | null = null;
  if (typeof rawVolumes === "object" && rawVolumes !== null) {
    const t = (rawVolumes as Record<string, unknown>)["totalProtectedBytes"];
    const a = (rawVolumes as Record<string, unknown>)["accounts"];
    if (typeof t === "number" && Number.isSafeInteger(t) && typeof a === "number" && Number.isSafeInteger(a)) {
      volumes = { totalProtectedBytes: t, accounts: a };
    }
  }
  // licence: presence plus the engine-held tier, and the tier ONLY when it is a member of the closed
  // tier vocabulary (isTier), so no string outside that set ever reaches the cleartext.
  const rawLicence = signed.bundle["licence"];
  const rawTier = typeof rawLicence === "object" && rawLicence !== null ? (rawLicence as Record<string, unknown>)["tier"] : undefined;
  const manifest: Record<string, unknown> = {
    kind: "downpipe-support-band-manifest",
    v: 1,
    generatedAt: nowIso(),
    ...(ctBytes ? { bodySha256: await sha256Hex(ctBytes) } : {}),
    signerFingerprint: await signerFingerprint({ ed: signer.edPublic, mldsa: signer.mldsaPublic }),
    signerPublic: { ed: b64urlEncode(signer.edPublic), mldsa: b64urlEncode(signer.mldsaPublic) },
    volumes,
    licence: { present: rawLicence != null, ...(isTier(rawTier) ? { tier: rawTier } : {}) },
  };
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, canonicalJSON(manifest));
  signer.mldsaSecret.fill(0);
  return { manifest, manifestSignature: b64urlEncode(sig) };
}
