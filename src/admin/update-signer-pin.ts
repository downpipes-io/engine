import { b64urlDecode } from "../crypto/bytes.ts";
import { parseVerifier } from "../crypto/keys.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import type { Env } from "../env.d.ts";
import { signerFingerprint } from "../format/writer-root.ts";
import type { PostureInput } from "./posture-types.ts";

// The pinned update signer, in one place. fetchAndVerifyChannel (updates.ts) verifies the channel
// signature with parsePinnedUpdateSigner, and GET /admin/status reports the fingerprint of the same
// parse, so the fingerprint the console shows is the key the engine verifies with.

// parsePinnedUpdateSigner parses UPDATE_SIGNER_PUBLIC (base64url of Ed25519 || ML-DSA-87 public) into
// the hybrid verifier. It throws on a malformed value.
export function parsePinnedUpdateSigner(pub: string): HybridVerifier {
  return parseVerifier(b64urlDecode(pub));
}

// updateSignerFingerprint is the edmldsa1 fingerprint (SHA-384 of the public key, the form the recovery
// sheet and the reader use) of the pinned update signer. null when UPDATE_SIGNER_PUBLIC is unset or does
// not parse, which is also when the channel check refuses with key-config.
export async function updateSignerFingerprint(env: Env): Promise<string | null> {
  if (!env.UPDATE_SIGNER_PUBLIC) return null;
  try { // nosemgrep: incident-catch-returns-empty -- the site fault waiver at the handler gives the reason
    return await signerFingerprint(parsePinnedUpdateSigner(env.UPDATE_SIGNER_PUBLIC));
  } catch {
    // site-fault-waiver: src/admin/update-signer-pin.ts:updateSignerFingerprint:catch:1 -- a malformed key is already reported as the key-config channel fault, and null withholds any fingerprint
    return null;
  }
}

// releaseSignerPinMatches compares the operator's declared RELEASE_SIGNER_PIN with the fingerprint of the
// key the engine verifies with. The declared value is trimmed and compared without regard to case. A
// short label or a partial fingerprint does not match. With no verifying key, nothing matches.
export function releaseSignerPinMatches(declared: string, fingerprint: string | null): boolean {
  return fingerprint !== null && declared.trim().toLowerCase() === fingerprint.toLowerCase();
}

// releaseSignerPinWarningText is the one sentence for a declared pin that does not match. The status
// warning and the release-signer-pin posture finding both use it, so the two never disagree. The
// fingerprint is public: a SHA-384 of a public key that is itself a plain-text var.
export function releaseSignerPinWarningText(fingerprint: string | null): string {
  return fingerprint !== null
    ? `RELEASE_SIGNER_PIN is only a label. The engine verifies updates with key ${fingerprint}. Set RELEASE_SIGNER_PIN to that value, or clear it.`
    : "RELEASE_SIGNER_PIN is only a label. The engine has no valid key to verify updates with, because UPDATE_SIGNER_PUBLIC is unset or malformed. Set UPDATE_SIGNER_PUBLIC, or clear RELEASE_SIGNER_PIN.";
}

// releaseSignerPinVerdict is the env-derived slice the router forwards to the posture computation. It is
// undefined when no pin is declared, so the check is not raised.
export async function releaseSignerPinVerdict(env: Env): Promise<{ matches: boolean; fingerprint?: string } | undefined> {
  const declared = env.RELEASE_SIGNER_PIN?.trim();
  if (!declared) return undefined;
  const fingerprint = await updateSignerFingerprint(env);
  return { matches: releaseSignerPinMatches(declared, fingerprint), ...(fingerprint !== null ? { fingerprint } : {}) };
}

// parseReleaseSignerPinSlice bounds the router-forwarded release-signer-pin slice at the DO boundary. A
// fingerprint that is not the edmldsa1 shape is dropped; a garbled slice reads as not declared.
export function parseReleaseSignerPinSlice(raw: unknown): PostureInput["releaseSignerPin"] {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as { matches?: unknown; fingerprint?: unknown };
  if (typeof r.matches !== "boolean") return undefined;
  const fp = typeof r.fingerprint === "string" && /^edmldsa1:[0-9a-f]{96}$/.test(r.fingerprint) ? r.fingerprint : undefined;
  return { matches: r.matches, ...(fp !== undefined ? { fingerprint: fp } : {}) };
}
