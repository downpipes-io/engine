import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { b64urlDecode } from "./crypto/bytes.ts";
import type { HybridRecipientPrivate, HybridRecipientPublic } from "./crypto/kem.ts";
import { parseIdentity } from "./crypto/keys.ts";
import type { HybridVerifier } from "./crypto/sign.ts";
import type { RecipientEntry, Signer } from "./format/writer.ts";

// Load the engine's signing and recipient keys from the account Secrets Store (via env).
// The signer private is the one secret the engine necessarily holds (it signs runs); the
// recipient keys are public. The break-glass PRIVATE is never here: the engine wraps to
// the break-glass public and can never unwrap it.

// The PKCS8 prefix for an Ed25519 raw private seed (OID 1.3.101.112).
const ED25519_PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

// loadSigner parses SIGNER_PRIVATE (base64url ed25519 seed(32) || ML-DSA-87 secret) into
// a Signer: the Ed25519 private becomes a Web Crypto signing key, and the public halves
// are derived for the manifest's recipient/signer fields.
export async function loadSigner(signerPrivateB64: string): Promise<Signer> {
  const raw = b64urlDecode(signerPrivateB64);
  // SIGNER_PRIVATE is ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes. The ML-DSA SEED is
  // stored, not the expanded 4896-byte secret (the same compact form the recipients use for
  // ML-KEM), so the value stays ~86 base64 chars and fits the Cloudflare 5.1 kB text-binding
  // limit; the expanded key is derived here deterministically from the seed.
  if (raw.length !== 64) throw new Error("signer private must be 64 bytes: ed25519 seed(32) || ML-DSA-87 seed(32)");
  const edSeed = raw.subarray(0, 32);
  const mldsa = ml_dsa87.keygen(raw.subarray(32, 64));

  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(edSeed, ED25519_PKCS8_PREFIX.length);
  const edPrivate = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);

  return {
    edPrivate,
    edPublic: ed25519.getPublicKey(edSeed),
    mldsaSecret: mldsa.secretKey,
    mldsaPublic: mldsa.publicKey,
  };
}

// loadRecipientPublic parses a base64url x25519(32) || ML-KEM-1024 ek(1568) public key.
export function loadRecipientPublic(b64: string): HybridRecipientPublic {
  const raw = b64urlDecode(b64);
  if (raw.length !== 1600) throw new Error(`recipient public key is ${raw.length} bytes, want 1600`);
  return { x25519: raw.subarray(0, 32), mlkemEk: raw.subarray(32) };
}

// loadRecipients builds the recipient set from env: the break-glass recipient (always) and an optional
// SECOND recipient, break-glass first.
//
// secondRole exists because the second recipient is not always the operational key. Archives seal to
// break-glass + operational, but the sealed CONTROL-PLANE export seals to break-glass + the config
// recipient (cron/control-plane-pass.ts), and this helper labelled that one "operational" too.
//
// The role is descriptive rather than behavioural: no open path branches on it. It is written into the
// sealed artefact's public recipient list, and the offline reader renders it in the one message a person
// reads at the worst possible moment, "this run needs one of: break-glass dpr1:X, operational dpr1:Y"
// (downpipe/internal/crypto/capsule.go, describeWanted). Telling an operator mid-disaster that their
// configuration export needs the operational key sends them after a key that does not open it and that a
// break-glass-only estate does not have.
//
// The default keeps every archive call site byte-identical; only the control-plane pass passes "config".
export function loadRecipients(breakGlassB64: string, secondB64?: string, secondRole = "operational"): RecipientEntry[] {
  const recipients: RecipientEntry[] = [{ role: "break-glass", pub: loadRecipientPublic(breakGlassB64) }];
  if (secondB64) recipients.push({ role: secondRole, pub: loadRecipientPublic(secondB64) });
  return recipients;
}

// loadIdentity parses a 96-byte recipient private identity (the in-account OPERATIONAL
// key used for the read-back drill). The break-glass private is never loaded in-account.
export function loadIdentity(b64: string): HybridRecipientPrivate {
  return parseIdentity(b64urlDecode(b64));
}

// verifierFrom derives the operator-pinned verifier (the signer public halves) from a
// loaded signer, for the reader to verify against.
export function verifierFrom(signer: Signer): HybridVerifier {
  return { ed: signer.edPublic, mldsa: signer.mldsaPublic };
}

// --- Key-material slot health (support-pack gap G194) -------------------------------------------
//
// After a key-rotation ceremony EVERY backup can fail because one pasted value is wrong. Today the
// pack can only say "signer configured: true" and (for three slots) "malformed: true", so support
// cannot tell WHICH slot is wrong or WHAT is wrong with it: a value pasted in the wrong encoding
// (PEM/base64-standard/hex instead of base64url) is indistinguishable from one that decodes cleanly
// but is the wrong key (a 32-byte seed pasted into the 1600-byte recipient slot, or a 96-byte private
// identity pasted into a public slot).
//
// classifyKeySlot answers both questions with a CLOSED vocabulary and nothing else. It is env-derived
// and pure (no I/O, no DO state): the pack builder calls buildKeyMaterialHealth(env) at pack-build
// time, exactly as buildKeysHealth already recomputes the malformed booleans from env.
//
// REDACTION (binding, no-custody): the classifier NEVER returns key bytes, the pasted value, a byte
// length, a fingerprint of private material, or an exception message. Only the slot id (closed), the
// malform class (closed) and booleans/counts leave this function. The decoders' own error strings do
// carry byte lengths ("recipient public key is 96 bytes, want 1600"), so they are caught and DISCARDED
// here; the class is derived from the shape checks, never from the message.

// KEY_SLOT_IDS is the closed set of key-material slots the engine reads from env. Each maps to exactly
// one env var: signer -> SIGNER_PRIVATE, break-glass -> BREAK_GLASS_PUBLIC, operational ->
// OPERATIONAL_PUBLIC, operational-private -> OPERATIONAL_PRIVATE (the in-account read-back identity).
export const KEY_SLOT_IDS = ["signer", "break-glass", "operational", "operational-private", "config-recipient", "config-recipient-private"] as const;
export type KeySlotId = (typeof KEY_SLOT_IDS)[number];

// KEY_MALFORM_CLASSES is the closed set of "what is wrong with this slot" answers:
//  - bad-encoding: the value is not base64url at all (wrong alphabet, a PEM header, padding, whitespace,
//    a hex paste). The customer pasted the wrong ENCODING of possibly the right key.
//  - wrong-length: it IS base64url and decodes, but not to the byte length this slot requires. The
//    customer pasted a DIFFERENT key (or a truncated one) into this slot. The actual length is NOT
//    reported: it would be an open integer, and the class is all support needs to say "wrong key here".
//  - unusable: it decodes to the right length but the key algorithm still rejects it (a corrupt seed /
//    an unparseable identity). Rare, and the honest answer when neither shape class fits.
export const KEY_MALFORM_CLASSES = ["bad-encoding", "wrong-length", "unusable"] as const;
export type KeyMalformClass = (typeof KEY_MALFORM_CLASSES)[number];

// The exact decoded byte length each slot requires. These are the SAME constants the loaders above
// enforce (signer 64, recipient public 1600, private identity 96), so a slot that classifies clean here
// is a slot the seal path can actually load.
// Exported so tests derive a well-formed value per slot from THIS map rather than restating the lengths.
// A test that hard-codes them drifts silently the moment a slot is added, which is exactly what happened.
export const SLOT_BYTES: Record<KeySlotId, number> = {
  signer: 64, // ed25519 seed(32) || ML-DSA-87 seed(32)
  "break-glass": 1600, // x25519(32) || ML-KEM-1024 ek(1568)
  operational: 1600,
  "operational-private": 96, // x25519 scalar(32) || ML-KEM seed(64)
  // The config recipient uses the SAME formats as any other recipient. It exists so the engine can open
  // its own configuration export without holding a key that opens customer archives.
  "config-recipient": 1600,
  "config-recipient-private": 96,
};

// KeySlotHealth is the per-slot verdict the pack carries. malformed/malformClass are present only when
// the slot is configured AND bad, so an unconfigured slot stays honestly silent (configured:false) and
// a healthy one carries no class at all.
export interface KeySlotHealth {
  slot: KeySlotId;
  configured: boolean;
  malformed?: true;
  malformClass?: KeyMalformClass;
}

// classifyKeySlot decides one slot's health from its raw env string. It runs the real decode + the real
// length check, and (for the two slots with a further algorithmic parse) the real parse, so the verdict
// cannot drift from what the seal/drill path would do. Every throw is swallowed: this is a diagnostic,
// it must never itself break a pack build.
export function classifyKeySlot(slot: KeySlotId, raw: string | undefined): KeySlotHealth {
  if (!raw) return { slot, configured: false };
  let bytes: Uint8Array;
  try {
    bytes = b64urlDecode(raw);
  } catch {
    // b64urlDecode rejects a non-base64url alphabet / an impossible length mod 4. Message discarded.
    return { slot, configured: true, malformed: true, malformClass: "bad-encoding" };
  }
  if (bytes.length !== SLOT_BYTES[slot]) {
    return { slot, configured: true, malformed: true, malformClass: "wrong-length" };
  }
  try {
    // Right length: run the slot's real structural parse. The public slots are pure subarray splits once
    // the length holds, so this only ever fires for a key the algorithm itself rejects.
    if (slot === "break-glass" || slot === "operational") loadRecipientPublic(raw);
    if (slot === "operational-private") parseIdentity(bytes);
  } catch {
    return { slot, configured: true, malformed: true, malformClass: "unusable" };
  }
  return { slot, configured: true };
}

// KeyMaterialHealth is the pack-ready block: the signer slot on its own (it is the one slot whose loss
// stops every run) plus the recipient slots as a counted set, so the pack can say "2 recipient slots
// configured, 1 malformed (operational, wrong-length)" without ever naming a value.
export interface KeyMaterialHealth {
  signer: KeySlotHealth;
  recipients: {
    configuredCount: number;
    malformedCount: number;
    malformedSlots: KeySlotId[];
    slots: KeySlotHealth[];
  };
}

// buildKeyMaterialHealth classifies every key slot from env. Pure, synchronous and allocation-cheap;
// the pack builder merges it into the keys section (pack-inventory 4.20) alongside the existing
// fingerprints. It is the ONLY place the signer's and the operational slots' malform classes come from.
export function buildKeyMaterialHealth(env: {
  SIGNER_PRIVATE?: string;
  BREAK_GLASS_PUBLIC?: string;
  OPERATIONAL_PUBLIC?: string;
  OPERATIONAL_PRIVATE?: string;
}): KeyMaterialHealth {
  const signer = classifyKeySlot("signer", env.SIGNER_PRIVATE);
  const slots: KeySlotHealth[] = [
    classifyKeySlot("break-glass", env.BREAK_GLASS_PUBLIC),
    classifyKeySlot("operational", env.OPERATIONAL_PUBLIC),
    classifyKeySlot("operational-private", env.OPERATIONAL_PRIVATE),
  ];
  const configured = slots.filter((s) => s.configured);
  const malformed = configured.filter((s) => s.malformed === true);
  return {
    signer,
    recipients: {
      configuredCount: configured.length,
      malformedCount: malformed.length,
      malformedSlots: malformed.map((s) => s.slot),
      slots,
    },
  };
}
