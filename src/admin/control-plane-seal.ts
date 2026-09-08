// The SEALED control-plane export. The plaintext export (control-plane.ts) is signed but written as
// cleartext JSON to the destination bucket, so a bucket READER sees the operator roster, destination
// endpoints/topology and the IdP/notify inventories. Sealing encrypts the export BODY to break-glass plus the
// CONFIG recipient (NOT the archive recipient set: config recovery is deliberately decoupled from the key
// that opens archives, see cron/control-plane-pass.ts), so a bucket reader sees only
// recipient fingerprints and a tiny plaintext header. It reuses the VERIFIED, archive-interoperable capsule +
// stream primitives, so the offline Go reader opens a sealed export with the SAME crypto it uses for archives.
//
// HARD CONSTRAINT (adversarial review): identity.key NEVER enters the browser. The engine opens with the
// CONFIG-RECIPIENT private (auto-heal, in EITHER posture); the offline Go reader opens with the break-glass identity;
// the console only VERIFIES the detached signature (a public key), it never unseals.
//
// The byte layout is documented alongside this module.

import { b64urlDecode, b64urlEncode, hexEncode, utf8 } from "../crypto/bytes.ts";
import { type CapsuleWrap, openCapsule, sealToRecipients } from "../crypto/capsule.ts";
import type { HybridRecipientPrivate } from "../crypto/kem.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type HybridVerifier, type HybridVerifyVerdict, hybridSign, hybridVerify, hybridVerifyDetailed } from "../crypto/sign.ts";
import { openStream, sealStream } from "../crypto/stream.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { RecipientEntry, Signer } from "../format/writer-root.ts";
import { assertNoPlaintextSecretInExport, type ControlPlaneExport, isControlPlaneExport, serialiseControlPlaneExport, signControlPlaneExport } from "./control-plane.ts";

// SEALED_EXPORT_V pins the sealed layout. It is INDEPENDENT of the plaintext export's `v:1`: a sealed export
// is a different artefact (a `.sealed.json` object beside the plaintext `.json`), and a reader tells them
// apart by the object key + this version. Additive: the plaintext layout stays valid + readable forever.
export const SEALED_EXPORT_V = 1 as const;

// The two domain-separated AADs. Fixed labels, DISTINCT from every archive AAD (the archive's master capsule
// binds a per-run key-commitment hex; a fixed label can never equal it), so an export capsule/body can never
// be cross-opened as an archive's and vice versa. The Go reader uses the SAME byte strings.
const EXPORT_CAPSULE_AAD = utf8("downpipes/control-plane-export/capsule/v1");
const EXPORT_BODY_AAD = utf8("downpipes/control-plane-export/body/v1");

// A capsule wrap as it rides in the sealed artefact JSON (b64url), mirroring the archive root's masterCapsule
// entries EXACTLY (fingerprint + kemCiphertext + sealed), so the Go reader's existing wrap parser reads it.
export interface SealedCapsuleWrapJSON {
  fingerprint: string;
  kemCiphertext: string; // b64url of the 1600-byte KEM ciphertext
  sealed: string; // b64url of the STREAM-sealed 32-byte content key
}

// A recipient descriptor in the sealed artefact: the role + fingerprint of an identity that can open it. Public
// metadata (no key), so a holder can see whether their identity is a recipient without decrypting.
export interface SealedRecipientDesc {
  role: string; // "break-glass" | "config" for a control-plane export; "break-glass" | "operational" for an archive
  fingerprint: string; // dpr1:...
}

// SealedControlPlaneExport is the whole sealed artefact (written as `_RECOVERY/CONTROL-PLANE/<v>-<iso>.sealed.json`).
// The plaintext HEADER carries ONLY the four fields the pre-decrypt paths need (selection, staleness, the
// change-gate, and the cross-account import decision); everything else lives sealed in `body`. The detached
// `.sig` covers canonicalJSON(this whole object), so verification precedes decryption always.
export interface SealedControlPlaneExport {
  v: typeof SEALED_EXPORT_V;
  exportedAt: string; // header (plaintext): staleness/selection
  configVersion: number; // header: the change-gate / generation key + naming
  engineAccountId: string | null; // header: the cross-account import branch decides BEFORE decrypt
  recipients: SealedRecipientDesc[]; // header: who can open (public fingerprints)
  capsule: SealedCapsuleWrapJSON[]; // the content key sealed to each recipient (EXPORT_CAPSULE_AAD)
  body: string; // b64url( sealStream(contentKey, canonicalJSON(inner ControlPlaneExport), nonce, EXPORT_BODY_AAD) )
  // bodyHash is `sha384:<hex>` of the PLAINTEXT bodyBytes (serialiseControlPlaneExport(inner)), BEFORE
  // sealing. It rides in the plaintext header, so it is covered by the SAME detached signature as everything
  // else in this object, and a verifier can check it WITHOUT decrypting `body`.
  //
  // WHY. A browser that unseals this artefact locally (identity.key never leaves it) recovers the
  // inner ControlPlaneExport plaintext, but that plaintext carries no signature of its own -- the export was
  // sealed, not signed-then-sealed, so the ONLY detached signature on disk covers the SEALED object, not the
  // inner bytes (buildControlPlaneArtefactToWrite writes ONE artefact + ONE signature per generation). Without
  // this field, an engine asked to import that recovered plaintext would have no way to confirm it is what the
  // signed artefact actually committed to, short of holding the same recipient private the browser just used
  // (which the whole point of browser-side unseal is to keep OUT of the engine). bodyHash closes that gap with
  // a public-key-only check: re-hash the candidate plaintext, compare to this pinned value, done. Optional so
  // an artefact sealed before this field existed still passes the SHAPE gate (isSealedControlPlaneExport does
  // not require it); the browser-unseal import route DOES require it, and refuses an artefact that lacks it
  // with an honest "written before hash-pinning, wait for the next export or use the offline reader" message
  // rather than silently trusting an unpinned plaintext.
  //
  // TRADE-OFF, STATED PLAINLY: bodyHash is a HASH COMMITMENT sitting in the
  // PLAINTEXT header of an artefact whose whole reason for existing is that a bucket reader must not learn
  // the body's content. A bucket reader -- exactly the party sealing exists to defend against -- who can
  // GUESS an exact candidate plaintext (the full canonicalJSON byte string: every downpipe id, destination
  // config, role, IdP connection, notify channel and timestamp, in the exact sorted-key, no-whitespace form
  // serialiseControlPlaneExport produces) can hash that guess and compare it to this field, for FREE, without
  // ever holding a recipient private key. That is a genuine confirmation oracle this field adds that did not
  // exist before it: without bodyHash a bucket reader had no way to check a guess against anything at all.
  // Accepted rather than closed, because closing it (e.g. binding the hash to something only a holder of a
  // wrapped key could compute) would reintroduce the exact problem this field exists to solve. The residual
  // risk is judged small, not zero: (1) the export carries NO secret by construction (assertNoPlaintextSecretInExport
  // is asserted on it both before sealing and again on the unsealed candidate), so a correct guess confirms
  // only non-secret configuration shape, never a credential; (2) the guess space is the WHOLE canonicalJSON
  // byte string, not one field -- getting every downpipe id, every destination's account/bucket naming, every
  // role and timestamp byte-exact is a high-entropy target for anything but a trivial estate, and ANY single
  // differing byte (including field ORDER, which canonicalJSON fixes but an attacker must still reproduce)
  // fails the hash silently, giving no partial credit and no oracle for narrowing a guess field-by-field. It is
  // not a zero-knowledge claim and must never be described as one.
  bodyHash?: string;
}

// serialiseSealedControlPlaneExport is the ONE canonical byte form, used for BOTH the detached signature and an
// external re-verify. canonicalJSON sorts object keys, so the bytes are reproducible across sign + verify.
export function serialiseSealedControlPlaneExport(s: SealedControlPlaneExport): Uint8Array {
  return canonicalJSON(s);
}

// sealControlPlaneExport encrypts the plaintext export body to the given recipients and returns the sealed
// artefact (WITHOUT the signature; the caller signs serialiseSealedControlPlaneExport(result)). A fresh random
// 32-byte content key seals the body (one AES-GCM stream) and is itself sealed to each recipient. Defence in
// depth: it re-asserts the no-custody invariant on the inner export before sealing, so a plaintext secret can
// never enter even the sealed body. nonceFor supplies fresh STREAM_NONCE_SIZE (16-byte) payload nonces
// (crypto.getRandomValues(16) in prod) -- the size sealStream prepends and openStream reads back; a wrong
// size breaks the round-trip.
export async function sealControlPlaneExport(
  inner: ControlPlaneExport,
  recipients: RecipientEntry[],
  nonceFor: () => Uint8Array,
): Promise<SealedControlPlaneExport> {
  if (recipients.length === 0) throw new Error("cannot seal a control-plane export to zero recipients");
  assertNoPlaintextSecretInExport(inner);
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    const bodyBytes = serialiseControlPlaneExport(inner);
    const bodyHash = `sha384:${hexEncode(await sha384(bodyBytes))}`;
    const sealedBody = await sealStream(contentKey, bodyBytes, nonceFor(), EXPORT_BODY_AAD);
    // sealToRecipients yields wraps in recipient order, so wraps[i] corresponds to recipients[i].
    const wraps = await sealToRecipients(contentKey, recipients.map((r) => r.pub), EXPORT_CAPSULE_AAD, nonceFor);
    return {
      v: SEALED_EXPORT_V,
      exportedAt: inner.exportedAt,
      configVersion: inner.configVersion,
      engineAccountId: inner.engineAccountId,
      recipients: recipients.map((r, i) => ({ role: r.role, fingerprint: wraps[i]!.fingerprint })),
      capsule: wraps.map((w) => ({ fingerprint: w.fingerprint, kemCiphertext: b64urlEncode(w.kemCiphertext), sealed: b64urlEncode(w.sealed) })),
      body: b64urlEncode(sealedBody),
      bodyHash,
    };
  } finally {
    contentKey.fill(0); // best-effort zeroize of the content key copy this function held
  }
}

// openSealedControlPlaneExport recovers the inner plaintext export from a sealed artefact, given a recipient
// PRIVATE identity: the engine's CONFIG-RECIPIENT private for auto-heal, or the offline break-glass identity
// in the Go reader. Those are the two publics the export is sealed to (control-plane-pass.ts:202,
// loadRecipients(BREAK_GLASS_PUBLIC, CONFIG_RECIPIENT_PUBLIC)), and neither is the operational key.
//
// This comment said "operational private" until, and the parameter below was named for it. That
// is not a cosmetic slip: an audit of what the operational key still buys read this header, concluded a
// break-glass-only estate could not self-heal its configuration after a Durable Object wipe, and had a docs
// change half-written before the CALL SITE was checked. Auto-heal is gated on CONFIG_RECIPIENT_PRIVATE,
// which the break-glass-only switch does not remove (router-keys.ts deletes only the two OPERATIONAL
// secrets), so it runs in either posture.
//
// It opens the capsule for the held identity, decrypts the body, and re-asserts the export shape +
// no-custody. It does NOT verify the signature; the caller verifies serialiseSealedControlPlaneExport against
// the signer BEFORE calling (verify-precedes-decrypt), exactly as the reconcile/import routes already do.
export async function openSealedControlPlaneExport(
  sealed: SealedControlPlaneExport,
  priv: HybridRecipientPrivate,
): Promise<ControlPlaneExport> {
  const wraps: CapsuleWrap[] = sealed.capsule.map((w) => ({ fingerprint: w.fingerprint, kemCiphertext: b64urlDecode(w.kemCiphertext), sealed: b64urlDecode(w.sealed) }));
  const contentKey = await openCapsule(wraps, priv, EXPORT_CAPSULE_AAD);
  try {
    const bodyBytes = await openStream(contentKey, b64urlDecode(sealed.body), EXPORT_BODY_AAD, 0);
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyBytes));
    } catch {
      throw new Error("the unsealed control-plane export body is not valid JSON");
    }
    if (!isControlPlaneExport(parsed)) throw new Error("the unsealed body is not a control-plane export artefact");
    assertNoPlaintextSecretInExport(parsed);
    return parsed as ControlPlaneExport;
  } finally {
    contentKey.fill(0);
  }
}

// signSealedControlPlaneExport attaches a DETACHED hybrid signature (b64url) over the canonical sealed bytes.
export async function signSealedControlPlaneExport(signer: Signer, sealed: SealedControlPlaneExport): Promise<string> {
  return b64urlEncode(await hybridSign(signer.edPrivate, signer.mldsaSecret, serialiseSealedControlPlaneExport(sealed)));
}

// verifySealedControlPlaneSignature re-derives the canonical bytes and verifies BOTH hybrid halves against the
// operator-pinned (or kit-supplied) verifier. Total: a malformed signature decodes to nothing and fails closed.
export async function verifySealedControlPlaneSignature(sealed: SealedControlPlaneExport, sig: string, verifier: HybridVerifier): Promise<boolean> {
  try {
    return await hybridVerify(verifier, serialiseSealedControlPlaneExport(sealed), b64urlDecode(sig));
  } catch {
    return false;
  }
}

// verifySealedControlPlaneSignatureDetailed is verifySealedControlPlaneSignature with the verdict kept,
// mirroring control-plane.ts's verifyControlPlaneSignatureDetailed for the plaintext export: the same five-
// world crypto verdict (a damaged .sig FILE, a damaged KEY, a genuinely altered artefact, or one damaged half
// of a hybrid key pair that PROVES the other half -- and therefore the whole sealed object, including the
// body ciphertext and bodyHash -- is intact) applies unchanged to the sealed wrapper's own signature. The
// browser-unseal import route (router-identity.ts POST /control-plane/import-sealed) uses this instead of the
// boolean form so a customer reading a refusal off a fresh, empty engine gets the same honest, five-way split
// the plaintext estate-import path already gives them, not a single coalesced "signature invalid".
export async function verifySealedControlPlaneSignatureDetailed(sealed: SealedControlPlaneExport, sig: string, verifier: HybridVerifier): Promise<HybridVerifyVerdict> {
  let bytes: Uint8Array;
  try {
    bytes = b64urlDecode(sig);
  } catch {
    return "sig-decode";
  }
  return await hybridVerifyDetailed(verifier, serialiseSealedControlPlaneExport(sealed), bytes);
}

// ControlPlaneArtefact is the recovery artefact the cron writes for one export generation: the object body,
// its detached signature text, and whether it is the SEALED form (which changes the bucket key suffix from
// `.json` to `.sealed.json`).
export interface ControlPlaneArtefact {
  sealed: boolean;
  bodyBytes: Uint8Array;
  sigText: string;
}

// buildControlPlaneArtefactToWrite decides the recovery artefact for one export generation, the single place
// the seal-or-plaintext choice lives (so the cron is a thin caller). recipients === undefined / empty => the
// SIGNED PLAINTEXT (sealing OFF; byte-identical to the pre-S5 cron path). recipients supplied => the SEALED
// artefact (body sealed to the recipients, the whole sealed object signed). Pure + testable; the cron supplies
// the signer, the recipient set (from loadRecipients) and nonceFor.
//
// BOTH branches assert no-custody before producing bytes. The sealed branch already got this for free
// (sealControlPlaneExport asserts internally, before it ever touches the plaintext). The plaintext branch did
// not: it is the exact bytes control-plane-pass.ts writes UNENCRYPTED to the customer's own destination
// bucket, reachable whenever sealing is off (the default state for a new customer -- no break-glass recipient
// configured yet -- and the documented CONTROL_PLANE_EXPORT_SEALING_DISABLED escape hatch), so a future
// projection regression that let a live secret ride in ControlPlaneExport would have written it to disk in
// the clear with zero defence-in-depth. The assertion is deliberately re-run here rather than trusted from an
// earlier call: this function has no caller-supplied guarantee the export was already checked.
export async function buildControlPlaneArtefactToWrite(
  exp: ControlPlaneExport,
  signer: Signer,
  recipients: RecipientEntry[] | undefined,
  nonceFor: () => Uint8Array,
): Promise<ControlPlaneArtefact> {
  if (recipients === undefined || recipients.length === 0) {
    assertNoPlaintextSecretInExport(exp);
    return { sealed: false, bodyBytes: serialiseControlPlaneExport(exp), sigText: await signControlPlaneExport(signer, exp) };
  }
  const s = await sealControlPlaneExport(exp, recipients, nonceFor);
  return { sealed: true, bodyBytes: serialiseSealedControlPlaneExport(s), sigText: await signSealedControlPlaneExport(signer, s) };
}

// unsealAndResignForAutoHeal is the crypto step the auto-heal runs AFTER it has verified a sealed export's
// signature (verify-precedes-decrypt stays in the caller for its distinct refusal code): UNSEAL the body with
// the CONFIG-RECIPIENT private (openSealedControlPlaneExport re-asserts the export shape + no-custody), then
// RE-SIGN the recovered inner with the engine signer, so the DO's apply-staged -- which re-verifies a
// PLAINTEXT-export signature and cannot itself unseal (no key in the DO) -- accepts the staged record. Same
// signer, so the staged inner is authentic. Throws on a wrong or absent config-recipient key, or a malformed
// body. Pure + testable.
//
// The parameter was called operationalPrivate until and never held that key: the sole caller
// passes env.CONFIG_RECIPIENT_PRIVATE (control-plane-pass.ts:593,624). See openSealedControlPlaneExport
// above for what the misnomer cost.
export async function unsealAndResignForAutoHeal(
  parsedSealed: SealedControlPlaneExport,
  signer: Signer,
  configRecipientPrivate: HybridRecipientPrivate,
): Promise<{ exp: ControlPlaneExport; innerSig: string }> {
  const exp = await openSealedControlPlaneExport(parsedSealed, configRecipientPrivate);
  const innerSig = await signControlPlaneExport(signer, exp);
  return { exp, innerSig };
}

// sealedArtefactKey turns a plaintext artefact key (`…-<iso>.json`) into its sealed sibling
// (`…-<iso>.sealed.json`), the distinct object key a sealed generation is written under.
export function sealedArtefactKey(plaintextKey: string): string {
  return plaintextKey.replace(/\.json$/, ".sealed.json");
}

// isSealedControlPlaneExport is a shape gate for a parsed (untrusted) sealed artefact read back from a bucket,
// before its signature is verified. It checks the version pin + the structural fields; full validation is the
// signature verify + the openSeal path (which never trusts the bytes until the signature verifies anyway).
export function isSealedControlPlaneExport(v: unknown): v is SealedControlPlaneExport {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.v === SEALED_EXPORT_V &&
    typeof o.exportedAt === "string" &&
    typeof o.configVersion === "number" &&
    Array.isArray(o.recipients) &&
    Array.isArray(o.capsule) &&
    (o.capsule as unknown[]).length > 0 &&
    typeof o.body === "string" &&
    (o.body as string).length > 0
  );
}
