// The WebAuthn / passkey CORE for the engine: the platform's OWN identity provider, independent
// of Cloudflare Access (which is not free over 50 users). This is the free, self-contained
// multi-user front door. It owns NO session issuance and NO transport; it is the pure verification
// and parsing core that the scheduler DO (the storage authority) and the router (the HTTP surface)
// drive. The DO stores the user/credential/challenge records and calls verifyRegistration and
// verifyAssertion here; the router exposes the four /admin/auth/* endpoints. The verified identity a
// successful login yields is the credential's bound email, resolved against the same `role:` table the
// Access path uses, so a passkey caller and an Access caller share one role model and one bootstrap.
//
// SECURITY DISCIPLINE:
//  - Every byte parsed from the authenticator (attestationObject, authenticatorData, the COSE key,
//    the DER signature) is BOUNDS-CHECKED before it is read; a truncated or malformed structure is a
//    typed rejection, never an out-of-range read or a thrown TypeError that leaks a stack.
//  - The challenge is compared in CONSTANT TIME and CONSUMED (single-use) by the DO; this module
//    only computes the comparison, the DO owns the consume so the read-modify-write is atomic there.
//  - The relying-party id hash, the origin, the clientDataJSON type, and the user-present flag are
//    all verified to the WebAuthn L3 server requirements (sections 7.1 step 7+ and 7.2 step 11+).
//  - The assertion signature is verified over (authenticatorData || SHA-256(clientDataJSON)) with the
//    stored COSE public key via Web Crypto: ES256 is ECDSA P-256/SHA-256 (the WebAuthn ASN.1/DER
//    signature is converted to the raw r||s Web Crypto wants), RS256 is RSASSA-PKCS1-v1_5/SHA-256.
//  - Clone detection: an asserted signCount that is not strictly greater than the stored one (unless
//    both are zero, the legitimate "authenticator does not maintain a counter" case) is rejected as a
//    possible cloned authenticator.
//  - Client-facing failures are COARSE reasons only; the raw detail goes to console.error with an
//    opaque FNV-1a error id, matching the engine's existing errId pattern (restore.ts).
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no Node built-ins,
// no enums, explicit field declarations. The pure parsers/verifiers are exercised directly by the
// validator with a real P-256 keypair, so the verification path under test is the production one.

import { ab, b64urlDecode, b64urlEncode, constantTimeEqual } from "../crypto/bytes.ts";
import { parseAuthData, parseClientData } from "./passkey-authdata.ts";
import { CborReader, COSE_ES256, COSE_RS256, mapGetText, parseCoseKey, verifySignature } from "./passkey-cose.ts";
// The passkey core is split across sibling modules so each stays a coherent unit under 500 lines:
//   - passkey-types.ts: the shared PasskeyError / PasskeyReason / errId (the leaf).
//   - passkey-cose.ts: the bounded CBOR decoder, the COSE_Key parse, and the import + signature verify.
//   - passkey-authdata.ts: the authenticatorData + clientDataJSON parsers.
// This module keeps the records, the ceremonies (verifyRegistration / verifyAssertion), and the begin-endpoint
// helpers, and RE-EXPORTS the moved public surface so every importer of passkey.ts (index.ts, the scheduler
// DO, the passkey validator) keeps working unchanged.
import { PasskeyError } from "./passkey-types.ts";

export type { AuthData, ClientData } from "./passkey-authdata.ts";
export { parseAuthData, parseClientData } from "./passkey-authdata.ts";
export type { CoseKey } from "./passkey-cose.ts";
export { COSE_ES256, COSE_RS256, derEcdsaToRaw, parseCoseKey, verifySignature } from "./passkey-cose.ts";
export type { PasskeyReason } from "./passkey-types.ts";
export { errId, PasskeyError, StoredKeyCorruptError } from "./passkey-types.ts";

// sha256 is the WebAuthn-mandated hash (the rpIdHash, the clientDataJSON hash, and the user-handle
// derivation all use SHA-256, not the archive format's SHA-384). The engine's crypto/primitives.ts is
// SHA-384 only, so this is the one SHA-256 helper, kept local to the passkey core (it is used nowhere
// else). Web Crypto's digest is identical in the Workers runtime and Node, so the same code runs in
// production and under the offline validator.
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", ab(data)));
}

// utf8 is the one module-level TextEncoder reused by every encode in this file (the user-handle label,
// the email and the rpId), matching the pre-encoded USER_HANDLE_LABEL pattern: a TextEncoder is stateless
// and reusable, so allocating one per call is unnecessary.
const utf8 = new TextEncoder();

// ---- Stored record shapes (held in the scheduler DO) -------------------------------------------
// PasskeyUser is the per-email account record (DO key `passkeyUser:<email>`). It carries only the
// canonical email, the display name the operator chose at registration, and the creation time. No
// secret, no key material; redaction-safe like the role table. The stable user handle the WebAuthn
// `user.id` carries is DERIVED from the email (userHandleFor), not stored, so it is reproducible and
// does not have to be persisted separately.
export interface PasskeyUser {
  readonly email: string;
  readonly displayName: string;
  readonly createdAt: string; // RFC-3339 UTC millis, matching the engine's nowMillisISO form
}

// PasskeyCred is one registered credential (DO key `passkeyCred:<credIdB64url>`). credentialId is the
// raw credential id bytes; cosePublicKey is the raw COSE_Key bytes exactly as extracted from the
// attestation authData (re-decoded at verify time, never trusted as pre-parsed); alg is the COSE
// algorithm identifier (-7 ES256 or -257 RS256); signCount is the last-seen authenticator counter (the
// clone-detection high-water mark); transports is the client-reported transport hint list (advisory,
// for the next get()'s allowCredentials); aaguid is the authenticator model id (16 bytes, advisory).
// It carries the PUBLIC key only; a public key is not a secret, but the record is still redaction-safe
// (no private material can exist here). Stored as base64url strings for the byte fields so it round-
// trips through DO JSON storage faithfully.
export interface PasskeyCred {
  readonly credentialId: string; // base64url(raw credential id)
  readonly email: string; // the canonical email this credential authenticates
  readonly cosePublicKey: string; // base64url(raw COSE_Key bytes)
  readonly alg: number; // COSE alg id: -7 (ES256) or -257 (RS256)
  readonly signCount: number; // last-seen authenticator signature counter (clone-detection high-water mark)
  readonly transports: string[]; // advisory client transport hints (usb/nfc/ble/internal/hybrid)
  readonly aaguid: string; // base64url(16-byte AAGUID); advisory authenticator-model id
  readonly createdAt: string; // RFC-3339 UTC millis
  // THE USABILITY WITNESS (PASSKEY-OWNER-ENROLLED-COUNTS-CREDENTIALS). Every other field on this
  // record is unchanged by the destruction of the authenticator holding the private half, which is why
  // `passkeyOwnerEnrolled` could read true on seven credentials that cannot produce an assertion. These two
  // fields are the only ones on the record whose presence is a PROOF rather than an inference: they are
  // written ONLY after verifyAssertion has returned, i.e. only after a signature over server-chosen challenge
  // bytes has verified under this credential's stored public key. That is proof of possession of the private
  // half at `lastAssertedAt`, on the same footing as the recovery MAC witness.
  //
  // Read them with the limit stated: they prove possession AT A MOMENT, not possession NOW, and their ABSENCE
  // proves nothing at all (see `witnessSince` on the org record and the gating note in lockoutPreflight).
  // They are advisory-only today and are NOT an input to any verdict.
  readonly lastAssertedAt?: string; // RFC-3339 UTC millis of the last VERIFIED assertion; absent = never, or predates the witness
  readonly lastAssertedVia?: PasskeyAssertionCeremony; // which ceremony produced that verified assertion
}

// PasskeyAssertionCeremony names the two ceremonies that run a full verifyAssertion against a stored
// credential: the login finish (an assertion that establishes a session) and the step-up finish (an
// assertion that unlocks one sensitive action). Both are proofs of possession of equal strength; they are
// distinguished only so an operator reading the witness can tell which path last demonstrated the key.
export type PasskeyAssertionCeremony = "login" | "stepup";

// PasskeyOwnerEvidence is the closed, redaction-safe enum lockoutPreflight reports alongside the unchanged
// `passkeyOwnerEnrolled` boolean. It never names an email, a credential or a count. See lockoutPreflight for
// what each member means and why none of them is a verdict input today.
export type PasskeyOwnerEvidence = "no-credential" | "demonstrated" | "never-asserted" | "unknown";

// PasskeyChallenge is the server-issued, single-use, short-TTL challenge bound to an operation (DO key
// `passkeyChallenge:<scope>`). scope is `reg:<email>` for registration (bound to the email so a
// registration challenge cannot be replayed for a different account) and `login:<id>` for login (bound
// to a fresh opaque id, since the asserting credential, and thus the email, is not known until the
// finish). challenge is base64url(32 random bytes); createdAt/expiresAt are epoch ms. The DO consumes
// it (deletes it) on first use inside the same read-modify-write as the verification, so it is strictly
// single-use even under a concurrent replay.
export interface PasskeyChallenge {
  readonly challenge: string; // base64url(32 random bytes)
  readonly scope: string; // "reg:<email>" or "login:<id>"
  readonly createdAt: number; // epoch ms
  readonly expiresAt: number; // epoch ms (createdAt + CHALLENGE_TTL_MS)
}

// PasskeyInvite is a SINGLE-USE, email-BOUND, TTL'd registration invite (DO key `passkeyInvite:<token>`).
// It is the proof that an Owner/access-admin authorised a SPECIFIC email to enrol a passkey: when a role
// is granted to an email that has no credential yet, the DO mints one of these and embeds the token in the
// role-invite email's registration link. A non-bootstrap, non-self-add registration MUST present a valid
// invite token; the bound email is taken FROM this record (never the client field), and the record is
// consumed (deleted) on a successful registration so the link works exactly once. It carries no secret and
// no key material: the token is an unguessable random id (the lookup key) and the email is the customer's
// own people data. createdAt/expiresAt are epoch ms.
export interface PasskeyInvite {
  readonly email: string; // the canonical email this invite authorises (the bound identity, not a client claim)
  readonly createdAt: number; // epoch ms
  readonly expiresAt: number; // epoch ms (createdAt + INVITE_TTL_MS)
}

// INVITE_TOKEN_BYTES is the registration-invite token length (32 random bytes, base64url), matching the
// challenge/secret-store 32-byte standard. INVITE_TTL_MS bounds how long an invite link is usable before
// the DO treats it as expired (7 days): long enough for a person to receive the email and enrol at their
// convenience, short enough that a leaked/stale link does not stay live indefinitely.
export const INVITE_TOKEN_BYTES = 32;
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// BootstrapInvite is the SINGLE-ACTIVE, email-BOUND, TTL'd FIRST-OWNER invite (DO key `bootstrapInvite`,
// one fixed slot: re-minting overwrites, so at most one link is live). It is the email-link counterpart of
// the ADMIN_TOKEN bootstrap proof: the engine mints it ONLY while the role table is empty and the
// bootstrap latch is unset, and emails the link ONLY to the deploy-time-pinned BOOTSTRAP_OWNER_EMAIL
// (never a client-supplied address), so redeeming it proves control of the inbox the deployer pinned when
// they proved control of the account. The bound email is taken FROM this record, the record is consumed
// (deleted) on a successful registration, and the bootstrapConsumed latch then closes the path for good.
// Unlike PasskeyInvite the token is stored IN the record (a fixed slot, not a token-keyed row) and is
// compared constant-time at peek/consume.
export interface BootstrapInvite {
  readonly token: string; // the unguessable random capability (base64url, INVITE_TOKEN_BYTES of CSPRNG)
  readonly email: string; // the deploy-time-pinned owner email this invite enrols (never a client claim)
  readonly createdAt: number; // epoch ms
  readonly expiresAt: number; // epoch ms (createdAt + BOOTSTRAP_INVITE_TTL_MS)
}

// BOOTSTRAP_INVITE_TTL_MS bounds the first-Owner link (24 hours): a first-run link should be redeemed the
// same day, and a re-send is one click on the sign-in screen (which also replaces the single slot), so it
// is deliberately much shorter than the 7-day teammate invite for a strictly stronger grant (Owner).
export const BOOTSTRAP_INVITE_TTL_MS = 24 * 60 * 60 * 1000;

// CHALLENGE_BYTES is the challenge length (32 random bytes). The WebAuthn spec requires at least 16
// bytes of entropy; 32 is the conventional, comfortable margin and matches the engine's other 32-byte
// random values (the secret-store standard). CHALLENGE_TTL_MS bounds how long an issued challenge is
// usable before the DO treats it as expired (two minutes), short enough to bound a stolen-challenge
// window yet long enough for a human to complete the authenticator gesture.
export const CHALLENGE_BYTES = 32;
export const CHALLENGE_TTL_MS = 2 * 60 * 1000;

// ---- Stable user handle ------------------------------------------------------------------------
// userHandleFor derives the stable, opaque 32-byte WebAuthn user handle for an email. The handle must
// be stable for an account (so re-registration targets the same user) and must NOT be the raw email
// (the spec says the user handle is an opaque id, not PII). We derive it as SHA-256("downpipes:passkey:
// user:v1" || email): deterministic, opaque, and stable, with a product-scoped domain label so it
// cannot collide with any other SHA-256 use. It is returned as base64url for transport in the creation
// options. (This is an IDENTIFIER, not a secret; SHA-256 is used for stable opacity, not confidentiality.)
const USER_HANDLE_LABEL = utf8.encode("downpipes:passkey:user:v1");
export async function userHandleFor(email: string): Promise<string> {
  const emailBytes = utf8.encode(email);
  // The explicit two-part concatenation (label || email) is intentional: it keeps the domain-separation
  // prefix and the email as visibly distinct byte runs, so a future v2 label change is an obvious edit of
  // USER_HANDLE_LABEL rather than a hidden string-template join.
  const input = new Uint8Array(USER_HANDLE_LABEL.length + emailBytes.length);
  input.set(USER_HANDLE_LABEL, 0);
  input.set(emailBytes, USER_HANDLE_LABEL.length);
  return b64urlEncode(await sha256(input));
}

// ---- The two verification entry points the DO drives -------------------------------------------
// RegistrationInput is what verifyRegistration needs: the raw clientDataJSON and attestationObject
// bytes (decoded from the base64url the client sent), the expected challenge (the stored single-use
// challenge, base64url), the expected origin (CONSOLE_ORIGIN), and the expected rp.id (the engine host).
export interface RegistrationInput {
  readonly clientDataJSON: Uint8Array;
  readonly attestationObject: Uint8Array;
  readonly expectedChallenge: string; // base64url
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
}

// VerifiedRegistration is what a successful verifyRegistration yields: the raw credential id, the raw
// COSE public-key bytes (stored verbatim, re-parsed on every login), the alg, the initial signCount, and
// the AAGUID. The DO persists these into a PasskeyCred. No secret leaves here.
export interface VerifiedRegistration {
  readonly credentialId: Uint8Array;
  readonly cosePublicKey: Uint8Array;
  readonly alg: number;
  readonly signCount: number;
  readonly aaguid: Uint8Array;
}

// verifyRegistration performs the WebAuthn registration ceremony verification (section 7.1). It does
// NOT touch storage (the DO owns the challenge consume and the cred write inside one read-modify-write);
// it is the pure verification over the inputs. Steps, in order:
//   1. clientDataJSON parses and type === "webauthn.create" and not crossOrigin;
//   2. challenge === expectedChallenge (constant-time over the raw challenge bytes), then CONSUMED by DO;
//   3. origin === expectedOrigin;
//   4. attestationObject parses; fmt is "none" (we accept only fmt=none, that is no attestation statement: this is an
//      in-account front door, not a device-attestation policy point, so we do not require an attestation
//      certificate chain; we DO still verify the key and all the binding facts);
//   5. authData parses, has attested credential data, rpIdHash === SHA-256(expectedRpId), UP flag set,
//      and (the admin front door) the UV flag set: this is a privileged sign-in, so user verification
//      (a PIN/biometric) is REQUIRED, not merely user presence, matching the "required" begin option;
//   6. the COSE key parses and validates (EC2 P-256/ES256 or RSA/RS256).
// On success it returns the credential id, the COSE key bytes, the alg, the initial signCount and the
// AAGUID. Any failure is a typed PasskeyError; the caller logs the precise reason with an opaque id and
// returns the coarse reason.
export async function verifyRegistration(input: RegistrationInput): Promise<VerifiedRegistration> {
  // 1. clientDataJSON.
  const cd = parseClientData(input.clientDataJSON);
  if (cd.type !== "webauthn.create") {
    throw new PasskeyError("bad_request", `registration: clientData type is ${JSON.stringify(cd.type)}, expected webauthn.create`);
  }
  if (cd.crossOrigin) throw new PasskeyError("origin", "registration: crossOrigin is true");
  // 2. challenge (constant time over the decoded bytes; the DO has already loaded+will-consume it).
  challengeMustMatch(cd.challenge, input.expectedChallenge);
  // 3. origin (exact match; no scheme/host normalisation beyond an exact string compare, since the
  //    console origin is a fixed configured value).
  if (cd.origin !== input.expectedOrigin) {
    throw new PasskeyError("origin", `registration: origin ${JSON.stringify(cd.origin)} != ${JSON.stringify(input.expectedOrigin)}`);
  }
  // 4. attestationObject + fmt.
  const top = new CborReader(input.attestationObject).decodeTop();
  if (top.t !== "map") throw new PasskeyError("bad_request", "registration: attestationObject is not a CBOR map");
  const fmtV = mapGetText(top.v, "fmt");
  const authDataV = mapGetText(top.v, "authData");
  if (fmtV === undefined || fmtV.t !== "text") throw new PasskeyError("bad_request", "registration: attestationObject missing fmt");
  if (fmtV.v !== "none") throw new PasskeyError("bad_request", `registration: unsupported attestation fmt ${JSON.stringify(fmtV.v)}`);
  if (authDataV === undefined || authDataV.t !== "bytes") throw new PasskeyError("bad_request", "registration: attestationObject missing authData");
  // 5. authData.
  const ad = parseAuthData(authDataV.v);
  if (!ad.at || ad.credentialId === undefined || ad.cosePublicKey === undefined || ad.aaguid === undefined) {
    throw new PasskeyError("bad_request", "registration: authData has no attested credential data");
  }
  const wantRpHash = await sha256(utf8.encode(input.expectedRpId));
  if (!constantTimeEqual(ad.rpIdHash, wantRpHash)) {
    throw new PasskeyError("rpid", "registration: rpIdHash != SHA-256(rpId)");
  }
  if (!ad.up) throw new PasskeyError("user_present", "registration: user-present flag not set");
  // The admin front door REQUIRES user verification (the begin options request it as "required"): a
  // bare user-presence touch is not enough to enrol a credential that can sign in to a privileged
  // console, so reject an attestation whose UV flag is clear.
  if (!ad.uv) throw new PasskeyError("user_verified", "registration: user-verified flag not set");
  // 6. COSE key parse + validate (this also pins alg to ES256/RS256).
  const cose = parseCoseKey(ad.cosePublicKey);
  return {
    credentialId: ad.credentialId,
    cosePublicKey: ad.cosePublicKey,
    alg: cose.alg,
    signCount: ad.signCount,
    aaguid: ad.aaguid,
  };
}

// AssertionInput is what verifyAssertion needs: the raw clientDataJSON and authenticatorData bytes, the
// raw signature, the expected challenge (the stored single-use login challenge), the expected origin and
// rp.id, the STORED COSE public-key bytes for the asserted credential, and the STORED signCount (the
// clone-detection high-water mark). The DO supplies the stored key + counter after looking up the cred
// by the asserted credential id (an unknown id is rejected by the DO before this is called).
export interface AssertionInput {
  readonly clientDataJSON: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly signature: Uint8Array;
  readonly expectedChallenge: string; // base64url
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
  readonly storedCosePublicKey: Uint8Array;
  readonly storedSignCount: number;
}

// VerifiedAssertion is what a successful verifyAssertion yields: the new signCount to persist (the DO
// updates the stored high-water mark). The verified email is the credential's bound email, which the DO
// already holds from the lookup; this core does not need to return it.
export interface VerifiedAssertion {
  readonly newSignCount: number;
}

// verifyAssertion performs the WebAuthn authentication ceremony verification (section 7.2). It does NOT
// touch storage; the DO owns the credential lookup, the challenge consume and the signCount write. Steps:
//   1. clientDataJSON parses and type === "webauthn.get" and not crossOrigin;
//   2. challenge === expectedChallenge (constant-time), then CONSUMED by DO;
//   3. origin === expectedOrigin;
//   4. authenticatorData parses; rpIdHash === SHA-256(expectedRpId); the AT flag is NOT set (an
//      assertion carries no attested credential data; a set AT is a malformed/hostile structure); the
//      UP flag is set; and (the admin front door) the UV flag is set (user verification REQUIRED);
//   5. SIGNATURE verifies over (authenticatorData || SHA-256(clientDataJSON)) with the stored COSE key;
//   6. CLONE DETECTION: the asserted signCount must be strictly greater than the stored one, UNLESS both
//      are 0 (an authenticator that does not maintain a counter legitimately reports 0 every time).
// On success it returns the new signCount for the DO to persist. Any failure is a typed PasskeyError.
export async function verifyAssertion(input: AssertionInput): Promise<VerifiedAssertion> {
  // 1. clientDataJSON.
  const cd = parseClientData(input.clientDataJSON);
  if (cd.type !== "webauthn.get") {
    throw new PasskeyError("bad_request", `assertion: clientData type is ${JSON.stringify(cd.type)}, expected webauthn.get`);
  }
  if (cd.crossOrigin) throw new PasskeyError("origin", "assertion: crossOrigin is true");
  // 2. challenge.
  challengeMustMatch(cd.challenge, input.expectedChallenge);
  // 3. origin.
  if (cd.origin !== input.expectedOrigin) {
    throw new PasskeyError("origin", `assertion: origin ${JSON.stringify(cd.origin)} != ${JSON.stringify(input.expectedOrigin)}`);
  }
  // 4. authenticatorData (no attested credential data on an assertion; parseAuthData stops at the header
  //    when AT is clear, which is the expected shape here).
  const ad = parseAuthData(input.authenticatorData);
  // An assertion MUST NOT carry attested credential data: the AT flag is a registration-only flag, so a
  // set AT on an assertion is a malformed or hostile structure (it would smuggle a credential/key blob
  // into the authentication path). Reject it before any further checks.
  if (ad.at) throw new PasskeyError("bad_request", "assertion: attested-credential-data (AT) flag set on an assertion");
  const wantRpHash = await sha256(utf8.encode(input.expectedRpId));
  if (!constantTimeEqual(ad.rpIdHash, wantRpHash)) {
    throw new PasskeyError("rpid", "assertion: rpIdHash != SHA-256(rpId)");
  }
  if (!ad.up) throw new PasskeyError("user_present", "assertion: user-present flag not set");
  // The admin front door REQUIRES user verification on every sign-in (the begin options request it as
  // "required"): reject an assertion whose UV flag is clear, so a stolen/forced bare-presence touch
  // cannot authenticate to the privileged console.
  if (!ad.uv) throw new PasskeyError("user_verified", "assertion: user-verified flag not set");
  // 5. signature over authenticatorData || SHA-256(clientDataJSON).
  const cose = parseCoseKey(input.storedCosePublicKey);
  const clientHash = await sha256(input.clientDataJSON);
  const signedData = new Uint8Array(input.authenticatorData.length + clientHash.length);
  signedData.set(input.authenticatorData, 0);
  signedData.set(clientHash, input.authenticatorData.length);
  let verified = false;
  try {
    verified = await verifySignature(cose, signedData, input.signature);
  } catch (e) {
    // A malformed signature (e.g. bad DER) is a non-verification, not a 500. Re-mark as a signature
    // rejection so the caller logs the precise reason and returns the coarse "signature".
    throw new PasskeyError("signature", `assertion: signature verification error (${(e as Error).message})`);
  }
  if (!verified) throw new PasskeyError("signature", "assertion: signature did not verify");
  // 6. clone detection.
  assertSignCountAdvanced(ad.signCount, input.storedSignCount);
  return { newSignCount: ad.signCount };
}

// challengeMustMatch compares the client-echoed challenge to the stored one in constant time over the
// DECODED bytes (not the strings: two different base64url spellings cannot represent the same bytes
// under the strict no-pad decoder, but comparing bytes is the robust, canonical comparison). A decode
// failure on either side, or a mismatch, is the "challenge" rejection. The DO performs the single-use
// CONSUME (delete) of the stored challenge; this only computes the equality.
function challengeMustMatch(clientChallengeB64: string, expectedChallengeB64: string): void {
  let got: Uint8Array;
  let want: Uint8Array;
  try {
    got = b64urlDecode(clientChallengeB64);
    want = b64urlDecode(expectedChallengeB64);
  } catch (e) {
    throw new PasskeyError("challenge", `challenge: not valid base64url (${(e as Error).message})`);
  }
  if (!constantTimeEqual(got, want)) throw new PasskeyError("challenge", "challenge: did not match the issued challenge");
}

// assertSignCountAdvanced enforces clone detection: the asserted counter must be strictly greater than
// the stored counter, UNLESS both are zero. A zero stored + zero asserted is the legitimate "this
// authenticator does not maintain a signature counter" case (common for platform authenticators and
// many security keys), so it is permitted and the high-water mark stays 0. Any other non-advance
// (asserted <= stored with at least one non-zero) is rejected as a possible cloned authenticator.
function assertSignCountAdvanced(asserted: number, stored: number): void {
  if (asserted === 0 && stored === 0) return; // counter not maintained: allowed, stays 0
  if (asserted <= stored) {
    throw new PasskeyError("clone", `clone detection: asserted signCount ${asserted} did not advance past stored ${stored}`);
  }
}

// ---- Helpers the DO/router share for the begin endpoints ---------------------------------------
// randomChallengeB64 returns a fresh CHALLENGE_BYTES random challenge as base64url, the value stored
// server-side and echoed in the creation/request options. crypto.getRandomValues is the CSPRNG in both
// the Workers runtime and Node.
export function randomChallengeB64(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES)));
}

// PUBKEY_CRED_PARAMS is the pubKeyCredParams the creation options advertise: ES256 (-7) then RS256
// (-257), in that order so a client prefers ES256. It is the exact algorithm surface verifyRegistration
// accepts, so a credential created under these options is always verifiable by this core.
export const PUBKEY_CRED_PARAMS: ReadonlyArray<{ type: "public-key"; alg: number }> = [
  { type: "public-key", alg: COSE_ES256 },
  { type: "public-key", alg: COSE_RS256 },
];

// EXCLUDE_CREDENTIALS_MAX is the largest excludeCredentials list a browser will accept on a registration
// ceremony, and it is a HARD CEILING rather than a preference: past it the ceremony is refused before any
// authenticator is consulted.
//
// MEASURED, not read off a spec. A dose-response over excludeCredentials sizes 0, 1, 18, 32, 63, 64, 65,
// 66 and 100 against Playwright's Chromium 1.61.1, with a CDP virtual authenticator and 32-byte credential
// ids: every size up to and including 64 created a credential, and 65 and above threw
// `DOMException` named `RangeError`, message "The `excludeCredentials` attribute exceeds the maximum
// allowed size (64)." The n=0 known positive created a credential, so the rig could succeed and its
// failures therefore mean something. Firefox and WebKit were INCONCLUSIVE in that rig (they answer
// NotAllowedError at 64 and at 65 alike, because neither exposes a virtual authenticator, so the refusal
// is "nothing answered" and not a size verdict); this constant is Chromium's measured number and no claim
// is made that the other two share it. If either turns out to enforce a smaller list, this is the one
// place to lower.
//
// WHY AN UNBOUNDED LIST WAS A LOCKOUT AND NOT A BLEMISH. passkeyRegisterBegin put
// EVERY credential an email holds into excludeCredentials. Three accounts on the probe estate had
// accumulated exactly 65, so every registration ceremony for them threw in the browser before a single
// byte reached this engine. That alone is only an inconvenience for someone holding a working passkey.
// The harm is that re-enrolment is ALSO the step that mints a fresh recovery-code set
// (passkeyRegisterFinish -> generateRecoveryFor): a break-glass recovery sign-in consumes one code and is
// then routed straight into enrolling a fresh passkey, and it is THAT enrolment which replaces the spent
// set. With the ceremony refused, each break-glass sign-in spent a code and replaced nothing, so the bank
// drained monotonically toward zero with no way back. probe's owner went 10 -> 8 in a single morning on
// two such sign-ins. An account that empties its bank in this state cannot enrol (the ceremony throws),
// cannot sign in with a passkey it has lost, and cannot delete a credential to get back under the ceiling,
// because /passkey/credentials/delete is step-up gated on the cookie path and step-up needs the very
// assertion it does not have. That is a permanent lockout reached by using the documented break-glass
// path exactly as intended.
//
// TRUNCATION IS SAFE HERE, AND REFUSAL WOULD NOT BE. excludeCredentials is a UX affordance: it stops a
// browser silently enrolling a second credential for an authenticator that already has one. It is NOT the
// duplicate guard. That guard is server-side in passkeyRegisterFinish, which refuses a credential id
// already registered, and it is unaffected by anything sent here. So the worst a truncated list can cost
// is a duplicate credential for an authenticator whose entry fell outside the window, which is a tidiness
// problem; an untruncated list costs the account.
export const EXCLUDE_CREDENTIALS_MAX = 64;

// ALLOW_CREDENTIALS_MAX is the same ceiling for the OTHER descriptor list: `allowCredentials` on an
// assertion (`navigator.credentials.get`). It is a separate constant because it is a separate measurement,
// not because the number is expected to differ.
//
// MEASURED, (another pass), Chromium 149.0.7827.55, CDP virtual authenticator on a local
// origin, dose-response over allowCredentials sizes 0, 1, 32, 63, 64, 65, 66, 100, 128 and 256. Sizes 1
// through 64 completed the assertion; 65 and above threw DOMException named `RangeError`, "The
// `allowCredentials` attribute exceeds the maximum allowed size (64)." The rig reproduced an earlier pass's
// excludeCredentials result (first throw at 65) in the same session as its control, and the verdict did
// not move when the genuine credential was placed LAST rather than first: the browser is refusing on list
// SIZE, before any authenticator is consulted.
//
// WHY AN UNBOUNDED allowCredentials IS A SECOND LOCKOUT THAT A NARROWER FIX DOES NOT CLOSE. stepUpBegin
// emitted an account's ENTIRE credential list here. Step-up gates recovery-code regeneration, self-add
// passkey, the key ceremony, posture risk-accept, restore-approve -- and /passkey/credentials/delete,
// which is the ONLY way to reduce a credential count. So an account at 65 could not step up, and could not
// delete a credential to get back under 65, because deleting requires the step-up it can no longer pass.
// The count moves in one direction only. Bounding excludeCredentials let such an account enrol again, but
// every enrolment adds a credential, so without this bound the fix walked the account further from the
// ceiling it needed to re-cross.
//
// TRUNCATION IS THE LESSER HARM HERE, AND UNLIKE THE EXCLUDE LIST IT IS NOT FREE. A credential outside the
// window cannot be offered, so an operator whose only remaining authenticator ranks 65th is not helped by
// this list. The alternative is that NOBODY on the account can assert at all, which is strictly worse and
// is the state being repaired. The ranking is what keeps the cost small: the window holds the credentials
// most recently PROVEN usable, which is the best available evidence of what the person is holding.
export const ALLOW_CREDENTIALS_MAX = 64;

// excludeCredentialsFor picks which of an email's credentials go into the creation options'
// excludeCredentials, bounded by EXCLUDE_CREDENTIALS_MAX.
//
// THE ORDER IS THE WHOLE DESIGN, because truncation means some credential is going to be left out and the
// choice of which one is not arbitrary. Exclusion is only useful for an authenticator the registrant might
// actually be holding right now, so the ranking is by evidence of that:
//
//   1. credentials PROVEN usable most recently (lastAssertedAt descending). A non-null lastAssertedAt is
//      written only after verifyAssertion returned, so it is proof of possession of the private half at
//      that instant, not an inference from the record existing.
//   2. then credentials never asserted, newest enrolment first (createdAt descending), since a recent
//      enrolment is the better guess at a device still in someone's pocket.
//
// A stable tiebreak on credentialId keeps the output deterministic for a given input, so the same account
// yields the same list on every begin and a test can assert on it.
//
// Pure and exported so the bound is unit-tested directly rather than only through a live ceremony.
export function excludeCredentialsFor(creds: readonly PasskeyCred[], max: number = EXCLUDE_CREDENTIALS_MAX): PasskeyCred[] {
  return credentialsByLikelyPresence(creds, max);
}

// allowCredentialsFor picks which of an email's credentials go into an assertion's allowCredentials,
// bounded by ALLOW_CREDENTIALS_MAX.
//
// It shares excludeCredentialsFor's ranking, and the sharing is the point rather than a saving: both lists
// answer the SAME question, "which credentials might this person be holding right now", and both are
// refused wholesale by the browser past the same measured ceiling. A future correction to either the
// ranking or the number should not have to be found twice.
export function allowCredentialsFor(creds: readonly PasskeyCred[], max: number = ALLOW_CREDENTIALS_MAX): PasskeyCred[] {
  return credentialsByLikelyPresence(creds, max);
}

// credentialsByLikelyPresence is the shared ranking-and-bound described above EXCLUDE_CREDENTIALS_MAX:
// credentials proven usable most recently first, then never-asserted ones newest-enrolment first, with a
// stable credentialId tiebreak so a given account yields the same list on every ceremony.
function credentialsByLikelyPresence(creds: readonly PasskeyCred[], max: number): PasskeyCred[] {
  const rank = (c: PasskeyCred): number => (typeof c.lastAssertedAt === "string" && c.lastAssertedAt.length > 0 ? 1 : 0);
  const sorted = [...creds].sort((a, b) => {
    const byProven = rank(b) - rank(a);
    if (byProven !== 0) return byProven;
    const aKey = rank(a) === 1 ? (a.lastAssertedAt ?? "") : a.createdAt;
    const bKey = rank(b) === 1 ? (b.lastAssertedAt ?? "") : b.createdAt;
    if (aKey !== bKey) return bKey.localeCompare(aKey);
    return a.credentialId.localeCompare(b.credentialId);
  });
  return sorted.slice(0, Math.max(0, max));
}

// loginChallengeId mints a fresh opaque id to scope a login challenge (`login:<id>`), since the
// asserting credential (and thus the email) is unknown until the finish. It is a random UUID; it is not
// secret (it is the scope key for the stored challenge), only unguessable enough that two concurrent
// logins do not collide. Returned so the begin response can echo it and the finish can present it back.
export function loginChallengeId(): string {
  return crypto.randomUUID();
}

// randomInviteToken mints a fresh, unguessable registration-invite token (INVITE_TOKEN_BYTES of CSPRNG as
// base64url). It is the lookup key for a PasskeyInvite (`passkeyInvite:<token>`) and is embedded in the
// role-invite email's registration link; it is not a secret to be MAC'd (it is a one-shot, server-stored,
// TTL'd capability the DO consumes on use), only random enough that it cannot be guessed or enumerated.
export function randomInviteToken(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(INVITE_TOKEN_BYTES)));
}
