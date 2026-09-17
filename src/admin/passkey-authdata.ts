// The authenticatorData + clientDataJSON parsers of the WebAuthn / passkey core, split out of passkey.ts so
// each module stays a coherent unit under 500 lines. This holds the bounds-checked authenticator-data parse
// (WebAuthn section 6.1: rpIdHash, flags, signCount, and the attested credential data on a registration) and
// the clientDataJSON parse (the type / challenge / origin / crossOrigin subset we check). The CBOR span of
// the COSE_Key inside authData is measured via the shared CborReader. The ceremony core (passkey.ts) imports
// these. Behaviour is byte-identical to the original passkey.ts: this code was MOVED verbatim, not changed.
//
// SECURITY: every field is bounds-checked before it is read; a truncated structure or an over-long credential
// id is a typed rejection, never an out-of-range read or a thrown TypeError that leaks a stack.
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no Node built-ins, no enums,
// explicit field declarations.

// The structural defects below throw the SAME coarse PasskeyError("bad_request", ...) they always did,
// but TAGGED with a closed WebauthnFaultClass (structuralPasskeyError, passkey-cose.ts), so the pack can tell a
// truncated authData from a malformed clientDataJSON from an over-long credential id. The client-facing
// response and the anti-enumeration property are unchanged.
import { CborReader, COSE_KEY_MAX, structuralPasskeyError } from "./passkey-cose.ts";

// AAGUID_LEN is the fixed length of the authenticator AAGUID field inside attested credential data (16
// bytes). CRED_ID_MAX bounds the credential id length the parser will accept from attested credential
// data: the WebAuthn 16-bit credentialIdLength field can express up to 65535, but a real credential id
// is small (32 to 64 bytes typically); we accept up to 1023 to be safe against a future longer id while
// rejecting an absurd length that would only be a malformed/hostile structure. RP id and origin are not
// bounded here (they are server-controlled config, not authenticator bytes).
const AAGUID_LEN = 16;
const CRED_ID_MAX = 1023;

// ---- authenticatorData parse -------------------------------------------------------------------
// AuthData is the parsed authenticator data structure (WebAuthn section 6.1): the 32-byte rpIdHash,
// the flags byte (we surface user-present UP and user-verified UV plus whether attested credential data
// is present AT), and the 32-bit signCount. When attested credential data is present (registration),
// aaguid, the credential id, and the COSE public-key BYTES are parsed out too. For an assertion there is
// no attested credential data, so those are absent.
export interface AuthData {
  rpIdHash: Uint8Array; // 32 bytes
  flags: number; // the raw flags byte
  up: boolean; // bit 0: user present
  uv: boolean; // bit 2: user verified
  at: boolean; // bit 6: attested credential data included
  ed: boolean; // bit 7: extension data included
  signCount: number; // 32-bit big-endian counter
  // Present ONLY when at is set (registration):
  aaguid?: Uint8Array; // 16 bytes
  credentialId?: Uint8Array; // the raw credential id (bounded by CRED_ID_MAX)
  cosePublicKey?: Uint8Array; // the raw COSE_Key bytes (re-encoded exactly as occupied in authData)
}

// AUTH_DATA_FLAG_UP/UV/AT/ED are the WebAuthn flag bit masks.
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;
// AUTH_DATA_MIN_LEN is the fixed header: 32-byte rpIdHash + 1 flags + 4 signCount.
const AUTH_DATA_MIN_LEN = 37;

// parseAuthData parses authenticator data, bounds-checking every field. When attested credential data is
// present it parses the AAGUID (16), the 16-bit credentialIdLength + that many credential-id bytes, and
// then decodes ONE CBOR item (the COSE_Key) to learn exactly how many bytes it occupies, so the COSE
// key bytes are captured precisely (extension data, if present, follows and is not consumed here). For an
// assertion (no AT flag) it stops after the 37-byte header (the spec puts no attested credential data on
// an assertion). A truncated structure or an over-long credential id is a typed rejection.
export function parseAuthData(raw: Uint8Array): AuthData {
  if (raw.length < AUTH_DATA_MIN_LEN) {
    throw structuralPasskeyError("authdata-truncated", `authData: too short (${raw.length} < ${AUTH_DATA_MIN_LEN})`);
  }
  const rpIdHash = raw.subarray(0, 32).slice();
  const flags = raw[32]!;
  const signCount = raw[33]! * 0x1000000 + (raw[34]! << 16) + (raw[35]! << 8) + raw[36]!;
  const up = (flags & FLAG_UP) !== 0;
  const uv = (flags & FLAG_UV) !== 0;
  const at = (flags & FLAG_AT) !== 0;
  const ed = (flags & FLAG_ED) !== 0;
  const base: AuthData = { rpIdHash, flags, up, uv, at, ed, signCount };
  if (!at) return base;

  // Attested credential data: AAGUID(16) || credentialIdLength(2 BE) || credentialId || COSE_Key.
  let off = AUTH_DATA_MIN_LEN;
  if (raw.length < off + AAGUID_LEN + 2) {
    throw structuralPasskeyError("authdata-truncated", "authData: truncated attested credential data header");
  }
  const aaguid = raw.subarray(off, off + AAGUID_LEN).slice();
  off += AAGUID_LEN;
  const credIdLen = (raw[off]! << 8) | raw[off + 1]!;
  off += 2;
  if (credIdLen === 0 || credIdLen > CRED_ID_MAX) {
    throw structuralPasskeyError("authdata-credid-range", `authData: credential id length ${credIdLen} out of range`);
  }
  if (raw.length < off + credIdLen) {
    throw structuralPasskeyError("authdata-truncated", "authData: truncated credential id");
  }
  const credentialId = raw.subarray(off, off + credIdLen).slice();
  off += credIdLen;
  // The remaining bytes begin with the COSE_Key CBOR item; decode it to find its exact length, then
  // capture exactly those bytes. We decode (not decodeTop) because extension data may follow the key
  // when the ED flag is set. position() after the decode is the precise span the COSE_Key occupied.
  const rest = raw.subarray(off);
  const reader = new CborReader(rest);
  reader.decode(0);
  const consumed = reader.position();
  if (consumed <= 0 || consumed > COSE_KEY_MAX) {
    throw structuralPasskeyError("cose-shape", `authData: COSE key span ${consumed} out of range`);
  }
  // When the ED flag is NOT set, the COSE_Key must be the LAST thing in authData: any trailing bytes are
  // a malformed structure. When ED is set, extension-data CBOR follows the key and is allowed (we do not
  // consume or use it). This keeps a forgery from appending bytes after the key on a non-extension cred.
  if (!ed && consumed !== rest.length) {
    throw structuralPasskeyError("cbor-trailing", "authData: trailing bytes after COSE key with no extension-data flag");
  }
  const cosePublicKey = rest.subarray(0, consumed).slice();
  return { ...base, aaguid, credentialId, cosePublicKey };
}

// ---- clientDataJSON parse ----------------------------------------------------------------------
// ClientData is the parsed, validated subset of clientDataJSON we check: the operation type, the
// base64url challenge the client echoed back, and the origin. crossOrigin is surfaced (we reject a
// cross-origin assertion). Anything beyond these is ignored (forward-compatible), but the three fields
// MUST be present and well-typed or the structure is rejected.
export interface ClientData {
  type: string; // "webauthn.create" (registration) or "webauthn.get" (assertion)
  challenge: string; // base64url challenge the client echoed (compared to the stored one)
  origin: string; // the caller's origin (must equal CONSOLE_ORIGIN)
  crossOrigin: boolean; // true if the call was made from a cross-origin context (rejected)
}

// parseClientData decodes clientDataJSON (raw bytes) and validates the three required string fields.
// fatal UTF-8 decode so invalid bytes are rejected. A non-object, a missing field, or a wrong-typed
// field is a "bad_request" rejection. crossOrigin defaults to false when absent (the field is optional
// in older clients), but a present non-boolean is rejected.
export function parseClientData(raw: Uint8Array): ClientData {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch (e) {
    throw structuralPasskeyError("clientdata-malformed", `clientData: not valid JSON (${(e as Error).message})`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw structuralPasskeyError("clientdata-malformed", "clientData: not a JSON object");
  }
  const o = parsed as Record<string, unknown>;
  const type = o.type;
  const challenge = o.challenge;
  const origin = o.origin;
  const crossOrigin = o.crossOrigin;
  if (typeof type !== "string") throw structuralPasskeyError("clientdata-malformed", "clientData: missing type");
  if (typeof challenge !== "string") throw structuralPasskeyError("clientdata-malformed", "clientData: missing challenge");
  if (typeof origin !== "string") throw structuralPasskeyError("clientdata-malformed", "clientData: missing origin");
  if (crossOrigin !== undefined && typeof crossOrigin !== "boolean") {
    throw structuralPasskeyError("clientdata-malformed", "clientData: crossOrigin is not a boolean");
  }
  return { type, challenge, origin, crossOrigin: crossOrigin === true };
}
