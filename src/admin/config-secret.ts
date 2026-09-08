import { b64urlDecode, b64urlEncode, hexEncode, utf8 } from "../crypto/bytes.ts";
import { aesGcmOpen, aesGcmSeal, hmacSha384 } from "../crypto/primitives.ts";
import { UnwrapFaultError } from "./diag-records.ts";

// At-rest encryption for a configuration secret held in Durable Object storage. Today the only such
// secret is the console-set destination secretAccessKey (the S3 credential for off-account 3-2-1
// copies), which the DO otherwise stores as a plaintext field protected only by the platform's own
// at-rest encryption (the "Durable Object plaintext floor", design ENTERPRISE-UX-BLUEPRINT §2.4).
// SIGNER_PRIVATE lives in the Secrets Store and the IdP client secret has a Secrets-Store-by-reference
// rung, so the destination credential was the one secret with no better rung than plaintext.
//
// This module upgrades that floor to an ENCRYPTED floor: the DO holds only ciphertext, and the
// AES-256-GCM key (CONFIG_WRAP_KEY) lives in the account Secrets Store. So a read of Durable Object
// storage alone no longer discloses the credential, and its confidentiality roots in the same vault
// the signer key does. The crypto runs in the engine Worker context only (the router on write,
// fetchDestConfig on read); the DO holds no env and never sees the key, so it can only ever store and
// return the opaque envelope. The AES-256-GCM primitive is the same one the seal format uses, so the
// offline reader's crypto surface is unchanged.

// WrappedSecret is the at-rest envelope: a GCM nonce and the ciphertext||tag, both base64url. v pins
// the layout for forward compatibility.
export interface WrappedSecret {
  v: 1;
  iv: string; // base64url 12-byte AES-GCM nonce
  ct: string; // base64url ciphertext || 16-byte tag
}

// The domain separator bound as AES-GCM additional authenticated data, so an envelope only opens in
// the configuration-secret context: a ciphertext lifted from any other GCM use in the system will not
// verify here, and vice versa.
const CONFIG_SECRET_AAD = utf8("downpipes/config-secret/v1");

// PUSH_SECRET_AAD is the SIBLING domain separator for the SIEM push destination's auth-header secret
// (SIEM-PUSH-DESIGN.md), kept DISTINCT from CONFIG_SECRET_AAD so the two secret classes can
// never be confused: AES-GCM's AAD is authenticated but not secret, so a push ciphertext sealed under
// THIS label fails to open under CONFIG_SECRET_AAD (and vice versa) even under the SAME wrap key. A
// destination credential can therefore never be replayed as a push auth header, or a push secret replayed
// as a destination credential, by a stored-record mix-up or a copy-paste of the wrong envelope.
export const PUSH_SECRET_AAD = utf8("downpipes/push-secret/v1");

// PUSH_S3_SECRET_AAD is the THIRD sibling domain separator, for the SIEM push S3-drop sink's
// secretAccessKey. It is kept DISTINCT from BOTH CONFIG_SECRET_AAD (the archive
// destination credential) AND PUSH_SECRET_AAD (the push auth-header secret), so the three secret classes can
// never be confused: a push-s3 ciphertext sealed under THIS label fails to open under either of the other
// two (and vice versa) even under the same wrap key. An archive credential can never be replayed as a push
// S3 key, nor a push header secret as a push S3 key, by a stored-record mix-up or a wrong-envelope paste.
export const PUSH_S3_SECRET_AAD = utf8("downpipes/push-s3-secret/v1");

// JSM_SECRET_AAD is the FOURTH sibling domain separator, for the Jira Service Management / Opsgenie
// notify channel's GenieKey API token (NotifyChannel.apiKey, src/notify/channels/jsm.ts). Kept DISTINCT
// from every other secret class above (and from SERVICENOW_SECRET_AAD below) so a jsm ciphertext fails to
// open under any of them (and vice versa) even under the same wrap key: a GenieKey token can never be
// replayed as a destination credential, a push secret, or a ServiceNow password, by a stored-record
// mix-up or a wrong-envelope paste.
export const JSM_SECRET_AAD = utf8("downpipes/jsm-secret/v1");

// SERVICENOW_SECRET_AAD is the FIFTH sibling domain separator, for the ServiceNow Event Management notify
// channel's HTTP Basic password (NotifyChannel.apiKey, src/notify/channels/servicenow.ts). Kept DISTINCT
// from every other secret class (including JSM_SECRET_AAD, its nearest sibling: both are notify-channel
// apiKey fields, but a ServiceNow password must never be replayable as a JSM GenieKey token or vice versa)
// so a servicenow ciphertext fails to open under any of them (and vice versa) even under the same wrap key.
export const SERVICENOW_SECRET_AAD = utf8("downpipes/servicenow-secret/v1");

// OTLP_PUSH_SECRET_AAD is the SIXTH sibling domain separator, for the OTLP/HTTP metrics push destination's
// auth header secret (a bearer token or vendor API key for Datadog/New
// Relic/Dynatrace/Elastic/Splunk Observability). Kept DISTINCT from every other secret class above (the
// archive destination credential, the SIEM push auth header, the SIEM push S3-drop sink key, the JSM
// GenieKey token and the ServiceNow password), so none of the six secret classes can ever be confused: an
// OTLP push ciphertext sealed under THIS label fails to open under any of the others (and vice versa) even
// under the same wrap key. A SIEM push header secret can never be replayed as an OTLP bearer token, nor the
// reverse, by a stored-record mix-up or a copy-paste of the wrong envelope.
export const OTLP_PUSH_SECRET_AAD = utf8("downpipes/otlp-push-secret/v1");

// DISCOVERY_SECRET_AAD is the SEVENTH sibling domain separator, for the account-wide Cloudflare
// discovery token (the read-only token the owner pastes under Sources, which every token source --
// cf-config / workers / stream / images / artifacts -- reads with). It was the LAST credential class
// stored in the clear: the DO held the raw token string while every other secret in this file was
// already sealed, so a Durable Object storage read yielded a live estate-wide credential. Kept
// DISTINCT from all six classes above so a discovery ciphertext cannot be opened as a destination
// credential, a push header or a notify secret, nor the reverse, even under the same wrap key.
export const DISCOVERY_SECRET_AAD = utf8("downpipes/discovery-secret/v1");

// isWrappedSecret is a PURE shape check (no crypto), safe to call inside the Durable Object: it tells
// an envelope apart from a legacy plaintext string so storage and reads accept either during the lazy
// migration (an existing plaintext credential keeps working until its destination is next saved).
export function isWrappedSecret(v: unknown): v is WrappedSecret {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return o.v === 1 && typeof o.iv === "string" && typeof o.ct === "string";
}

// loadConfigWrapKey parses CONFIG_WRAP_KEY (base64url of 32 bytes = AES-256) from its env string, or
// returns undefined when it is unset (the back-compat plaintext-floor path). A present-but-malformed
// value THROWS, so a misconfigured key fails loud rather than silently leaving secrets unencrypted.
export function loadConfigWrapKey(raw: string | undefined): Uint8Array | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const key = b64urlDecode(raw.trim());
  if (key.length !== 32) {
    // TAGGED with its closed cause (the message is byte-identical, so every existing response, test and
    // log line is unchanged). A malformed wrap key stops the WHOLE fleet -- no destination credential in the
    // account can be opened -- so it must never coarsen into the same bucket as one bad destination record.
    throw new UnwrapFaultError("key-malformed", `CONFIG_WRAP_KEY must be base64url of 32 bytes (AES-256); got ${key.length} bytes`);
  }
  return key;
}

// A KEY-CHECK VALUE (KCV) for the wrap key: a redaction-safe, non-reversible commitment to WHICH wrap key is
// configured, for the support pack's rotation diagnosis (config-wrap-key-rotated-wrong is a DATA-LOSS keystone -
// a key rotated after a credential was wrapped renders it undecryptable, and today that is invisible until a
// destination read fails lazily). The KCV is HMAC-SHA-384 of a FIXED PUBLIC domain label under the key, truncated
// and domain-tagged. This is the HSM key-check-value construction: HMAC is a PRF, so the KCV leaks nothing about
// the key (unlike a plain hash of the key, which would be a verification oracle for a guessed key). It is NEVER
// the key bytes. Two engines configured with the same wrap key share a KCV; a rotated key changes it - which is
// exactly the signal support cross-checks against the recovery sheet / a prior pack.
const CONFIG_WRAP_KEY_KCV_LABEL = utf8("downpipes/config-wrap-key/kcv/v1");
export async function configWrapKeyCheckValue(key: Uint8Array): Promise<string> {
  const mac = await hmacSha384(key, CONFIG_WRAP_KEY_KCV_LABEL);
  return `dpk1:${hexEncode(mac).slice(0, 32)}`;
}

// wrapConfigSecret envelopes a plaintext secret under the wrap key with a fresh random nonce. aad
// defaults to CONFIG_SECRET_AAD (every existing call site is unchanged); a caller sealing a DIFFERENT
// secret class (e.g. the SIEM push auth header) passes its own sibling AAD constant so the two can never
// be cross-opened.
export async function wrapConfigSecret(key: Uint8Array, plaintext: string, aad: Uint8Array = CONFIG_SECRET_AAD): Promise<WrappedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await aesGcmSeal(key, iv, utf8(plaintext), aad);
  return { v: 1, iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
}

// unwrapConfigSecret opens an envelope; a tag mismatch (wrong key, tampered bytes, or the WRONG aad, e.g.
// a push secret presented to the destination-credential AAD) throws. aad defaults to CONFIG_SECRET_AAD.
export async function unwrapConfigSecret(key: Uint8Array, w: WrappedSecret, aad: Uint8Array = CONFIG_SECRET_AAD): Promise<string> {
  const pt = await aesGcmOpen(key, b64urlDecode(w.iv), b64urlDecode(w.ct), aad);
  return new TextDecoder().decode(pt);
}

// canOpenConfigSecret is the DIAGNOSTIC twin of unwrapConfigSecret for probes that need only the
// VERDICT ("does this key open this envelope?"), never the value -- the support pack's wrap-key
// health check (keys security review, item 5b). AES-GCM cannot verify a tag without
// producing the plaintext, so the plaintext buffer necessarily exists for an instant; this helper
// guarantees it is never decoded to an (unzeroable, GC-lifetime) string and zero-fills the buffer
// before returning, so a probe caller cannot accidentally retain or surface the secret. Returns
// false on any open failure (wrong key, tampered/corrupt envelope, undecodable base64url).
export async function canOpenConfigSecret(key: Uint8Array, w: WrappedSecret): Promise<boolean> {
  try {
    const pt = await aesGcmOpen(key, b64urlDecode(w.iv), b64urlDecode(w.ct), CONFIG_SECRET_AAD);
    pt.fill(0);
    return true;
  } catch {
    return false;
  }
}

// maybeWrapConfigSecret is the single WRITE ingress (the router's destination-store routes, and the SIEM
// push destination route with the sibling PUSH_SECRET_AAD): it wraps when a key is configured, otherwise
// returns the plaintext unchanged (the back-compat floor). aad defaults to CONFIG_SECRET_AAD.
export async function maybeWrapConfigSecret(
  key: Uint8Array | undefined,
  plaintext: string,
  aad: Uint8Array = CONFIG_SECRET_AAD,
): Promise<string | WrappedSecret> {
  return key === undefined ? plaintext : wrapConfigSecret(key, plaintext, aad);
}

// resolveConfigSecret is the READ counterpart (fetchDestConfig, and the SIEM push drain/test-send with the
// sibling PUSH_SECRET_AAD): a plaintext string (legacy, pre encryption) is returned unchanged; an envelope
// is opened with the key. A present envelope with NO key configured throws rather than be mistaken for a
// credential string, so a destination encrypted at rest can never be silently signed-with-garbage and a
// removed key is surfaced loudly. aad defaults to CONFIG_SECRET_AAD.
export async function resolveConfigSecret(
  key: Uint8Array | undefined,
  stored: string | WrappedSecret,
  aad: Uint8Array = CONFIG_SECRET_AAD,
): Promise<string> {
  if (typeof stored === "string") return stored;
  if (!isWrappedSecret(stored)) {
    // G028: the stored record is neither shape -- a corrupted / half-written DO row, NOT a key problem.
    throw new UnwrapFaultError("envelope-shape", "stored destination credential is neither a plaintext string nor a valid envelope");
  }
  if (key === undefined) {
    // G028: the credential IS encrypted and the key is not bound at all -- a deploy dropped the env var. The
    // key itself may be perfectly fine, which is the opposite remediation from a rotation.
    throw new UnwrapFaultError("key-missing", "destination credential is encrypted at rest but CONFIG_WRAP_KEY is not configured");
  }
  // DECODE before OPEN, so the two causes stop being one. Undecodable base64url means the stored
  // ENVELOPE is damaged (restoring the previous key will not help); a decodable envelope that fails the AEAD
  // tag means the KEY is wrong (restoring the previous key is exactly the fix). They were previously the same
  // catch, and therefore the same -- and, for a corrupt record, the WRONG -- operator instruction.
  let iv: Uint8Array;
  let ct: Uint8Array;
  try {
    iv = b64urlDecode(stored.iv);
    ct = b64urlDecode(stored.ct);
  } catch {
    throw new UnwrapFaultError("envelope-corrupt", "the stored destination credential's envelope does not decode; the stored record is damaged (restoring a previous CONFIG_WRAP_KEY will not open it). Re-enter the destination credential to re-wrap it.");
  }
  try {
    const pt = await aesGcmOpen(key, iv, ct, aad);
    return new TextDecoder().decode(pt);
  } catch {
    // The envelope is well-formed (isWrappedSecret passed above) but the AEAD open failed: the configured
    // CONFIG_WRAP_KEY is present but does NOT decrypt this credential, almost always because the key was
    // ROTATED after the credential was wrapped. Name that actionable cause instead of surfacing a raw
    // crypto/decrypt error, so the operator restores the prior key rather than chasing a tag failure. The
    // raw error text is deliberately not echoed (it carries no operator-useful detail beyond "did not open").
    throw new UnwrapFaultError("aead-tag", "the configured CONFIG_WRAP_KEY does not decrypt this destination credential; it was most likely rotated after the credential was wrapped, so restore the prior CONFIG_WRAP_KEY in the Secrets Store or re-enter the destination credential to re-wrap it under the current key");
  }
}
