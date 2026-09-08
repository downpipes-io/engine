// Recovery codes: the normal-app account-recovery break-glass for an Owner (or any enrolled user) who
// loses their passkey. This is the ONGOING break-glass for admin SIGN-IN, distinct from the ADMIN_TOKEN
// (a one-time bootstrap credential, then disposed) and distinct from the backup BREAK-GLASS KEY (which is
// for offline DATA recovery, never admin sign-in). A user signs in with a recovery code at the sign-in
// screen, gets a normal signed session for their resolved role, and is then prompted to enrol a fresh
// passkey and regenerate codes.
//
// This module is the PURE, key-as-argument core (no I/O, no storage), exactly like session.ts and
// passkey.ts: the scheduler DO drives it with the in-DO session signing key and owns the per-email record.
// Keeping the crypto here (and free of transport/storage) means the generate, hash and verify can never be
// computed two different ways, and the validator exercises the production path with a real key.
//
// SECURITY DISCIPLINE (treat a recovery code as a HIGH-VALUE credential; an adversarial review will hunt
// for flaws):
//  - A code is CSPRNG (crypto.getRandomValues), human-formatted as six hyphen-joined groups of five over an
//    unambiguous alphabet (Crockford base32 minus the easily-confused letters), so it is 150 bits of entropy
//    (30 chars x 5 bits), above the ASVS 112-bit lookup-secret floor, and still transcribable.
//  - ONLY a salted HMAC of each code is ever stored (HMAC-SHA-256 under the in-DO session signing key,
//    PLUS a per-code random salt). The plaintext is returned to the caller ONCE at generation and NEVER
//    stored, logged, or returned again. A holder of the DO storage cannot recover a code from the hash.
//  - Verification recomputes the HMAC over the presented code + the stored salt and compares in CONSTANT
//    TIME against EVERY unconsumed code's hash (constantTimeEqual over the raw MAC bytes), so neither a
//    match position nor a prefix of any stored hash leaks through timing, and a mismatch is indistinguishable
//    from "email has no codes" at this layer (the DO adds the per-IP/per-email rate limit + the generic
//    response, so there is no oracle on which part failed).
//  - Each code is SINGLE USE: a successful verify marks exactly that code consumed, so the same code fails
//    the second time. Regenerating replaces the whole set (all prior codes invalid at once).
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no Node built-ins, no
// enums, explicit field declarations.

import { ab, b64urlDecode, b64urlEncode, constantTimeEqual, hexEncode } from "../crypto/bytes.ts";
import { RECOVERY_CODES_LOW_THRESHOLD } from "./recovery-constants.ts";

// RECOVERY_CODE_COUNT is how many single-use codes a generation mints (the caller's spec: 10). A user
// saves the whole set offline; each is good for exactly one sign-in.
export const RECOVERY_CODE_COUNT = 10;

// RECOVERY_CODE_GROUPS / RECOVERY_CODE_GROUP_LEN shape the human format: SIX groups of five characters
// joined by hyphens (xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx). Thirty characters over the 32-symbol alphabet is
// 150 bits of entropy, which clears the ASVS V6.5.2 / V11.5.1 112-bit floor for a lookup secret (raised from
// the prior 50 bits / 10 chars) while staying writable. Each char is one CSPRNG byte masked to 5 bits, no
// modulo bias. NOTE: raising this length invalidates any previously-issued 10-char codes (they no longer
// match the length gate), so a deploy must be paired with a recovery-code REGENERATION; passkey holders are
// unaffected (codes are the lost-passkey break-glass).
const RECOVERY_CODE_GROUPS = 6;
const RECOVERY_CODE_GROUP_LEN = 5;

// RECOVERY_CODE_ALPHABET is Crockford base32 with the visually ambiguous symbols removed (no I/L/O to avoid
// 1/0 confusion, no U). 32 symbols means each character carries exactly 5 bits, so a character maps cleanly
// to a 5-bit slice of CSPRNG output with NO modulo bias. It is uppercase; normalisation upper-cases input.
const RECOVERY_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // 32 symbols, no I L O U

// RECOVERY_CODE_ALPHABET_SET is the alphabet as a Set for an O(1) membership check during normalisation
// (idiomatic for a fixed alphabet, in place of a linear scan of the alphabet string per input character).
const RECOVERY_CODE_ALPHABET_SET = new Set(RECOVERY_CODE_ALPHABET);

// RECOVERY_SALT_BYTES is the per-code random salt length (16 bytes / 128 bits). A salt per code means two
// users (or two generations) that happened to mint the same code string still store different hashes, and
// it defends the stored hashes against any precomputation even though the codes are already high-entropy.
const RECOVERY_SALT_BYTES = 16;

// RecoveryCodeHash is one stored code: the per-code random salt (base64url) and the HMAC hash
// ("hmac-sha256:" + hex), plus the single-use consumed flag. NO plaintext is ever held here. The salt is
// NOT a secret (it is stored beside the hash, exactly like a password salt); the secrecy rests on the code
// entropy + the in-DO HMAC key. consumed flips true the instant a code is used for a successful recovery.
export interface RecoveryCodeHash {
  salt: string; // base64url, per-code CSPRNG
  hash: string; // "hmac-sha256:" + hex(HMAC-SHA-256(key, salt || code-bytes))
  consumed: boolean; // single-use latch; a consumed code never matches again
}

// RecoveryRecord is the per-email recovery set the DO persists (one storage key per email). It carries the
// canonical email it belongs to (so a misfiled record is self-describing), the salted hashes, and when the
// set was generated. There is deliberately no plaintext and no count field (the count is derived from the
// unconsumed hashes, so it can never drift from the truth).
export interface RecoveryRecord {
  email: string; // the canonical (trimmed, lowercased) email this set belongs to
  codes: RecoveryCodeHash[]; // the salted hashes, consumed-flagged; never any plaintext
  generatedAt: string; // RFC-3339 of the generation that produced THIS set
  // keyProof is the KEY-CONTINUITY witness (LOCKOUT-PREFLIGHT-COUNTS-RECORDS-NOT-USABLE-FACTORS):
  // a MAC over a fixed, domain-separated label under the SAME key the hashes above were computed with, so a
  // reader holding only the record and the current key can PROVE whether a banked code can still verify,
  // without a code and without consuming one. It is what separates "this account has recovery codes" from
  // "this account has recovery codes that work", which is the whole defect. Optional on the type because
  // records minted before this field existed do not carry one; the DO falls back to a key-timeline
  // inference for those and treats an unprovable one as NOT ready. It is not a secret beyond the key itself
  // (a reader of this record can already read the key from the same DO storage) and is never returned by
  // any route.
  keyProof?: string; // "hmac-sha256:" + hex(HMAC(key, RECOVERY_KEY_PROOF_LABEL))
}

// RecoveryBreakGlassReason is the CLOSED enum the recovery break-glass verdict reports. It is deliberately
// coarse: it names the condition that failed and nothing about who, how many or which code, so it is
// redaction-safe enough to travel in an API response and into the support pack. "ok" is the only ready
// value; every other member is a distinct remedy the operator can act on.
export type RecoveryBreakGlassReason =
  | "ok"
  | "no-passkey-bound-owner" // no Owner whose recovery session would carry Owner authority
  | "no-recovery-record" // no codes have ever been minted for such an Owner
  | "unparseable-recovery-record" // the stored record cannot be read, so nothing can be counted or verified
  | "no-unconsumed-codes" // every code in the set has been used
  | "recovery-codes-orphaned-from-key"; // the codes cannot verify: the key they were hashed under is gone

// isRecoveryRecordShaped is the PARSEABILITY gate the lockout pre-flight needs. A stored value that is not
// an object with a codes ARRAY and a string generatedAt cannot be counted, cannot be verified against, and
// would throw inside remainingCount. The pre-flight must answer "is a code usable" for such a record with
// NO, never with a fault and never with the optimistic default that produced the defect this exists to fix.
export function isRecoveryRecordShaped(rec: unknown): rec is RecoveryRecord {
  if (rec === null || typeof rec !== "object") return false;
  const r = rec as { codes?: unknown; generatedAt?: unknown };
  if (!Array.isArray(r.codes)) return false;
  if (typeof r.generatedAt !== "string" || r.generatedAt.length === 0) return false;
  for (const slot of r.codes) {
    if (slot === null || typeof slot !== "object") return false;
    const s = slot as { salt?: unknown; hash?: unknown };
    if (typeof s.salt !== "string" || typeof s.hash !== "string") return false;
  }
  return true;
}

// HASH_PREFIX tags the stored hash so the algorithm is unambiguous and a future change is detectable rather
// than silently misread (mirrors the codebase's "sha384:" / "edmldsa1:" tagged-digest discipline).
const HASH_PREFIX = "hmac-sha256:";

// randomCode returns one CSPRNG recovery code in the six-group xxxxx-...-xxxxx human format. Each character is an
// independent 5-bit draw mapped to RECOVERY_CODE_ALPHABET (a 32-symbol alphabet, so no modulo bias), taken
// from crypto.getRandomValues. The groups are joined by a single hyphen for readability; the hyphen is
// purely cosmetic and is stripped on normalisation, so a user may type it or not.
function randomCode(): string {
  const totalChars = RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_LEN;
  // One random byte per character; we use only the low 5 bits of each (0..31), an exact index into the
  // 32-symbol alphabet, so there is no bias from a modulo over a non-power-of-two.
  const rnd = crypto.getRandomValues(new Uint8Array(totalChars));
  const chars: string[] = [];
  for (let i = 0; i < totalChars; i++) {
    chars.push(RECOVERY_CODE_ALPHABET[rnd[i]! & 31]!);
  }
  const groups: string[] = [];
  for (let g = 0; g < RECOVERY_CODE_GROUPS; g++) {
    groups.push(chars.slice(g * RECOVERY_CODE_GROUP_LEN, (g + 1) * RECOVERY_CODE_GROUP_LEN).join(""));
  }
  return groups.join("-");
}

// normaliseCode canonicalises a presented code for comparison: upper-case, and strip every character that
// is not in the alphabet (so a hyphen, a space, or stray punctuation a user typed is ignored). The result
// is the bare alphabet characters the hash was computed over. A code whose normalised length is not exactly
// the expected length is structurally invalid; verifyCode treats that as no-match (never an error), so a
// malformed input cannot crash the recovery path and yields the same generic failure as a wrong code.
export function normaliseCode(raw: unknown): string {
  if (typeof raw !== "string") return "";
  let out = "";
  for (const ch of raw.toUpperCase()) {
    const mapped = RECOVERY_CODE_CONFUSABLES[ch];
    if (mapped !== undefined) out += mapped;
    else if (RECOVERY_CODE_ALPHABET_SET.has(ch)) out += ch;
  }
  return out;
}

// RECOVERY_CODE_CONFUSABLES is the Crockford base32 confusable MAP: a code is read off paper and typed
// back, so characters that look alike (O/0, I/L/1) map to the one the code really holds rather than being
// stripped, which would otherwise shorten a mistyped code below the expected length and fail verification.
// U maps to nothing: Crockford excludes it to avoid accidental obscenities, not for visual ambiguity.
const RECOVERY_CODE_CONFUSABLES: Record<string, string> = { I: "1", L: "1", O: "0" };

// RECOVERY_CODE_CHARS is the expected normalised length (the bare alphabet characters, hyphen excluded), so
// the DO and the validator agree on what a structurally-valid code looks like.
export const RECOVERY_CODE_CHARS = RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_LEN;

// hmacKey imports the raw in-DO session signing key as an HMAC-SHA-256 CryptoKey (non-extractable, sign
// only). The recovery-code HMAC deliberately reuses the SAME in-DO secret that signs sessions: it is a
// 32-byte CSPRNG key that already never leaves the DO, so there is one high-value secret to protect, not
// two. Importing per-call is fine (recovery generate/verify is not a hot loop).
async function hmacKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length < 32) {
    // The DO always supplies a >=32-byte session key; a short key is a misconfiguration, refuse loudly
    // rather than hash under a weak key.
    throw new Error(`recovery signing key too short: ${rawKey.length} < 32`);
  }
  return crypto.subtle.importKey("raw", ab(rawKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

// hashOf computes the stored hash for a (salt, normalised-code) pair: HMAC-SHA-256(key, salt-bytes ||
// code-bytes) as "hmac-sha256:" + hex. The salt is prepended to the message (domain separation per code),
// so two equal codes with different salts hash differently. This is the ONE place the hash is computed, so
// generation and verification cannot diverge in construction.
async function hashOf(rawKey: Uint8Array, salt: Uint8Array, normalisedCode: string): Promise<string> {
  const key = await hmacKey(rawKey);
  const codeBytes = new TextEncoder().encode(normalisedCode);
  const msg = new Uint8Array(salt.length + codeBytes.length);
  msg.set(salt, 0);
  msg.set(codeBytes, salt.length);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, ab(msg)));
  return HASH_PREFIX + hexEncode(mac);
}

// generateRecoveryCodes mints a fresh set of RECOVERY_CODE_COUNT codes, returning the PLAINTEXT codes (for
// the one-time display) AND the RecoveryRecord of salted hashes to persist. The plaintext is returned ONLY
// here and is never part of the record; the DO returns it to the caller exactly once and stores only the
// record. generatedAt is supplied by the DO (the DO owns the clock). The email must already be canonical
// (the DO normalises it before calling).
export async function generateRecoveryCodes(
  rawKey: Uint8Array,
  email: string,
  generatedAt: string,
): Promise<{ codes: string[]; record: RecoveryRecord }> {
  const codes: string[] = [];
  const hashes: RecoveryCodeHash[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const code = randomCode();
    const salt = crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_BYTES));
    const hash = await hashOf(rawKey, salt, normaliseCode(code));
    codes.push(code);
    hashes.push({ salt: b64urlEncode(salt), hash, consumed: false });
  }
  const record: RecoveryRecord = { email, codes: hashes, generatedAt, keyProof: await recoveryKeyProof(rawKey) };
  return { codes, record };
}

// RECOVERY_KEY_PROOF_LABEL is the fixed message the key-continuity witness is computed over. It is
// DOMAIN-SEPARATED from a code hash by construction: hashOf's message is (16 raw salt bytes || 30 alphabet
// characters), this one is a fixed ASCII label, so no salt/code pair can produce this MAC and the witness
// can never stand in for a code hash. The "v1" is there so a future change to the witness is a new label
// rather than a silent reinterpretation of an old one.
const RECOVERY_KEY_PROOF_LABEL = "downpipes/recovery-key-proof/v1";

// recoveryKeyProof computes the key-continuity witness for a raw key. Two records carry the same witness if
// and only if they were minted under the same key bytes, so comparing a record's stored witness against a
// freshly-computed one under the key the engine WOULD verify with answers "can a banked code from this
// record still verify?" exactly, with no code and no consumption. It reveals nothing about the key that the
// stored code hashes do not already (both are MACs under it), and it never leaves the DO.
export async function recoveryKeyProof(rawKey: Uint8Array): Promise<string> {
  const key = await hmacKey(rawKey);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, ab(new TextEncoder().encode(RECOVERY_KEY_PROOF_LABEL))));
  return HASH_PREFIX + hexEncode(mac);
}

// fakeRecoveryRecord is an anti-enumeration helper: it builds a throwaway RecoveryRecord
// shaped EXACTLY like a real one - RECOVERY_CODE_COUNT slots, each a real CSPRNG salt plus a hash-shaped
// string - WITHOUT ever calling hashOf/hmacKey (no crypto.subtle.importKey, no HMAC sign) and without
// drawing a randomCode() (a code that is never displayed has no reason to be human-formatted). The "hash" is
// just HASH_PREFIX + hex of 32 random bytes: the same tagged-hex shape and byte length verifyCode expects
// from a real HMAC-SHA-256 output, so it recomputes and compares against it exactly as for a real record and
// (being uniform random, not a real MAC) it can never match. Building this costs a few getRandomValues draws,
// not an HMAC pass, so the caller (dummyRecoveryRecord) no longer runs a full extra round of signing before
// verifyCode even starts - the no-record path now does the SAME crypto work as the real-record path, not
// double it.
export function fakeRecoveryRecord(): RecoveryRecord {
  const hashes: RecoveryCodeHash[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const salt = crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_BYTES));
    const fakeMac = crypto.getRandomValues(new Uint8Array(32)); // same byte length as a real HMAC-SHA-256 output
    hashes.push({ salt: b64urlEncode(salt), hash: HASH_PREFIX + hexEncode(fakeMac), consumed: false });
  }
  return { email: "dummy@invalid.example", codes: hashes, generatedAt: "1970-01-01T00:00:00.000Z" };
}

// VerifyResult is the outcome of checking a presented code against a record: matched (and which index, so
// the DO can mark exactly that code consumed) or not. It is intentionally minimal and carries NO reason
// (the DO returns a single generic failure to the client, so there is no oracle).
export interface VerifyResult {
  matched: boolean;
  index: number; // the matched code's index in record.codes, or -1 when no match
  // corruptSlots is HOW MANY of the record's stored slots had an UNDECODABLE salt or hash.
  // A corrupt slot can never match, so every code the operator types is rejected with the same generic,
  // no-oracle 401 the WRONG code gets -- "the owner lost their passkey and every recovery code fails" is then
  // byte-identical to "the owner is mistyping", and no store anywhere records that the PERSISTED RECORD is
  // unreadable. This is a COUNT of the defective slots and nothing else: never a salt, a hash or a code. The
  // caller (the DO) records it as a closed auth signal; the client-facing response is unchanged and stays
  // generic, so the no-oracle property is preserved.
  corruptSlots: number;
}

// RECOVERY_SIGNING_KEY_MIN_BYTES is the floor hmacKey enforces. A shorter key is a misconfiguration and every
// recovery-code operation throws under it (a bare 500), so the LAST way back into a locked-out account is
// broken with nothing recorded anywhere. isRecoverySigningKeyUsable lets the DO OBSERVE that state
// before it walks into the throw, and record recovery-signing-key-invalid. It is a length check on a key it
// never returns, logs or hashes.
export const RECOVERY_SIGNING_KEY_MIN_BYTES = 32;

export function isRecoverySigningKeyUsable(rawKey: Uint8Array): boolean {
  return rawKey.length >= RECOVERY_SIGNING_KEY_MIN_BYTES;
}

// verifyCode checks a presented code against a record's UNCONSUMED hashes in CONSTANT TIME. It normalises
// the input, then for EVERY code in the record recomputes the HMAC over (that code's salt || the normalised
// input) and compares to the stored hash in constant time, recording the first unconsumed match. It walks
// the WHOLE list (it does not early-exit on the first match) so the work is independent of where (or
// whether) a match lies, removing a timing oracle on the match position. A consumed code can never match
// (its slot is skipped for the match decision even if the bytes equal). A structurally-invalid input (wrong
// length after normalisation) still walks the list against a fixed dummy so the timing does not reveal "too
// short"; it simply never matches. It does not throw in normal operation; a caller that modifies hashOf
// should guard this call (the DO still guards it regardless).
export async function verifyCode(rawKey: Uint8Array, record: RecoveryRecord, presented: unknown): Promise<VerifyResult> {
  const norm = normaliseCode(presented);
  // A structurally-invalid code (wrong length) never matches (the structurallyValid gate prevents it), but
  // the loop still runs hashOf for each slot so the iteration count leaks nothing. The hash input varies
  // slightly from a valid code, but the per-slot HMAC work is dominated by the fixed key schedule, not the
  // message length. The match is forced off below.
  const structurallyValid = norm.length === RECOVERY_CODE_CHARS;
  let matchedIndex = -1;
  // COUNT the slots whose persisted salt/hash will not decode. This is the ONLY place the engine can
  // see that the stored record is corrupt (both decode failures below already fall back to empty bytes so the
  // loop's timing stays uniform, and then simply never match), and until now it was thrown away -- so a
  // corrupt record and a mistyped code produced the identical generic 401 forever.
  let corruptSlots = 0;
  for (let i = 0; i < record.codes.length; i++) {
    const slot = record.codes[i]!;
    let salt: Uint8Array;
    let slotCorrupt = false;
    try {
      salt = b64urlDecode(slot.salt);
    } catch {
      // A corrupt stored salt can never match; still do equivalent work (hash over an empty salt) so the
      // loop body's cost stays uniform, and leave the match off.
      salt = new Uint8Array(0);
      slotCorrupt = true;
    }
    const recomputed = await hashOf(rawKey, salt, norm);
    let expected: Uint8Array;
    try {
      expected = hexDecodeTagged(slot.hash);
    } catch {
      expected = new Uint8Array(0);
      slotCorrupt = true;
    }
    if (slotCorrupt) corruptSlots++;
    const recomputedBytes = hexDecodeTagged(recomputed);
    const equal = constantTimeEqual(recomputedBytes, expected);
    // Accept the match ONLY for a structurally-valid input, an UNCONSUMED slot, and the FIRST such match.
    // The boolean AND here is on already-computed values (no new branch on the secret), and we do not break
    // the loop, so the remaining slots are still walked.
    if (equal && structurallyValid && !slot.consumed && matchedIndex === -1) {
      matchedIndex = i;
    }
  }
  return { matched: matchedIndex !== -1, index: matchedIndex, corruptSlots };
}

// hexDecodeTagged decodes a "hmac-sha256:" + hex string to bytes, tolerating an already-bare hex string. It
// is a tiny local helper so verifyCode can compare raw MAC bytes (constant-time over equal-length byte
// arrays) rather than hex strings (a string compare would early-exit and leak a prefix). A malformed value
// throws, which the caller maps to a non-matching empty array.
function hexDecodeTagged(s: string): Uint8Array {
  const hex = s.startsWith(HASH_PREFIX) ? s.slice(HASH_PREFIX.length) : s;
  if (hex.length === 0 || hex.length % 2 !== 0) throw new Error("bad hash hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("bad hash hex");
    out[i] = byte;
  }
  return out;
}

// remainingCount is the number of UNCONSUMED codes in a record (0 when the record is absent). It is the
// single source of the "codes left" the console shows and the posture low-warning reads, derived from the
// hashes so it can never drift from the stored truth.
export function remainingCount(record: RecoveryRecord | null): number {
  if (record === null) return 0;
  let n = 0;
  for (const c of record.codes) if (!c.consumed) n++;
  return n;
}

// RECOVERY_CODES_LOW_THRESHOLD now lives in recovery-constants.ts (a dependency-free module) so the pure
// posture-checks module and scheduler-do.ts bind to the same literal. Re-exported here to keep the existing
// public import path stable.
export { RECOVERY_CODES_LOW_THRESHOLD };
