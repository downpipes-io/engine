// ULID text to its 16-byte binary form, the form used as an HKDF salt and in MACs
// (SPEC 11.6). Crockford base32, uppercase, canonical.

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Decodes a canonical 26-character Crockford base32 ULID to its 16-byte binary form (SPEC 11.6),
 * the form used as an HKDF salt and in MACs.
 *
 * @param s - the 26-character uppercase Crockford base32 ULID.
 * @returns the 16-byte binary ULID.
 * @throws Error when the string is not 26 characters or contains a non-Crockford character, and
 *   when its first character overflows 128 bits.
 */
export function decodeULID(s: string): Uint8Array {
  if (s.length !== 26) throw new Error("ulid must be 26 characters");
  let bits = 0n;
  for (const ch of s) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) throw new Error(`invalid ULID character: ${ch}`);
    bits = (bits << 5n) | BigInt(v);
  }
  // 26 * 5 = 130 bits; a canonical ULID fits in 128 bits, so the top 2 bits must
  // be zero. The first Crockford character encodes the top 5 bits; any value above
  // 7 (binary 01000) sets bit 128 or higher. Silently truncating would make
  // distinct runId strings collapse to the same 16-byte salt, so we reject instead,
  // matching the Go reference DecodeULID ("first character overflows 128 bits").
  if (bits >> 128n !== 0n) {
    throw new Error(`ULID first character overflows 128 bits: ${s[0]}`);
  }
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(bits & 0xffn);
    bits >>= 8n;
  }
  return out;
}

/**
 * Reports whether s is a canonical ULID, without throwing. HI-09: a caller-supplied runId is
 * interpolated raw into object-key templates (`run/${runId}/...`); Crockford's alphabet excludes
 * '.', '/', '-' and '_', so this one check is enough to keep a dot-segment ("..") or path-separator
 * payload out of any key built from it, closing the S3-destination URL-collapse class at the input.
 *
 * @param s - the candidate string.
 * @returns whether s decodes as a canonical ULID.
 */
export function isValidRunId(s: string): boolean {
  try {
    decodeULID(s);
    return true;
  } catch {
    return false;
  }
}

// G321 (support-pack gap audit). isValidRunId SWALLOWS the specific decode reason: the restore /
// verify endpoints answer a flat 400 "runId must be a valid ULID", nothing is persisted, and support cannot
// see server-side whether the customer's integration script is sending TRUNCATED ids (a 25-character slice, an
// off-by-one), LOWER-CASED or otherwise non-Crockford ids (a UUID library, an 'O'-for-'0' transcription), or
// ids whose first character overflows 128 bits (a home-made generator). Those are three different fixes and
// the customer cannot be told which one applies.
//
// The classifier below is the closed answer. It returns an ENUM MEMBER and nothing else: the candidate string
// is the one value that must never be recorded (a hostile or careless caller can put ANYTHING in it -- a
// token, an email, a path traversal), so it is read here to select a member and then discarded.

/**
 * RUNID_MALFORM_KINDS is the closed set of reasons a candidate runId failed the canonical-ULID check.
 * Each member points at a different fix on the customer's side (the id is being sliced, the alphabet is
 * wrong, or the generator is emitting out-of-range values), which is the split the flat 400 could not
 * make. Kept in declaration order; the classifier tests length, then charset, then the 128-bit range.
 */
export const RUNID_MALFORM_KINDS = [
  "length", // not 26 characters: a truncated / padded / concatenated id (the classic integration-script bug)
  "charset", // a non-Crockford character: a lower-cased id, a UUID, an 'O'/'I'/'L' transcription slip
  "overflow", // 26 valid characters whose first overflows 128 bits: a home-made generator emitting out-of-range ids
] as const;
/**
 * RunIdMalformKind is the union over RUNID_MALFORM_KINDS. It is the only value besides null that
 * classifyRunIdMalformation may return, which is what keeps the candidate string (potentially a token, an
 * email or a traversal payload a caller supplied) out of every record built from the classification.
 */
export type RunIdMalformKind = (typeof RUNID_MALFORM_KINDS)[number];

/**
 * classifyRunIdMalformation reports WHY a candidate runId is not a canonical ULID, as a closed enum, or null
 * when it is valid. It reads the candidate ONLY to select a member and RETURNS that member: the candidate
 * itself (which could be any string a caller chose) never leaves this function.
 *
 * @param s - the candidate string.
 * @returns the closed malformation kind, or null when the candidate is a canonical ULID.
 */
export function classifyRunIdMalformation(s: unknown): RunIdMalformKind | null {
  if (typeof s !== "string" || s.length !== 26) return "length";
  for (const ch of s) {
    if (CROCKFORD.indexOf(ch) < 0) return "charset";
  }
  // The charset is clean and the length is right, so the only remaining refusal is the 128-bit overflow the
  // decoder makes (26 * 5 = 130 bits, and a canonical ULID fits in 128).
  return isValidRunId(s) ? null : "overflow";
}
