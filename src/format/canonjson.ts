import { utf8 } from "../crypto/bytes.ts";

// Canonical JSON for signing (SPEC 11.1): object keys sorted by UTF-16 code unit, no
// insignificant whitespace, integers only, no HTML escaping, and only valid-UTF-8 strings.
// JavaScript's default string comparison is already UTF-16 code-unit order, matching the Go
// reference's lessUTF16, and JSON.stringify does not HTML-escape, so a recursive sorted-key
// compact stringify reproduces the canonical form for the manifests this engine writes. A
// string carrying a lone surrogate has no valid UTF-8 encoding; rather than let JSON.stringify
// emit an escaped \uD8xx that the Go reader refuses (utf8.ValidString), this rejects it, so
// the two ports agree on which objects are signable (see canonString below).

/**
 * Serialises a value to canonical JSON bytes for signing (SPEC 11.1): object keys sorted by UTF-16
 * code unit, no insignificant whitespace, integers only, no HTML escaping, and only valid-UTF-8
 * strings.
 *
 * @param value - the value to canonicalise (objects, arrays, strings, integers, booleans, null).
 * @returns the canonical JSON encoding as UTF-8 bytes.
 * @throws Error when the value contains a non-integer or out-of-range number, raw bytes, a string
 *   with a lone surrogate (no valid UTF-8), or an unsupported type.
 */
export function canonicalJSON(value: unknown): Uint8Array {
  return utf8(canon(value));
}

// hasLoneSurrogate reports whether a UTF-16 string contains an unpaired surrogate: a high
// surrogate (U+D800-U+DBFF) not immediately followed by a low surrogate (U+DC00-U+DFFF), or
// a low surrogate not immediately preceded by a high one. Such a string has no valid UTF-8
// encoding, so the Go reference (canonjson.go, utf8.ValidString) refuses to canonicalise it
// rather than transcode it to U+FFFD. A well-formed surrogate pair (a supplementary code
// point) is left alone. We scan the raw code units rather than using a "� round-trips"
// test so a deliberately-embedded U+FFFD is not mistaken for an invalid input.
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      // High surrogate: the next unit must be a low surrogate to form a valid pair.
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i++; // consume the paired low surrogate
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      // A low surrogate not preceded by a high one (a leading high surrogate would have
      // consumed it above), so it is unpaired.
      return true;
    }
  }
  return false;
}

// canonString encodes a JSON string, first rejecting any input that is not valid UTF-8 (a
// lone surrogate). A name must not be quietly rewritten and a signature must stay
// reproducible (SPEC 11.1, 6.4), so the two ports agree on which strings are signable. This
// guards both values and object keys.
function canonString(s: string): string {
  if (hasLoneSurrogate(s)) {
    throw new Error("string is not valid UTF-8 (lone surrogate); canonical JSON must not transcode it");
  }
  return JSON.stringify(s);
}

function canon(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error(`non-integer number ${v} is not allowed in a signed object`);
    if (!Number.isSafeInteger(v)) throw new Error(`integer ${v} exceeds the 2^53-1 canonical ceiling`);
    return String(v);
  }
  if (typeof v === "string") return canonString(v);
  if (v instanceof Uint8Array) throw new Error("raw bytes must be base64url-encoded to a string before canonicalisation");
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (typeof v === "object") {
    // safe: the null guard, Array guard and typeof check above narrow v to a plain object
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort(); // default JS sort is UTF-16 code-unit order
    return `{${keys.map((k) => `${canonString(k)}:${canon(obj[k])}`).join(",")}}`;
  }
  throw new Error(`unsupported value in canonical JSON: ${typeof v}`);
}
