// Canonical numeric form (SPEC 11.3), ported from the Go reference
// internal/format/canonnum.go. Count and size fields carried as JSON numbers must be
// non-negative integers at most 2^53-1; a value encoded as a string is rejected even
// when in range (the string form is reserved for values above the ceiling, which this
// reader does not accept). A missing field is permitted; a field present as JSON null is refused, as is a null array or object on the path to it
// (except at a step marked "?").
//
// The rule is about the TOKEN, not the parsed value. Go decodes with UseNumber and refuses any token that
// carries ".", "e" or "E", so "1.0" and "1e2" are refused even though they parse to integers. JSON.parse
// folds both to 1 and 100, so this port reads each number's source text through the reviver's context
// (JSON.parse source text access) and applies Go's token rules to that text.

import { integrityError } from "./integrity-error.ts";

const MAX_CANONICAL = BigInt(2 ** 53 - 1);

// NumberToken is one parsed JSON number, kept as the exact token text it was parsed from.
class NumberToken {
  readonly source: string;
  constructor(source: string) {
    this.source = source;
  }
}

type SourceReviver = (this: unknown, key: string, value: unknown, context?: { source?: string }) => unknown;

// parseWithTokens parses rawText and replaces every number with its NumberToken, so the check below sees the
// token Go sees. A runtime without source text access cannot apply the rule, so it refuses rather than pass a
// token it cannot read.
function parseWithTokens(rawText: string): unknown {
  const reviver: SourceReviver = (_key, value, context) => {
    if (typeof value !== "number") return value;
    if (typeof context?.source !== "string") throw new Error("this runtime does not expose JSON number source text");
    return new NumberToken(context.source);
  };
  return (JSON.parse as (text: string, reviver: SourceReviver) => unknown)(rawText, reviver);
}

// foldKey approximates Go's strings.EqualFold for the field-name collision check: two keys collide when they
// are equal after upper-casing then lower-casing (which also folds the long s with "s" and the Kelvin sign
// with "k").
function foldKey(k: string): string {
  return k.toUpperCase().toLowerCase();
}

interface CountSite {
  path: string;
  value: unknown;
}

// collectCounts walks one dotted path through the parsed JSON, mirroring the Go reference collectCounts
// (canonnum.go). A segment ending in "[]" names an array whose every element is walked. A segment ending in
// "?" names an object the format allows to be null. A missing field yields nothing (permitted); a non-object
// on the way yields nothing; a key that differs from the wanted one only in case is refused, because Go's
// case-insensitive struct decoding would read it. A null on the path is present and is not the shape the
// format gives that field, so it is refused: a null count, a null array, a null object the count sits in and
// a null array element before a further step. Only a "?" step may be null, and a null there adds nothing.
// Resolving structurally (rather than scanning the source text for the leaf name) is what makes a leaf-name
// collision resolve the correct field: a sibling or ancestor object with the same leaf key is never reached.
function collectCounts(v: unknown, parts: string[], prefix: string, out: CountSite[]): void {
  if (parts.length === 0) {
    out.push({ path: prefix, value: v });
    return;
  }
  const each = parts[0]!.endsWith("[]");
  const seg = each ? parts[0]!.slice(0, -2) : parts[0]!;
  const nullable = seg.endsWith("?");
  const key = nullable ? seg.slice(0, -1) : seg;
  if (v === null || typeof v !== "object" || Array.isArray(v) || v instanceof NumberToken) return;
  const path = prefix === "" ? key : `${prefix}.${key}`;
  const obj = v as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (k !== key && foldKey(k) === foldKey(key)) {
      throw integrityError(`field "${path}" appears as "${k}", which differs only in case: canonical field names are exact`);
    }
  }
  if (!Object.hasOwn(obj, key)) return;
  const child = obj[key];
  if (child === undefined) return;
  if (child === null) {
    if (nullable) return;
    if (parts.length === 1 && !each) throw integrityError(`field "${path}" must be a canonical integer, not null`);
    if (each) throw integrityError(`field "${path}" must be an array, not null`);
    throw integrityError(`field "${path}" must be an object, not null`);
  }
  if (!each) {
    collectCounts(child, parts.slice(1), path, out);
    return;
  }
  if (!Array.isArray(child)) throw integrityError(`field "${path}" must be an array, not ${typeof child}`);
  for (let i = 0; i < child.length; i++) {
    const elPath = `${path}[${i}]`;
    if (child[i] === null && parts.length > 1) throw integrityError(`field "${elPath}" must be an object, not null`);
    collectCounts(child[i], parts.slice(1), elPath, out);
  }
}

// checkCanonicalCount enforces SPEC 11.3 for one resolved value, mirroring the Go reference
// checkCanonicalCount (canonnum.go). The parsed JSON type decides the kind (a JSON string is rejected,
// because the string form is reserved for values above the ceiling); for a number the TOKEN text decides:
// no ".", "e" or "E", no leading "-" (which also refuses "-0"), no leading zero, and at most 2^53-1.
function checkCanonicalCount(field: string, v: unknown): void {
  if (typeof v === "string") {
    throw integrityError(
      `field "${field}" must be a canonical integer, not a string (the string form is reserved for values above 2^53-1, which this reader does not accept)`,
    );
  }
  if (!(v instanceof NumberToken)) {
    throw integrityError(`field "${field}" must be a canonical integer, not ${v === null ? "null" : typeof v}`);
  }
  const s = v.source;
  if (/[.eE]/.test(s)) throw integrityError(`field "${field}" is not an integer: ${s}`);
  if (s.startsWith("-")) throw integrityError(`field "${field}" must be a non-negative integer: ${s}`);
  if (s.length > 1 && s[0] === "0") throw integrityError(`field "${field}" has a leading zero and is not in canonical form: ${s}`);
  if (!/^[0-9]+$/.test(s) || BigInt(s) > MAX_CANONICAL) {
    throw integrityError(`field "${field}" is out of canonical range (>2^53-1): ${s}`);
  }
}

/**
 * Enforces the SPEC 11.3 canonical-numeric rules for each named field in the raw JSON source text:
 * a count or size field must be a non-negative integer token at most 2^53-1 (no fraction, exponent,
 * sign or leading zero, even when the value it parses to is an integer), the string form is rejected
 * even when in range, a key that differs from the field name only in case is rejected, and a missing
 * field is permitted. The source is parsed once and each (possibly dotted) path is resolved
 * structurally, so a leaf-name collision resolves the correct field; a segment ending in "[]" checks
 * every element of an array and a segment ending in "?" may be null. Mirrors the Go reference validateCounts (a violation is a usage error,
 * exit 6).
 *
 * @param rawText - the raw JSON source text to check (parsed once).
 * @param paths - the field paths to validate; a dotted path walks nested objects and a "[]" suffix walks an array.
 * @returns nothing; it either passes silently or throws.
 * @throws Error when the JSON cannot be parsed, or any named field is a string, a non-canonical number
 *   token, a negative value, above the 2^53-1 ceiling, a case variant of the field name, or an array
 *   segment that is not an array.
 */
export function validateCanonicalCounts(rawText: string, ...paths: string[]): void {
  let parsed: unknown;
  try {
    parsed = parseWithTokens(rawText);
  } catch (e) {
    throw integrityError(`canonical-numeric check could not parse the JSON: ${(e as Error).message}`);
  }
  for (const p of paths) {
    const sites: CountSite[] = [];
    collectCounts(parsed, p.split("."), "", sites);
    for (const site of sites) checkCanonicalCount(site.path, site.value);
  }
}
