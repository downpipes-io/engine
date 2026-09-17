// Canonical numeric form (SPEC 11.3), ported from the Go reference
// internal/format/canonnum.go. Count and size fields carried as JSON numbers must be
// non-negative integers at most 2^53-1; a value encoded as a string is rejected even
// when in range (the string form is reserved for values above the ceiling, which this
// reader does not accept). A missing field is permitted.

import { integrityError } from "./integrity-error.ts";

const MAX_CANONICAL = BigInt(2 ** 53 - 1);

// resolvePath walks a dotted path through parsed JSON objects, mirroring the Go reference
// resolvePath (canonnum.go). It returns the value at the path, or undefined when any
// segment is missing or a non-object is encountered. Resolving structurally (rather than
// scanning the source text for the leaf name) is what makes a leaf-name collision resolve
// the correct field: a sibling or ancestor object with the same leaf key is never reached.
function resolvePath(value: unknown, parts: string[]): unknown {
  let cur: unknown = value;
  for (const p of parts) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[p];
    if (cur === undefined) return undefined;
  }
  return cur;
}

// checkCanonicalCount enforces SPEC 11.3 for one resolved value, mirroring the Go
// reference checkCanonicalCount (canonnum.go). The parsed JSON type is authoritative: a
// JSON string parses to a string (rejected, the string form is reserved for values above
// the ceiling), a JSON number parses to a number (which must be a non-negative integer at
// most 2^53-1). A missing field (undefined/null) is permitted.
function checkCanonicalCount(field: string, v: unknown): void {
  if (v === undefined || v === null) return; // a missing field is permitted
  if (typeof v === "string") {
    throw integrityError(
      `field "${field}" must be a canonical integer, not a string (the string form is reserved for values above 2^53-1, which this reader does not accept)`,
    );
  }
  if (typeof v !== "number") {
    throw integrityError(`field "${field}" must be a canonical integer, not ${typeof v}`);
  }
  // A non-finite value (a JSON token such as 1e400 parses to Infinity) or a fractional
  // value is not an integer. Number.isInteger is false for both, matching Go's rejection
  // of any token containing ".eE".
  if (!Number.isInteger(v)) {
    throw integrityError(`field "${field}" is not an integer: ${v}`);
  }
  // Counts are non-negative; reject any negative value. Go rejects any token with a
  // leading "-", including the non-canonical "-0"; JSON "-0" parses to JavaScript -0, so
  // reject that too (Object.is distinguishes -0 from 0) to keep the rejection faithful.
  if (v < 0 || Object.is(v, -0)) {
    throw integrityError(`field "${field}" must be a non-negative integer: ${v}`);
  }
  if (BigInt(v) > MAX_CANONICAL) {
    throw integrityError(`field "${field}" is out of canonical range (>2^53-1): ${v}`);
  }
}

/**
 * Enforces the SPEC 11.3 canonical-numeric rules for each named field in the raw JSON source text:
 * a count or size field must be a non-negative integer at most 2^53-1, the string form is rejected
 * even when in range, and a missing field is permitted. The source is parsed once and each
 * (possibly dotted) path is resolved structurally, so a leaf-name collision resolves the correct
 * field. Mirrors the Go reference validateCounts (a violation is a usage error, exit 6).
 *
 * @param rawText - the raw JSON source text to check (parsed once).
 * @param paths - the field paths to validate; a dotted path walks nested objects.
 * @returns nothing; it either passes silently or throws.
 * @throws Error when the JSON cannot be parsed, or any named field is a string, a non-integer, a
 *   negative value, or above the 2^53-1 ceiling.
 */
export function validateCanonicalCounts(rawText: string, ...paths: string[]): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (e) {
    throw integrityError(`canonical-numeric check could not parse the JSON: ${(e as Error).message}`);
  }
  for (const p of paths) {
    const v = resolvePath(parsed, p.includes(".") ? p.split(".") : [p]);
    checkCanonicalCount(p, v);
  }
}
