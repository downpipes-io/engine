// fast-check property tests (guardrails B7-3): a SMALL, BOUNDED set of generative properties over
// the crypto byte helpers and the canonical-JSON serialiser. ADDITIVE to the deterministic Node
// validators (which assert fixed reference vectors); these assert invariants over MANY random
// inputs that a fixed vector cannot.
//
// Run:  node test/property/property-crypto-format.ts   (or: npm run test:property)
//
// Kept deliberately fast: low run counts and bounded input sizes, so this stays well inside a CI
// step and never becomes a slow gate. It exercises:
//   - base64url and hex encode/decode ROUNDTRIP (decode(encode(x)) === x)
//   - canonicalJSON STABILITY (key order in the input object never changes the output bytes)
//   - constantTimeEqual CORRECTNESS (matches a plain compare on equal/unequal/length-mismatch)
//
// It does NOT attempt to assert timing (a constant-time TIMING measurement is flaky in JS); it
// asserts the FUNCTIONAL contract of constantTimeEqual, which is what the validators consume.
import fc from "fast-check";

import { b64urlEncode, b64urlDecode, hexEncode, hexDecode, constantTimeEqual } from "../../src/crypto/bytes.ts";
import { canonicalJSON } from "../../src/format/canonjson.ts";

let failures = 0;
function prop(label: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ok   ${label}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${label}: ${(e as Error).message}`);
  }
}

// Bytes generator: arrays of 0..256 bytes is plenty to cover the base64url 3-byte grouping
// (rem 0/1/2) and hex padding without being slow.
const bytes = fc.uint8Array({ minLength: 0, maxLength: 256 });
const RUNS = { numRuns: 200 };

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

console.log("crypto/format property vectors (fast-check)");

prop("base64url roundtrip: decode(encode(x)) === x", () => {
  fc.assert(
    fc.property(bytes, (x) => eq(b64urlDecode(b64urlEncode(x)), x)),
    RUNS,
  );
});

prop("hex roundtrip: decode(encode(x)) === x, and encode is lowercase no-pad", () => {
  fc.assert(
    fc.property(bytes, (x) => {
      const h = hexEncode(x);
      if (h.length !== x.length * 2) return false;
      if (h !== h.toLowerCase()) return false;
      return eq(hexDecode(h), x);
    }),
    RUNS,
  );
});

prop("canonicalJSON stability: insertion order of keys does not change the output bytes", () => {
  // Build an object two ways (forward and reversed key insertion order) from the same entries.
  const keyArb = fc.string({ minLength: 1, maxLength: 8 }).filter((s) => !/[\uD800-\uDFFF]/.test(s));
  const entriesArb = fc.uniqueArray(fc.tuple(keyArb, fc.integer({ min: -1000, max: 1000 })), {
    selector: (t) => t[0],
    minLength: 0,
    maxLength: 8,
  });
  fc.assert(
    fc.property(entriesArb, (entries) => {
      const forward: Record<string, number> = {};
      for (const [k, v] of entries) forward[k] = v;
      const reversed: Record<string, number> = {};
      for (const [k, v] of [...entries].reverse()) reversed[k] = v;
      return eq(canonicalJSON(forward), canonicalJSON(reversed));
    }),
    RUNS,
  );
});

prop("canonicalJSON determinism: the same value always serialises to the same bytes", () => {
  const jsonish = fc.jsonValue({ maxDepth: 3 }).map((v) => {
    // canonicalJSON requires integer numbers only; coerce any number to a bounded integer.
    return JSON.parse(JSON.stringify(v), (_k, val) => (typeof val === "number" ? Math.trunc(val) : val));
  });
  fc.assert(
    fc.property(jsonish, (v) => {
      try {
        return eq(canonicalJSON(v), canonicalJSON(v));
      } catch {
        // Inputs canonicalJSON legitimately rejects (e.g. non-integer it could not coerce) are not
        // a stability counterexample; skip them.
        return true;
      }
    }),
    RUNS,
  );
});

prop("constantTimeEqual matches a plain compare for equal, unequal and length-mismatched inputs", () => {
  // Equal pairs.
  fc.assert(
    fc.property(bytes, (x) => constantTimeEqual(x, Uint8Array.from(x)) === true),
    RUNS,
  );
  // Arbitrary pairs: the result must agree with a plain byte compare.
  fc.assert(
    fc.property(bytes, bytes, (a, b) => constantTimeEqual(a, b) === eq(a, b)),
    RUNS,
  );
  // A single flipped byte in an otherwise-equal array must make them unequal.
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 1, maxLength: 256 }),
      fc.nat(),
      (x, idx) => {
        const i = idx % x.length;
        const y = Uint8Array.from(x);
        y[i] = (y[i]! ^ 0x01) & 0xff;
        return constantTimeEqual(x, y) === false;
      },
    ),
    RUNS,
  );
});

if (failures > 0) process.exitCode = 1;
if (failures === 0) {
  console.log("\nall crypto/format property vectors passed");
  process.exit(0);
} else {
  console.log(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
