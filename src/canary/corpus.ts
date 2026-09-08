import { utf8 } from "../crypto/bytes.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../sources/types.ts";

// The canary corpus is the KNOWN DATA: a small, fixed, fully deterministic set of records the
// canary seals every flight and compares the read-back against, byte-for-byte. It is generated
// in code from constant seeds (no clock, no randomness), so the bytes are identical on every
// flight and on every deployment. That determinism is the whole point: it is the "exact known
// data" the owner specified, so any deviation of even a single bit is provable. The records
// span the byte shapes that catch real corruption: every byte value 0x00..0xFF, all-zeros,
// all-ones, multibyte UTF-8, structured JSON, and a kilobyte of deterministic pseudo-random
// bytes (a transposition or truncation anywhere shows up as a byte delta).

// CanaryRecord is one known record: a stable name and its exact bytes.
export interface CanaryRecord {
  name: string;
  value: Uint8Array;
}

// xorshift32 is a tiny deterministic PRNG. It is NOT cryptographic; it exists only to fill a
// record with bytes that are non-trivial yet reproducible from a constant seed, so a silent
// truncation, padding or transposition in the archive path surfaces as a byte delta rather
// than hiding in a block of zeros.
function deterministicBytes(seed: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed >>> 0;
  for (let i = 0; i < length; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

function allByteValues(): Uint8Array {
  const out = new Uint8Array(256);
  for (let i = 0; i < 256; i++) out[i] = i;
  return out;
}

// CANARY_CORPUS is the canonical known data. Order and names are stable; readers match by name.
export const CANARY_CORPUS: readonly CanaryRecord[] = Object.freeze([
  { name: "canary/ascii", value: utf8("downpipes canary: the bird sings while every byte returns exactly.") },
  // Multibyte UTF-8 (accents, an emoji and a CJK ideograph) so an encoding-layer mangle is caught.
  { name: "canary/utf8", value: utf8("coalmine, le canari chante éèê 🐦 暑") },
  { name: "canary/all-bytes", value: allByteValues() },
  { name: "canary/zeros", value: new Uint8Array(64) },
  { name: "canary/ones", value: new Uint8Array(64).fill(0xff) },
  { name: "canary/json", value: utf8('{"bird":"canary","alive":true,"records":7,"note":"known answer"}') },
  { name: "canary/block-1k", value: deterministicBytes(0x9e3779b9, 1024) },
]);

// CANARY_CORPUS_BYTES is the total plaintext byte count of the corpus, for a coarse display.
export const CANARY_CORPUS_BYTES = CANARY_CORPUS.reduce((n, r) => n + r.value.length, 0);

// CanarySource is the SourceAdapter that yields the corpus to the seal pipeline. It reads
// nothing live and holds no key; it only yields the in-code known records. The seal path treats
// them as ordinary buffered records (sourceType "kv", namespace "canary") and seals their bytes
// exactly as it would a real value, so the canary exercises the real write path end to end.
export class CanarySource implements SourceAdapter {
  readonly sourceType = "kv" as const;

  async *crawl(_selector: Selector): AsyncIterable<SourceRecord> {
    for (const rec of CANARY_CORPUS) {
      yield { sourceType: "kv", name: rec.name, value: rec.value, namespace: "canary" };
    }
  }

  async estimate(_selector: Selector): Promise<{ records: number; bytes: number }> {
    return { records: CANARY_CORPUS.length, bytes: CANARY_CORPUS_BYTES };
  }
}
