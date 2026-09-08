// Prove the streaming seal is byte-identical to the buffered sealStream across sizes
// (empty, partial, exact 64 KiB multiple, multi-chunk, multi-chunk+partial), that the
// optional aad is threaded into every chunk exactly as the buffered sealStream and the Go
// reference streamWriter do, that a fixed multi-chunk seal matches a frozen byte pin, and
// that the streaming two-pass addressing (addressStream) matches the buffered segId +
// plaintext SHA-384 for both the non-secret and the secrets address class.
// Run: node test/validate-streamseal.ts

import { sealStream } from "../src/crypto/stream.ts";
import { sealStreamTo, sealSegmentToStream, addressStream, type ChunkSource, type StreamingValue } from "../src/crypto/streamseal.ts";
import { deriveCAK, deriveNonSecretFileKey, segID } from "../src/crypto/derive.ts";
import { sealNonSecretSegment } from "../src/crypto/segment.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { b64urlDecode, b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { ADDR_SECRETS, ADDR_SINGLE_NON_SECRET, CHUNK_SIZE, CODEC_NONE } from "../src/format/version.ts";
import { sealRecordToDest, type RecordSealDeps } from "../src/seal/record.ts";
import { coarseRunError } from "../src/seal/slice.ts";
import { MAX_SINGLE_RECORD_CONTENT_BYTES, MAX_SINGLE_SLICE_RECORD_BYTES, MAX_SLICE_WALL_MS } from "../src/seal/budget.ts";
import { R2_MAX_SINGLE_PUT } from "../src/dest/types.ts";
import { BYTE_RANGE_WINDOW } from "../src/sources/byte-fetch.ts";
import type { Destination } from "../src/dest/types.ts";

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return concat(...parts);
}

// Frozen multi-chunk pin. A deterministic 3-chunk plaintext (2 full chunks + a
// 777-byte tail) sealed under the Go-pinned crypto-kat fileKey and 16 x 0x01 payload
// nonce. Reusing the crypto-kat fileKey/nonce means the payload key is HKDF-SHA-384 over
// the exact bytes the crypto-kat already pins to the Go reference (its single-chunk
// streamBody rides the same fileKey + nonce), so this multi-chunk seal rides the
// identical Go AES-256-GCM keystream; the per-chunk nonce framing (counter in bytes
// 3..10, last-chunk flag in byte 11) is the SPEC 7.8 construction that stream.go emits.
// The pin is therefore a Go-keystream-anchored byte freeze (not a committed Go vector):
// any drift in the chunk-nonce counter placement, the last-chunk flag, the chunk
// ordering or the 64 KiB boundary changes these digests and fails here, even if the
// buffered and streaming paths were to drift together. SHA-384(payload) is pinned rather
// than the whole ~129 KiB payload to keep the vector small.
// PIN_FILE_KEY_B64 is a verbatim copy of the crypto-kat fileKey (that vector's fileKey is derived through
// INFO_SEG_KEY / INFO_PAYLOAD), so this pin's key rides the live crypto-kat keystream the anchoring claim
// above depends on. The four OUTPUT pins below are computed from it. The INPUTS (nonce, tail length, aad,
// plaintext fill) define the frozen construction.
const PIN_FILE_KEY_B64 = "F6WUTEv98T0FGyWhsV1X5WTFsd4X2OYw4cpojHlRVpw";
const PIN_NONCE_B64 = "AQEBAQEBAQEBAQEBAQEBAQ"; // 16 x 0x01, the crypto-kat payload nonce
const PIN_TAIL = 777; // bytes after the second full chunk: a 3-chunk seal
const PIN_SHA384 = "qWFn7Y13hgHXSJE18zjmpJVG6gQBBnCoScLMhUDGAkHfRYkdLELB0CUgPSxY2j_s";
const PIN_HEAD_B64 = "AQEBAQEBAQEBAQEBAQEBAXCMk2EdgCO5"; // nonce(16) + first 8 ciphertext bytes
const PIN_TAIL_B64 = "HUhlPUcC9ZpP-IOA8aSOIJ2kQA1B7_rZ"; // last 24 bytes of the payload
// With a non-empty aad the whole seal changes; this is the frozen digest of the same
// plaintext sealed under the same key/nonce but with the aad below bound into every chunk.
const PIN_AAD = "downpipe-capsule-commitment-pin";
const PIN_SHA384_AAD = "IZZ0S2xdR-qwf1_gnbBbnfiGtlc8Ik8eHaZ_CFdfA0NMKy6IEirC2J4-GQMNW203";

// The deterministic pin plaintext: a pure function of its length, distinct from fill().
function pinFill(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 131 + 17) & 0xff;
  return b;
}

async function streamToBytes(fileKey: Uint8Array, source: ChunkSource, nonce: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  await sealStreamTo(fileKey, source, nonce, async (b) => {
    parts.push(b);
  }, aad);
  return concat(...parts);
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A source that yields the value in arbitrary-sized pieces, to exercise re-chunking.
function chunked(value: Uint8Array, piece: number): ChunkSource {
  return {
    async *chunks() {
      for (let i = 0; i < value.length; i += piece) yield value.subarray(i, Math.min(i + piece, value.length));
    },
  };
}

function fill(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
  return b;
}

async function main(): Promise<void> {
  const fileKey = new Uint8Array(32).fill(0x5a);
  const nonce = new Uint8Array(16).fill(0x03);
  const master = new Uint8Array(32).fill(0x7e);
  const cak = await deriveCAK(master, "dp_stream");

  const sizes = [0, 1, 100, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE, 2 * CHUNK_SIZE + 500, 5 * CHUNK_SIZE + 123];
  for (const size of sizes) {
    const value = fill(size);
    const buffered = await sealStream(fileKey, value, nonce);
    // Stream through odd-sized pieces so the re-chunker is exercised, not aligned.
    const parts: Uint8Array[] = [];
    await sealStreamTo(fileKey, chunked(value, 7000), nonce, async (b) => {
      parts.push(b);
    });
    const streamed = concat(...parts);
    ok(`sealStreamTo == sealStream at ${size} bytes`, b64urlEncode(streamed) === b64urlEncode(buffered));

    const addr = await addressStream(cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), chunked(value, 5000));
    const wantSeg = await segID(cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), value);
    const wantSha = hexEncode(await sha384(value));
    ok(`addressStream segId+sha+size at ${size} bytes`, hexEncode(addr.segId) === hexEncode(wantSeg) && addr.plaintextSha384 === wantSha && addr.size === size);

    // The framed streamed segment must equal the buffered framed segment byte-for-byte.
    const segFileKey = await deriveNonSecretFileKey(master, wantSeg, CODEC_NONE);
    const streamedSeg = await collect(sealSegmentToStream(segFileKey, chunked(value, 6000), nonce));
    const bufferedSeg = await sealNonSecretSegment(master, wantSeg, CODEC_NONE, value, nonce);
    ok(`sealSegmentToStream == sealNonSecretSegment at ${size} bytes`, b64urlEncode(streamedSeg) === b64urlEncode(bufferedSeg));

    // aad is threaded into every chunk exactly as the buffered sealStream does (the Go
    // streamWriter binds its aad into every flush). With a non-empty aad the streamed and
    // buffered forms still agree byte-for-byte, and both differ from the empty-aad seal,
    // so the capsule could move to streaming without silently dropping its key-commitment
    // aad (the binding that fails a swapped capsule).
    const aad = utf8("dp-stream-aad-probe");
    const bufferedAad = await sealStream(fileKey, value, nonce, aad);
    const streamedAad = await streamToBytes(fileKey, chunked(value, 7000), nonce, aad);
    ok(`sealStreamTo(aad) == sealStream(aad) at ${size} bytes`, b64urlEncode(streamedAad) === b64urlEncode(bufferedAad));
    ok(`aad binds: sealStreamTo(aad) != sealStreamTo() at ${size} bytes`, b64urlEncode(streamedAad) !== b64urlEncode(streamed));
  }

  // Frozen multi-chunk byte pin: a fixed 3-chunk seal under the Go-pinned
  // crypto-kat fileKey + nonce must reproduce the frozen digest, the head bytes (nonce +
  // start of chunk 0) and the tail bytes, for BOTH the buffered and the streaming form,
  // and the aad form must reproduce its own frozen digest. This locks the streaming write
  // bytes to a constant, so a regression in counter/last-flag/ordering is caught against a
  // value that cannot drift in lockstep with the buffered path.
  {
    const fileKey = b64urlDecode(PIN_FILE_KEY_B64);
    const nonce = b64urlDecode(PIN_NONCE_B64);
    const value = pinFill(2 * CHUNK_SIZE + PIN_TAIL);

    const buffered = await sealStream(fileKey, value, nonce);
    const streamed = await streamToBytes(fileKey, chunked(value, 4096), nonce); // odd pieces, re-chunked
    ok("multi-chunk pin: streamed == buffered", b64urlEncode(streamed) === b64urlEncode(buffered));
    ok("multi-chunk pin: total length is nonce + plaintext + 3 tags", streamed.length === 16 + value.length + 3 * 16);
    ok("multi-chunk pin: SHA-384(buffered) matches frozen", b64urlEncode(await sha384(buffered)) === PIN_SHA384);
    ok("multi-chunk pin: SHA-384(streamed) matches frozen", b64urlEncode(await sha384(streamed)) === PIN_SHA384);
    ok("multi-chunk pin: head bytes (nonce + chunk 0 start) match frozen", b64urlEncode(streamed.subarray(0, 24)) === PIN_HEAD_B64);
    ok("multi-chunk pin: tail bytes match frozen", b64urlEncode(streamed.subarray(streamed.length - 24)) === PIN_TAIL_B64);

    const aad = utf8(PIN_AAD);
    const streamedAad = await streamToBytes(fileKey, chunked(value, 4096), nonce, aad);
    ok("multi-chunk pin (aad): streamed == buffered", b64urlEncode(streamedAad) === b64urlEncode(await sealStream(fileKey, value, nonce, aad)));
    ok("multi-chunk pin (aad): SHA-384 matches frozen", b64urlEncode(await sha384(streamedAad)) === PIN_SHA384_AAD);
    ok("multi-chunk pin (aad): differs from empty-aad seal", b64urlEncode(streamedAad) !== b64urlEncode(streamed));
  }

  // addressStream over the secrets class (the ADDR_SECRETS branch). The streaming
  // two-pass address must equal the buffered segID for the secrets class, which mixes the
  // record salt after the class byte (derive.ts), across sizes spanning the chunk boundary.
  {
    const cak = await deriveCAK(master, "dp_secrets_stream");
    const recordSalt = new Uint8Array(16).fill(0x2b);
    for (const size of [0, 1, CHUNK_SIZE, 2 * CHUNK_SIZE + 99]) {
      const value = fill(size);
      const addr = await addressStream(cak, ADDR_SECRETS, recordSalt, chunked(value, 5000));
      const wantSeg = await segID(cak, ADDR_SECRETS, recordSalt, value);
      const wantSha = hexEncode(await sha384(value));
      ok(`addressStream secrets segId+sha+size at ${size} bytes`, hexEncode(addr.segId) === hexEncode(wantSeg) && addr.plaintextSha384 === wantSha && addr.size === size);
    }
    // The salt is load-bearing for the secrets class: a different salt must change the address.
    const value = fill(200);
    const a1 = await addressStream(cak, ADDR_SECRETS, new Uint8Array(16).fill(0x01), chunked(value, 5000));
    const a2 = await addressStream(cak, ADDR_SECRETS, new Uint8Array(16).fill(0x02), chunked(value, 5000));
    ok("addressStream secrets: salt is mixed in (different salt -> different segId)", hexEncode(a1.segId) !== hexEncode(a2.segId));
  }

  // The two in-band capture ceilings are derived in seal/budget.ts. Pin BOTH derivations so an edit to the
  // budget arithmetic is a deliberate, reviewed change, and pin the BYTE_RANGE_WINDOW copy (the one-slice
  // ceiling derives from a literal copy of it, to avoid a seal -> sources import) so it cannot silently
  // drift from the real sources/byte-fetch.ts value.
  {
    const MAX_SLICE_SUBREQUESTS = 940; // mirrors seal/budget.ts; the one-slice ceiling uses HALF the cap over 2 passes
    // MAX_SINGLE_SLICE_RECORD_BYTES is the NO-RESUME bound (a value with no stable etag, or SLICED_RUNS_DISABLED):
    // it must seal WHOLE in one slice, so it is the subrequest-derived ~1.84 GiB ceiling (the old behaviour).
    const wantSlice = Math.floor(MAX_SLICE_SUBREQUESTS / 2 / 2) * BYTE_RANGE_WINDOW;
    ok("one-slice ceiling is derived from BYTE_RANGE_WINDOW (the budget copy has not drifted from sources)", MAX_SINGLE_SLICE_RECORD_BYTES === wantSlice);
    ok("one-slice ceiling sits near 1.84 GiB (subrequest-bound, the no-resume case)", MAX_SINGLE_SLICE_RECORD_BYTES > 1.5 * 1024 * 1024 * 1024 && MAX_SINGLE_SLICE_RECORD_BYTES < 2 * 1024 * 1024 * 1024);
    // MAX_SINGLE_RECORD_CONTENT_BYTES is the RESUMABLE bound (an etag-pinned value sealed across slices): its
    // limit is the prefix re-hash within HALF the wall budget at a conservative 64 MiB/s SHA-384 floor.
    const REHASH_BYTES_PER_MS = 64 * 1024; // mirrors seal/budget.ts
    const wantResumable = REHASH_BYTES_PER_MS * Math.floor(MAX_SLICE_WALL_MS / 2);
    ok("resumable ceiling is the prefix-re-hash wall bound (HALF MAX_SLICE_WALL_MS at 64 MiB/s)", MAX_SINGLE_RECORD_CONTENT_BYTES === wantResumable);
    ok("resumable ceiling is HIGHER than the one-slice ceiling (resume captures larger objects)", MAX_SINGLE_RECORD_CONTENT_BYTES > MAX_SINGLE_SLICE_RECORD_BYTES);
    ok("resumable ceiling stays below R2's single-PUT max (a captured object remains restorable in-account)", MAX_SINGLE_RECORD_CONTENT_BYTES < R2_MAX_SINGLE_PUT);
    ok("resumable ceiling sits in the expected ~3.66 GiB band, with margin", MAX_SINGLE_RECORD_CONTENT_BYTES > 3 * 1024 * 1024 * 1024 && MAX_SINGLE_RECORD_CONTENT_BYTES < 4 * 1024 * 1024 * 1024);
  }

  // DEFENCE IN DEPTH (the whole-run-wedge backstop): the producing adapter declines an over-ceiling object
  // at probe time (sources/byte-fetch.ts), so the seal should never receive one. If one ever reaches the
  // chained seal from another path, sealChainedStreamRecord must refuse it LOUDLY and legibly, classified as
  // a source read error, rather than spending past the platform subrequest cap mid-record and wedging the
  // whole run. A StreamingValue declared over the ceiling is enough to trip the guard; its openRange is
  // never invoked (the guard throws first), so no real bytes are needed.
  {
    const overValue: StreamingValue = {
      size: MAX_SINGLE_RECORD_CONTENT_BYTES + 1,
      open: () => { throw new Error("the backstop must refuse BEFORE opening the stream"); },
      openRange: () => { throw new Error("the backstop must refuse BEFORE ranging the stream"); },
    };
    const fill32 = (seed: number) => { const u = new Uint8Array(32); for (let i = 0; i < 32; i++) u[i] = (seed + i) & 0xff; return u; };
    const dest: Destination = {
      exists: async () => false,
      putStream: async () => { throw new Error("the backstop must refuse BEFORE any put"); },
      put: async () => {},
      get: async () => null,
      putConditional: async () => ({ ok: true as const, etag: '"x"' }),
      delete: async () => {},
      list: async () => [],
    };
    const deps: RecordSealDeps = {
      cak: fill32(7), master: fill32(11), runIdBytes: new Uint8Array(16).fill(3), dest,
      randomNonce: () => new Uint8Array(16).fill(1), randomSalt: () => new Uint8Array(16).fill(9),
    };
    let caught: Error | undefined;
    try {
      await sealRecordToDest(deps, "r000000000000000", { sourceType: "stream", name: "huge/video.mp4", stream: overValue });
    } catch (e) {
      caught = e as Error;
    }
    ok("an over-ceiling streamed value reaching the seal is REFUSED (no wedge), not attempted", caught !== undefined);
    ok("the refusal names the object + the limit and steers to out-of-band recovery", caught !== undefined && /single-invocation in-band capture limit/.test(caught.message) && /out of band/.test(caught.message));
    // A record past the in-band ceiling is neither a read fault nor an outage: it is a hard, documented
    // ceiling with a documented out-of-band remedy, and the failed run row says so, distinct from the
    // generic "source read error" bucket.
    ok("the refusal classifies as the in-band size-ceiling class (never the generic 'run failed')", caught !== undefined && coarseRunError(caught.message) === "record over the in-band size ceiling (recover it out of band)");
  }

  console.log(failures === 0 ? "\nSTREAMING SEAL MATCHES THE BUFFERED SEAL" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
