import { hmac } from "@noble/hashes/hmac.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { ADDR_SECRETS, CHUNK_SIZE, CONTAINER_VERSION, MAGIC_SEG, STREAM_NONCE_SIZE, TAG_SIZE } from "../format/version.ts";
import { ab, concat, hexEncode } from "./bytes.ts";
import { payloadKey } from "./derive.ts";
import { aesGcmSeal } from "./primitives.ts";
import { chunkNonce } from "./stream.ts";

// Streaming seal: seal an arbitrarily large value without buffering the whole plaintext
// or the whole sealed output, so a multi-GiB R2 object stays within the Worker memory
// limit (design F11). The output is byte-identical to the buffered sealStream for the
// same plaintext. Incremental HMAC/SHA-384 come from @noble/hashes (Web Crypto has no
// streaming MAC); they byte-match Web Crypto and the Go reference.

/**
 * A re-readable source of plaintext bytes: chunks() yields the plaintext in arbitrary-sized
 * pieces, which the seal re-chunks to 64 KiB.
 */
export interface ChunkSource {
  // chunks yields the plaintext in arbitrary-sized pieces; the seal re-chunks to 64 KiB.
  chunks(): AsyncIterable<Uint8Array>;
}

/**
 * A re-openable large value whose size is known up front (for example an R2 object): the two-pass
 * seal opens it once to address and once to seal. openRange, when the source supports bounded
 * reads (R2 ranged GETs), opens one window, which is what lets the writer seal a value past the
 * single-segment ceiling as a chained multi-segment record (SPEC 6.2, 14.5): each window is
 * addressed and sealed as its own segment, two passes per window, never holding a window whole.
 *
 * `size` is the total value byte count. `open()` returns a fresh ChunkSource over the whole value.
 * `openRange(offset, length)`, when present, returns a ChunkSource over one window of the value
 * (the source MAY split it into several subrequests internally, e.g. one HTTP Range per memory
 * window). `openStreamedRange(offset, length)`, when present, returns a ChunkSource over an extent
 * read in ONE subrequest (a single ranged GET streamed chunk by chunk in bounded memory): the
 * mid-record resume re-hashes the already-sealed prefix [0, offsetSealed) through it, so the resume
 * always makes forward progress in a single subrequest regardless of how large the prefix is.
 *
 * `etag`, when present, is the version the source pins every read to (the probe-time ETag). The
 * mid-record resume compares it across slices: if the object changed (the etag differs), the
 * already-written prefix segments would disagree with a re-hash of the new bytes, so the partial is
 * abandoned rather than resumed. A value with no stable etag is never mid-record-resumed.
 */
export interface StreamingValue {
  size: number;
  etag?: string;
  open(): ChunkSource;
  openRange?(offset: number, length: number): ChunkSource;
  openStreamedRange?(offset: number, length: number): ChunkSource;
}

/**
 * Pass one of the two-pass content addressing: streams the plaintext through an incremental HMAC
 * (the segId) and an incremental SHA-384 (the plaintext hash), computing the size, without holding
 * the value whole.
 *
 * @param cak - the per-downpipe content-addressing key.
 * @param klass - the address domain separator (for example ADDR_SINGLE_NON_SECRET, ADDR_SECRETS).
 * @param recordSalt - mixed into the address only for the secrets class.
 * @param source - the plaintext source to stream once.
 * @param tap - optional observer that sees every chunk as it passes; a chained multi-segment
 *   record threads one whole-record SHA-384 through the per-window passes this way (SPEC 6.2, 6.5).
 * @returns the 48-byte segId, the lowercase-hex plaintext SHA-384, and the byte size.
 */
export async function addressStream(cak: Uint8Array, klass: number, recordSalt: Uint8Array, source: ChunkSource, tap?: { update(b: Uint8Array): void }): Promise<{ segId: Uint8Array; plaintextSha384: string; size: number }> {
  const mac = hmac.create(sha384, cak);
  mac.update(new Uint8Array([klass]));
  if (klass === ADDR_SECRETS) mac.update(recordSalt);
  const digest = sha384.create();
  let size = 0;
  for await (const chunk of source.chunks()) {
    mac.update(chunk);
    digest.update(chunk);
    tap?.update(chunk);
    size += chunk.length;
  }
  return { segId: mac.digest(), plaintextSha384: hexEncode(digest.digest()), size };
}

/**
 * Pass two of the streaming seal: seals the plaintext stream under the file key with the given
 * payload nonce, writing the payload nonce then each sealed 64 KiB chunk to the sink, holding
 * roughly one chunk in memory. The last chunk carries the last-chunk flag exactly as the buffered
 * sealStream does (including the empty-payload and exact-multiple cases), so the output is
 * byte-identical and the two forms interoperate.
 *
 * @param fileKey - the segment file key.
 * @param source - the plaintext source to stream (the same logical bytes addressed in pass one).
 * @param payloadNonce - the 16-byte payload nonce, written first.
 * @param write - the sink callback invoked for the nonce and each sealed chunk, in order.
 * @param aad - optional additional authenticated data bound into every chunk; empty for data and
 *   shard units, the run key commitment for the master capsule.
 * @returns a promise that resolves once the whole stream has been sealed and written.
 */
export async function sealStreamTo(fileKey: Uint8Array, source: ChunkSource, payloadNonce: Uint8Array, write: (b: Uint8Array) => Promise<void>, aad?: Uint8Array): Promise<void> {
  const pk = await payloadKey(fileKey, payloadNonce);
  await write(payloadNonce);
  let counter = 0n;
  let pending: Uint8Array | null = null; // a full 64 KiB chunk awaiting last-determination
  let buf = new Uint8Array(0);

  const sealPending = async () => {
    if (pending) {
      await write(await aesGcmSeal(pk, chunkNonce(counter, false), pending, aad));
      counter += 1n;
      pending = null;
    }
  };

  for await (const incoming of source.chunks()) {
    buf = buf.length === 0 ? ab(incoming) : concat(buf, incoming);
    while (buf.length >= CHUNK_SIZE) {
      await sealPending(); // the previous full chunk is definitely not last
      pending = buf.subarray(0, CHUNK_SIZE);
      buf = buf.subarray(CHUNK_SIZE);
    }
  }

  // Flush: pending is a held full chunk, buf is the trailing partial (possibly empty).
  if (pending && buf.length > 0) {
    await sealPending();
    await write(await aesGcmSeal(pk, chunkNonce(counter, true), buf, aad));
  } else if (pending) {
    await write(await aesGcmSeal(pk, chunkNonce(counter, true), pending, aad));
  } else {
    // No full chunk accumulated: buf is the only chunk (a single, possibly empty, last chunk).
    await write(await aesGcmSeal(pk, chunkNonce(counter, true), buf, aad));
  }
}

/**
 * Computes the exact framed .seg byte length for a plaintext of the given size: magic(4) +
 * version(1) + payload nonce(16) + plaintext + one 16-byte GCM tag per 64 KiB STREAM chunk (an
 * empty plaintext is one empty chunk). Destinations use it to run a length-known streamed put
 * (live R2 bindings require a known length) and to bound the sealed stream; note a maximal 1
 * GiB-plaintext segment (SPEC 14.5) seals to slightly more than 1 GiB.
 *
 * @param plaintextSize - the plaintext byte count.
 * @returns the exact sealed, framed .seg byte length.
 */
export function sealedSegmentLength(plaintextSize: number): number {
  const chunks = plaintextSize === 0 ? 1 : Math.ceil(plaintextSize / CHUNK_SIZE);
  return 4 + 1 + STREAM_NONCE_SIZE + plaintextSize + chunks * TAG_SIZE;
}

/**
 * Produces the framed .seg (DPS1 + version + STREAM) as a ReadableStream, so a large non-secret
 * segment streams straight into a single PUT body without ever being held whole. The result is
 * byte-identical to the buffered sealNonSecretSegment.
 *
 * @param fileKey - the segment file key.
 * @param source - the plaintext source to stream.
 * @param payloadNonce - the 16-byte payload nonce for the STREAM.
 * @returns a ReadableStream of the framed sealed segment bytes; a seal error surfaces as a stream
 *   error to the consumer.
 */
export function sealSegmentToStream(fileKey: Uint8Array, source: ChunkSource, payloadNonce: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        controller.enqueue(concat(MAGIC_SEG, new Uint8Array([CONTAINER_VERSION])));
        await sealStreamTo(fileKey, source, payloadNonce, async (b) => {
          controller.enqueue(b);
        });
        controller.close();
      } catch (e) {
        controller.error(e);
      }
    },
  });
}
