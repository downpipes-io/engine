import { noteStreamFault } from "../format/integrity-fault-ledger.ts";
import { CHUNK_NONCE_COUNTER_OFFSET, CHUNK_NONCE_SIZE, CHUNK_SIZE, STREAM_NONCE_SIZE, TAG_SIZE } from "../format/version.ts";
import { ab, concat, u64be } from "./bytes.ts";
import { payloadKey } from "./derive.ts";
import { aesGcmOpen, aesGcmSeal } from "./primitives.ts";

// The downpipe STREAM (SPEC 7.8), ported byte-for-byte from internal/crypto/stream.go:
// a 16-byte payload nonce followed by AES-256-GCM chunks of 64 KiB plaintext, each with
// a 12-byte nonce of three reserved zero bytes, an 8-byte big-endian chunk counter (uint64
// from 0), and a 1-byte last-chunk flag.

/**
 * Builds the 12-byte AES-GCM nonce for a STREAM chunk: three reserved zero bytes, the 8-byte
 * big-endian counter, then a 1-byte last-chunk flag. Exported so the streaming seal reuses the
 * exact same construction rather than a copy.
 *
 * @param counter - the zero-based chunk index.
 * @param last - whether this is the final chunk of the STREAM.
 * @returns the 12-byte nonce.
 */
export function chunkNonce(counter: bigint, last: boolean): Uint8Array {
  const n = new Uint8Array(CHUNK_NONCE_SIZE);
  n.set(u64be(counter), CHUNK_NONCE_COUNTER_OFFSET); // bytes 0..2 stay zero (reserved), 3..10 carry the counter
  n[CHUNK_NONCE_SIZE - 1] = last ? 1 : 0;
  return n;
}

/**
 * Seals plaintext as a downpipe STREAM (SPEC 7.8): the payload nonce followed by AES-256-GCM
 * chunks of 64 KiB plaintext each, the last carrying the last-chunk flag (an empty plaintext is
 * one empty last chunk).
 *
 * @param fileKey - the segment file key, expanded per nonce into the per-chunk AES key.
 * @param plaintext - the bytes to seal.
 * @param payloadNonce - the 16-byte payload nonce, prepended to the output.
 * @param aad - optional additional authenticated data bound into every chunk; empty for data and
 *   shard units, the run key commitment for the master capsule.
 * @returns the payload nonce followed by the sealed chunks.
 */
export async function sealStream(fileKey: Uint8Array, plaintext: Uint8Array, payloadNonce: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const pk = await payloadKey(fileKey, payloadNonce);
  const chunks: Uint8Array[] = [payloadNonce];
  let counter = 0n;
  let off = 0;
  do {
    const end = Math.min(off + CHUNK_SIZE, plaintext.length);
    const last = end >= plaintext.length;
    chunks.push(await aesGcmSeal(pk, chunkNonce(counter, last), plaintext.subarray(off, end), aad));
    counter += 1n;
    off = end;
  } while (off < plaintext.length);
  return concat(...chunks);
}

/**
 * Opens a downpipe STREAM, reversing sealStream: reads the payload nonce, re-derives the chunk
 * key, then decrypts and authenticates each 64 KiB chunk in order.
 *
 * @param fileKey - the segment file key the STREAM was sealed under.
 * @param sealed - the payload nonce followed by the sealed chunks.
 * @param aad - optional additional authenticated data; must match what was sealed.
 * @param maxChunks - a chunk-count ceiling (0 means unbounded); pass the count implied by a signed
 *   chunk range to bound a hostile input.
 * @returns the recovered plaintext.
 * @throws Error when the stream is shorter than the nonce, has no chunks, exceeds maxChunks, a
 *   chunk is shorter than the tag, or any chunk fails to authenticate.
 */
export async function openStream(fileKey: Uint8Array, sealed: Uint8Array, aad?: Uint8Array, maxChunks = 0): Promise<Uint8Array> {
  // G111: EVERY abort below used to leave a bare Error (or, for the GCM arm, a bare DOMException
  // OperationError) with no locus at all -- no chunk index, no byte counts, nothing to say whether the object
  // was zero-byte, partially written, or authentically corrupt. The locus rides the ledger; the throws below
  // are byte-for-byte unchanged, so no caller's behaviour moves. Ints only: never the object key or a byte.
  if (sealed.length < STREAM_NONCE_SIZE) {
    noteStreamFault({ leg: "decrypt-open", cls: "short-nonce", receivedBytes: sealed.length, expectedBytes: STREAM_NONCE_SIZE });
    throw new Error("stream shorter than the payload nonce");
  }
  const nonce = sealed.subarray(0, STREAM_NONCE_SIZE);
  const pk = await payloadKey(fileKey, nonce);
  const body = sealed.subarray(STREAM_NONCE_SIZE);
  const stride = CHUNK_SIZE + TAG_SIZE;

  const slices: Uint8Array[] = [];
  for (let off = 0; off < body.length; off += stride) {
    slices.push(body.subarray(off, Math.min(off + stride, body.length)));
  }
  if (slices.length === 0) {
    noteStreamFault({ leg: "decrypt-open", cls: "no-chunks", receivedBytes: sealed.length });
    throw new Error("stream has no chunks");
  }
  if (maxChunks > 0 && slices.length > maxChunks) {
    noteStreamFault({ leg: "decrypt-open", cls: "over-limit-chunks", chunkIndex: slices.length, expectedBytes: maxChunks });
    throw new Error(`stream exceeds the ${maxChunks}-chunk limit`);
  }

  const out: Uint8Array[] = [];
  for (let i = 0; i < slices.length; i++) {
    const last = i === slices.length - 1;
    if (slices[i]!.length < TAG_SIZE) {
      noteStreamFault({ leg: "decrypt-open", cls: "short-chunk", chunkIndex: i, receivedBytes: slices[i]!.length, expectedBytes: TAG_SIZE });
      throw new Error(`chunk ${i} shorter than the tag`);
    }
    try {
      out.push(await aesGcmOpen(pk, chunkNonce(BigInt(i), last), slices[i]!, aad));
    } catch (e) {
      // THE one that mattered: a GCM authentication failure. This is a bare DOMException OperationError, so
      // by the time it reaches a catch that owns a DO stub it says nothing at all. The chunk INDEX is the
      // whole diagnosis: chunk 0 means the object was mangled from the first byte (a store that ate the
      // write); chunk 4,000 of 4,001 means a truncated tail.
      noteStreamFault({ leg: "decrypt-open", cls: "gcm-auth-fail", chunkIndex: i, receivedBytes: slices[i]!.length });
      throw e;
    }
  }
  return concat(...out);
}

// StreamFillState is the mutable buffer + end-of-input flag fillBuffer reads and updates. buf holds the bytes
// not yet consumed (first the prefix until the nonce is read, then the unprocessed body, drained to at most a
// stride after every pull so memory stays bounded); done records whether the underlying reader reported
// end-of-input. It is a small object so fillBuffer can live outside the pull closure yet still mutate them.
interface StreamFillState {
  buf: Uint8Array;
  done: boolean;
}

// fillBuffer reads from the underlying stream reader until state.buf holds at least `need` bytes or the input
// ends, appending each piece and never dropping a byte. Used to assemble the nonce and to look one stride
// ahead. It is a standalone function (not a pull-closure arrow) so it can be reasoned about and tested on its
// own; it touches only the passed reader and the mutable state object.
async function fillBuffer(reader: ReadableStreamDefaultReader<Uint8Array>, state: StreamFillState, need: number): Promise<void> {
  while (state.buf.length < need && !state.done) {
    const { done: d, value } = await reader.read();
    if (d) {
      state.done = true;
      break;
    }
    if (value && value.length > 0) state.buf = state.buf.length === 0 ? ab(value) : concat(state.buf, value);
  }
}

/**
 * Opens a downpipe STREAM as a ReadableStream of plaintext, the constant-memory counterpart of
 * openStream: it reads the payload nonce, re-derives the chunk key, then decrypts and authenticates
 * each 64 KiB chunk IN ORDER, emitting each chunk's plaintext as it is verified and NEVER holding
 * the whole value (or the whole sealed segment) in memory. Roughly two strides (~128 KiB) are
 * resident at once: the chunk currently awaiting a last/not-last decision plus whatever the producer
 * has handed in since.
 *
 * The final chunk carries the last-chunk flag, so the open must know which chunk is last BEFORE it
 * decrypts it (the flag is bound into the GCM nonce). It determines this with a ONE-STRIDE LOOKAHEAD:
 * a full stride is decrypted with last=false only once at least one further body byte has arrived
 * (proving it is not the final chunk); whatever remains when the input ends is the last chunk,
 * decrypted with last=true. A chunk that fails to authenticate (a wrong key, nonce, aad, or any
 * tampering) ERRORS the stream rather than emitting unauthenticated bytes: every byte this stream
 * yields has already passed its per-chunk AES-256-GCM tag check.
 *
 * Unlike openStream it takes no maxChunks ceiling: memory is bounded here by the two-stride window
 * rather than by a chunk count, so a caller that must REFUSE an over-long segment has to bound the
 * input itself. What it authenticates is exactly what the key, nonce and aad cover. The chunk counter
 * is this reader's own, so a reordered, dropped or truncated chunk fails to authenticate, but nothing
 * here establishes that the segment is the one a manifest asked for.
 *
 * @param fileKey - the segment file key the STREAM was sealed under.
 * @param sealed - the payload nonce followed by the sealed chunks, as a ReadableStream or a whole
 *   Uint8Array (the latter is wrapped in a one-shot stream, so a buffered caller can reuse this).
 * @param aad - optional additional authenticated data; must match what was sealed.
 * @returns a ReadableStream of the decrypted plaintext, one verified chunk per pull; it errors when
 *   the stream is shorter than the nonce, has no chunks, a chunk is shorter than the tag, or any
 *   chunk fails to authenticate. On any of those it also cancels the upstream reader, so a
 *   partially-consumed segment stream is released rather than left open.
 */
export function openStreamToStream(fileKey: Uint8Array, sealed: ReadableStream<Uint8Array> | Uint8Array, aad?: Uint8Array): ReadableStream<Uint8Array> {
  const stride = CHUNK_SIZE + TAG_SIZE;
  const reader = (sealed instanceof Uint8Array ? oneShotStream(sealed) : sealed).getReader();

  const state: StreamFillState = { buf: new Uint8Array(0), done: false };
  let pk: Uint8Array | null = null; // the derived payload key, set once the nonce is read
  let counter = 0n; // the zero-based chunk index, bound into each chunk's nonce
  let emitted = false; // whether any chunk has been emitted (to reject a stream with no chunks)

  return new ReadableStream<Uint8Array>({
    async pull(controller): Promise<void> {
      try {
        // First pull: read the 16-byte payload nonce (it may straddle producer pieces) and derive
        // the per-file payload key before any chunk is opened.
        if (pk === null) {
          await fillBuffer(reader, state, STREAM_NONCE_SIZE);
          if (state.buf.length < STREAM_NONCE_SIZE) throw new Error("stream shorter than the payload nonce");
          pk = await payloadKey(fileKey, state.buf.subarray(0, STREAM_NONCE_SIZE));
          state.buf = state.buf.subarray(STREAM_NONCE_SIZE);
        }
        const key = pk; // pin the non-null key for this pull (pk is a closure-mutable let)

        // One-stride lookahead: a full stride is the LAST chunk only if nothing follows it. Read
        // until buf holds more than one stride (so the leading stride is provably not last) or the
        // input is exhausted (so whatever remains is the last chunk).
        await fillBuffer(reader, state, stride + 1);

        if (state.buf.length > stride) {
          // A full, non-final chunk: decrypt it with last=false and emit its plaintext. The bytes
          // are authenticated by the GCM tag before they leave this function.
          const chunk = state.buf.subarray(0, stride);
          state.buf = state.buf.subarray(stride); // keep at most a stride pending; memory stays ~2 strides
          controller.enqueue(await aesGcmOpen(key, chunkNonce(counter, false), chunk, aad));
          counter += 1n;
          emitted = true;
          return;
        }

        // Input exhausted (buf.length <= stride): buf is the final chunk. A STREAM always has at
        // least one chunk (an empty value seals to one empty last chunk), so an empty buf here with
        // nothing emitted is a malformed stream; a chunk shorter than the tag cannot authenticate.
        if (state.buf.length === 0) {
          if (!emitted) throw new Error("stream has no chunks");
          controller.close();
          return;
        }
        if (state.buf.length < TAG_SIZE) throw new Error(`chunk ${counter} shorter than the tag`);
        const last = state.buf;
        state.buf = new Uint8Array(0);
        controller.enqueue(await aesGcmOpen(key, chunkNonce(counter, true), last, aad));
        counter += 1n;
        emitted = true;
        controller.close();
      } catch (e) {
        // G111: the STREAMING open is the path a multi-GiB restore actually takes, and its aborts crossed two
        // async stream boundaries before anything could see them. Record the locus HERE, where the chunk
        // counter is still in scope, before the error is handed to the controller and coarsened away. The
        // classification reads the engine's OWN throw literals (the three above) to select a closed class and
        // returns nothing: the message is discarded.
        const m = e instanceof Error ? e.message : "";
        const cls = m.includes("payload nonce") ? "short-nonce" : m.includes("no chunks") ? "no-chunks" : m.includes("shorter than the tag") ? "short-chunk" : "gcm-auth-fail";
        noteStreamFault({ leg: "decrypt-open", cls, chunkIndex: Number(counter) });
        // Cancel the upstream reader so a partially-consumed segment stream is released, then error
        // this stream: a GCM failure (or any malformation) must surface as a stream error, never as
        // a short or unauthenticated body.
        await reader.cancel(e).catch(() => {});
        controller.error(e);
      }
    },
    async cancel(reason): Promise<void> {
      await reader.cancel(reason).catch(() => {});
    },
  });
}

// oneShotStream wraps a whole buffer as a single-pull ReadableStream so a buffered caller can drive
// openStreamToStream without a producer of its own. It is byte-for-byte the same input the streaming
// reader would see from a real segment stream.
function oneShotStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      if (bytes.length > 0) controller.enqueue(bytes);
      controller.close();
    },
  });
}
