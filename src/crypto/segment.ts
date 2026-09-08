import { frame, unframeSeg } from "../format/container.ts";
import { MAGIC_SEG } from "../format/version.ts";
import { deriveNonSecretFileKey, deriveSecretsFileKey } from "./derive.ts";
import { openStream, sealStream } from "./stream.ts";

// Segment open/seal over the framed .seg container (SPEC 7), ported from
// internal/crypto/segment.go. The reader uses the open paths; the writer uses seal.

/**
 * Opens a non-secret segment: derives the file key from the content address and codec, unframes
 * the .seg container, and STREAM-opens it. maxChunks mirrors the Go reader's OpenStreamTo bound in
 * openSegment, so a segment longer than its declared range is rejected mid-stream rather than
 * fully buffered.
 *
 * @param master - the 32-byte run master.
 * @param segIDBytes - the segment's 48-byte content address.
 * @param codecID - the codec byte mixed into the file key (CODEC_NONE or CODEC_GZIP).
 * @param sealed - the framed .seg container bytes.
 * @param maxChunks - the STREAM chunk ceiling from the signed chunkRange; 0 means unbounded.
 * @returns the recovered segment plaintext (still codec-encoded if gzip).
 * @throws Error when the container framing is wrong or the STREAM fails to authenticate or exceeds
 *   maxChunks.
 */
export async function openNonSecretSegment(master: Uint8Array, segIDBytes: Uint8Array, codecID: number, sealed: Uint8Array, maxChunks = 0): Promise<Uint8Array> {
  const fileKey = await deriveNonSecretFileKey(master, segIDBytes, codecID);
  return openStream(fileKey, unframeSeg(sealed), undefined, maxChunks);
}

/**
 * Opens a secrets segment: derives the run-, record- and salt-bound file key, unframes the .seg
 * container, and STREAM-opens it.
 *
 * @param master - the 32-byte run master.
 * @param segIDBytes - the segment's 48-byte content address.
 * @param recordID - the record id bytes.
 * @param recordSalt - the per-record salt.
 * @param runIDBytes - the 16-byte run id.
 * @param sealed - the framed .seg container bytes.
 * @param maxChunks - the STREAM chunk ceiling from the signed chunkRange; 0 means unbounded.
 * @returns the recovered secret plaintext.
 * @throws Error when the container framing is wrong or the STREAM fails to authenticate or exceeds
 *   maxChunks.
 */
export async function openSecretsSegment(master: Uint8Array, segIDBytes: Uint8Array, recordID: Uint8Array, recordSalt: Uint8Array, runIDBytes: Uint8Array, sealed: Uint8Array, maxChunks = 0): Promise<Uint8Array> {
  const fileKey = await deriveSecretsFileKey({ master, segIDBytes, recordID, recordSalt, runIDBytes });
  return openStream(fileKey, unframeSeg(sealed), undefined, maxChunks);
}

/**
 * Seals a non-secret value into a framed .seg container: derives the content-only file key and
 * STREAM-seals the plaintext under the DPS1 framing.
 *
 * @param master - the 32-byte run master.
 * @param segIDBytes - the segment's 48-byte content address.
 * @param codecID - the codec byte mixed into the file key (CODEC_NONE or CODEC_GZIP).
 * @param plaintext - the value bytes to seal.
 * @param payloadNonce - the 16-byte payload nonce for the STREAM.
 * @returns the framed sealed .seg bytes.
 */
export async function sealNonSecretSegment(master: Uint8Array, segIDBytes: Uint8Array, codecID: number, plaintext: Uint8Array, payloadNonce: Uint8Array): Promise<Uint8Array> {
  const fileKey = await deriveNonSecretFileKey(master, segIDBytes, codecID);
  return frame(MAGIC_SEG, await sealStream(fileKey, plaintext, payloadNonce));
}

/**
 * Seals a secret value into a framed .seg container: derives the run-, record- and salt-bound file
 * key and STREAM-seals the plaintext under the DPS1 framing.
 *
 * @param master - the 32-byte run master.
 * @param segIDBytes - the segment's 48-byte content address.
 * @param recordID - the record id bytes.
 * @param recordSalt - the per-record salt.
 * @param runIDBytes - the 16-byte run id.
 * @param plaintext - the secret bytes to seal.
 * @param payloadNonce - the 16-byte payload nonce for the STREAM.
 * @returns the framed sealed .seg bytes.
 */
export async function sealSecretsSegment(master: Uint8Array, segIDBytes: Uint8Array, recordID: Uint8Array, recordSalt: Uint8Array, runIDBytes: Uint8Array, plaintext: Uint8Array, payloadNonce: Uint8Array): Promise<Uint8Array> {
  const fileKey = await deriveSecretsFileKey({ master, segIDBytes, recordID, recordSalt, runIDBytes });
  return frame(MAGIC_SEG, await sealStream(fileKey, plaintext, payloadNonce));
}
