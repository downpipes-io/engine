import {
  ADDR_SECRETS,
  CHUNK_SIZE,
  INFO_CONTENT_ADDRESS,
  INFO_KEY_COMMIT,
  INFO_MANIFEST_KEY,
  INFO_MANIFEST_WRAP,
  INFO_NAME_MAC,
  INFO_PAYLOAD,
  INFO_SEG_KEY,
} from "../format/version.ts";
import { concat, lpAppend, u32be, utf8 } from "./bytes.ts";
import { hkdfSha384, hmacSha384 } from "./primitives.ts";

// The key tree and keyed addressing, ported byte-for-byte from internal/crypto/derive.go.
// Every value here is exercised by the crypto-kat cross-implementation vector.

/**
 * Derives the content-addressing key (SPEC 7.2). It is derived from the PER-RUN master (HKDF IKM)
 * with the downpipe id as the salt, so it is per-RUN, not stable per-downpipe across runs: a fresh
 * random master each run yields a fresh CAK, so segment addresses (and thus seg/ object keys) differ
 * run-to-run even for identical content. Content addressing therefore dedups only WITHIN a run.
 *
 * @param master - the 32-byte run master (fresh per run).
 * @param downpipeID - the downpipe id, mixed in as the HKDF salt.
 * @returns the 32-byte content-addressing key.
 */
export function deriveCAK(master: Uint8Array, downpipeID: string): Promise<Uint8Array> {
  return hkdfSha384(master, utf8(downpipeID), utf8(INFO_CONTENT_ADDRESS), 32);
}

/**
 * Computes the 48-byte keyed content address of a value (SPEC 7.2): HMAC-SHA-384 under the
 * content-addressing key over the class byte, the record salt (secrets only) and the plaintext.
 *
 * @param cak - the per-downpipe content-addressing key.
 * @param klass - the address domain separator (one of ADDR_SINGLE_NON_SECRET, ADDR_PACKED,
 *   ADDR_SECRETS).
 * @param recordSalt - mixed in only for the secrets class; pass an empty array for non-secret
 *   classes.
 * @param plaintext - the value's plaintext bytes.
 * @returns the 48-byte segment address.
 */
export function segID(cak: Uint8Array, klass: number, recordSalt: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const parts: Uint8Array[] = [new Uint8Array([klass])];
  if (klass === ADDR_SECRETS) parts.push(recordSalt);
  parts.push(plaintext);
  return hmacSha384(cak, concat(...parts));
}

function nonSecretContext(segIDBytes: Uint8Array, codecID: number): Uint8Array {
  let ctx = new Uint8Array(0);
  ctx = lpAppend(ctx, segIDBytes);
  ctx = lpAppend(ctx, new Uint8Array([codecID]));
  ctx = lpAppend(ctx, u32be(CHUNK_SIZE));
  return ctx;
}

function secretsContext(segIDBytes: Uint8Array, recordID: Uint8Array, recordSalt: Uint8Array): Uint8Array {
  let ctx = new Uint8Array(0);
  ctx = lpAppend(ctx, segIDBytes);
  ctx = lpAppend(ctx, recordID);
  ctx = lpAppend(ctx, recordSalt);
  ctx = lpAppend(ctx, new Uint8Array([0x00])); // secrets never compress
  ctx = lpAppend(ctx, u32be(CHUNK_SIZE));
  return ctx;
}

/**
 * Derives the 32-byte file key for a non-secret segment (SPEC 7.4). The key is bound to the
 * PER-RUN master (the HKDF IKM), so it is per-RUN, not content-only: the SAME content sealed in two
 * different runs derives DISTINCT file keys (and, via the per-run content-addressing key
 * {@link deriveCAK}, DISTINCT 48-byte segment addresses), so identical content across runs yields
 * DISTINCT segment objects. Deduplication is therefore WITHIN a single run only -- the same content
 * appearing twice in one run addresses to one shared segment -- and is NEVER cross-run.
 *
 * @param master - the 32-byte run master (fresh per run); binding it here is what makes the key per-run.
 * @param segIDBytes - the segment's 48-byte content address.
 * @param codecID - the codec byte (CODEC_NONE or CODEC_GZIP), mixed into the key context.
 * @returns the 32-byte file key.
 */
export function deriveNonSecretFileKey(master: Uint8Array, segIDBytes: Uint8Array, codecID: number): Promise<Uint8Array> {
  const info = concat(utf8(INFO_SEG_KEY), new Uint8Array([0x00]), nonSecretContext(segIDBytes, codecID));
  return hkdfSha384(master, new Uint8Array(0), info, 32);
}

/**
 * The bound inputs for {@link deriveSecretsFileKey} (SPEC 7.4), passed as one options object so the
 * five positional inputs cannot be transposed at a call site.
 */
export interface SecretsFileKeyParams {
  /** the 32-byte run master. */
  master: Uint8Array;
  /** the segment's 48-byte content address. */
  segIDBytes: Uint8Array;
  /** the record id bytes. */
  recordID: Uint8Array;
  /** the per-record salt. */
  recordSalt: Uint8Array;
  /** the 16-byte run id, mixed in as the HKDF salt. */
  runIDBytes: Uint8Array;
}

/**
 * Derives the 32-byte file key for a secrets segment (SPEC 7.4), bound to the run, record and
 * salt so a secret is never deduplicated across runs.
 *
 * @param params - the bound inputs (see {@link SecretsFileKeyParams}).
 * @returns the 32-byte file key.
 */
export function deriveSecretsFileKey(params: SecretsFileKeyParams): Promise<Uint8Array> {
  const { master, segIDBytes, recordID, recordSalt, runIDBytes } = params;
  const info = concat(utf8(INFO_SEG_KEY), new Uint8Array([0x00]), secretsContext(segIDBytes, recordID, recordSalt));
  return hkdfSha384(master, runIDBytes, info, 32);
}

/**
 * Derives the per-run manifest subkey (SPEC 11.7).
 *
 * @param master - the 32-byte run master.
 * @param runIDBytes - the 16-byte run id, mixed in as the HKDF salt.
 * @returns the 32-byte manifest subkey.
 */
export function deriveMK(master: Uint8Array, runIDBytes: Uint8Array): Promise<Uint8Array> {
  return hkdfSha384(master, runIDBytes, utf8(INFO_MANIFEST_KEY), 32);
}

/**
 * Derives the keyed-name MAC key from the manifest subkey (SPEC 6.4).
 *
 * @param mk - the per-run manifest subkey.
 * @param runIDBytes - the 16-byte run id, mixed in as the HKDF salt.
 * @returns the 32-byte name-MAC key.
 */
export function deriveNameMACKey(mk: Uint8Array, runIDBytes: Uint8Array): Promise<Uint8Array> {
  return hkdfSha384(mk, runIDBytes, utf8(INFO_NAME_MAC), 32);
}

/**
 * Derives the per-shard manifest-wrap key (SPEC 6.3): the shard id is appended to the HKDF info
 * after a 0x00 separator.
 *
 * @param mk - the per-run manifest subkey.
 * @param runIDBytes - the 16-byte run id, mixed in as the HKDF salt.
 * @param shardID - the shard id, appended to the info.
 * @returns the 32-byte manifest-wrap key for the shard.
 */
export function deriveManifestWrapKey(mk: Uint8Array, runIDBytes: Uint8Array, shardID: string): Promise<Uint8Array> {
  const info = concat(utf8(INFO_MANIFEST_WRAP), new Uint8Array([0x00]), utf8(shardID));
  return hkdfSha384(mk, runIDBytes, info, 32);
}

/**
 * Computes the keyed name MAC of a record's source name (SPEC 6.4): HMAC-SHA-384 over the source
 * type, a 0x00 separator and the name.
 *
 * @param nameMACKey - the keyed-name MAC key from deriveNameMACKey.
 * @param sourceType - the record's source type (for example "kv", "r2").
 * @param name - the record's source name.
 * @returns the 48-byte name MAC.
 */
export function nameMAC(nameMACKey: Uint8Array, sourceType: string, name: string): Promise<Uint8Array> {
  return hmacSha384(nameMACKey, concat(utf8(sourceType), new Uint8Array([0x00]), utf8(name)));
}

/**
 * Computes the key commitment that binds the master to the run (SPEC 8.4): HMAC-SHA-384 keyed by
 * the master over the commitment label and the run id.
 *
 * @param master - the 32-byte run master.
 * @param runIDBytes - the 16-byte run id.
 * @returns the 48-byte key commitment.
 */
export function keyCommitment(master: Uint8Array, runIDBytes: Uint8Array): Promise<Uint8Array> {
  return hmacSha384(master, concat(utf8(INFO_KEY_COMMIT), runIDBytes));
}

/**
 * Expands a file key into the per-file STREAM payload key (SPEC 7.8): the payload nonce is the
 * HKDF salt, so every sealed unit gets a fresh AES-256 key.
 *
 * @param fileKey - the segment's 32-byte file key.
 * @param payloadNonce - the 16-byte payload nonce, used as the HKDF salt.
 * @returns the 32-byte STREAM payload key.
 */
export function payloadKey(fileKey: Uint8Array, payloadNonce: Uint8Array): Promise<Uint8Array> {
  return hkdfSha384(fileKey, payloadNonce, utf8(INFO_PAYLOAD), 32);
}
