import { b64urlEncode, concat, hexEncode, utf8 } from "../crypto/bytes.ts";
import { type CapsuleWrap, recipientFingerprint, recipientSetHash, sealToRecipients } from "../crypto/capsule.ts";
import { deriveManifestWrapKey, deriveMK, keyCommitment } from "../crypto/derive.ts";
import type { HybridRecipientPublic } from "../crypto/kem.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type HybridVerifier, hybridSign } from "../crypto/sign.ts";
import { sealStream } from "../crypto/stream.ts";
import { canonicalJSON } from "./canonjson.ts";
import { frame } from "./container.ts";
import { decodeULID } from "./ulid.ts";
import { CHUNK_SIZE, CODEC_NAME_NONE, MAGIC_DPE, VERSION } from "./version.ts";

// The root and shard sealers and the signer fingerprint: the manifest-shard seal, the signed
// cleartext root, and the SPEC 11.4 signer hint. Split out of writer.ts so the archive writer
// stays under the structural ceiling while the public API (re-exported from writer.ts) is
// unchanged.

/** One recipient the run master is wrapped to: its role ("break-glass" or "operational") and its
 * hybrid public key. */
export interface RecipientEntry {
  role: string; // "break-glass" | "operational"
  pub: HybridRecipientPublic;
}

/** The run signer's key material: the Ed25519 private (a CryptoKey) and public, and the ML-DSA-87
 * secret and public keys. */
export interface Signer {
  edPrivate: CryptoKey;
  edPublic: Uint8Array; // 32
  mldsaSecret: Uint8Array;
  mldsaPublic: Uint8Array; // 2592
}

/**
 * The input to sealShardManifest: the master and run/shard identity, the downpipe name and
 * cadence, the source type and window, the canonical record lines that landed in this shard, and
 * the nonce source.
 */
export interface ShardSealParams {
  master: Uint8Array;
  runId: string;
  shardId: string;
  downpipeName: string;
  cadence: string;
  sourceType: string;
  windowStart: string;
  windowEnd: string;
  recordLines: unknown[];
  randomNonce: () => Uint8Array;
}

/**
 * Seals one manifest shard (the preamble line then the record lines, NDJSON of canonical JSON)
 * under the per-shard manifest-wrap key.
 *
 * @param p - the shard seal parameters (master, identities, window, record lines, nonce source).
 * @returns the framed sealed shard bytes, the shard object key, and its lowercase-hex SHA-384 (what
 *   the root lists).
 */
export async function sealShardManifest(p: ShardSealParams): Promise<{ object: string; bytes: Uint8Array; sha384Hex: string }> {
  const runIDBytes = decodeULID(p.runId);
  const mk = await deriveMK(p.master, runIDBytes);
  const preamble = {
    kind: "preamble",
    formatVersion: VERSION,
    runId: p.runId,
    shardId: p.shardId,
    manifestCodec: CODEC_NAME_NONE,
    downpipe: { name: p.downpipeName, cadence: p.cadence },
    source: { type: p.sourceType },
    window: { start: p.windowStart, end: p.windowEnd },
    consistency: "crawl",
    recordCountInShard: p.recordLines.length,
  };
  const ndjson = concat(
    canonicalJSON(preamble),
    utf8("\n"),
    ...p.recordLines.flatMap((l) => [canonicalJSON(l), utf8("\n")]),
  );
  const shardWrap = await deriveManifestWrapKey(mk, runIDBytes, p.shardId);
  const bytes = frame(MAGIC_DPE, await sealStream(shardWrap, ndjson, p.randomNonce()));
  return { object: `run/${p.runId}/manifest/${p.shardId}.dpe`, bytes, sha384Hex: hexEncode(await sha384(bytes)) };
}

/**
 * The input to buildSignedRoot: the downpipe and run identity, the master, recipients and signer,
 * the full shard list and run-wide counts, the hex Merkle root, the freshness anchor, and the
 * nonce source. The sliced seal folds its Merkle frontier into merkleRootHex; buildArchive passes
 * its single shard and in-memory root.
 */
export interface RootSealParams {
  downpipeId: string;
  runId: string;
  createdAt: string;
  master: Uint8Array;
  recipients: RecipientEntry[];
  signer: Signer;
  shards: { id: string; object: string; sha384: string }[];
  declaredRecordCount: number;
  merkleRootHex: string;
  prevRunId: string | null;
  runlogIndex: number;
  randomNonce: () => Uint8Array;
}

/**
 * Builds and signs the cleartext root manifest (SPEC 5): wraps the master to the recipients,
 * assembles the canonical root over the envelope, recipients, capsule, counts, Merkle root and
 * freshness anchor, and signs it.
 *
 * @param p - the root seal parameters.
 * @returns the canonical root bytes and the detached signature file body (the base64url text form).
 */
export async function buildSignedRoot(p: RootSealParams): Promise<{ rootBytes: Uint8Array; sigBytes: Uint8Array }> {
  const runIDBytes = decodeULID(p.runId);
  const kc = await keyCommitment(p.master, runIDBytes);
  const pubs = p.recipients.map((r) => r.pub);
  const wraps = await sealToRecipients(p.master, pubs, kc, p.randomNonce);
  const rsh = await recipientSetHash(pubs);

  const recipientsJSON = [];
  for (const r of p.recipients) {
    recipientsJSON.push({
      fingerprint: await recipientFingerprint(r.pub.x25519, r.pub.mlkemEk),
      role: r.role,
      x25519: b64urlEncode(r.pub.x25519),
      mlkem: b64urlEncode(r.pub.mlkemEk),
    });
  }
  const capsuleJSON = wraps.map((w: CapsuleWrap) => ({
    fingerprint: w.fingerprint,
    kemCiphertext: b64urlEncode(w.kemCiphertext),
    sealed: b64urlEncode(w.sealed),
  }));

  const root = {
    formatVersion: VERSION,
    runId: p.runId,
    createdAt: p.createdAt,
    downpipeId: p.downpipeId,
    envelope: { aead: "AES-256-GCM", kem: "X25519+ML-KEM-1024", sig: "Ed25519+ML-DSA-87", kdf: "HKDF-SHA-384", chunkSize: CHUNK_SIZE, codec: CODEC_NAME_NONE },
    recipients: recipientsJSON,
    masterCapsule: capsuleJSON,
    recipientSetHash: hexEncode(rsh),
    keyCommitment: hexEncode(kc),
    breakGlassPresent: p.recipients.some((r) => r.role === "break-glass"),
    shards: p.shards,
    shardCount: p.shards.length,
    declaredRecordCount: p.declaredRecordCount,
    merkleRoot: p.merkleRootHex,
    freshness: { prevRunId: p.prevRunId, runlogIndex: p.runlogIndex },
    // The non-load-bearing signer hint (SPEC 11.4): the reader verifies against the
    // operator-pinned signer and ignores this field, but it is the real fingerprint of THIS
    // run's signer (the "edmldsa1:"-prefixed SHA-384 of its Ed25519 || ML-DSA-87 public keys),
    // computed over the signer's own public material so it matches what the Go conformance
    // writer emits (crypto.SignerFingerprint) and what a reader recomputes from the emitted
    // signer.pub. It is derived, not a constant.
    signingKeyFingerprint: await signerFingerprint({ ed: p.signer.edPublic, mldsa: p.signer.mldsaPublic }),
  };
  const rootBytes = canonicalJSON(root);
  const rootSig = await hybridSign(p.signer.edPrivate, p.signer.mldsaSecret, rootBytes);
  return { rootBytes, sigBytes: utf8(b64urlEncode(rootSig)) };
}

/**
 * Computes the "edmldsa1:"-prefixed SHA-384 of a hybrid signer's Ed25519 || ML-DSA-87 public keys
 * (SPEC 11.4), the byte-identical port of the Go reference crypto.SignerFingerprint. It fills the
 * root's non-load-bearing signingKeyFingerprint hint, so that field and the emitted signer.pub
 * agree and a reader can recompute it.
 *
 * @param v - the hybrid verifier (the signer's Ed25519 and ML-DSA-87 public keys).
 * @returns the "edmldsa1:"-prefixed hex fingerprint.
 */
export async function signerFingerprint(v: HybridVerifier): Promise<string> {
  return `edmldsa1:${hexEncode(await sha384(concat(v.ed, v.mldsa)))}`;
}
