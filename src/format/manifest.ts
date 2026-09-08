// The on-disk JSON shapes, mirroring internal/spec/manifest.go. Binary fields are
// base64url no-pad strings and hashes are bare lowercase hex, as the reader parses them.

/** The run-wide cryptographic envelope: the AEAD, KEM, signature and KDF algorithm names, the
 * STREAM chunk size, and the run-wide codec. */
export interface Envelope {
  readonly aead: string;
  readonly kem: string;
  readonly sig: string;
  readonly kdf: string;
  readonly chunkSize: number;
  readonly codec: string;
}

/** One recipient entry in the signed root: its fingerprint, role, and base64url X25519 and ML-KEM
 * public keys. */
export interface Recipient {
  readonly fingerprint: string;
  readonly role: string;
  readonly x25519: string;
  readonly mlkem: string;
}

/** The JSON form of a master-capsule wrap: the recipient fingerprint and the base64url KEM
 * ciphertext and STREAM-sealed master. */
export interface CapsuleWrapJSON {
  readonly fingerprint: string;
  readonly kemCiphertext: string;
  readonly sealed: string;
}

/** A reference to one manifest shard from the signed root: its id, object key, and SHA-384 hex. */
export interface ShardRef {
  readonly id: string;
  readonly object: string;
  readonly sha384: string;
}

/** The freshness anchor fields in the signed root: the previous run id of this downpipe (or null)
 * and this run's account-global RUNLOG index. */
export interface Freshness {
  readonly prevRunId: string | null;
  readonly runlogIndex: number;
}

/** The signed root manifest of a run (SPEC 5): the format version and run identity, the envelope,
 * recipients and master capsule, the recipient-set hash and key commitment, the shard list and
 * counts, the Merkle root, the freshness anchor and the signer fingerprint hint. */
export interface RootManifest {
  readonly formatVersion: string;
  readonly runId: string;
  readonly createdAt: string;
  readonly downpipeId: string;
  readonly envelope: Envelope;
  readonly recipients: Recipient[];
  readonly masterCapsule: CapsuleWrapJSON[];
  readonly recipientSetHash: string;
  readonly keyCommitment: string;
  readonly breakGlassPresent: boolean;
  readonly shards: ShardRef[];
  readonly shardCount: number;
  readonly declaredRecordCount: number;
  readonly merkleRoot: string;
  readonly freshness: Freshness;
  readonly signingKeyFingerprint: string;
}

/** A packed record's byte slice within a shared segment's decrypted bytes: the start offset and
 * the length. */
export interface Packed {
  readonly offset: number;
  readonly length: number;
}

/** One segment of a record (SPEC 6.2): its object key, the half-open STREAM chunk range, and the
 * packed slice (or null when the segment is not packed). */
export interface Segment {
  readonly object: string;
  readonly chunkRange: [number, number];
  readonly packed: Packed | null;
}

// The per-source restore descriptors, mirroring spec/manifest.go (KVDescriptor,
// R2Descriptor, SecretsDescriptor, D1Descriptor). They carry the configuration a restore
// reconstructs beyond the value bytes (SPEC 6.2, 12.3). The opaque metadata fields are held
// as parsed JSON (the reader never interprets them; it only restores them), matching Go's
// json.RawMessage. Every field is optional with the omitempty contract: a field is present
// only when non-empty, and the whole descriptor is present on a record only when it has at
// least one non-empty field.
/** The KV restore descriptor (SPEC 6.2, 12.3): the opaque metadata and the absolute expiration a
 * restore reconstructs. Both fields are optional under the omitempty contract. */
export interface KVDescriptor {
  readonly metadata?: unknown;
  readonly expiration?: number;
}

/** The R2 restore descriptor (SPEC 6.2, 12.3): the HTTP and custom metadata a restore
 * reconstructs. Both fields are optional under the omitempty contract. */
export interface R2Descriptor {
  readonly httpMetadata?: Record<string, string>;
  readonly customMetadata?: Record<string, string>;
}

/** The Secrets Store restore descriptor (SPEC 6.2, 12.3): the store, scope, comment and the
 * worker/binding the secret was bound to. All fields are optional under the omitempty contract. */
export interface SecretsDescriptor {
  readonly store?: string;
  readonly scope?: string;
  readonly comment?: string;
  readonly worker?: string;
  readonly bindingVar?: string;
}

/** The D1 restore descriptor (SPEC 6.2, 12.3): the dump format. Optional under the omitempty
 * contract. */
export interface D1Descriptor {
  readonly format?: string;
}

/** One record line in a manifest shard: its kind and source identity, the keyed name hash and
 * record id, the plaintext size and hash, the Merkle-leaf record hash, the codec, the ordered
 * segments, the optional secrets salt, the per-source restore descriptors, and the optional
 * incompleteness-marker kind. */
export interface ShardRecord {
  readonly kind: string;
  readonly sourceType: string;
  readonly namespace?: string;
  readonly bucket?: string;
  readonly database?: string;
  readonly account?: string;
  readonly name: string;
  readonly keyNameHash: string;
  readonly recordId: string;
  readonly plaintextSize: number;
  readonly plaintextSha384: string;
  readonly recordHash: string;
  readonly codec: string;
  readonly segments: Segment[];
  readonly recordSalt?: string;
  readonly kv?: KVDescriptor;
  readonly r2?: R2Descriptor;
  readonly secrets?: SecretsDescriptor;
  readonly d1?: D1Descriptor;
  // incompleteMarker (RV-CLI-MARKER): present ONLY when this record's VALUE is an incompleteness SENTINEL
  // the source emitted in place of real bytes (one of seal/marker.ts MARKER_KEYS: _unavailable/_skipped/
  // _pending/_truncated/_refused); its string value is that marker KIND. Absent on every real-data record
  // and on all archives sealed before this field shipped, so it is fully backward-compatible and an old
  // reader simply ignores it. It rides in the shard record line the root's per-shard SHA-384 pins, so it is
  // signed + tamper-evident, and it is NOT folded into the Merkle-leaf recordHash (like namespace/bucket/the
  // descriptors, it is a manifest annotation). It lets the offline restore treat a marker record as the
  // sentinel it is (never re-materialising the sentinel bytes as real data) without decrypting its value.
  readonly incompleteMarker?: string;
}

/** The first line of a manifest shard: its kind, the format version, the run and shard ids, and
 * the number of records in the shard. */
export interface ShardPreamble {
  readonly kind: string;
  readonly formatVersion: string;
  readonly runId: string;
  readonly shardId: string;
  readonly recordCountInShard: number;
}
