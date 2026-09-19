// Frozen on-disk constants of the downpipe/0.1.0 format, ported verbatim from the Go
// reference internal/spec/spec.go and container.go. A label or size that diverges from
// the reference is a silent interop break, so this file is the single source of these
// constants and is never edited without a vector regeneration.
//
// WHAT CHECKS IT, by name, because until this header said the file "is checked
// against spec.go" and NOTHING DID: `grep -rln "spec.go" scripts test` returned this file
// alone, and none of the repo's gates named the Go reference at all. A reviewer reading the
// old sentence would conclude the check existed and stop looking, which is worse than the
// gap it described. The check is now test/validate-format-constants.ts (chain member
// validate:format-constants): it reads the Go declarations and the exports below and
// compares every pair that pins a byte-level rule, plus the closed source-type set, and it
// fails on a constant added to either side that the other has not ported. CI re-runs it with
// DOWNPIPE_REPO set so the comparison is against the live spec.go, not only the pinned
// vendored copy at test/vectors/spec/.

/** The archive format version label written into every manifest. */
export const VERSION = "downpipe/0.1.0";

/** The engine's own release version, reported by the update check and compared against the
 * vendor-signed recommended version. Bumped per engine release.
 *
 * 0.1.9 was burned twice over and must never be re-published. The artefact the stable channel
 * served from carries ENGINE_VERSION "0.1.9" and writes the RETIRED downpipe/1.0
 * format, so one version number named two incompatible archive formats. 0.1.10 is burned as
 * well: the workspace's chaos-test rehearsal kit already ships an engine-0.1.10.mjs of different
 * bytes on its own rehearsal channel. This bump to 0.2.0 is the re-cut
 * COMPATIBILITY-AND-BACKTESTING.md demands ("a re-cut must bump rather than re-publish 0.1.9"),
 * and the minor rather than the patch because the archive format identity moved with it. */
export const ENGINE_VERSION = "0.3.5";

/** The STREAM chunk size in bytes: 64 KiB of plaintext per AES-256-GCM chunk. */
export const CHUNK_SIZE = 65536;
/** The STREAM payload nonce size in bytes (prepended to a sealed STREAM). */
export const STREAM_NONCE_SIZE = 16;
/** The AES-256-GCM authentication tag size in bytes (appended to each chunk). */
export const TAG_SIZE = 16;
/** The per-chunk AES-GCM nonce size in bytes (three reserved bytes, an 8-byte counter, a 1-byte flag). */
export const CHUNK_NONCE_SIZE = 12;
/** The byte offset of the 8-byte chunk counter within the per-chunk nonce (after the three reserved bytes). */
export const CHUNK_NONCE_COUNTER_OFFSET = 3;

/**
 * The per-segment STREAM-chunk ceiling for the format major (SPEC 14.5): a record is split into
 * segments of at most 16384 chunks (16384 * 65536 = 1 GiB of codec=none plaintext), so a
 * whole-segment chunkRange's lastChunkExclusive is at most this. Mirrors the Go reference
 * maxSegmentChunks and bounds a per-segment read independently of any single manifest's declared
 * range.
 */
export const MAX_SEGMENT_CHUNKS = 16384;

/** Codec identifier for no compression (the byte form mixes into the file-key context). */
export const CODEC_NONE = 0x00;
/** Codec identifier for gzip compression (the byte form mixes into the file-key context). */
export const CODEC_GZIP = 0x01;
/** The JSON codec name for no compression. */
export const CODEC_NAME_NONE = "none";
/** The JSON codec name for gzip compression. */
export const CODEC_NAME_GZIP = "gzip";

/** Address domain separator for a single non-secret segment. */
export const ADDR_SINGLE_NON_SECRET = 0x01;
/** Address domain separator for a packed segment. */
export const ADDR_PACKED = 0x02;
/** Address domain separator for a secrets segment. */
export const ADDR_SECRETS = 0x03;

/** HKDF info string for the content-addressing key derivation (frozen for the major version). */
export const INFO_CONTENT_ADDRESS = "downpipe/0.1.0 content-address";
/** HKDF info string for the per-run manifest subkey derivation. */
export const INFO_MANIFEST_KEY = "downpipe/0.1.0 manifest-key";
/** HKDF info string for the per-shard manifest-wrap key derivation. */
export const INFO_MANIFEST_WRAP = "downpipe/0.1.0 manifest-wrap";
/** HMAC label for the keyed name MAC. */
export const INFO_NAME_MAC = "downpipe/0.1.0 name-mac";
/** HKDF info string for the per-segment file-key derivation. */
export const INFO_SEG_KEY = "downpipe/0.1.0 seg-key";
/** HMAC label for the run key commitment. */
export const INFO_KEY_COMMIT = "downpipe/0.1.0 key-commit";
/** Hash label for the recipient-set hash. */
export const INFO_RECIPIENT_SET = "downpipe/0.1.0 recipient-set";
/** HKDF info string for the master-capsule DEM key derivation. */
export const INFO_CAPSULE_DEM = "downpipe/0.1.0 capsule-dem";
/** HKDF info string for the per-file STREAM payload key derivation. */
export const INFO_PAYLOAD = "downpipe/0.1.0 payload";
/** The hybrid KEM combiner label bound into the shared-secret derivation. */
export const HYBRID_KEM_LABEL = "downpipe/0.1.0 hybrid-kem";

/** The 4-byte segment container magic, "DPS1" (SPEC 7.1, 11.9); framing only, never in the AEAD. */
export const MAGIC_SEG = new Uint8Array([0x44, 0x50, 0x53, 0x31]); // "DPS1"
/** The 4-byte manifest container magic, "DPE1" (SPEC 7.1, 11.9); framing only, never in the AEAD. */
export const MAGIC_DPE = new Uint8Array([0x44, 0x50, 0x45, 0x31]); // "DPE1"
/** The 1-byte container version that follows the magic in a framed container. */
export const CONTAINER_VERSION = 0x01;

/**
 * KNOWN_SOURCE_TYPES is the closed downpipe/0.1.0 source-type set (SPEC 12.1), mirrored verbatim
 * from the Go reference internal/spec/sourcetype.go. The reader checks every opened record against
 * it (reader.ts openShards) and refuses the archive rather than restoring an unknown type under a
 * guessed behaviour, so both readers agree on what a valid archive may contain. The reserved
 * durable_object and vectorize are deliberately absent. Widening this set widens the format itself,
 * so it belongs with a spec.go change and a vector regeneration, not with a source-side edit.
 */
export const KNOWN_SOURCE_TYPES: ReadonlySet<string> = new Set([
  "kv", "r2", "secrets", "d1", "workers", "cf-config", "stream", "images", "artifacts",
]);
