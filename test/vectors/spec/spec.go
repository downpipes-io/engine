// Package spec holds the frozen on-disk constants of the downpipe/0.1.0 archive
// format: the version label, the HKDF and MAC info strings, the codec and address
// domain identifiers, and the fixed STREAM chunk size. It is a leaf package that
// imports none of the crypto, format, restore or command packages, so the
// version-pinned byte rules live in one place that the writer, the reader and the
// conformance vectors all share (CONTRIBUTING, decision D10).
//
// A change to any constant here that pins a byte-level rule in
// docs/format/SPEC.md is a new FORMAT VERSION, which while the format major is 0
// means a MINOR bump: downpipe/0.1.0 becomes downpipe/0.2.0, not downpipe/1.0.0
// (SPEC.md section 13). The minor is the compatibility unit, so the new identity is
// one no existing reader implements, and a reader that reads both is retained code
// rather than a widened version comparison (SPEC.md 13.1).
package spec

// Version is the frozen format version label. It appears byte-identically in the
// cleartext root manifest, in the HKDF and MAC labels below, and in the
// compatibility section of the spec (SPEC.md sections 11.7 and 13).
const Version = "downpipe/0.1.0"

// ChunkSize is the downpipe STREAM plaintext chunk size in bytes (SPEC.md 7.8).
const ChunkSize = 65536

// Codec identifiers. The byte form is mixed into the AEAD-bound file-key context
// (SPEC.md 7.4 and 11.9); the textual names are the JSON values.
const (
	CodecNone byte = 0x00
	CodecGzip byte = 0x01

	CodecNameNone = "none"
	CodecNameGzip = "gzip"
)

// Address domain separators for the keyed segment address (SPEC.md 7.2). The
// one-byte prefix keeps the three source classes from colliding on one address.
const (
	AddrSingleNonSecret byte = 0x01 // one non-secret record's stored bytes
	AddrPacked          byte = 0x02 // several packed non-secret records
	AddrSecrets         byte = 0x03 // a secrets record, salted and never deduped
)

// HKDF and MAC info strings, frozen for the format version (SPEC.md 11.7). Where a
// label is a prefix (seg-key, manifest-wrap, key-commit, recipient-set) the caller
// appends the documented context bytes.
const (
	InfoContentAddress = "downpipe/0.1.0 content-address" // CAK, salt = downpipeId
	InfoManifestKey    = "downpipe/0.1.0 manifest-key"    // MK, salt = runId
	InfoManifestWrap   = "downpipe/0.1.0 manifest-wrap"   // || 0x00 || shardId
	InfoNameMAC        = "downpipe/0.1.0 name-mac"        // salt = runId, ikm = MK
	InfoSegKey         = "downpipe/0.1.0 seg-key"         // || 0x00 || ctx
	InfoKeyCommit      = "downpipe/0.1.0 key-commit"      // message || runId
	InfoRecipientSet   = "downpipe/0.1.0 recipient-set"   // || 0x00 || rpk_sorted
	InfoCapsuleDEM     = "downpipe/0.1.0 capsule-dem"     // master-capsule DEM wrap key
)

// Symmetric STREAM payload constants. The AEAD is AES-256-GCM applied in fixed-size
// chunks (SPEC.md 7.8). A per-file payload nonce is the HKDF salt that expands the
// file key into the per-file payload key, so the AES key is fresh per sealed unit.
const (
	StreamNonceSize = 16 // per-file payload nonce, the HKDF salt for the payload key
	TagSize         = 16 // AES-256-GCM authentication tag per chunk
)

// FileKeySize is the derived symmetric key length in bytes: 256-bit, the
// AES-256-GCM key size that every HKDF file-key derivation expands to.
const FileKeySize = 32

// InfoPayload is the HKDF-SHA-384 info string for the per-file payload key (SPEC.md
// 7.8 and 11.7).
const InfoPayload = "downpipe/0.1.0 payload"

// HybridKEMLabel is the info-string prefix for the hybrid KEM combiner (SPEC.md 4
// and 11.7). The combiner mirrors X-Wing's binding choices generalised to
// ML-KEM-1024 over HKDF-SHA-384.
const HybridKEMLabel = "downpipe/0.1.0 hybrid-kem"
