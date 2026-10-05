package spec

import "sort"

// Source-type identifiers for a record's `sourceType` field (SPEC.md 12.1). These are
// the textual JSON values a conformant downpipe/0.1.0 writer emits; a reader MUST refuse a
// `sourceType` outside this set (SPEC.md 12.1, 13). They live in this leaf package so the
// reader, the restore targets and the conformance tests share one definition rather than
// each carrying a private string literal.
const (
	// SourceKV is Workers KV: a name and an opaque value (SPEC.md 12.1).
	SourceKV = "kv"
	// SourceR2 is an R2 object: a large opaque blob, a segment chain per object
	// (SPEC.md 12.1).
	SourceR2 = "r2"
	// SourceSecrets is the account Secrets Store and per-Worker secrets: the
	// high-assurance, possibly load-bearing source, subject to the secrets rule
	// (SPEC.md 12.1, 12.4).
	SourceSecrets = "secrets"
	// SourceD1 is a D1 database exported as a single SQLite-compatible dump; restore
	// replays the dump (SPEC.md 12.1).
	SourceD1 = "d1"
	// SourceWorkers is a Workers script snapshot: the code, the settings (bindings,
	// compatibility date/flags) and a versions inventory. Its restore is REPROVISION,
	// never a blind redeploy: the snapshot proves the code and the binding/secret
	// inventory are recoverable and the operator re-deploys deliberately (SPEC.md 12.1).
	SourceWorkers = "workers"
	// SourceCFConfig is a Cloudflare-configuration surface snapshot (DNS, zone settings,
	// rulesets, Access, and so on) as one record per surface. Its restore is tiered
	// replay guidance: only an idempotent surface can be re-applied, ordered and
	// reprovision surfaces stay out of band (SPEC.md 12.1).
	SourceCFConfig = "cf-config"
	// SourceStream is a Cloudflare Stream video-inventory snapshot: one record per video
	// carrying its metadata (uid, name, duration, playback, status, requireSignedURLs, ...).
	// Its restore is REPROVISION, like workers: the snapshot proves the inventory + per-video
	// config are recoverable and the operator re-uploads deliberately. When the downpipe opts in
	// (includeContent), the video binaries and captions are captured as extra records and verified
	// the same way; restore stays reprovision (SPEC.md 12.1).
	SourceStream = "stream"
	// SourceImages is a Cloudflare Images inventory snapshot: one record per image carrying its
	// metadata (id, filename, uploaded, requireSignedURLs, variants, user meta) plus an account-level
	// variant-definitions record. Its restore is REPROVISION, like stream/workers: the snapshot proves
	// the inventory + variant config are recoverable and the operator re-uploads deliberately. When the
	// downpipe opts in (includeContent), the image binaries are captured as extra records and verified the
	// same way; restore stays reprovision (SPEC.md 12.1).
	SourceImages = "images"
	// SourceArtifacts is a Cloudflare Artifact Registry inventory snapshot: one record per repo carrying
	// its namespace + repo metadata. Its restore is REPROVISION, like stream/images/workers: the snapshot
	// proves the namespace/repo inventory is recoverable and the operator re-creates + re-pushes. When the
	// downpipe opts in (includeContent), the repo CONTENTS (the commit log, every commit + reachable tree,
	// and each reachable blob's bytes) are captured as extra records and verified the same way; restore
	// stays reprovision (SPEC.md 12.1).
	SourceArtifacts = "artifacts"
)

// knownSourceTypes is the closed set of supported `sourceType` values for this format
// version (SPEC.md 12.1); the compatibility unit is the minor while the format major is
// 0, so widening this set is downpipe/0.2.0 and not a change within downpipe/0.1.x. The reserved-but-unsupported types (`durable_object`,
// `vectorize`, SPEC.md 12.1) are deliberately NOT in this set: they have native
// point-in-time recovery and sit outside downpipe/0.1.0 scope, so a record claiming one is
// refused exactly like any other out-of-set type.
var knownSourceTypes = map[string]struct{}{
	SourceKV:        {},
	SourceR2:        {},
	SourceSecrets:   {},
	SourceD1:        {},
	SourceWorkers:   {},
	SourceCFConfig:  {},
	SourceStream:    {},
	SourceImages:    {},
	SourceArtifacts: {},
}

// KnownSourceTypes returns the closed set of supported downpipe/0.1.0 `sourceType` values
// (SPEC.md 12.1) in a sorted, deterministic order. It lets a caller (notably the
// reprovision-guidance regression test) drive over the authoritative set rather than
// maintaining a parallel literal that can silently fall out of step when a type is added.
func KnownSourceTypes() []string {
	out := make([]string, 0, len(knownSourceTypes))
	for t := range knownSourceTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// IsKnownSourceType reports whether t is a supported downpipe/0.1.0 `sourceType` (SPEC.md
// 12.1). A reader uses this to refuse an out-of-set type rather than restore it as opaque
// bytes under a guessed behaviour.
func IsKnownSourceType(t string) bool {
	_, ok := knownSourceTypes[t]
	return ok
}

// ReprovisionSourceType reports whether a record's source type restores by REPROVISION or
// replay guidance rather than a direct value write (SPEC.md 12.1). It returns true for the
// five reprovision types: `workers`, `cf-config`, `stream`, `images` and `artifacts`. For
// each, the offline reader still decrypts and hash-verifies the value (so the snapshot's
// recoverability is proven) and writes the verified bytes out for the operator, but it
// never treats them as a live re-apply: a Worker is never blind-redeployed, a
// Cloudflare-config surface is never blindly re-applied, and stream/images/artifacts
// inventories are never blind-re-uploaded from the offline tool, because any of these could
// brick a live service. The operator re-provisions deliberately from the surfaced bytes and
// guidance. The direct-write sources (`kv`, `r2`, `secrets`, `d1`) return false: their
// verified bytes are a value the reader can write back directly.
func ReprovisionSourceType(t string) bool {
	return t == SourceWorkers || t == SourceCFConfig || t == SourceStream || t == SourceImages || t == SourceArtifacts
}
