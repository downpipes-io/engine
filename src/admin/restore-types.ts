// The wire types for the in-account restore route, shared by the engine handler and copied
// verbatim into the console's api.ts so the two sides cannot drift. Restore is the
// write-back dual of the seal: it opens a sealed run read-only, verifies the whole chain
// and each record's plaintext hash, then (only on confirm) writes the verified plaintext
// back into live in-account resources. Dry-run is the default and writes nothing.

export type RestoreSinkType = "kv" | "r2" | "secrets" | "d1" | "cf-config" | "workers" | "images" | "stream";

// RESTORE_SINK_TYPES is the runtime membership set used to verify that a DATA record's manifest sourceType
// (a typed string) is a known RestoreSink before it is narrowed and resolved to a sink. It is intentionally
// NARROWER than RestoreSinkType: "images"/"stream" are receipt source-type LABELS (a media record is
// re-uploaded through the Cloudflare media API, never through a RestoreSink), so they are NOT in this set
// and a media record is never classified as a data-record sink.
export const RESTORE_SINK_TYPES = new Set<string>(["kv", "r2", "secrets", "d1", "cf-config", "workers"]);

// RestoreTarget overrides where records are written. When omitted, each record is restored
// to the source binding/namespace/bucket recovered from the manifest. binding is the env
// binding to write through; namespaceId/bucketName override the recorded names.
export interface RestoreTarget {
  binding?: string;
  namespaceId?: string;
  bucketName?: string;
}

// RestoreRequest is the POST /admin/restore body. confirm defaults to false (dry-run);
// include/exclude are prefix selectors with the same include-empty-means-all / exclude-wins
// semantics as sources Selector; maxRecords caps a dry-run preview or a partial apply.
export interface RestoreRequest {
  runId: string;
  confirm?: boolean;
  target?: RestoreTarget;
  include?: string[];
  exclude?: string[];
  maxRecords?: number;
  // recordName (GRANULAR restore, E4/C1) is the FIRST-CLASS single-record path: when set, the restore
  // plans + applies EXACTLY the one record whose source name equals recordName (an EXACT match, never a
  // prefix), and every other record in the run is reported "not the selected record". It is the explicit,
  // single-record-safe convenience over the prefix selector (which is prefix-based: include:["user:42"]
  // would also catch "user:42x"); recordName resolves to precisely the named record or to nothing (an
  // honest "record not found in run" when no record carries that exact name). It composes with the SAME
  // dry-run-default + dual-control-to-apply + reserved-binding + two-phase-verify safety as a full
  // restore; it only ever NARROWS the scope to one record, never widens it. When recordName is set the
  // include/exclude prefixes are ignored (recordName is the more specific intent); exclude still cannot
  // re-admit anything because the scope is already a single exact name. It is bound into the plan hash
  // (restorePlanHash) so a single-record apply carries its own distinct approval, never reusing a
  // whole-run approval.
  recordName?: string;
  // destinationId selects WHICH archive destination to read the run back from (multi-destination):
  // the bucket the run's downpipe writes to. ABSENT = the default destination (back-compat). The
  // console passes the run's downpipe's destinationId so a restore reads from the right bucket; an
  // engine that resolves it wrong would read a run that is not there, not write anywhere unsafe.
  destinationId?: string;
  // cfConfig carries the in-console Cloudflare-config restore context (the "next increment" over the
  // out-of-band default): an EDIT-scoped Cloudflare API token (for an apply) or a READ token (to compute
  // the dry-run diff), plus the account and optional zone the snapshot belongs to (the console knows them
  // from the downpipe's source). The token is NEVER stored, NEVER logged, and NEVER bound into the plan
  // hash (only the account/zone are). Only idempotent (T1) surfaces re-apply; ordered/reprovision stay out
  // of band. Absent => cf-config records remain out of band exactly as before (no behaviour change).
  //
  // confirmDifferentAccountId is the CROSS-ACCOUNT confirmation (G-P0-021, the confused-deputy guard). A
  // cf-config apply writes to this caller-supplied accountId; the engine cross-checks it against the account
  // the archive was CAPTURED from (the signed rec.account, stamped at seal). When they MATCH (the common
  // same-account restore) nothing is required and this is ignored. When they DIFFER, or the archive recorded
  // no origin account (so the target cannot be verified), the apply is REFUSED before any write UNLESS this
  // field echoes the target accountId exactly (a type-to-confirm that names the foreign account). This makes
  // a disaster-recovery restore into a different Cloudflare account a deliberate, non-silent choice rather
  // than a silent write to whatever account a drifted or hostile caller supplied. It is NOT a secret and is
  // NOT bound into the plan hash (the write TARGET, accountId, already is): it is an independent safety gate,
  // like the reserved-binding guard.
  // `surfaces` is an OPTIONAL allow-list of surface ids this apply may write. It only ever NARROWS: it is
  // intersected with the in-band set, so naming an ordered/reprovision surface does not grant it a write
  // path. Omitted means every in-band surface. Either way the RESOLVED list is bound into the plan hash
  // (F10, see approvals.ts resolveCfConfigSurfaces), so an approval authorises a concrete surface set
  // rather than whatever the engine's in-band set grows into.
  cfConfig?: { token: string; accountId: string; zoneId?: string; confirmDifferentAccountId?: string; confirmDifferentZoneId?: string; surfaces?: string[] };
  // mediaRestore carries the in-account media re-upload context (the "next increment" over the out-of-band
  // default for stream/images): an EDIT-scoped Cloudflare API token + the account, so a captured image is
  // re-uploaded to its ORIGINAL id and a captured video is re-uploaded (the service assigns a new uid,
  // reported as an id-map). SAFE-BY-DEFAULT: nothing uploads unless this is present AND confirm is true; a
  // dry run reports what would upload. The re-upload is additive (create-only, never delete). The token is
  // NEVER stored, logged, or bound into the plan hash. Absent => media records stay out of band as before.
  //
  // confirmDifferentAccountId is the CROSS-ACCOUNT confirmation (G-P0-022), the media-leg twin of the
  // cfConfig field above: a media re-upload writes to this caller-supplied accountId, so the engine
  // cross-checks it against the archive's signed origin account (rec.account) and refuses a DIFFERENT (or
  // unverifiable) target before any upload unless this echoes the target accountId exactly. Same-account
  // media restore (origin == target) requires nothing. Not a secret, not bound into the plan hash.
  mediaRestore?: { token: string; accountId: string; confirmDifferentAccountId?: string };
  // d1Tables (D1 TABLE-SUBSET restore) scopes a restore to a chosen set of ONE database's tables: the
  // header (which creates every table) + the schema + ONLY the named tables' row pages are restored, into
  // a FRESH database (the D1 fresh-target contract is unchanged; unselected tables are created empty).
  // Table names are matched case-insensitively against the backup's header; an unknown table name is
  // refused (a typo is an honest error, not a silent no-op). It supersedes include/exclude for that
  // database and is MUTUALLY EXCLUSIVE with recordName. Bound into the plan hash, so a table-subset apply
  // carries its own distinct approval. Absent => no table-subset scoping (unchanged behaviour). createOnly
  // (default false): when true the fresh database is created with ONLY the selected tables (a minimal
  // extract) instead of the full schema; a kept table's foreign key to an unselected table stays a dangling
  // FK (SQLite-legal with FK enforcement off; the dependency lint warns). createOnly is bound into the plan
  // hash too (it changes what is created).
  d1Tables?: { database: string; tables: string[]; createOnly?: boolean };
}

// CapsuleResult (008) is the POST /admin/restore/capsule response: the NON-SECRET material the operator's
// browser needs to recover a chosen run's per-run master locally (openCapsule) for an in-console break-glass
// restore. masterCapsule is the run's master-capsule wraps (each a hybrid KEM ciphertext + a STREAM-sealed
// 32-byte master addressed to a recipient fingerprint) and keyCommitment is the DEM aad; NEITHER is
// decryptable without the break-glass PRIVATE, which stays in the browser, so it is safe to serve to the
// authenticated owner (the capsule already sits encrypted in the customer's own destination bucket, and the
// run's root manifest is signature-verified before it is served, so the route is not an oracle for
// attacker-shaped bytes). recordCount is the run's declared record count (so the browser can estimate the
// restore work). On a run that could not be read or whose manifest did not verify it is ok:false + a coarse
// reason (never a 500), with the capsule fields absent. It carries NO key and NO plaintext.
export interface CapsuleResult {
  ok: boolean;
  runId: string;
  masterCapsule?: Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>;
  keyCommitment?: string;
  recordCount?: number;
  reason?: string;
}

// One preview row in a dry-run plan. binding is the resolved destination binding (the target
// override, else the record's recovered source binding); namespace/bucket echo the recovered
// manifest fields.
export interface RestoreSampleItem {
  name: string;
  sourceType: RestoreSinkType;
  binding: string;
  namespace?: string;
  bucket?: string;
  plaintextSize: number;
}

export interface RestoreSkipped {
  name: string;
  reason: string;
}

// RestoreFidelityWarning is a record the apply WILL write, but not at full fidelity, and which the dry run
// can already say so about. It is deliberately NOT a RestoreSkipped: a skipped record is one an apply does
// not write, and filing a written-but-degraded record there would tell an operator their data is still in
// the archive when it is about to be in their account.
//
// It exists because the receipt was the only place a fidelity loss was ever named, and the receipt is read
// AFTER the operator has committed. The dry run is the screen they read before every apply. A KV key whose
// captured expiration has already lapsed restores without that expiration and then never expires, which for
// a namespace of session or cache keys is a decision an operator may well want to make differently (restore
// a narrower selection, or re-set the TTLs immediately afterwards). Naming it only on the receipt makes that
// a discovery rather than a choice.
//
// Redaction-safe on the same terms as RestoreSkipped: it carries the record name (the customer's own key,
// or a synthetic "(...)" aggregate label) and engine-authored prose, never a value or a credential.
export interface RestoreFidelityWarning {
  name: string;
  reason: string;
}

// D1DependencyWarning is one entry of the D1 table-subset restore lint: a SELECTED D1 child table whose
// foreign-key parent is present in the backup but is NOT itself in the restore scope. Restoring the
// child without its parent leaves the child's references dangling. It is ADVISORY, never a gate: a D1
// restore runs with foreign-key enforcement off (creation-order inserts), so the child's rows still
// load; the warning exists so the operator can widen the selection before confirming. database is the
// D1 database name, table the selected child, missingParent the unselected parent (the backup's spelling).
export interface D1DependencyWarning {
  database: string;
  table: string;
  missingParent: string;
}

// CrossAccountWarning (G-P0-021/022, the confused-deputy guard) names a restore LEG (cf-config or media)
// whose caller-supplied TARGET Cloudflare account is not provably the account the archive was captured FROM.
// A cf-config / media apply writes through the Cloudflare API to a caller-supplied accountId, so a wrong (or
// drifted) account would land the write in the WRONG account. The engine surfaces this on the dry-run so a
// cross-account restore is SEEN before it is confirmed, and refuses the apply unless the leg's
// confirmDifferentAccountId echoes the target (see RestoreRequest.cfConfig / .mediaRestore).
//   originAccount: the archive's SIGNED origin account for this leg's records (the source adapter's own
//     accountId, stamped at seal and pinned by the root's per-shard SHA-384, so it cannot be spoofed by the
//     request), or null when the archive recorded none (an unverifiable origin, treated as cross-account so a
//     silent write to an unverified account is impossible).
//   targetAccount: the account the caller supplied for this leg (where an apply WOULD write).
export interface CrossAccountWarning {
  leg: "cf-config" | "media";
  originAccount: string | null;
  targetAccount: string;
}

// CrossZoneWarning is the ZONE twin of CrossAccountWarning, and it exists because the account guard does
// not cover the case that is far easier to hit. A customer with several zones in one account picks the
// wrong one in the console: the account matches, so nothing gates, and 118 zone-scoped surfaces (DNS,
// rulesets, page rules, zone settings) are written into the wrong zone. The restore is additive, so it
// does not delete the target zone's records; it pollutes the zone with another zone's configuration,
// which is its own kind of outage and a tedious one to unpick.
//
// The origin zone is read from the cf-config identity record, which every crawl emits first and whose
// value carries {accountId, zoneId, zoneName}. That record is hash-verified by restoreRecord before it is
// parsed, exactly like any other, so the origin cannot be spoofed by the restore request. It is used
// rather than a manifest field because ShardRecord carries `account` and no zone, and adding one is a
// format change for a guard the archive already has the data for.
export interface CrossZoneWarning {
  originZone: string | null;
  targetZone: string;
  // The zone-scoped surfaces this would write. Named so the operator sees the blast radius rather than a
  // count, which is the same reason F9 names removals.
  zoneSurfaces: string[];
}

// RestorePlan is the dry-run result: verify read-only, write nothing, return what an apply
// WOULD do. recordsVerified counts records whose full chain + plaintext hash verified within
// the selector/maxRecords window; plannedWrites is how many would be written on apply; bytes
// is the summed plaintext size of the planned writes (an upper bound).
export interface RestorePlan {
  ok: boolean;
  runId: string;
  mode: "dry-run";
  recordsVerified: number;
  isLatest: boolean;
  plannedWrites: number;
  bytes: number;
  sample: RestoreSampleItem[];
  // plannedAt / applyDeadline: the instant this plan was computed, and the LAST instant at which an apply of
  // an approval anchored to it may still be writing (plannedAt + RESTORE_APPLY_DEADLINE_MS, the approval's
  // own life plus the reservation lease an apply holds while it writes). fidelityWarnings is computed
  // against applyDeadline, not against plannedAt, so the set the plan warns about is a superset of the set
  // the sink can drop at every instant the approval permits. Stated on the wire so the claim is checkable
  // rather than asserted: a reader can take applyDeadline, ask the sink's own rule what it would drop then,
  // and compare. RFC-3339 UTC millis, the same shape as the approval record's own timestamps.
  //
  // Present on every plan that actually previewed the run. Absent ONLY on the refusal stubs that preview
  // nothing (a reserved binding, a break-glass posture with no read-back key, an out-of-scope request):
  // those write nothing and disclose nothing, so a deadline for them would be a fact about no apply. A plan
  // carrying fidelityWarnings always carries both, which is asserted rather than assumed
  // (test/validate-restore-promise-gaps.ts, GAP 3f).
  plannedAt?: string;
  applyDeadline?: string;
  // destFallback: present only when the 3-2-1 walk had to fall past at least one destination to produce this
  // result. See RestoreDestFallback.
  destFallback?: RestoreDestFallback;
  skipped: RestoreSkipped[];
  // configChanges (cf-config dry-run): the per-surface diff preview for Cloudflare-config records an apply
  // WOULD write back (idempotent surfaces only). Present only when a cfConfig context was supplied; each
  // entry is a surface id + a human diff summary + whether it would apply any change. No bytes here (a
  // config diff, not a data write).
  configChanges?: Array<{ surface: string; summary: string; willApply: boolean }>;
  // cfConfigSurfaces (F10): the RESOLVED cf-config surface allow-list this plan was computed against, in
  // the same sorted form restorePlanHash binds. Present only when a cfConfig context was supplied.
  //
  // It is on the wire so the CONSOLE can compute a matching plan hash: the console mirrors restorePlanHash
  // client-side to show the operator the hash an approval binds to, and needs the resolved surface list to
  // do it (the default is the proven set, which the console has no independent copy of). An older engine
  // omits it, and an older engine also does not bind surfaces, so a console that falls back to omitting them
  // still matches.
  cfConfigSurfaces?: string[];
  // mediaPlanned (media dry-run): the captured media files an apply WOULD re-upload (images to their
  // original id, videos as new uids). Present only when a mediaRestore context was supplied.
  mediaPlanned?: Array<{ name: string; type: "images" | "stream" }>;
  // dependencyWarnings (D1 table-subset lint): read-only advisories that a SELECTED D1 child table's
  // foreign-key parent is in the backup but NOT in the restore scope. Present only when at least one such
  // case is detected. Never a gate (a D1 restore runs with FK enforcement off); the operator may widen the
  // selection to include the parent, or proceed knowingly.
  dependencyWarnings?: D1DependencyWarning[];
  // fidelityWarnings: records this apply WOULD write, but not at full fidelity, known from the signed
  // manifest before anything is written. Present only when at least one applies. Advisory, never a gate:
  // the write succeeds, so plannedWrites still counts it and ok is unaffected. See RestoreFidelityWarning.
  fidelityWarnings?: RestoreFidelityWarning[];
  // crossAccountWarnings (G-P0-021/022): the cf-config / media legs whose target account is NOT provably the
  // archive's origin account, so an apply would write into a DIFFERENT (or unverifiable) Cloudflare account.
  // Present only when at least one leg is cross-account; the console renders it and drives the type-to-confirm
  // the apply requires. Absent on the common same-account restore. Redaction-safe (account ids + a leg label).
  crossAccountWarnings?: CrossAccountWarning[];
  // The cf-config zone guard (B5). Present only when a zone-scoped surface would be written into a zone
  // that is not provably the one the archive came from.
  crossZoneWarning?: CrossZoneWarning;
  // WINDOWED-RESTORE HONESTY (maxRecords): when maxRecords caps the plan to fewer records than the
  // selector matched, the records beyond the window are NOT verified. outOfWindow is how many were
  // dropped; windowed is outOfWindow > 0; complete is true only when nothing failed AND nothing fell
  // outside the window (a full, faithful preview). These are the honest signal that a windowed preview
  // is not a whole-run preview; ok keeps its existing meaning (dryRunSkipped.length === 0) so callers
  // that intentionally page with maxRecords are not regressed. A "(window)" skipped marker spells out
  // the count and the remedy. All optional so existing consumers do not break.
  outOfWindow?: number;
  windowed?: boolean;
  complete?: boolean;
  reason?: string;
}

// RESTORE_FAILURE_CLASSES (G285) -- WHY one record of a restore did not land, as a closed class tagged AT THE
// FAULT SITE. The `reason` beside it is operator-facing prose (it names the remedy and reaches the caller's
// live response) and it is NOT what rides into the pack: the pack carries the COUNT PER CLASS.
//
// "My restore applied with 3 failures. Which three?" The pack confirmed the number and could say nothing else,
// so a restore blocked by a scope-starved destination token, one whose bytes landed and would not read back
// (the data may be fine and the proof is missing), one whose Cloudflare config surface refused the write, and
// one whose video would not re-upload were ONE integer. They are four different tickets and three of them are
// not even about the archive.
//
// The class is chosen by the BRANCH that pushes the failure, never inferred from the prose. That is the whole
// point: a classifier over the reason strings would silently mislabel the first time one is reworded, and these
// strings are reworded for clarity all the time.
export const RESTORE_FAILURE_CLASSES = [
  "sink-write", // the record could not be WRITTEN to the destination sink at all (a dest-access fault, a D1 batch that died mid-load). Nothing landed
  "readback-failed", // the bytes WERE written and the post-write readback could not prove them (unreadable, or a hash mismatch). The data may well be fine; the PROOF is not
  "cf-config-surface", // a Cloudflare configuration surface refused the write (the cf-config restore leg)
  "media-upload", // an Images/Stream re-upload failed, or its restored asset could not be confirmed
  "integrity", // the archived record failed its own integrity check on the way out (a blind verify): the ARCHIVE is bad, not the target
] as const;
export type RestoreFailureClass = (typeof RESTORE_FAILURE_CLASSES)[number];

export interface RestoreFailure {
  name: string;
  reason: string;
  // The closed class, tagged at the fault site (G285). Optional on the type only so a failure built by an older
  // caller still compiles; every push site in this engine sets it, and the audit tally counts an untagged
  // failure honestly under `sink-write` rather than dropping it.
  cls?: RestoreFailureClass;
}

// RestoreReceiptRecord is one line of the auditable restore receipt: a single record's
// proof-of-correct-restore. It carries only redaction-safe fields (the record NAME -- the customer's own
// key -- its source type, hashes, the path that wrote it, and the verdict); never a value, a key, or a
// binding credential.
//   expectedSha384: the whole-record plaintext SHA-384 from the SIGNED manifest (what the bytes SHOULD be).
//   verifiedSha384: the hash the engine computed of the bytes that LANDED. For a STREAMED record and a
//     small BUFFERED R2 record it is the POST-WRITE READBACK hash (the persisted object re-read and
//     re-hashed). For a buffered-no-readback record (KV/Secrets/D1, which expose no readback API) it is the
//     verified in-memory plaintext hash that was written by an atomic put -- NOT proof of the landed bytes,
//     only proof of what was written. It is null only when a record that DOES read back (R2) could not be
//     read back at all.
//   verified: whether verifiedSha384 equals expectedSha384 (a true proof-of-correct-restore for this record).
//   via: which path produced verifiedSha384 -- "streamed-readback" (large R2: re-read the persisted object
//     and re-hash), "buffered-readback" (small R2: written whole then re-read and re-hashed),
//     "buffered-no-readback" (KV/Secrets/D1: atomic put of the verified bytes, NO post-write readback because
//     the resource has no readback API), "media-image-readback" (an IMAGE re-upload: the image keeps its
//     ORIGINAL id, so the live /blob is read back and re-hashed -- verifiedSha384 is the readback hash, a true
//     proof-of-correct-restore), or "media-stream-exists" (a VIDEO re-upload: Stream TRANSCODES the asset to a
//     NEW uid, so a byte-for-byte readback is impossible; the engine instead proves the new uid RESOLVES (the
//     live object is queryable), so verifiedSha384 is null and verified means the uid resolved, the strongest
//     proof available on a transcoded asset), or "cf-config-applied" (a Cloudflare CONFIGURATION surface: the
//     snapshot is not written as bytes at all, it is DIFFED against live config and re-applied item by item
//     through the Cloudflare API, so no landed-byte hash exists and verifiedSha384 is null; verified means
//     every item the diff produced was ACCEPTED by the API, which is the strongest proof available on a
//     diff-driven apply). It makes the proof's provenance explicit and never overclaims.
//
// A cf-config SURFACE IS ON THE RECEIPT so that a restore whose cf-config leg wrote NOTHING -- because the
// caller's edit-scoped Cloudflare token was too NARROW and every item came back 401/403 -- cannot produce a
// receipt with zero records, allVerified vacuously true, and a digest identical to a clean one. The receipt
// states that the surface was attempted and refused, and the digest moves when it was.
// THE ID MAP IS ON THE RECEIPT, NOT ONLY THE SCREEN. Cloudflare Stream TRANSCODES every upload, so a
// restored video lands on a NEW uid and every reference the customer holds to the archived uid has to be
// repointed. The receipt is the artefact the customer keeps and the one the "Download receipt" button
// writes, so it carries the map: after a recovery of many videos the durable record says which archived uid
// became which live one.
//
// A RECEIPT IS SIGNED, SO ADDING A FIELD IS NOT COSMETIC. Both fields are emitted into the signed and hashed
// core ONLY when the upload actually remapped (restore-receipt.ts receiptCore), which is exactly the terms
// recordsSkipped, configSkipReasonCounts and destFallback already sit on. Every receipt that does not carry a
// remapped video therefore canonicalises byte-for-byte as it did before this field existed, so its digest and
// its signature are unchanged and every receipt already anchored in the audit chain still verifies. A receipt
// that DOES carry one is signed over the map at the moment it is made; nothing is ever re-signed. There is no
// second implementation of receiptCore anywhere in the workspace (the console reads the receipt and does not
// re-derive its digest, and the offline reader does not verify restore receipts at all), so no verifier is
// pinned to the older shape.
//
// They are INSIDE the core rather than beside it for the destFallback reason: the id map is precisely what a
// tamperer would want to strip, since it is the operational key to finishing the recovery, and a field outside
// the hash can be stripped without breaking anything. Redaction-safe: a Stream uid is the customer's own
// asset id, the same class of identifier the record name already carries.
export interface RestoreReceiptRecord {
  name: string;
  sourceType: RestoreSinkType;
  expectedSha384: string;
  verifiedSha384: string | null;
  verified: boolean;
  via: "streamed-readback" | "buffered-readback" | "buffered-no-readback" | "media-image-readback" | "media-stream-exists" | "cf-config-applied";
  // The LIVE id the re-upload produced, present only when it DIFFERS from the archived one (a transcoded
  // Stream video). An image keeps its original id, so it carries neither field.
  restoredId?: string;
  // True only alongside restoredId, and never false: it states that the archived id in `name` no longer
  // addresses this asset. It is not inferred from `via`, because which media types remap is a platform
  // behaviour and not a property of the proof path.
  remapped?: true;
}

// RestoreReceipt is the auditable proof-of-correct-restore for an APPLIED restore (it is absent on a
// dry-run, which writes nothing). It states WHAT was restored and that each restored record's LANDED bytes
// hash to the signed manifest hash, and it is made TAMPER-EVIDENT two ways: (1) it is always anchored into
// the engine's tamper-evident audit chain by its receiptSha384 (a "restore-verified" audit entry carrying
// the digest, the runId, the count and allVerified), and (2) when the engine's signer key is reachable it
// also carries a DETACHED HYBRID SIGNATURE (Ed25519 + ML-DSA-87, the manifest's scheme) over the
// canonicalised receipt core, verifiable against the operator-pinned signer's public halves. With no
// reachable signer the audit anchor is the tamper-evidence and the receipt is honestly "audit-anchored",
// not "key-signed" (no fragile bespoke signing, no fabricated key). It is redaction-safe throughout
// (names + hashes + counts only).
//   records: one RestoreReceiptRecord per RESTORED record (a record that failed to write or failed its
//     readback is in failures, not here, except a streamed readback that ran and MISMATCHED is recorded
//     here with verified:false AND drained to failures, so the receipt shows the bad landing honestly).
//   summary.allVerified: true ONLY when every receipt record verified, so a single streamed mismatch
//     flips it false (and the apply's ok is already false from the drained failure).
//   receiptSha384: the canonical SHA-384 of the receipt core (every field except the tamper-evidence
//     fields), the value anchored into the audit chain and the digest a verifier recomputes.
//   signature/signatureAlg: present only when the receipt was key-signed; the detached hybrid signature
//     (base64url) over the canonical core and its algorithm label. Absent on an audit-anchored-only receipt.
// RestoreDestRefusal is ONE destination the 3-2-1 walk tried and did not get an answer from: the run's own
// destination id (the customer's own identifier for their own bucket, never a credential, an endpoint or a
// region) and the engine-produced reason it refused. The reason is always one of restore-reasons.ts's
// REASON_* literals, at most enriched with the shape-gated S3 <Code> destRejectionDetail admits, so nothing
// a destination said can ride here. destinationId is absent when the run recorded no destination and the
// read went to the engine default.
export interface RestoreDestRefusal {
  destinationId?: string;
  reason: string;
}

// RestoreDestFallback is the record of a restore-class operation that was NOT served by its first-choice
// destination. It is present ONLY on a result the 3-2-1 walk had to fall past at least one destination to
// produce, so a first-choice restore carries no field at all and is distinguishable from a fallback by its
// absence rather than by a boolean nobody reads.
//
// It exists so a customer restoring from a replica learns something about their primary: without it, a
// restore served from the third copy after the first two refused looks identical to one served from the
// first, and that is worth surfacing rather than masking.
//
//   servedAt: the 1-based position in the walk of the destination this result came from. 2 means the first
//     choice refused; it is never 1, because a first-choice result carries no RestoreDestFallback.
//   servedDestinationId: which destination this result came from, so the operator knows what they restored
//     from and not merely that it was not the usual one. Absent only when the walk ended on the default.
//     On a result that is itself a refusal it is the destination that gave the final answer, which is the
//     honest reading: an operator whose three copies failed for three different reasons is told all three.
//   refused: every destination tried before it, IN WALK ORDER, each with the reason it refused. The order
//     is the diagnosis: a primary that refused with a freshness reason and a replica that refused with an
//     access reason are two separate faults on two separate buckets, and one line saying "fell back" would
//     have said neither.
export interface RestoreDestFallback {
  servedAt: number;
  servedDestinationId?: string;
  refused: RestoreDestRefusal[];
}

export interface RestoreReceipt {
  runId: string;
  restoredAt: string; // RFC-3339 UTC millis the apply completed
  isLatest: boolean;
  records: RestoreReceiptRecord[];
  // destFallback rides INSIDE the signed and hashed receipt core, on the same terms as recordsSkipped:
  // present only when this restore was not served by its first-choice destination, absent otherwise. Inside
  // rather than beside, because the whole point of the field is that a receipt for a restore served from a
  // replica must not hash the same as a receipt for one served from the primary. A field a tamperer could
  // strip without breaking the digest would leave the silent fallback exactly where it was, and a receipt
  // is the artefact a customer keeps to prove what they recovered and from where.
  destFallback?: RestoreDestFallback;
  // recordsSkipped is the count of records the apply deliberately did NOT write (a secrets record has no
  // runtime write path; a data record whose captured value is an incompleteness marker is a sentinel, not
  // real bytes). It is present only when non-zero, so a restore that skipped nothing hashes and signs
  // byte-identically to a receipt built before this field existed and every already-anchored receipt still
  // verifies. Without it the receipt reads "restored 98, allVerified true" and a reader auditing the
  // recovery cannot see that two records from the archive are still not in the account.
  // configSkipReasonCounts is the CLOSED {class: count} map of every cf-config ITEM the Cloudflare API refused
  // on this apply, summed across surfaces. The per-surface receipt record above says WHICH surface did not
  // fully apply; this says WHY, in the vocabulary that routes the remedy: `auth` means the restore token lacks
  // the edit scope (one line to fix, and it will have refused every item on that surface), `quota` means the
  // account is at its plan limit, `validation` means the snapshot item was refused as malformed. Those are
  // three different tickets, and an integer cannot tell them apart. Redaction-safe by construction: every key
  // is a CfConfigSkipClass member and every value a count, and the raw Cloudflare message it was classified
  // from is never recorded (see cf-config-fault.ts). Present only when non-empty, so a restore whose cf-config
  // leg refused nothing carries no key and hashes as if the field did not exist.
  // metadataFieldsDropped is the CLOSED {field: count} tally of restore descriptors the sinks SHED, on the
  // same terms as the two above: present only when non-empty, so a full-fidelity restore hashes as if the
  // field did not exist. It is on the RECEIPT and not only on the RestoreResult because the receipt is the
  // artefact the customer keeps and the one the console's download button writes, and this is the field that
  // says the restore was not clean. A count that lives only in the live API response is gone the moment the
  // screen is closed, and one that lives outside the hash can be stripped without breaking the digest, which
  // for the field whose whole purpose is to stop a receipt claiming full fidelity is the wrong place for it.
  // Typed Record<string, number> rather than to the closed field union, matching RestoreResult below: this
  // module is IMPORT-FREE by contract (it is copied verbatim into the console's api.ts), and the key space is
  // held closed at the DROP SITE by METADATA_SHED_FIELDS and re-gated by sanitiseMetadataShed.
  summary: { recordsRestored: number; bytesRestored: number; allVerified: boolean; recordsSkipped?: number; configSkipReasonCounts?: Partial<Record<CfConfigSkipClass, number>>; metadataFieldsDropped?: Record<string, number> };
  receiptSha384: string; // "<hex>" canonical SHA-384 of the receipt core; the audit-anchor digest
  signature?: string; // base64url detached hybrid signature over the canonical core; present iff key-signed
  signatureAlg?: string; // the signature algorithm label; present iff key-signed
}

// BlindRestoreTest is the result of the BLIND restore test (restorability assurance, the keyed Tier):
// it decrypts EVERY in-scope record of a run to a DISCARD sink, verifying each record's plaintext SHA-384
// against the signed recordHash, and NEVER returns or logs a single byte of plaintext. It is the
// strongest single-archive recoverability proof short of an actual apply: the whole archive is genuinely
// decrypted and integrity-checked, but nothing is written and nothing is disclosed.
//   recordsVerified / bytesVerified: how many in-scope records decrypted-and-verified, and their summed
//     plaintext size. bytesVerified is the real decrypted byte count (the bytes that flowed to discard),
//     so it is a measured throughput figure, not a manifest-declared estimate.
//   failures: per-record coarse reasons for any record that did NOT verify (a tampered or unrecoverable
//     record). A non-empty list means the archive is not fully recoverable; the names are the source
//     names (the customer's own keys, redaction-safe), never a value.
//   restoreDigest: a "sha384:"-prefixed hash that stands IN FOR the verified plaintext WITHOUT the
//     plaintext itself ever entering the digest. It folds each verified record's recordId together with
//     that record's plaintextSha384 (the hash decryption PROVED equals the actual plaintext), in recordId
//     order, so the SAME data restoring yields the SAME digest (a repeat test proves the same bytes
//     restore) while the digest input is only the per-record hash, never a plaintext byte (so it cannot be
//     a confirmation oracle for a guessed value). It is null when no record verified (nothing to attest);
//     ok is true iff every in-scope record verified. NOTE: this is NOT byte-identical to the Go offline
//     reader's "discard" restore digest. Both fold a per-record plaintext SHA-384 (never the plaintext)
//     and are deterministic and content-sensitive, but the constructions differ: the engine chains a
//     re-hash over (recordId, plaintextSha384) in recordId-sorted order (foldDigestLeaf in restore.ts),
//     whereas the Go discard target streams (destinationKey, plaintextSha384) through one running SHA-384
//     in iteration order. They are independent recoverability proofs of the same data, not a shared value
//     to compare across the two implementations.
export interface BlindRestoreTest {
  ok: boolean;
  runId: string;
  // downpipeId is the run's own downpipe id, recovered from the verified root manifest, so the engine
  // can stamp the "offline restorability last proven" record onto the right downpipe on a pass. It is the
  // customer's own id (redaction-safe, like every downpipe id), never a key or value. Absent when the run
  // could not be opened (a break-glass-only posture or a failure before the manifest was read).
  downpipeId?: string;
  recordsVerified: number;
  bytesVerified: number;
  failures: RestoreFailure[];
  restoreDigest: string | null;
  isLatest: boolean;
  // destFallback: present only when the 3-2-1 walk had to fall past at least one destination to produce this
  // result. See RestoreDestFallback.
  destFallback?: RestoreDestFallback;
  reason?: string;
  // nothingToVerify (WIRE-28): true iff ok is false SOLELY because the run holds no records (run.records.length
  // === 0), never because a record failed its integrity check or a freshness/rollback check refused the run.
  // ok stays false either way -- "zero records is not a pass" (drill.ts's identical clause) -- but
  // a bare {ok:false} the caller could not tell apart from a genuine verification failure, so a fresh seal on a
  // source that had not been given any data yet read identically to a corrupted archive. reason is always
  // NOTHING_TO_VERIFY_REASON (admin/drill.ts) when this is true, mirroring the scheduled/manual drill's own
  // {nothingToVerify:true, reason} pair so both restorability-proof routes describe the same state the same way.
  nothingToVerify?: boolean;
}

// KeylessAttestationResult is the wire shape of the Tier 0 keyless integrity attestation: the
// signature/completeness/anti-rollback verdict that needs NO decryption key and NO data. It mirrors the
// reader's KeylessAttestation (the engine maps the reader result onto this so the wire type lives with the
// other restore wire types and is copyable into the console). ok is the AND of the three flags; reason is
// a coarse, secret-free note on the first failing check, or absent on a clean attestation.
export interface KeylessAttestationResult {
  ok: boolean;
  runId: string;
  // downpipeId is the run's own downpipe id, recovered from the SIGNATURE-VERIFIED root manifest (so it
  // is trustworthy even keylessly), letting the engine stamp the "last proven" record onto the right
  // downpipe on a pass. Redaction-safe; absent when the signature did not verify (no trustworthy manifest).
  downpipeId?: string;
  signatureValid: boolean;
  complete: boolean;
  notRolledBack: boolean;
  // destFallback: present only when the 3-2-1 walk had to fall past at least one destination to produce this
  // result. See RestoreDestFallback.
  destFallback?: RestoreDestFallback;
  reason?: string;
}

// RestoreResult is the applied result (confirm:true): every record is plaintext-hash-verified
// before it is written. recordsRestored is records actually written; bytesRestored is the
// summed plaintext size actually written; failures are per-record coarse reasons for records
// that verified but could not be written, drained without aborting the whole restore.
// skipped lists records that were intentionally not written and do not represent failures. Two kinds
// reach it: a secrets record, which has no runtime write path (Secrets Store bindings are read-only at
// runtime and must be restored out of band via the Cloudflare API or wrangler), and a data record whose
// captured value is an incompleteness MARKER (the object vanished or was over-ceiling at capture), which
// is a sentinel rather than real bytes and must never be written back as a live value.
//
// A non-empty skipped list does not set ok:false on its own, and that is right: nothing failed. It does
// mean the apply is NOT a clean full restore, because those records are in the archive and are not in the
// account, so a caller must read this list rather than reading ok:true as "everything landed". The console
// classifies a skipped apply distinctly for that reason, and the offline reader exits an advisory code
// rather than 0 for the marker case.

// CfConfigSkipClass is the closed vocabulary of WHY one cf-config item did not apply on a restore (G191).
// It MIRRORS sources/cf-config-fault.ts CF_WRITE_SKIP_CLASSES, which is where the classification happens.
// It is duplicated rather than imported because this module is IMPORT-FREE by contract (it is copied verbatim
// into the console's api.ts so the two sides cannot drift); test/validate-cron-source-diag.ts binds the two
// lists together, so a member added to one and forgotten in the other fails the gate.
export type CfConfigSkipClass =
  | "auth"
  | "entitlement"
  | "quota"
  | "validation"
  | "conflict"
  | "no-live-id"
  | "no-live-phase"
  | "live-only-rules"
  // "read-current-failed" was declared here and described in sources/cf-config-fault.ts's comment, but it
  // was never a member of CF_WRITE_SKIP_CLASSES and no code path ever produced it, in this repo or any
  // consumer. A closed vocabulary that advertises a class the product cannot emit is a false claim to
  // whoever reads a support pack. If the read-current case is ever implemented, add it to
  // CF_WRITE_SKIP_CLASSES first and this union will follow, which is the direction the drift assertion
  // (validate-cron-source-diag.ts) enforces.
  | "rate-limited"
  | "api-unavailable"
  | "other";

export interface RestoreResult {
  ok: boolean;
  runId: string;
  mode: "applied";
  recordsVerified: number;
  recordsRestored: number;
  bytesRestored: number;
  isLatest: boolean;
  failures: RestoreFailure[];
  skipped?: RestoreSkipped[];
  // configApplied (cf-config apply): the per-surface result of re-applying Cloudflare-config records to the
  // live account (idempotent surfaces only), each a surface id + the count applied + the count skipped (an
  // un-settable field the API refused). Present only when a cfConfig context was supplied. A cf-config write
  // that throws is recorded in failures (so ok reflects it), never silently dropped.
  // skipReasonCounts (G191) is the CLOSED {class: count} map behind `skipped`. The bare integer could not
  // distinguish "your plan caps DNS records" (quota) from "the restore token lacks the edit scope" (auth)
  // from "the snapshot item is malformed" (validation) -- three tickets, three different remedies. Every key
  // is a CfConfigSkipClass member and every value a count, so it is safe to carry in a support pack; the raw
  // Cloudflare message stays in the operator's live response and is never recorded.
  configApplied?: Array<{ surface: string; applied: number; skipped: number; skipReasonCounts?: Partial<Record<CfConfigSkipClass, number>> }>;
  // mediaRestored (media apply): the captured media files re-uploaded to the live account, each the record
  // name + the restored id and whether it was REMAPPED (stream gets a new uid; images keep their original
  // id). The remapped entries are the id-map the operator uses to update references. Present only when a
  // mediaRestore context was supplied. A failed upload is recorded in failures (so ok reflects it).
  mediaRestored?: Array<{ name: string; restoredId: string; remapped: boolean }>;
  // The per-CLASS media failure tally, keyed by the closed MEDIA_FAULT_CLASSES (media-restore.ts), and the
  // conflict DIGEST PAIRS distinguish an over-the-200MB-cap video (a platform limit, recover it out of band),
  // a transient Cloudflare blip (retry) and an id occupied by DIFFERENT live bytes (the operator must choose
  // to overwrite or remap), which would otherwise be indistinguishable. The digests are SHA-384 hashes of the
  // customer's OWN bytes -- the same irreversible join-key idiom the restore receipt already carries -- so a
  // "that image WAS ours" conflict can be adjudicated rather than argued. Honestly ABSENT when no media record
  // failed. Counts + closed class keys + hex digests only; never bytes, ids or a body.
  mediaFaults?: Record<string, number>;
  mediaConflictDigests?: Array<{ archivedSha384: string; liveSha384: string }>;
  // G055 (D1 partial apply): the evidence that LOCALISES a half-applied D1 restore -- the worst silent
  // corruption the engine can leave behind. A D1 restore replays over several NON-ATOMIC db.batch() calls, so
  // a fault part way leaves a PARTIALLY-LOADED database, and the receipt said only "partial restore": not
  // which batch broke (batch 3 of 900 is a schema/type problem; 899 of 900 is a size/constraint problem), not
  // what kind of failure it was, and -- on the "target not empty" refusal, where NOTHING was written -- not
  // even how many tables are standing in the way. d1ErrorClass is the closed D1_ERROR_CLASSES member the
  // classifier SELECTED from D1's own error tokens; the SQLite message (which embeds table names, column
  // names and, on a constraint violation, ROW VALUES) is read only to select it and is never carried.
  // schemaObjectsFiltered counts the indexes/triggers/views a table-SUBSET restore silently dropped, so an app
  // that breaks after a "complete" subset restore has an answer. Integers and one closed enum, nothing else.
  d1Fault?: { d1ErrorClass: string; failedBatchIndex?: number; batchTotal?: number; residualTableCount?: number };
  d1SchemaObjectsFiltered?: number;
  // G348: the restore descriptor fields a sink SHED (a KV expiration that was not a usable number, an R2
  // cacheExpiry that did not parse). Both are dropped by design -- writing an Invalid Date or a garbage TTL
  // would be worse -- but both were SILENT behind a receipt claiming full fidelity, so "our restored keys
  // never expire" had no evidence at all. A {closed field kind: count} map (dest/restore-fault.ts
  // METADATA_SHED_FIELDS); the unusable value is never carried. Absent on a full-fidelity restore.
  metadataFieldsDropped?: Record<string, number>;
  // WINDOWED-RESTORE HONESTY (maxRecords): see RestorePlan. When maxRecords caps the apply to fewer
  // records than the selector matched, the records beyond the window are NOT restored. outOfWindow is
  // how many were left unrestored; windowed is outOfWindow > 0; complete is true only when nothing
  // failed AND nothing fell outside the window. ok keeps its existing meaning (failures.length === 0)
  // so a caller that intentionally pages with maxRecords is not regressed; complete:false plus the
  // "(window)" skipped marker is the honest signal that records beyond the window went unrestored.
  // All optional so existing consumers do not break.
  outOfWindow?: number;
  windowed?: boolean;
  complete?: boolean;
  // receipt (auditable proof-of-correct-restore): the signed / audit-anchored RestoreReceipt for this
  // applied restore. Present on every APPLIED result that reached the write phase (absent only when the
  // apply was refused before any write -- a break-glass posture, a reserved binding, an oversized window,
  // or an early integrity abort -- where there is nothing to attest). It proves each restored record's
  // LANDED bytes match the signed hash and is tamper-evident (audit-anchored always, key-signed when the
  // signer is reachable). Redaction-safe (names + hashes + counts only). See RestoreReceipt.
  receipt?: RestoreReceipt;
  // destFallback: present only when the 3-2-1 walk had to fall past at least one destination to produce this
  // result. See RestoreDestFallback. The same value is inside the receipt's signed core when there is one.
  destFallback?: RestoreDestFallback;
  reason?: string;
}

// PointInTimeRun is the resolution of "the run to restore from AS OF timestamp T" (E4/C1 point-in-time):
// the LATEST SUCCESSFUL run of a given downpipe that completed AT-OR-BEFORE T, read from the bounded
// per-downpipe run-history ring. It is the join a console offers when an operator picks a moment on a
// recovery timeline rather than a specific runId; the resolved runId then flows through the existing
// restore/drill path unchanged.
//   found: a run at-or-before T exists in the retained ring.
//     runId/completedAt: the resolved run and the RFC-3339 instant it completed (the recovery point it
//     restores to). index is its monotonic run index (a join key / ordering hint for a console).
//   when NOT found (found:false): runId/completedAt are absent and reason says WHY honestly, either T
//     precedes every retained run ("no run completed at or before that time within the retained window")
//     or the downpipe has no successful run in the ring at all. retainedFrom/retainedTo, when present,
//     are the completedAt bounds of the SUCCESSFUL runs the ring currently holds, so the console can say
//     plainly "you can only restore to a point between <from> and <to>", the honest retained-window
//     statement (you cannot restore to a point older than the oldest run the ring still holds).
// It is a pure projection of the redaction-safe history ring: a run id + a timestamp + an index, never a
// key, value or selector.
export interface PointInTimeRun {
  downpipeId: string;
  found: boolean;
  runId?: string;
  completedAt?: string; // RFC-3339 UTC millis the resolved run completed (its recovery point)
  index?: number;
  reason?: string;
  retainedFrom?: string; // completedAt of the OLDEST retained successful run (the recovery-window floor)
  retainedTo?: string; // completedAt of the NEWEST retained successful run (the recovery-window ceiling)
  // G082: how many SUCCESSFUL runs were EXCLUDED from this resolution because their startedAt could not be
  // parsed (so they cannot be placed on the timeline). Present only when non-zero. It is the difference
  // between "no run covers that instant" (an honest empty window) and "no run covers that instant AND we
  // discarded N runs that might have" -- the second is an engine defect, not a recovery limit, and it was
  // reported nowhere. A count only; the corrupt value itself never rides.
  excludedCorruptRuns?: number;
}

