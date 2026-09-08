// THE INTEGRITY FAULT LEDGER: the isolate-local, bounded accumulator the FORMAT and CRYPTO layers record
// into at the exact fault site (support-pack gap audit, gaps G011, G056, G057, G087, G088, G012,
// G111).
//
// WHY: the seal / verify / restore core is a PURE computation. It has no DO stub, no env and no scheduler, so
// every fault it hits could only ever be THROWN. By the time the throw crosses the two async stream boundaries
// and reaches a catch that owns a DO stub, it has been coarsened to one of a handful of reasons:
//   - a read-side 403 / 429 / cold-storage miss on the RUNLOG or the root manifest persists as the literal
//     "RUNLOG absent" (G011): support tells the customer the object is gone while it is visibly in the bucket;
//   - ~15 distinct SPEC 8.3 verification stages (root signature, capsule unwrap, key commitment, canonical
//     counts, recipient set, format version, record hash, Merkle root, ...) collapse to "integrity check
//     failed" (G056), and each one sends the customer down a completely different path;
//   - the throw site NAMES the failing shard / record / segment and the declared-vs-recovered counts, and all
//     of it is discarded (G057), so a ONE-RECORD hash mismatch and a WHOLESALE truncation look identical;
//   - five untyped throws in the verify paths misclassify an INTEGRITY fault as AVAILABILITY (G087), so the
//     pack records a class that is not merely coarse but WRONG, and the 3-2-1 replica fallback engages against
//     a damaged signature object;
//   - a record with neither value nor stream is defaulted to ZERO BYTES, sealed, signed and reported green
//     (G088): months later the restore yields nothing and no record anywhere says the engine held empty
//     content at capture time;
//   - a key-provisioning fault (a truncated paste, the SIGNER and OPERATIONAL labels swapped, a recipient
//     identity that matches no capsule wrap) is indistinguishable from a destination fault or a genuine
//     tamper (G012);
//   - a streaming open aborts with a bare DOMException OperationError carrying no segment, no chunk index and
//     no leg (G111), so support cannot locate the offending object without re-running with instrumentation.
//
// WHAT: one bounded, module-level accumulator. The fault site calls a `note*` function (which never throws and
// never alters control flow: the throw it accompanies still happens, unchanged), and the run / restore path
// DRAINS the ledger at the end and posts it to the scheduler DO, exactly as sources/source-fault-ledger.ts
// does for the crawl. A clean run accumulates nothing and posts nothing.
//
// LEAF (binding): this module imports NOTHING. crypto/* and format/* both record into it, and admin/* drains
// it; a single import here would close a cycle between those layers (the same reason admin/diag-records.ts and
// cron/retention-record.ts are leaves). Anything that needs a digest computes it AT THE CALL SITE and passes
// the hex in.
//
// REDACTION (binding, NO-CUSTODY): every field is a CLOSED ENUM, a COUNT, a CLAMPED INT or a 12-hex one-way
// digest. The record id, the object key, the segment key, the bucket, the endpoint, the S3 XML, the exception
// message, the key bytes, the base64url/hex material and the offending character NEVER enter this ledger. A
// classifier here READS an error only to SELECT an enum member and RETURNS that member; the text is discarded
// inside the function. Fingerprints of PUBLIC key material are the one non-enum value permitted (the class the
// pack already carries under keys.*), and they are shape-gated on the way in.

// ---------------------------------------------------------------------------------------------------------
// G011: the destination READ fault behind an "absent/missing" verdict
// ---------------------------------------------------------------------------------------------------------

/**
 * FETCH_FAULT_CLASSES is the closed answer to "the object IS in my bucket, why does the pack say it is gone?".
 * The freshness / attestation / bundle reads catch the store's exception and return a bare "absent" string; the
 * real cause is one of these, and each has a different fix (re-enter the credential, widen the bucket policy,
 * back off, restore from the cold tier, chase the network).
 *
 * "other" is last on purpose: classifyFetchFault falls through to it, so a store error nobody has taught it
 * about is reported as unclassified rather than folded into a neighbouring class. admin/diag-records.ts
 * re-declares this set by hand (it is a leaf and cannot import), and that copy is the gate a posted row must
 * pass, so a member added here has to be added there in the same change or every row carrying it is dropped.
 */
export const FETCH_FAULT_CLASSES = [
  "not-found", // the store genuinely answered 404 / NoSuchKey: the object is not there
  "access-denied", // 403: a rotated credential, a narrowed bucket policy, an expired STS session
  "throttled", // 429 / SlowDown: the read was refused for rate, not for absence
  "cold-storage", // the object exists but is in a restore-required tier (Glacier / deep archive)
  "network", // a fetch that threw with no HTTP status: DNS, TLS, a reset
  "other", // reached, refused, and none of the above (kept last so an unknown fault is never mislabelled)
] as const;
/**
 * FetchFaultClass is the union over FETCH_FAULT_CLASSES. classifyFetchFault returns it, freshness.ts carries
 * it on its own result so a caller can report the read fault without touching the exception, and it is the
 * middle field of the "<site>|<class>|<statusClass>" key the drained fetchFaults map counts under.
 */
export type FetchFaultClass = (typeof FETCH_FAULT_CLASSES)[number];

/**
 * FETCH_STATUS_CLASSES is the coarse HTTP verdict beside the class. Deliberately a CLASS, never the status: it
 * separates "the store refused me" from "the store is broken" from "there was no HTTP exchange at all".
 *
 * "none" is the fall-through, so it also covers a status that is neither 4xx nor 5xx (a 3xx that threw): read
 * it as "no 4xx or 5xx was seen", not as proof that no HTTP exchange took place.
 */
export const FETCH_STATUS_CLASSES = ["4xx", "5xx", "none"] as const;
/**
 * FetchStatusClass is the union over FETCH_STATUS_CLASSES. It rides beside the fault class on the freshness
 * result and as the last field of the fetchFaults key, which is what lets support separate a store that
 * refused the read from one that was broken while the class stays the same.
 */
export type FetchStatusClass = (typeof FETCH_STATUS_CLASSES)[number];

/**
 * FETCH_SITES names WHICH read faulted, because the three answer different questions: the RUNLOG is the
 * anti-rollback chain, the root manifest is the run's signed head, and the recovery bundle is the offline
 * escape hatch. "The RUNLOG is unreadable" and "this run's root is unreadable" are different tickets.
 *
 * The site is not derived from the error, it is passed in by the catch that knows which read it wrapped, so a
 * new read site is only visible in the pack once its catch calls noteFetchFault with the right member.
 */
export const FETCH_SITES = ["runlog", "root-manifest", "recovery-bundle"] as const;
/**
 * FetchSite is the union over FETCH_SITES: noteFetchFault's first parameter, and the leading field of the
 * fetchFaults key. admin/support-sections-faults.ts imports the array to re-derive the whole
 * site|class|statusClass product and DROPS any drained key outside it, so the union is also the pack's gate.
 */
export type FetchSite = (typeof FETCH_SITES)[number];

/**
 * classifyFetchFault coarsens a STORE read exception into a closed {class, statusClass} pair. It reads the
 * message ONLY to select the enum members and RETURNS them: the message -- which routinely embeds the object
 * key, the endpoint host and a chunk of S3 XML -- never leaves this function and can never reach a record.
 *
 * The ordering is load-bearing: a cold-storage refusal is itself delivered as a 403 by several stores, so it
 * is tested BEFORE the generic access-denied arm, or a lifecycle transition would read as a credential fault
 * and send the customer to rotate keys that are perfectly fine.
 *
 * @param e - the thrown store error.
 * @returns the closed fault class and its HTTP status class.
 */
export function classifyFetchFault(e: unknown): { cls: FetchFaultClass; statusClass: FetchStatusClass } {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  const status = /status (\d{3})/.exec(m)?.[1];
  const statusClass: FetchStatusClass = status === undefined ? "none" : status.startsWith("5") ? "5xx" : status.startsWith("4") ? "4xx" : "none";
  // Cold storage FIRST: several stores deliver a restore-required object as a 403 with an InvalidObjectState
  // code, so testing access-denied first would misfile every lifecycle transition as a credential fault.
  if (/InvalidObjectState|storage class|GLACIER|DEEP_ARCHIVE|not.*restored|archived/i.test(m)) return { cls: "cold-storage", statusClass };
  if (/SlowDown|Throttl|TooManyRequests|RequestLimitExceeded|status 429/i.test(m)) return { cls: "throttled", statusClass };
  if (/AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|ExpiredToken|Unauthorized|Forbidden|status 40[13]/i.test(m)) return { cls: "access-denied", statusClass };
  if (/NoSuchKey|NoSuchBucket|is missing|not found|status 404/i.test(m)) return { cls: "not-found", statusClass };
  if (statusClass === "none" && /network|fetch failed|ECONNRESET|ECONNREFUSED|ENOTFOUND|DNS|socket|timeout|timed out|TLS|certificate/i.test(m)) {
    return { cls: "network", statusClass };
  }
  return { cls: "other", statusClass };
}

// ---------------------------------------------------------------------------------------------------------
// G056: WHICH SPEC 8.3 verification stage failed
// ---------------------------------------------------------------------------------------------------------

/**
 * VERIFY_FAIL_STAGES is the closed split of the single "integrity check failed" reason. Each member is a
 * DIFFERENT ticket: signer-rotated means re-pin the signer, capsule-unwrap means the wrong recipient identity
 * is held, format-version means an engine rollback, record-hash means the bytes at the destination changed.
 *
 * The stage is WHERE in the SPEC 8.3 chain the run stopped, so at most a handful are seen per run and the
 * drained failStages map is keyed by the member itself. admin/diag-records.ts re-declares the same list as
 * VERIFY_FAIL_STAGE_NAMES and test/validate-integrity-faults.ts asserts the two arrays are equal element for
 * element, so a new stage must be added in both places and in the same position or the pin fails.
 */
export const VERIFY_FAIL_STAGES = [
  "capsule-unwrap", // no master-capsule wrap matched the held recipient identity, or the wrap's DEM would not open
  "root-structure", // the root manifest is structurally wrong (a missing/mistyped required field)
  "format-version", // the archive's format major is one this engine does not read (an engine rollback under a newer archive)
  "shard-hash", // a manifest SHARD's declared hash does not match its bytes
  "freshness-signature", // the RUNLOG's own signature did not verify
  "freshness-index", // the RUNLOG index / prevRunId disagrees with the signed root, or the run is not present
  "freshness-chain", // the RUNLOG chain is anomalous (a duplicate index, a broken/forked prevRunId) or below the min-index pin
  "recovery-bundle", // the recovery bundle's root manifest or its signature is absent or malformed
] as const;
/**
 * VerifyFailStage is the union over VERIFY_FAIL_STAGES: noteFailStage's first parameter. "format-version" is
 * the one member that carries anything besides itself, the encountered format-major label, and only through
 * that function's shape gate.
 */
export type VerifyFailStage = (typeof VERIFY_FAIL_STAGES)[number];

/**
 * CLASSIFIED_BY records HOW a failure class was reached (G087): a TYPED throw is authoritative; a
 * KEYWORD-FALLBACK classification guessed from a message and is lower-confidence evidence. A pack showing
 * keyword-fallback classifications is telling support "do not fully trust the class you are reading".
 *
 * It is tallied in its own map rather than against the stage, so the pack can report how much of a run's
 * evidence was guessed without joining the two, at the cost of not saying WHICH stage was the guess.
 */
export const CLASSIFIED_BY_KINDS = ["typed", "keyword-fallback"] as const;
/**
 * ClassifiedByKind is the union over CLASSIFIED_BY_KINDS: noteFailStage's second parameter, which defaults to
 * "typed" because a site that names its own stage knows it rather than inferring it.
 */
export type ClassifiedByKind = (typeof CLASSIFIED_BY_KINDS)[number];

// ---------------------------------------------------------------------------------------------------------
// G057: WHERE it failed (the locator), and G088 (the silent zero-byte seal)
// ---------------------------------------------------------------------------------------------------------

/**
 * INTEGRITY_FAULT_KINDS is the closed structural mode behind a locator row. Where a fail stage says WHICH
 * check stopped the run, the kind says WHAT was structurally wrong with the item that failed it, so a row is
 * readable on its own: a chunk range outside its segment and an inflate running past the declared size are
 * both "integrity check failed" without it.
 *
 * admin/diag-records.ts re-declares the same list as INTEGRITY_FAULT_KIND_NAMES and
 * test/validate-integrity-faults.ts pins the two arrays element for element.
 */
export const INTEGRITY_FAULT_KINDS = [
  "absent", // the shard / segment the root commits to is not there
  "chunk-range", // a requested chunk range lies outside the segment
  "decompress-overflow", // an inflate ran past the declared plaintext size (a zip-bomb guard, or a corrupt member)
  "malformed-object-key", // a hex-encoded object key would not decode (the silent hexDecode hole)
  "defaulted-empty-record", // G088: a record arrived with NEITHER a value NOR a stream and was sealed as ZERO BYTES
  // G089: the SEAL CHECKPOINT (the Merkle frontier) deserialised CORRUPT on resume, so a huge multi-invocation
  // run dies on every resume attempt. The existing sealFaults ring carries checkpoint-unwrap-failed (a SIGNER
  // rotation stranding the checkpoint), which is a different fault: this is DESERIALISE-time corruption of the
  // state itself. The run's failure is coarse, the corrupt DO state is transient, and support could not see
  // remotely that the CHECKPOINT (not the source and not the destination) was killing the run. declaredCount /
  // recoveredCount carry the count-vs-covered-leaves drift (so a one-leaf slip is distinguishable from
  // wholesale corruption) and shardOrdinal carries the frontier stack depth. Never the serialised blob.
  "checkpoint-corrupt",
] as const;
/**
 * IntegrityFaultKind is the union over INTEGRITY_FAULT_KINDS and the ONE required field of IntegrityLocator:
 * every other field on a locator row is optional, because how much a fault site can say about the item varies
 * (a malformed object key has no counts to report, a count shortfall has no useful digest).
 */
export type IntegrityFaultKind = (typeof INTEGRITY_FAULT_KINDS)[number];

/**
 * IntegrityLocator is the redaction-safe answer to "WHICH one failed, and how much is gone?". Every field is
 * an int or a closed enum, except `digest`, which is a 12-hex one-way prefix of the failing record id or
 * segment key -- the same discipline as runs[].causeDigest, and joinable to the customer's OWN bucket listing
 * (they can hash their keys and match), while carrying nothing back to us.
 */
export interface IntegrityLocator {
  readonly kind: IntegrityFaultKind;
  readonly shardOrdinal?: number; // which shard of the manifest (int)
  readonly declaredCount?: number; // what the signed root declares
  readonly recoveredCount?: number; // what the reader actually recovered
  readonly digest?: string; // 12 lower-case hex: a one-way digest of the failing record id / object key
}

/**
 * The locator ring ceiling. A restore that fails 100,000 records must not grow this: the first few rows tell
 * support everything (one record vs wholesale), and the counts carry the magnitude.
 *
 * noteLocator keeps the FIRST rows and drops everything after the cap, not the other way round, so the rows
 * that survive are the ones nearest the start of the failure. The magnitude is not lost with them:
 * defaultedEmptyRecords keeps counting past the cap even when its locator row is dropped.
 */
export const INTEGRITY_LOCATORS_CAP = 16;
// The digest shape gate: engine-computed hex only. Anything else did not come from a digest and is dropped.
const DIGEST_RE = /^[0-9a-f]{12}$/;

// ---------------------------------------------------------------------------------------------------------
// G012: key and recipient PROVISIONING faults
// ---------------------------------------------------------------------------------------------------------

/**
 * CRYPTO_FAULT_CLASSES names WHAT is wrong with the key material. Never the material.
 *
 * These are PROVISIONING faults, raised from the crypto layer (key parsing, signature verification, capsule
 * unwrap and the X25519 exchange), and the split that matters to the customer is between a key that is wrong
 * for the job and a signature that genuinely does not verify: recipient-no-capsule-match says the operator
 * holds the wrong identity, verify-mismatch says the bytes and the pinned key disagree. admin/diag-records.ts
 * re-declares the list as CRYPTO_FAULT_CLASS_NAMES, pinned element for element by
 * test/validate-integrity-faults.ts.
 */
export const CRYPTO_FAULT_CLASSES = [
  "key-wrong-label", // the key file's label does not match the role it was loaded for (SIGNER and OPERATIONAL swapped)
  "key-malformed-b64url", // the base64url payload would not decode (a bad character, a non-canonical trailing bit group)
  "recipient-no-capsule-match", // the held recipient identity matches NO master-capsule wrap in this archive: the WRONG identity is held (not a tamper)
  "recipient-noncontributory", // the X25519 exchange produced an all-zero shared secret (a non-contributory point: a corrupt or hostile recipient key)
  "verify-structural-fault", // a signature verification threw on MALFORMED input rather than returning a clean false
  "verify-mismatch", // the signature is well-formed and does not verify under the held key
] as const;
/**
 * CryptoFaultClass is the union over CRYPTO_FAULT_CLASSES: the cls field of a CryptoFault row, which is the
 * half that says what went wrong. It is always paired with a role, because the same class means a different
 * remedy depending on which key it was (a malformed signer file and a malformed recipient file are not the
 * same ticket).
 */
export type CryptoFaultClass = (typeof CRYPTO_FAULT_CLASSES)[number];

/**
 * CRYPTO_KEY_ROLES names WHICH key. A closed product vocabulary: these are the engine's own role names, which
 * is precisely the thing the pack could never say ("your backups fail" -> "your OPERATIONAL key is truncated").
 *
 * The role is what the key was loaded AS, not what it turned out to be, which is what makes the swapped-label
 * fault legible: crypto/keys.ts maps a key file's label to a member and files the fault under the role the
 * caller asked for. Pinned to admin/diag-records.ts CRYPTO_KEY_ROLE_NAMES by test/validate-integrity-faults.ts.
 */
export const CRYPTO_KEY_ROLES = ["signer", "operational", "break-glass", "recipient", "verifier"] as const;
/**
 * CryptoKeyRole is the union over CRYPTO_KEY_ROLES: the role field of a CryptoFault, and the return type of
 * the label-to-role mapping in crypto/keys.ts, so a role reaching the ledger is one this list already names.
 */
export type CryptoKeyRole = (typeof CRYPTO_KEY_ROLES)[number];

// The fingerprint shape gate. Fingerprints are of PUBLIC material only (the class the pack already carries in
// keys.*): the engine's own `dpr1:<96 hex>` recipient fingerprint, or a bare hex digest. A value outside that
// shape did not come from the engine's own digest function and is DROPPED rather than stored, so no exception
// message, key body or customer value can ever ride in this field.
const FINGERPRINT_RE = /^(?:dpr1:)?[0-9a-f]{8,96}$/;

/** One key/recipient provisioning fault. Closed class + closed role + optional PUBLIC-material fingerprints. */
export interface CryptoFault {
  readonly cls: CryptoFaultClass;
  readonly role: CryptoKeyRole;
  readonly heldFingerprint?: string; // recipient-no-capsule-match: the fingerprint of the identity the operator HOLDS
  readonly wantFingerprint?: string; // recipient-no-capsule-match: the fingerprint the ARCHIVE's wraps were made for
  readonly lengthClass?: number; // key-wrong-length: the byte length actually seen (an integer, never the bytes)
}
/**
 * The ceiling on the cryptoFaults ring. noteCryptoFault keeps the first rows of a run and drops the rest: a
 * provisioning fault is a property of the KEY, so it repeats identically for every record or signature the
 * run touches, and the rows after the first few restate one fact while the body posted to the DO grows.
 */
export const CRYPTO_FAULTS_CAP = 16;

// ---------------------------------------------------------------------------------------------------------
// G111: the STREAMING failure locus
// ---------------------------------------------------------------------------------------------------------

/**
 * STREAM_LEGS names which side of the pipe stopped. It is the first question of every large-object ticket
 * ("is my SOURCE flaky or is my DESTINATION flaky?") and today the answer is nowhere.
 *
 * decrypt-open is the leg BETWEEN the two: the sealed bytes arrived and would not open, which is neither
 * endpoint misbehaving and is the leg every crypto-side abort files under.
 */
export const STREAM_LEGS = ["source-read", "dest-write", "decrypt-open"] as const;
/**
 * StreamLeg is the union over STREAM_LEGS: the leg field of a StreamFault, and the value the support pack
 * gates each drained row on, so a row whose leg is outside this list never reaches a rendered section.
 */
export type StreamLeg = (typeof STREAM_LEGS)[number];

/**
 * STREAM_FAULT_CLASSES is the closed structural mode of a streaming abort.
 *
 * The point of the list is that the opener CAN tell these apart before the AEAD does: a truncated object, a
 * header too short to hold a nonce and a length prefix past the format's ceiling are all recognisable from
 * the framing, and only gcm-auth-fail means the bytes themselves changed. Without the split they arrive as
 * one bare OperationError. Pinned to admin/diag-records.ts STREAM_FAULT_CLASS_NAMES by
 * test/validate-integrity-faults.ts.
 */
export const STREAM_FAULT_CLASSES = [
  "short-nonce", // the segment header did not carry a full nonce: the object is truncated at byte ~0 (a zero-byte / partial write)
  "no-chunks", // the sealed object declares no chunks at all
  "short-chunk", // a chunk's declared length runs past the bytes actually present: a TRUNCATED object
  "over-limit-chunks", // more chunks than the format permits (a corrupt or hostile length prefix)
  "gcm-auth-fail", // the AEAD tag did not authenticate: THE bytes changed under us (the bare OperationError today)
  "container-framing", // the container preamble/segment framing is malformed
  "master-length-mismatch", // the recovered master key is not 32 bytes (a corrupt capsule that nonetheless opened)
] as const;
/**
 * StreamFaultClass is the union over STREAM_FAULT_CLASSES: the cls field of a StreamFault. The ordinals and
 * byte counts beside it are what make a member actionable, so a fault site fills in whichever of them it
 * knows (a short chunk knows its index and both lengths; a framing fault often knows only the length seen).
 */
export type StreamFaultClass = (typeof STREAM_FAULT_CLASSES)[number];

/** One streaming-failure locus. Ordinals and byte counts are bare ints; NEVER the object key or any bytes. */
export interface StreamFault {
  readonly leg: StreamLeg;
  readonly cls: StreamFaultClass;
  readonly segmentOrdinal?: number;
  readonly chunkIndex?: number;
  readonly receivedBytes?: number;
  readonly expectedBytes?: number;
}
/**
 * The ceiling on the streamFaults ring, with the same keep-the-first-rows rule as the other two. Each open
 * files at most one row and then throws, so the rows accumulate one per failing record or segment: a restore
 * walking a wholesale-damaged archive would otherwise post one for every object it touched.
 */
export const STREAM_FAULTS_CAP = 16;

// ---------------------------------------------------------------------------------------------------------
// G102: the ANTI-ROLLBACK / RUNLOG anomaly, with forensic evidence
//
// The engine detects a possible ROLLBACK ATTACK (rollbackDetected) or a corrupt RUNLOG and records NOTHING
// about it: the reason string it builds interpolates the customer's run and downpipe ids, so it can never be
// carried, and everything ELSE the detector knows -- WHICH anomaly, the two DISAGREEING indices, which LINE
// of the document was unparseable, how many entries the chain held -- was thrown away at the fault site. A
// tamper-vs-corruption investigation (the highest-stakes ticket the product has: "was our backup history
// rewritten, or did the destination flip a bit?") therefore starts with nothing at all, and the RUNLOG
// snapshot that proves the anomaly lives only in the customer's own bucket.
//
// This is the forensic row. Every field is an int or a closed enum, plus ONE 12-hex one-way digest of the
// RUNLOG BYTES: the customer can hash their own _RECOVERY/RUNLOG object and compare the prefix to prove the
// document support is reasoning about is the document they hold (or that it has since changed underneath
// them). The digest carries nothing back to us and no RUNLOG line content ever rides.
// ---------------------------------------------------------------------------------------------------------

/**
 * RUNLOG_ANOMALY_KINDS is the closed set of ways the anti-rollback chain can be wrong, and it is the field
 * the tamper-vs-corruption question turns on: a rewritten or forked chain and a replayed document point at an
 * ATTACK, while an unparsable line or a signature that will not verify over the bytes point at a damaged
 * object. The detector in freshness.ts raises them at verify time and writer-runlog.ts raises parse-field when
 * it reads the log to append.
 *
 * noteRunlogAnomaly re-gates the kind against this list and DROPS an unrecognised one rather than widening the
 * vocabulary, so the set is a boundary and not just a type. Pinned to admin/diag-records.ts
 * RUNLOG_ANOMALY_KIND_NAMES by test/validate-format-root-evidence.ts.
 */
export const RUNLOG_ANOMALY_KINDS = [
  "duplicate-index", // two entries carry the same account-global index: the counter never reissues one, so the log was rewritten
  "forked-prev", // two entries share a prevRunId: the chain FORKED (two histories claim the same parent)
  "dangling-prev", // an entry's prevRunId resolves to no entry at all: a predecessor was DELETED from the middle of the chain
  "chain-break", // a downpipe's prevRunId linearity broke (an entry does not chain to the prior retained entry)
  "index-regression", // the account-global RUNLOG max fell BELOW the out-of-band min-index pin: a whole-document replay of an older, validly-signed log
  "parse-field", // a RUNLOG line failed the shape / canonical-number gate: the document is corrupt (a destination-side bit-flip is the classic)
  "sig-invalid", // the RUNLOG's own detached signature did not verify over its bytes
  "runlog-absent", // the RUNLOG or its signature could not be read at all: DELETING the document is the quietest attack on the chain, so its absence is itself the row
  "run-missing", // the RUNLOG verified and parsed, but the run being checked is not in it: its entry was removed
  "root-disagreement", // the RUNLOG's entry for the run does not bind to the signed root (the index pair rides when the disagreement is on the index)
] as const;
/**
 * RunlogAnomalyKind is the union over RUNLOG_ANOMALY_KINDS: the kind field of a RunlogAnomaly row. The chain
 * detector in freshness.ts types its OWN anomaly rows with it as well, so the vocabulary the detector can
 * produce and the vocabulary the ledger will accept are the same list rather than two lists that agree today.
 */
export type RunlogAnomalyKind = (typeof RUNLOG_ANOMALY_KINDS)[number];

/**
 * One RUNLOG anomaly. indexA / indexB are the DISAGREEING pair the detector compared (the duplicated index,
 * the two entries' indices either side of a fork, the observed max vs the pin); lineOrdinal is which line of
 * the document failed to parse; entryCount is how long the chain was; digest is a 12-hex one-way prefix of a
 * SHA-384 over the RUNLOG BYTES. Never a run id, a downpipe id or one byte of line content.
 */
export interface RunlogAnomaly {
  readonly kind: RunlogAnomalyKind;
  readonly indexA?: number;
  readonly indexB?: number;
  readonly lineOrdinal?: number;
  readonly entryCount?: number;
  readonly digest?: string; // 12 lower-case hex over the RUNLOG bytes, computed at the call site
}
/**
 * The ceiling on the runlogAnomalies ring, half the others because an anomaly is a property of the DOCUMENT
 * rather than of a record: one RUNLOG yields a handful of rows at most, and each row's entryCount already
 * says how long the chain was, so the count of rows is not the measure of the damage.
 */
export const RUNLOG_ANOMALIES_CAP = 8;

// ---------------------------------------------------------------------------------------------------------
// G166: the WRITER's loud refusals, coarsened to a generic "run failed"
//
// The archive writer refuses three things by design, and each refusal is SELF-DESCRIBING at the throw site and
// then collapses into the run row's generic failure by the time it crosses the stream boundaries. The first is
// a CUSTOMER FAULT support cannot even name today: an emptied KV namespace or a de-scoped API token makes the
// source enumerate NOTHING, so every run dies on "buildArchive requires at least one record" and the customer
// is told, in effect, that the engine broke. The other two are ENGINE WIRING invariants (a streamed record
// with no destination, a secret handed in as a stream), and telling those two apart from the first is the
// whole diagnosis.
// ---------------------------------------------------------------------------------------------------------

/**
 * WRITER_REFUSAL_KINDS is the closed set of refusals format/writer.ts raises before it will seal anything, and
 * the split that matters is between the first member and the other two: source-enumerated-zero is a CUSTOMER
 * fault, while the stream-wiring members are engine invariants. Getting that wrong sends support down the
 * opposite path, because the coarse run row looks the same either way.
 *
 * These are counted rather than ringed (the kind IS the whole record, so a repeat adds a number and nothing
 * else). Pinned to admin/diag-records.ts WRITER_REFUSAL_KIND_NAMES by test/validate-format-root-evidence.ts.
 */
export const WRITER_REFUSAL_KINDS = [
  "source-enumerated-zero", // the run reached the writer with ZERO records: the SOURCE produced nothing (an emptied namespace, a de-scoped token), not an engine fault
  "stream-no-destination", // a record carries a stream but no destination was wired: the run fails only for values above the streaming threshold
  "secrets-streamed", // a secrets record arrived as a stream: secrets are sealed whole, so this is an engine wiring invariant
] as const;
/**
 * WriterRefusalKind is the union over WRITER_REFUSAL_KINDS: noteWriterRefusal's only parameter, re-gated
 * against the set on the way in, and the key the drained writerRefusals map counts under. The record NAME the
 * throw site interpolates into its message deliberately has no field here, so nothing else can ride along.
 */
export type WriterRefusalKind = (typeof WRITER_REFUSAL_KINDS)[number];

// ---------------------------------------------------------------------------------------------------------
// G320: the DEGRADED attestation coverage mode behind an unqualified complete:true
//
// A very large run is attested against a SAMPLE of shards (the subrequest cap), which is sound because the
// root signature already pins every shard's digest. The presence pass (RL-VAS-05, one LIST cross-referenced
// against the signed shard list) is what stops a durably MISSING shard outside the sample from reading as
// complete. When the store cannot LIST, that pass is SILENTLY SKIPPED and the verdict still says complete --
// an overclaim nobody can see afterwards. The coverage mode is the qualifier that makes complete:true honest.
// ---------------------------------------------------------------------------------------------------------

/**
 * KEYLESS_COVERAGE_MODES is the closed qualifier on an attestation's complete:true, ordered from the strongest
 * claim to the weakest. keyless.ts decides which one its completeness pass actually achieved and hands it to
 * noteAttestCoverage, which records only the DEGRADED modes, so a fleet reading back every shard stays silent.
 *
 * The ordering carries meaning in one place: the weakest mode a run reaches WINS in the ledger, because a
 * later undegraded attestation in the same warm isolate must not overwrite the fact that an earlier one could
 * not check presence. Pinned to admin/diag-records.ts KEYLESS_COVERAGE_NAMES by
 * test/validate-format-root-evidence.ts, which is why "full" is re-declared there despite never being posted.
 */
export const KEYLESS_COVERAGE_MODES = [
  "full", // every shard the signed root lists was read back and hashed (the offline CLI + drill path)
  "sampled", // a strided GET sample, WITH the per-shard presence pass: a missing shard is still caught
  "sampled-no-presence", // a strided GET sample and NO presence pass (the store cannot LIST): complete:true is a WEAKER claim
] as const;
/**
 * KeylessCoverageMode is the union over KEYLESS_COVERAGE_MODES. keyless.ts both returns it beside the
 * attestation verdict, so a caller reading complete:true can see how strong that claim is, and passes it to
 * noteAttestCoverage. It is the one piece of ledger evidence that rides a run reporting a CLEAN result.
 */
export type KeylessCoverageMode = (typeof KEYLESS_COVERAGE_MODES)[number];

// ---------------------------------------------------------------------------------------------------------
// the ledger itself
// ---------------------------------------------------------------------------------------------------------

/** The drained snapshot: bounded in every dimension, and the exact body posted to the DO. */
export interface IntegrityFaultSnapshot {
  fetchFaults: Record<string, number>; // "<site>|<class>|<statusClass>" -> count
  failStages: Record<string, number>; // closed VerifyFailStage -> count
  classifiedBy: Record<string, number>; // closed ClassifiedByKind -> count
  locators: IntegrityLocator[]; // capped
  cryptoFaults: CryptoFault[]; // capped
  streamFaults: StreamFault[]; // capped
  defaultedEmptyRecords: number; // G088: how many records were sealed as zero bytes because they arrived empty
  formatVersionSeen: string; // format-version only: the encountered MAJOR label from the fixed product vocabulary ("downpipe/2.x"), never a manifest value
  runlogAnomalies: RunlogAnomaly[]; // G102: capped forensic rows behind a rollbackDetected / corrupt RUNLOG
  writerRefusals: Record<string, number>; // G166: closed WriterRefusalKind -> count
  attestCoverage: string; // G320: the DEGRADED coverage mode of the last attestation ("" when full / undegraded)
}

const COUNT_CAP = 1_000_000;
// The format-major label gate: a fixed product vocabulary shape ("downpipe/<major>.x"), never a manifest value.
const FORMAT_LABEL_RE = /^downpipe\/\d{1,3}\.x$/;

// The closed sets, as sets, for the note-side gates: a note function must never widen the vocabulary either.
const RUNLOG_ANOMALY_KIND_SET: ReadonlySet<string> = new Set(RUNLOG_ANOMALY_KINDS);
const WRITER_REFUSAL_KIND_SET: ReadonlySet<string> = new Set(WRITER_REFUSAL_KINDS);
const KEYLESS_COVERAGE_MODE_SET: ReadonlySet<string> = new Set(KEYLESS_COVERAGE_MODES);

function emptyLedger(): IntegrityFaultSnapshot {
  return {
    fetchFaults: {},
    failStages: {},
    classifiedBy: {},
    locators: [],
    cryptoFaults: [],
    streamFaults: [],
    defaultedEmptyRecords: 0,
    formatVersionSeen: "",
    runlogAnomalies: [],
    writerRefusals: {},
    attestCoverage: "",
  };
}

// The ISOLATE-LOCAL accumulator. A Workers isolate is warm and serves many runs, so the run path RESETS this
// before a crawl / restore and DRAINS it after, exactly as source-fault-ledger.ts does: a fault carried into
// the next run would be MIS-ATTRIBUTED, which is worse than a missing one.
let ledger: IntegrityFaultSnapshot = emptyLedger();

function bump(map: Record<string, number>, key: string): void {
  map[key] = Math.min(COUNT_CAP, (map[key] ?? 0) + 1);
}

/**
 * noteFetchFault records a destination READ fault behind an absent/missing verdict (G011). Never throws: the
 * caller's own return / throw is unchanged.
 *
 * @param site - which read faulted (closed).
 * @param e - the thrown store error; it is classified here and DISCARDED (never stored).
 */
export function noteFetchFault(site: FetchSite, e: unknown): void {
  try {
    const { cls, statusClass } = classifyFetchFault(e);
    bump(ledger.fetchFaults, `${site}|${cls}|${statusClass}`);
  } catch {
    /* an observation must never break the path it observed */
  }
}

/**
 * noteFailStage records WHICH SPEC 8.3 verification stage failed (G056) and whether the class was reached from
 * a TYPED throw or a keyword guess (G087).
 *
 * @param stage - the closed stage.
 * @param by - how the class was reached (defaults to typed: a site that calls this KNOWS its stage).
 * @param formatMajorLabel - format-version only: the encountered major label ("downpipe/2.x"); shape-gated.
 */
export function noteFailStage(stage: VerifyFailStage, by: ClassifiedByKind = "typed", formatMajorLabel?: string): void {
  try {
    bump(ledger.failStages, stage);
    bump(ledger.classifiedBy, by);
    if (stage === "format-version" && typeof formatMajorLabel === "string" && FORMAT_LABEL_RE.test(formatMajorLabel)) {
      ledger.formatVersionSeen = formatMajorLabel;
    }
  } catch {
    /* best-effort */
  }
}

/**
 * noteLocator records WHICH item failed and by how much (G057). The digest MUST already be a 12-hex one-way
 * prefix computed at the call site (this module is a leaf and cannot hash); anything else is dropped, so a raw
 * record id or object key structurally cannot ride here.
 *
 * @param loc - the locator row.
 */
export function noteLocator(loc: IntegrityLocator): void {
  try {
    if (ledger.locators.length >= INTEGRITY_LOCATORS_CAP) return;
    const digest = typeof loc.digest === "string" && DIGEST_RE.test(loc.digest) ? loc.digest : undefined;
    ledger.locators.push({
      kind: loc.kind,
      ...(clampInt(loc.shardOrdinal) !== undefined ? { shardOrdinal: clampInt(loc.shardOrdinal)! } : {}),
      ...(clampInt(loc.declaredCount) !== undefined ? { declaredCount: clampInt(loc.declaredCount)! } : {}),
      ...(clampInt(loc.recoveredCount) !== undefined ? { recoveredCount: clampInt(loc.recoveredCount)! } : {}),
      ...(digest !== undefined ? { digest } : {}),
    });
  } catch {
    /* best-effort */
  }
}

/**
 * noteDefaultedEmptyRecord counts ONE record the writer defaulted to zero bytes because it arrived with
 * neither a value nor a stream (G088), and files a locator carrying only a one-way digest of its name.
 *
 * @param digest - a 12-hex one-way digest of the record name, computed at the call site (optional).
 */
export function noteDefaultedEmptyRecord(digest?: string): void {
  try {
    ledger.defaultedEmptyRecords = Math.min(COUNT_CAP, ledger.defaultedEmptyRecords + 1);
    noteLocator({ kind: "defaulted-empty-record", ...(digest !== undefined ? { digest } : {}) });
  } catch {
    /* best-effort */
  }
}

/**
 * noteCryptoFault records a key / recipient PROVISIONING fault (G012). Fingerprints are of PUBLIC material
 * only and are shape-gated; the key bytes, the base64url/hex text and the offending character never ride.
 *
 * @param f - the fault (closed class + closed role, plus optional public fingerprints / a byte length).
 */
export function noteCryptoFault(f: CryptoFault): void {
  try {
    if (ledger.cryptoFaults.length >= CRYPTO_FAULTS_CAP) return;
    const held = typeof f.heldFingerprint === "string" && FINGERPRINT_RE.test(f.heldFingerprint) ? f.heldFingerprint : undefined;
    const want = typeof f.wantFingerprint === "string" && FINGERPRINT_RE.test(f.wantFingerprint) ? f.wantFingerprint : undefined;
    ledger.cryptoFaults.push({
      cls: f.cls,
      role: f.role,
      ...(held !== undefined ? { heldFingerprint: held } : {}),
      ...(want !== undefined ? { wantFingerprint: want } : {}),
      ...(clampInt(f.lengthClass) !== undefined ? { lengthClass: clampInt(f.lengthClass)! } : {}),
    });
  } catch {
    /* best-effort */
  }
}

/**
 * noteStreamFault records the LOCUS of a streaming abort (G111): which leg, which structural mode, which
 * segment / chunk, and how truncated it was.
 *
 * @param f - the fault row.
 */
export function noteStreamFault(f: StreamFault): void {
  try {
    if (ledger.streamFaults.length >= STREAM_FAULTS_CAP) return;
    ledger.streamFaults.push({
      leg: f.leg,
      cls: f.cls,
      ...(clampInt(f.segmentOrdinal) !== undefined ? { segmentOrdinal: clampInt(f.segmentOrdinal)! } : {}),
      ...(clampInt(f.chunkIndex) !== undefined ? { chunkIndex: clampInt(f.chunkIndex)! } : {}),
      ...(clampInt(f.receivedBytes) !== undefined ? { receivedBytes: clampInt(f.receivedBytes)! } : {}),
      ...(clampInt(f.expectedBytes) !== undefined ? { expectedBytes: clampInt(f.expectedBytes)! } : {}),
    });
  } catch {
    /* best-effort */
  }
}

/**
 * noteRunlogAnomaly records the FORENSICS of an anti-rollback / RUNLOG anomaly (G102): which anomaly, the two
 * disagreeing indices, the offending line ordinal, the chain length, and a 12-hex one-way digest of the RUNLOG
 * bytes (computed at the call site: this module is a leaf and cannot hash). The anomaly's own reason string
 * interpolates the customer's run and downpipe ids and is NEVER passed in; no RUNLOG line content can ride.
 *
 * Never throws: the caller's own return / throw is unchanged, so the anti-rollback refusal still happens.
 *
 * @param a - the anomaly row.
 */
export function noteRunlogAnomaly(a: RunlogAnomaly): void {
  try {
    if (ledger.runlogAnomalies.length >= RUNLOG_ANOMALIES_CAP) return;
    if (!RUNLOG_ANOMALY_KIND_SET.has(a.kind)) return; // out of vocabulary: DROP rather than widen it
    const digest = typeof a.digest === "string" && DIGEST_RE.test(a.digest) ? a.digest : undefined;
    ledger.runlogAnomalies.push({
      kind: a.kind,
      ...(clampInt(a.indexA) !== undefined ? { indexA: clampInt(a.indexA)! } : {}),
      ...(clampInt(a.indexB) !== undefined ? { indexB: clampInt(a.indexB)! } : {}),
      ...(clampInt(a.lineOrdinal) !== undefined ? { lineOrdinal: clampInt(a.lineOrdinal)! } : {}),
      ...(clampInt(a.entryCount) !== undefined ? { entryCount: clampInt(a.entryCount)! } : {}),
      ...(digest !== undefined ? { digest } : {}),
    });
  } catch {
    /* best-effort */
  }
}

/**
 * noteWriterRefusal counts ONE loud writer refusal (G166) that the run row would otherwise coarsen to a
 * generic failure: a source that enumerated zero records (a CUSTOMER fault), or one of the two stream-wiring
 * invariants (an ENGINE fault). The record NAME the throw site interpolates never rides: the kind is the whole
 * record.
 *
 * @param kind - the closed refusal kind.
 */
export function noteWriterRefusal(kind: WriterRefusalKind): void {
  try {
    if (!WRITER_REFUSAL_KIND_SET.has(kind)) return;
    bump(ledger.writerRefusals, kind);
  } catch {
    /* best-effort */
  }
}

/**
 * noteAttestCoverage records the attestation's coverage mode (G320) when it is DEGRADED -- i.e. anything other
 * than a full read-back. A "full" run notes nothing, so a healthy fleet stays silent; "sampled-no-presence" is
 * the one that matters, because it is the mode in which complete:true is an OVERCLAIM (no per-shard presence
 * pass ran, so a durably missing shard outside the sample would not have been seen).
 *
 * @param mode - the closed coverage mode.
 */
export function noteAttestCoverage(mode: KeylessCoverageMode): void {
  try {
    if (!KEYLESS_COVERAGE_MODE_SET.has(mode) || mode === "full") return;
    // The weaker claim WINS: one degraded shard-check in a run is the fact support needs, and a later full
    // attestation in the same isolate must not overwrite it.
    if (ledger.attestCoverage === "sampled-no-presence") return;
    ledger.attestCoverage = mode;
  } catch {
    /* best-effort */
  }
}

// clampInt is the one numeric gate: a non-finite, negative or absent value is DROPPED (undefined), and a real
// one is floored and capped. So no NaN, no Infinity and no unbounded integer can reach a record.
function clampInt(n: unknown): number | undefined {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return undefined;
  return Math.min(Number.MAX_SAFE_INTEGER, Math.floor(n));
}

/** resetIntegrityFaultLedger clears the accumulator. Called before a crawl / restore by the run path. */
export function resetIntegrityFaultLedger(): void {
  ledger = emptyLedger();
}

/** drainIntegrityFaultLedger returns the snapshot and clears the accumulator in one step. */
export function drainIntegrityFaultLedger(): IntegrityFaultSnapshot {
  const snap = ledger;
  ledger = emptyLedger();
  return snap;
}

/**
 * isEmptyIntegritySnapshot reports whether a drained snapshot carries nothing worth posting. A clean run must
 * cost no subrequest and leave no record: silence is the healthy steady state.
 *
 * @param s - the drained snapshot.
 * @returns true when there is nothing to report.
 */
export function isEmptyIntegritySnapshot(s: IntegrityFaultSnapshot): boolean {
  return (
    Object.keys(s.fetchFaults).length === 0 &&
    Object.keys(s.failStages).length === 0 &&
    s.locators.length === 0 &&
    s.cryptoFaults.length === 0 &&
    s.streamFaults.length === 0 &&
    s.defaultedEmptyRecords === 0 &&
    // G102 / G166 / G320: each is evidence in its own right and can be the ONLY thing a snapshot carries -- a
    // degraded attestation coverage mode in particular rides a run that otherwise reports a clean, complete
    // verdict, which is the entire point of recording it. Omitting them here would silently drop the post.
    s.runlogAnomalies.length === 0 &&
    Object.keys(s.writerRefusals).length === 0 &&
    s.attestCoverage === ""
  );
}
