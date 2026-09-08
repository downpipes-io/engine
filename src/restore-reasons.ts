// Shared failure-reason constants for the restore / verify / seal read paths. These strings are matched
// across producers (restore.ts, drill.ts, restore-verify.ts, verify-at-seal.ts, keyless.ts) and the 3-2-1
// replica-fallback consumer (router-sources.ts withRunDestFallback), so they live here to stop the coupling
// drifting silently: a grep or type pins every producer and the consumer to the same literal.

import { integrityCategoryOf, isIntegrityFailure } from "./format/integrity-error.ts";

// REASON_INTEGRITY is the classifier reason for a verification failure that is NOT availability: a bad
// signature, a key-commitment mismatch, a per-record or Merkle hash mismatch, a completeness shortfall
// (the reader's "recovered N records, the root declares M"), or a structural format violation. It is a
// TAMPER / corruption signal a healthy replica could NOT remedy (a replica holds the SAME signed run), so
// it is NEVER in the replica-fallback set: the operator must see it loud, not have it masked by a replica.
export const REASON_INTEGRITY = "integrity check failed";

// REASON_FRESHNESS is the classifier reason for the anti-rollback verifier firing on a check that RAN to a
// verdict: an internally anomalous chain, or a document below the out-of-band min-runlog-index pin. It is
// NEVER in the replica-fallback set. That is not because a replica holds the same document (it does not,
// see below) but because the verdict is a FINDING about the run: the log was rewritten, or the account's
// own high-water mark says history was rolled back. Walking to a second copy after a finding like that is
// how a rollback gets masked, so the walk stops here on every destination.
export const REASON_FRESHNESS = "freshness check failed";

// REASON_FRESHNESS_UNVERIFIABLE is the classifier reason for a freshness check that COULD NOT RUN against
// this destination: `_RECOVERY/RUNLOG` or its signature could not be read (gone, denied, throttled, moved
// to a cold tier, a transport fault), the signature did not verify, or the document does not carry this run
// in a form that binds to the signed root. It is FreshnessResult.checked being false, raised to a reason.
//
// IT IS IN THE REPLICA-FALLBACK SET, and it is the one member whose ground differs from the other three.
// The others are availability faults on the archive objects. This one is a fault in a DIFFERENT document
// that happens to live in the same bucket, and the reason a replica can remedy it is that the RUNLOG is not
// shared: appendRunlog's relinkLocalPrev writes each destination its own entry against that destination's
// own tail and signs that destination's own copy. So "a replica holds the same signed run", the sentence
// that correctly excludes every integrity failure, is simply not true of this document.
//
// The customer's position when this fires on the primary is the one three copies exist for: one copy is
// damaged and the others may be perfect. Refusing the whole restore protects them from unverified data,
// which is right, and it also denies them a restore from a replica that would verify end to end, which is
// not. The walk is what resolves that, and it resolves it without weakening anything: the destination the
// fault was found on still REFUSES, the replica is opened and verified in full from its own bytes (the op
// re-runs, inheriting nothing from the failed attempt), and a run that serves from anywhere other than the
// first choice says so in its result and inside its SIGNED receipt core. A fallback nobody is told about
// would be a different defect of the same family as an unverifiable check reporting no rollback.
export const REASON_FRESHNESS_UNVERIFIABLE = "freshness check could not run";

// REASON_FORMAT_UNSUPPORTED is the classifier reason for the format-version gate (structural-gates.ts
// checkFormatVersion) refusing a WELL-FORMED version label this build does not implement. It is the one
// non-availability reason where nothing about the archive is in question: the root signature verified before
// the gate ran, so the bytes are provably ours and intact, no check over any byte failed, and nothing was
// written. The only true statement is that the reader is a different build from the writer.
//
// IT EXISTS BECAUSE THE ALTERNATIVE WAS ACTIVELY HARMFUL. Every version refusal used to reach
// REASON_INTEGRITY, which the console renders as "the archive failed its integrity verification (possible
// corruption or tampering)". That is the sentence a customer read while holding intact bytes written by the
// engine our own update channel recommends, and it sends them hunting a corruption that is not there.
//
// IT IS NOT IN THE REPLICA-FALLBACK SET. A 3-2-1 replica holds the SAME signed run carrying the SAME
// formatVersion label, so a replica walk could only refuse again, exactly the ground that excludes every
// integrity failure. Terminal, then, but terminal for a reason the customer can act on.
export const REASON_FORMAT_UNSUPPORTED = "archive format version not supported by this engine build";

// REASON_OBJECT_MISSING is the classifier reason for an object that is absent from the bucket (a 404 or an
// "is missing" producer error). It is one of the AVAILABILITY reasons another bucket in the 3-2-1 set could
// remedy, so the replica fallback retries the next candidate on it (see isReplicaFallbackReason).
export const REASON_OBJECT_MISSING = "object missing";

// REASON_DESTINATION_ACCESS is the classifier reason for a destination read that reached the provider but
// was refused or faulted with an HTTP status: a 403 (revoked/rotated credentials, denied bucket), a 5xx
// (provider outage), a redirect, a 429. The PRIMARY being unreadable for one of these reasons is exactly the
// real-world 3-2-1 DR case, so it too triggers the replica fallback. The OBJECT itself may be perfectly
// intact on a healthy replica; this is an availability fault on this destination, not a corruption signal.
export const REASON_DESTINATION_ACCESS = "destination access error";

// REASON_ORIGIN_REMOVED (DEST-2) is the TERMINAL, actionable reason for a restore whose run was recorded to
// destination(s) that are NO LONGER CONFIGURED (an Owner force-removed the destination while it held the only
// copy, or a ring-evicted/deleted-downpipe run). The bytes may still physically exist in the (now
// unconfigured) bucket, but the engine holds no credential to address it, so every recorded candidate
// resolves to null and the read falls through to the generic "object missing". This names the real cause and
// points the operator at the fix: re-add a destination holding these bytes (or pass an explicit destination
// to re-point the restore at one). It is deliberately NOT in isReplicaFallbackReason: there is nothing left
// to fall back to (every recorded copy's destination is gone), so it is the final, honest answer.
export const REASON_ORIGIN_REMOVED = "this run's only copy was on a removed destination; re-add it (or a destination that holds these bytes) and retry, or re-point the restore with an explicit destination";

// REASON_RECOVERY_CHECK is the catch-all classifier reason a producer falls back to when a primary read
// failed but matched no more specific class: in practice a NETWORK / TRANSPORT fault reading the primary (a
// fetch that threw with no HTTP status, a connection reset, a DNS failure). That is an availability fault on
// THIS destination, so it also falls through to the next destination in the 3-2-1 chain rather than failing
// the whole restore. (Producers that classify a network fault as REASON_DESTINATION_ACCESS land on that
// availability reason instead; both are in the fallback set, so either classification falls back.)
export const REASON_RECOVERY_CHECK = "recovery check failed";

// DEST_REJECTION_RE pulls the sanitised S3 <Code> a destination WRITE failure carries in parentheses.
// s3WriteFailure (s3-worm.ts) builds the message "PUT seg/0001: status 400 (InvalidRequest: object lock
// write requires a checksum)": that detail is engine-built from a documented S3 error-code enum plus a fixed
// hint, so it is never secret and never customer data. A bare "status NNN" read error (the get/list path) has
// no parentheses and yields undefined.
//
// BUT THE EXTRACTION ITSELF CANNOT KNOW THAT. It runs over an arbitrary error MESSAGE, and this reason rides
// into the sealed bundle via sealVerification.reason and the run rows. Trusting the shape "status NNN (...)"
// to have been built by us is trusting the destination not to answer in a shape that looks like ours: a
// destination whose message happens to carry parentheses after a status would have its content pass through
// verbatim, into a pack the customer sends to the vendor.
//
// So the detail is now SHAPE-GATED, not merely extracted. Only an S3-error-code token survives: PascalCase
// letters and digits, bounded, optionally followed by the engine's own fixed hint after a colon. Anything
// else, which is to say anything a destination could put there, is DROPPED and the bare availability reason
// rides alone. That costs one word of operator detail in an exotic case and removes the passthrough entirely.
//
// This is the same lesson as updates.last.reason (see support-sections-runs.ts): a clamp is not a redaction,
// and neither is a regex that trusts its input to have been written by us.
const DEST_REJECTION_RE = /status \d+ \(([^)]+)\)/;
const S3_ERROR_CODE_SHAPE = /^[A-Z][A-Za-z0-9]{2,48}(: [ -~]{1,80})?$/;

// destRejectionDetail returns the parenthesised S3 <Code> detail from a write-failure message, or undefined
// when the message carries none, or none of the ENGINE'S OWN shape. It is the SINGLE source of truth for the
// extraction, shared by every destination-access classifier (slice.ts coarseRunError, verify-at-seal, keyless,
// restore-apply), so the pattern can never drift between them.
export function destRejectionDetail(m: string): string | undefined {
  const raw = DEST_REJECTION_RE.exec(m)?.[1];
  if (raw === undefined) return undefined;
  return S3_ERROR_CODE_SHAPE.test(raw) ? raw : undefined; // a destination-supplied detail is dropped, not carried
}

// destAccessReason maps a destination-access failure message to the availability reason, ENRICHED with the
// real S3 <Code> when the message carries one ("destination access error (AccessDenied)"), else the bare
// REASON_DESTINATION_ACCESS. The enriched form STILL classifies as a replica-fallback availability reason
// (isReplicaFallbackReason matches the "destination access error" base, with or without the parenthesised
// detail), so surfacing the actionable cause to the operator never suppresses the 3-2-1 replica fallback.
export function destAccessReason(m: string): string {
  const detail = destRejectionDetail(m);
  return detail === undefined ? REASON_DESTINATION_ACCESS : `${REASON_DESTINATION_ACCESS} (${detail})`;
}

// isReplicaFallbackReason decides whether a failed restore-class op against ONE destination should fall
// through to the next destination in the 3-2-1 chain. It returns true ONLY for AVAILABILITY faults that a
// healthy replica could remedy: the object is missing here (404), the destination refused/faulted with an
// HTTP status (403 revoked creds / 5xx outage / redirect / 429), or a network/transport fault reading here.
//
// It returns FALSE for everything else, and the exclusions are load-bearing for the integrity guarantee:
//   - "integrity check failed" (a bad signature, a hash mismatch, a Merkle-root or key-commitment failure)
//     is a TAMPER / corruption signal, NOT a missing object. Silently reading a replica would mask the very
//     corruption the operator must see, so it surfaces immediately and never falls back.
//   - "freshness check failed" is the anti-rollback verifier reaching a VERDICT; falling through after a
//     finding of that kind could mask a rollback.
//   - "engine not fully configured" and any unrecognised reason are not faults another bucket can fix.
// A record-scope miss ("record not found in run") is likewise not in the set: the record is genuinely not in
// this run, and a replica holds the same run, so retrying cannot help.
//
// It returns TRUE for one reason that is not an archive-object availability fault:
// REASON_FRESHNESS_UNVERIFIABLE, a freshness check that could not RUN here. See that constant for why the
// "a replica holds the same signed run" ground does not reach it (the RUNLOG is written and signed per
// destination) and for the two conditions that keep it honest: the destination it was found on still
// refuses, and a served fallback is never silent.
export function isReplicaFallbackReason(reason: string | undefined): boolean {
  if (reason === undefined) return false;
  // The destination-access reason may now carry a parenthesised S3 <Code> detail (destAccessReason); it is
  // still the same availability fault, so match the base with OR without the detail. Surfacing the real
  // cause to the operator must never change whether the 3-2-1 replica fallback fires.
  return (
    reason === REASON_OBJECT_MISSING ||
    reason === REASON_DESTINATION_ACCESS ||
    reason.startsWith(`${REASON_DESTINATION_ACCESS} (`) ||
    reason === REASON_RECOVERY_CHECK ||
    reason === REASON_FRESHNESS_UNVERIFIABLE
  );
}

// worseRestoreReason picks which of two per-record failure reasons a pass over MANY records should report
// when more than one record failed. It exists because a windowed pass (drill.ts measureWindow, the scheduled
// restore test) DRAINS every per-record failure so the cursor advances past a bad record, and then has to
// name ONE reason for the whole window.
//
// The rule is the reader's own precedence, and it is the one an integrity guarantee needs: a failure that
// genuinely FAILED A CHECK beats one that merely could not reach the bytes. Taking the first failure in
// cursor order instead is not a tie-break, it is a coin toss, because the cursor rotates every tick: the same
// damaged archive would report a tamper on one tick and a destination fault on the next.
//
// It is DERIVED from isReplicaFallbackReason rather than restating a severity list, so the two can never
// drift. That derivation is the whole point. A reason the replica walk refuses to fall back on is, by
// construction, a FINDING about the archive (a tamper, a completeness shortfall, a rollback verdict, a
// configuration fault a second bucket cannot fix); a reason it does fall back on is an availability fault on
// THIS destination. Letting an availability fault carry the window's verdict when a finding was also present
// would hand a replica-fallback-eligible reason to withRunDestFallback (router-sources.ts), which would then
// serve the run from a replica with the finding on this copy never reported. Adding a member to the fallback
// set therefore keeps this rule correct automatically, and removing one does too.
//
// Within a class the FIRST failure seen wins, which preserves the previous behaviour exactly whenever the
// window's failures are all of one class (the common case, and every case the drill tests covered before).
// REASON_FORMAT_UNSUPPORTED is the ONE explicit exception to the derivation, and it is stated rather than
// derived because it is the one reason that is TERMINAL WITHOUT BEING A FINDING. The derivation reads "not
// fallback-eligible" as "a finding about the archive", which holds for every other member: a tamper, a
// completeness shortfall, a rollback verdict, a configuration fault. A version refusal is not one. No check
// over any byte ran, let alone failed, and the root signature had already verified before the gate spoke.
//
// So it must never DISPLACE a reason that genuinely failed a check. Letting it win a window that also held a
// real tamper would report a wrong-build message over a damaged archive, which is the same class of harm
// this reason was minted to stop, pointing the other way. It still beats an availability fault, because it
// is terminal and a replica cannot clear it.
export function worseRestoreReason(current: string | null | undefined, candidate: string): string {
  if (current === null || current === undefined) return candidate;
  // A genuine finding outranks a version refusal in both directions. Checked before the general rule, which
  // would otherwise read both as the same non-fallback class and keep whichever was seen first.
  if (candidate === REASON_FORMAT_UNSUPPORTED && current !== REASON_FORMAT_UNSUPPORTED && !isReplicaFallbackReason(current)) return current;
  if (current === REASON_FORMAT_UNSUPPORTED && candidate !== REASON_FORMAT_UNSUPPORTED && !isReplicaFallbackReason(candidate)) return candidate;
  // A finding beats an availability fault. Same class, first-seen keeps the window.
  return isReplicaFallbackReason(current) && !isReplicaFallbackReason(candidate) ? candidate : current;
}

// RESTORE_TEST_REASON_CODES is the CLOSED short-code vocabulary the support pack carries for a scheduled
// restore-test FAILURE (support-pack mode scheduled-restore-fail-reason). The full reason strings above can
// carry an operator-actionable sentence or an S3 <Code> parenthetical; the pack carries only the coarse
// CODE (never the raw reason), so the diagnosis can tell a tamper (integrity/freshness) from an availability
// fault (dest-access/object-missing) from a config / removed-destination cause. Redaction-safe by design.
export const RESTORE_TEST_REASON_CODES = ["integrity", "freshness", "format-unsupported", "object-missing", "dest-access", "origin-removed", "not-configured", "recovery-check", "other"] as const;
export type RestoreTestReasonCode = (typeof RESTORE_TEST_REASON_CODES)[number];

// coarseRestoreTestReasonCode maps a runDrill failure reason (one of the REASON_* strings above, possibly
// the enriched destination-access form, or the "engine not fully configured" config error) to its closed
// short code. It keys on the SAME shared constants the producers use (not a fresh regex), so it cannot
// drift. An absent / unrecognised reason maps to "other"; the raw reason is NEVER propagated. Pure; no I/O.
export function coarseRestoreTestReasonCode(reason: string | undefined): RestoreTestReasonCode {
  if (reason === undefined || reason === "") return "other";
  if (reason === REASON_INTEGRITY) return "integrity";
  // Both freshness reasons coarsen to the SAME closed code deliberately. The pack's short-code vocabulary is
  // mirrored by the console's plain-words phrase table (console screens/sources-downpipes/helpers.ts
  // restoreTestReasonPhrase), whose default arm renders any code it does not know as "the recovery check
  // failed" -- so minting a code here would make the console describe a freshness refusal as a network
  // fault, which is a less true sentence than the one it prints now. The fine reason string keeps the split
  // for the operator; widening the closed code is a console change and belongs with the console.
  if (reason === REASON_FRESHNESS || reason === REASON_FRESHNESS_UNVERIFIABLE) return "freshness";
  // A version refusal MINTS a code rather than reusing one, which is the opposite call to the freshness pair
  // just above, and the difference is which way the console's default arm cuts. Splitting freshness would
  // have taken one of two cases from a truthful phrase to the generic one, so it lost. Here there is no
  // truthful phrase to lose: the only code that currently fits is "integrity", whose phrase accuses intact
  // bytes of corruption, and every other existing code is a lie of a different kind. Until the console adds
  // its case this renders through the same default arm as "recovery-check" does today, which does not accuse
  // the archive of anything, so minting is a strict improvement on every alternative and it makes the
  // support pack's auto-diagnosis able to tell a wrong-build refusal from a tamper. THE CONSOLE OWES a
  // phrase for this code in screens/sources-downpipes/helpers.ts restoreTestReasonPhrase.
  if (reason === REASON_FORMAT_UNSUPPORTED) return "format-unsupported";
  if (reason === REASON_OBJECT_MISSING) return "object-missing";
  if (reason === REASON_DESTINATION_ACCESS || reason.startsWith(`${REASON_DESTINATION_ACCESS} (`)) return "dest-access";
  if (reason === REASON_ORIGIN_REMOVED) return "origin-removed";
  if (reason === REASON_RECOVERY_CHECK) return "recovery-check";
  if (reason.includes("not fully configured") || reason.startsWith("missing required configuration")) return "not-configured";
  return "other";
}

// classifyRestoreFailure is the SINGLE robust classifier the restore/verify catch handlers use to map a
// caught reader failure onto a coarse, enumerated reason. It replaces a brittle keyword regex over the raw
// reader message that mis-routed several genuine integrity/completeness failures (e.g. the reader's
// "recovered N records, the root declares M" completeness error, a codec/preamble structural mismatch) into
// the catch-all REASON_RECOVERY_CHECK, which IS in the replica-fallback set, so a truncated / incomplete /
// corrupt archive could wrongly fall back to a replica instead of failing loud. The fix is to classify by
// the reader's STRUCTURED failure category, not by guessing from the message:
//
//   1. A structured reader integrity/freshness failure (RunIntegrityError, the typed signal the verifying
//      reader now raises for EVERY tamper / completeness / structural / signature / freshness failure) is
//      classified by its category, NEVER by its text. integrity -> REASON_INTEGRITY (non-fallback);
//      freshness -> REASON_FRESHNESS (non-fallback). This is the load-bearing change: ANY integrity failure
//      is non-fallback by construction, so a completeness/structural error can no longer slip to a replica.
//   2. As defence in depth (a future integrity throw that is not yet typed), the same integrity/freshness
//      keyword nets are kept BELOW the availability tests, so an untyped integrity message still lands on a
//      non-fallback reason rather than the availability catch-all.
//   3. Only TRUE availability faults reach the fallback reasons: an absent object (404 / "is missing") ->
//      REASON_OBJECT_MISSING; a reached-but-refused/faulted HTTP status (403 / 5xx / redirect / 429) ->
//      REASON_DESTINATION_ACCESS; a configuration error -> "engine not fully configured" (non-fallback).
//   4. Everything else (a network/transport fault with no HTTP status, an unrecognised message) falls to
//      REASON_RECOVERY_CHECK, the network/transport availability reason, which DOES fall back.
//
// The ordering matters: the structured-type check and the integrity keyword net run BEFORE any availability
// test, so an integrity failure can never be mis-read as availability even if its message happens to contain
// a substring like "status" or "missing".
export function classifyRestoreFailure(e: unknown): string {
  const cat = integrityCategoryOf(e);
  // The typed category is the ONLY route to the fallback-eligible freshness reason. The keyword net further
  // down deliberately does not have one: an untyped throw whose message merely mentions the RUNLOG lands on
  // the terminal REASON_FRESHNESS, so a future path that forgets to type itself fails closed on the strict
  // side rather than earning a replica walk by accident.
  if (cat === "freshness-unverifiable") return REASON_FRESHNESS_UNVERIFIABLE;
  if (cat === "freshness") return REASON_FRESHNESS;
  // The TYPED category is the only route to the version reason, for the same fail-closed ground as the
  // freshness split above: the keyword net below deliberately keeps "formatVersion" on the integrity side,
  // so an untyped throw that merely mentions the field lands on the strict answer rather than earning the
  // softer one by wording. Only checkFormatVersion's own well-formed-but-unimplemented branch is typed.
  if (cat === "format-unsupported") return REASON_FORMAT_UNSUPPORTED;
  if (cat === "integrity" || isIntegrityFailure(e)) return REASON_INTEGRITY;
  const m = (e as Error)?.message ?? "";
  // Defence in depth: an integrity/completeness/structural/signature failure that is (for any reason) not a
  // typed RunIntegrityError still classifies as integrity by message, NEVER as availability or the catch-all.
  if (/signature did not verify|key commitment|hash does not match|Merkle root|failed its plaintext hash|recovered \d+ records|the root declares|differs from the envelope codec|must not be compressed|preamble does not match|does not match the requested run|recipient|must be \d+ bytes|out of range|mixes a packed slice|terminates after|chunk range|canonical|formatVersion|must be an array|must be a string/.test(m)) {
    return REASON_INTEGRITY;
  }
  // The anti-rollback freshness verifier firing (by message), also non-fallback.
  if (/RUNLOG|freshness|latest run|stale|rolled back|chain/.test(m)) return REASON_FRESHNESS;
  // INT-3: a missing SEGMENT object (the bulk content-addressed data of an otherwise-present, signed run)
  // classifies as integrity, so it never falls through to a 3-2-1 replica. This net runs BEFORE the generic
  // is-missing/404 availability rule below so a `seg/` miss never lands on REASON_OBJECT_MISSING. (A missing
  // root.manifest.json or `run/<id>/manifest/...` shard stays REASON_OBJECT_MISSING and still falls through.)
  //
  // This is a deliberate divergence from treating an absent segment as a plain availability fault. A run
  // whose only issue is a missing segment could in principle fall back to a healthy replica, but this engine
  // aborts its verify and write passes at the FIRST failing record (restore-apply.ts, restore-plan.ts), so a
  // single classification here cannot yet distinguish "every failure was a missing segment" from "a missing
  // segment sits alongside a genuine tamper on another record". Until per-record failures are aggregated
  // across the whole run, classifying this as integrity is the safe choice: it costs a replica walk in the
  // pure-availability case but never risks serving a replica while a real tamper on this copy goes unseen.
  if (/object seg\/\S+ is missing/.test(m)) return REASON_INTEGRITY;
  // True availability faults: only these fall through to a 3-2-1 replica.
  if (/is missing|status 404/.test(m)) return REASON_OBJECT_MISSING;
  if (/status \d/.test(m)) return REASON_DESTINATION_ACCESS;
  if (/missing required configuration/.test(m)) return "engine not fully configured";
  // A network/transport fault with no HTTP status (a fetch that threw, a reset, a DNS failure) is the
  // catch-all availability reason that DOES fall back.
  return REASON_RECOVERY_CHECK;
}
