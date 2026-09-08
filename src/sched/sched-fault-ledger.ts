// The SCHEDULER-DO fault ledger: the small, best-effort, never-throwing recorders that promote the
// scheduler/identity faults that used to leave NO durable trace into closed-vocabulary, redaction-safe
// evidence the support pack can carry (support-pack gap audit, deferred round).
//
// It is a sibling of ./scheduler-do-diag.ts (the persist-state / housekeeping recorders) and of
// ../sources/source-fault-ledger.ts + ../dest/fault-log.ts, and it follows the same shape: classify the
// fault into a CLOSED vocabulary, clamp everything, write a bounded counter, and NEVER let the observation
// break the path it observed. It is written as FREE FUNCTIONS over the DO's storage rather than a mixin so
// any mixin can record without widening the SchedulerDOSurface interface, and so the pure classify/apply
// logic is unit-testable with no DO harness.
//
// It is the ENTRY POINT of a four-module family. Beside it sit ./sched-fault-core.ts (the shared substrate and
// the six founding ledgers), ./sched-fault-admin-ledger.ts (the four ADMIN-EDGE refusal ledgers) and
// ./sched-fault-client-ledger.ts (the browser's own evidence); this file keeps every remaining subject and the
// single readSchedDiag the pack projects. Each sibling carries WHOLE families, so a closed vocabulary and the
// recorder that gates on it are never in different modules: that pairing, not file length, is what the
// exemption on this leaf was written to protect, and the split is along the family seam the section banners
// already marked. Every symbol the siblings export is re-exported here, so every caller keeps importing from
// this one path.
//
// REDACTION (binding, no-custody): every field written here is a closed enum member, an integer count, a
// clamped timestamp, an OPAQUE server-minted error id, or the customer's own downpipe label (the same class
// the pack already carries in downpipes[] and sealFaults.downpipeId). A raw error message, a stack, a secret,
// a token, a challenge, a credential id, an email, an IP, an origin, an rpId, an endpoint, a bucket or a
// header NEVER rides. classifyReplicationReason READS a coarse error string ONLY to SELECT an enum member and
// returns that enum type (the classifyCoarseError / isWormRefusal idiom); the string itself is discarded.

import { CHAIN_BREAK_CAUSES, type ChainBreakCause } from "../admin/audit-types.ts";
import { WORM_UNKNOWN_REASONS, type WormUnknownReason } from "../dest/types.ts";
import { DELIVERY_FAIL_CODES, type DeliveryFailCode, sanitiseEmailPlatformCode } from "../notify/types.ts";

import {
  APPROVAL_FAULTS_KEY,
  CAP_TRUNCATION_SUBJECTS_KEY,
  type CapTruncationSubjects,
  CAP_TRUNCATIONS_KEY,
  CEREMONY_FAULTS_KEY,
  CHAIN_BREAKS_KEY,
  CONTRACT_FAULTS_KEY,
  DEFAULT_DEST_HEALTH_KEY,
  type DefaultDestHealth,
  DROPPED_WRITES_KEY,
  EXPIRY_OBSERVE_FAULTS_KEY,
  FAULT_COUNT_CAP,
  type FaultCountAgg,
  FRESHNESS_FAULTS_KEY,
  type FreshnessFaults,
  type LedgerStorage,
  RECENT_ERRORS_KEY,
  type RecentErrorEntry,
  RECOVERY_RESUME_KEY,
  ROSTER_DISCARDS_KEY,
  STORAGE_ANOMALIES_KEY,
  TEST_OUTCOMES_KEY,
  VOCAB_DROPS_KEY,
  bumpCount,
  flushDroppedWrites,
  safeLabel,
  stripLedgerControls,
  writeLedger,
} from "./sched-fault-core.ts";
import { ADMIN_REFUSALS_KEY, AUTHZ_REFUSALS_KEY, CONFIG_COERCIONS_KEY, CONFIG_REJECTIONS_KEY } from "./sched-fault-admin-ledger.ts";
import { CLIENT_DIAG_KEY, type ClientDiagnostics } from "./sched-fault-client-ledger.ts";

// The siblings are re-exported so every caller keeps importing this one path. The split moved whole families,
// never a vocabulary away from the recorder that gates on it, so the import surface is unchanged.
export * from "./sched-fault-core.ts";
export * from "./sched-fault-admin-ledger.ts";
export * from "./sched-fault-client-ledger.ts";

// ---- vocabDrops (G092): the closed-set gates that DROP an out-of-vocabulary observation ----------
//
// Every closed vocabulary in this engine is enforced with a silent drop (the redaction property: no caller
// string can ever become a storage key). That is correct, and it is also a BLIND SPOT: after a PARTIAL
// update, a NEWER component emits a value an OLDER reader's set does not hold, so the reader drops it and
// the pack's ring/counter stays EMPTY. Support then reads "no seal faults / no delivery codes / tested and
// failed" when the truth is "this engine cannot understand what its own other half is saying". Counting the
// DROP (never the unknown token, which is arbitrary drift content and could carry anything) turns component
// skew into a one-line read.
export const VOCAB_DROP_SURFACES = [
  "seal-fault", // a POST /seal-fault whose kind is outside SEAL_FAULT_KINDS: the pack's seal-fault ring stays empty while the seal DO faults on every run
  "delivery-code", // a notify history entry whose failure code is outside DELIVERY_FAIL_CODES: a failed webhook lands with NO deliveryCode and reads as an unexplained failure
  "deferral-kind", // a restore-test completion whose deferral kind is outside {no-run, posture}: the console renders a DEFERRAL as "tested and failed" (the cruel one: it accuses a healthy backup)
  "sink-screen", // a notify history entry whose sink-screen verdict is outside SINK_SCREEN_VERDICTS: the rebind-exposure evidence silently vanishes
  "auth-signal", // a POST /auth-signal name outside AUTH_SIGNAL_NAMES: the counter silently stops incrementing during the lockout it exists to explain
] as const;
export type VocabDropSurface = (typeof VOCAB_DROP_SURFACES)[number];
const VOCAB_DROP_SURFACE_SET: ReadonlySet<string> = new Set(VOCAB_DROP_SURFACES);

// recordVocabDrop counts ONE out-of-vocabulary observation at the gate that discarded it. The dropped token
// is NEVER passed in and never stored: only the surface it was dropped at.
export async function recordVocabDrop(storage: LedgerStorage, surface: VocabDropSurface): Promise<void> {
  if (!VOCAB_DROP_SURFACE_SET.has(surface)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, VOCAB_DROPS_KEY, "vocab-drop", (prior) => bumpCount(prior ?? {}, surface, at));
}

// ---- expiryObserveFaults (G093): the credential-expiry warning ladder that never ARMED ------------
//
// The expiry tracker is the thing that says "your SAML cert expires in 21 days". Every write into it is
// FAIL-OPEN (a hiccup must never fail the IdP create that triggered it), so an observation that is REJECTED
// by the validator, THROWS on storage, or yields NO usable date silently leaves the credential UNTRACKED.
// The lapse is then discovered the way it always is: the cert expires and every login stops. These counters
// are the difference between "we never warned you" and "we could not observe it, here is when we stopped".
export const EXPIRY_ITEM_CLASSES = ["saml-cert", "idp-secret", "licence", "attach-token", "other"] as const;
export type ExpiryItemClass = (typeof EXPIRY_ITEM_CLASSES)[number];
const EXPIRY_ITEM_CLASS_SET: ReadonlySet<string> = new Set(EXPIRY_ITEM_CLASSES);

export const EXPIRY_FAULT_CLASSES = [
  "validate-rejected", // the observed item failed validateExpiryItem: it was never written, and the ladder can never fire for it
  "storage-fault", // the upsert/delete THREW: the tracked row is stale or absent (a refresh that fails forever silently freezes the countdown)
  "unparseable-date", // the artefact carried an expiry the engine could not parse, so the row is DELETED / never written ("the console stopped warning about our licence expiry")
  "no-cert-date", // a SAML signing cert parsed to NO notAfter at all: nothing to count down from
] as const;
export type ExpiryFaultClass = (typeof EXPIRY_FAULT_CLASSES)[number];
const EXPIRY_FAULT_CLASS_SET: ReadonlySet<string> = new Set(EXPIRY_FAULT_CLASSES);

// expiryFaultKey is the composite aggregate key. Both halves are closed-set members validated at the record
// boundary, so the item's own id (customer-authored: an IdP connection id) never becomes a storage key.
export function expiryFaultKey(item: ExpiryItemClass, fault: ExpiryFaultClass): string {
  return `${item}|${fault}`;
}

// classifyExpiryItem REDUCES an expiry item id to its closed KIND CLASS. It reads the id ONLY to select an
// enum member (matching the engine's OWN id prefixes, minted in scheduler-do-idp.ts / observeLicence) and
// RETURNS that enum: the id itself, which embeds the customer's connection id, is never stored here.
export function classifyExpiryItem(id: unknown): ExpiryItemClass {
  if (typeof id !== "string") return "other";
  if (id.startsWith("idp-cert-")) return "saml-cert";
  if (id.startsWith("idp-secret-")) return "idp-secret";
  if (id === "licence") return "licence";
  if (id.startsWith("attach-token-") || id.startsWith("attach:")) return "attach-token";
  return "other";
}

// recordExpiryObserveFault counts ONE failed observation of a tracked credential. Closed classes only: never
// the item id, the cert content or the date value.
export async function recordExpiryObserveFault(storage: LedgerStorage, item: ExpiryItemClass, fault: ExpiryFaultClass): Promise<void> {
  if (!EXPIRY_ITEM_CLASS_SET.has(item) || !EXPIRY_FAULT_CLASS_SET.has(fault)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, EXPIRY_OBSERVE_FAULTS_KEY, "expiry-observe-fault", (prior) => bumpCount(prior ?? {}, expiryFaultKey(item, fault), at));
}

// ---- approvalFaults (G094): the dual-control restore lifecycle's REFUSALS and lease anomalies -----
//
// The restore approval machine audits its SUCCESSES only. Every refusal is a thrown Error whose text reaches
// one operator's screen and nothing else, and the two lease anomalies (a release or a consume that finds the
// reservation RECLAIMED) return a bare boolean the router discards. So the pack cannot answer the two
// questions dual control exists to answer: "prove nobody tried to self-approve a restore" and, far worse,
// "did one approval authorise two applies?" A consume that misses is exactly that accounting hole, and it was
// recorded nowhere. These counters are the record. Closed stages x closed refusal classes; no plan content,
// no plan hash, no actor identity (the audit excerpt's standing redaction already governs actors).
export const APPROVAL_STAGES = ["request", "approve", "reject", "reserve", "release", "consume"] as const;
export type ApprovalStage = (typeof APPROVAL_STAGES)[number];
const APPROVAL_STAGE_SET: ReadonlySet<string> = new Set(APPROVAL_STAGES);

export const APPROVAL_REFUSAL_CLASSES = [
  "self-approval", // the checker IS the maker (by stable subject): a maker-checker VIOLATION was attempted. The bot escalates on this one
  "identity-unattributable", // a bare-token break-glass caller tried to be a maker or a checker: dual control needs two stable subjects
  "already-exists", // a re-request found a still-usable approval or a LIVE reservation and refused to clobber it
  "not-approvable", // the record cannot be approved from its current effective status (already approved, rejected, being applied)
  "not-rejectable", // the veto was refused: the record is already terminal or is mid-apply ("we tried to veto a restore but the reject kept failing")
  "expired", // the approval's TTL lapsed before the action
  "no-plan-anchor", // a request was raised against a plan hash with NO recorded dry run: the engine cannot date the preview the operator read, so it cannot promise the apply drops no more than that preview disclosed. Kept separate from "expired" (which means the preview WAS recorded and is simply too old) because the two have different causes: a skipped preview, a swallowed anchor note after a DO hiccup, or a re-request after a reject/consume dropped the anchor
  "consumed", // the approval was already used (single-use enforced)
  "no-such-request", // no approval record exists for the plan hash at all (an apply against a plan nobody raised, or a record that vanished)
  "lease-reclaimed", // THE ACCOUNTING HOLE: a release or a consume found the reservation was no longer its own (the lease lapsed and a fresh reserve took it). A consume-miss after a SUCCESSFUL apply means the approval that authorised it is not marked consumed and could authorise another
  "applying-in-flight", // a reserve found the plan already reserved by another in-flight apply (a double-clicked Apply, a retry-on-timeout)
] as const;
export type ApprovalRefusalClass = (typeof APPROVAL_REFUSAL_CLASSES)[number];
const APPROVAL_REFUSAL_CLASS_SET: ReadonlySet<string> = new Set(APPROVAL_REFUSAL_CLASSES);

export function approvalFaultKey(stage: ApprovalStage, cls: ApprovalRefusalClass): string {
  return `${stage}|${cls}`;
}

// classifyApprovalRefusal maps the approval machine's own STRUCTURED state (the record's effective status,
// plus the one boolean the caller knows: whether this was a self-approval) to a closed refusal class. It
// never reads the refusal MESSAGE (the messages are operator-facing prose, and reading them would be the
// free-text leak the vocabulary exists to prevent): the status enum is the input.
export function classifyApprovalRefusal(effective: string | null, selfApproval = false): ApprovalRefusalClass {
  if (selfApproval) return "self-approval";
  switch (effective) {
    case null:
      return "no-such-request";
    case "expired":
      return "expired";
    case "consumed":
      return "consumed";
    case "applying":
      return "applying-in-flight";
    default:
      return "not-approvable";
  }
}

// recordApprovalFault counts ONE refused/anomalous step of the dual-control lifecycle.
export async function recordApprovalFault(storage: LedgerStorage, stage: ApprovalStage, cls: ApprovalRefusalClass): Promise<void> {
  if (!APPROVAL_STAGE_SET.has(stage) || !APPROVAL_REFUSAL_CLASS_SET.has(cls)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, APPROVAL_FAULTS_KEY, "approval-fault", (prior) => bumpCount(prior ?? {}, approvalFaultKey(stage, cls), at));
}

// ---- storageAnomalies (G105): the SILENT self-heals, coercions and safe-default reads -------------
//
// The DO is full of defensive reads that paper over a corrupt record with a safe default. Each one is right
// on its own (a corrupt value must never crash the scheduler) and each one DESTROYS the evidence that the
// record was corrupt at all. The worst is epoch-corrupt-defaulted: a corrupt idpEpoch coerces to 0, which
// means "revoke nothing", so "we disabled that IdP connection but a session kept working" is a REVOCATION
// BYPASS whose only trace was the corrupt byte itself. Counting the heal costs nothing and makes a storage
// corruption investigation possible.
export const STORAGE_ANOMALY_KINDS = [
  "audit-head-rebuilt", // the audit head POINTER was missing and was reconstructed by scanning the chain. Expected exactly once after an upgrade; a REPEAT means the pointer key is being lost, and a lost pointer is how a chain silently re-anchors
  "rollover-record-lost", // the audit chain demonstrably rolled over (it begins above seq 1) but the rollover RECORD is gone: without the derived fallback this reads as a TAMPER (a spurious break)
  "verify-incomplete", // a prior audit verify never finished (the CPU budget killed it mid-recompute): its verdict was never written and the stale meta was being read as if current
  "marker-corrupt-defaulted", // a {count,lastAt} governance marker read back malformed and was coerced to ZERO. THREE markers share this shape and all three now book it: the emergency-change tally (the compliance flag it raises silently clears itself), the change-control refusal tally and the config auto-snapshot failure tally. The pack surfaces the latter two ONLY above zero, so the coerced zero is not a low number there, it is an ABSENT block indistinguishable from a clean account; configIntegrity.unavailableProbes names WHICH marker
  "epoch-corrupt-defaulted", // an idpEpoch / session epoch read back malformed and was coerced to 0 = "revoke nothing" (a REVOCATION BYPASS)
  "preflight-read-failed", // the lockout/connection-removal preflight degraded on a read fault and answered fail-safe: the guard that prevents an account locking itself out was running blind
  "dryrun-rollback-failed", // a change-control DRY RUN's rollback THREW: the proposal's writes may have survived as unattributable config side effects
  "snapshot-ts-corrupt", // a stored posture-snapshot timestamp did not parse, so the scheduled evaluation re-ran (or the recency read lied)
  "posture-read-failed", // the posture identity/passkey read faulted and returned "cannot verify": the posture check silently abstains rather than failing
  "config-key-fp-baselined", // the config-history signing-key FINGERPRINT baseline was (re)established: until the NEXT snapshot, signingKeyRotated is a structural FALSE NEGATIVE, which is the window a key regeneration hides in
  "roster-claimant-discarded", // a roster repair DISCARDED a divergent claimant's config row (the twin was healthy, so N-1 claimants lose their config): "after the repair my downpipe has the wrong schedule"
  "audit-head-count-lost", // the audit head pointer is PRESENT and its count cannot be believed (not a non-negative integer, or zero while it names a newest entry above seq 0). CORRUPT WAS WORSE THAN MISSING here: an ABSENT pointer is reconstructed from the chain and reports the truth, and a present-but-empty one was returned verbatim, so an account with a full chain read `auditCount: 0`
  "audit-head-anchor-unreadable", // the audit head ANCHOR is PRESENT and its headSeq is not a positive integer, so the tail-deletion witness had nothing to compare against. It was skipped SILENTLY and the verify still answered intact, which is the one reading that must never be produced by a damaged anchor
  "expiry-row-unreadable-surfaced", // a tracked expiry row's expiresAt did not parse, so it is neither approaching nor expired and the warning count could not see it. The row is now carried as its own figure rather than being absorbed into a zero
] as const;
export type StorageAnomalyKind = (typeof STORAGE_ANOMALY_KINDS)[number];
const STORAGE_ANOMALY_KIND_SET: ReadonlySet<string> = new Set(STORAGE_ANOMALY_KINDS);

// recordStorageAnomaly counts ONE silent heal / coercion / degraded read. Counts and closed kinds only: never
// the corrupt value (which is by definition arbitrary bytes and could hold anything).
export async function recordStorageAnomaly(storage: LedgerStorage, kind: StorageAnomalyKind): Promise<void> {
  if (!STORAGE_ANOMALY_KIND_SET.has(kind)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, STORAGE_ANOMALIES_KEY, "storage-anomaly", (prior) => bumpCount(prior ?? {}, kind, at));
}

// ---- rosterDiscards (G105): WHICH claimant a roster repair threw away --------------------------------
//
// The counter above says a config was discarded; this ring says WHOSE. A divergent claimant is a dp: row whose
// key and embedded id disagree; when a healthy twin exists the repair deletes the row, and the operator's
// schedule/retention edits in that row go with it. The evidence carries the two ids (the customer's own
// labels, the class the pack already ships in downpipes[]) and a one-way DIGEST of the discarded config, so a
// customer asking "what did the repair take from me?" can be answered, and the config content itself is never
// carried (it can hold a destination id, a prefix, a cadence: operator data with no diagnostic value here).
export interface RosterDiscardEntry {
  key: string; // the misplaced dp: key's suffix id (clamped)
  embeddedId: string; // the id the row's config claimed (clamped)
  configDigest: string; // a 12-hex one-way prefix digest of the discarded config, never the config
  at: string;
}
export const ROSTER_DISCARDS_CAP = 32;
// A digest is engine-computed hex. Anything else did not come from the engine and is dropped.
const DIGEST_PATTERN = /^[0-9a-f]{1,32}$/;

export async function recordRosterClaimantDiscard(storage: LedgerStorage, suffixId: unknown, embeddedId: unknown, configDigest: unknown): Promise<void> {
  const key = safeLabel(suffixId);
  const embedded = safeLabel(embeddedId);
  if (key === null || embedded === null) return;
  const digest = typeof configDigest === "string" && DIGEST_PATTERN.test(configDigest) ? configDigest : "";
  const entry: RosterDiscardEntry = { key, embeddedId: embedded, configDigest: digest, at: new Date().toISOString() };
  await writeLedger<RosterDiscardEntry[]>(storage, ROSTER_DISCARDS_KEY, "roster-discard", (prior) => {
    const ring = Array.isArray(prior) ? [...prior, entry] : [entry];
    return ring.length > ROSTER_DISCARDS_CAP ? ring.slice(ring.length - ROSTER_DISCARDS_CAP) : ring;
  });
}

// ---- testOutcomes (G246): the wiring-check button whose ANSWER died with the browser tab --------------
//
// Every setup surface in the console has a Test button, and every one of them is the operator's ONLY proof
// that the thing they just wired actually works. Not one of their outcomes was persisted anywhere.
//
//   "The push test failed with a 401 yesterday but works when support asks us to retry."
//   "My Slack test keeps failing."  "The SSO test failed with some cert error."  "Verify destination keeps failing."
//
// Each of those is a customer reporting an outcome the engine COMPUTED, richly and correctly, and then threw
// away with the HTTP response. The one artefact that WAS persisted -- the notify history's test row -- carries
// `delivered:false` and NO reason, which is worse than nothing: it confirms the failure and refuses to explain
// it. So support asks the customer to press the button again, in front of them, which is the whole reason this
// gap is rated common.
//
// The ring below is the record. It is a RING, not a counter map, because the SEQUENCE is what answers these
// tickets: "failed, failed, failed, ok" is a fixed configuration; "ok, failed, ok, failed" is a flapping
// endpoint; and a lone "failed" yesterday against an "ok" today is exactly the customer's story, corroborated.
//
// NO-CUSTODY: a closed surface, a boolean, a closed reason class and a closed HTTP status class. NEVER the
// target URL, the webhook address, the recipient e-mail, the probe endpoint, the bucket, the IdP issuer or the
// provider's rejection text. The reason is CLASSIFIED at the call site (which reads the text only to select a
// member) and the text is discarded there.
export const TEST_SURFACES = ["notify-channel", "email", "push", "idp", "dest-verify"] as const;
export type TestSurface = (typeof TEST_SURFACES)[number];
const TEST_SURFACE_SET: ReadonlySet<string> = new Set(TEST_SURFACES);

// The CLOSED reason class, shared across the five surfaces. One vocabulary rather than five keeps the ring
// readable in one pass and keeps the redaction boundary in one place; the SURFACE disambiguates where two
// surfaces would use the same word.
export const TEST_REASON_CLASSES = [
  "auth", // the target REFUSED our credential (a 401/403, a rejected key, an expired token). The single most common test failure, and the one the customer can fix
  "not-configured", // the surface has nothing to test: no channel, no push destination, no email binding, no destination config
  "unreachable", // the target could not be reached at all (DNS, connection refused, an egress block)
  "timeout", // the target accepted the connection and never answered
  "tls", // a certificate / handshake failure reaching the target (a private CA, an expired cert, an interception proxy)
  "rejected", // the target ANSWERED and refused the payload (a 4xx that is not auth, a provider validation error, an unverified sender domain)
  "rate-limited", // the target throttled us (a 429): the wiring is right and the test is being refused for volume
  // "delete-denied" was REMOVED from this vocabulary, and it is the reason the dead-vocab gate exists.
  //
  // A denied DELETE is not a FAILED test: probeDestination's delete is in its own try/catch and never fails the
  // probe (the destination accepted the write, so backups genuinely work). The class could therefore only ever
  // be selected on the ok:false path, where the reason is an auth / redirect / sanitised message that cannot
  // contain the words -- so it had ZERO producers, and the test that "proved" it posted a hand-written
  // "delete-denied" reason straight into the recorder, a string the real route cannot generate.
  //
  // The fact is real and worth carrying; it was simply not a FAILURE REASON. It now rides on its own
  // discriminator (deleteProbe below), beside the probe's object-lock verdict, on a row whose ok is honestly
  // true.
  "cert", // idp ONLY: the IdP's signing certificate is missing, expired or would not parse ("the SSO test failed with some cert error")
  "metadata", // idp ONLY: the IdP metadata / discovery document could not be read or did not carry what the connection needs
  "shape", // the target answered something structurally unusable (a captive portal, an HTML error page, a body that would not parse)
  "internal", // the ENGINE failed the test (its own config could not be read, its wrap key would not decrypt): not the customer's target at all
  "other", // residual (never a message)
] as const;
export type TestReasonClass = (typeof TEST_REASON_CLASSES)[number];
const TEST_REASON_CLASS_SET: ReadonlySet<string> = new Set(TEST_REASON_CLASSES);

// The coarse HTTP status CLASS, when the test saw one. "401" is split out from 4xx deliberately: it is the
// customer's answer ("your token is wrong"), and folding it into 4xx would erase the whole point of the ticket.
export const TEST_STATUS_CLASSES = ["2xx", "3xx", "401", "403", "404", "429", "4xx", "5xx", "other"] as const;
export type TestStatusClass = (typeof TEST_STATUS_CLASSES)[number];
const TEST_STATUS_CLASS_SET: ReadonlySet<string> = new Set(TEST_STATUS_CLASSES);

// ---- G246: the DELETE-DENIED destination, a PASS that hides a broken retention -----------------------------
//
// A destination whose DELETE is refused accepts every backup and can never expire one. Storage grows for ever,
// the retention policy the customer configured silently does nothing, and the verify button says OK -- because
// it IS ok, for backups. The probe knew (it returns deleteProbe) and the recorder threw it away, so a healthy
// destination and one whose retention does not work produced a BYTE-IDENTICAL row: {surface:"dest-verify",
// ok:true}. That is the state the gap exists to separate.
//
// It rides beside the probe's OBJECT-LOCK verdict, and beside that verdict's OWN closed unknown-reason and a
// default-retention boolean. Every one of those four fields is a MEASUREMENT. None of them is an intent, and the
// row must never claim an intent the probe has not established:
//
//   * The engine's DELETE sends no versionId (dest/s3-read-ops.ts), and an unversioned DELETE on an Object-Lock
//     bucket (which is necessarily versioned) writes a delete marker: Object Lock protects VERSIONS, it does not
//     refuse that request. So {denied, enforced} is NOT "the customer's WORM hardening, nothing to fix" -- it is a
//     POLICY or CREDENTIAL denial on a locked bucket, and it may be the very fault the ticket is about.
//   * ObjectLockEnabled does not mean anything is RETAINED (a bucket can have lock on with no default rule), so
//     "enforced" cannot stand in for "locked". defaultRetention carries what was actually measured.
//   * {denied, not-enforced} is not "NOBODY chose this" either: an explicit Deny on s3:Delete* over an otherwise
//     broad key is the ordinary anti-ransomware hardening on a store with no Object Lock.
//
// So the row says what was measured, and support reads the remedy off the combination:
//   deleteProbe "ok"                                          -> the destination writes AND prunes.
//   deleteProbe "denied" + objectLock "unknown" + reason
//     "denied"                                                -> the key may not read the lock config either: one
//                                                                least-privilege allow-list is short two actions.
//   deleteProbe "denied" + objectLock "unknown" + reason
//     "not-implemented"                                       -> the store has NO Object-Lock API; the refusal is a
//                                                                delete policy. These two were the SAME ROW.
//   deleteProbe "denied" + objectLock "enforced"              -> a locked bucket that also refused an unversioned
//                                                                delete: retention pruning will not work, and the
//                                                                lock did not cause the refusal.
//   deleteProbe "denied" + objectLock "not-enforced"          -> the credential cannot delete and no lock explains
//                                                                it: the archive grows for ever.
// Every field is a closed enum or a boolean the probe already computes. No bucket, endpoint or credential is
// representable.
//
// R5: "denied" IS A PERMISSION FACT, AND THE PROBE WAS INFERRING IT FROM THE BARE FACT OF A THROW.
//
// probeDestination's cleanup delete used to be `try { await dest.delete(k) } catch { deleteProbe = "denied" }`,
// and s3-read-ops del() throws on ANY non-204/404 status and on a transport fault. So a 503 SlowDown, a 500
// store error, a 429 throttle and a dropped socket all landed as "denied" -- the word that sends support to an
// IAM allow-list that is already correct, and files a DURABLE row saying this customer's retention is
// permanently broken because one request was unlucky. In the other direction a genuine least-privilege denial
// became waveable-away as "the store was flaky", which is the state this gap exists to expose.
//
// The discriminator was already in hand: del() reads the status off the response before it throws. It now
// throws it TAGGED (dest/types.ts DestStatusError), so the probe classifies what it MEASURED:
//   "ok"         the delete returned (204, or 404: already gone).
//   "denied"     401/403. The credential is not allowed to delete. THE permission fact, and only it.
//   "transient"  429 or 5xx, or the request never got a status at all (a transport fault). The store was busy
//                or the socket dropped: nothing is known about the credential, and nothing is broken for ever.
//   "other"      any other status the store answered with (a 4xx that is not auth). Residual, never a guess.
// deleteStatusClass carries the status class itself off the existing testStatusClass(), so a throttle (429) and
// a store fault (5xx) are separable too, and its ABSENCE on a "transient" row is exactly the transport case.
export const TEST_DELETE_PROBES = ["ok", "denied", "transient", "other"] as const;
export type TestDeleteProbe = (typeof TEST_DELETE_PROBES)[number];
const TEST_DELETE_PROBE_SET: ReadonlySet<string> = new Set(TEST_DELETE_PROBES);

export const TEST_OBJECT_LOCKS = ["enforced", "not-enforced", "unknown"] as const;
export type TestObjectLock = (typeof TEST_OBJECT_LOCKS)[number];
const TEST_OBJECT_LOCK_SET: ReadonlySet<string> = new Set(TEST_OBJECT_LOCKS);

// The object-lock probe's OWN closed reason vocabulary (dest/types.ts WORM_UNKNOWN_REASONS), reused rather than
// re-declared: every member has a producer in the store layer, and "unknown" without it names no remedy.
const TEST_OBJECT_LOCK_UNKNOWN_REASON_SET: ReadonlySet<string> = new Set(WORM_UNKNOWN_REASONS);

export interface TestOutcomeEntry {
  surface: TestSurface;
  at: string;
  ok: boolean;
  reasonClass?: TestReasonClass; // absent on a PASS (a pass has no reason)
  statusClass?: TestStatusClass; // present only when the test saw an HTTP status
  deleteProbe?: TestDeleteProbe; // dest-verify ONLY: could the destination DELETE what it just wrote?
  deleteStatusClass?: TestStatusClass; // dest-verify ONLY, and only when the delete FAILED: the status class the store answered with. ABSENT on a failed delete = no status was ever seen (a transport fault)
  objectLock?: TestObjectLock; // dest-verify ONLY: what the bucket REPORTS about Object-Lock. Never an intent
  objectLockUnknownReason?: WormUnknownReason; // dest-verify ONLY, and only when objectLock is "unknown": WHY the probe could not confirm. "denied" and "not-implemented" are different remedies
  defaultRetention?: boolean; // dest-verify ONLY, and only when objectLock is "enforced": is a DEFAULT RETENTION RULE actually configured, or is the lock merely switched on?
  // R6: the EMAIL surface ONLY, and only on a FAILED send: WHAT THE EMAIL SERVICE ACTUALLY SAID, as the bounded
  // E_UPPER_SNAKE platform code (E_SENDER_DOMAIN_NOT_AVAILABLE, E_SENDER_NOT_VERIFIED, E_RATE_LIMITED, or the
  // engine-owned E_OTHER when the platform sent a code of some other shape). Without it, an un-onboarded sending
  // domain, an unverified sender and a platform throttle were ONE row -- {"ok":false,"reasonClass":"other"} --
  // with three different remedies, and "our test email never arrives" was unanswerable from the pack. It is the
  // same bounded token the notify history already carries (the G236 chokepoint, sanitiseEmailPlatformCode): a
  // shape-gated code, never the platform's message. R7: admitted on the NOTIFY-CHANNEL surface too, because the
  // console's OTHER Test button (POST /admin/notify/test, on a kind:"email" channel) asks the same Email Service
  // the same question through the same adapter, and it was collapsing E_SENDER_DOMAIN_NOT_AVAILABLE,
  // E_SENDER_NOT_VERIFIED and an invalid EMAIL_FROM into one {"ok":false,"reasonClass":"rejected"} row.
  platformCode?: string;
  // R7: THE NOTIFY-CHANNEL SURFACE'S OWN DISCRIMINATOR, and the reason "my Slack test keeps failing" died six
  // rounds. deliverToChannel ALREADY returns a closed DeliveryFailCode (http-bad-request, http-gone, http-4xx,
  // email-platform-rejected, email-from-invalid, ...): the route laundered it through `reason` into
  // classifyTestFailure, whose text arm coarsens ALL of those to "rejected". So a DEPROVISIONED Slack webhook
  // (410: recreate the integration), a wrong path on a live sink (404: fix the path) and an engine payload
  // regression (400: OUR bug) were one byte-identical row with three opposite remedies -- re-collapsing the very
  // G248 and G236 splits the channel layer had already built. The code rides here, unlaundered, on the
  // notify-channel surface only, and only on a FAILED test.
  deliveryCode?: DeliveryFailCode;
}
// Per-surface cap: enough to show the SEQUENCE (flapping vs fixed) without unbounded growth. A busy operator
// pressing Test twenty times still leaves a bounded record, and the five surfaces are independent rings.
export const TEST_OUTCOMES_PER_SURFACE = 8;
export type TestOutcomes = Record<string, TestOutcomeEntry[]>;

/**
 * testStatusClass reduces an HTTP status to its closed class. Pure and total.
 *
 * @param status - the observed HTTP status, if any.
 * @returns the closed class, or undefined when no status was seen (a DNS failure, a timeout, a thrown probe).
 */
export function testStatusClass(status: unknown): TestStatusClass | undefined {
  if (typeof status !== "number" || !Number.isFinite(status) || status <= 0) return undefined;
  const n = Math.floor(status);
  if (n === 401) return "401";
  if (n === 403) return "403";
  if (n === 404) return "404";
  if (n === 429) return "429";
  if (n >= 200 && n < 300) return "2xx";
  if (n >= 300 && n < 400) return "3xx";
  if (n >= 400 && n < 500) return "4xx";
  if (n >= 500 && n < 600) return "5xx";
  return "other";
}

/**
 * classifyTestFailure REDUCES a test's failure reason to ONE closed class. It reads the string ONLY to SELECT
 * an enum member and RETURNS that enum -- the classifyCoarseError idiom -- so the reason itself (which
 * interpolates endpoints, provider prose, bucket names and e-mail addresses) never leaves this function.
 *
 * The HTTP status, when the test saw one, OUTRANKS the text: a 401 is an auth failure whatever the body says.
 *
 * @param reason - the engine-or-provider text, read only to select a member.
 * @param status - the observed HTTP status, if any.
 * @returns the closed reason class.
 */
export function classifyTestFailure(reason: unknown, status?: unknown): TestReasonClass {
  const st = typeof status === "number" && Number.isFinite(status) ? Math.floor(status) : 0;
  // The STATUS outranks the text: a 401 is an auth failure whatever the body says.
  if (st === 401 || st === 403) return "auth";
  if (st === 429) return "rate-limited";
  const m = typeof reason === "string" ? reason : "";
  if (m === "") return "other";
  // The four surfaces feed this their OWN closed codes (DELIVERY_FAIL_CODES, the IdP probe's fail classes,
  // the destination probe's reason, the email platform code), so the first arms match those literals exactly
  // rather than guessing. The looser arms below catch a provider sentence that reached us unclassified.
  if (/^not-set$|not[- ](configured|set)|unconfigured|email-not-configured|no channel|no destination|missing required configuration/i.test(m)) return "not-configured";
  // The delete-denied arm was REMOVED with its class: a denied delete never fails the probe, so no reason
  // string reaching here can ever have carried those words. It matched nothing, and its presence was the only
  // thing making the dead class look alive to a reader (and to a literal-scanning gate).
  if (/http-auth|unauthoris|unauthoriz|forbidden|invalid[- ]?(key|token|credential)|AccessDenied|SignatureDoesNotMatch|ExpiredToken/i.test(m)) return "auth";
  if (/\bcert\b|cert-|certificate|notAfter|x509/i.test(m)) return "cert";
  if (/metadata|discovery|jwks|well-known|issuer-mismatch|no-usable-keys/i.test(m)) return "metadata";
  if (/network-tls|\bTLS\b|\bSSL\b|handshake/i.test(m)) return "tls";
  if (/timeout|timed out|deadline|ETIMEDOUT/i.test(m)) return "timeout";
  if (/network-dns|network-reset|network-error|internal-sink-blocked|unsafe-url|unreachable|fetch failed|ECONNREFUSED|ENOTFOUND|DNS|egress/i.test(m)) return "unreachable";
  if (/http-rate-limited|throttl|SlowDown|TooManyRequests/i.test(m)) return "rate-limited";
  if (/non-json|url-invalid|parse|unexpected token|malformed|\bshape\b/i.test(m)) return "shape";
  if (/config-unreadable|wrap key|decrypt|\binternal\b/i.test(m)) return "internal";
  if (/http-(redirect|bad-request|gone|4xx|5xx|other)|non-200|reject|refused|invalid|unsupported|not verified|unverified/i.test(m)) return "rejected";
  return "other";
}

/**
 * recordTestOutcome appends ONE wiring-check outcome to its surface's bounded ring. Both enums are closed-set
 * validated HERE (the recorder is the redaction chokepoint), so no reason text, URL or address can enter the
 * record even from a drifted caller. Never throws.
 *
 * @param storage - the DO storage.
 * @param entry - the classified outcome (closed surface + boolean + closed classes only).
 */
export async function recordTestOutcome(
  storage: LedgerStorage,
  entry: { surface: string; ok: boolean; reasonClass?: string; statusClass?: string; deleteProbe?: string; deleteStatusClass?: string; objectLock?: string; objectLockUnknownReason?: string; defaultRetention?: boolean; platformCode?: string; deliveryCode?: string },
): Promise<void> {
  if (!TEST_SURFACE_SET.has(entry.surface)) return;
  const reasonClass = typeof entry.reasonClass === "string" && TEST_REASON_CLASS_SET.has(entry.reasonClass) ? (entry.reasonClass as TestReasonClass) : undefined;
  const statusClass = typeof entry.statusClass === "string" && TEST_STATUS_CLASS_SET.has(entry.statusClass) ? (entry.statusClass as TestStatusClass) : undefined;
  // G246: closed-set validated HERE like every other field, and admitted ONLY on dest-verify -- the one surface
  // whose probe computes them. A drifted caller cannot smuggle them onto an e-mail or push row.
  const isDestVerify = entry.surface === "dest-verify";
  const deleteProbe = isDestVerify && typeof entry.deleteProbe === "string" && TEST_DELETE_PROBE_SET.has(entry.deleteProbe) ? (entry.deleteProbe as TestDeleteProbe) : undefined;
  // R5: the delete's own status class, admitted ONLY where it describes something -- a delete that FAILED. On an
  // "ok" delete there is no status to explain (204/404 both mean the object is gone), so carrying one would be a
  // field riding on a row it cannot describe.
  const deleteStatusClass =
    deleteProbe !== undefined && deleteProbe !== "ok" && typeof entry.deleteStatusClass === "string" && TEST_STATUS_CLASS_SET.has(entry.deleteStatusClass)
      ? (entry.deleteStatusClass as TestStatusClass)
      : undefined;
  const objectLock = isDestVerify && typeof entry.objectLock === "string" && TEST_OBJECT_LOCK_SET.has(entry.objectLock) ? (entry.objectLock as TestObjectLock) : undefined;
  // R4: the reason is admitted ONLY where it means something (objectLock "unknown"), and the retention boolean
  // ONLY where it means something (objectLock "enforced"). A field that rides on a row it cannot describe is a
  // fact the code never established, so it is dropped rather than carried.
  const objectLockUnknownReason =
    objectLock === "unknown" && typeof entry.objectLockUnknownReason === "string" && TEST_OBJECT_LOCK_UNKNOWN_REASON_SET.has(entry.objectLockUnknownReason)
      ? (entry.objectLockUnknownReason as WormUnknownReason)
      : undefined;
  const defaultRetention = objectLock === "enforced" && typeof entry.defaultRetention === "boolean" ? entry.defaultRetention : undefined;
  // R6: the email platform code, re-gated HERE through the same shape gate the notify path uses, and admitted
  // ONLY on the EMAIL surface and ONLY on a FAILED send (a delivered message has nothing to explain, and a
  // drifted caller cannot smuggle a token onto a push, idp, notify-channel or dest-verify row). The gate is the
  // redaction chokepoint: an E_UPPER_SNAKE token or nothing, never the platform's message.
  // R7: the SAME gate, widened to the surface that asks the SAME question. The notify-channel Test button on a
  // kind:"email" channel drives the identical sendEmail primitive and gets the identical platform code back; the
  // gate stays the shape gate (an E_UPPER_SNAKE token or nothing, never the platform's message), so widening the
  // surface admits no new leak surface. Every other surface (push, idp, dest-verify) still cannot carry one.
  const emailPlatformSurface = entry.surface === "email" || entry.surface === "notify-channel";
  const platformCode = emailPlatformSurface && entry.ok !== true ? sanitiseEmailPlatformCode(entry.platformCode) : undefined;
  // R7: the closed DeliveryFailCode, re-gated HERE against the channel layer's own allow-list (the recorder is
  // the redaction chokepoint, so a drifted caller cannot smuggle a URL or a provider sentence in through it) and
  // admitted ONLY on the notify-channel surface and ONLY on a FAILED test. deliverToChannel is the only producer
  // of the vocabulary, and POST /admin/notify/test is the only test route that calls it.
  const deliveryCode =
    entry.surface === "notify-channel" && entry.ok !== true && typeof entry.deliveryCode === "string" && DELIVERY_FAIL_CODES.has(entry.deliveryCode)
      ? (entry.deliveryCode as DeliveryFailCode)
      : undefined;
  const row: TestOutcomeEntry = {
    surface: entry.surface as TestSurface,
    at: new Date().toISOString(),
    ok: entry.ok === true,
    // A PASS carries no reason (there is nothing to explain); a FAIL always carries one, coarsening to `other`
    // rather than being dropped, so a failure can never appear in the ring with no cause at all.
    ...(entry.ok === true ? {} : { reasonClass: reasonClass ?? "other" }),
    ...(statusClass !== undefined ? { statusClass } : {}),
    ...(deleteProbe !== undefined ? { deleteProbe } : {}),
    ...(deleteStatusClass !== undefined ? { deleteStatusClass } : {}),
    ...(objectLock !== undefined ? { objectLock } : {}),
    ...(objectLockUnknownReason !== undefined ? { objectLockUnknownReason } : {}),
    ...(defaultRetention !== undefined ? { defaultRetention } : {}),
    ...(platformCode !== undefined ? { platformCode } : {}),
    ...(deliveryCode !== undefined ? { deliveryCode } : {}),
  };
  await writeLedger<TestOutcomes>(storage, TEST_OUTCOMES_KEY, "test-outcome", (prior) => {
    const map: TestOutcomes = { ...(prior ?? {}) };
    const existing = map[row.surface];
    const ring: TestOutcomeEntry[] = Array.isArray(existing) ? [...existing] : [];
    ring.push(row);
    map[row.surface] = ring.length > TEST_OUTCOMES_PER_SURFACE ? ring.slice(ring.length - TEST_OUTCOMES_PER_SURFACE) : ring;
    return map;
  });
}

// ---- chainBreaks (G313): the tamper verdict that SELF-HEALS and leaves no trace -----------------------
//
// "Audit verify showed a break last Tuesday but shows intact now." Both statements can be TRUE, and the pack
// cannot corroborate either. The verdict is RECOMPUTED at bundle-build time from the retained chain, so:
//
//   - a break that has since ROLLED OVER (the broken entries pruned past the retention cap) reads INTACT, and
//     the pack carries no record that a break was ever seen. The customer sounds unreliable; they are not.
//   - a break that IS present reads broken-at-N, and "broken at version 41" cannot distinguish an EDITED
//     snapshot from a FORGED digest from a DELETED version. Three different investigations, one answer.
//
// The latch below is the durable memory the recompute cannot have. It records the FIRST detection (never
// overwritten: the first sighting is the forensically interesting one), the sequence it broke at, the CLOSED
// cause class, and how many times it has been re-observed since. It SURVIVES rollover, which is the whole
// point: a break that self-heals by falling off the retention window still has a row.
//
// NO-CUSTODY: two closed chain names, a closed cause enum, integer sequences, counts, timestamps. No entry
// content, no hash, no actor, no target.
export const AUDIT_CHAINS = ["audit", "config-history"] as const;
export type AuditChain = (typeof AUDIT_CHAINS)[number];
const AUDIT_CHAIN_SET: ReadonlySet<string> = new Set(AUDIT_CHAINS);
const CHAIN_BREAK_CAUSE_SET: ReadonlySet<string> = new Set(CHAIN_BREAK_CAUSES);

export interface ChainBreakLatch {
  chain: AuditChain; // which chain this break is on (the map key composes it, so it is carried explicitly too)
  firstDetectedAt: string; // the FIRST time this break was seen. Never overwritten while the latch stands
  lastDetectedAt: string; // the most recent verify that still saw it
  brokenAtSeq: number; // the seq/id the break was reported at, at first detection
  causeClass: ChainBreakCause;
  detections: number; // how many verifies have seen it (a break seen once and never again is a different story from one seen on every verify)
  healedAt?: string; // set when a LATER verify read INTACT: the break is gone from the retained chain (typically a rollover), and this row is now the only evidence it ever existed
}
export type ChainBreakLatches = Record<string, ChainBreakLatch>;

// The number of DISTINCT breaks latched per chain. Bounded, because the latch must survive rollover and a
// pathological chain must not grow storage without limit. Two chains x this is a small, fixed ceiling.
export const CHAIN_BREAKS_PER_CHAIN = 8;

/**
 * chainBreakKey is the latch's TUPLE KEY, and getting it wrong was the whole defect (G313).
 *
 * The latch used to be keyed by CHAIN NAME ALONE. causeClass and brokenAtSeq discriminate the OUTCOME, and
 * leaving them out of the key meant a later, genuinely DIFFERENT break folded into the first one and
 * disappeared: latch a seq-gap at 41, then detect an edited snapshot at 12, and the pack shows one row --
 * seq-gap@41, detections:2. The edited snapshot at version 12 is invisible, and "detections: 2", sold as
 * evidence of a standing break, is indistinguishable from the SAME break seen twice.
 *
 * Keying on chain + cause + seq means each distinct break gets its own latch, and detections then means what
 * it says: this break, seen this many times.
 *
 * @param chain - the closed chain name.
 * @param cause - the closed cause class.
 * @param seq - the sequence/id the break was reported at.
 * @returns the composed key (closed members and an integer only).
 */
export function chainBreakKey(chain: AuditChain, cause: ChainBreakCause, seq: number): string {
  return `${chain}|${cause}|${seq}`;
}

/**
 * recordChainVerdict latches ONE chain-verify outcome (G313). A BREAK sets (or re-touches) the latch; an
 * INTACT verdict does NOT clear it -- it stamps healedAt, so "it shows intact now" and "it showed a break last
 * Tuesday" are both in the pack, together, which is the only way that ticket is answerable.
 *
 * Never throws (a diagnostic must not break a verify).
 *
 * R4: it now CONSULTS THE ROTATED-KEY FACT before it latches a forgery. The config-history digests are HMAC'd
 * with the in-DO session key, and the engine models a regenerated or lost key explicitly (scheduler-do-base.ts:
 * "if that key is regenerated/lost, EVERY config-history digest fails verifyConfigChain") as RECOVERABLE
 * CONTEXT. The latch used to file that state under a cause whose documentation asserts a forgery -- "the
 * record's attribution was forged, or the record was fabricated without the DO's HMAC key" -- so a customer
 * whose key rotated got a durable, tamper-shaped row about an attacker who does not exist. The boolean was sitting
 * in a different pack section (configIntegrity.signingKeyRotated) and the recorder never read it. A rotated key
 * now has its own cause, and it displaces every digest-family cause, because with the key gone the digest check
 * proves nothing at all.
 *
 * R5: AND IT NOW REFUSES TO SAY "NOTHING WAS TAMPERED" UNTIL THE UNKEYED EVIDENCE AGREES.
 *
 * verifyConfigChain returns at the FIRST break, so with the key gone it fails on version 1's digest and never
 * looks at 2..N. Displacing the whole digest family to signing-key-rotated therefore asserted non-tamper about
 * versions the code had never examined -- and the key can be destroyed by an OWNER BUTTON (terminate-all-sessions
 * deletes the passkey session key), so any actor with the DO-storage write access a tamper already requires could
 * press it and turn every config-history tamper into the row that says nothing happened. A one-button mask.
 *
 * The content hashes, the parent links and the id contiguity are UNKEYED: a rotated key cannot fake or break one
 * of them. The caller now runs that pass over the WHOLE chain and passes its verdict here. signing-key-rotated is
 * latched only when the unkeyed pass is CLEAN; when it is not, the unkeyed cause is latched AT ITS OWN SEQ beside
 * the key fact, so "the owner signed everyone out" and "the owner signed everyone out AND version 2 is the
 * attacker's" are two different rows.
 *
 * @param storage - the DO storage.
 * @param chain - which chain (closed).
 * @param verdict - the verify outcome: intact, plus the broken seq + closed cause when it is not.
 * R6: AND IT LATCHES A TRUNCATED HEAD, WHICH EVERY RECOMPUTE PASS IS BLIND TO.
 *
 * Both verifies walk the RETAINED entries and check that each links to the one before it. Delete the NEWEST
 * entries -- the ones recording what the attacker just did -- and the survivors still link perfectly: the chain
 * reads INTACT. The witness that catches it needs no key and is already in storage: the persisted HEAD ANCHOR
 * the DO writes on every append (the audit head's seq+hash, the config-history head's id+contentHash). Retention
 * rolls the OLDEST entries off and never lowers that anchor, so a retained head BELOW the anchor -- or at it with
 * a different hash -- is a removed or rewritten tail and nothing else. The caller computes that comparison and
 * passes it here as `anchor`; it is latched at the anchor's own seq, BESIDE whatever the recompute found (an
 * intact recompute does not heal it, because the recompute never looked at the entries that are gone).
 *
 * @param signingKeyRotated - true when the in-DO signing key's fingerprint has DRIFTED from its stored baseline.
 * @param unkeyed - the KEY-FREE verdict over the whole chain (content recompute + parent link + id contiguity).
 * @param anchor - the HEAD-ANCHOR verdict: does the retained head still match the head this DO committed to?
 */
export async function recordChainVerdict(
  storage: LedgerStorage,
  chain: AuditChain,
  verdict: { intact: boolean; brokenAt?: number; causeClass?: string },
  signingKeyRotated?: boolean,
  unkeyed?: { intact: boolean; brokenAt?: number; causeClass?: string },
  anchor?: { intact: boolean; brokenAt?: number; causeClass?: string },
): Promise<void> {
  if (!AUDIT_CHAIN_SET.has(chain)) return;
  const at = new Date().toISOString();
  await writeLedger<ChainBreakLatches>(storage, CHAIN_BREAKS_KEY, "chain-break", (prior) => {
    const map: ChainBreakLatches = { ...(prior ?? {}) };
    // The head-anchor break is latched on EVERY path, including the intact one, and it is latched AFTER the heal
    // sweep, so an intact recompute cannot stamp healedAt on a truncation it is structurally unable to see.
    const anchorCause = typeof anchor?.causeClass === "string" && CHAIN_BREAK_CAUSE_SET.has(anchor.causeClass) ? (anchor.causeClass as ChainBreakCause) : undefined;
    const anchorBroken = anchor !== undefined && anchor.intact === false && anchorCause !== undefined;
    const anchorSeq = typeof anchor?.brokenAt === "number" && Number.isFinite(anchor.brokenAt) ? Math.max(0, Math.floor(anchor.brokenAt)) : 0;
    const withAnchor = (m: ChainBreakLatches): ChainBreakLatches => {
      if (anchorBroken && anchorCause !== undefined) latchChainBreak(m, chain, anchorCause, anchorSeq, at);
      return m;
    };
    if (verdict.intact) {
      // INTACT. Every break latched on THIS chain and not yet healed is now gone from the retained chain --
      // almost always because the broken entries rolled off the retention window. That is not a reason to
      // forget them: stamp healedAt on each, so "it shows intact now" and "it showed a break last Tuesday"
      // are both in the pack, together, which is the only way that ticket is answerable.
      for (const [k, latch] of Object.entries(map)) {
        if (latch.chain === chain && latch.healedAt === undefined) map[k] = { ...latch, healedAt: at };
      }
      return withAnchor(map);
    }
    const reported = typeof verdict.causeClass === "string" && CHAIN_BREAK_CAUSE_SET.has(verdict.causeClass) ? (verdict.causeClass as ChainBreakCause) : "recompute-mismatch";
    // R4: a ROTATED OR LOST in-DO signing key makes every keyed digest fail, so every digest-family cause the
    // verify reports on this pass is about a key that is gone, not about a tamper that happened. Nothing was
    // edited and nobody was forged: name the state the engine already models and stop pointing support at an
    // attacker. The non-digest causes (an edited body, a broken link, a gap, a missing body) are unaffected by
    // the key and keep their own verdict.
    const digestFamily = reported === "envelope-digest-mismatch" || reported === "content-swapped" || reported === "digest-unvouched";
    const seq = typeof verdict.brokenAt === "number" && Number.isFinite(verdict.brokenAt) ? Math.max(0, Math.floor(verdict.brokenAt)) : 0;
    // R5: the KEY-FREE evidence decides whether the key fact may speak for the whole chain. A rotated key cannot
    // touch a content recompute, a parent link or an id sequence, so an unkeyed break is a TAMPER that happened,
    // whatever the key did -- and it is latched at its own seq, under its own cause, beside the key fact.
    const unkeyedCause = typeof unkeyed?.causeClass === "string" && CHAIN_BREAK_CAUSE_SET.has(unkeyed.causeClass) ? (unkeyed.causeClass as ChainBreakCause) : undefined;
    const unkeyedBroken = unkeyed !== undefined && unkeyed.intact === false;
    if (signingKeyRotated === true && digestFamily) {
      latchChainBreak(map, chain, "signing-key-rotated", seq, at);
      if (unkeyedBroken && unkeyedCause !== undefined) {
        const unkeyedSeq = typeof unkeyed.brokenAt === "number" && Number.isFinite(unkeyed.brokenAt) ? Math.max(0, Math.floor(unkeyed.brokenAt)) : 0;
        latchChainBreak(map, chain, unkeyedCause, unkeyedSeq, at);
      }
      return withAnchor(map);
    }
    latchChainBreak(map, chain, reported, seq, at);
    return withAnchor(map);
  });
}

/**
 * latchChainBreak writes ONE break into the latch map, bounded, and re-touches an existing one. Extracted so the
 * recorder can file TWO rows for one pass (a rotated key AND the unkeyed tamper it would otherwise have masked)
 * without duplicating the eviction and re-sighting rules.
 *
 * @param map - the latch map being rewritten.
 * @param chain - which chain.
 * @param cause - the closed cause.
 * @param seq - the clamped broken seq.
 * @param at - the engine-minted stamp.
 */
function latchChainBreak(map: ChainBreakLatches, chain: AuditChain, cause: ChainBreakCause, seq: number, at: string): void {
  // The tuple key carries the CAUSE and the SEQ, so a second, different break cannot fold into the first and
  // vanish (see chainBreakKey).
  const key = chainBreakKey(chain, cause, seq);
  const existing = map[key];
  if (existing === undefined) {
    // Bounded: a pathological chain cannot grow this map without limit. The OLDEST latch on this chain is
    // evicted first, never the newest, so the most recent evidence always survives.
    const onChain = Object.entries(map).filter(([, l]) => l.chain === chain);
    if (onChain.length >= CHAIN_BREAKS_PER_CHAIN) {
      const oldest = onChain.sort((a, b) => a[1].firstDetectedAt.localeCompare(b[1].firstDetectedAt))[0];
      if (oldest !== undefined) delete map[oldest[0]];
    }
    map[key] = { chain, firstDetectedAt: at, lastDetectedAt: at, brokenAtSeq: seq, causeClass: cause, detections: 1 };
    return;
  }
  // The SAME break again. detections now means exactly that -- this break, seen this many times -- because a
  // different break can no longer land here. A re-sighting after a heal re-opens the same latch (the break came
  // back), keeping its original firstDetectedAt: the first sighting is the forensically interesting one.
  const { healedAt: _healed, ...rest } = existing;
  map[key] = { ...rest, lastDetectedAt: at, detections: Math.min(FAULT_COUNT_CAP, existing.detections + 1) };
}

// ---- recoveryResume (G103): what the DR auto-heal SILENTLY dropped, repointed and stripped ---------
//
// After a control-plane wipe the auto-heal replays the signed export. It is deliberately TOLERANT (one
// malformed downpipe must not block the fleet's resume), and every tolerated defect was invisible: a skipped
// downpipe survived only as the integer resumeSkipped, a dangling default destination was silently
// re-pointed at whatever destination happened to be first (backups then land in an UNEXPECTED BUCKET), an
// import validator dropped a WORM/addressing/storage-class/pricing field it did not accept (the customer's
// retention posture quietly vanished), and a staged apply refusal recorded no class at all. This record is
// the per-item truth beside the counters the pack already carries.
export const RESUME_SKIP_CLASSES = [
  "config-invalid", // the exported downpipe config failed the live validators (a schema the current engine no longer accepts)
  "capability-refused", // the replay caller was refused a capability the config's fields require
  "storage-fault", // the re-add threw on storage
  "other", // a throw outside the named classes (never a message)
] as const;
export type ResumeSkipClass = (typeof RESUME_SKIP_CLASSES)[number];

export const IMPORT_DROP_FIELDS = ["worm", "addressing", "storageClass", "pricing"] as const;
export type ImportDropField = (typeof IMPORT_DROP_FIELDS)[number];
const IMPORT_DROP_FIELD_SET: ReadonlySet<string> = new Set(IMPORT_DROP_FIELDS);

export const STAGED_APPLY_REFUSAL_CLASSES = [
  "version-mismatch", // the staged export's filename version and its signed configVersion disagree (a relabelled or replayed artefact): the resume stalls here forever with no recorded reason
  "no-latch", // a resume was attempted with no recovery latch set
  "no-staged", // a resume was attempted with nothing staged
  "refusal-unclassified", // the auto-heal refused and recorded only operator-facing free text, which the pack deliberately does not forward: the pack's refusedCode was EMPTY
] as const;
export type StagedApplyRefusalClass = (typeof STAGED_APPLY_REFUSAL_CLASSES)[number];
const STAGED_APPLY_REFUSAL_SET: ReadonlySet<string> = new Set(STAGED_APPLY_REFUSAL_CLASSES);

export interface ResumeSkipEntry {
  downpipeId: string; // the customer's own downpipe label (clamped 128), the class the pack already carries
  reasonClass: ResumeSkipClass;
  at: string;
}

export interface RecoveryResumeDiag {
  resumeSkips: ResumeSkipEntry[]; // WHICH downpipes never came back, and why
  defaultRepointed: boolean; // the exported default destination did not exist in the imported set, so the default was re-pointed
  reestablishDestIds: string[]; // destinations whose secret was NOT in the export (they cannot ride the recovery until re-entered)
  importFieldDrops: FaultCountAgg; // closed field -> count of imported values a validator refused
  stagedApplyRefusal: { cls: StagedApplyRefusalClass; at: string } | null;
  at: string;
}
export const RESUME_SKIPS_CAP = 32;
export const REESTABLISH_DESTS_CAP = 32;

const EMPTY_RESUME_DIAG: RecoveryResumeDiag = { resumeSkips: [], defaultRepointed: false, reestablishDestIds: [], importFieldDrops: {}, stagedApplyRefusal: null, at: "" };

// classifyResumeSkip REDUCES a tolerated resume throw to a closed class. It reads the message ONLY to select
// an enum member and RETURNS that enum (the classifyCoarseError idiom); the message, which interpolates the
// customer's downpipe id and field values, is never stored.
export function classifyResumeSkip(e: unknown): ResumeSkipClass {
  const name = (e as { name?: unknown } | null)?.name;
  if (name === "AuthError") return "capability-refused";
  const m = e instanceof Error ? e.message : "";
  if (/invalid|must be|required|unsupported|unknown|malformed|not allowed/i.test(m)) return "config-invalid";
  if (/storage|put failed|exceeded/i.test(m)) return "storage-fault";
  return "other";
}

// recordResumeSkip files ONE downpipe the tolerant resume left behind (the "one of my backups never came
// back" ticket, whose id used to survive only as an integer).
export async function recordResumeSkip(storage: LedgerStorage, downpipeId: unknown, reasonClass: ResumeSkipClass): Promise<void> {
  const id = safeLabel(downpipeId);
  if (id === null) return;
  const at = new Date().toISOString();
  await writeLedger<RecoveryResumeDiag>(storage, RECOVERY_RESUME_KEY, "recovery-resume", (prior) => {
    const rec = { ...EMPTY_RESUME_DIAG, ...(prior ?? {}) };
    const skips = [...(Array.isArray(rec.resumeSkips) ? rec.resumeSkips : []), { downpipeId: id, reasonClass, at }];
    return { ...rec, resumeSkips: skips.length > RESUME_SKIPS_CAP ? skips.slice(skips.length - RESUME_SKIPS_CAP) : skips, at };
  });
}

// recordResumeDestinations records the two destination-side facts of a resume: whether the exported DEFAULT
// destination was dangling (so the default was silently re-pointed, which is how "backups land in an
// unexpected bucket" happens), and which destinations came back WITHOUT their secret and so cannot run until
// the operator re-enters it. Destination ids are the customer's own labels (the sourcesDetached class).
export async function recordResumeDestinations(storage: LedgerStorage, f: { defaultRepointed: boolean; reestablishDestIds: readonly unknown[] }): Promise<void> {
  const ids = f.reestablishDestIds.map((d) => safeLabel(d)).filter((d): d is string => d !== null).slice(0, REESTABLISH_DESTS_CAP);
  const at = new Date().toISOString();
  await writeLedger<RecoveryResumeDiag>(storage, RECOVERY_RESUME_KEY, "recovery-resume", (prior) => {
    const rec = { ...EMPTY_RESUME_DIAG, ...(prior ?? {}) };
    return { ...rec, defaultRepointed: f.defaultRepointed === true, reestablishDestIds: ids, at };
  });
}

// recordImportFieldDrop counts ONE imported destination field a validator refused (the customer's WORM
// retention, addressing, storage class or pricing posture, silently stripped by the recovery that was
// supposed to restore it). Field NAMES are a fixed engine vocabulary; the refused VALUE never rides.
export async function recordImportFieldDrop(storage: LedgerStorage, field: ImportDropField): Promise<void> {
  if (!IMPORT_DROP_FIELD_SET.has(field)) return;
  const at = new Date().toISOString();
  await writeLedger<RecoveryResumeDiag>(storage, RECOVERY_RESUME_KEY, "recovery-resume", (prior) => {
    const rec = { ...EMPTY_RESUME_DIAG, ...(prior ?? {}) };
    return { ...rec, importFieldDrops: bumpCount({ ...(rec.importFieldDrops ?? {}) }, field, at), at };
  });
}

// recordStagedApplyRefusal stamps the CLASS of a refused staged apply (or of an auto-heal refusal that
// carried no class), so a recovery that has stalled for weeks finally says why in the pack.
export async function recordStagedApplyRefusal(storage: LedgerStorage, cls: StagedApplyRefusalClass): Promise<void> {
  if (!STAGED_APPLY_REFUSAL_SET.has(cls)) return;
  const at = new Date().toISOString();
  await writeLedger<RecoveryResumeDiag>(storage, RECOVERY_RESUME_KEY, "recovery-resume", (prior) => {
    const rec = { ...EMPTY_RESUME_DIAG, ...(prior ?? {}) };
    return { ...rec, stagedApplyRefusal: { cls, at }, at };
  });
}

// ---- destResolveFallback (G090): the pipe that SILENTLY writes to a destination it was not pinned to ----
//
// THE DATA-LOSS ONE. Three resolvers deviate from configured intent and say nothing: a downpipe whose
// destinationIds list is present but holds only blanks falls through to the legacy single id / the env
// default (primaryDestinationId); a stored collection whose defaultId names a destination that no longer
// exists is HEALED on read to list[0] (loadDestinations), so every unassigned downpipe repoints; and a canary
// pinned to destinations that have all been deleted flies against the default instead (resolveEffectiveDests).
// In each case the run row's destinationId is the destination actually USED, so the pack shows the symptom
// ("my backups are landing in the wrong bucket") with nothing saying the engine chose it rather than the
// customer. These classes ARE that statement.
export const DEST_RESOLVE_FALLBACK_CLASSES = [
  "malformed-list-fallback", // the downpipe's destinationIds held no usable entry: the primary fell back to the legacy destinationId (or, absent that, the env default). The list the operator SET is not the list being written to
  "dangling-default-healed", // the stored collection's defaultId names no live destination and was healed to the first entry on read: every downpipe with no explicit pin now writes somewhere else
  "canary-pin-dangling", // every destination the canary is PINNED to has been deleted, so the flight went to the default: the bird is proving a destination nobody asked it to prove, and the pinned ones are unproven
] as const;
export type DestResolveFallbackClass = (typeof DEST_RESOLVE_FALLBACK_CLASSES)[number];
const DEST_RESOLVE_FALLBACK_SET: ReadonlySet<string> = new Set(DEST_RESOLVE_FALLBACK_CLASSES);

export const DEST_RESOLVE_FALLBACK_KEY = "diag:destfallback";
export const DEST_FALLBACK_RING_CAP = 32;

export interface DestFallbackEntry {
  cls: DestResolveFallbackClass;
  downpipeId: string | null; // the customer's own downpipe label (clamped), or null for an account-wide heal
  at: string;
}
export interface DestResolveFallbackRecord {
  counts: FaultCountAgg; // closed class -> {count,lastAt}: the RATE (a heal that fires on every read is a different fault from one that fired once)
  recent: DestFallbackEntry[]; // newest-last, capped: WHICH downpipes deviated
}

// isMalformedDestList is the PURE predicate behind malformed-list-fallback, unit-testable with no DO: a
// destinationIds ARRAY that is present and non-empty but contains no usable (non-blank string) entry. That is
// exactly the state primaryDestinationId silently falls through on. An absent list is the ordinary
// "follow the default" configuration and is NOT a fault.
export function isMalformedDestList(c: { destinationId?: string; destinationIds?: string[] }): boolean {
  const list = c.destinationIds;
  if (!Array.isArray(list) || list.length === 0) return false;
  return !list.some((x) => typeof x === "string" && x.trim() !== "");
}

// THE THROTTLE (and why it is honest). dangling-default-healed fires inside loadDestinations, which is a HOT
// READ path (every canary view, every dest status read, every seal dispatch): while the default is dangling it
// would fire on every read, so an unthrottled recorder would turn one broken record into a storage write per
// read and would flood the 32-entry ring with one class. So a given class is recorded at most once per
// FALLBACK_THROTTLE_MS per DO isolate. The counter therefore counts DISTINCT ~minute WINDOWS in which the
// fallback fired, not individual reads -- which is the diagnostic question anyway ("is this still happening,
// and since when?"). It can only UNDER-count, never over-count, and lastAt stays exact.
const FALLBACK_THROTTLE_MS = 60_000;
const fallbackThrottle = new WeakMap<LedgerStorage, Map<string, number>>();

function throttled(storage: LedgerStorage, key: string, now: number): boolean {
  let m = fallbackThrottle.get(storage);
  if (m === undefined) {
    m = new Map();
    fallbackThrottle.set(storage, m);
  }
  const last = m.get(key);
  if (last !== undefined && now - last < FALLBACK_THROTTLE_MS) return true;
  m.set(key, now);
  return false;
}

// recordDestResolveFallback stamps ONE resolver deviation. Closed class + the customer's own downpipe label;
// never a bucket, an endpoint, a credential or the destination's configuration.
export async function recordDestResolveFallback(storage: LedgerStorage, cls: DestResolveFallbackClass, downpipeId?: unknown): Promise<void> {
  if (!DEST_RESOLVE_FALLBACK_SET.has(cls)) return;
  const now = Date.now();
  const id = safeLabel(downpipeId);
  if (throttled(storage, `${cls}|${id ?? ""}`, now)) return;
  const at = new Date(now).toISOString();
  await writeLedger<DestResolveFallbackRecord>(storage, DEST_RESOLVE_FALLBACK_KEY, "dest-resolve-fallback", (prior) => {
    const rec: DestResolveFallbackRecord = { counts: { ...(prior?.counts ?? {}) }, recent: Array.isArray(prior?.recent) ? [...prior.recent] : [] };
    bumpCount(rec.counts, cls, at);
    rec.recent.push({ cls, downpipeId: id, at });
    if (rec.recent.length > DEST_FALLBACK_RING_CAP) rec.recent = rec.recent.slice(rec.recent.length - DEST_FALLBACK_RING_CAP);
    return rec;
  });
}

// ---- canaryLosses (G091): the flights that were never flown, and the results that were never read ----
//
// The canary is the known-answer probe that says a destination is still WRITEABLE and READABLE. Its own
// losses were unrecorded: a flight allocated under a lease that then expired (the worker was evicted) is
// silently re-allocated on the next tick, so "lastRunAt keeps sliding" has no cause; a per-destination result
// whose shape the completion handler does not recognise is `continue`d, so that destination's bird FREEZES on
// its last verdict forever; a completion whose whole body is malformed throws past every destination's update;
// and a collection larger than CANARY_MAX_DESTS is TRUNCATED, so the destinations past the cap are never flown
// at all while support reads the canary as total coverage. Counts + the customer's own destination labels.
export const CANARY_LOSS_KINDS = [
  "lost-flight", // a flight was allocated (runIds minted, lease taken) and its completion never arrived within the lease: the flight is abandoned and re-allocated, and nothing said so
  "malformed-completion", // the posted completion had no usable run/results: EVERY destination's liveness update in that flight was lost
  "malformed-result", // ONE destination's result row was unusable and was skipped: that destination's status is frozen on a stale verdict while the aggregate reads healthy
  "dest-excluded-by-cap", // the destination collection is larger than CANARY_MAX_DESTS: the destinations past the cap are NEVER flown (uncoveredDestIds names them)
] as const;
export type CanaryLossKind = (typeof CANARY_LOSS_KINDS)[number];
const CANARY_LOSS_KIND_SET: ReadonlySet<string> = new Set(CANARY_LOSS_KINDS);

export const CANARY_LOSSES_KEY = "diag:canarylosses";
export const CANARY_UNCOVERED_CAP = 16;

export interface CanaryLossRecord {
  counts: FaultCountAgg;
  uncoveredDestIds: string[]; // the destinations the cap excluded from coverage (the customer's own labels, capped)
}

export async function recordCanaryLoss(storage: LedgerStorage, kind: CanaryLossKind, uncoveredDestIds?: readonly unknown[]): Promise<void> {
  if (!CANARY_LOSS_KIND_SET.has(kind)) return;
  const at = new Date().toISOString();
  const uncovered = (uncoveredDestIds ?? []).map((d) => safeLabel(d)).filter((d): d is string => d !== null).slice(0, CANARY_UNCOVERED_CAP);
  await writeLedger<CanaryLossRecord>(storage, CANARY_LOSSES_KEY, "canary-loss", (prior) => {
    const rec: CanaryLossRecord = { counts: { ...(prior?.counts ?? {}) }, uncoveredDestIds: Array.isArray(prior?.uncoveredDestIds) ? prior.uncoveredDestIds : [] };
    bumpCount(rec.counts, kind, at);
    if (uncovered.length > 0) rec.uncoveredDestIds = uncovered; // the CURRENT truncation set, not an accumulation
    return rec;
  });
}

// ---- drillDrops (G059 + G097): the restore-test/fleet-drill pipeline's SILENT discards --------------
//
// The drill pipeline is how a customer proves their backups restore. Every one of its tolerated drops made a
// PASSED drill, a measurement or a whole campaign member disappear with no trace: a completion for a downpipe
// that was renamed/deleted between dispatch and callback returns ok:true and records NOTHING (so the console
// keeps showing the stale verdict); a malformed OOM measurement or deep-verify cursor is ignored, so the
// early-warning and the rotating full-decrypt coverage silently stall; a PASSED restorability proof for a
// deleted downpipe is discarded; a fleet-drill member whose callback never arrives is re-queued FOREVER
// ("stuck at 3 remaining for two days"); a member deleted mid-campaign is counted as a drill FAILURE, which
// alarms the customer about a downpipe that no longer exists. G097 adds the DRILL-EVIDENCE half: the dated
// evidence trail the customer's auditor reads is written best-effort, so an empty trail could not be told from
// "every evidence write has been failing since a route regression".
export const DRILL_DROP_KINDS = [
  "completion-unknown-downpipe", // a restore-test completion named a downpipe this DO no longer holds: the drill RAN and its verdict was dropped
  "malformed-oom", // the drill's OOM-risk measurement was unusable: the isolate-OOM early warning silently stopped advancing
  "malformed-cursor", // the drill's deep-verify cursor was unusable: the rotating full-decrypt coverage stalls on the same window forever
  "proof-dropped", // a PASSED blind-test / keyless attestation could not be stamped (the downpipe was gone): a real proof of restorability was thrown away
  "member-requeued", // a fleet-drill member's completion never arrived within the in-flight timeout and it went back to the worklist (the invisible forever-loop behind "stuck at N remaining")
  "member-deleted-failed", // a fleet-drill member was DELETED between start and dispatch and was counted as a FAILURE so the campaign could converge: a scary red count for a downpipe that does not exist
  "campaign-bookkeeping-failed", // advanceFleetDrill's storage write faulted and was swallowed: the campaign's counts are now short and it may never converge
  "evidence-refused", // G097: a drill-evidence append was REFUSED by validation (a bad runId/kind/note): the dated trail silently has a hole
  "evidence-write-failed", // G097: the drill-evidence append itself FAULTED on storage: the drill happened (downpipes[].lastRestoreTestAt proves it) and its evidence row does not exist
] as const;
export type DrillDropKind = (typeof DRILL_DROP_KINDS)[number];
const DRILL_DROP_KIND_SET: ReadonlySet<string> = new Set(DRILL_DROP_KINDS);

export const DRILL_DROPS_KEY = "diag:drilldrops";

export async function recordDrillDrop(storage: LedgerStorage, kind: DrillDropKind): Promise<void> {
  if (!DRILL_DROP_KIND_SET.has(kind)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, DRILL_DROPS_KEY, "drill-drop", (prior) => bumpCount(prior ?? {}, kind, at));
}

// ---- notifyDrops (G060): WHICH alert died, not just how many ----------------------------------------
//
// notifyHealth carries four integers (passSkips / recordSkips / parseRejects / feedbackFails). The customer's
// question is never "how many alerts were dropped"; it is "MY backup-failure alert never arrived". A rejected
// emission takes its per-channel delivery outcomes with it, so the exact gap the customer is asking about is
// the one thing the pack cannot show. This ring names the dropped alert by the fields the delivered-history
// ring already carries (a closed event name, a closed severity, the customer's own downpipe id) and NOTHING
// else: never the emission's free-text detail and never a channel URL.
export const NOTIFY_DROP_KINDS = [
  "parse-reject", // the emission failed the input-boundary parse (a bad enum, an over-long free-text detail): the alert never routed, and on the recordNotify half an ENTIRE emission's per-channel outcomes were discarded with it
  "record-skip", // one delivery-outcome row was unusable and was skipped: that channel's outcome is missing from the history the customer is reading
  "digest-clear-failed", // a digest-flush clear carried an id the DO could not act on: the delivered entry is NOT cleared, so the SAME success digest is delivered again next window (the "we get the same email twice every hour" ticket)
  "dangling-channel-skip", // a rule selected a channel id that no longer exists: the rule looks armed and routes to nothing
] as const;
export type NotifyDropKind = (typeof NOTIFY_DROP_KINDS)[number];
const NOTIFY_DROP_KIND_SET: ReadonlySet<string> = new Set(NOTIFY_DROP_KINDS);

// The closed severity set (the notify contract's own). Kept local so this ledger stays a leaf; an out-of-set
// value is simply OMITTED from the row (never stored), so a drift can only lose a field, never leak one.
const NOTIFY_SEVERITIES: ReadonlySet<string> = new Set(["info", "warning", "critical"]);

export const NOTIFY_DROPS_KEY = "diag:notifydrops";
export const NOTIFY_DROPS_RING_CAP = 10;

export interface NotifyDropEntry {
  at: string;
  dropKind: NotifyDropKind;
  event?: string; // the CLOSED notify event name, admitted ONLY when the caller proved it is in NOTIFY_EVENT_NAMES
  severity?: string; // the closed severity
  downpipeId?: string; // the customer's own downpipe label (clamped) -- the same class the notify history ring already carries
}
export interface NotifyDropRecord {
  counts: FaultCountAgg; // closed kind -> {count,lastAt}
  recent: NotifyDropEntry[]; // newest-last, capped: WHICH alerts died
}

// recordNotifyDrop files ONE dropped alert. `event` is admitted ONLY when the CALLER has already proved it a
// member of the notify contract's closed event vocabulary and passes eventKnown:true (the DO mixin owns that
// vocabulary; duplicating it here would be a second copy to drift). Everything else is a closed enum, a
// clamped label, or nothing: the emission's free-text detail is never passed in and can never be stored.
export async function recordNotifyDrop(
  storage: LedgerStorage,
  dropKind: NotifyDropKind,
  ctx?: { event?: string; eventKnown?: boolean; severity?: unknown; downpipeId?: unknown },
): Promise<void> {
  if (!NOTIFY_DROP_KIND_SET.has(dropKind)) return;
  const at = new Date().toISOString();
  const event = ctx?.eventKnown === true && typeof ctx.event === "string" && ctx.event.length > 0 && ctx.event.length <= 64 ? ctx.event : undefined;
  const severity = typeof ctx?.severity === "string" && NOTIFY_SEVERITIES.has(ctx.severity) ? ctx.severity : undefined;
  const downpipeId = safeLabel(ctx?.downpipeId) ?? undefined;
  // A drop with NO identifying alert (a digest clear that could not act on its id, a dangling channel ref) is a
  // RATE, not a casualty: it bumps the count and does NOT push a ring row. That keeps a permanently-broken
  // config -- which fires on every single emission -- from flooding the 10-row ring and evicting the named
  // casualties, which are the rows the ring exists to carry.
  const nameable = event !== undefined || severity !== undefined || downpipeId !== undefined;
  const entry: NotifyDropEntry = { at, dropKind, ...(event !== undefined ? { event } : {}), ...(severity !== undefined ? { severity } : {}), ...(downpipeId !== undefined ? { downpipeId } : {}) };
  await writeLedger<NotifyDropRecord>(storage, NOTIFY_DROPS_KEY, "notify-drop", (prior) => {
    const rec: NotifyDropRecord = { counts: { ...(prior?.counts ?? {}) }, recent: Array.isArray(prior?.recent) ? [...prior.recent] : [] };
    bumpCount(rec.counts, dropKind, at);
    if (!nameable) return rec;
    rec.recent.push(entry);
    if (rec.recent.length > NOTIFY_DROPS_RING_CAP) rec.recent = rec.recent.slice(rec.recent.length - NOTIFY_DROPS_RING_CAP);
    return rec;
  });
}

// ---- governanceFaults (G034): the dual-control / change-control apply attempts that leave no trace ----
//
// A pending change or owner action that will not apply is the single most frustrating governance ticket: the
// record just SITS there, "approved", and the pack shows the propose/approve events and nothing else. The
// failed apply attempts, their causes, and (security-significant) a detected stored-record TAMPER or a REPLAYED
// one-shot approval were seen only by the approver's browser. Closed stage x closed outcome, so a foreseeable
// refusal (a guard said no) is never confused with an unexpected fault (the mutation threw).
export const GOVERNANCE_STAGES = ["change-approve", "change-apply", "owner-action-approve", "owner-action-execute", "dry-run"] as const;
export type GovernanceStage = (typeof GOVERNANCE_STAGES)[number];
const GOVERNANCE_STAGE_SET: ReadonlySet<string> = new Set(GOVERNANCE_STAGES);

export const GOVERNANCE_OUTCOME_CLASSES = [
  "integrity-failed", // the STORED record did not match its own integrity tag: a tamper (or a storage corruption) on the governance record itself. The single most security-significant member here
  "replay-detected", // a one-shot approval was presented twice: the second presentation was refused. "The same approval seems to have authorised two applies" is the ticket this exists to answer
  "guard-refused", // a FORESEEABLE refusal: a guard (maker!=checker, last-owner, capability, expiry) said no. The change is fine; the attempt was not allowed
  "apply-faulted", // an UNEXPECTED fault: the validated mutation itself threw when replayed. The approval is good and the engine cannot honour it -- a bug, not a policy
  "expired", // the record's approval TTL lapsed before the apply
] as const;
export type GovernanceOutcomeClass = (typeof GOVERNANCE_OUTCOME_CLASSES)[number];
const GOVERNANCE_OUTCOME_SET: ReadonlySet<string> = new Set(GOVERNANCE_OUTCOME_CLASSES);

export function governanceFaultKey(stage: GovernanceStage, cls: GovernanceOutcomeClass): string {
  return `${stage}|${cls}`;
}

export const GOVERNANCE_FAULTS_KEY = "diag:governancefaults";

// classifyGovernanceOutcome reduces an apply/approve throw to a closed outcome class. It reads the message
// ONLY to select an enum member and RETURNS that member (the classifyCoarseError idiom); the guard's
// operator-facing prose -- which interpolates emails, ids and params -- is never stored.
export function classifyGovernanceOutcome(e: unknown): GovernanceOutcomeClass {
  const name = (e as { name?: unknown } | null)?.name;
  const m = e instanceof Error ? e.message : "";
  if (/integrity|tamper|does not match its recorded/i.test(m)) return "integrity-failed";
  if (/replay|already (applied|consumed|used)/i.test(m)) return "replay-detected";
  if (/expired|lapsed/i.test(m)) return "expired";
  // WORD-BOUNDARY anchors are load-bearing here. An unanchored /refus/i matches inside ECONNREFUSED, so a
  // transport fault would be filed as a POLICY refusal -- the exact opposite diagnosis (blame the customer's
  // approver rather than the engine). The validate suite plants a connect-refused message to pin this.
  if (name === "AuthError" || /\bforbidden\b|\bnot allowed\b|\bcannot\b|\bmust be\b|\brefus/i.test(m) || /\bapprover\b|\bmaker\b|\blast Owner\b/i.test(m)) return "guard-refused";
  return "apply-faulted";
}

export async function recordGovernanceFault(storage: LedgerStorage, stage: GovernanceStage, cls: GovernanceOutcomeClass): Promise<void> {
  if (!GOVERNANCE_STAGE_SET.has(stage) || !GOVERNANCE_OUTCOME_SET.has(cls)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, GOVERNANCE_FAULTS_KEY, "governance-fault", (prior) => bumpCount(prior ?? {}, governanceFaultKey(stage, cls), at));
}

// ---- governanceRefusals (G182): the REASON, which "guard-refused" erases -----------------------------------
//
// THE GAP, and why governanceFaults above does NOT close it. That aggregate has exactly one member for every
// foreseeable refusal: `guard-refused` ("a guard said no"). But the ticket is never "a guard said no" -- the
// ticket is "my APPROVED restore refuses to apply" or "the console demands a change number I already entered",
// and the four or five states behind each of those have completely different remedies:
//
//   expired            raise a new request                          |  self-approval    get a SECOND person
//   consumed           the approval was already spent (a retry)     |  applying-lease   an apply is IN FLIGHT
//   base-moved         the config changed under the approver        |  bare-token       sign in properly
//   change-ref-garbled the console's header did not decode          |  change-ref-missing nothing was attached
//
// Every one of them folded into `guard-refused`, and the human-readable reason (which DOES distinguish them)
// is deliberately never persisted -- it interpolates e-mails, ids and parameters, so it cannot ride in the
// pack. Recording a GENERIC fault where the ticket needs a DISCRIMINATOR is a subtler kind of dead evidence:
// the recorder exists, the caller exists, the field is in the bundle, and the ticket is still unanswerable.
//
// So the pure decision helpers (approvals.ts, change-control.ts, owner-action.ts, change-ref.ts) now return a
// closed reasonCode ALONGSIDE their operator prose, and this aggregate keeps the {stage, reason} tally. The
// prose is unchanged and still never stored.
//
// NO-CUSTODY: a closed stage, a closed reason, an int count and an ISO timestamp. No approver, no proposer, no
// e-mail, no id, no change number, no parameter.

// GOVERNANCE_REFUSAL_STAGES extends the fault stages with the two surfaces that had NO fault recorder at all:
// the restore dual-control approve/apply gate, the change-number policy check, and the custom-role escalation
// bar (an attempted privilege escalation that left no evidence either way).
export const GOVERNANCE_REFUSAL_STAGES = [
  "restore-approve", // POST /restore/approve: the second owner's approval of a restore
  "restore-reject", // POST /restore/reject: the VETO of a live restore. Its own stage, because a refused veto ("we tried to stop the restore and the reject kept failing while the apply went through") is the highest-signal event this machine produces, and borrowing restore-approve's stage put it on the SAME key as a refused approval
  "restore-apply", // POST /restore: the apply gate over the approval record. Written by gateRestore, which is the FIRST approval check the apply makes and the one whose flat 403 the operator sees
  "prune-apply", // POST /retention-prune/apply: the apply gate over the PRUNE approval record. Its own stage, not restore-apply's: a prune apply deletes the archive itself, so "our approved prune refuses to run" and "our approved restore refuses to run" are different incidents with different remedies and must never coalesce onto one key
  "change-approve", // the config-change dual-control approval
  "change-apply", // the config-change apply
  "owner-action-approve", // the owner-action dual-control approval
  "owner-action-execute", // the owner-action execute (the armed approval being spent)
  "change-ref", // the "Require Change Number" policy gate (change-ref.ts)
  "role-escalation", // a custom role that tried to grant a capability its creator does not hold, or an owner-reserved one
] as const;
export type GovernanceRefusalStage = (typeof GOVERNANCE_REFUSAL_STAGES)[number];
const GOVERNANCE_REFUSAL_STAGE_SET: ReadonlySet<string> = new Set(GOVERNANCE_REFUSAL_STAGES);

// GOVERNANCE_REFUSAL_REASONS is the closed WHY. Each member is one remedy.
export const GOVERNANCE_REFUSAL_REASONS = [
  "no-such-request", // there is NO approval record for this plan hash at all: nobody raised it, or the plan hash moved under the operator (a re-planned restore is a different plan). Distinct from `pending`, which is a record that exists and was never approved
  "expired", // the request's TTL lapsed before it was approved or applied: raise a new one
  "consumed", // the approval was ALREADY spent. The retry of an apply that worked looks exactly like this
  "pending", // the record is still merely REQUESTED: it was never approved (the console may be showing a stale badge)
  "applying-lease", // another apply is IN FLIGHT against this same approval (the reservation lease). A concurrent-apply refusal, which reads to the operator as a flat "no"
  "self-approval", // maker == checker on the stable subject: the same person raised and approved it
  "bare-token", // the caller is the shared break-glass token, which carries no attributable identity and can never be a second approver
  "missing-approver", // the record carries no checker subject at all (it was never really approved)
  "maker-authority-lapsed", // the identity that RAISED this request no longer holds the capability to raise it: the approval was armed by somebody who has since been removed, demoted or had their grant lapse. Remedy: somebody still authorised raises the plan again (a re-approval alone does not help, because the MAKER is the axis that failed)
  "checker-authority-lapsed", // the identity that APPROVED this request no longer holds the capability to approve it, so the approval is no longer backed by a second authorised identity. Remedy: an approver who still holds it approves the plan again (the request itself is fine)
  "no-capability", // the approver does not hold the write capability the change itself requires
  "not-owner", // only an Owner may approve this class of action
  "base-moved", // the config head moved under the approver: the diff they reviewed is stale, so the change is superseded
  "hash-mismatch", // the stored record does not match its own integrity tag (or its recomputed action hash): tamper, or storage corruption
  "terminal-state", // the record is already applied / rejected / superseded / executed: there is nothing left to decide
  "change-ref-missing", // "Require Change Number" is ON and NO reference was supplied at all
  "change-ref-garbled", // a reference WAS supplied and the X-Downpipes-Change header did not decode (bad base64url, bad JSON). "I already entered a change number" -- and the engine never saw it
  "change-ref-truncated", // a reference decoded and NORMALISED TO NOTHING (all control characters, or whitespace only), so the policy refused a number the operator believes they typed
  "change-ref-over-length", // a reference decoded and carried a change NUMBER longer than the cap. The engine REFUSES the request (400) rather than trimming it: a trimmed reference still looks like a change number and matches nothing in the customer's change-management system
  "change-ref-no-justification", // an EMERGENCY change was raised with no justification, which the policy requires
  "escalation-refused", // a custom role tried to grant a capability its creator does not hold: a privilege-escalation attempt, refused
  "owner-reserved", // a custom role tried to include an owner-reserved capability, which can never enter one
] as const;
export type GovernanceRefusalReason = (typeof GOVERNANCE_REFUSAL_REASONS)[number];
const GOVERNANCE_REFUSAL_REASON_SET: ReadonlySet<string> = new Set(GOVERNANCE_REFUSAL_REASONS);

export function governanceRefusalKey(stage: GovernanceRefusalStage, reason: GovernanceRefusalReason): string {
  return `${stage}|${reason}`;
}

export const GOVERNANCE_REFUSALS_KEY = "diag:governancerefusals";

/**
 * recordGovernanceRefusal bumps the {stage|reason} tally. Both members are re-checked against their closed set
 * (an out-of-vocabulary value records NOTHING rather than widening the key space), so this is the single
 * redaction chokepoint for the aggregate: nothing but two enum members and a timestamp can enter it.
 *
 * @param storage - the DO storage.
 * @param stage - the closed governance surface that refused.
 * @param reason - the closed reason it refused.
 */
export async function recordGovernanceRefusal(storage: LedgerStorage, stage: GovernanceRefusalStage, reason: GovernanceRefusalReason): Promise<void> {
  if (!GOVERNANCE_REFUSAL_STAGE_SET.has(stage) || !GOVERNANCE_REFUSAL_REASON_SET.has(reason)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, GOVERNANCE_REFUSALS_KEY, "governance-refusal", (prior) => bumpCount(prior ?? {}, governanceRefusalKey(stage, reason), at));
}

// ---- refusalRings (G037): the last-only counters that collapse five causes into one ------------------
//
// Three surfaces keep a {count, lastAt, lastCode} tally. A customer who retried a licence activation five
// times with THREE different causes reads as count=5 and one code -- and the last code is the one they got
// RIGHT before giving up, i.e. the least informative one. A small bounded ring of {at, code} per surface
// makes the SEQUENCE readable, which is what actually diagnoses these ("expired, expired, wrong-signer" is a
// different story from "malformed, malformed, malformed"). Closed surfaces; the code is the surface's own
// engine-set closed code, clamped, never a token, a reference string or an error message.
export const REFUSAL_SURFACES = [
  "licence-activation", // POST /admin/licence refusals (incl. the DO-side shape reject that used to bypass the counter entirely)
  "change-control", // a change-number-required refusal, by the action kind it refused
  "config-snapshot", // an auto-snapshot that FAILED, by its closed failure class (a config change that was never versioned)
] as const;
export type RefusalSurface = (typeof REFUSAL_SURFACES)[number];
const REFUSAL_SURFACE_SET: ReadonlySet<string> = new Set(REFUSAL_SURFACES);

// The closed config-snapshot failure classes (G037): the root cause used to live only in Workers Logs.
export const SNAPSHOT_FAILURE_CLASSES = [
  "signing-key", // the config-history signing key could not be loaded/imported: NO config change can ever be versioned until it is fixed
  "storage", // the snapshot write itself faulted
  "shape", // the config could not be canonicalised into a snapshot (a producer/consumer drift)
] as const;
export type SnapshotFailureClass = (typeof SNAPSHOT_FAILURE_CLASSES)[number];

// classifySnapshotFailure reads the throw ONLY to select a closed class and returns it; the message never rides.
export function classifySnapshotFailure(e: unknown): SnapshotFailureClass {
  const m = e instanceof Error ? e.message : "";
  if (/key|sign|import|CryptoKey|SIGNER/i.test(m)) return "signing-key";
  if (/storage|put|exceeded|limit/i.test(m)) return "storage";
  return "shape";
}

export const REFUSAL_RINGS_KEY = "diag:refusalrings";
export const REFUSAL_RING_CAP = 20;
// The code clamp. Every code written here is an ENGINE-SET closed member (a licence reason code, an engine
// action kind, a snapshot failure class), so the clamp is defence in depth, not the redaction boundary.
const REFUSAL_CODE_MAX = 64;

export interface RefusalRingEntry {
  at: string;
  code: string; // the surface's own engine-set closed code
}
export type RefusalRings = Record<string, RefusalRingEntry[]>;

// recordRefusal appends ONE refusal to its surface's bounded ring. The surface is closed-set validated (so no
// caller-derived string can become a storage key) and the code is control-stripped + clamped.
export async function recordRefusal(storage: LedgerStorage, surface: RefusalSurface, code: unknown): Promise<void> {
  if (!REFUSAL_SURFACE_SET.has(surface)) return;
  const at = new Date().toISOString();
  const c = typeof code === "string" && code.length > 0 ? stripLedgerControls(code).slice(0, REFUSAL_CODE_MAX) : "";
  if (c === "") return;
  await writeLedger<RefusalRings>(storage, REFUSAL_RINGS_KEY, "refusal-ring", (prior) => {
    const rings: RefusalRings = { ...(prior ?? {}) };
    const ring = Array.isArray(rings[surface]) ? [...rings[surface]] : [];
    ring.push({ at, code: c });
    rings[surface] = ring.length > REFUSAL_RING_CAP ? ring.slice(ring.length - REFUSAL_RING_CAP) : ring;
    return rings;
  });
}

// ---- alertingHealth (G188): the alerting pipeline's own health ----------------------------------
//
// The alerting pipeline is the thing a customer trusts to tell them their backups broke, and its OWN health
// was invisible. Every member here is a way the pipeline goes quiet WITHOUT any evidence:
//   detection-off-no-sink        both reconcile passes SHORT-CIRCUIT to an empty batch when there is no
//                                notify channel at all. Delete your last channel and detection silently
//                                stops -- "why did no staleness alert ever fire".
//   cron-deadman-tripped         the alarm-driven dead-man DETECTED the cron was dead and stood in for it,
//                                and recorded nothing. This is the pack's cron-driver-silent signal.
//   deadman-sweep-fault          a fault INSIDE the backstop itself hit a bare catch.
//   undeliverable-alert-batch    a batch was generated and reached NO sink. The env-free dead-man holds no
//                                channel adapter, so during a cron outage the batch it detects is DISCARDED
//                                and the customer gets zero pages; nothing else says so.
//   abandoned-recovery-resolve   an owed auto-resolve aged out past the retry window and its marker was
//                                DELETED -- "the incident never auto-closed even though the backup recovered".
//   alarm-rearm-skipped-corrupt  a corrupt due-index key made rearmAlarm return WITHOUT setting an alarm, so
//                                the alarm chain (and with it the dead-man) stops entirely.
export const ALERTING_HEALTH_EVENTS = [
  "detection-off-no-sink",
  "cron-deadman-tripped",
  "deadman-sweep-fault",
  "undeliverable-alert-batch",
  "abandoned-recovery-resolve",
  "alarm-rearm-skipped-corrupt-key",
] as const;
export type AlertingHealthEvent = (typeof ALERTING_HEALTH_EVENTS)[number];
const ALERTING_HEALTH_EVENT_SET: ReadonlySet<string> = new Set(ALERTING_HEALTH_EVENTS);

export const ALERTING_HEALTH_KEY = "diag:alertinghealth";

export async function recordAlertingHealth(storage: LedgerStorage, event: AlertingHealthEvent, by = 1): Promise<void> {
  if (!ALERTING_HEALTH_EVENT_SET.has(event)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, ALERTING_HEALTH_KEY, "alerting-health", (prior) => bumpCount(prior ?? {}, event, at, by));
}

// ---- auditEgress (G323): the SIEM audit feed's own health ----------------------------------------
//
// Two ways the customer's SIEM stops seeing the audit trail, both invisible engine-side:
//   mirror-failure   mirrorAuditEvent's structured-log emission (the Logpush/SIEM PUSH leg) throws and is
//                    swallowed by design so the audit COMMIT is never affected. Correct -- and silent.
//   gap-page         the PULL feed served a forward page whose cursor sits BELOW the oldest retained entry:
//                    the events between were rolled over and that collector will NEVER receive them. The gap
//                    signal existed only in the HTTP response to the customer's own collector.
export interface AuditEgressHealth {
  mirrorFailures: { count: number; lastAt: string } | null;
  gapPagesServed: { count: number; lastAt: string; lastGapBeforeSeq: number } | null;
}
export const AUDIT_EGRESS_KEY = "diag:auditegress";

export async function recordAuditMirrorFailure(storage: LedgerStorage): Promise<void> {
  const at = new Date().toISOString();
  await writeLedger<AuditEgressHealth>(storage, AUDIT_EGRESS_KEY, "audit-egress", (prior) => ({
    mirrorFailures: { count: Math.min(FAULT_COUNT_CAP, (prior?.mirrorFailures?.count ?? 0) + 1), lastAt: at },
    gapPagesServed: prior?.gapPagesServed ?? null,
  }));
}

// recordAuditGapPage records a served feed page that IMPLIES pruned-undelivered events. earliestSeq is an
// engine-minted monotonic sequence number, clamped: it is not customer data and carries no event content.
export async function recordAuditGapPage(storage: LedgerStorage, earliestSeq: unknown): Promise<void> {
  const at = new Date().toISOString();
  const seq = typeof earliestSeq === "number" && Number.isFinite(earliestSeq) ? Math.max(0, Math.min(FAULT_COUNT_CAP, Math.floor(earliestSeq))) : 0;
  await writeLedger<AuditEgressHealth>(storage, AUDIT_EGRESS_KEY, "audit-egress", (prior) => ({
    mirrorFailures: prior?.mirrorFailures ?? null,
    gapPagesServed: { count: Math.min(FAULT_COUNT_CAP, (prior?.gapPagesServed?.count ?? 0) + 1), lastAt: at, lastGapBeforeSeq: seq },
  }));
}

// capTruncations (G325) now lives in sched-fault-core.ts, one layer down, because the freshnessFaults cap is
// itself a truncating surface and its recorder is in core: a core recorder cannot import from this file
// without a cycle. `export * from "./sched-fault-core.ts"` above re-exports the whole block, so every import
// site (three DO mixins, the pack projector and the gap-evidence validator) is unchanged.

// ---- posture (G334): the security-centre evaluation the pack never carried ------------------------
//
// The Security Centre's verdicts drive real customer action ("retire the break-glass token", "admin-strong-auth
// cannot be verified"), and NONE of it is in the pack: not the last evaluation, not the overrides, and not the
// INPUT FAULTS that make a check read cannot-verify. So a dropped IDP_KV binding (a permanent, one-line fix)
// reads exactly like a transient blip, a version-skewed status slice produces a SPURIOUS regression, and a real
// WORM misconfiguration is flattened to "not configured".
//
// The input-fault classes are the three ways a posture input arrives unusable. The override projection carries
// the closed check id + the closed override KIND; the free-text justification the owner wrote deliberately
// STAYS DO-side and never enters the bundle.
export const POSTURE_INPUT_FAULTS = [
  "identity-read-failed", // gatherPostureIdentity threw (a dropped IDP_KV binding, a storage fault) -> admin-strong-auth abstains
  "status-slice-malformed", // the router-forwarded env presence slice was absent/garbled -> every status-derived check reads its WORST-POSTURE default
  "worm-slice-malformed", // a WORM slice was forwarded but unusable -> the immutability check flattens to not-configured
] as const;
export type PostureInputFault = (typeof POSTURE_INPUT_FAULTS)[number];
const POSTURE_INPUT_FAULT_SET: ReadonlySet<string> = new Set(POSTURE_INPUT_FAULTS);

export const POSTURE_INPUT_FAULTS_KEY = "diag:postureinputfaults";

export async function recordPostureInputFault(storage: LedgerStorage, fault: PostureInputFault): Promise<void> {
  if (!POSTURE_INPUT_FAULT_SET.has(fault)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, POSTURE_INPUT_FAULTS_KEY, "posture-input-fault", (prior) => bumpCount(prior ?? {}, fault, at));
}

// The pack-side posture projection. `checks` is the stored regression snapshot (closed check ids + a boolean +
// a closed severity -- already redaction-safe by construction, posture.ts owns that contract). `overrides`
// carries the closed check id + the closed override kind + the time; the REASON TEXT is dropped here, which is
// the single chokepoint that keeps it out of the bundle.
export interface PostureDiagOverride {
  checkId: string;
  overrideKind: string;
  at: string;
}
export interface PostureDiag {
  lastEvaluatedAt: string | null;
  checks: { id: string; passed: boolean; severity: string }[];
  overrides: PostureDiagOverride[];
  inputFaults: FaultCountAgg;
  // attendedCadenceDays is the estate's STATED attended-verification interval in whole days, 0 when none is
  // stated. It is here because "attended-verification-cadence: failed" is uninterpretable without it: failed
  // against WHAT? A support engineer reading the pack can otherwise see the verdict and not the target, which
  // is the same omission the restore-tests report had before it carried the interval.
  //
  // One integer. It names no downpipe and carries no proof history, so it adds nothing to the pack's
  // disclosure surface.
  attendedCadenceDays: number;
}
export const POSTURE_OVERRIDES_CAP = 64;
const POSTURE_CHECKS_CAP = 64;

// readPostureDiag projects the DO's posture snapshot + overrides + input faults. The override list is read
// through storage.list (optional on LedgerStorage, so a Map-backed test fake without it degrades to an empty
// list rather than throwing). Every field is re-clamped HERE, so this function -- not its callers -- is the
// redaction chokepoint for the posture section.
export async function readPostureDiag(storage: LedgerStorage): Promise<PostureDiag> {
  const inputFaults = (await storage.get<FaultCountAgg>(POSTURE_INPUT_FAULTS_KEY)) ?? {};
  // The stated interval, re-clamped HERE like every other field, because this function is the redaction
  // chokepoint for the posture section. A non-number, a negative or a non-integer all read as 0 (no stated
  // rhythm), which is the same normalisation the oracle, the check and the report apply, so all four agree.
  const policy = (await storage.get<{ attendedCadenceDays?: unknown }>("orgpolicy")) ?? null;
  const rawCadence = policy?.attendedCadenceDays;
  const attendedCadenceDays = typeof rawCadence === "number" && Number.isFinite(rawCadence) && rawCadence > 0 ? Math.floor(rawCadence) : 0;
  const snap = (await storage.get<{ at?: unknown; checks?: unknown }>("posture-snapshot")) ?? null;
  const checks: { id: string; passed: boolean; severity: string }[] = [];
  if (snap !== null && Array.isArray(snap.checks)) {
    for (const c of (snap.checks as { id?: unknown; passed?: unknown; severity?: unknown }[]).slice(0, POSTURE_CHECKS_CAP)) {
      if (typeof c?.id !== "string") continue;
      checks.push({
        id: stripLedgerControls(c.id).slice(0, 64),
        passed: c.passed === true,
        severity: typeof c.severity === "string" ? stripLedgerControls(c.severity).slice(0, 16) : "unknown",
      });
    }
  }
  const overrides: PostureDiagOverride[] = [];
  if (typeof storage.list === "function") {
    try {
      const map = await storage.list<{ checkId?: unknown; kind?: unknown; at?: unknown }>({ prefix: "posture-accept:" });
      for (const rec of [...map.values()].slice(0, POSTURE_OVERRIDES_CAP)) {
        if (typeof rec?.checkId !== "string") continue;
        overrides.push({
          checkId: stripLedgerControls(rec.checkId).slice(0, 64),
          // The legacy record (written before override kinds existed) carries no kind and means risk-accepted.
          overrideKind: typeof rec.kind === "string" && rec.kind !== "" ? stripLedgerControls(rec.kind).slice(0, 32) : "risk-accepted",
          at: typeof rec.at === "string" ? stripLedgerControls(rec.at).slice(0, 32) : "",
        });
      }
    } catch {
      /* best-effort: an unreadable override set leaves the list empty, never a thrown pack build */
    }
  }
  return {
    lastEvaluatedAt: snap !== null && typeof snap.at === "string" ? stripLedgerControls(snap.at).slice(0, 32) : null,
    checks,
    overrides,
    inputFaults,
    attendedCadenceDays,
  };
}

// ---- the single read path the support pack projects ----------------------------------------------

export interface SchedDiagBundle {
  ceremonyFaults: FaultCountAgg;
  recentErrors: RecentErrorEntry[];
  contractFaults: FaultCountAgg;
  droppedWrites: FaultCountAgg;
  defaultDestination: DefaultDestHealth | null;
  freshnessFaults: FreshnessFaults;
  vocabDrops: FaultCountAgg; // G092
  expiryObserveFaults: FaultCountAgg; // G093
  approvalFaults: FaultCountAgg; // G094
  storageAnomalies: FaultCountAgg; // G105
  rosterDiscards: RosterDiscardEntry[]; // G105
  chainBreaks: ChainBreakLatches; // G313: the tamper verdict a rollover would otherwise erase
  testOutcomes: TestOutcomes; // G246: every Test button's outcome, which used to die with the browser tab
  recoveryResume: RecoveryResumeDiag | null; // G103
  destResolveFallbacks: DestResolveFallbackRecord | null; // G090
  canaryLosses: CanaryLossRecord | null; // G091
  drillDrops: FaultCountAgg; // G059 + G097
  notifyDrops: NotifyDropRecord | null; // G060
  governanceFaults: FaultCountAgg; // G034
  governanceRefusals: FaultCountAgg; // G182: the closed REASON behind a governance refusal, which guard-refused erases
  refusalRings: RefusalRings; // G037
  adminRefusals: FaultCountAgg; // G146 + G126
  clientDiagnostics: ClientDiagnostics | null; // G172/G173/G174/G176/G178/G181 + G097's console half
  configRejections: FaultCountAgg; // G139 + G141: surface|reason -> {count,lastAt}
  authzRefusals: FaultCountAgg; // G187 + G249: gate -> {count,lastAt}
  alertingHealth: FaultCountAgg; // G188: closed event -> {count,lastAt}
  configCoercions: FaultCountAgg; // G297: surface|dropClass -> {count = dropped items, lastAt}
  auditEgress: AuditEgressHealth | null; // G323
  capTruncations: FaultCountAgg; // G325: surface -> {count = dropped rows, lastAt}
  capTruncationSubjects: CapTruncationSubjects; // G325: surface -> WHICH subjects were dropped, and whether any could not be named
  posture: PostureDiag; // G334
}

// readSchedDiag returns the whole ledger in ONE read for the support pack (GET /sched-diag). Redaction-safe by
// construction: closed-enum keys, integer counts, clamped timestamps, opaque error ids and the customer's own
// downpipe labels. Any pending in-memory dropped writes are folded first, so the pack's under-count caveat is
// current at the moment the bundle is generated.
export async function readSchedDiag(storage: LedgerStorage): Promise<SchedDiagBundle> {
  await flushDroppedWrites(storage);
  return {
    ceremonyFaults: (await storage.get<FaultCountAgg>(CEREMONY_FAULTS_KEY)) ?? {},
    recentErrors: (await storage.get<RecentErrorEntry[]>(RECENT_ERRORS_KEY)) ?? [],
    contractFaults: (await storage.get<FaultCountAgg>(CONTRACT_FAULTS_KEY)) ?? {},
    droppedWrites: (await storage.get<FaultCountAgg>(DROPPED_WRITES_KEY)) ?? {},
    defaultDestination: (await storage.get<DefaultDestHealth>(DEFAULT_DEST_HEALTH_KEY)) ?? null,
    freshnessFaults: (await storage.get<FreshnessFaults>(FRESHNESS_FAULTS_KEY)) ?? {},
    vocabDrops: (await storage.get<FaultCountAgg>(VOCAB_DROPS_KEY)) ?? {},
    expiryObserveFaults: (await storage.get<FaultCountAgg>(EXPIRY_OBSERVE_FAULTS_KEY)) ?? {},
    approvalFaults: (await storage.get<FaultCountAgg>(APPROVAL_FAULTS_KEY)) ?? {},
    storageAnomalies: (await storage.get<FaultCountAgg>(STORAGE_ANOMALIES_KEY)) ?? {},
    rosterDiscards: (await storage.get<RosterDiscardEntry[]>(ROSTER_DISCARDS_KEY)) ?? [],
    chainBreaks: (await storage.get<ChainBreakLatches>(CHAIN_BREAKS_KEY)) ?? {},
    testOutcomes: (await storage.get<TestOutcomes>(TEST_OUTCOMES_KEY)) ?? {},
    recoveryResume: (await storage.get<RecoveryResumeDiag>(RECOVERY_RESUME_KEY)) ?? null,
    destResolveFallbacks: (await storage.get<DestResolveFallbackRecord>(DEST_RESOLVE_FALLBACK_KEY)) ?? null,
    canaryLosses: (await storage.get<CanaryLossRecord>(CANARY_LOSSES_KEY)) ?? null,
    drillDrops: (await storage.get<FaultCountAgg>(DRILL_DROPS_KEY)) ?? {},
    notifyDrops: (await storage.get<NotifyDropRecord>(NOTIFY_DROPS_KEY)) ?? null,
    governanceFaults: (await storage.get<FaultCountAgg>(GOVERNANCE_FAULTS_KEY)) ?? {},
    governanceRefusals: (await storage.get<FaultCountAgg>(GOVERNANCE_REFUSALS_KEY)) ?? {},
    refusalRings: (await storage.get<RefusalRings>(REFUSAL_RINGS_KEY)) ?? {},
    adminRefusals: (await storage.get<FaultCountAgg>(ADMIN_REFUSALS_KEY)) ?? {},
    clientDiagnostics: (await storage.get<ClientDiagnostics>(CLIENT_DIAG_KEY)) ?? null,
    configRejections: (await storage.get<FaultCountAgg>(CONFIG_REJECTIONS_KEY)) ?? {},
    authzRefusals: (await storage.get<FaultCountAgg>(AUTHZ_REFUSALS_KEY)) ?? {},
    alertingHealth: (await storage.get<FaultCountAgg>(ALERTING_HEALTH_KEY)) ?? {},
    configCoercions: (await storage.get<FaultCountAgg>(CONFIG_COERCIONS_KEY)) ?? {},
    auditEgress: (await storage.get<AuditEgressHealth>(AUDIT_EGRESS_KEY)) ?? null,
    capTruncations: (await storage.get<FaultCountAgg>(CAP_TRUNCATIONS_KEY)) ?? {},
    capTruncationSubjects: (await storage.get<CapTruncationSubjects>(CAP_TRUNCATION_SUBJECTS_KEY)) ?? {},
    posture: await readPostureDiag(storage),
  };
}
