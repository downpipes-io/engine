// OPT-IN dual-control change control for CONFIG mutations. When the org setting requireConfigApproval
// is OFF (the default), this module is never reached and config applies inline exactly as before. When
// it is ON, a config mutation is VALIDATED at propose time (so a bad or unauthorised request is rejected
// then, not deferred) but, instead of committing the state write, a PENDING CHANGE REQUEST is recorded;
// a SECOND authorised identity (maker != checker, holding the same write capability) must approve before
// the SAME validated mutation logic is replayed and applied. This is the config-mutation analogue of the
// restore dual control (approvals.ts): this module owns the pending-record shape, the content-binding
// hash a change is keyed to, the maker != checker rule, the write-capability-per-kind map, and the
// supersede check; the scheduler Durable Object holds the records (the single storage authority) and
// drives this pure logic, so the propose, the approve and the apply can never compute the binding or the
// authority two different ways.
//
// THE BINDING (maker != checker, no stale/superseded apply). A pending change is keyed by a fresh id and
// carries a contentHash over its DECISION-RELEVANT inputs: the mutation KIND, its canonical PARAMS, and
// the config-history HEAD VERSION it was computed against (the pre-image head id + that version's content
// hash). The approve path re-derives the same hash AND re-reads the current head: if either the params
// changed (a tampered record) or the head config moved since the proposal (a concurrent config change, so
// the diff the approver reviewed is stale), the approve is refused as superseded and a re-proposal is
// required. This is the TOCTOU defence: the approver approves the EXACT change they reviewed against the
// EXACT base it was computed against, or nothing applies.
//
// SINGLE APPLY PATH. The DO replays the ORIGINAL validated mutation method (addDownpipe/setRole/...) on
// approve; there is exactly one write code path (the same method that runs in the gate-off case), so an
// approved apply cannot skip the validation or the no-escalation guard that an inline apply runs. This
// module never writes config; it only describes the pending record and the rules around it.
//
// PARAMS ARE THE CUSTOMER'S OWN CONFIG, WITH ONE EXCEPTION, and the exception is why the read-time
// projection and the at-rest scrub at the foot of this file exist. A config mutation's params are the same
// data the config snapshot and GET /downpipes already expose: downpipe ids/names/selectors + secret NAMES
// (never bound-secret values), role grants, and notify routing. Seventeen of the eighteen kinds are exactly
// that. notify-channel-set is not: it stores the submitted NotifyChannel VERBATIM, so its params hold the
// channel's url (a Slack/Teams/generic-webhook ingest url, whose token usually rides in the path), its
// PagerDuty routingKey, and its JSM/ServiceNow apiKey. The params are stored verbatim so the replay is
// byte-faithful, and the diff is the config-history plain-English diff (current config vs the would-be
// config), which reads only named metadata and already redacts a channel url to its HOST. The validator
// asserts the kinds are the closed set and the hash binds the head.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries a value.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { GovernanceDecision } from "./approvals.ts";
import { webhookHost } from "./config-snapshot.ts";
import type { Capability } from "./identity.ts";

// ConfigChangeKind is the CLOSED set of config mutations the gate covers: exactly the config-mutating
// methods that auto-snapshot into config history. It is a closed union so a crafted kind cannot reach the
// replay dispatcher (the DO's applyConfigMutation switch is exhaustive over this set and throws on any
// other value). Each maps to one existing validated DO method and one write Capability (see
// CHANGE_WRITE_CAPABILITY). The toggle itself (requireConfigApproval) is NOT in this set: it is the
// owner-only control that arms/disarms the gate, and it is not a ConfigChangeKind because it must never be
// queued as a CONFIG CHANGE.
// "NOT IN THIS SET" IS NOT "NEVER GATED", and the difference is a direction rather than a detail. ARM
// (false->true) and any no-op are immediate, which is what stops the gate deadlocking its own off switch.
// DISARM is the dangerous direction and IS gated, through a different mechanism: an attributable owner's
// disarm routes through gatedOwnerAction("dual-control-disable") and only flips OFF on a distinct second
// owner's approve (scheduler-do-routing-config.ts, POST /config/approval-policy). A BARE-TOKEN break-glass
// owner still disarms immediately, because it cannot propose or approve owner actions at all and must keep a
// direct escape. owner-action.ts states the same asymmetry; this file used to contradict it.
export type ConfigChangeKind =
  | "downpipe-upsert" // POST /downpipes -> addDownpipe
  | "downpipe-delete" // POST /downpipes/delete -> removeDownpipe
  | "role-set" // POST /roles -> setRole
  | "role-delete" // POST /roles/delete -> deleteRole
  | "group-role-set" // POST /group-roles -> setGroupRole
  | "group-role-delete" // POST /group-roles/delete -> deleteGroupRole
  | "custom-role-set" // POST /custom-roles -> addCustomRole
  | "custom-role-delete" // POST /custom-roles/delete -> deleteCustomRole
  | "notify-channel-set" // POST /notify/channels -> addNotifyChannel
  | "notify-channel-delete" // POST /notify/channels/delete -> deleteNotifyChannel
  | "notify-rule-set" // POST /notify/rules -> addNotifyRule
  | "notify-rule-delete" // POST /notify/rules/delete -> deleteNotifyRule
  | "posture-accept" // POST /posture/accept -> acceptPostureRisk
  | "posture-unaccept" // POST /posture/unaccept -> unacceptPostureRisk
  | "expiry-item-set" // POST /expiry -> addExpiryItem (a tracked credential/key expiry)
  | "expiry-item-delete" // POST /expiry/delete -> deleteExpiryItem
  | "coverage-inventory" // POST /coverage/inventory -> setCoverageInventory
  | "cf-config-mode-set"; // POST /cf-config/mode -> setCfConfigMode (a cf-config downpipe's capture mode: auto | manual)

// CHANGE_KINDS is the value-level companion to the type-only union (the union cannot be iterated at
// runtime), used by isConfigChangeKind and by the validator's "the dispatcher covers every kind" check.
// Kept in lockstep with ConfigChangeKind (the validator asserts the two agree so they cannot drift).
export const CHANGE_KINDS: readonly ConfigChangeKind[] = [
  "downpipe-upsert",
  "downpipe-delete",
  "role-set",
  "role-delete",
  "group-role-set",
  "group-role-delete",
  "custom-role-set",
  "custom-role-delete",
  "notify-channel-set",
  "notify-channel-delete",
  "notify-rule-set",
  "notify-rule-delete",
  "posture-accept",
  "posture-unaccept",
  "expiry-item-set",
  "expiry-item-delete",
  "coverage-inventory",
  "cf-config-mode-set",
];

// isConfigChangeKind guards a stored/forwarded kind against the closed set, mirroring isRole/isCapability.
// It is defensive: the kind is set by the DO from its own dispatch (never a free client field), but a
// tampered stored record carrying an unknown kind must not reach the replay, so the approve path re-checks
// it and the dispatcher throws on a non-member.
export function isConfigChangeKind(v: unknown): v is ConfigChangeKind {
  return typeof v === "string" && (CHANGE_KINDS as readonly string[]).includes(v);
}

// CHANGE_WRITE_CAPABILITY maps each kind to the WRITE capability the ORIGINAL mutation requires, so the
// approver guard "the approver holds the same write capability the original mutation requires" is a single
// lookup, and the propose-time proposer re-check uses the same map. These match the router's gate() on the
// corresponding route (so the gate adds NO new authority model; it reuses the existing per-route
// capability). The validator asserts every kind has a mapping.
//
// THREE KINDS HAVE NO DO-METHOD RE-CHECK OF THEIR OWN, and the sentence that used to stand here said the map
// matched "the DO method's own re-check verbatim", which was true of fifteen and read as though it were true
// of all eighteen. addDownpipe re-checks only the narrower scheduledtest.config; removeDownpipe and
// setCfConfigMode are dispatched with no caller at all. The map is now consumed at approve by BOTH halves of
// the maker-checker pair -- canApproveChange for the CHECKER, and approveChange's maker floor for the
// PROPOSER's live re-resolved authority -- so it is the map, not the delegated method, that carries those
// three at apply time.
export const CHANGE_WRITE_CAPABILITY: Record<ConfigChangeKind, Capability> = {
  "downpipe-upsert": "downpipe.write",
  "downpipe-delete": "downpipe.delete",
  "role-set": "roles.write",
  "role-delete": "roles.write",
  "group-role-set": "access.policy",
  "group-role-delete": "access.policy",
  "custom-role-set": "access.policy",
  "custom-role-delete": "access.policy",
  "notify-channel-set": "notify.config",
  "notify-channel-delete": "notify.config",
  "notify-rule-set": "notify.config",
  "notify-rule-delete": "notify.config",
  "posture-accept": "posture.riskaccept",
  "posture-unaccept": "posture.riskaccept",
  // A tracked credential/key expiry is operational config gated on expiry.config (the same capability the
  // addExpiryItem/deleteExpiryItem DO re-check requires).
  "expiry-item-set": "expiry.config",
  "expiry-item-delete": "expiry.config",
  "coverage-inventory": "access.policy",
  // A cf-config downpipe's capture mode is downpipe config, gated on downpipe.write (the same capability the
  // POST /cf-config/mode router gate requires; setCfConfigMode itself takes no caller and re-checks nothing,
  // so at apply this entry is the only thing that answers for it).
  "cf-config-mode-set": "downpipe.write",
};

// A single plain-English change line, mirrored from config-history's ConfigChange so the pending record
// can carry the diff the approver reviews without importing the whole config-history surface into a
// consumer. The DO populates it from diffConfig(currentSnapshot, wouldBeSnapshot); it is redaction-safe
// (the diff reads only named config metadata, never a secret).
export interface PendingChangeLine {
  kind: "added" | "removed" | "changed";
  area: string;
  text: string;
}

// PendingConfigChange is one queued change request, held in the scheduler DO under
// `configchange:${id}`. It carries the binding (kind + params + the base head it was computed against),
// the proposer (the MAKER), the plain-English diff (current config vs the would-be config, reusing the
// config-history diff), the contentHash that binds all of it, and, once approved-and-applied, the
// approver (the CHECKER). proposedBy is the verified maker email; approvedBy MUST differ (maker !=
// checker), enforced server-side in the DO (the type cannot encode the inequality, so it is a runtime
// invariant the validator proves). params is the EXACT mutation body the original request carried, stored
// verbatim so the approve path replays the identical validated mutation. Every string here is the
// customer's own non-secret config metadata, escaped on display like every server-supplied value.
//
// THE PROPOSER IDENTITY FIELDS (proposedBy, proposedBySubject, proposedByGroups) record who proposed and
// with what authority AT PROPOSE TIME. The apply re-resolves the proposer's authority from the STABLE
// subject (ASVS V10.3.3 / V10.5.2: iss+"|"+sub for Access, passkeySubject(email) for passkey) against the
// LIVE role table (keyed on the immutable subject, never the mutable email) AND those groups, so a proposer
// revoked or demoted between propose and approve is caught, a recycled email cannot inherit a departed
// proposer's authority, and a group-derived proposer keeps exactly the authority they presented (no group
// they did not hold). All three are BOUND INTO contentHash because the apply re-resolves authority from
// them, so a stored-record tamper of the actor identity must be caught by the approve-time recompute, the
// same check that catches a params tamper. proposedBySubject is null only for the bare-token break-glass,
// which cannot propose a change (refused upstream), so a queued record always carries a real subject.
export interface PendingConfigChange {
  id: string; // the record id (a ULID, also the storage key suffix `configchange:${id}`)
  kind: ConfigChangeKind; // which mutation this change is
  params: unknown; // the exact validated mutation params (the original request body), replayed on approve
  proposedBy: string; // the proposer's verified email (the MAKER); a bare-token proposer is refused upstream
  proposedBySubject: string | null; // the proposer's stable principal at propose time (see the block comment)
  proposedByGroups: string[]; // the proposer's verified IdP groups at propose time (see the block comment)
  // proposedBySourceIp is the EDGE ADDRESS THE PROPOSE REQUEST ARRIVED FROM, carried so the approve-time REPLAY
  // can attribute its audit row to the same place the proposal came from. The replay runs AS THE PROPOSER
  // (their email, their subject, their propose-time groups) and it appends an ordinary human-attributed audit
  // entry; with no IP on the replay caller that entry landed with sourceIp null, which is the exact shape the
  // audit-human-event-missing-source-ip counter names as a CAPTURE FAULT. So every approved change under dual
  // control bumped a fault counter on an engine whose capture path was working perfectly, and the governance-
  // mature accounts (the ones that turned the gate ON) were the ones it cried wolf at. The engine DID capture the
  // address at propose time; this is where it keeps it. It is NOT bound into contentHash: the apply re-resolves
  // no authority from it, so it is provenance, not a decision input. It never reaches the support pack (the
  // audit excerpt strips sourceIp from every event by design); it rides only in the customer's own audit chain,
  // exactly as a direct, ungated mutation's does.
  proposedBySourceIp?: string | null;
  proposedAt: string; // RFC-3339 UTC millis
  baseVersionId: number; // the config-history head id the diff + hash were computed against (-1 if none yet)
  baseVersionHash: string; // that head version's contentHash (or the genesis sentinel when there is no head)
  diff: PendingChangeLine[]; // plain-English (Australian) change list: current config -> the would-be config
  contentHash: string; // "sha384:" over { kind, params, proposedBy, proposedBySubject, proposedByGroups, baseVersionId, baseVersionHash }
  status: PendingChangeStatus;
  approvedBy?: string; // the CHECKER's verified email; set on apply; MUST differ from proposedBy
  approvedAt?: string;
  // supersededAt/supersededReason are set when an approve is refused because the base config moved (the
  // record is marked superseded so the inbox shows it is stale and a re-proposal is needed). A superseded
  // record is terminal and never applies.
  supersededAt?: string;
  // The record's LAST FAILED APPLY ATTEMPT. Without it a change that will not apply just SITS in the
  // inbox marked "pending" with zero history of the attempts or their causes ("our second owner approved but
  // nothing happened"), because every refusal was a thrown Error that reached one approver's browser and
  // nothing else. outcomeClass is a CLOSED enum (sched-fault-ledger GOVERNANCE_OUTCOME_CLASSES) that
  // distinguishes a FORESEEABLE refusal (guard-refused) from an UNEXPECTED fault (apply-faulted) and names
  // the two security-significant ones (integrity-failed, replay-detected). Never the guard's reason prose,
  // the params or an identity: those already have their own homes on the record and in the audit chain.
  lastAttempt?: { at: string; outcomeClass: string };
  // paramsScrubbedAt records that this record's AT-REST params were stripped of their secret-bearing fields
  // because the change can never be replayed again (see configChangeParamsSpent below). It is stamped ONLY
  // when the strip actually removed something, so a secret-free change is never marked and the marker means
  // exactly what it says. A scrubbed record's contentHash can no longer recompute from its params, which is
  // safe here and NOT safe in general: every recompute site (approveChange's fast fail and its in-guard
  // repeat) is reached only after canApproveChange has admitted the record, and canApproveChange refuses
  // applied/rejected/superseded before any hash is derived. So a scrubbed record is never hashed, and a
  // scrub can never be mistaken for a tamper. The validator asserts that ordering rather than trusting it.
  paramsScrubbedAt?: string;
}

// PendingChangeStatus is the closed lifecycle of a pending change. pending: queued, awaiting a checker.
// applied: a distinct approver approved AND the validated replay committed (single use; terminal).
// rejected: an approver (or the proposer) discarded it (terminal). superseded: an approve found the base
// config had moved, so the reviewed diff was stale; terminal, requires re-proposal. Unlike the restore
// approval there is no TTL-expiry state: a config change carries no blast-radius window to bank against,
// and the supersede check already voids any change whose base moved, so a stale pending is caught at
// approve time by the base-moved check rather than a clock.
export type PendingChangeStatus = "pending" | "applied" | "rejected" | "superseded";

// CHANGE_PREFIX is the DO storage key prefix; the key is `configchange:${id}`. The id is a ULID so a
// storage prefix list returns records in chronological (oldest-first) order without a separate counter,
// the same idiom as the drill-evidence log.
export const CHANGE_PREFIX = "configchange:";

// changeKey is the storage key for a pending change record.
export function changeKey(id: string): string {
  return CHANGE_PREFIX + id;
}

// ChangeBinding is the canonical object the contentHash is computed over: the mutation kind, its params,
// the PROPOSER IDENTITY (email + stable subject + propose-time groups) the apply re-resolves authority from,
// and the base head id + hash the change was computed against. Binding the base head is the no-stale-apply
// teeth: an approve recomputes this over the SAME inputs AND re-reads the current head; if the head moved
// (baseVersionId/Hash no longer match the live head) the change is superseded, and if the params OR the
// proposer identity were tampered the hash no longer matches. Folding proposedBy + proposedBySubject +
// proposedByGroups is the no-actor-tamper teeth: the apply re-resolves the proposer's LIVE authority from
// exactly these fields (keyed on the immutable subject), so a stored-record swap of the actor identity (to
// borrow a more privileged proposer) is caught by the same recompute that catches a params tamper. The params
// + groups are folded as-is (the customer's own non-secret config + directory data); canonicalJSON sorts
// object keys so a key-order difference in the stored params cannot change the hash, matching the
// config-history content hash discipline.
interface ChangeBinding {
  kind: ConfigChangeKind;
  params: unknown;
  proposedBy: string;
  proposedBySubject: string | null;
  proposedByGroups: string[];
  baseVersionId: number;
  baseVersionHash: string;
}

// changeContentHash computes the binding hash: "sha384:" + hex(SHA-384(canonicalJSON(binding))), the SAME
// primitives the config-history content hash and the restore plan hash use (canonical JSON + SHA-384,
// "sha384:" prefix). It is recomputable from the stored record alone (kind/params/proposedBy/
// proposedBySubject/proposedByGroups/baseVersionId/baseVersionHash), so the approve path re-derives it
// without re-running anything, and it folds NO key and NO secret. It is async (sha384 is async) and pure.
export async function changeContentHash(
  kind: ConfigChangeKind,
  params: unknown,
  proposedBy: string,
  proposedBySubject: string | null,
  proposedByGroups: string[],
  baseVersionId: number,
  baseVersionHash: string,
): Promise<string> {
  const binding: ChangeBinding = { kind, params, proposedBy, proposedBySubject, proposedByGroups, baseVersionId, baseVersionHash };
  return `sha384:${hexEncode(await sha384(canonicalJSON(binding)))}`;
}

// canApproveChange decides whether a caller may APPROVE a pending change, returning a precise refusal
// reason or null to allow. It encodes the dual-control-specific rules; the WRITE-CAPABILITY check (the
// approver holds CHANGE_WRITE_CAPABILITY[kind]) is the DO's own re-resolution and is passed in as
// approverHasWriteCap (so this stays pure over the record + the two facts). The rules, in order:
//   - the change must still be pending (an applied/rejected/superseded record cannot be approved);
//   - maker != checker on the STABLE SUBJECT axis (the authority axis, ASVS V10.3.3 / V10.5.2),
//     the SAME axis restore dual control compares (approvals.ts: approverSubject !== requesterSubject):
//     the approver's subject must differ from proposedBySubject. The display-email comparison is kept
//     as a belt-and-suspenders floor (a canonicalised-email self-approval is also refused), so a
//     pre-subject legacy record with a null proposedBySubject still cannot be self-approved by email;
//   - the approver must hold the same write capability the original mutation requires.
// The base-moved / hash-mismatch (supersede) check is NOT here: it needs the live head + a recomputed
// hash (async, storage), so the DO does it in approveChange around this call. canApproveChange is the
// synchronous identity/state/capability gate; both run inside the DO's read-modify-write so the decision
// is atomic with the write.
export function canApproveChange(
  record: PendingConfigChange,
  approverEmail: string | null,
  approverSubject: string | null,
  approverHasWriteCap: boolean,
): GovernanceDecision {
  if (record.status === "applied") return { ok: false, reason: "the change was already applied", reasonCode: "terminal-state" };
  if (record.status === "rejected") return { ok: false, reason: "the change was rejected", reasonCode: "terminal-state" };
  if (record.status === "superseded") return { ok: false, reason: "the change was superseded; raise it again", reasonCode: "base-moved" };
  if (approverEmail === null) {
    return { ok: false, reason: "dual control requires an attributable identity; the bare-token fallback cannot approve a change", reasonCode: "bare-token" };
  }
  // Maker != checker on the subject axis (primary): a self-approval is refused even across an email
  // change, exactly as restore dual control compares subjects. record.proposedBySubject is non-null for
  // any change proposed after the subject re-key; a null (legacy) value falls through to the email floor.
  if (record.proposedBySubject !== null && approverSubject === record.proposedBySubject) {
    return { ok: false, reason: "cannot approve your own change", reasonCode: "self-approval" };
  }
  // Email floor (belt-and-suspenders): also refuse a same-display-email self-approval.
  if (approverEmail === record.proposedBy) {
    return { ok: false, reason: "cannot approve your own change", reasonCode: "self-approval" };
  }
  if (!approverHasWriteCap) {
    return { ok: false, reason: `cannot approve: you do not hold the ${CHANGE_WRITE_CAPABILITY[record.kind]} capability the change requires`, reasonCode: "no-capability" };
  }
  return { ok: true };
}

// canRejectChange mirrors canApproveChange for a rejection: only a still-pending record can be rejected.
// A reject does NOT require maker != checker (the proposer may withdraw their own change), but it must not
// overwrite a terminal state (applied/rejected/superseded).
export function canRejectChange(record: PendingConfigChange): GovernanceDecision {
  if (record.status === "applied") return { ok: false, reason: "the change was already applied", reasonCode: "terminal-state" };
  if (record.status === "rejected") return { ok: false, reason: "the change was already rejected", reasonCode: "terminal-state" };
  if (record.status === "superseded") return { ok: false, reason: "the change was superseded", reasonCode: "base-moved" };
  return { ok: true };
}

// baseMoved reports whether the live config-history head differs from the base the change was computed
// against (the no-stale-apply / TOCTOU check). The change bound baseVersionId + baseVersionHash at propose
// time; if the current head id or hash differs, a config change committed in between, so the diff the
// approver reviewed is stale and the change must be superseded (not applied against a base it was never
// reviewed against). An exact match on BOTH id and hash means the base is unchanged and the replay applies
// against the same posture the proposer saw. It is a pure comparison the DO feeds the live head into.
export function baseMoved(record: PendingConfigChange, liveHeadId: number, liveHeadHash: string): boolean {
  return record.baseVersionId !== liveHeadId || record.baseVersionHash !== liveHeadHash;
}

// ---- The read-time projection, and the AT-REST scrub -------------------------------------------------
//
// THE EXPOSURE THIS CLOSES, which is a CAPABILITY BYPASS and not merely a residue. A NotifyChannel carries
// the customer's live delivery credential: the url of a webhook/Slack/Teams channel (whose ingest token
// usually rides in the path or query), a PagerDuty routingKey, a JSM GenieKey or ServiceNow password as
// apiKey. router-ops.ts gates GET /admin/notify/channels on notify.config SPECIFICALLY for that reason, in
// as many words: a channel is "a bearer credential, not read-only metadata", so the read is gated like its
// writes rather than like every other notify read. GET /admin/config/changes is gated on downpipe.read,
// because the pending-change inbox is a governance queue that any config reader may watch, and it returned
// the queued records VERBATIM. Under the dual-control gate a queued notify-channel-set therefore published
// that same credential to every downpipe.read holder. Read off ROLE_CAPABILITIES, viewer, restore-operator
// and access-admin hold downpipe.read and hold NO notify.config, so three roles that are deliberately
// refused the credential on the channels route were handed it on the inbox route.
//
// THE REMEDY IS A READ-TIME REDACTION, NOT A TIGHTER GATE, and the choice is load-bearing. The inbox holds
// all eighteen kinds; gating the route on notify.config would blind an access-admin to the queued ROLE
// change they are the natural approver of, and per-record filtering by the caller's capability would make
// the governance queue itself invisible to the viewer whose whole purpose is to watch it. Neither buys
// anything the redaction does not.
//
// AND THE REDACTION KEEPS THE REVIEWABLE PART, which is the difference between this and simply deleting the
// fields. A reviewer approving a notify-channel-set has to be able to answer "where will our alerts go", and
// the plain-English diff does NOT tell them: for a new channel it reads "notify channel <name> (<kind>)
// added" and names no endpoint at all. So the url is reduced to its HOST through config-snapshot's own
// webhookHost(), under the same urlHost name that snapshot uses, rather than dropped: the reviewer sees
// exactly what the config history will show them once the change applies, computed by exactly the same code.
// The routingKey and the apiKey have no reviewable sub-part and the snapshot itself keeps only their
// presence, so those are dropped outright, and the channel's kind already says which one it had.
//
// AND THE STORE IS SCRUBBED TOO, because a redaction is a read-path control and says nothing about what is
// held. configchange: has no TTL (deliberately: the base-moved check substitutes for one, see
// PendingChangeStatus) and nothing anywhere deletes a record, so a rejected or superseded notify-channel-set
// kept the submitted credential for ever. That is the same kind of residue removed one store along, and it is
// the residue whose exposure GROWS with time. The scrub runs in the SAME storage.put as each terminal
// status, so there is no window, and it reuses the projection's own field list so there is ONE definition of
// what counts as a secret here.
//
// WHAT IS DELIBERATELY NOT CLOSED: a change that is PROPOSED AND NEVER DECIDED. Its params are the exact
// bytes the approved replay must apply and the exact bytes contentHash binds, so they cannot be stripped
// while the record can still be approved. That copy lives until somebody approves, rejects or supersedes
// it, and unlike the owner-action store there is no clock that will do it for them. It is bounded by the
// operator emptying their own inbox, and the support pack already counts a stalled queue.

// CHANGE_SECRET_PARAM_KEYS is the SINGLE declaration of which stored param fields carry a live credential.
// All three are top-level on the notify-channel-set params (the submitted NotifyChannel): url (webhook /
// slack / teams / jsm / servicenow), routingKey (pagerduty Events v2), apiKey (the JSM GenieKey or the
// ServiceNow basic password, a sealed WrappedSecret when CONFIG_WRAP_KEY is set and a plain string on the
// documented no-wrap-key floor; deleting the key covers both). No other kind's params carry any of the
// three, which is why this is a flat key list and not a per-kind map. It is deliberately conservative: it
// strips the EXACT known keys rather than guessing, so a new secret-bearing kind has to be declared here on
// purpose. NOT included: servicenow's `username`, which NotifyChannel declares is an integration account
// name and not a secret, and which is therefore resupplied in the clear on every submit; widening to it
// here would be a second, quieter answer to a question that type already answers.
export const CHANGE_SECRET_PARAM_KEYS: readonly string[] = ["url", "routingKey", "apiKey"];

// redactConfigChangeParamsForListing returns a redacted COPY of a change's params: every field in
// CHANGE_SECRET_PARAM_KEYS is removed, and a removed `url` is REPLACED by `urlHost`, the same host-only
// reduction config-snapshot applies to the same value under the same name (an unparseable url yields null
// there and yields null here, because it is literally the same function). It NEVER mutates the input (the
// at-rest record the approve path replays from is read by id and is untouched), and it returns the input BY
// REFERENCE when there was nothing to strip, which is what lets both callers tell "a secret went" from
// "there was none": the listing skips a needless copy and the scrub stamps paramsScrubbedAt only when
// something actually went. A non-object params value round-trips unchanged.
export function redactConfigChangeParamsForListing(params: unknown): unknown {
  if (params === null || typeof params !== "object" || Array.isArray(params)) return params;
  const src = params as Record<string, unknown>;
  if (!CHANGE_SECRET_PARAM_KEYS.some((k) => k in src)) return params;
  const out: Record<string, unknown> = { ...src };
  for (const k of CHANGE_SECRET_PARAM_KEYS) delete out[k];
  // Only a url has a reviewable part to keep. It is emitted under the snapshot's own field name so a reader
  // of either surface recognises it, and only when the source really carried a url string, so a channel kind
  // with no url never grows a null field it never had.
  if (typeof src.url === "string") out.urlHost = webhookHost(src.url);
  return out;
}

// viewConfigChange is the read-time projection for any CALLER-FACING echo of a record: the inbox listing and
// the approve/reject response bodies. It is a pure copy; the STORED record is untouched, so the approve
// path's replay (which reads the record by id, never through this projection) still applies the byte-
// identical params, and the contentHash recompute still runs over what was actually stored. The three
// echoes are covered together because the same rule the owner-action store settled is a rule about every
// caller-facing echo, not about the listing alone: an approver arming a change and an approver vetoing one
// are both reading, and neither needs the credential to decide.
export function viewConfigChange(record: PendingConfigChange): PendingConfigChange {
  const params = redactConfigChangeParamsForListing(record.params);
  if (params === record.params) return record;
  return { ...record, params };
}

// configChangeParamsSpent reports whether a record's params can never be needed again: its status is one of
// the three TERMINAL ones. Those are exactly the states from which no approve can proceed (canApproveChange
// refuses all three by name) and no reject can (canRejectChange likewise), so the params have no remaining
// reader. "pending" is deliberately absent: that record is still approvable and its params are both the
// replay input and the hash pre-image.
export function configChangeParamsSpent(record: PendingConfigChange): boolean {
  return record.status === "applied" || record.status === "rejected" || record.status === "superseded";
}

// scrubConfigChangeParams strips every secret-bearing field from the AT-REST params of a spent change. It is
// the SAME projection the listing applies, deliberately: one declaration of what a secret is, so a new
// secret-bearing kind cannot be redacted on the read path and left in the store.
export function scrubConfigChangeParams(params: unknown): unknown {
  return redactConfigChangeParamsForListing(params);
}

// configChangeParamsScrubbed reports whether a record's at-rest params were stripped, and therefore whether
// its contentHash can still be recomputed from them. See PendingConfigChange.paramsScrubbedAt.
export function configChangeParamsScrubbed(record: PendingConfigChange): boolean {
  return typeof record.paramsScrubbedAt === "string" && record.paramsScrubbedAt.length > 0;
}
