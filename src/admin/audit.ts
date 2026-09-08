// The tamper-evident, hash-chained, append-only audit log. This module owns the record
// shape, the hash-chain mechanism, the verify, the redaction-by-construction discipline, and
// the JSON/CSV export. The scheduler Durable Object holds the chain (it is the single storage
// authority); this module is the pure logic the DO and the validators share so the append and
// the verify can never compute the hash two different ways.
//
// The claim is TAMPER-EVIDENT, never tamper-proof. A holder of the DO storage could rewrite the
// whole chain; what the chain guarantees is that any edit or deletion of a past entry that is
// not a full re-chain is DETECTABLE by verifyChain, and the export head hash lets an external
// verifier detect truncation-after-export. Code and copy say exactly this.
//
// REDACTION BY CONSTRUCTION (the no-plaintext rule). The recorder accepts only the closed
// AuditTarget union below; there is no free-form "details" field a caller could stuff a secret
// into, so the safe path is the ONLY path the types allow. The log never records a key, a value,
// a secret, a private fingerprint, a destination credential, an endpoint, a bucket, a region, or
// the licence/update pinned signer. It may record what is already public or non-sensitive
// in-account: a downpipe id/name, a run id, a target binding NAME, a role, a member email (the
// actor key itself), counts, the plan hash, a version string, a free-text reason. This mirrors
// GET /admin/status (presence-only, status.ts) and the coarse run errors (index.ts).
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries
// a value. The hash is SHA-384 over canonical JSON, matching the codebase's fingerprint and
// archive hashing discipline (dpr1:/edmldsa1: are sha384; the RUNLOG/manifest hash is sha384).

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { canonicalJSON } from "../format/canonjson.ts";

// The closed-union type vocabulary lives in audit-types.ts (the redaction-by-construction boundary
// in type form) and the engine-observed presence/version snapshot logic in audit-status.ts. They
// are re-exported here so importers keep one public surface (../admin/audit.ts) and no caller has
// to learn the split.
import { SHA384_HEX_LEN } from "./audit-types.ts";
import type {
  AuditDraft,
  AuditEvent,
  AuditFilter,
  AuditTarget,
  ChainVerdict,
  VerifyChainOptions,
} from "./audit-types.ts";

export {
  diffStatus,
  STATUS_SNAPSHOT_KEY,
  type StatusObservation,
  type StatusSnapshot,
  TRACKED_PRESENCE_FIELDS,
  type TrackedPresenceField,
} from "./audit-status.ts";
export { SHA384_HEX_LEN } from "./audit-types.ts";
export type {
  AuditAction,
  AuditActorMethod,
  AuditDraft,
  AuditEvent,
  AuditFilter,
  AuditOutcome,
  AuditTarget,
  ChainVerdict,
  ExportFormat,
  VerifyChainOptions,
} from "./audit-types.ts";
// SEQ_PAD is the zero-padded width of the sequence in the storage key, so a storage
// list({prefix:"audit:"}) returns entries in ascending sequence order (lexicographic == numeric
// at a fixed width). 20 digits holds well past any realistic event count (2^53-1 is 16 digits).
export const SEQ_PAD = 20;

// The audit chain head hash placeholder for the genesis entry's prevHash: "sha384:" followed by
// SHA384_HEX_LEN hex zeros. The width is DERIVED from the shared constant in audit-types.ts, not
// typed here, so this placeholder and destsim's accepting regex cannot disagree about it.
// A real prevHash is the prior entry's hash.
export const GENESIS_PREV_HASH = `sha384:${"0".repeat(SHA384_HEX_LEN)}`;

// The storage key prefix for the chain and the key for the monotonic sequence counter, kept here
// so the DO and any reader agree on the exact strings.
export const AUDIT_PREFIX = "audit:";
/** @knipignore Storage-key contract constant, retained so the DO and any reader agree on the exact string. */
export const AUDIT_SEQ_KEY = "auditSeq";

// AUDIT_CAP bounds how many audit entries the DO retains, so the tamper-evident log cannot grow
// the Durable Object storage without limit. At the cap the DO rolls over the
// OLDEST entries (a documented retention rollover, not a silent drop): the seq stays monotonic, the
// retained chain stays internally verifiable (verifyChain takes its baseline from the first RETAINED
// entry, not a hardcoded genesis), and the DO records the earliest retained seq + the rolled-over
// count so a reviewer sees the chain legitimately begins above seq 1. The operator path to keep the
// full history is EXPORT-BEFORE-ROLLOVER (GET /admin/audit/export carries the head hash, so the
// export is itself verifiable and truncation-after-export is detectable); the cap only bounds what
// the live DO holds, it never silently loses an unexported entry's evidentiary value because the
// rollover is counted and surfaced, not hidden. The constant lives here (the audit domain) and is
// re-exported from the scheduler DO (where the rollover is enforced) so both agree on one value.
export const AUDIT_CAP = 10000;

// AUDIT_NEAR_CAP_FRACTION is the share of AUDIT_CAP at or above which status reports auditNearCap, so
// the console can prompt the operator to export before the rollover begins. 0.9 leaves a 10% margin.
export const AUDIT_NEAR_CAP_FRACTION = 0.9;

// padSeq renders the sequence as a fixed-width zero-padded string for the storage key, so a
// prefix list is naturally ordered. The seq is a safe integer (the DO bumps it by one per
// append), so a plain padStart is exact.
function padSeq(seq: number): string {
  return String(seq).padStart(SEQ_PAD, "0");
}

// auditKey is the storage key for an entry: `audit:00000000000000000042`.
export function auditKey(seq: number): string {
  return AUDIT_PREFIX + padSeq(seq);
}

// auditHash computes the entry hash: "sha384:" + hex(SHA-384(canonicalJSON(event-without-hash))).
// The hashed object includes prevHash and every field except hash, so each entry commits to the
// prior entry's hash (the chain) and to its own content (tamper-evidence). canonicalJSON sorts
// keys and forbids non-integer numbers, so the hash is reproducible across the append and the
// verify. The function is given the full event for ergonomics and ignores its hash field.
export async function auditHash(event: AuditEvent): Promise<string> {
  // Reconstruct the hashed object explicitly (rather than delete event.hash) so the hashed set of
  // fields is unambiguous and stable even if AuditEvent gains a field later: the hash covers
  // exactly these, in canonical (sorted-key) order.
  //
  // BACKWARD-COMPATIBLE actorSubject: include it ONLY when it is a string. A legacy entry (recorded
  // before subject-keying) has no actorSubject, so the field is absent from `hashed` and the digest is
  // byte-for-byte what it was before this change, leaving every pre-upgrade entry's stored hash intact
  // and the chain verifiable across the upgrade. A new entry stamps a string subject (or omits it for
  // the token/engine actor, which also leaves it out), so the hash commits to the subject when there is
  // one. canonicalJSON sorts keys, so adding the key when present does not disturb the others' order.
  const hashed: Record<string, unknown> = {
    seq: event.seq,
    ts: event.ts,
    actorEmail: event.actorEmail,
    actorMethod: event.actorMethod,
    sourceIp: event.sourceIp,
    action: event.action,
    outcome: event.outcome,
    target: event.target,
    prevHash: event.prevHash,
  };
  if (typeof event.actorSubject === "string") hashed.actorSubject = event.actorSubject;
  // BACKWARD-COMPATIBLE advisory (V6.8.4): fold the IdP acr/amr/auth_time signal into the digest ONLY when
  // present (it rides only on an idp-sign-in whose IdP asserted it). An event without it -- every pre-upgrade
  // entry and every non-sign-in entry -- hashes exactly as before, so the chain verifies across the upgrade.
  // canonicalJSON sorts keys, so adding the key when present does not disturb the order of the others.
  if (event.advisory !== undefined) hashed.advisory = event.advisory;
  return `sha384:${hexEncode(await sha384(canonicalJSON(hashed)))}`;
}

// buildEvent assembles the next chain entry from a draft and the chain head (the prior entry, or
// null for genesis), allocating seq and ts and computing prevHash + hash. This is the ONE place an
// entry is constructed, so the append (DO) and any re-derivation share identical logic. ts is
// passed in so the caller controls the clock (the DO uses nowMillisISO()); seq is passed in so the
// DO allocates it inside the same storage transaction as the counter bump.
export async function buildEvent(draft: AuditDraft, seq: number, ts: string, prev: AuditEvent | null): Promise<AuditEvent> {
  const prevHash = prev ? prev.hash : GENESIS_PREV_HASH;
  // actorSubject defaults to null when the draft omits it (an engine-observed event, or a caller with no
  // stable identity). It is stamped as a real field so the event shape is consistent; auditHash folds it
  // into the digest only when it is a string, so a null/omitted subject does not change a legacy-shaped
  // entry's hash. exactOptionalPropertyTypes: normalise undefined to null here so the stored value is
  // explicit (the DO structured-clones it; an explicit null round-trips, an undefined would be dropped).
  const actorSubject = draft.actorSubject ?? null;
  const event: AuditEvent = {
    seq,
    ts,
    actorSubject,
    actorEmail: draft.actorEmail,
    actorMethod: draft.actorMethod,
    sourceIp: draft.sourceIp,
    action: draft.action,
    outcome: draft.outcome,
    target: draft.target,
    // V6.8.4: carry the OPTIONAL advisory IdP acr/amr/auth_time when the draft supplied it (idp-sign-in only),
    // exactOptionalPropertyTypes-safe. auditHash folds it into the digest only when present (see above).
    ...(draft.advisory !== undefined ? { advisory: draft.advisory } : {}),
    prevHash,
    hash: "", // filled below; not part of the hashed object
  };
  event.hash = await auditHash(event);
  return event;
}

// verifyChain recomputes the chain from genesis over the entries (which MUST be in ascending seq
// order) and reports the first break. A break is any of: a stored hash that does not recompute
// from the entry's own fields (the entry was edited); a prevHash that does not equal the prior
// entry's stored hash (an entry was inserted/deleted/reordered, or its predecessor edited); or a
// SEQUENCE that is not contiguous, i.e. each entry's seq must be exactly its predecessor's seq + 1
// (a gap means an entry was deleted, even if a sophisticated tamper re-linked the hashes around the
// hole). The first entry in the ordered list establishes the baseline seq. By default its prevHash
// must be GENESIS_PREV_HASH (it is expected to be the true genesis), so deleting genesis from a
// never-rolled-over chain is still detected; after a documented retention rollover the caller passes
// expectGenesis:false (see VerifyChainOptions) and the baseline is taken from the first RETAINED
// entry instead, since genesis was legitimately pruned. Contiguity is enforced from the baseline
// either way. This makes the module's "any deletion is detectable" claim true WITHIN the retained
// set: a deleted middle entry yields a seq gap that this check reports at the entry after the hole.
// This is the on-screen proof of tamper-evidence.
//
// SCALING: each entry's hash is re-derived with an await auditHash(e) and the
// prevHash/seq links are inherently SERIAL (each entry commits to its predecessor's stored hash), so
// the re-hash CANNOT be parallelised across the chain without breaking the order dependency. The cost
// is therefore bounded by the chain length, which is in turn bounded by AUDIT_CAP (10,000): a full-cap
// verify is at most AUDIT_CAP sequential SHA-384 + canonicalJSON operations. This is an accepted design
// constraint, not a defect: the cap keeps the worst case finite, the export-before-rollover path carries
// the head hash so an external verifier can confirm completeness offline, and a caller worried about the
// request-path CPU budget can verify a bounded entries range rather than the whole retained set.
export async function verifyChain(entries: AuditEvent[], opts?: VerifyChainOptions): Promise<ChainVerdict> {
  if (entries.length === 0) return { intact: true, checkedThrough: -1, earliestSeq: -1 };
  const expectGenesis = opts?.expectGenesis ?? true;
  const earliestSeq = entries[0]!.seq;
  let prev: AuditEvent | null = null;
  for (const e of entries) {
    // The link: prevHash must equal the prior entry's stored hash. For the FIRST entry there is no
    // retained predecessor: when expectGenesis is true it must link to the zero hash (the true
    // genesis); when false (a documented rollover) its prevHash links to a now-pruned predecessor we
    // cannot re-derive, so it is accepted as the baseline and only checked from the second entry on.
    // A mismatch from the second entry onward means an entry was inserted, removed, reordered, or its
    // predecessor edited.
    if (prev === null) {
      if (expectGenesis && e.prevHash !== GENESIS_PREV_HASH) return { intact: false, checkedThrough: e.seq, earliestSeq, brokenAt: e.seq, causeClass: "genesis-link" };
    } else if (e.prevHash !== prev.hash) {
      return { intact: false, checkedThrough: e.seq, earliestSeq, brokenAt: e.seq, causeClass: "prev-hash-mismatch" };
    }
    // The sequence: after the baseline (the first entry), each seq must be exactly prev.seq + 1.
    // A gap (e.g. seq jumps by 2) means an entry between them was deleted; a non-increase means a
    // reorder/duplicate. This is the seq tampering the module claims to detect; the baseline entry
    // (prev === null) defines the lowest expected seq and is not itself a gap.
    if (prev !== null && e.seq !== prev.seq + 1) return { intact: false, checkedThrough: e.seq, earliestSeq, brokenAt: e.seq, causeClass: "seq-gap" };
    // The content: the stored hash must recompute from the entry's own fields. A mismatch means
    // the entry was edited in place.
    const recomputed = await auditHash(e);
    if (recomputed !== e.hash) return { intact: false, checkedThrough: e.seq, earliestSeq, brokenAt: e.seq, causeClass: "recompute-mismatch" };
    prev = e;
  }
  return { intact: true, checkedThrough: entries[entries.length - 1]!.seq, earliestSeq };
}

// targetDownpipeId extracts a downpipe id from a target where one is meaningful, so the downpipe
// filter can match downpipe-create/-delete events. Restore/run targets carry a runId, not a
// downpipe id, so they do not match a downpipe filter (the console filters those by run/action).
function targetDownpipeId(t: AuditTarget): string | null {
  return t.kind === "downpipe" ? t.id : null;
}

// matchesFilter applies one AuditFilter predicate to one event (before/limit are applied by the
// pager, not here). String comparisons are case-insensitive for the email; ts bounds are simple
// lexical comparisons, valid because the timestamps are a fixed RFC-3339 millis form.
function matchesFilter(e: AuditEvent, f: AuditFilter): boolean {
  if (f.actor !== undefined) {
    if (e.actorEmail === null) return false;
    if (e.actorEmail.toLowerCase() !== f.actor.toLowerCase()) return false;
  }
  if (f.action !== undefined && e.action !== f.action) return false;
  if (f.outcome !== undefined && e.outcome !== f.outcome) return false;
  if (f.downpipe !== undefined && targetDownpipeId(e.target) !== f.downpipe) return false;
  if (f.from !== undefined && e.ts < f.from) return false;
  if (f.to !== undefined && e.ts > f.to) return false;
  // afterSeq is the audit-feed tail cursor: only entries strictly after the collector's checkpoint cross.
  // Applying it here lets the DO pre-filter the export to the matching window, so the feed pull is
  // O(limit) rather than loading the whole retained log into the Worker to filter.
  if (f.afterSeq !== undefined && e.seq <= f.afterSeq) return false;
  return true;
}

// AUDIT_PAGE_DEFAULT / AUDIT_PAGE_MAX bound an INTERACTIVE page (GET /audit) so a single UI GET cannot
// return an unbounded body. The console pages that view with before+limit; the head hash is returned
// alongside so an external verifier can confirm completeness. This cap is for the paged VIEW only: the
// compliance EXPORT (GET /audit/export) must be COMPLETE, so it shapes its document with
// filterEventsAscending (below, no cap), never pageEvents. A compliance export silently truncated at 500
// rows while presenting itself as the full log is an integrity defect (an auditor would miss every older
// event with no signal), so the paged view and the export are deliberately distinct paths.
export const AUDIT_PAGE_DEFAULT = 100;
export const AUDIT_PAGE_MAX = 500;

// pageEvents applies a filter then the before/limit pager over the full, ascending-seq list,
// returning a newest-first page. It does not verify the chain (that is GET /audit/verify); it is a
// pure read shaping helper, shared by the DO route and the validator.
export function pageEvents(all: AuditEvent[], f: AuditFilter): AuditEvent[] {
  const limit = Math.min(Math.max(1, f.limit ?? AUDIT_PAGE_DEFAULT), AUDIT_PAGE_MAX);
  // Walk the ascending-seq list from the tail (newest first), applying the filter and the before
  // cursor inline, and stop once limit results are collected. This is O(limit) in the common case
  // and allocates only the bounded result page, never a reversed or filtered copy of all.
  const page: AuditEvent[] = [];
  for (let i = all.length - 1; i >= 0 && page.length < limit; i--) {
    const e = all[i]!;
    if (f.before !== undefined && e.seq >= f.before) continue;
    if (matchesFilter(e, f)) page.push(e);
  }
  return page;
}

// filterEventsAscending applies a filter to the full ascending-seq list and returns EVERY matching entry
// in ascending-seq order, with NO page-size cap. This is the COMPLETE-EXPORT shaping helper: a compliance
// export must contain every event, so unlike pageEvents (the interactive newest-first pager, capped at
// AUDIT_PAGE_MAX so a single UI GET cannot return an unbounded body) it never truncates. It applies the
// same before + matchesFilter predicates as pageEvents, differing ONLY in the absence of the cap and in
// returning ascending (document) order. before is honoured for symmetry (the export strips it, so it is
// inert there); afterSeq is honoured via matchesFilter so a filtered forward slice can bound itself after.
// The caller reads the WHOLE chain (paged past one storage page), so this plus that read make the export
// complete up to the retained AUDIT_CAP, never truncated at the first storage page nor at AUDIT_PAGE_MAX.
export function filterEventsAscending(all: AuditEvent[], f: AuditFilter): AuditEvent[] {
  const out: AuditEvent[] = [];
  for (const e of all) {
    if (f.before !== undefined && e.seq >= f.before) continue;
    if (matchesFilter(e, f)) out.push(e);
  }
  return out;
}

// headOf returns the chain head (seq + hash) from the full ascending-seq list, or the empty-log
// sentinels. Used to populate AuditPage.headSeq/headHash and the export head hash.
export function headOf(all: AuditEvent[]): { headSeq: number; headHash: string } {
  if (all.length === 0) return { headSeq: -1, headHash: GENESIS_PREV_HASH };
  const head = all[all.length - 1]!;
  return { headSeq: head.seq, headHash: head.hash };
}

// earliestSeqOf returns the seq of the OLDEST retained entry (0 for an empty log). Surfaced on the audit
// export + feed so a collector can detect a retention-rollover GAP: when its checkpoint afterSeq falls below
// earliestSeq - 1, entries between them were pruned and will never be delivered, which the envelope's headSeq
// alone could not reveal. The list is ascending by seq, so the first element is oldest.
export function earliestSeqOf(all: AuditEvent[]): number {
  return all.length === 0 ? 0 : all[0]!.seq;
}

// ---- Export ------------------------------------------------------------------------------------
// The export is the customer's own data, generated in-account; no custody concern. JSON is the
// default; CSV is offered for a spreadsheet/SIEM import. Both carry the chain head hash so an
// external verifier can confirm completeness and detect truncation-after-export. The CSV flattens
// the target to a single redaction-safe "target" column (a short, human description built only
// from the closed union's safe fields), never a raw value.

// describeTarget renders a target as a short, redaction-safe human string for the CSV column and
// for a console summary. It reads ONLY the closed union's safe fields, so it can never emit a
// secret; an unknown future variant falls through to its kind name. This is presentation of
// already-safe data, not a new place data could leak.
function describeTarget(t: AuditTarget): string {
  switch (t.kind) {
    case "downpipe":
      return t.name ? `downpipe ${t.id} (${t.name})` : `downpipe ${t.id}`;
    case "run":
      return `run ${t.runId}`;
    case "prune-approval": {
      const approver = t.approverEmail ? `, approved by ${t.approverEmail}` : "";
      const reject = t.reasonClass ? `, rejected (${t.reasonClass})` : "";
      return `prune approval for downpipe ${t.downpipeId} (${t.retainedRuns} retained, ${t.supersededRuns} superseded, ${t.planHash})${approver}${reject}`;
    }
    case "restore": {
      const where = t.redirectBinding ? `redirect to ${t.redirectBinding}` : "original bindings";
      const latest = t.isLatest ? "latest" : "older run";
      const approver = t.approverEmail ? `, approved by ${t.approverEmail}` : "";
      // Name the archive destination the cues/bytes came from, when recorded, so a reviewer
      // reading the CSV/summary does not have to open the raw JSON target to see it.
      const dest = t.destinationId ? `, dest ${t.destinationId}` : "";
      return `restore run ${t.runId} (${where}, ${latest}, ${t.planHash})${approver}${dest}`;
    }
    case "restore-receipt": {
      // The receipt anchor: the run, how many records landed verified, and the receipt's own digest. No
      // value or key is representable here, so the rendered line carries none.
      const verdict = t.allVerified ? "all verified" : "NOT all verified";
      return `restore receipt run ${t.runId} (${t.recordsRestored} restored, ${verdict}, ${t.receiptSha384})`;
    }
    case "role":
      return `role ${t.role} for ${t.email}`;
    case "grouprole":
      return `group-role ${t.role} for group ${t.group}`;
    case "customrole": {
      // A 0 capability count signals a removal (or an assignment, which records the count separately);
      // a positive count is a create/update bundling that many capabilities.
      if (t.capabilityCount > 0) return `custom role ${t.name} (${t.capabilityCount} capabilities)`;
      // On a removal, say how many grants the deletion floors to viewer. The operator reading their own
      // audit feed sees the blast radius of the tidy-up on the line that records it.
      if (typeof t.affectedGrantCount === "number" && t.affectedGrantCount > 0) {
        return `custom role ${t.name} (${t.affectedGrantCount} ${t.affectedGrantCount === 1 ? "grant" : "grants"} dropped to the viewer floor)`;
      }
      return `custom role ${t.name}`;
    }
    case "configchange": {
      // A pending config change: its kind (which mutation) + opaque id, and the checker once approved. The
      // params/diff are NOT here (the closed shape cannot hold them), so the rendered line carries no secret.
      const approver = t.approverEmail ? `, approved by ${t.approverEmail}` : "";
      return `config change ${t.changeKind} (${t.id})${approver}`;
    }
    case "owneraction": {
      // A dual-control owner action: its OPERATION KIND (which owner op) + opaque id, and the checker once
      // approved. The params (ids/fingerprints) and any credential are NOT here (the closed shape cannot hold
      // them), so the rendered line carries no secret, exactly like the configchange target.
      const approver = t.approverEmail ? `, approved by ${t.approverEmail}` : "";
      return `owner action ${t.actionKind} (${t.id})${approver}`;
    }
    case "change": {
      // A change-controlled action's CHANGE REFERENCE. Emergency changes are rendered LOUDLY (they bypass the
      // number requirement and must stand out in a SIEM/spreadsheet scan); a normal change names its CR number.
      // The reason is rendered for an emergency (the operator's justification); both number and reason are the
      // already-bounded operator free text the parse produced, never a secret.
      if (t.emergency) {
        const num = t.changeNumber ? ` ${t.changeNumber}` : " (no change number)";
        const why = t.reason ? `: ${t.reason}` : "";
        return `EMERGENCY CHANGE${num} for ${t.actionKind}${why}`;
      }
      return `change ${t.changeNumber ?? "(none)"} for ${t.actionKind}`;
    }
    case "key-ceremony":
      return "key ceremony";
    case "access-policy":
      return "access policy";
    case "posture-ack":
      // A key-posture acknowledgement: the posture chosen, the statement version, the capture channel and
      // the resolved principal type. The statement HASH is in the raw target for verification; the summary
      // reads the safe labels only, never the words (which are never stored here).
      return `posture acknowledged (${t.posture}, ${t.statementVersion}, ${t.channel}, ${t.principalType})`;
    case "custody-share":
      // A Shamir share emailed to a custodian: the threshold and total, counts only (never a share or address).
      return `custody share emailed (${t.m} of ${t.n})`;
    case "posture-check":
      return `posture check ${t.checkId}${t.overrideKind !== null ? ` (${t.overrideKind})` : ""}`;
    case "dest-change": {
      // A destination-config mutation's redaction-safe detail: the op, the id acted on (operator label), the
      // default-pointer redirect, a forced-orphan drop count, or a rejected set. No secret is representable.
      if (t.op === "remove") {
        const forced = t.force ? ` [FORCED, ${t.uncoveredOriginRunCount ?? 0} run(s) had no other proven copy]` : "";
        const promo = t.fromDefaultId !== t.toDefaultId ? ` (default ${t.fromDefaultId ?? "(none)"} -> ${t.toDefaultId ?? "(none)"})` : "";
        return `destination removed ${t.id ?? "(?)"}${promo}${forced}`;
      }
      if (t.rejectReason) return `destination set REJECTED (${t.rejectReason})`;
      if (t.op === "default") return `default destination -> ${t.toDefaultId ?? t.id ?? "(?)"}`;
      if (t.op === "clear") return t.fromDefaultId !== t.toDefaultId ? `destination cleared (default ${t.fromDefaultId ?? "(none)"} -> ${t.toDefaultId ?? "(none)"})` : "destination cleared";
      return t.id ? `destination set ${t.id}` : "destination set";
    }
    case "supportcredential":
      // The scope + the PUBLIC clientId (when known); the secret/hash are unrepresentable in the type.
      return t.clientId ? `support credential ${t.scope} (${t.clientId})` : `support credential ${t.scope}`;
    case "idpconnection":
      // The connection's protocol + opaque id and the lifecycle op, or a completed sign-in through it. No
      // secret/cert/token is representable in the type, so the rendered line carries none.
      return t.op === "signin" ? `sign-in via ${t.connKind} connection ${t.connId}` : `${t.connKind} connection ${t.connId} (${t.op})`;
    case "credential-cleanup":
      // The registry item id + the PUBLIC token id descriptor (when captured); never the token value.
      return t.tokenRef ? `credential cleanup ${t.itemId} (token ${t.tokenRef})` : `credential cleanup ${t.itemId}`;
    case "push-destination": {
      // A SIEM push destination mutation or delivery outcome: the op, a rejected set's closed reason class,
      // or a delivery-failure's consecutive-failure count. No secret or endpoint URL is representable.
      if (t.rejectReason) return `push destination set REJECTED (${t.rejectReason})`;
      if (t.op === "delivery-failure") return `push delivery failed${t.failureCount !== undefined ? ` (${t.failureCount} consecutive)` : ""}`;
      if (t.op === "test") return "push destination test send";
      if (t.op === "clear") return "push destination cleared";
      return t.id ? `push destination set ${t.id}` : "push destination set";
    }
    case "attest-session": {
      // An attended-verification session event: the opaque session id + the redaction-safe counts (how many
      // runs the event covered, the sample rate). No master, seed or proof is representable in the type.
      const runs = t.runs !== undefined ? `, ${t.runs} run(s)` : "";
      const rate = t.sampleRate !== undefined ? `, ${t.sampleRate}% sample` : "";
      return `attested verification session ${t.sessionId}${runs}${rate}`;
    }
    case "engine-state":
      return `engine ${t.field}: ${t.detail}`;
    case "test-fault": {
      // The armed instant rides the CSV column for the two ops that carry it, because a fire without its
      // window is a point in time and a reviewer needs both ends to know which verdicts to doubt.
      const since = t.armedAt ? `, armed ${t.armedAt}` : "";
      const binding = t.binding ? ` on ${t.binding}` : "";
      return `test fault ${t.op} ${t.faultKind}${binding}${since}`;
    }
  }
}

// csvCell quotes a CSV cell per RFC 4180: wrap in double quotes and double any embedded quote,
// always quoting so an embedded comma/newline (e.g. in a reason rendered into the target) is safe.
//
// CSV FORMULA INJECTION (OWASP CSV-injection guidance, https://owasp.org/www-community/attacks/CSV_Injection):
// a cell whose value begins with = + - @ tab CR or NUL is evaluated
// as a formula by Excel/Sheets/LibreOffice when the export is opened. Several columns carry IdP-claim or
// edge-header-derived text (actorEmail / actorSubject / sourceIp, and an approverEmail rendered into the
// target), so neutralise a leading formula trigger with a single quote BEFORE the RFC-4180 quote-wrap.
// Doing it here covers every column uniformly with no caller change; the quote is the recommended
// neutralisation and round-trips visibly for a human reader.
function csvCell(s: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: the tab/CR/NUL control characters are the deliberate CSV formula-injection triggers (OWASP CSV-injection guidance) this guard must detect.
  const neutralised = /^[=+\-@\t\r\x00]/.test(s) ? `'${s}` : s;
  return `"${neutralised.replace(/"/g, '""')}"`;
}

// toCSV renders the events as RFC-4180 CSV with a header row, plus a trailing comment-style row
// carrying the head hash so the head travels with the document. Columns are the safe scalars and
// the flattened target description; no raw target object, so no value can leak.
export function toCSV(events: AuditEvent[], head: { headSeq: number; headHash: string }): string {
  const header = ["seq", "ts", "actorSubject", "actorEmail", "actorMethod", "sourceIp", "action", "outcome", "target", "prevHash", "hash"];
  const lines: string[] = [header.map(csvCell).join(",")];
  for (const e of events) {
    lines.push(
      [
        String(e.seq),
        e.ts,
        e.actorSubject ?? "",
        e.actorEmail ?? "",
        e.actorMethod,
        e.sourceIp ?? "",
        e.action,
        e.outcome,
        describeTarget(e.target),
        e.prevHash,
        e.hash,
      ]
        .map(csvCell)
        .join(","),
    );
  }
  // The head row is a clearly-labelled final line carrying the chain head, so a verifier reading
  // the CSV can pin headSeq/headHash without parsing every row. It is not an event row (the seq
  // column reads "head"). It carries the same 11 cells as the header: "head" in the seq column,
  // headSeq=N in the target column, headHash in the hash column (column 11), and an empty prevHash
  // placeholder so a position-based parser reads headHash from the hash column, not prevHash.
  lines.push([csvCell("head"), csvCell(""), csvCell(""), csvCell(""), csvCell(""), csvCell(""), csvCell(""), csvCell(""), csvCell(`headSeq=${head.headSeq}`), csvCell(""), csvCell(head.headHash)].join(","));
  return `${lines.join("\r\n")}\r\n`;
}
