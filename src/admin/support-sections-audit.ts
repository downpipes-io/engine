// Support-pack section gatherers: the audit-chain / config-events domain (the PII-stripped
// configEvents excerpt with its keystone retention + field extractors, the audit-chain verify
// verdict, and the SIEM audit-feed grant state). Moved verbatim out of support.ts, which
// assembles the bundle from these gatherers; each keeps its original redaction contract
// (see the per-function comments). Behaviour is unchanged. The control-plane recovery latch
// and export-lag gatherers moved on, whole and verbatim, to support-sections-recovery.ts

import { D1_ERROR_CLASSES, METADATA_SHED_FIELDS } from "../dest/restore-fault.ts";
import { CF_WRITE_SKIP_CLASSES } from "../sources/cf-config-fault.ts";
import { RESTORE_REJECT_REASON_SET } from "./approvals.ts";
import { KEY_CEREMONY_CAUSES, KEY_CEREMONY_STEPS } from "./attach.ts";
import { TRACKED_PRESENCE_FIELDS } from "./audit-status.ts";
import { CF_STATUS_CLASSES } from "./cf-api.ts";
import { isConfigChangeKind } from "./change-control.ts";
import { EXPORT_ATTEMPT_OUTCOMES, EXPORT_CHANNELS, EXPORT_FORMATS } from "./diag-records.ts";
import { MEDIA_FAULT_CLASSES } from "./media-restore.ts";
import { RESTORE_FAILURE_CLASSES } from "./restore-types.ts";
import { doURL } from "../do-url.ts";
import { clampInt, clampTs, gateClosed, grantExpiryState } from "./support-shared.ts";

// The ROUND-5 restore-receipt vocabularies, taken from the module that CLASSIFIES at the fault site so the
// pack's gate and the classifier cannot drift apart (G055 / G348).
const D1_ERROR_CLASS_SET: ReadonlySet<string> = new Set(D1_ERROR_CLASSES);
const METADATA_SHED_FIELD_SET: ReadonlySet<string> = new Set(METADATA_SHED_FIELDS);

// The G030 media-restore gates: the closed fault classes, the per-apply conflict-digest cap, and the bare
// SHA-384 hex shape (96 lower-case hex). A digest is one-way, so the asset's bytes can never ride; the shape
// gate is what stops anything that is NOT a digest from entering the field.
const MEDIA_FAULT_CLASS_SET: ReadonlySet<string> = new Set(MEDIA_FAULT_CLASSES);
const MEDIA_CONFLICT_DIGESTS_MAX = 8;
const SHA384_HEX = /^[0-9a-f]{96}$/;

// fetchConfigEvents (v:2) pulls a small, recent, PII-STRIPPED excerpt of the tamper-evident audit chain
// for the diagnosis layer. It copies ONLY redaction-safe fields (seq, ts, action, the chain hashes, and
// for an engine-version-change the new version from the engine-state detail), never actorEmail,
// actorSubject or sourceIp. Allowlisted actions only (the closed set the diagnosis reasons over); a
// failing fetch yields an empty list (honest absence). The whole bundle signature is the integrity
// guarantee for the excerpt on the self-service path, so the owner-#1 "did a deploy drop my bindings"
// question is answerable from the downloadable bundle without a standing pull credential.
// The configEvents excerpt answers "what CHANGED", so it allowlists the CONFIG-CHANGE / OWNER / IDENTITY /
// KEY / DEST / LICENCE / UPDATE mutation actions (a diagnoser must see a deploy, a detach, a role/IdP change,
// a dest repoint, an update/rollback, a key rotation, a licence change). It deliberately EXCLUDES the
// high-FREQUENCY auth events (idp-sign-in, authn-failure), those would flood the bounded excerpt and belong
// in a separate auth-events surface. Privileged actions are infrequent, so this generous set still fits.
const CONFIG_EVENT_ALLOWLIST = new Set([
  "engine-version-change", "sources-attached", "sources-detached", "dest-config-set", "dest-config-cleared",
  "restore-apply", "restore-verified", "restore-request", "restore-approve", "restore-reject",
  "downpipe-create", "downpipe-delete", "downpipe-roster-reconcile",
  "role-change", "group-role-change", "custom-role-change", "idp-connection-change",
  "key-ceremony-intent", "keys-installed", "break-glass-rotated", "operational-removed",
  "access-policy-change-intent", "bootstrap-consumed", "break-glass-token-retired",
  "config-change-propose", "config-change-approve", "config-change-reject", "config-change-supersede", "config-policy-change",
  "owner-action-propose", "owner-action-approve", "owner-action-execute", "owner-action-reject",
  "change-recorded",
  "discovery-token-set", "discovery-token-cleared", "discovery-accounts-set", "discovery-sources-set",
  "engine-account-verified",
  "licence-activated", "licence-cleared",
  "update-promoted", "update-applied", "update-rolled-back", "update-refused", "canary-config",
  // Control-plane lifecycle (CPR: cp-lifecycle-events-not-allowlisted): a recovery export was written, the
  // plane was found empty (amnesia latched), the no-authority resume slice ran, or a break-glass reconcile
  // rebuilt the plane. Without these the whole amnesia/auto-heal/reconcile lifecycle was absent from the excerpt.
  "control-plane-exported", "control-plane-empty", "control-plane-resumed", "control-plane-reconciled",
  // control-plane-recovery-acknowledged (CP-RECOVERY-LATCH-NO-CLEAR-PATH-AFTER-ORGANIC-RESUME):
  // an authenticated owner acknowledged an organically-recovered plane (the latch cleared with no import).
  // Distinct from control-plane-reconciled precisely so a diagnoser can tell the two apart in the excerpt.
  "control-plane-recovery-acknowledged",
  // The KEY-CEREMONY FAILURE + PRESENCE-LOSS events (G026/G027). The engine recorded a secret APPEARING and
  // never one VANISHING, so "backups stopped three weeks ago" after a deploy that dropped SIGNER_PRIVATE (the
  // owner's stated #1 fear) showed signerConfigured:false TODAY with nothing, anywhere, saying WHEN it
  // flipped -- and the whole diagnosis turns on when. key-install-failed / key-removal-failed likewise: an
  // install that dies at the second PUT leaves the engine HALF-KEYED, which left no trace at all.
  "engine-secret-absent", "key-install-failed", "key-removal-failed",
  // posture-override-set (G334): an owner RISK-ACCEPTED a failing posture check, which makes a red check read
  // GREEN in every downstream report. Without the mutation in the excerpt, "our compliance report says we pass
  // immutability and the bucket does not enforce it" has no trace of the decision that made it so. The
  // schedDiag posture block carries the STANDING overrides; this carries the moment one was SET, and by
  // whether an attributable identity or the shared break-glass token. The free-text justification and the
  // acceptedBy address are dropped at their own chokepoints and never reach the excerpt.
  "posture-override-set",
]);
// Bound to the canonical RESTORE_FAILURE_CLASSES tuple rather than hand-listed, for the reason the auto-heal
// refusal codes are: a hand-listed copy is exactly how a class the fault site happily tags gets silently
// dropped at this boundary, leaving a pack that reads clean while the evidence is gone.
const RESTORE_FAILURE_CLASS_SET: ReadonlySet<string> = new Set(RESTORE_FAILURE_CLASSES);
const CONFIG_EVENTS_MAX = 40;
// Keystone actions are ALWAYS retained in the excerpt even if older than the recent window, the owner's #1
// fear ("did a deploy drop my bindings?") must never be unanswerable because the deploy/detach marker rolled
// off. The recent-window fetch is ONE bounded forward page (the DO serves it from the cursor, bounded by the
// request limit and the platform's per-list page), so on a busy account a churn of high-frequency auth events
// can push the latest keystone marker OUT of that window; we therefore fetch the latest of EACH keystone action
// DIRECTLY via the DO's server-side action filter (see fetchLatestAction), guaranteed to find it regardless of
// churn, rather than relying on the bounded window. (The whole-log COMPLIANCE export is complete; this excerpt
// deliberately reads a bounded recent window for cost, so completeness is not the property it leans on.)
// Widened (truncation review): beyond the owner-#1 deploy/detach/dest markers, the latest
// restore outcome (restore-apply-incomplete forensics), IdP connection change (sso-disruption
// attribution), and approved config change (the notify-broke-after-a-config-change correlation) are
// each bot-signal inputs that a 40-event churn of role/owner-action noise could otherwise roll out of
// the excerpt. One extra capped action-filter query each, only when absent from the recent window.
const CONFIG_EVENT_KEYSTONE = new Set([
  "engine-version-change", "sources-detached", "sources-attached", "dest-config-set", "dest-config-cleared",
  "restore-verified", "restore-apply", "idp-connection-change", "config-change-approve",
  // engine-secret-absent is a KEYSTONE for exactly the reason the deploy marker is: it is the record of WHEN a
  // key presence flipped true -> false. It is rare and old by the time the ticket is raised ("backups stopped
  // three weeks ago"), so a churn of newer events must never roll it out of the excerpt.
  "engine-secret-absent",
]);
// How far back the recent-context window's cursor reaches. NOTE: the DO serves this as ONE bounded forward
// page (bounded by the request limit and the platform's per-list page), not the whole log, so the recent
// window is best-effort CONTEXT; the keystone guarantee above does NOT depend on it (it uses the per-action
// filter instead). The whole-log compliance export (GET /audit/export, no limit) IS complete; this is not.
const CONFIG_EVENT_SCAN = 2000;
type AuditExcerptEvent = {
  seq: number;
  ts: string;
  action: string;
  // actorEmail is READ (never projected) so the excerpt can carry the ATTRIBUTED boolean (G309): the console
  // honestly renders "shared token (break-glass), no attributable email", but remotely support could not tell
  // an attributed mutation from an unattributable break-glass one -- so "who proposed this change?" had no
  // answer in the pack at all. The address itself stays out by the excerpt's standing redaction contract; only
  // its PRESENCE rides, exactly as restoreProven.by is collapsed to restoreProven.attributed.
  actorEmail?: string | null;
  target?: {
    detail?: string;
    connKind?: string;
    op?: string;
    // WS-P4 restore-apply summary fields (redaction-safe counts + booleans; projected by restoreApplyFields).
    complete?: unknown;
    allVerified?: unknown;
    recordsRestored?: unknown;
    recordsVerified?: unknown;
    failures?: unknown;
    recordsSkipped?: unknown;
    outOfWindow?: unknown;
    readbackVerified?: unknown;
    readbackMismatched?: unknown;
    d1Total?: unknown;
    d1Verified?: unknown;
    // G055 / G348 (the restore-receipt target; projected by restoreApplyFields): the D1 fault LOCUS + class,
    // the schema objects a subset restore silently filtered, and the per-record metadata that was SHED on an
    // otherwise successful write (a KV key restored with no TTL).
    d1Fault?: unknown;
    d1SchemaObjectsFiltered?: unknown;
    metadataFieldsDropped?: unknown;
    // dest-change fields (dest-config-set/cleared audit target; projected by destChangeFields).
    id?: string;
    fromDefaultId?: string;
    toDefaultId?: string;
    force?: boolean;
    uncoveredOriginRunCount?: number;
    rejectReason?: string;
    // config-change field (configchange audit target; the closed-enum changeKind projected by configChangeFields).
    changeKind?: string;
    // G026/G027 key-ceremony failure fields (the key-ceremony audit target; projected by keyCeremonyFields):
    // the CLOSED step (an env-var NAME, never a value) + cause, and Cloudflare's own status class + numeric
    // error codes. G030 media fields (the restore-receipt target; projected by restoreApplyFields): the
    // per-class media fault counts and the archived/live SHA-384 conflict pairs.
    step?: unknown;
    cause?: unknown;
    cfStatusClass?: unknown;
    cfCodes?: unknown;
    mediaFaults?: unknown;
    mediaConflictDigests?: unknown;
    // G036: the access-policy target's enrichment (projected by accessPolicyFields) and the FORCED dest
    // removal's blast radius (affectedDownpipeNames, projected by destChangeFields). G191: the cf-config
    // restore's per-surface skip-reason CLASS counts (projected by restoreApplyFields).
    policyName?: unknown;
    newValue?: unknown;
    canaryOp?: unknown;
    gateBypass?: unknown;
    affectedDownpipeNames?: unknown;
    configSkipReasons?: unknown;
    reasonClass?: unknown; // G288: the checker's CLOSED restore-rejection reason

    failuresByClass?: unknown; // G285: per-CLASS counts of the records a restore could not land

  };
  outcome?: string;
  prevHash?: string;
  hash?: string;
};
// idp-connection-change carries a structured `idpconnection` audit target ({ connKind, op }) plus an `outcome`,
// ALL closed vocabularies (audit-types.ts). The excerpt projects connKind/op/outcome so the diagnosis can tell
// WHICH kind of IdP connection changed and HOW, a delete/disable/update can break existing SSO sign-in, which the
// bare action name alone could not convey. connId is deliberately NOT projected: it is an operator-chosen slug and
// the excerpt keeps operator-chosen identifiers out by design (see the ConfigEvent contract), while the diagnosis
// only needs the protocol KIND + the OP, not which connection. Each field is forwarded ONLY when it is a member of
// its closed set, so an unexpected string is dropped rather than propagated (defence-in-depth on the redaction).
const IDP_CONN_KINDS = new Set(["oidc", "oauth2", "saml"]);
const IDP_CONN_OPS = new Set(["create", "update", "delete", "enable", "disable", "signin", "test"]);
const IDP_CONN_OUTCOMES = new Set(["success", "denied", "failed"]);
function idpConnectionFields(e: AuditExcerptEvent): Record<string, string> {
  if (e.action !== "idp-connection-change") return {};
  const out: Record<string, string> = {};
  if (typeof e.target?.connKind === "string" && IDP_CONN_KINDS.has(e.target.connKind)) out.connKind = e.target.connKind;
  if (typeof e.target?.op === "string" && IDP_CONN_OPS.has(e.target.op)) out.op = e.target.op;
  if (typeof e.outcome === "string" && IDP_CONN_OUTCOMES.has(e.outcome)) out.outcome = e.outcome;
  return out;
}
// RESTORE_OUTCOMES bounds the restore event outcome to the closed success/failed set (defence-in-depth on redaction).
const RESTORE_OUTCOMES = new Set(["success", "failed"]);
// RESTORE_APPLY_COUNT_FIELDS are the redaction-safe INTEGER-COUNT fields a restore-verified anchor carries (WS-P4).
// recordsSkipped is here for the reason the list exists. The projection answers "did my restore actually
// land, fully and verified?", and a restore that skipped records is the case where the answer is no while
// every other count looks clean: recordsRestored 98 of recordsVerified 100, failures 0, outOfWindow 0.
// Without it the pack shows support the gap and nothing that explains it, which is the shape of ticket
// this section exists to close. A non-negative integer count, so it is redaction-safe by construction.
const RESTORE_APPLY_COUNT_FIELDS = ["recordsRestored", "recordsVerified", "failures", "recordsSkipped", "outOfWindow", "readbackVerified", "readbackMismatched", "d1Total", "d1Verified"] as const;
// restoreApplyFields projects the WS-P4 restore-APPLY summary from a restore-verified / restore-apply excerpt
// event into the pack, mirroring idpConnectionFields: it answers "did my restore actually land, fully and
// verified?" (the windowed-restore complete flag, the readback-hash proof counts, the per-DB(D1) apply
// outcome), which the bare action name + presence could not. STRICTLY redaction-safe by construction: only the
// closed success/failed outcome, two booleans (complete / allVerified), and non-negative integer COUNTS are
// forwarded; each is emitted ONLY when it is the expected type (an unexpected value is dropped, never
// propagated), so a record name / value / hash-of-content can never ride through even if a future writer
// mis-stamps the target. Absent for any non-restore action.
// stripAuditControl removes the C0/C1 control codepoints from a customer-owned label before it is projected.
// It filters by CODEPOINT rather than by a regex character class: a control character written literally into a
// regex is unreadable and a classic source of silent corruption (it is what the linter's
// noControlCharactersInRegex rule exists to catch), and "no control bytes reach the pack" is clearer said outright.
function stripAuditControl(v: string): string {
  let out = "";
  for (const ch of v) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || c === 0x7f) continue;
    out += ch;
  }
  return out;
}

// CF_CONFIG_SKIP_CLASS_SET is the closed cf-config restore-skip vocabulary (G191), taken from the module that
// CLASSIFIES at the skip site, so the pack's gate and the classifier cannot drift apart.
const CF_CONFIG_SKIP_CLASS_SET: ReadonlySet<string> = new Set(CF_WRITE_SKIP_CLASSES);

// restoreRejectFields (G288): WHY the checker turned a restore down. The restore-reject event was in the
// excerpt already and carried no reason of any kind, so "why was my restore rejected?" was unanswerable from
// the pack, from the console and from the approval record alike: the checker's actual reasoning existed only in
// whatever they said to the requester. The closed class is re-gated here, so no prose can ever reach the pack.
function restoreRejectFields(e: AuditExcerptEvent): Record<string, unknown> {
  if (e.action !== "restore-reject") return {};
  const cls = e.target?.reasonClass;
  return typeof cls === "string" && RESTORE_REJECT_REASON_SET.has(cls) ? { reasonClass: cls } : {};
}

function restoreApplyFields(e: AuditExcerptEvent): Record<string, unknown> {
  if (e.action !== "restore-verified" && e.action !== "restore-apply") return {};
  const out: Record<string, unknown> = {};
  if (typeof e.outcome === "string" && RESTORE_OUTCOMES.has(e.outcome)) out.outcome = e.outcome;
  const t = e.target;
  if (t === undefined) return out;
  if (typeof t.complete === "boolean") out.complete = t.complete;
  if (typeof t.allVerified === "boolean") out.allVerified = t.allVerified;
  for (const k of RESTORE_APPLY_COUNT_FIELDS) {
    const v = t[k];
    if (typeof v === "number" && Number.isFinite(v) && v >= 0) out[k] = Math.floor(v);
  }
  // configSkipReasons (G191): the cf-config restore's per-item skip CLASSES. `skipped: 20` was an integer with
  // no cause -- the reason lived only as a RAW Cloudflare API message on an HTTP response nobody kept. The
  // classes route to OPPOSITE remediations (entitlement = a benign plan gate, and telling that customer to
  // rotate a perfectly good token is the wrong answer; quota = a full plan, not an invalid record), which is
  // why the class is the diagnosis. Re-gated on the closed vocabulary here, counts clamped; the text never rides.
  const skipReasons: Record<string, number> = {};
  if (typeof t.configSkipReasons === "object" && t.configSkipReasons !== null) {
    for (const [cls, n] of Object.entries(t.configSkipReasons as Record<string, unknown>)) {
      if (!CF_CONFIG_SKIP_CLASS_SET.has(cls)) continue; // closed vocabulary only
      const v = typeof n === "number" && Number.isFinite(n) ? Math.max(0, Math.min(1_000_000, Math.floor(n))) : 0;
      if (v > 0) skipReasons[cls] = v;
    }
  }
  if (Object.keys(skipReasons).length > 0) out.configSkipReasons = skipReasons;
  // failuresByClass (G285): the per-CLASS breakdown of a restore's failed records, re-gated on the closed
  // vocabulary here (defence in depth: anything outside the set is DROPPED, never propagated, so a future
  // change at the fault site cannot smuggle a free-text class into the pack). This answers "my restore
  // applied with 3 failures, which three?" with the actual classes (a dest token with no write scope, a
  // readback that could not PROVE bytes that in fact landed, a refused Cloudflare config surface, a
  // video that would not re-upload) rather than a bare integer. The record NAMES and the per-record
  // reason prose never ride.
  const failClasses: Record<string, number> = {};
  if (typeof t.failuresByClass === "object" && t.failuresByClass !== null) {
    for (const [cls, n] of Object.entries(t.failuresByClass as Record<string, unknown>)) {
      if (!RESTORE_FAILURE_CLASS_SET.has(cls)) continue;
      const v = typeof n === "number" && Number.isFinite(n) ? Math.max(0, Math.min(1_000_000, Math.floor(n))) : 0;
      if (v > 0) failClasses[cls] = v;
    }
  }
  if (Object.keys(failClasses).length > 0) out.failuresByClass = failClasses;
  // mediaFaults (G030): the class is the whole remediation, and the classes call for OPPOSITE actions:
  // over-size-cap is a PLATFORM limit (recover out of band; retrying cannot help), upload-failed says
  // retry, conflict-different-bytes says the id is occupied by a DIFFERENT live asset and the operator
  // must choose to overwrite or remap, and the readback split separates readback-unreadable (a transient
  // 5xx -- RETRY) from readback-mismatch (the bytes WERE read and are wrong -- a real, durable restore
  // failure). Closed class keys + clamped counts only.
  const mediaFaults: Record<string, number> = {};
  const mf = t.mediaFaults;
  if (typeof mf === "object" && mf !== null) {
    for (const [cls, n] of Object.entries(mf as Record<string, unknown>)) {
      if (!MEDIA_FAULT_CLASS_SET.has(cls)) continue; // closed vocabulary only
      if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) continue;
      mediaFaults[cls] = Math.min(1_000_000_000, Math.floor(n));
    }
  }
  if (Object.keys(mediaFaults).length > 0) out.mediaFaults = mediaFaults;
  // mediaConflictDigests (G030): on a conflict, the archived + live SHA-384 PAIR, so a "that image WAS ours"
  // dispute can be ADJUDICATED from the pack instead of argued. Shape-gated to bare 96-hex, so nothing that is
  // not a SHA-384 digest can enter -- and a digest is one-way, so the asset's bytes never ride.
  const digests = (Array.isArray(t.mediaConflictDigests) ? t.mediaConflictDigests : [])
    .slice(0, MEDIA_CONFLICT_DIGESTS_MAX)
    .flatMap((d) => {
      const p = (typeof d === "object" && d !== null ? d : {}) as { archivedSha384?: unknown; liveSha384?: unknown };
      if (typeof p.archivedSha384 !== "string" || !SHA384_HEX.test(p.archivedSha384)) return [];
      if (typeof p.liveSha384 !== "string" || !SHA384_HEX.test(p.liveSha384)) return [];
      return [{ archivedSha384: p.archivedSha384, liveSha384: p.liveSha384 }];
    });
  if (digests.length > 0) out.mediaConflictDigests = digests;
  // d1Fault (G055): the D1 restore's fault LOCUS. failedBatchIndex of batchTotal SIZES the loss (batch 1
  // of 2 = roughly half the rows never landed) and the class routes the remedy: `constraint` is the
  // customer's own schema rejecting our rows, `target-not-empty` is a REFUSAL that wrote NOTHING AT ALL
  // (the restore is safe and the fix is to drop the target). residualTableCount is what is
  // ACTUALLY in the target on a refusal (excluding sqlite_/_cf_ internals), which is how "is my database
  // half-loaded?" gets a real answer. The SQLite driver's message -- which quotes the offending ROW VALUE, and
  // therefore the customer's own data -- is read ONLY to select the class and never rides.
  const d1 = t.d1Fault;
  if (typeof d1 === "object" && d1 !== null) {
    const f = d1 as Record<string, unknown>;
    const cls = typeof f.d1ErrorClass === "string" && D1_ERROR_CLASS_SET.has(f.d1ErrorClass) ? f.d1ErrorClass : undefined;
    if (cls !== undefined) {
      // A drifted class drops the row WHOLE rather than half-carrying it: a magnitude with no cause invites a
      // wrong diagnosis more surely than an absent record does.
      const int = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(1_000_000_000, Math.floor(v)) : undefined);
      out.d1Fault = {
        d1ErrorClass: cls,
        ...(int(f.failedBatchIndex) !== undefined ? { failedBatchIndex: int(f.failedBatchIndex) } : {}),
        ...(int(f.batchTotal) !== undefined ? { batchTotal: int(f.batchTotal) } : {}),
        ...(int(f.residualTableCount) !== undefined ? { residualTableCount: int(f.residualTableCount) } : {}),
      };
    }
  }
  // d1SchemaObjectsFiltered (G055): the schema objects a subset restore SILENTLY dropped -- a table restored
  // without its indexes/triggers is a restore that "worked" and is slow or subtly wrong forever.
  if (typeof t.d1SchemaObjectsFiltered === "number" && Number.isFinite(t.d1SchemaObjectsFiltered) && t.d1SchemaObjectsFiltered > 0) {
    out.d1SchemaObjectsFiltered = Math.min(1_000_000, Math.floor(t.d1SchemaObjectsFiltered));
  }
  // metadataFieldsDropped (G348): the record RESTORED and a piece of its metadata did not. A KV key whose
  // stored expiration was unusable restores with NO TTL -- it will never expire, which is a compliance and a
  // cost fault that no error anywhere reported. Counts per closed field name; the unusable value never rides
  // (it was rejected precisely for being unusable, and carrying it would be the leak).
  const shed: Record<string, number> = {};
  const md = t.metadataFieldsDropped;
  if (typeof md === "object" && md !== null) {
    for (const [field, n] of Object.entries(md as Record<string, unknown>)) {
      if (!METADATA_SHED_FIELD_SET.has(field)) continue; // closed vocabulary only: a hostile key cannot become a pack key
      if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) continue;
      shed[field] = Math.min(1_000_000, Math.floor(n));
    }
  }
  if (Object.keys(shed).length > 0) out.metadataFieldsDropped = shed;
  return out;
}
// keyCeremonyFields projects the KEY-CEREMONY FAILURE evidence (G026/G027) off a key-install-failed /
// key-removal-failed event. Two facts a diagnosis cannot work without, neither of which existed anywhere:
//   step  - the CLOSED ceremony step it died at, which is an ENV-VAR NAME, never a value. An install that
//           died at step "break-glass" left the engine HALF-KEYED (signer set, break-glass not): the console
//           shows a partial posture and the operator cannot tell whether to retry or to start over.
//   cause - parse (the pasted key would not decode -- the customer's problem) vs cf-put / cf-delete (the
//           Cloudflare API refused -- NOT the customer's problem). Opposite tickets, and they were the same
//           evidence: none.
// cfStatusClass / cfCodes carry Cloudflare's OWN verdict (G026): cfErr already extracted the numeric error
// codes and dropped them on the floor, so "Cloudflare: HTTP 502" during a CF INCIDENT was indistinguishable
// from a token-scope problem. A "429" class is a THROTTLE (slow down; do NOT re-scope the token). Every field
// is a closed enum or a bounded list of Cloudflare's documented integer codes; the raw body (which can embed
// the account and script names) never rides, and the pasted key never existed on this path at all.
const KEY_CEREMONY_ACTIONS = new Set(["key-install-failed", "key-removal-failed"]);
const KEY_CEREMONY_STEP_SET: ReadonlySet<string> = new Set(KEY_CEREMONY_STEPS);
const KEY_CEREMONY_CAUSE_SET: ReadonlySet<string> = new Set(KEY_CEREMONY_CAUSES);
const CF_STATUS_CLASS_SET: ReadonlySet<string> = new Set(CF_STATUS_CLASSES);
const CF_CODES_MAX = 8;
function keyCeremonyFields(e: AuditExcerptEvent): Record<string, unknown> {
  if (!KEY_CEREMONY_ACTIONS.has(e.action)) return {};
  const t = e.target;
  if (t === undefined) return {};
  const out: Record<string, unknown> = {};
  if (typeof t.step === "string" && KEY_CEREMONY_STEP_SET.has(t.step)) out.step = t.step;
  if (typeof t.cause === "string" && KEY_CEREMONY_CAUSE_SET.has(t.cause)) out.cause = t.cause;
  if (typeof t.cfStatusClass === "string" && CF_STATUS_CLASS_SET.has(t.cfStatusClass)) out.cfStatusClass = t.cfStatusClass;
  // cfCodes are Cloudflare's own documented NUMERIC error codes. Integers only, capped and clamped, so a
  // drifted writer cannot turn this into a string field.
  const codes = (Array.isArray(t.cfCodes) ? t.cfCodes : [])
    .filter((c): c is number => typeof c === "number" && Number.isFinite(c))
    .slice(0, CF_CODES_MAX)
    .map((c) => Math.max(0, Math.min(1_000_000, Math.floor(c))));
  if (codes.length > 0) out.cfCodes = codes;
  return out;
}

// secretAbsentFields projects the PRESENCE-LOSS event (G027): WHICH key-presence boolean flipped true ->
// false, from the engine's own fixed TRACKED_PRESENCE_FIELDS vocabulary. The event's TIMESTAMP is the whole
// diagnosis (it is the day the backups stopped), and it rides on the event row already; this names the field.
// A closed enum member only -- never a key, a value, or a length.
const TRACKED_PRESENCE_FIELD_SET: ReadonlySet<string> = new Set(TRACKED_PRESENCE_FIELDS);
function secretAbsentFields(e: AuditExcerptEvent): Record<string, unknown> {
  if (e.action !== "engine-secret-absent") return {};
  const f = e.target?.detail;
  return typeof f === "string" && TRACKED_PRESENCE_FIELD_SET.has(f) ? { secretAbsent: f } : {};
}

// customRoleFields projects the DELETION CONSEQUENCE (G301): how many member + group grants still named the
// custom role when it was deleted, i.e. how many people the tidy-up floors to viewer at their next request.
// The deletion FACT already rode (custom-role-change is allowlisted above); the consequence rode nowhere, so
// "Bob lost access to restores after we tidied up old roles" could not be linked to the event that caused it.
//
// A CLAMPED COUNT only. Never a holder's email or subject, and never the role NAME (a customer-chosen label
// that the excerpt keeps out by the same design that keeps operator ids out of the dest-change rows). Absent
// on a create/update (the engine stamps it only on the delete path), so its presence also marks the row as a
// deletion without the excerpt having to read the capability count.
function customRoleFields(e: AuditExcerptEvent): Record<string, unknown> {
  if (e.action !== "custom-role-change") return {};
  const n = clampInt((e.target as { affectedGrantCount?: unknown } | undefined)?.affectedGrantCount, 1_000_000);
  return n !== undefined ? { affectedGrantCount: n } : {};
}

// dest-config-set / dest-config-cleared carry a structured `dest-change` audit target (op + operator labels
// + closed flags/ints). The excerpt projects the CLOSED diagnostic signals so the config-change modes the
// bare action name could not convey become visible: the op (set|clear|default|remove); whether a removal was
// FORCED past the orphan guard and how many origin runs had no other proven copy (dest-removed-force-orphans-
// runs); whether the default POINTER moved (dest-default-promotion-silent-redirect), as a BOOLEAN derived
// from the before/after ids WITHOUT surfacing the operator labels (the excerpt keeps operator ids out by
// design; the raw ids remain on the customer's own audit-feed); a REJECTED set's closed reason class
// (dest-set-validation-reject); and the failed/denied outcome. Each field is forwarded ONLY when a member of
// its closed set (defence-in-depth on the redaction), so an unexpected value is dropped, not propagated.
const DEST_CHANGE_OPS = new Set(["set", "clear", "default", "remove"]);
const DEST_REJECT_REASONS = new Set(["endpoint-not-https", "missing-fields", "invalid-config"]);
function destChangeFields(e: AuditExcerptEvent): Record<string, unknown> {
  if (e.action !== "dest-config-set" && e.action !== "dest-config-cleared") return {};
  const t = e.target;
  if (!t || typeof t.op !== "string" || !DEST_CHANGE_OPS.has(t.op)) return {};
  const out: Record<string, unknown> = { op: t.op };
  if (typeof t.force === "boolean") out.force = t.force;
  if (typeof t.uncoveredOriginRunCount === "number" && Number.isFinite(t.uncoveredOriginRunCount)) out.uncoveredOriginRunCount = Math.max(0, Math.min(1_000_000, Math.floor(t.uncoveredOriginRunCount)));
  if (typeof t.rejectReason === "string" && DEST_REJECT_REASONS.has(t.rejectReason)) out.rejectReason = t.rejectReason;
  // affectedDownpipeNames (G036): WHICH downpipes lost their only proven copy on a FORCED removal.
  // uncoveredOriginRunCount is the magnitude and answers "how bad"; this answers "who", which is the question
  // an incident timeline actually has. The names are the customer's OWN downpipe labels (the redaction class
  // downpipes[] already carries), control-stripped, clamped and capped at 5 -- the same cap the refusal
  // message already shows the operator.
  const affected = (Array.isArray(t.affectedDownpipeNames) ? t.affectedDownpipeNames : [])
    .filter((n): n is string => typeof n === "string" && n !== "")
    .slice(0, 5)
    .map((n) => stripAuditControl(n).slice(0, 128));
  if (affected.length > 0) out.affectedDownpipeNames = affected;
  // defaultChanged: whether the default pointer MOVED (a silent redirect), derived from the before/after ids
  // without surfacing the operator labels. Only when both are present (a clear/remove/default carries them).
  if (typeof t.fromDefaultId === "string" && typeof t.toDefaultId === "string") out.defaultChanged = t.fromDefaultId !== t.toDefaultId;
  // A rejected set is outcome "failed" (a denied gate is "denied"): carry it so a REJECTED/denied change reads
  // distinctly from an applied one.
  if (typeof e.outcome === "string" && (e.outcome === "failed" || e.outcome === "denied")) out.outcome = e.outcome;
  return out;
}
// accessPolicyFields projects the `access-policy` audit target's G036 enrichment. The target was FIELD-LESS
// by design, and that design lost the decisive field on every governance event that used it: an incident
// timeline could not prove WHEN dual control was disarmed (a config-approval toggle and a change-number
// toggle wrote byte-identical events), that the break-glass token was UN-retired (both directions wrote the
// same event), or that the canary was DISABLED before an incident (enable and disable were one
// "canary-config"). Every field is a CLOSED ENUM or a BOOLEAN -- the policy NAME, never its value; the
// DIRECTION, never any operator text -- so the redaction class of the target is unchanged. gateBypass is the
// posture fact that was recorded nowhere at all: the gated action was executed via the BARE BREAK-GLASS
// TOKEN, which is exempt from the high-blast dual-control auto-apply.
const ACCESS_POLICY_NAMES: ReadonlySet<string> = new Set(["config-approval", "change-number", "notify-signin-context", "break-glass-retired"]);
const CANARY_OPS: ReadonlySet<string> = new Set(["enable", "disable", "pin", "cadence"]);
function accessPolicyFields(e: AuditExcerptEvent): Record<string, unknown> {
  const t = e.target;
  if (t === undefined) return {};
  const out: Record<string, unknown> = {};
  if (typeof t.policyName === "string" && ACCESS_POLICY_NAMES.has(t.policyName)) out.policyName = t.policyName;
  if (typeof t.newValue === "boolean") out.newValue = t.newValue;
  if (typeof t.canaryOp === "string" && CANARY_OPS.has(t.canaryOp)) out.canaryOp = t.canaryOp;
  if (t.gateBypass === "break-glass") out.gateBypass = "break-glass";
  return out;
}

// CONFIG_CHANGE_ACTIONS are the dual-control config-approval lifecycle events whose audit target is the
// `configchange` variant carrying the closed-enum `changeKind` (audit-types.ts). config-policy-change is the
// gate TOGGLE (an access-policy target, no changeKind) and is deliberately excluded.
const CONFIG_CHANGE_ACTIONS = new Set(["config-change-propose", "config-change-approve", "config-change-reject", "config-change-supersede"]);
// configChangeFields projects the closed-enum `changeKind` off a config-change event's `configchange` target
// so the excerpt says WHICH config mutation was queued/approved, most importantly a NOTIFY-CONFIG mutation
// (notify-channel-set/delete, notify-rule-set/delete), so "someone changed a rule
// and broke alerting" is LEGIBLE in the pack rather than an opaque "a config change happened". The
// channel/rule mutations reach the chain as these config-change events (already allowlisted) when the
// dual-control config-approval gate is on. changeKind is a CLOSED product enum (change-control.ts), NEVER operator free
// text, and is forwarded ONLY when it is a member of that closed set (isConfigChangeKind), defence in depth on
// the redaction, mirroring idpConnectionFields; the change's params / plain-English diff are unrepresentable
// on the configchange target by design, so they can never reach the excerpt.
function configChangeFields(e: AuditExcerptEvent): Record<string, string> {
  if (!CONFIG_CHANGE_ACTIONS.has(e.action)) return {};
  const kind = e.target?.changeKind;
  return typeof kind === "string" && isConfigChangeKind(kind) ? { changeKind: kind } : {};
}
// fetchLatestAction returns the single newest audit event of one action via the DO's server-side action filter
// (limit=1), or null. This is how a keystone marker is retained even when it predates the recent window's
// server-side row cap. The action MUST be a valid AuditAction, parseAuditFilter SILENTLY DROPS an unknown
// action (which would then return the newest event of ANY action), so we re-check e.action === action as a
// guard. Every CONFIG_EVENT_KEYSTONE member is a valid AuditAction (asserted by the engine's audit-types).
async function fetchLatestAction(scheduler: DurableObjectStub, action: string): Promise<AuditExcerptEvent | null> {
  const page = await fetchActionPage(scheduler, action);
  // ASCENDING seq: the NEWEST matching event is the LAST element, not the first. (The DO's action-filtered
  // export returns the newest AUDIT_PAGE_MAX matches of that action and then reverses them into ascending
  // order; a supplied `limit` is honoured only alongside an afterSeq cursor, so it does not narrow this page.)
  const e = page[page.length - 1];
  return e != null && e.action === action ? e : null;
}

// fetchActionPage returns the DO's server-side action-filtered page (ascending seq, newest AUDIT_PAGE_MAX
// matches of that ONE action), or [] on any fault. This is the churn-proof read: a keystone marker is found
// through the action filter regardless of how much newer traffic has buried it in the recent window.
async function fetchActionPage(scheduler: DurableObjectStub, action: string): Promise<AuditExcerptEvent[]> {
  try {
    const resp = await scheduler.fetch(doURL(`/audit/export?action=${encodeURIComponent(action)}`), { method: "GET" });
    const doc = (await resp.json()) as { events?: AuditExcerptEvent[] };
    return (doc.events ?? []).filter((e) => e != null && e.action === action);
  } catch {
    return [];
  }
}

// fetchLatestForcedDestRemoval (G079) finds the newest FORCED removal of a destination that was the ONLY
// PROVEN COPY of backed-up runs, and it is smart-retained UNCONDITIONALLY.
//
// This is the single most destructive action an operator can take in the product. The engine REFUSES an
// ordinary removal that would orphan runs ("destination is the only proven copy of N backed-up run(s)"); the
// forced removal overrides that refusal and drops those copies. The data is then gone: the audit event is the
// ONLY record anywhere that says which downpipes lost their last copy, and how many runs went with it.
//
// Retaining the action NAME was not enough. dest-config-cleared is already a keystone, but the keystone rule
// retains the LATEST event of the action -- so one later, entirely benign clear (a stale destination tidied
// away) evicts the forced destruction from the excerpt, and 40 events of ordinary churn evict it from the
// recent window. The one event that must never be missing was the one most easily buried. So the predicate is
// on the DESTRUCTION, not the action: force AND at least one uncovered origin run.
//
// Redaction is unchanged: the excerpt's existing destChangeFields projection carries the op, the force flag,
// the clamped uncoveredOriginRunCount and up to five of the customer's OWN downpipe names (the class
// downpipes[] already carries). No destination id, endpoint, bucket or operator label rides.
async function fetchLatestForcedDestRemoval(scheduler: DurableObjectStub): Promise<AuditExcerptEvent | null> {
  const page = await fetchActionPage(scheduler, "dest-config-cleared");
  for (let i = page.length - 1; i >= 0; i--) {
    const e = page[i]!;
    const t = e.target;
    const uncovered = typeof t?.uncoveredOriginRunCount === "number" ? t.uncoveredOriginRunCount : 0;
    if (t?.force === true && uncovered > 0) return e;
  }
  return null;
}
// fetchConfigEvents returns { events, fetched }. `fetched` (CPR: configevents-fetch-fail-silent-empty)
// distinguishes an EMPTY-but-successful excerpt (no allowlisted changes -- benign) from a FETCH FAILURE (the
// audit export threw). Wrapped in section() at the call site, so a throwing fetch degrades to the {events:[],
// fetched:false} fallback (the excerpt is unavailable, not proof of no changes) and the section reads "error".
export async function fetchConfigEvents(scheduler: DurableObjectStub): Promise<{ events: unknown[]; fetched: boolean }> {
  {
    // Find the chain head, then pull a recent window (the export is seq-cursored ascending).
    const headResp = await scheduler.fetch(doURL("/audit/export?afterSeq=0&limit=1"), { method: "GET" });
    const head = (await headResp.json()) as { headSeq?: number };
    const headSeq = typeof head.headSeq === "number" ? head.headSeq : 0;
    const from = Math.max(0, headSeq - CONFIG_EVENT_SCAN);
    const resp = await scheduler.fetch(doURL(`/audit/export?afterSeq=${from}&limit=${CONFIG_EVENT_SCAN}`), { method: "GET" });
    const doc = (await resp.json()) as { events?: AuditExcerptEvent[] };
    const allowed = (doc.events ?? []).filter((e) => CONFIG_EVENT_ALLOWLIST.has(e.action)); // ascending seq
    // The recent window, PLUS the latest of each keystone action smart-retained even if it predates the window
    // (so a deploy/detach/dest-repoint marker is never absent just because the page filled with newer churn).
    const out = new Map<number, AuditExcerptEvent>();
    for (const e of allowed.slice(-CONFIG_EVENTS_MAX)) out.set(e.seq, e);
    for (const k of CONFIG_EVENT_KEYSTONE) {
      if ([...out.values()].some((e) => e.action === k)) continue;
      const latest = await fetchLatestAction(scheduler, k); // server-side action filter, robust to churn
      if (latest) out.set(latest.seq, latest);
    }
    // G079: the FORCED removal of the only proven copy, retained on its own PREDICATE rather than on its
    // action name. The action-name keystone above retains only the LATEST dest-config-cleared, so a single
    // later benign clear evicts the one event that records data being deliberately destroyed. Unconditional:
    // it is re-fetched even when a dest-config-cleared is already present, because the present one is very
    // likely the benign clear that displaced it. `out` is a Map keyed by seq, so retaining an event the
    // window already holds is a no-op rather than a duplicate.
    const forced = await fetchLatestForcedDestRemoval(scheduler);
    if (forced) out.set(forced.seq, forced);
    const events = [...out.values()].sort((a, b) => a.seq - b.seq).map((e) => ({
      seq: e.seq,
      at: e.ts,
      action: e.action,
      // attributed (G309): was this governance mutation made by a VERIFIED identity, or by the shared
      // break-glass token (which has no attributable human)? A boolean only -- never the email or the subject.
      attributed: typeof e.actorEmail === "string" && e.actorEmail !== "",
      ...(typeof e.hash === "string" ? { hash: e.hash } : {}),
      ...(typeof e.prevHash === "string" ? { prevHash: e.prevHash } : {}),
      ...(e.action === "engine-version-change" && typeof e.target?.detail === "string" ? { toVersion: e.target.detail } : {}),
      ...idpConnectionFields(e),
      ...restoreApplyFields(e), // WS-P4 + G030 + G285: the restore-APPLY summary, the per-class media faults + conflict digests, and the per-class failure breakdown
      ...restoreRejectFields(e), // G288: WHY the checker rejected the restore (a closed class, never prose)
      ...destChangeFields(e), // dest-config-set/cleared: the redaction-safe dest-change diagnostic signals
      ...accessPolicyFields(e), // G036: WHICH governance policy moved, and in which DIRECTION (closed enums + booleans)
      ...configChangeFields(e), // config-change-*: the closed-enum changeKind (notify-config mutation legibility)
      ...keyCeremonyFields(e), // G026/G027: the ceremony step + cause it died at, and Cloudflare's own verdict
      ...secretAbsentFields(e), // G027: WHICH key presence flipped true -> false, and (from the row's `at`) WHEN
      ...customRoleFields(e), // G301: how many grants a custom-role DELETION floors to the viewer floor
    }));
    return { events, fetched: true };
  }
}

// fetchAuditStatus pulls the audit-chain VERIFY VERDICT into the pack (CPR: audit-chain-break-verdict-absent
// + rollover-state-lost-false-tamper + near-cap-warning-absent + verify-cpu-cost-near-cap). GET /audit/verify
// recomputes the hash chain and reports whether it is INTACT or the first brokenAt seq, whether a retention
// rollover has legitimately dropped genesis (rolledOver + count + earliestSeq -- so a rollover is never
// misread as tamper), the live count + near-cap flag (prompt an export before the rollover begins), and the
// verify's own cost (duration/entries -- so a costly verify near the cap is visible). Every field is a
// boolean / int / clamped timestamp, no entry content. Best-effort: {} on failure (honest absence).
export async function fetchAuditStatus(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/audit/verify"), { method: "GET" });
    const j = (await r.json()) as { intact?: unknown; checkedThrough?: unknown; earliestSeq?: unknown; rolledOver?: unknown; rolledOverCount?: unknown; brokenAt?: unknown; headTruncated?: unknown; headTruncatedAt?: unknown; headAnchorUnreadable?: unknown; auditCountRecovered?: unknown; auditCount?: unknown; auditNearCap?: unknown; verify?: { at?: unknown; entriesChecked?: unknown; durationMs?: unknown; complete?: unknown } | null };
    const verify = j.verify && typeof j.verify === "object"
      ? {
          ...(clampTs(j.verify.at) !== undefined ? { at: clampTs(j.verify.at) } : {}),
          ...(clampInt(j.verify.entriesChecked) !== undefined ? { entriesChecked: clampInt(j.verify.entriesChecked) } : {}),
          ...(clampInt(j.verify.durationMs) !== undefined ? { durationMs: clampInt(j.verify.durationMs) } : {}),
          complete: j.verify.complete === true,
        }
      : null;
    return {
      intact: j.intact === true,
      ...(clampInt(j.checkedThrough) !== undefined ? { checkedThrough: clampInt(j.checkedThrough) } : {}),
      ...(clampInt(j.earliestSeq) !== undefined ? { earliestSeq: clampInt(j.earliestSeq) } : {}),
      rolledOver: j.rolledOver === true,
      ...(clampInt(j.rolledOverCount) !== undefined ? { rolledOverCount: clampInt(j.rolledOverCount) } : {}),
      ...(clampInt(j.brokenAt) !== undefined ? { brokenAt: clampInt(j.brokenAt) } : {}),
      // headTruncated (G313, R7): THE ONE BREAK CLASS THAT LEAVES `intact` TRUE. verifyChain walks the RETAINED
      // entries, so deleting the NEWEST ones -- the entries that record what the attacker just did -- would
      // otherwise leave the survivors perfectly linked with nothing beside `intact` to say so. The
      // engine's own head anchor (written on every append, never lowered by a rollover) proves the tail is gone,
      // and its verdict rides HERE, next to the verdict it qualifies, so `intact` can never stand alone
      // against a truncation the same call established. headTruncatedAt is the seq the anchor committed to.
      ...(j.headTruncated === true ? { headTruncated: true } : {}),
      ...(j.headTruncated === true && clampInt(j.headTruncatedAt) !== undefined ? { headTruncatedAt: clampInt(j.headTruncatedAt) } : {}),
      // headAnchorUnreadable / auditCountRecovered: THE SAME REASONING AS headTruncated ABOVE, ON THE TWO
      // OTHER VERDICTS a reader needs. They ride BESIDE the verdicts they qualify rather than instead of
      // them: `intact` still means the retained chain links, and `auditCount` is still the best available
      // count, but a reader consulting the audit block alone can also tell an engine whose head pointer
      // is trustworthy from one whose count had to be RECONSTRUCTED, and one whose tail-deletion witness
      // ran from one where it could not run at all.
      //
      // What changes is that neither `intact` nor `auditCount` can stand alone against a doubt the SAME
      // call already established.
      // can stand alone against a doubt the SAME call already established.
      ...(j.headAnchorUnreadable === true ? { headAnchorUnreadable: true } : {}),
      ...(j.auditCountRecovered === true ? { auditCountRecovered: true } : {}),
      ...(clampInt(j.auditCount) !== undefined ? { auditCount: clampInt(j.auditCount) } : {}),
      auditNearCap: j.auditNearCap === true,
      ...(verify ? { verify } : {}),
    };
  }
}

// fetchAuditFeedState pulls the audit-feed INGEST GRANT state (CPR: audit-feed-credential-lapse-siem-gap +
// siem-mirror-drop-unobserved) so support can see whether a SIEM PULL channel is wired and being used. The
// audit trail reaches a SIEM two ways: the Logpush MIRROR (account-level, invisible to the engine) and the
// PULL feed (GET /support/audit-feed, gated by an audit-feed ingest credential the engine DOES see). This
// surfaces the pull side: whether a credential is granted (configured), whether it has expired, and the
// last-pull recency (a lapse = the SIEM stopped collecting). It projects ONLY non-PII fields: the grantedBy
// email + the clientId are DROPPED; only booleans, a pull count, and clamped timestamps ride. Best-effort {}.
export async function fetchAuditFeedState(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/ingest-credential?scope=audit-feed"), { method: "GET" });
    const j = (await r.json()) as { grant?: { grantedAt?: unknown; expiresAt?: unknown; pulls?: unknown } | null };
    if (!j.grant) return { configured: false };
    const pulls = Array.isArray(j.grant.pulls) ? (j.grant.pulls as Array<{ at?: unknown }>) : [];
    const lastPullAt = pulls.length > 0 ? clampTs(pulls[pulls.length - 1]?.at) : undefined;
    const expiresAt = clampTs(j.grant.expiresAt);
    // G312: read the RAW stored value, not the clamped one. clampTs drops an EMPTY string to undefined, and
    // the old expression then answered `expired: false` and OMITTED expiresAt entirely -- so a corrupt grant
    // was byte-identical to one whose expiry field simply was not there. grantExpiryState reports the third
    // state instead of collapsing it, and `expired` stays the coarse "is it still usable" boolean every
    // existing reader takes (the gate refuses an unreadable expiry, so `true` is the honest coarse answer).
    const expiry = grantExpiryState(j.grant.expiresAt);
    const expired = expiry.readable ? expiry.expired : true;
    return {
      configured: true,
      expired,
      ...(expiry.readable ? {} : { expiryUnreadable: true }),
      pullCount: Math.min(pulls.length, 1000),
      ...(clampTs(j.grant.grantedAt) !== undefined ? { grantedAt: clampTs(j.grant.grantedAt) } : {}),
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      ...(lastPullAt !== undefined ? { lastPullAt } : {}),
    };
  }
}

// fetchMetricsFeed mirrors fetchAuditFeedState for the METRICS ingest scope (G262): a Prometheus-compatible
// scraper (Prometheus / Grafana / a Datadog agent) pulls GET /support/metrics gated by a metrics-scope ingest
// credential the engine issues (max 400 days, a 50-pull ring). Section 1 shows the grant exists but no bundle
// section read it, so "our metrics scraper stopped collecting" was undiagnosable. Same redaction contract as
// the audit feed: only booleans, a pull count and clamped timestamps ride; the grantedBy email + clientId are
// DROPPED. A fetch/parse fault PROPAGATES to section(); a not-granted scope reads configured:false ("empty").
export async function fetchMetricsFeed(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/ingest-credential?scope=metrics"), { method: "GET" });
    const j = (await r.json()) as { grant?: { grantedAt?: unknown; expiresAt?: unknown; pulls?: unknown } | null };
    if (!j.grant) return { configured: false };
    const pulls = Array.isArray(j.grant.pulls) ? (j.grant.pulls as Array<{ at?: unknown }>) : [];
    const lastPullAt = pulls.length > 0 ? clampTs(pulls[pulls.length - 1]?.at) : undefined;
    const expiresAt = clampTs(j.grant.expiresAt);
    // G312: the audit-feed block's twin, same reasoning, same three states (see fetchAuditFeedState above).
    const expiry = grantExpiryState(j.grant.expiresAt);
    const expired = expiry.readable ? expiry.expired : true;
    return {
      configured: true,
      expired,
      ...(expiry.readable ? {} : { expiryUnreadable: true }),
      pullCount: Math.min(pulls.length, 1000),
      ...(clampTs(j.grant.grantedAt) !== undefined ? { grantedAt: clampTs(j.grant.grantedAt) } : {}),
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      ...(lastPullAt !== undefined ? { lastPullAt } : {}),
    };
  }
}

// ---------------------------------------------------------------------------------------------------------
// G022: THE FAILED AUDIT-LOG EXPORT ATTEMPT.
//
// The audit chain's whole value is that it can leave the account and be verified independently. Both export
// paths are pass-throughs (the console download in router-rbac.ts, the collector feed in support-ingest.ts).
// This section records every export attempt so a failed export -- "we cannot produce our audit log", the
// same class of harm as losing it -- is itself visible, rather than the exported log being structurally
// incapable of recording its own failure to export.
//
//
// Read it as: failures/attempts is the rate; lastFailureAt is whether it is happening NOW; byChannel says who
// is blocked (an operator at a browser, or a SIEM quietly missing days); byFormat.csv alone means the whole-log
// SCAN is too big rather than the DO being down; filteredFailures separates a filter fault from an outage.
//
// Redaction: counts, closed enums and clamped epochs. The caller's filter (an actor e-mail, an action, a
// downpipe name, a date range) was reduced to one boolean at the fault site and never left it; every key here
// is re-gated against its closed set at the pack boundary too. Best-effort: {} when no export has ever been
// attempted, which is itself the honest answer to "has anyone ever taken this log out?".
const EXPORT_ATTEMPT_OUTCOME_SET: ReadonlySet<string> = new Set(EXPORT_ATTEMPT_OUTCOMES);
const EXPORT_CHANNEL_SET: ReadonlySet<string> = new Set(EXPORT_CHANNELS);
const EXPORT_FORMAT_SET: ReadonlySet<string> = new Set(EXPORT_FORMATS);

// gateCounts re-gates one {closed key -> count} tally at the pack boundary: an out-of-vocabulary key is dropped
// and every count is clamped, so a record written by a drifted build cannot widen the projected shape.
function gateCounts(m: unknown, allowed: ReadonlySet<string>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(typeof m === "object" && m !== null ? (m as Record<string, unknown>) : {})) {
    if (!allowed.has(k)) continue;
    const n = clampInt(v, 1_000_000) ?? 0;
    if (n > 0) out[k] = n;
  }
  return out;
}

export async function fetchAuditExportAttempts(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/export-attempts"), { method: "GET" });
  const j = (await r.json()) as { attempts?: unknown };
  const a = (typeof j.attempts === "object" && j.attempts !== null ? j.attempts : null) as Record<string, unknown> | null;
  if (a === null) return {}; // no export has ever been attempted: honest absence
  const byOutcome = gateCounts(a.byOutcome, EXPORT_ATTEMPT_OUTCOME_SET);
  const byChannel = gateCounts(a.byChannel, EXPORT_CHANNEL_SET);
  const byFormat = gateCounts(a.byFormat, EXPORT_FORMAT_SET);
  const lastFailureOutcome = gateClosed(a.lastFailureOutcome, EXPORT_ATTEMPT_OUTCOME_SET);
  return {
    attempts: clampInt(a.attempts, 1_000_000) ?? 0,
    failures: clampInt(a.failures, 1_000_000) ?? 0,
    ...(Object.keys(byOutcome).length > 0 ? { byOutcome } : {}),
    ...(Object.keys(byChannel).length > 0 ? { byChannel } : {}),
    ...(Object.keys(byFormat).length > 0 ? { byFormat } : {}),
    filteredFailures: clampInt(a.filteredFailures, 1_000_000) ?? 0,
    ...(typeof a.lastAt === "number" && Number.isFinite(a.lastAt) ? { lastAt: Math.max(0, Math.floor(a.lastAt)) } : {}),
    ...(typeof a.lastFailureAt === "number" && Number.isFinite(a.lastFailureAt) ? { lastFailureAt: Math.max(0, Math.floor(a.lastFailureAt)) } : {}),
    ...(lastFailureOutcome !== undefined ? { lastFailureOutcome } : {}),
  };
}
