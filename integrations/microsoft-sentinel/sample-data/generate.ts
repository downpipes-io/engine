// Generates the Microsoft Sentinel Content Hub sample-data NDJSON for the Downpipes audit feed
// (see the Content Hub solution's "Sample data" review expectation).
//
// A reviewer approving a Content Hub submission, and the KQL parser tests, need to see
// the exact shape of events the feed produces without a live subscription. Rather than hand-type
// JSON that could quietly drift from what the engine actually emits, this script drives the
// engine's own chain-construction logic (buildEvent, src/admin/audit.ts) OFFLINE, over one
// representative AuditDraft per member of AUDIT_ACTIONS (src/admin/audit-types.ts), including the
// run-failed action. buildEvent computes the same prevHash/hash a live append would, so the output
// is a genesine-anchored, hash-chained NDJSON file that is provably the same shape as production,
// and whose own chain verifies with verifyChain exactly like a real export.
//
// The per-action AuditDraft below is a REPRESENTATIVE shape, not a captured production event: each
// one is drawn from the real call site that constructs that action in src/ (cited inline), with
// fixture-safe placeholder values substituted for anything customer-specific (RFC 5737 example
// addresses, .example email domains, opaque ids). Where an action's outcome is itself "the record
// of a rejection" (e.g. restore-reject), the outcome field still reads "success", matching
// production: the audit event records that the reject action completed, not that the underlying
// request was granted.
//
// Timestamps are a fixture sequence, one second apart from an arbitrary fixed instant, and carry
// no meaning beyond "some plausible moment" -- they are not derived from the wall clock this
// generator happens to run on.
//
// Run:
//   node integrations/microsoft-sentinel/sample-data/generate.ts
// writes sample-events.ndjson next to this file. test/validate-sentinel-sample-data.ts imports
// generateSampleEvents() directly (so it never depends on a stale committed file) and separately
// re-verifies the committed file on disk against the engine's own verifyChain.

import { createHash } from "node:crypto";
import { realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AUDIT_ACTIONS, type AuditAction, type AuditDraft, type AuditEvent } from "../../../src/admin/audit-types.ts";
import { buildEvent } from "../../../src/admin/audit.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SAMPLE_FILE = join(HERE, "sample-events.ndjson");

// FIXTURE_EPOCH_MS is an arbitrary fixed instant for the sample data's ts fields; each event adds
// one second to it, in AUDIT_ACTIONS order. It is deliberately not "today" so the file cannot be
// mistaken for a real capture.
const FIXTURE_EPOCH_MS = Date.parse("2025-03-01T00:00:00.000Z");

// fixtureHash produces a real SHA-384 hex digest of a label, so fields like planHash/receiptSha384
// look exactly like the hashes production writes (a "sha384:" prefix over 96 hex characters)
// without asserting they came from any real artefact.
function fixtureHash(label: string): string {
  return `sha384:${createHash("sha384").update(label).digest("hex")}`;
}

// Fixture identities. None of these resolve to a real Cloudflare Access tenant, IdP or customer;
// "acme.example" is the reserved documentation domain (RFC 2606) and the IPs below are the reserved
// documentation ranges (RFC 5737).
const OWNER_EMAIL = "owner@acme.example";
const OWNER_SUBJECT = "passkey|owner@acme.example";
const OPERATOR_EMAIL = "operator@acme.example";
const OPERATOR_SUBJECT = "passkey|operator@acme.example";
const APPROVER_EMAIL = "approver@acme.example";
const APPROVER_SUBJECT = "passkey|approver@acme.example";
const ACCESS_ADMIN_EMAIL = "access-admin@acme.example";
const ACCESS_ADMIN_SUBJECT = "https://acme.cloudflareaccess.com|4d2f7c1a-9b3e-4a2c-8f0d-6e1a2b3c4d5e";
const VIEWER_EMAIL = "viewer@acme.example";
const IP_A = "203.0.113.10";
const IP_B = "198.51.100.24";

// DRAFTS is a Record, not a switch: TypeScript requires exactly one entry per AuditAction member,
// so a member added to AUDIT_ACTIONS without a matching entry here is a compile error, and a typo
// in an action string is too (the same "closed union, tsc-enforced" discipline the console's own
// audit-action mirror uses). Each entry cites the real src/ call site its shape is drawn from.
export const DRAFTS: Record<AuditAction, AuditDraft> = {
  // src/sched/scheduler-do-restore-approval.ts:307
  "restore-request": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "restore-request",
    outcome: "success",
    target: { kind: "restore", runId: "run_2f8a1c9077b3", redirectBinding: null, planHash: fixtureHash("restore-plan:run_2f8a1c9077b3"), isLatest: true, reason: "verifying last night's backup restores cleanly" },
  },
  // src/sched/scheduler-do-restore-approval.ts:380
  "restore-approve": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "restore-approve",
    outcome: "success",
    target: { kind: "restore", runId: "run_2f8a1c9077b3", redirectBinding: null, planHash: fixtureHash("restore-plan:run_2f8a1c9077b3"), isLatest: true, reason: "verifying last night's backup restores cleanly", approverEmail: APPROVER_EMAIL, approverSubject: APPROVER_SUBJECT },
  },
  // src/admin/router-restore.ts:436 (the applied outcome; maker + checker both attributed)
  "restore-apply": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "restore-apply",
    outcome: "success",
    target: { kind: "restore", runId: "run_2f8a1c9077b3", redirectBinding: null, planHash: fixtureHash("restore-plan:run_2f8a1c9077b3"), isLatest: true, reason: "verifying last night's backup restores cleanly", approverEmail: APPROVER_EMAIL, approverSubject: APPROVER_SUBJECT },
  },
  // src/sched/scheduler-do-restore-approval.ts:439 (outcome stays "success": the reject act itself
  // completed). The real call site also spreads a reasonClass onto this target via a conditional
  // spread, but "restore"'s declared shape carries no such field (only "prune-approval" does) --
  // that spread evades tsc's excess-property check on an object literal, so it is left out here
  // rather than reproduced into a strictly-typed literal.
  "restore-reject": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "restore-reject",
    outcome: "success",
    target: { kind: "restore", runId: "run_9c4e6b21aa07", redirectBinding: null, planHash: fixtureHash("restore-plan:run_9c4e6b21aa07"), isLatest: true, reason: "checking the D1 change looked safe before go-live" },
  },
  // src/admin/router-restore.ts:436-462 (the receipt anchor written alongside a successful apply)
  "restore-verified": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "restore-verified",
    outcome: "success",
    target: { kind: "restore-receipt", runId: "run_2f8a1c9077b3", receiptSha384: fixtureHash("restore-receipt:run_2f8a1c9077b3"), recordsRestored: 482, allVerified: true, complete: true, recordsVerified: 482, failures: 0, readbackVerified: 482, readbackMismatched: 0 },
  },
  // src/sched/scheduler-do-prune-approval.ts:106
  "retention-prune-request": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "retention-prune-request",
    outcome: "success",
    target: { kind: "prune-approval", downpipeId: "dp_4b7e2f1a", planHash: fixtureHash("prune-plan:dp_4b7e2f1a"), retainedRuns: 30, supersededRuns: 12, reason: "clearing superseded runs past the 30-day policy" },
  },
  // src/sched/scheduler-do-prune-approval.ts:144
  "retention-prune-approve": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "retention-prune-approve",
    outcome: "success",
    target: { kind: "prune-approval", downpipeId: "dp_4b7e2f1a", planHash: fixtureHash("prune-plan:dp_4b7e2f1a"), retainedRuns: 30, supersededRuns: 12, reason: "clearing superseded runs past the 30-day policy", approverEmail: APPROVER_EMAIL, approverSubject: APPROVER_SUBJECT },
  },
  // src/sched/scheduler-do-prune-approval.ts:173 (outcome stays "success": the reject act itself completed)
  "retention-prune-reject": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "retention-prune-reject",
    outcome: "success",
    target: { kind: "prune-approval", downpipeId: "dp_9e21ff03", planHash: fixtureHash("prune-plan:dp_9e21ff03"), retainedRuns: 14, supersededRuns: 3, reason: "clearing old runs before the audit window closes", reasonClass: "insufficient-justification" },
  },
  // src/sched/scheduler-do.ts:918
  "downpipe-create": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "downpipe-create",
    outcome: "success",
    target: { kind: "downpipe", id: "dp_4b7e2f1a", name: "workers-kv-nightly" },
  },
  // src/admin/router-pipelines.ts:98
  "downpipe-delete": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "downpipe-delete",
    outcome: "success",
    target: { kind: "downpipe", id: "dp_9e21ff03" },
  },
  // src/admin/router-pipelines.ts:134 (roster-hygiene heal; field-less access-policy target)
  "downpipe-roster-reconcile": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "downpipe-roster-reconcile",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/admin/router-pipelines.ts:171
  "run-trigger": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "run-trigger",
    outcome: "success",
    target: { kind: "run", runId: "run_3a9c7d1e5f02" },
  },
  // src/sched/scheduler-do-sre-alerting.ts, reconcileAlerts: isTransition && toAlert === "failed".
  // Never a human actor, never per reconciliation tick.
  "run-failed": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "run-failed",
    outcome: "failed",
    target: { kind: "run", runId: "run_7b1f4a8c2d90" },
  },
  // src/sched/scheduler-do-rbac-mutations.ts:202
  "role-change": {
    actorSubject: ACCESS_ADMIN_SUBJECT,
    actorEmail: ACCESS_ADMIN_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "role-change",
    outcome: "success",
    target: { kind: "role", email: OPERATOR_EMAIL, role: "operator" },
  },
  // src/sched/scheduler-do-rbac-mutations.ts:444
  "group-role-change": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "group-role-change",
    outcome: "success",
    target: { kind: "grouprole", group: "backup-operators", role: "operator" },
  },
  // src/sched/scheduler-do-rbac-mutations.ts:189
  "custom-role-change": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "custom-role-change",
    outcome: "success",
    target: { kind: "customrole", name: "restore-only", capabilityCount: 3 },
  },
  // src/sched/scheduler-do-idp.ts:629 (Owner-only)
  "idp-connection-change": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "idp-connection-change",
    outcome: "success",
    target: { kind: "idpconnection", connId: "idp-primary", connKind: "oidc", op: "create" },
  },
  // src/sched/scheduler-do-idp.ts:990. advisory demonstrates the OPTIONAL, non-gating IdP acr/amr/auth_time
  // signal (V6.8.4) -- present here so the sample data covers the one AuditEvent field the DCR's fixed
  // 11-column project silently drops.
  "idp-sign-in": {
    actorSubject: "oidc|a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "oidc",
    sourceIp: IP_A,
    action: "idp-sign-in",
    outcome: "success",
    target: { kind: "idpconnection", connId: "idp-primary", connKind: "oidc", op: "signin" },
    advisory: { acr: "urn:mace:incommon:iap:silver", amr: ["pwd", "mfa"], authTime: Math.floor(FIXTURE_EPOCH_MS / 1000) },
  },
  // src/sched/scheduler-do-routing-identity.ts:66 (no identity is verified on a failed attempt)
  "authn-failure": {
    actorEmail: null,
    actorMethod: "passkey",
    sourceIp: null,
    action: "authn-failure",
    outcome: "failed",
    target: { kind: "access-policy" },
  },
  // src/admin/router-rbac.ts:347 (the console-driven marker route; intent only, never a result)
  "key-ceremony-intent": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "key-ceremony-intent",
    outcome: "success",
    target: { kind: "key-ceremony" },
  },
  // src/admin/router-keys.ts:165 (field-less on the success rows)
  "keys-installed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "keys-installed",
    outcome: "success",
    target: { kind: "key-ceremony" },
  },
  // src/admin/router-keys.ts:415
  "break-glass-rotated": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "break-glass-rotated",
    outcome: "success",
    target: { kind: "key-ceremony" },
  },
  // src/admin/router-keys.ts:487
  "operational-added": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "operational-added",
    outcome: "success",
    target: { kind: "key-ceremony" },
  },
  // src/admin/router-keys.ts:591
  "operational-removed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "operational-removed",
    outcome: "success",
    target: { kind: "key-ceremony" },
  },
  // src/admin/router-keys.ts, recordKeyCeremonyFailure: the half-keyed-engine evidence
  "key-install-failed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "key-install-failed",
    outcome: "failed",
    target: { kind: "key-ceremony", step: "SIGNER_PRIVATE", cause: "cf-put", cfStatusClass: "5xx", cfCodes: [10001] },
  },
  // src/admin/router-keys.ts, recordKeyCeremonyFailure (the removal counterpart)
  "key-removal-failed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "key-removal-failed",
    outcome: "failed",
    target: { kind: "key-ceremony", step: "OPERATIONAL_PRIVATE", cause: "cf-delete", cfStatusClass: "4xx", cfCodes: [10000] },
  },
  // src/admin/router-keys.ts:672
  "posture-acknowledged": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "posture-acknowledged",
    outcome: "success",
    target: { kind: "posture-ack", posture: "operational", statementVersion: "v3", statementSha384: fixtureHash("posture-ack-statement:v3:operational"), channel: "onboarding", principalType: "owner-passkey" },
  },
  // src/admin/router-custody.ts:235
  "custody-share-emailed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "custody-share-emailed",
    outcome: "success",
    target: { kind: "custody-share", n: 5, m: 3 },
  },
  // src/admin/router-rbac.ts:347 (the same intent-marker route, the access-policy branch)
  "access-policy-change-intent": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "access-policy-change-intent",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-observability.ts:1159 (Owner-only, posture.riskaccept)
  "posture-override-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "posture-override-set",
    outcome: "success",
    target: { kind: "posture-check", checkId: "posture-tls-min-version", overrideKind: "risk-accepted" },
  },
  // src/sched/scheduler-do-observability.ts:1183
  "posture-override-withdrawn": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "posture-override-withdrawn",
    outcome: "success",
    target: { kind: "posture-check", checkId: "posture-tls-min-version", overrideKind: "risk-accepted" },
  },
  // src/sched/scheduler-do-change-control.ts:452
  "config-change-propose": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "config-change-propose",
    outcome: "success",
    target: { kind: "configchange", id: "chg_0a1b2c3d", changeKind: "role-set" },
  },
  // src/sched/scheduler-do-change-control.ts:719
  "config-change-approve": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "config-change-approve",
    outcome: "success",
    target: { kind: "configchange", id: "chg_0a1b2c3d", changeKind: "role-set", approverEmail: APPROVER_EMAIL },
  },
  // src/sched/scheduler-do-change-control.ts:813 (outcome stays "success": the reject act itself completed)
  "config-change-reject": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "config-change-reject",
    outcome: "success",
    target: { kind: "configchange", id: "chg_4e5f6a7b", changeKind: "dest-config-set" },
  },
  // src/sched/scheduler-do-change-control.ts:601 (a stale pending change superseded by a fresher config read)
  "config-change-supersede": {
    actorSubject: APPROVER_SUBJECT,
    actorEmail: APPROVER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "config-change-supersede",
    outcome: "success",
    target: { kind: "configchange", id: "chg_8c9d0e1f", changeKind: "role-set" },
  },
  // src/sched/scheduler-do-change-control.ts:91 (the requireConfigApproval toggle itself)
  "config-policy-change": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "config-policy-change",
    outcome: "success",
    target: { kind: "access-policy", policyName: "config-approval", newValue: true },
  },
  // src/sched/scheduler-do-dual-control.ts:100
  "owner-action-propose": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "owner-action-propose",
    outcome: "success",
    target: { kind: "owneraction", id: "oa_1a2b3c4d", actionKind: "dest-remove" },
  },
  // src/sched/scheduler-do-dual-control.ts:293 (maker != checker)
  "owner-action-approve": {
    actorSubject: "passkey|second-owner@acme.example",
    actorEmail: "second-owner@acme.example",
    actorMethod: "access",
    sourceIp: IP_B,
    action: "owner-action-approve",
    outcome: "success",
    target: { kind: "owneraction", id: "oa_1a2b3c4d", actionKind: "dest-remove", approverEmail: "second-owner@acme.example" },
  },
  // src/sched/scheduler-do-dual-control.ts:409 (the approved action actually ran; actor is the maker again)
  "owner-action-execute": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "owner-action-execute",
    outcome: "success",
    target: { kind: "owneraction", id: "oa_1a2b3c4d", actionKind: "dest-remove", approverEmail: "second-owner@acme.example" },
  },
  // src/sched/scheduler-do-dual-control.ts:715 (any Owner may veto; outcome stays "success")
  "owner-action-reject": {
    actorSubject: "passkey|second-owner@acme.example",
    actorEmail: "second-owner@acme.example",
    actorMethod: "access",
    sourceIp: IP_B,
    action: "owner-action-reject",
    outcome: "success",
    target: { kind: "owneraction", id: "oa_5e6f7a8b", actionKind: "update-apply" },
  },
  // src/sched/scheduler-do-change-management.ts:144 (opt-in "Require Change Number")
  "change-recorded": {
    actorSubject: OPERATOR_SUBJECT,
    actorEmail: OPERATOR_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "change-recorded",
    outcome: "success",
    target: { kind: "change", actionKind: "restore-apply", emergency: false, changeNumber: "CHG0004521", reason: null },
  },
  // src/sched/scheduler-do-org-policy.ts:232 (the first Owner row, latched so no later bootstrap mints a second)
  "bootstrap-consumed": {
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "bootstrap-consumed",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-org-policy.ts:403 (newValue is the direction: true = retired)
  "break-glass-token-retired": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "break-glass-token-retired",
    outcome: "success",
    target: { kind: "access-policy", policyName: "break-glass-retired", newValue: true },
  },
  // src/sched/scheduler-do-account-config.ts:175
  "discovery-token-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "discovery-token-set",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-account-config.ts:115
  "discovery-token-cleared": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "discovery-token-cleared",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-account-config.ts:214
  "discovery-accounts-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "discovery-accounts-set",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-account-config.ts:267
  "discovery-sources-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "discovery-sources-set",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-account-config.ts:321 (the engine proving its own account id; no caller at all)
  "engine-account-verified": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "engine-account-verified",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-dest-config.ts:290-337, auditDestChange (the richer dest-change target)
  "dest-config-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "dest-change", op: "set", id: "s3-primary" },
  },
  // src/sched/scheduler-do-dest-config.ts:290-337 (a forced removal, uncovering two downpipes' only proven copy)
  "dest-config-cleared": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "dest-config-cleared",
    outcome: "success",
    target: { kind: "dest-change", op: "remove", id: "s3-secondary", force: true, uncoveredOriginRunCount: 2, affectedDownpipeNames: ["workers-kv-nightly", "r2-media-weekly"] },
  },
  // src/sched/scheduler-do-account-config.ts:378
  "licence-activated": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "licence-activated",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-account-config.ts:354
  "licence-cleared": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "licence-cleared",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/admin/router-updates.ts:526, recordAuditAfterSelfDeploy (phase 1 made the new version live)
  "update-promoted": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "update-promoted",
    outcome: "success",
    target: { kind: "engine-state", field: "engineVersion", detail: "0.3.2 -> 0.3.3 (0.3.3); pending canary verification" },
  },
  // src/admin/router-updates-components.ts:164 (the canary proved it healthy and it was kept)
  "update-applied": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "update-applied",
    outcome: "success",
    target: { kind: "engine-state", field: "engineVersion", detail: "0.3.2 -> 0.3.3 (canary ok, self-check ok): applied" },
  },
  // src/admin/router-updates-components.ts:225 (it did not sing and was reverted)
  "update-rolled-back": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "update-rolled-back",
    outcome: "success",
    target: { kind: "engine-state", field: "engineVersion", detail: "console standalone rollback 0.3.3 -> 0.3.2" },
  },
  // src/admin/router-updates-shared.ts:113 (aborted before going live)
  "update-refused": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "update-refused",
    outcome: "denied",
    target: { kind: "engine-state", field: "engineVersion", detail: "artefact signature did not verify against the pinned signer" },
  },
  // src/sched/scheduler-do-canary.ts:216 (canaryOp ranks a disable over a pin/cadence change)
  "canary-config": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "canary-config",
    outcome: "success",
    target: { kind: "access-policy", canaryOp: "cadence" },
  },
  // src/admin/router-discovery.ts:142 (one-shot deploy token; binding names never ride here)
  "sources-attached": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "sources-attached",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/admin/router-discovery.ts:143
  "sources-detached": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "sources-detached",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-expiry.ts:342 (an operator ATTESTATION that a spent token was deleted in Cloudflare)
  "expiry-cleanup-attested": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "expiry-cleanup-attested",
    outcome: "success",
    target: { kind: "credential-cleanup", itemId: "attach-token-2025-03", tokenRef: "CF-TOK-9f2a" },
  },
  // src/sched/scheduler-do-recovery.ts:189
  "recovery-codes-generated": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "recovery-codes-generated",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-recovery.ts:223 (minted but held back; the live set still verifies)
  "recovery-codes-staged": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "recovery-codes-staged",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-recovery.ts:453 (a wrong/absent code)
  "recovery-code-used": {
    actorEmail: null,
    actorMethod: "recovery",
    sourceIp: IP_A,
    action: "recovery-code-used",
    outcome: "failed",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-routing.ts:311
  "support-credential-grant": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "support-credential-grant",
    outcome: "success",
    target: { kind: "supportcredential", scope: "audit-feed", clientId: "client_7f3a9c1e", expiresAt: "2025-06-01T00:00:00.000Z" },
  },
  // src/sched/scheduler-do-routing.ts:356
  "support-credential-revoke": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "support-credential-revoke",
    outcome: "success",
    target: { kind: "supportcredential", scope: "audit-feed", clientId: "client_7f3a9c1e" },
  },
  // src/sched/scheduler-do-recovery.ts:921 (ASVS V6.5.6 theft/loss revocation)
  "passkey-credential-revoke": {
    actorSubject: VIEWER_EMAIL,
    actorEmail: VIEWER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "passkey-credential-revoke",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-signin-factors.ts:449 (the role is what they HELD, not a transition)
  "signin-factor-revoke": {
    actorSubject: ACCESS_ADMIN_SUBJECT,
    actorEmail: ACCESS_ADMIN_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "signin-factor-revoke",
    outcome: "success",
    target: { kind: "role", email: "departed-operator@acme.example", role: "operator" },
  },
  // src/sched/scheduler-do-rbac-mutations.ts:282 (an admin terminating a member's sessions)
  "session-terminate": {
    actorSubject: ACCESS_ADMIN_SUBJECT,
    actorEmail: ACCESS_ADMIN_EMAIL,
    actorMethod: "access",
    sourceIp: IP_B,
    action: "session-terminate",
    outcome: "success",
    target: { kind: "role", email: OPERATOR_EMAIL, role: "viewer" },
  },
  // src/cron/retention-pass.ts:543 (the cron, no human actor; an APPLIED prune only)
  "retention-prune": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "retention-prune",
    outcome: "success",
    target: { kind: "downpipe", id: "dp_4b7e2f1a", name: "workers-kv-nightly" },
  },
  // src/sched/scheduler-do-control-plane.ts:309 (the cron pass; field-less)
  "control-plane-exported": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "control-plane-exported",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-control-plane.ts:344 (the amnesia signal: an empty plane while the bucket has runs)
  "control-plane-empty": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "control-plane-empty",
    outcome: "failed",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-control-plane.ts, writeReconcileBridge (the first event of a rebuilt chain; the
  // seam marker). actorMethod is hardcoded "token" here: a break-glass-only estate has no held key for the
  // cron to use, so the reconcile is driven by the bare break-glass token, not an Access-verified caller.
  "control-plane-reconciled": {
    actorEmail: OWNER_EMAIL,
    actorMethod: "token",
    sourceIp: IP_A,
    action: "control-plane-reconciled",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-control-plane.ts:646 (an acknowledge-only clear, no reconcile)
  "control-plane-recovery-acknowledged": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "control-plane-recovery-acknowledged",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/sched/scheduler-do-control-plane.ts:780 (the cron auto-heal; no human actor; grants no authority)
  "control-plane-resumed": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "control-plane-resumed",
    outcome: "success",
    target: { kind: "access-policy" },
  },
  // src/admin/audit-status.ts:63 (a GET /admin/status presence transition false -> true)
  "engine-secret-present": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "engine-secret-present",
    outcome: "success",
    target: { kind: "engine-state", field: "secret-present", detail: "signerConfigured" },
  },
  // src/admin/audit-status.ts:81 (the presence transition true -> FALSE; a tracked secret disappearing)
  "engine-secret-absent": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "engine-secret-absent",
    outcome: "failed",
    target: { kind: "engine-state", field: "secret-absent", detail: "signerConfigured" },
  },
  // src/admin/audit-status.ts:99
  "engine-version-change": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "engine-version-change",
    outcome: "success",
    target: { kind: "engine-state", field: "engineVersion", detail: "0.3.3" },
  },
  // src/sched/scheduler-do-siem-push.ts:340-ish (the "set" branch of auditPushChange)
  "push-destination-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "push-destination-set",
    outcome: "success",
    target: { kind: "push-destination", op: "set" },
  },
  // src/sched/scheduler-do-siem-push.ts:340-ish (the "clear" branch)
  "push-destination-cleared": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "push-destination-cleared",
    outcome: "success",
    target: { kind: "push-destination", op: "clear" },
  },
  // src/sched/scheduler-do-siem-push.ts:493 (the cron drain recording a failed delivery attempt)
  "push-delivery-failure": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "push-delivery-failure",
    outcome: "failed",
    target: { kind: "push-destination", op: "delivery-failure", failureCount: 3 },
  },
  // src/sched/scheduler-do-*, the OTLP metrics-push sibling of push-destination-set (same target shape)
  "otlp-push-destination-set": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "otlp-push-destination-set",
    outcome: "success",
    target: { kind: "push-destination", op: "set" },
  },
  "otlp-push-destination-cleared": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "otlp-push-destination-cleared",
    outcome: "success",
    target: { kind: "push-destination", op: "clear" },
  },
  "otlp-push-delivery-failure": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "otlp-push-delivery-failure",
    outcome: "failed",
    target: { kind: "push-destination", op: "delivery-failure", failureCount: 2 },
  },
  // src/admin/router-attest.ts:167 (the challenge issued, runs pinned)
  "attest-session-started": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "attest-session-started",
    outcome: "success",
    target: { kind: "attest-session", sessionId: "attest_0f1e2d3c", runs: 20, sampleRate: 10 },
  },
  // src/admin/router-attest.ts:197 (proving live possession of the break-glass private)
  "attest-session-proven": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "attest-session-proven",
    outcome: "success",
    target: { kind: "attest-session", sessionId: "attest_0f1e2d3c", runs: 20, sampleRate: 10 },
  },
  // src/admin/router-attest.ts:315 (a batch of runs sampled-and-verified, counts only)
  "attest-run-verified": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "attest-run-verified",
    outcome: "success",
    target: { kind: "attest-session", sessionId: "attest_0f1e2d3c", runs: 2, sampleRate: 10 },
  },
  // src/admin/router-attest.ts:342 (the operator ending the session)
  "attest-session-aborted": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "attest-session-aborted",
    outcome: "success",
    target: { kind: "attest-session", sessionId: "attest_0f1e2d3c" },
  },
  // src/sched/scheduler-do-test-fault.ts:90 (HARNESS_TEST_FAULTS estates only)
  "test-fault-armed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "test-fault-armed",
    outcome: "success",
    target: { kind: "test-fault", op: "arm", faultKind: "drop-source-binding", binding: "R2_ARCHIVE" },
  },
  // src/sched/scheduler-do-test-fault.ts:119 (cleared BEFORE firing)
  "test-fault-disarmed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "test-fault-disarmed",
    outcome: "success",
    target: { kind: "test-fault", op: "disarm", faultKind: "drop-source-binding", binding: "R2_ARCHIVE", armedAt: "2025-03-01T00:00:00.000Z" },
  },
  // src/sched/scheduler-do-test-fault.ts:158 (the moment the hook actually changed engine behaviour)
  "test-fault-fired": {
    actorEmail: null,
    actorMethod: "engine",
    sourceIp: null,
    action: "test-fault-fired",
    outcome: "success",
    target: { kind: "test-fault", op: "fire", faultKind: "control-plane-recovery-required", armedAt: "2025-03-01T00:00:00.000Z" },
  },
  // src/sched/scheduler-do-test-fault.ts:194 (releasing the real recovery-required latch a fired fault set)
  "test-fault-control-plane-cleared": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "test-fault-control-plane-cleared",
    outcome: "success",
    target: { kind: "test-fault", op: "control-plane-clear", faultKind: "control-plane-recovery-required" },
  },
  // src/sched/scheduler-do-expiry.ts, confirmSecretRotation (an owner ATTESTATION that a bearer/
  // destination credential named in the rotation schedule was rotated; a signer/recipient key's rotation
  // is engine-observed from its fingerprint instead and never carries this action)
  "secret-rotation-confirmed": {
    actorSubject: OWNER_SUBJECT,
    actorEmail: OWNER_EMAIL,
    actorMethod: "access",
    sourceIp: IP_A,
    action: "secret-rotation-confirmed",
    outcome: "success",
    target: { kind: "secret-rotation", secretId: "admin_token" },
  },
};

export async function generateSampleEvents(): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];
  let prev: AuditEvent | null = null;
  for (let i = 0; i < AUDIT_ACTIONS.length; i++) {
    const action = AUDIT_ACTIONS[i]!;
    const draft = DRAFTS[action];
    const ts = new Date(FIXTURE_EPOCH_MS + i * 1000).toISOString();
    const event = await buildEvent(draft, i + 1, ts, prev);
    events.push(event);
    prev = event;
  }
  return events;
}

export function toNDJSON(events: AuditEvent[]): string {
  return `${events.map((e) => JSON.stringify(e)).join("\n")}\n`;
}

async function main(): Promise<void> {
  const events = await generateSampleEvents();
  writeFileSync(SAMPLE_FILE, toNDJSON(events));
  console.log(`wrote ${events.length} sample events (one per AUDIT_ACTIONS member) to ${SAMPLE_FILE}`);
}

// Run the CLI only when invoked directly, not when imported by the validator. This is a local,
// realpath-canonicalised check (matching test/lib/verdict-guard.ts's isEntryPoint), deliberately
// NOT imported from that module: importing it arms its process-wide "did you declare a verdict"
// exit hook for the whole process, which is right for a validator but wrong for a plain generator
// script that owes no pass/fail tally.
function isMainEntryPoint(importMetaUrl: string): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(importMetaUrl)) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (isMainEntryPoint(import.meta.url)) {
  void main();
}
