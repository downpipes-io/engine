// Prove the supportability surface end to end: the ingest credential (client/secret)
// mints with the secret stored ONLY as its SHA-384, verifies constant-time-correctly
// (right bearer accepted; wrong secret, wrong clientId, malformed and expired bearers
// refused), the redacted grant view never carries the hash, the support bundle is
// REDACTION-SAFE (no secret value, no credential, no key material anywhere in it) and
// its hybrid signature verifies, the sealed form opens ONLY with the vendor identity
// and carries the signed bundle inside, and the public pull routes enforce the
// credential, record pulls (the most recent 50), and serve the seq-cursored audit feed a SIEM collector
// checkpoints against.
// Run: node test/validate-support.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import {
  signedSupportBundle,
  sealedSupportBundle,
  SUPPORT_SECTION_NAMES,
  summariseSections,
} from "../src/admin/support.ts";
import { buildBandManifest } from "../src/admin/support-band-manifest.ts";
import { signerFingerprint } from "../src/format/writer.ts";
import {
  mintIngestCredential,
  checkIngestCredential,
  redactGrant,
  handleSupportPull,
  type IngestGrant,
} from "../src/admin/support-ingest.ts";
import { projectDownpipeDiagnostics, selfIdentityDegradedCount, stateRefusalIndex, type SupportDownpipeRow } from "../src/admin/support-sections-downpipes.ts";
import { MARKER_ATTRIBUTION_MAX_PER_KIND, MARKER_ATTRIBUTION_ID_MAX_LEN } from "../src/seal/marker.ts";
import { expiryStatuses, type ExpiryItem } from "../src/admin/expiry.ts";
import { appendTickOutcome, applyStorageFault, classifyStorageFault, EMPTY_STORAGE_FAULTS, TICK_RING_CAP, type TickOutcome, type TickReport } from "../src/sched/scheduler-helpers.ts";
import { FREE_PLAN_SUBREQUEST_CEILING, LOW_SLICE_WALL_MS } from "../src/seal/budget.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { hybridVerify } from "../src/crypto/sign.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { parseWraps, openCapsule, sealToRecipients } from "../src/crypto/capsule.ts";
import { loadRecipients } from "../src/keys-env.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { aesGcmOpen, hkdfSha384 } from "../src/crypto/primitives.ts";
import { b64urlDecode, b64urlEncode, concat, sha256Hex, utf8 } from "../src/crypto/bytes.ts";
import { wrapConfigSecret, type WrappedSecret } from "../src/admin/config-secret.ts";
import type { Env } from "../src/env.d.ts";

// Phase-3 CPR fixtures: a real CONFIG_WRAP_KEY + a destination secret wrapped under it, so the pack's
// wrap-key health probe (fetchWrapKeyHealth) can prove the "ok" class end to end (the env key decrypts the
// encrypted-at-rest dest credential). Set in main() before the double is built.
let WRAP_KEY_B64 = "";
let WRAPPED_DEST_SECRET: WrappedSecret | null = null;

// The /expiry double's two rows, and their instants, derived ONCE from this run's clock so the double and
// the assertion that reads it can never disagree, and so neither carries a date that ages. See the long
// note at the "/expiry" case for why a written-down state was the defect and why a later literal is not the
// fix. 60 and 91 days sit well clear of APPROACHING_DAYS (30), so both rows compute "ok" with room to spare
// and a slow run cannot tip either into "approaching".
const EXPIRY_DAY_MS = 86_400_000;
const EXPIRY_DOUBLE_CLOCK = Date.now();
const LICENCE_TRACKED_NOT_AFTER = new Date(EXPIRY_DOUBLE_CLOCK + 60 * EXPIRY_DAY_MS).toISOString();
const S3_KEY_NOT_AFTER = new Date(EXPIRY_DOUBLE_CLOCK + 91 * EXPIRY_DAY_MS).toISOString();
const EXPIRY_DOUBLE_ITEMS: ExpiryItem[] = [
  { id: "lic-observed", label: "my licence", kind: "licence", expiresAt: LICENCE_TRACKED_NOT_AFTER, source: "observed" },
  { id: "s3-key", label: "S3 destination access key", kind: "credential", expiresAt: S3_KEY_NOT_AFTER, source: "manual" },
];

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A scheduler double serving the routes the bundle and the pull path read, with a
// settable grant store and a record of every call.
function schedulerDouble(): { stub: DurableObjectStub; grants: Record<string, IngestGrant | null>; pulls: { scope: string }[]; calls: string[]; auditStatusPosts: Array<Record<string, unknown>> } {
  // An audit-feed grant IS wired + has been pulled (CPR: audit-feed-credential-lapse-siem-gap). The pack must
  // surface configured/expired/lastPullAt but DROP the grantedBy email + the clientId (no-PII projection).
  //
  // expiresAt IS DERIVED FROM THE CLOCK because the assertion below reads a LIVE one. The projection computes
  // `expired: Date.now() > Date.parse(grant.expiresAt)` in src/admin/support-ingest.ts, and the assertion
  // requires expired === false, so a written-down expiry is a date on which this file turns red for reasons
  // that have nothing to do with the pack. It was, which would have reddened
  // (bisected under a shifted Date: green at plus 295 days, red at plus 296, one FAIL, auditFeed surfaces the
  // SIEM pull credential state + last-pull recency). Ninety days ahead is unambiguously unexpired and cannot
  // age. The lapsed twin at the expired-grant check stays a written-down 2020 instant on purpose: an instant
  // in the PAST only gets further past, so its assertion cannot flip and the fresh-against-lapsed pair keeps
  // meaning what it says.
  const grants: Record<string, IngestGrant | null> = {
    diagnostics: null,
    "audit-feed": { clientId: "dpc_feed", secretSha384: "0".repeat(96), scope: "audit-feed", grantedAt: "2026-06-01T00:00:00.000Z", grantedBy: "siem-admin@example.com", expiresAt: new Date(Date.now() + 90 * 86_400_000).toISOString(), pulls: [{ at: "2026-06-28T00:00:00.000Z" }, { at: "2026-06-29T00:00:00.000Z" }] },
  };
  const pulls: { scope: string }[] = [];
  type FakeAuditEvent = { seq: number; ts: string; action: string; outcome: string; prevHash: string; hash: string; target?: { kind?: string; connId?: string; connKind?: string; op?: string; detail?: string; runId?: string; receiptSha384?: string; recordsRestored?: number; allVerified?: boolean; complete?: boolean; recordsVerified?: number; failures?: number; recordsSkipped?: number; outOfWindow?: number; readbackVerified?: number; readbackMismatched?: number; d1Total?: number; d1Verified?: number; id?: string; fromDefaultId?: string; toDefaultId?: string; force?: boolean; uncoveredOriginRunCount?: number; rejectReason?: string; changeKind?: string; approverEmail?: string } };
  const auditEvents: FakeAuditEvent[] = Array.from({ length: 25 }, (_, i) => ({ seq: i + 1, ts: `2026-06-10T0${i % 10}:00:00.000Z`, action: "role-change", outcome: "ok", prevHash: `sha384:${i}`, hash: `sha384:${i + 1}` }));
  // WS-P4: a restore-verified anchor carrying the redaction-safe apply SUMMARY. This apply was WINDOWED and
  // partially failed (complete:false, 2 failures, 3 left out of window) with 2 readback mismatches, and a
  // partial D1 load (3 of 4 D1 records proven). d1Verified is set NEGATIVE to prove the pack's count guard
  // DROPS a malformed count. It replaces a role-change churn event so headSeq stays 25 and the chain is continuous.
  auditEvents[21] = { seq: 22, ts: "2026-06-10T01:30:00.000Z", action: "restore-verified", outcome: "failed", prevHash: "sha384:21", hash: "sha384:22", target: { kind: "restore-receipt", runId: "01RESTORE", receiptSha384: "sha384:rcpt", recordsRestored: 8, allVerified: false, complete: false, recordsVerified: 10, failures: 2, recordsSkipped: 4, outOfWindow: 3, readbackVerified: 8, readbackMismatched: 2, d1Total: 4, d1Verified: -1 } };
  // The three most-recent window events are idp-connection-change (seq 23-25): each carries a structured
  // idpconnection target { connKind, op } + an outcome. The excerpt must project connKind/op/outcome (all closed
  // vocabularies) but NEVER connId (an operator-chosen slug). seq23 = a DISRUPTIVE change (a SAML connection
  // DELETED, success); seq24 = a DENIED management attempt (an OIDC pre-save test); seq25 = a hostile event whose
  // connKind/op are OUTSIDE their closed sets and must be DROPPED (outcome still projected). They REPLACE role-change
  // churn so headSeq stays 25 and the chain hashes stay continuous.
  // Two dest-config events carrying the structured dest-change target (WS-D config-change modes): seq 20 = a
  // FORCED removal that dropped the only proven copy of 3 runs AND silently promoted the default (op remove +
  // force + uncoveredOriginRunCount + before/after default); seq 21 = a REJECTED set (op set + rejectReason +
  // outcome failed). The excerpt must project the CLOSED signals (op/force/count/rejectReason/defaultChanged/
  // outcome) but NEVER the operator dest ids. They REPLACE role-change churn so the chain stays continuous.
  auditEvents[19] = { seq: 20, ts: "2026-06-10T01:20:00.000Z", action: "dest-config-cleared", outcome: "success", prevHash: "sha384:19", hash: "sha384:20", target: { kind: "dest-change", op: "remove", id: "old-dest-slug", fromDefaultId: "old-dest-slug", toDefaultId: "promoted-dest-slug", force: true, uncoveredOriginRunCount: 3 } };
  auditEvents[20] = { seq: 21, ts: "2026-06-10T01:21:00.000Z", action: "dest-config-set", outcome: "failed", prevHash: "sha384:20", hash: "sha384:21", target: { kind: "dest-change", op: "set", id: "bad-dest-slug", rejectReason: "endpoint-not-https" } };
  auditEvents[22] = { seq: 23, ts: "2026-06-10T02:00:00.000Z", action: "idp-connection-change", outcome: "success", prevHash: "sha384:22", hash: "sha384:23", target: { kind: "idpconnection", connId: "acme-saml-slug", connKind: "saml", op: "delete" } };
  auditEvents[23] = { seq: 24, ts: "2026-06-10T03:00:00.000Z", action: "idp-connection-change", outcome: "denied", prevHash: "sha384:23", hash: "sha384:24", target: { kind: "idpconnection", connId: "probe-oidc-slug", connKind: "oidc", op: "test" } };
  auditEvents[24] = { seq: 25, ts: "2026-06-10T04:00:00.000Z", action: "idp-connection-change", outcome: "success", prevHash: "sha384:24", hash: "sha384:25", target: { kind: "idpconnection", connId: "evil-slug", connKind: "not-a-kind", op: "frobnicate" } };
  // seq 18-19: dual-control config-approval lifecycle events (Phase 2 item 5), placed at role-change churn slots
  // 17-18 (Phase 3 already occupies indices 19-21 / seq 20-22 with the dest-change + restore-verified anchors).
  // Each carries a `configchange` target with a closed-enum changeKind. seq18 = a NOTIFY-CONFIG mutation APPROVED
  // (a notify channel deleted): its changeKind must be projected so "someone changed a rule and broke alerting"
  // is legible, but its approverEmail + the configchange id must NEVER reach the redacted excerpt. seq19 = a
  // hostile changeKind OUTSIDE the closed vocabulary (must be DROPPED, defence in depth). They REPLACE role-change
  // churn so the chain hashes stay continuous (headSeq 25); the config-change-* actions are already allowlisted.
  auditEvents[17] = { seq: 18, ts: "2026-06-10T00:00:00.000Z", action: "config-change-approve", outcome: "success", prevHash: "sha384:17", hash: "sha384:18", target: { kind: "configchange", id: "cc-approve-secret-id", changeKind: "notify-channel-delete", approverEmail: "checker@example.com" } };
  auditEvents[18] = { seq: 19, ts: "2026-06-10T01:00:00.000Z", action: "config-change-propose", outcome: "success", prevHash: "sha384:18", hash: "sha384:19", target: { kind: "configchange", id: "cc-hostile-id", changeKind: "not-a-real-kind" } };
  // Keystone events that exist in the chain but are NOT returned by the recent-window (afterSeq) query -- only
  // by the server-side action filter. This is exactly the busy-account case the F2 keystone fix targets: the
  // latest deploy/detach marker has scrolled past the (server-capped) recent page yet must still be retained.
  const keystoneByAction: Record<string, { seq: number; ts: string; action: string; target?: { detail?: string }; prevHash: string; hash: string }> = {
    "engine-version-change": { seq: 2, ts: "2026-06-09T00:00:00.000Z", action: "engine-version-change", target: { detail: "2026.07.01-abc" }, prevHash: "sha384:k1", hash: "sha384:k2" },
    "sources-detached": { seq: 3, ts: "2026-06-09T01:00:00.000Z", action: "sources-detached", prevHash: "sha384:k2", hash: "sha384:k3" },
  };
  // calls records every DO round trip in order (method + path) so ordering contracts are provable
  // (the deploy-identity self-observation must land BEFORE the excerpt read); auditStatusPosts captures
  // the observation bodies (the timing-race fix's payload).
  const calls: string[] = [];
  const auditStatusPosts: Array<Record<string, unknown>> = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push(`${init?.method ?? "GET"} ${url.pathname}`);
      if (url.pathname === "/audit-status") {
        auditStatusPosts.push(body ?? {});
        return new Response(JSON.stringify({ appended: 0, auditCount: 25, auditNearCap: false }));
      }
      switch (url.pathname) {
        case "/downpipes":
          // nextRunAt rides (a clamped timestamp); cronResolve carries a HOSTILE class outside the closed
          // vocabulary, which the projection must DROP (defence-in-depth redaction) while keeping nextRunAt.
          // dp1 ALSO carries a persisted scheduled-restore-test FAILURE: a closed coarse code + a consecutive-
          // failure streak (support-pack mode scheduled-restore-fail-reason). The pack must project both.
          // The kv source ALSO carries a BINDING + namespaceId (not just accountId), so fetchSourcesDetached
          // resolves it against the (empty) live env bindings and reports it DETACHED (sources-detached-binding-
          // names-absent); the downpipes projection never surfaces the binding (only accountId).
          // blackoutResolve: a REAL closed class -- the deferral loop exhausted its hop ceiling and the run
          // will fire INSIDE the customer's declared change freeze (a silent change-freeze violation). The window
          // minutes/days are NOT on this row and must never be derivable from the pack.
          return new Response(JSON.stringify([{ config: { id: "dp1", name: "uploads", enabled: true, cadenceSeconds: 3600, source: { type: "kv", binding: "UPLOADS_KV", namespaceId: "ns-uploads", include: ["uploads/*"], exclude: ["uploads/tmp/*"], accountId: "acct-123" } }, lastRunId: "01RUN", inFlight: false, nextRunAt: 1_700_000_050_000, cronResolve: { class: "bogus-class", at: 1_700_000_050_000 }, blackoutResolve: { class: "hop-ceiling-fired-inside-window", at: 1_700_000_060_000 }, lastRestoreTestAt: 1_700_000_000_000, lastRestoreTestOk: false, lastRestoreTestReason: "integrity", restoreTestConsecutiveFailures: 3 }]));
        case "/history": {
          // recordsIncomplete + its PER-MARKER breakdown: the run sealed 3 incompleteness sentinels -- 2 _truncated
          // and 1 _skipped. The pack must carry incompleteByMarker verbatim (WHICH kinds, for the diagnostics-bot).
          // WS-P1: incompleteIds carries WHICH surface each kind hit (cf-config surface ids -- the closed/product
          // tokens the pack may carry). The _unavailable list is deliberately OVER-CAP (40 ids, first one over-long)
          // to prove the pack boundary re-clamps to MARKER_ATTRIBUTION_MAX_PER_KIND / MARKER_ATTRIBUTION_ID_MAX_LEN
          // and drops a non-string entry, so a malformed/oversized DO row can never bloat the pack.
          // multipartAbortFailed: this run's destination reported a FAILED multipart abort (stranded parts); the
          // pack must surface the BOOLEAN on the run row (multipart-abort-stranded-parts).
          const overCap = ["Z".repeat(MARKER_ATTRIBUTION_ID_MAX_LEN + 72), ...Array.from({ length: 40 }, (_, i) => `surface_${i}`), 123 as unknown as string];
          return new Response(JSON.stringify({ byDownpipe: { dp1: [{ runId: "01RUN", index: 4, startedAt: "2026-06-10T00:00:00.000Z", status: "ok", recordCount: 12, bytes: 4096, durationMs: 900, recordsIncomplete: 3, recordsVanished: 2, incompleteByMarker: { _truncated: 2, _skipped: 1 }, incompleteIds: { _truncated: ["dns_records", "rulesets"], _skipped: ["page_rules"], _unavailable: overCap }, multipartAbortFailed: true }] } }));
        }
        case "/notify/history":
          // The DO returns a FLAT bare array of NotifyHistoryEntry (NOT a nested { entries:[{deliveries}] }).
          // NOTIF (dns-rebinding-gap): the send-time sinkScreen verdict rides here. A DELIVERED webhook to a bare
          // hostname carries sinkScreen:"hostname" (the residual rebind-exposed class — success, not a failure);
          // an out-of-vocab verdict must be DROPPED by the projection (defence in depth).
          // seq 4: the CRUELLEST notify row. The JSM create was async-ACCEPTED (202) so `delivered:true`
          // -- but the follow-up status poll came back with the provider POSITIVELY reporting the create FAILED.
          // The page never existed. That is a REAL non-delivery hiding inside a delivered:true row, and both
          // `unconfirmed` and `ackOutcome` were being dropped by the pack. seq 5 carries a HOSTILE ackOutcome the
          // closed gate must drop. seq 2 carries the rotated-wrap-key code (credential-undecryptable), which
          // used to masquerade as the misleading `no-transport`.
          return new Response(JSON.stringify([
            { seq: 5, ts: "2026-06-10T00:00:05.000Z", event: "backup-failure", severity: "critical", downpipeId: "dp1", channelKind: "servicenow", delivered: true, unconfirmed: true, ackOutcome: "hostile-not-an-outcome" },
            { seq: 4, ts: "2026-06-10T00:00:04.000Z", event: "backup-failure", severity: "critical", downpipeId: "dp1", channelKind: "jsm", delivered: true, unconfirmed: true, ackOutcome: "async-create-failed" },
            { seq: 3, ts: "2026-06-10T00:00:03.000Z", event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true, sinkScreen: "hostname" },
            { seq: 2, ts: "2026-06-10T00:00:02.000Z", event: "backup-failure", severity: "critical", downpipeId: "dp1", channelKind: "webhook", delivered: false, deliveryCode: "credential-undecryptable", sinkScreen: "id=secret-leak" },
            { seq: 1, ts: "2026-06-10T00:00:01.000Z", event: "backup-ok", severity: "info", channelKind: "email", delivered: true },
          ]));
        case "/notify/channels":
          // Two channels (one DISABLED). Ids are server-minted ULIDs (not customer data); the pack counts a
          // disabled channel and uses the id set to detect a rule referencing a DELETED channel.
          return new Response(JSON.stringify([{ id: "ch-live", kind: "webhook", url: "https://hooks.example/secret-path", enabled: true }, { id: "ch-off", kind: "email", toAddresses: ["ops@example.com"], enabled: false }]));
        case "/notify/rules":
          // events: "all" is a valid rule shape (NotifyEvent[] | "all"); the pack must normalise the bare
          // string to a single-element array. channelIds references a DELETED channel (ch-deleted) so the pack
          // counts a DANGLING rule->channel reference (rule-references-missing-or-deleted-channel).
          return new Response(JSON.stringify([{ events: "all", minSeverity: "warn", scope: { kind: "global", downpipeId: "dp1" }, channelIds: ["ch-live", "ch-deleted"] }]));
        case "/notify/digest-pending":
          // NOTIF: a non-empty deferred success-digest queue (the pack surfaces depth + oldest deferred + the
          // per-cadence window state: depth/oldest/dueAt per daily/weekly, so a never-flushing digest names
          // WHICH cadence is stuck and WHEN its batch was due).
          return new Response(JSON.stringify({
            count: 2,
            oldestAt: "2026-06-28T00:00:00.000Z",
            byPeriod: {
              daily: { count: 1, oldestAt: "2026-06-29T00:00:00.000Z", dueAt: "2026-06-30T00:00:00.000Z" },
              weekly: { count: 1, oldestAt: "2026-06-28T00:00:00.000Z", dueAt: "2026-07-05T00:00:00.000Z" },
            },
          }));
        case "/canary/transitions":
          // NOTIF (canary-transition-only-pages-once): the canary's aggregate liveness + its bounded transition
          // ring. A transition with an out-of-vocab `to` must be DROPPED; a valid dead/recovered rides through.
          return new Response(JSON.stringify({
            enabled: true,
            status: "dead",
            deadDestinations: 1,
            transitionCount: 2,
            transitions: [
              { at: "2026-06-30T01:00:00.000Z", destinationId: "offsite-s3", to: "dead", runSeq: 12 },
              { at: "2026-06-29T01:00:00.000Z", destinationId: null, to: "bogus", runSeq: 11 },
            ],
          }));
        case "/notify/cooldowns":
          // NOTIF (cooldown-suppresses-renudge-1h): the per-downpipe alert-cooldown state (which pipes are within
          // a re-nudge cooldown, and since when), for the staleness/failure + replication streams. An out-of-vocab
          // state must be DROPPED.
          return new Response(JSON.stringify({
            cooldownMs: 3_600_000,
            alert: [
              { downpipeId: "dp1", state: "failed", at: 1_700_000_500_000 },
              { downpipeId: "dp-bad", state: "not-a-state", at: 1_700_000_600_000 },
            ],
            replication: [{ downpipeId: "dp1", state: "replication-degraded", at: 1_700_000_700_000 }],
          }));
        case "/control-plane/recovery-status":
          // refused carries a FREE-TEXT reason in the DO that can embed a secret field NAME + a storage JSON
          // path; the pack MUST project it to a boolean (F1) and never forward the reason, but it DOES forward
          // the closed `refusedCode` classifier. staged carries a sourceKey bucket path that MUST be dropped.
          // The needs-new-logging signals ride here too: amnesiaProbe (the latch's own blind spot), deploy
          // (the deterministic deploy-identity marker), exportHealth (skip reason + per-dest write outcome),
          // and the staged resume diagnostics (resumeSkipped/appliedVersion) — all closed enums/ints/flags.
          return new Response(JSON.stringify({
            recoveryRequired: true,
            reason: "scheduler durable object was found empty while signed archives remain",
            configEmpty: true,
            resumeApplied: false,
            refused: { reason: 'the latest recovery export failed the no-custody/shape check: no-custody violation: plaintext secret field "secretAccessKey" at $.destinations[0]', at: "2026-06-10T00:00:00.000Z", code: "shape-check" },
            refusedCode: "shape-check",
            amnesiaProbe: { probe: "runs-present", at: "2026-06-10T00:00:00.000Z" },
            deploy: { engineVersion: "9.9.9-test", cfVersionId: "cf-deploy-xyz", cfVersionIdAbsent: false, baselineEstablished: true, changesObserved: 2, firstSeenAt: "2026-06-01T00:00:00.000Z", lastSeenAt: "2026-06-30T00:00:00.000Z", lastChangeAt: "2026-06-29T00:00:00.000Z" },
            exportHealth: { at: "2026-06-30T00:00:00.000Z", skipped: "budget-yield", wroteAny: false, configVersion: 7, perDest: [{ id: "primary-r2", ok: true }, { id: "offsite-s3", ok: false }] },
            staged: { version: "v42", stagedAt: "2026-06-09T00:00:00.000Z", downpipes: 3, resumeApplied: false, resumeSkipped: 1, appliedVersion: 42, appliedAt: "2026-06-09T00:00:00.000Z", sourceKey: "downpipe/control-plane/export-v42.json" },
          }));
        case "/control-plane/export-state":
          // B4 export-lag: the last-export pointer carries the config VERSION the signed control-plane export
          // covered, the configContentHash (which the pack MUST drop), and WHEN it was written.
          return new Response(JSON.stringify({ configVersion: 7, configContentHash: "sha384:x", exportedAt: "2026-06-29T00:00:00.000Z" }));
        case "/replication":
          // A3.2: dp1 has a healthy origin AND a replica proven DOWN this run (lastOk:false). The down
          // destination is recorded ONLY here (not on the run row), so the pack must surface it from here.
          return new Response(JSON.stringify({ byDownpipe: { dp1: {
            "origin-r2": { holdsRunId: "01RUN", holdsIndex: 4, lastOk: true, lastAttemptAt: 1_700_000_000_000 },
            "replica-s3": { holdsRunId: "01OLD", holdsIndex: 2, lastOk: false, lastAttemptAt: 1_700_000_100_000, reason: "unreachable" },
          } } }));
        case "/reconcile-inventory":
          // The cron's report-only reconcile pass persisted a per-destination inventory + RUNLOG health.
          // origin-r2 has recoverable-but-invisible orphan runs; replica-s3 has a corrupt / unverifiable
          // RUNLOG (the runlog-unverifiable abstain class -- the runlog-corrupt-parse signal).
          // origin-r2 now carries the SPLIT counts the DO inventory always made but the three-way summary
          // folded away -- `undetermined` splits into a benign too-young run, a HARD read fault, and a read-BUDGET
          // deferral (the count that never drains because every pass runs out of budget), and `neverReferenced`
          // splits TAMPER (root signature invalid) from a CRASHED FINALISE. replica-s3 tripped the circuit
          // breaker, whose numerator/denominator ARE the whole diagnosis.
          return new Response(JSON.stringify({ byDest: [
            { destKey: "origin-r2", at: 1_700_000_000_000, runlogPresent: true, runlogSigVerified: true, runlogHealth: "ok", committed: 12, orphanedRecoverable: 2, neverReferenced: 3, undetermined: 6, freshnessResiduals: 1, circuitBreakerTripped: false, undeterminedWithinGrace: 1, undeterminedUnreadable: 2, undeterminedPendingClassify: 3, neverReferencedSigInvalid: 1, neverReferencedAttestIncomplete: 2 },
            { destKey: "replica-s3", at: 1_700_000_050_000, runlogPresent: true, runlogSigVerified: false, runlogHealth: "corrupt", committed: 0, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, freshnessResiduals: 0, circuitBreakerTripped: false, deferred: "runlog-unverifiable" },
            // A THIRD destination whose mass-orphan CIRCUIT BREAKER tripped: the fraction that tripped the
            // guard IS the whole diagnosis, carried as its two raw counts and never as a ratio sentence.
            { destKey: "cold-s3", at: 1_700_000_060_000, runlogPresent: true, runlogSigVerified: true, runlogHealth: "ok", committed: 1, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, freshnessResiduals: 0, circuitBreakerTripped: true, deferred: "circuit-breaker", orphanFractionNumerator: 9, orphanFractionDenominator: 10 },
          ] }));
        case "/seal-faults":
          // The seal DO's bounded OBSERVE ring, newest first. A truncated-archive refuse carries its
          // found/expected counts; an orphan-root reclaim on a WORM destination carries the wormBlocked signal;
          // a hostile out-of-vocabulary kind must be DROPPED by the pack's defence-in-depth gate. (Modes
          // shard-list-truncated / orphan-root-worm-leak / signer-rotation-strands-runs.)
          // Retention adds three kinds: a prune that ABSTAINED (deferClass + the opaque id of the
          // blocking retained run -- the run that defers every pass forever), superseded runs the planner
          // SILENTLY excluded because they would not read, and an ENFORCED prune that died PARTWAY through its
          // delete loop with WORM refusing the delete (an irreducible remainder -- the real "storage keeps
          // growing" cause). A HOSTILE deferClass must be dropped while the rest of its row survives.
          return new Response(JSON.stringify({ faults: [
            { kind: "orphan-root-reclaim", at: 1_700_000_200_000, downpipeId: "dp1", runId: "01C", reclaimed: 0, wormBlocked: true },
            { kind: "shard-list-truncated", at: 1_700_000_100_000, downpipeId: "dp1", runId: "01RUN", found: 968, expected: 970 },
            { kind: "hostile-not-a-kind", at: 1_700_000_150_000, downpipeId: "dp1" },
            { kind: "prune-deferred", at: 1_700_000_210_000, downpipeId: "dp1", runId: "01BLOCK", deferClass: "retained-run-unreadable", skipped: 2, unparseableTime: 1 },
            { kind: "prune-runs-skipped", at: 1_700_000_220_000, downpipeId: "dp1", skipped: 3, deferClass: "s3://bucket/secret-key.txt not-a-class" },
            { kind: "prune-partial-apply", at: 1_700_000_230_000, downpipeId: "dp1", superseded: 5, reclaimed: 12, partial: true, wormBlocked: true },
          ] }));
        case "/tick-info":
          return new Response(JSON.stringify({ lastTickAt: Date.now() }));
        case "/update-status":
          // The safe-apply update lifecycle: a PENDING promote awaiting canary + a LAST outcome that
          // ROLLED BACK because the canary went dead, plus the rollback-needed latch + the anti-rollback
          // high-water mark. The reason is an engine-authored class; version strings are engine ids.
          return new Response(JSON.stringify({
            pending: { fromVersion: "2026.06.30", toVersion: "2026.07.01-abc", recommendedVersion: "2026.07.01-abc", riskClass: "migration", promotedAt: 1_700_000_800_000 },
            last: { outcome: "rolled-back", fromVersion: "2026.06.30", toVersion: "2026.07.01-abc", canaryVerdict: "dead", selfCheckOk: true, settleTrace: [{ step: "canary-flight", ok: false, detail: "dead" }, { step: "canary-flight-retry-1", ok: false, detail: "dead" }], at: 1_700_000_900_000, reason: "canary readback found strayed bytes; auto-rolled-back" },
            rollbackNeeded: { recommendedVersion: "2026.07.01-abc", toVersion: "2026.07.01-abc", canaryVerdict: "dead", at: 1_700_000_950_000 },
            settledHighWaterMark: "2026.06.30",
          }));
        case "/sources/discovery-config":
          // The engine account IS marked (an engineAccountId is stored), so engineAccountMarked resolves true.
          return new Response(JSON.stringify({ config: { engineAccountId: "acct-engine-xyz" } }));
        case "/scheduler-signals":
          // The scheduler-liveness aggregate: a HEALTHY tick followed by a FALSE-GREEN one (a large interval =
          // missed ticks, dispatched 0 of 5 due, 2 coalesced + 3 carried, a crashed pass, and an over-budget
          // subrequest overdraw), a DRIFTED due-index snapshot, and a RESET runlog counter (counter < max index).
          return new Response(JSON.stringify({
            ticks: [
              { at: 1_000, intervalMs: 0, due: 3, dispatched: 3, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 120, budgetRemaining: 580, overBudget: false },
              { at: 900_000, intervalMs: 899_000, due: 5, dispatched: 0, coalesced: 2, carried: 3, sealErrors: 0, passErrors: 1, budgetCap: 700, budgetSpent: 720, budgetRemaining: 0, overBudget: true },
            ],
            dueIndex: { at: 900_000, indexEntriesBeforeRebuild: 4, indexEntriesRequired: 5, dpTotal: 5, matched: false },
            runlog: { counter: 3, maxHistoryIndex: 7 },
            listCaps: { pageSize: 1000, maxPages: 1000, historyRings: 5 },
            // SCHED persist-state-storage-fault / INFRA do-value-size-limit: the DISTINCT persist-state storage-
            // fault counter — 3 faults, 1 of them a DO value-too-large put, the last one a value-too-large.
            // lastDownpipeId ATTRIBUTES it: a climbing valueTooLarge count that names no downpipe cannot
            // be acted on, so the pack now says WHICH downpipe's dp: record outgrew the DO per-value cap.
            storageFaults: { total: 3, valueTooLarge: 1, putFailed: 2, lastAt: 950_000, lastKind: "value-too-large", lastDownpipeId: "dp1" },
            // schedHealth: the housekeeping faults that would otherwise be fully silent. listTruncations > 0 is the
            // cruellest -- downpipes past the DO paging cap are never enumerated, so they read as NONEXISTENT to
            // due() and simply stop being scheduled. parityStampStale says the dueIndex block above is a STALE
            // snapshot being served as if fresh (its parity-stamp write failed after that snapshot was taken).
            schedHealth: {
              sweepFaults: { count: 4, lastAt: 940_000 },
              listTruncations: { count: 2, lastAt: 945_000 },
              parityStampFailures: { count: 1, lastAt: 950_000 },
              parityStampStale: true,
            },
            // stateRefusals: dp1's persisted record was REFUSED at read time -- the engine was rolled
            // back and is reading NEWER-schema state, so dp1 is skipped before a run row is ever created (it
            // silently stops producing runs, showing only growing staleness). The second row carries a HOSTILE
            // out-of-vocabulary class the pack MUST drop (defence in depth).
            stateRefusals: {
              total: 2,
              truncated: false,
              downpipes: [
                { downpipeId: "dp1", class: "schema-newer", at: 1_700_000_070_000, count: 9, storedVersion: 4, supportedVersion: 3 },
                { downpipeId: "dp-hostile", class: "not-a-real-class", at: 1_700_000_070_000, count: 1, storedVersion: 1, supportedVersion: 3 },
              ],
            },
          }));
        case "/retention-state":
          // The latest retention-prune pass. This is the "storage keeps growing despite my retention
          // policy" pack answer. dp1 DEFERRED (a retained run could not be read, so nothing was safe to delete --
          // the perpetual-deferral case); dp-dry is the single commonest cause of all, `enforce` never set;
          // dp-bad carries a HOSTILE outcome the pack MUST drop whole (the outcome is load-bearing).
          // replicationUnreadable: the M7 coverage gate ran on NO proof, so every replicated run was HELD.
          return new Response(JSON.stringify({ record: {
            at: 1_700_000_300_000,
            downpipesWithRetention: 3,
            replicationUnreadable: true,
            auditWriteFailures: 2,
            destinations: [{ destKey: "origin-r2", downpipeCount: 3, skipCode: "runlog-unreadable" }],
            downpipes: [
              { id: "dp1", outcome: "deferred", deferralClass: "retained-run-unreadable", supersededRuns: 0, runTreeObjects: 0, orphanSegs: 0, retainedRuns: 12, volumeHeld: 1 },
              { id: "dp-dry", outcome: "dry-run", supersededRuns: 5, runTreeObjects: 40, orphanSegs: 3, retainedRuns: 10 },
              { id: "dp-bad", outcome: "not-a-real-outcome", supersededRuns: 0, runTreeObjects: 0, orphanSegs: 0, retainedRuns: 0 },
            ],
          } }));
        case "/beacon-state":
          // The last opt-in vendor-beacon POST outcome (beacon-post-lost): a healthy attempt (2xx) this tick.
          return new Response(JSON.stringify({ at: 1_700_000_000_000, ok: true, status: 200 }));
        case "/destinations":
          // Two destinations for the effective-resolution block: d-r2 FORCES vhost on a DOTTED bucket (a TLS-SNI
          // risk) + carries a storage class; d-s3 uses auto addressing on a DNS-safe amazonaws bucket (-> vhost).
          // The endpointHost + bucket are used ONLY to compute the derived signals and must never be surfaced.
          // Each destination's IMMUTABILITY posture must be visible: d-r2 is the dangerous immutability SHADOW:
          // a WORM policy is CONFIGURED but the bucket does NOT actually enforce Object-Lock, so the customer
          // believes their archive is immutable and it is not. d-s3 has a HOSTILE objectLock value the pack
          // must drop. Every destination's posture must ride, not only the DEFAULT destination (via the single
          // live wormPosture probe).
          return new Response(JSON.stringify({ destinations: [
            { id: "d-r2", label: "R2", endpointHost: "acct.r2.cloudflarestorage.com", bucket: "my.dotted.bucket", addressing: "vhost", storageClass: "STANDARD_IA", worm: { mode: "compliance", retentionDays: 30 }, objectLock: "not-enforced", deleteProbe: "ok" },
            { id: "d-s3", label: "S3", endpointHost: "s3.amazonaws.com", bucket: "plainbucket", addressing: "auto", objectLock: "hostile-not-a-state", deleteProbe: "denied" },
            { id: "d-path", label: "Path", endpointHost: "s3.example.com", bucket: "third", addressing: "path" },
            // The pre-existing REDACTION HOLE (found by the bot wave, already shipping): storageClass was
            // projected with a bare `typeof === "string"` check, so an OPERATOR-CONTROLLED value rode into the
            // confidential pack ungated. It must now be SHAPE-GATED to the engine's own S3 storage-class
            // allow-list, collapsing anything else to unknown-code -- never carrying the value verbatim.
            { id: "d-ungated", label: "Ungated", endpointHost: "s3.example.com", bucket: "fourth", addressing: "path", storageClass: "GLACIER acme-secret-bucket-name" },
          ], defaultId: "d-r2" }));
        // Item 1 (DO-owned status opts): the pack now round-trips these so buildStatus lights up the same
        // break-glass-disposal / expiry / live-destination findings the console's /admin/status shows.
        case "/expiry/warnings":
          return new Response(JSON.stringify({ expiryWarnings: 2, cleanupPending: 1 }));
        case "/policy/break-glass-disposal":
          return new Response(JSON.stringify({ bootstrapConsumed: true, breakGlassTokenRetired: false }));
        case "/dest-status":
          // A LIVE console-set R2 destination (reached via its S3-compatible endpoint): consoleDestSet:true
          // drives statusSource "live"; the r2.cloudflarestorage.com host resolves destResolved to "r2".
          // The host itself must NEVER reach the bundle (buildStatus uses it only to pick the KIND).
          return new Response(JSON.stringify({ present: true, endpointHost: "acct123.r2.cloudflarestorage.com" }));
        case "/sso-failures":
          // D2: the bounded per-code SSO sign-in failure aggregate. Includes a code OUTSIDE the closed vocabulary
          // ("bogus-injected") to prove the projection DROPS it, and a zero-count code to prove it is omitted.
          return new Response(JSON.stringify({
            issuer: { count: 5, lastAt: "2026-06-10T00:00:00.000Z" },
            "clock-skew": { count: 2, lastAt: "2026-06-10T01:00:00.000Z" },
            "bogus-injected": { count: 9, lastAt: "2026-06-10T02:00:00.000Z" },
            connection: { count: 0, lastAt: "2026-06-10T03:00:00.000Z" },
          }));
        case "/sso-failures-by-kind":
          // P1: the per-connection-KIND breakdown. "bogus-kind" (outer) and "bogus-code" (inner) are OUTSIDE their
          // closed vocabularies and must be DROPPED at both levels; the zero-count inner `replay` must be omitted.
          return new Response(JSON.stringify({
            saml: { signature: { count: 4, lastAt: "2026-06-10T00:00:00.000Z" }, "bogus-code": { count: 3, lastAt: "2026-06-10T00:00:00.000Z" }, replay: { count: 0, lastAt: "2026-06-10T00:00:00.000Z" } },
            oidc: { issuer: { count: 2, lastAt: "2026-06-10T01:00:00.000Z" } },
            "bogus-kind": { issuer: { count: 9, lastAt: "2026-06-10T02:00:00.000Z" } },
          }));
        case "/auth-signals":
          // P2: the bounded auth-signal aggregate. "not-a-real-signal" is OUTSIDE the closed vocabulary and must be
          // DROPPED; the zero-count "csrf-origin-mismatch" must be omitted.
          return new Response(JSON.stringify({
            "emailless-assertion": { count: 3, lastAt: "2026-06-10T00:00:00.000Z" },
            "scim-unauthorised": { count: 7, lastAt: "2026-06-10T01:00:00.000Z" },
            // P3: a sample of the newly-wired closed-vocabulary signals must project through unchanged.
            "cf-access-aud-mismatch": { count: 4, lastAt: "2026-06-10T04:00:00.000Z" },
            "saml-relaystate-missing": { count: 2, lastAt: "2026-06-10T05:00:00.000Z" },
            "session-revoked-idp-epoch": { count: 6, lastAt: "2026-06-10T06:00:00.000Z" },
            "not-a-real-signal": { count: 5, lastAt: "2026-06-10T02:00:00.000Z" },
            "csrf-origin-mismatch": { count: 0, lastAt: "2026-06-10T03:00:00.000Z" },
          }));
        case "/auth-posture":
          // P4/P3: session signing-key presence + age + adequate-length (never the key), the do-plaintext missing
          // count, and the alternative admin-credential-path counts (passkeys + enabled IdP connections).
          return new Response(JSON.stringify({ sessionSigningKey: { present: true, ageMs: 123456, adequateLength: true }, doPlaintextSecretsMissing: 2, adminCredentialPaths: { passkeyCredentials: 1, enabledIdpConnections: 3 } }));
        case "/audit/export": {
          // The server-side action filter (the F2 keystone fetch): return the single newest matching event,
          // or none. The recent-window query below deliberately does NOT include the keystones, so a retained
          // keystone in the bundle PROVES the action-filter path ran (not an in-memory scan of the page).
          const action = url.searchParams.get("action");
          if (action) {
            const e = keystoneByAction[action];
            return new Response(JSON.stringify({ events: e ? [e] : [], headSeq: 25, headHash: "sha384:25", exportedAt: "2026-06-10T01:00:00.000Z" }));
          }
          // Mirror the real DO's afterSeq+limit pushdown (engine-src-022-07): when the feed pull supplies
          // both, return ONLY the matching window (events strictly after the cursor), the OLDEST limit
          // ascending; otherwise the whole ascending set. This is the behaviour the Worker now trusts the
          // DO to perform instead of loading the entire log and filtering in memory.
          const afterSeqParam = url.searchParams.get("afterSeq");
          const limitParam = url.searchParams.get("limit");
          let events = auditEvents;
          if (afterSeqParam !== null) {
            const after = Math.floor(Number(afterSeqParam));
            events = events.filter((e) => e.seq > after);
            if (limitParam !== null) {
              const lim = Math.floor(Number(limitParam));
              if (Number.isFinite(lim) && lim > 0) events = events.slice(0, lim);
            }
          }
          return new Response(JSON.stringify({ events, headSeq: 25, headHash: "sha384:25", exportedAt: "2026-06-10T01:00:00.000Z" }));
        }
        case "/drive-budget-yield":
          // failover-probe-budget-exhaustion: the cumulative cron seal-loop budget-yield record (2 ticks
          // yielded, last carried 7 due downpipes over). The pack surfaces the count + last time + last carried.
          return new Response(JSON.stringify({ count: 2, lastAt: 1_700_000_050_000, lastCarried: 7 }));
        case "/config-snapshot-health":
          // config-snapshot-best-effort-gap: a config change committed but the auto-snapshot capture failed twice.
          return new Response(JSON.stringify({ count: 2, lastAt: "2026-06-10T05:00:00.000Z" }));
        case "/config-history-health":
          // config-history-session-key-regen: the chain does NOT verify AND the in-DO signing key ROTATED, so the
          // pack must surface signingKeyRotated (a key rotation, not content tamper) alongside the verdict.
          return new Response(JSON.stringify({ count: 9, headId: 9, verify: { intact: false, checkedThrough: 9, earliestId: 1, brokenAt: 4, signingKeyRotated: true } }));
        case "/change-control/refusals":
          // change-number-required-refusal: changes refused for want of a change number (the CR ledger is
          // untouched — this is a SEPARATE counter). The pack surfaces the count + last time + last action kind.
          return new Response(JSON.stringify({ count: 3, lastAt: "2026-06-10T06:00:00.000Z", lastActionKind: "dest-remove" }));
        case "/licence-activation-refusal":
          // failed-activation-no-trace: console activations refused by verify-before-store. lastReasonCode is a
          // CLOSED code (expired); the pack forwards only closed-vocab codes.
          return new Response(JSON.stringify({ count: 4, lastAt: 1_700_000_060_000, lastReasonCode: "expired" }));
        case "/expiry":
          // expiry-tracker-stale: the OBSERVED `licence` expiry-registry row's notAfter DIFFERS from the live
          // licence.notAfter (community here, absent), so the tracked row is visibly stale. The pack projects
          // trackedNotAfter + state + source, NEVER the operator label ("my licence").
          //
          // THIS DOUBLE COMPUTES ITS `state`, IT DOES NOT WRITE IT DOWN, and that is the whole point of the
          // line below. It used to return two rows carrying a literal state: "ok" beside fixed instants of
          // and. The route it emulates does not write that field at all:
          // scheduler-do-expiry.ts returns expiryStatuses(items, Date.now()), and stateFor maps
          // daysRemaining <= 0 to "expired" and <= APPROACHING_DAYS to "approaching".
          //
          // So the double was faithful on the day it was written and stopped being so without anything going
          // red. Driving the PRODUCTION function on the double's own two rows at three clocks: on the
          // authoring day it gives ok(31d) and ok(62d), matching what was written down; on
          // it gives expired(-9d) and approaching(22d); both are expired. The
          // assertion downstream pinned state === "ok" and stayed green throughout, because a literal cannot
          // drift, so the check went on passing while proving something weaker than it was written to prove.
          //
          // A CLOCK SHIFT CANNOT FIND THIS. Moving the clock moves the producer, and the fixture was a
          // constant, so nothing flips and a sweep sees a stable green. Nor is the remedy to move the
          // literals forward: that buys a year and rebuilds the same defect with a later fuse.
          //
          // Both halves are needed. Calling the real expiryStatuses makes the double structurally incapable
          // of returning a row the route could not produce, and deriving the instants from this run's own
          // clock keeps the intended states fixed for ever. The offsets are deliberately clear of the
          // APPROACHING_DAYS boundary so a slow run cannot tip a row into "approaching".
          return new Response(JSON.stringify(expiryStatuses(EXPIRY_DOUBLE_ITEMS, Date.now())));
        case "/status-baseline":
          // engine-version-change-baseline-suppressed / same-version-redeploy: the deploy-identity marker recorded
          // at the last status-snapshot baseline. The pack surfaces version + cfVersionId + at under engine.deployBaseline.
          return new Response(JSON.stringify({ version: "2026.07.01", cfVersionId: "cfv-baseline-abc", at: 1_700_000_070_000 }));
        case "/ingest-credential": {
          const scope = url.searchParams.get("scope")!;
          return new Response(JSON.stringify({ grant: grants[scope] ?? null }));
        }
        case "/audit/verify":
          // CPR: the audit-chain verify VERDICT the pack surfaces as `audit` -- intact + rollover state +
          // the near-cap warning + the verify's own cost.
          return new Response(JSON.stringify({ intact: true, checkedThrough: 25, earliestSeq: 3, rolledOver: true, rolledOverCount: 2, auditCount: 25, auditNearCap: false, verify: { at: "2026-06-30T00:00:00.000Z", entriesChecked: 25, durationMs: 4, complete: true } }));
        case "/notify/health":
          // NOTIF: the notify-pipeline drop counters the pack surfaces as `notifyHealth`.
          return new Response(JSON.stringify({ passSkips: 1, recordSkips: 2, parseRejects: 3, feedbackFails: 0, lastAt: "2026-06-30T00:00:00.000Z" }));
        case "/control-plane/export":
          // CPR: the no-custody export slice the wrap-key health probe reads. One dest carries a real
          // WrappedSecret envelope (decryptable by the env CONFIG_WRAP_KEY), so the probe reports class "ok".
          return new Response(JSON.stringify({ destinations: [{ id: "d1", secret: WRAPPED_DEST_SECRET !== null ? { wrapped: WRAPPED_DEST_SECRET } : { reestablish: true } }] }));
        // ---- the round-3 diagnostic sections -------------------------------------------------------------
        // The two ledgers Wave-D recorded and never delivered (drainSourceFaultLedger had NO caller), plus the
        // restore fault ring and the admin silent-fallback counters. Each carries a HOSTILE member the closed
        // gate must drop, and a customer value the redaction sweep must never find.
        case "/source-faults":
          return new Response(JSON.stringify({
            dp1: {
              at: 1_700_000_000_000,
              incompleteReasons: { _unavailable: { auth: 4, "not-a-reason": 9 } },
              incompleteIds: { _unavailable: ["workers/settings", "s3://acme-secret-bucket-name/payroll.xlsx"] },
              shapeAnomalies: 2,
              fatal: { sourceType: "images", statusClass: "403", stage: "list" },
              snapshotConsistency: "re-anchored",
              throttle429Count: 17,
              securityRefusals: { "redirect-refused": 1 },
            },
          }));
        case "/dest-faults":
          return new Response(JSON.stringify({
            dp1: {
              at: 1_700_000_000_000,
              total: 3,
              faults: [
                { op: "put", httpStatus: 403, s3Code: "ExpiredToken", fault: "auth", arm: "matched-status", requestIdPresent: true, wormChecksumComplaint: false, count: 3 },
                { op: "put", httpStatus: 500, s3Code: "acme-secret-bucket-name", fault: "transient", arm: "matched-status", count: 1 },
              ],
              io: { throttleObservations: 41, headNon200CollapsedToAbsent: 7 },
            },
          }));
        case "/restore-faults":
          return new Response(JSON.stringify({ faults: [
            { at: 1_700_000_000_000, op: "apply", phase: "readback", cls: "readback-mismatch", recordName: "uploads/invoice-003.pdf", count: 2, errId: "deadbeef" },
            { at: 1_700_000_001_000, op: "apply", phase: "write", cls: "not-a-class", count: 1, errId: "acme-secret-bucket-name" },
          ] }));
        case "/admin-counters":
          return new Response(JSON.stringify({
            "licence-source-flip": { count: 2, lastAt: "2026-07-01T00:00:00.000Z" },
            "restore-apply-lease-reclaimed": { count: 1, lastAt: "2026-07-02T00:00:00.000Z" },
            "dest-config-worm-policy-dropped": { count: 1, lastAt: "2026-07-03T00:00:00.000Z" },
            "acme-secret-bucket-name": { count: 99, lastAt: "2026-07-04T00:00:00.000Z" },
          }));
        case "/ingest-credential/record-pull":
          pulls.push({ scope: String(body?.["scope"]) });
          return new Response(JSON.stringify({ ok: true }));
        default:
          return new Response(JSON.stringify({}));
      }
    },
  } as unknown as DurableObjectStub;
  return { stub, grants, pulls, calls, auditStatusPosts };
}

async function main(): Promise<void> {
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);

  console.log("ingest credential mechanics:");
  {
    const minted = await mintIngestCredential("diagnostics", "owner@example.com.au", undefined);
    ok("the secret is never stored (grant carries only its SHA-384)", !JSON.stringify(minted.grant).includes(minted.secret));
    ok("the right bearer verifies", await checkIngestCredential(`${minted.clientId}.${minted.secret}`, minted.grant));
    ok("a wrong secret is refused", !(await checkIngestCredential(`${minted.clientId}.dps_${b64urlEncode(rand(24))}`, minted.grant)));
    ok("a wrong clientId is refused", !(await checkIngestCredential(`dpc_other.${minted.secret}`, minted.grant)));
    ok("a malformed bearer is refused", !(await checkIngestCredential("no-dot-here", minted.grant)));
    ok("an absent grant is refused", !(await checkIngestCredential(`${minted.clientId}.${minted.secret}`, null)));
    const expired: IngestGrant = { ...minted.grant, expiresAt: "2020-01-01T00:00:00.000Z" };
    ok("an expired grant is refused server-side", !(await checkIngestCredential(`${minted.clientId}.${minted.secret}`, expired)));
    const redacted = JSON.stringify(redactGrant(minted.grant));
    ok("the redacted grant view drops the secret hash", !redacted.includes(minted.grant.secretSha384));
    const diagTtl = Date.parse(minted.grant.expiresAt) - Date.now();
    ok("diagnostics default TTL is 72 hours (7-day cap)", diagTtl > 71 * 3600_000 && diagTtl <= 7 * 24 * 3600_000);
    const feed = await mintIngestCredential("audit-feed", null, 400 * 24 * 3600);
    const feedTtl = Date.parse(feed.grant.expiresAt) - Date.now();
    ok("audit-feed TTL caps at 365 days", feedTtl <= 365 * 24 * 3600_000 + 60_000);
  }

  console.log("\nthe per-tick outcome ring (pure appendTickOutcome):");
  {
    const base: TickReport = { due: 3, dispatched: 3, coalesced: 0, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 100 };
    let ring: TickOutcome[] = [];
    ring = appendTickOutcome(ring, base, 1_000);
    ok("the first tick has intervalMs 0 and derives budgetRemaining + overBudget", ring[0]!.intervalMs === 0 && ring[0]!.budgetRemaining === 600 && ring[0]!.overBudget === false && ring[0]!.at === 1_000);
    // A later tick with an overdrawn budget: the interval is derived from the prior entry, overBudget fires, remaining floors at 0.
    ring = appendTickOutcome(ring, { ...base, budgetSpent: 720 }, 901_000);
    ok("a later tick derives the interval since the prior tick + the overBudget overdraw flag", ring[1]!.intervalMs === 900_000 && ring[1]!.overBudget === true && ring[1]!.budgetRemaining === 0);
    // A malformed report (negative / NaN counts) is CLAMPED to safe non-negative ints, never propagated.
    ring = appendTickOutcome(ring, { due: -5, dispatched: Number.NaN, coalesced: 2.9, carried: 0, sealErrors: 0, passErrors: 0, budgetCap: 700, budgetSpent: 50 } as unknown as TickReport, 902_000);
    ok("a malformed report is clamped (negative -> 0, NaN -> 0, fractional floored)", ring[2]!.due === 0 && ring[2]!.dispatched === 0 && ring[2]!.coalesced === 2);
    // The ring is bounded: appending past the cap keeps only the most-recent TICK_RING_CAP entries (newest-last).
    let big: TickOutcome[] = [];
    for (let i = 0; i < TICK_RING_CAP + 20; i++) big = appendTickOutcome(big, base, 1_000 + i);
    ok("the ring is bounded to TICK_RING_CAP newest-last", big.length === TICK_RING_CAP && big[big.length - 1]!.at === 1_000 + TICK_RING_CAP + 19);
  }

  // Wrap-key health fixture: a 32-byte key + a dest secret wrapped under it, so the pack's wrap-key probe
  // proves the "ok" class (the env key decrypts the encrypted-at-rest credential).
  const wrapKey = rand(32);
  WRAP_KEY_B64 = b64urlEncode(wrapKey);
  WRAPPED_DEST_SECRET = await wrapConfigSecret(wrapKey, "a-destination-secret-access-key");

  console.log("\nthe sections completeness + summary (pure summariseSections):");
  {
    // INFRA no-runtime-logs-in-pack: a COMPLETE map (every roster subsystem present) is summarised without any
    // fill, and the ok/empty/error counts reconcile with the expected roster size.
    const complete: Record<string, "ok" | "empty" | "error"> = Object.fromEntries(SUPPORT_SECTION_NAMES.map((n, i) => [n, i === 0 ? "empty" : i === 1 ? "error" : "ok"]));
    const s1 = summariseSections(complete);
    ok("summariseSections: a complete map reconciles (expected = ok + empty + error, no fill)", s1.expected === SUPPORT_SECTION_NAMES.length && s1.ok + s1.empty + s1.error === s1.expected && s1.empty === 1 && s1.error === 1 && Object.keys(complete).length === SUPPORT_SECTION_NAMES.length);
    // A map MISSING a roster subsystem is COMPLETED: the missing member is stamped "error" (couldn't-gather) so
    // the vector can never silently omit a subsystem, and the summary counts the stamped error.
    const partial: Record<string, "ok" | "empty" | "error"> = { downpipes: "ok" };
    const s2 = summariseSections(partial);
    ok("summariseSections: a missing roster subsystem is stamped 'error' (the vector is completed, never silently short)", partial["scheduler"] === "error" && partial["updates"] === "error" && Object.keys(partial).length === SUPPORT_SECTION_NAMES.length && s2.error === SUPPORT_SECTION_NAMES.length - 1 && s2.ok === 1);
  }

  console.log("\nthe persist-state storage-fault counter (pure classify/apply):");
  {
    // classifyStorageFault (SCHED persist-state-storage-fault / INFRA do-value-size-limit): a DO 128 KiB value-
    // too-large put is classified as "value-too-large"; any other storage failure (and a non-Error/absent value)
    // is the generic "put-failed". The classifier NEVER changes behaviour (the original error is always re-thrown);
    // it only labels the counter's class, so a best-effort message heuristic is acceptable for the diagnostic.
    ok("classifyStorageFault: a 'value too large' put maps to value-too-large", classifyStorageFault(new Error("put() failed: value too large")) === "value-too-large");
    ok("classifyStorageFault: a 413 / size-limit message maps to value-too-large", classifyStorageFault(new Error("413 payload exceeds size limit")) === "value-too-large");
    ok("classifyStorageFault: a generic storage error maps to put-failed", classifyStorageFault(new Error("storage subsystem unavailable")) === "put-failed");
    ok("classifyStorageFault: a non-Error thrown value maps to put-failed", classifyStorageFault("boom") === "put-failed" && classifyStorageFault(null) === "put-failed");

    // applyStorageFault (PURE): each fault bumps the total + its class sub-count and stamps the last class/time.
    const one = applyStorageFault(EMPTY_STORAGE_FAULTS, "value-too-large", 1_000);
    ok("applyStorageFault: a value-too-large fault bumps total + valueTooLarge + stamps class/time", one.total === 1 && one.valueTooLarge === 1 && one.putFailed === 0 && one.lastKind === "value-too-large" && one.lastAt === 1_000);
    const two = applyStorageFault(one, "put-failed", 2_000);
    ok("applyStorageFault: a second, distinct fault accumulates (total 2, one per class, newest class/time)", two.total === 2 && two.valueTooLarge === 1 && two.putFailed === 1 && two.lastKind === "put-failed" && two.lastAt === 2_000);
    // An undefined prior uses the zero counter; a malformed prior (negative/NaN) and a non-finite `now` are CLAMPED.
    const fromNothing = applyStorageFault(undefined, "put-failed", 5_000);
    ok("applyStorageFault: an undefined prior starts from the zero counter", fromNothing.total === 1 && fromNothing.putFailed === 1);
    // lastDownpipeId: null is the "no fault attributed yet" prior. Left null deliberately: this case is about
    // CLAMPING the numeric fields, and an unattributed prior is what a counter written before the attribution
    // field existed looks like.
    const clamped = applyStorageFault({ total: -9, valueTooLarge: Number.NaN, putFailed: -1, lastAt: 0, lastKind: null, lastDownpipeId: null }, "value-too-large", Number.POSITIVE_INFINITY);
    ok("applyStorageFault: a malformed prior + non-finite now are clamped to safe non-negative ints", clamped.total === 1 && clamped.valueTooLarge === 1 && clamped.putFailed === 0 && clamped.lastAt === 0);
  }

  console.log("\nthe support bundle:");
  {
    const sched = schedulerDouble();
    const env = { SIGNER_PRIVATE: signerB64, CONFIG_WRAP_KEY: WRAP_KEY_B64, SCHEDULER: {} as DurableObjectNamespace, RUNSEAL: undefined, CF_ACCOUNT_ID: "acct-eng-xyz", CF_VERSION_METADATA: { id: "cfv-running-xyz", tag: "v9" }, BEACON_URL: "https://beacon.example", BEACON_INGEST_KEY: "bkn_secret_value", DEST_RATE_PER_SEC: "not-a-number" } as unknown as Env;
    const signed = await signedSupportBundle(env, sched.stub);
    const text = JSON.stringify(signed.bundle);
    ok("the bundle carries status, preflight, runs and notify outcomes", text.includes("downpipe-support-bundle") && text.includes("preflight") && text.includes("01RUN") && text.includes("webhook"));
    // Capture-timing race fix: the bundle build SELF-OBSERVES the deploy identity -- the same
    // StatusObservation POST the status route makes -- and does so BEFORE the excerpt read, so a bundle
    // captured after a redeploy but before any GET /admin/status still records the owner-#1 keystone.
    {
      const obsIdx = sched.calls.findIndex((c) => c === "POST /audit-status");
      const excerptIdx = sched.calls.findIndex((c) => c.startsWith("GET /audit/export"));
      ok("bundle build posts the deploy-identity observation BEFORE reading the configEvents excerpt", obsIdx >= 0 && excerptIdx >= 0 && obsIdx < excerptIdx);
      const obs = sched.auditStatusPosts[0] ?? {};
      ok("the self-observation carries the running deploy identity (cfVersionId + engineVersion + presence flags)", obs["cfVersionId"] === "cfv-running-xyz" && typeof obs["engineVersion"] === "string" && typeof obs["signerConfigured"] === "boolean" && typeof obs["destConfigured"] === "boolean");
    }
    ok("the bundle is redaction-safe (no signer material, no credential strings)", !text.includes(signerB64) && !text.includes("dps_") && !text.includes("secretSha384"));

    // ---- the ROUND-3 sections: the evidence that was recorded and never delivered ------------------------
    // The whole point of this wave: a gap is NOT closed until its evidence is in the BUNDLE. The source and
    // destination fault ledgers were written at the fault site and then dropped on the floor
    // (drainSourceFaultLedger() had no caller anywhere in src/), so none of it reached a remote diagnosis.
    // validate-run-fault-evidence.ts proves the whole chain from the adapter; here we pin the BUNDLE contract.
    {
      const b = signed.bundle;
      const sf = (b as { sourceFaults?: Record<string, Record<string, unknown>> }).sourceFaults ?? {};
      const dp1 = sf["dp1"] ?? {};
      ok("sourceFaults rides in the bundle, keyed by the customer's own downpipe id", sf["dp1"] !== undefined);
      ok("sourceFaults: the closed REASON behind an incompleteness sentinel rides (auth -- a scope gap, not a mystery)", (dp1["incompleteReasons"] as Record<string, Record<string, number>>)?.["_unavailable"]?.["auth"] === 4);
      ok("sourceFaults: an OUT-OF-VOCABULARY reason is dropped at the pack boundary", (dp1["incompleteReasons"] as Record<string, Record<string, number>>)?.["_unavailable"]?.["not-a-reason"] === undefined);
      ok("sourceFaults: the run-fatal transport class + crawl STAGE ride (a token that cannot even LIST)", (dp1["fatal"] as Record<string, unknown>)?.["statusClass"] === "403" && (dp1["fatal"] as Record<string, unknown>)?.["stage"] === "list");
      ok("sourceFaults: the MIXED-SNAPSHOT data-integrity verdict rides on a run that reported ok", dp1["snapshotConsistency"] === "re-anchored");
      ok("sourceFaults: a bucket/object path smuggled into an attribution id fails the shape gate", JSON.stringify(dp1["incompleteIds"] ?? {}) === JSON.stringify({ _unavailable: ["workers/settings"] }));

      const df = (b as { destFaults?: Record<string, Record<string, unknown>> }).destFaults ?? {};
      const drows = (df["dp1"]?.["faults"] ?? []) as Array<Record<string, unknown>>;
      ok("destFaults rides in the bundle", df["dp1"] !== undefined);
      ok("destFaults: the closed S3 <Code> rides (ExpiredToken = a lapsed STS session, not a bucket policy)", drows.some((r) => r["s3Code"] === "ExpiredToken"));
      ok("destFaults: an S3 code OUTSIDE the documented allow-list drops its whole row", drows.length === 1);
      ok("destFaults: the degradation counters ride (a GREEN run that is slow and expensive)", (df["dp1"]?.["io"] as Record<string, number>)?.["headNon200CollapsedToAbsent"] === 7);

      const rf = ((b as { restoreFaults?: unknown[] }).restoreFaults ?? []) as Array<Record<string, unknown>>;
      ok("restoreFaults rides in the bundle", rf.length === 1);
      ok("restoreFaults: the PHASE rides -- readback means the bytes ARE on the target and could not be PROVEN", rf[0]?.["phase"] === "readback" && rf[0]?.["cls"] === "readback-mismatch");
      ok("restoreFaults: the 8-hex Workers-Logs join key rides, and a non-hex one is dropped", rf[0]?.["errId"] === "deadbeef");
      ok("restoreFaults: an out-of-vocabulary class drops the whole row", !JSON.stringify(rf).includes("not-a-class"));

      const ac = ((b as { adminCounters?: Record<string, { count: number }> }).adminCounters ?? {});
      ok("adminCounters rides in the bundle", ac["licence-source-flip"]?.count === 2);
      ok("adminCounters: the dual-control accounting hole rides (an apply that crashed holding a single-use approval)", ac["restore-apply-lease-reclaimed"]?.count === 1);
      ok("adminCounters: an operator's WORM destination policy silently discarded rides", ac["dest-config-worm-policy-dropped"]?.count === 1);
      ok("adminCounters: an out-of-vocabulary counter name is dropped", ac["acme-secret-bucket-name"] === undefined);

      // The pre-existing REDACTION HOLE: destResolution.destinations[].storageClass was projected ungated.
      const dr = (b as { destResolution?: { destinations?: Array<Record<string, unknown>> } }).destResolution ?? {};
      const dpath = (dr.destinations ?? []).find((d) => d["id"] === "d-ungated") ?? {};
      ok("storageClass: a real S3 allow-list member still rides", (dr.destinations ?? []).find((d) => d["id"] === "d-r2")?.["storageClass"] === "STANDARD_IA");
      ok("storageClass REDACTION HOLE CLOSED: an operator-controlled value is gated, never carried verbatim", dpath["storageClass"] === "unknown-code");

      // The sweep that actually matters: a customer value planted in EVERY one of the new sections above must
      // reach no byte of the signed bundle.
      ok("REDACTION: the customer value planted in every new section reaches no byte of the bundle", !text.includes("acme-secret-bucket-name") && !text.includes("payroll.xlsx"));
    }

    // Item 1 (buildStatus WITH DO opts) + Item 2 (statusSource / destResolved): buildStatus is now called
    // with the DO round-trip opts, so the pack's status carries the break-glass-disposal latches, the
    // expiry/cleanup counts, the restorability count, and the LIVE console-set destination — none of which
    // the former opt-less call surfaced. statusSource "live" proves the DO /dest-status read resolved; a DO
    // blip would read "env-fallback" (gap-B6, the status-preflight-conflict tell). destResolved names the
    // resolved archive kind (here the console-set R2 reached via its S3-compatible endpoint).
    const st = signed.bundle["status"] as Record<string, unknown>;
    ok("status carries the DO break-glass-disposal latches (bootstrapConsumed / breakGlassTokenRetired)", st["bootstrapConsumed"] === true && st["breakGlassTokenRetired"] === false);
    ok("status carries the DO expiry + cleanup counts", st["expiryWarnings"] === 2 && st["cleanupPending"] === 1);
    ok("status carries the restorabilityProven count (0 is meaningful: none proven in this roster)", st["restorabilityProven"] === 0);
    ok("status reports statusSource 'live' when the DO dest read resolved (gap-B6)", st["statusSource"] === "live");
    ok("status resolves the console-set R2 destination kind (destResolved)", st["destResolved"] === "r2" && st["destKind"] === "r2");
    ok("the console-set destination endpoint host NEVER reaches the bundle (no-custody)", !text.includes("r2.cloudflarestorage.com") && !text.includes("acct123"));
    // recoveryCodesRemaining is per verified caller EMAIL; a self-service bundle has no caller, so it is
    // honestly ABSENT (the /admin/status route, which HAS a caller, is where the count lives).
    ok("status omits the caller-scoped recoveryCodesRemaining (a self-service bundle has no caller)", !("recoveryCodesRemaining" in st));

    // Item 3 (WORM / Object-Lock posture) FAIL-SOFT side: the pack now carries the default destination's live
    // posture. With no WORM policy AND no destination configured, the policy verdict reads configured:false and
    // the live probe is fail-soft — buildDestination throws on an absent destination, the catch leaves
    // bucketEnforces honestly ABSENT (never a false enforcement claim), and the bundle build never fails.
    const wp = signed.bundle["wormPosture"] as Record<string, unknown> | undefined;
    ok("wormPosture is plumbed into the pack (configured:false + misconfigured:false when no WORM policy is set)", wp !== undefined && wp["configured"] === false && wp["misconfigured"] === false);
    ok("wormPosture is fail-soft on an absent destination: bucketEnforces is honestly absent (no false claim)", wp !== undefined && !("bucketEnforces" in wp));

    // v:2 run row carries the PER-MARKER incompleteness breakdown: the diagnostics-bot consumes WHICH markers a
    // run sealed, not just the aggregate recordsIncomplete. /history serialises the row verbatim and
    // fetchRunHistory projects it with a conditional spread, so the per-kind map rides into the pack unchanged.
    const run0 = ((signed.bundle["runs"] as Record<string, Array<Record<string, unknown>>>)["dp1"] ?? [])[0]!;
    const ibm0 = run0["incompleteByMarker"] as Record<string, number> | undefined;
    ok("the pack run row carries incompleteByMarker with the per-kind counts (_truncated:2, _skipped:1)", ibm0 !== undefined && ibm0["_truncated"] === 2 && ibm0["_skipped"] === 1);
    ok("incompleteByMarker on the pack row omits the zero-count kinds (only non-zero keys)", ibm0 !== undefined && !("_unavailable" in ibm0) && !("_pending" in ibm0) && !("_refused" in ibm0));
    ok("the aggregate recordsIncomplete rides alongside the breakdown", run0["recordsIncomplete"] === 3);
    // WS-P2: the run row surfaces recordsVanished (in-scope objects deleted mid-crawl between list and read) as
    // a redaction-safe count, distinct from recordsIncomplete (a sealed marker) -- the churn signal for the pack.
    ok("the pack run row carries recordsVanished (mid-crawl deletions), distinct from recordsIncomplete", run0["recordsVanished"] === 2 && run0["recordsIncomplete"] === 3);
    // WS-P1 per-kind ATTRIBUTION: the pack run row names WHICH surface each incompleteness kind hit (cf-config
    // surface ids, the closed/product tokens). The realistic kinds ride verbatim; the over-cap _unavailable kind
    // proves the pack boundary re-clamps count + id length and drops the non-string entry (no-custody bound).
    const iids0 = run0["incompleteIds"] as Record<string, string[]> | undefined;
    ok("the pack run row carries incompleteIds attributing the shorted surfaces (cf-config surface ids)",
      iids0 !== undefined && JSON.stringify(iids0["_truncated"]) === JSON.stringify(["dns_records", "rulesets"]) && JSON.stringify(iids0["_skipped"]) === JSON.stringify(["page_rules"]));
    ok("incompleteIds is re-clamped at the pack boundary: per-kind count capped and over-long id truncated, non-string dropped",
      iids0 !== undefined && Array.isArray(iids0["_unavailable"]) && iids0["_unavailable"]!.length === MARKER_ATTRIBUTION_MAX_PER_KIND
      && iids0["_unavailable"]!.every((s) => typeof s === "string" && s.length <= MARKER_ATTRIBUTION_ID_MAX_LEN)
      && iids0["_unavailable"]![0]!.length === MARKER_ATTRIBUTION_ID_MAX_LEN);
    ok("incompleteIds carries only closed/product-token surface ids (no operator/customer free-text key leaked)",
      iids0 !== undefined && Object.values(iids0).flat().every((s) => typeof s === "string" && /^[A-Za-z0-9_]+$/.test(s)));
    // The licence in the bundle is the LicenceStatus (tier/valid/notAfter/features/source),
    // which deliberately OMITS the signed-over `account` claim. The bundle must never carry
    // the licence account id, so no `account` key may appear ANYWHERE in the serialised
    // bundle. A whole-bundle scan (not just the licence sub-object) guards against a future
    // field reintroducing it elsewhere. The check looks for the JSON key form so a record
    // value that happened to contain the word would not trip it.
    ok("the bundle carries no licence account id anywhere", !/"account"\s*:/.test(text) && !text.includes('"account"'));

    // v:2 licence diagnostics ride into the pack via the licence block (readLicence): the CLOSED reasonCode
    // sub-classification + the DO/env fallback flags let the bot tell a tamper from a stale client from a
    // future tier. Here no token is configured and the /licence-token DO route is absent (the double's
    // default {}), so the effective licence is the community no-token default: reasonCode 'no-token',
    // envTokenPresent false (no deploy-time env LICENCE_TOKEN either). Proves the fields survive the bundle.
    const lic = signed.bundle["licence"] as { tier: string; valid: boolean; reasonCode?: string; envTokenPresent?: boolean };
    ok("the pack licence carries the closed reasonCode sub-classification (no-token)", lic.tier === "community" && lic.valid === false && lic.reasonCode === "no-token");
    ok("the pack licence carries envTokenPresent (false: no env token masking)", lic.envTokenPresent === false);

    // engine.accountTag (accounttag-mismatch): the engine's OWN Cloudflare account id (CF_ACCOUNT_ID) rides
    // in the pack so support can confirm which account this engine reports under, and disambiguate two
    // engines flapping one licence-ledger row. Not a secret (the operator's own id, already the beacon key +
    // already surfaced per-source as accountId). Never the string "account" as a bare key (no-custody scan).
    const eng = signed.bundle["engine"] as { version: string; accountTag?: string };
    ok("engine.accountTag surfaces the engine's own CF_ACCOUNT_ID for account-mismatch diagnosis", eng.accountTag === "acct-eng-xyz");

    // v:2 beacon (beacon-off-no-corroboration + beacon-post-lost): the pack shows whether the opt-in vendor
    // beacon is CONFIGURED (env presence of BEACON_URL + BEACON_INGEST_KEY + CF_ACCOUNT_ID) AND the last POST
    // outcome (lastOk/lastAt/lastStatus), so a beacon that is off (no corroboration) or configured-but-not-
    // reaching-the-vendor is visible. The BEACON_INGEST_KEY VALUE is never surfaced (only `configured`).
    const beacon = signed.bundle["beacon"] as { configured: boolean; lastOk?: boolean; lastAt?: number; lastStatus?: number };
    ok("beacon.configured reflects env presence and the last POST outcome rides into the pack", beacon.configured === true && beacon.lastOk === true && beacon.lastStatus === 200 && beacon.lastAt === 1_700_000_000_000);
    ok("the beacon ingest key value never reaches the pack (presence only)", !text.includes("bkn_secret_value"));

    // v:2 destResolution (DEST write-path): the EFFECTIVE resolved write settings the engine never records.
    // A set-but-invalid DEST_RATE_PER_SEC ("not-a-number") silently falls back to the default AND is flagged
    // (dest-rate-knob-typo); per destination the resolved addressing style rides (wrong-addressing-style), a
    // dotted bucket forced vhost is flagged a TLS risk (dotted-bucket-vhost-tls), and the effective storage
    // class rides (storageclass-silently-dropped). The endpoint host + bucket NAME are never surfaced.
    const dr = signed.bundle["destResolution"] as { effectiveRatePerSec: number; rateKnobInvalid: boolean; destinations: Array<{ id: string; addressing: string; storageClass?: string; dottedBucketVhostRisk?: boolean }> };
    ok("destResolution surfaces the effective rate + flags a rate-knob typo (fell back to the default 50)", dr.effectiveRatePerSec === 50 && dr.rateKnobInvalid === true);
    const dR2 = dr.destinations.find((d) => d.id === "d-r2");
    ok("destResolution resolves a forced-vhost DOTTED bucket as a TLS risk + carries the effective storage class", dR2?.addressing === "vhost" && dR2?.dottedBucketVhostRisk === true && dR2?.storageClass === "STANDARD_IA");
    const dS3 = dr.destinations.find((d) => d.id === "d-s3");
    ok("destResolution resolves auto addressing on a DNS-safe amazonaws bucket to vhost (no dotted risk)", dS3?.addressing === "vhost" && dS3?.dottedBucketVhostRisk === undefined);
    const dPath = dr.destinations.find((d) => d.id === "d-path");
    ok("destResolution resolves an explicit path-style dest to path (and omits an absent storage class)", dPath?.addressing === "path" && dPath?.dottedBucketVhostRisk === undefined && dPath?.storageClass === undefined);
    ok("destResolution never surfaces the endpoint host or bucket name (only derived signals)", !text.includes("my.dotted.bucket") && !text.includes("cloudflarestorage") && !text.includes("plainbucket"));

    // v:2 configEvents KEYSTONE smart-retain (F2): the recent window here is role-change churn (+ the seq 23-25
    // idp-connection-change events below); the deploy/detach markers come ONLY from the server-side action filter,
    // so finding them proves the latest keystone is retained even when it has scrolled past the (server-capped)
    // recent page -- the owner-#1 "did a deploy drop my bindings?" question stays answerable on a busy account.
    const cfgEvents = signed.bundle["configEvents"] as Array<Record<string, unknown>>;
    const evc = cfgEvents.find((e) => e["action"] === "engine-version-change");
    ok("configEvents retains the engine-version-change keystone (with toVersion) despite recent-window churn", evc !== undefined && evc["toVersion"] === "2026.07.01-abc");
    ok("configEvents retains the sources-detached keystone despite recent-window churn", cfgEvents.some((e) => e["action"] === "sources-detached"));

    // v:2 idp-connection-change STRUCTURED projection: the excerpt carries the closed-vocab connKind/op/outcome so
    // the diagnosis can tell WHICH IdP connection changed and HOW (a delete/disable/update can break existing SSO
    // sign-in) -- but NEVER the connId operator slug, and an op/connKind outside its closed set is DROPPED.
    const idpEvents = cfgEvents.filter((e) => e["action"] === "idp-connection-change");
    const idpDelete = idpEvents.find((e) => e["op"] === "delete");
    ok("configEvents projects a disruptive idp-connection-change with connKind + op + outcome", idpDelete !== undefined && idpDelete["connKind"] === "saml" && idpDelete["outcome"] === "success");
    const idpDenied = idpEvents.find((e) => e["outcome"] === "denied");
    ok("configEvents projects a denied idp management attempt (outcome=denied + op + connKind)", idpDenied !== undefined && idpDenied["op"] === "test" && idpDenied["connKind"] === "oidc");
    const idpHostile = idpEvents.find((e) => e["hash"] === "sha384:25");
    ok("configEvents DROPS an idp connKind/op outside the closed vocabularies (outcome still projected)", idpHostile !== undefined && idpHostile["connKind"] === undefined && idpHostile["op"] === undefined && idpHostile["outcome"] === "success");
    ok("configEvents NEVER carries an idp connId operator slug", !text.includes("-slug") && !JSON.stringify(cfgEvents).includes("connId"));

    // WS-P4 restore-APPLY summary projection: a restore-verified event carries HOW the apply landed. The excerpt
    // projects the windowed-restore complete flag, the verified/restored/failure/out-of-window counts, the
    // readback-hash proof counts, and the per-DB(D1) apply outcome -- all redaction-safe counts + booleans.
    const rv = cfgEvents.find((e) => e["action"] === "restore-verified");
    ok("configEvents projects the restore-verified windowed-complete flag + outcome (a partial/windowed apply is visible)",
      rv !== undefined && rv["complete"] === false && rv["outcome"] === "failed" && rv["allVerified"] === false);
    ok("configEvents projects the restore-apply counts (restored/verified/failures/outOfWindow)",
      rv !== undefined && rv["recordsRestored"] === 8 && rv["recordsVerified"] === 10 && rv["failures"] === 2 && rv["outOfWindow"] === 3);
    // recordsSkipped is the count that EXPLAINS a shortfall the other numbers only expose. A restore can
    // read recordsRestored 98 of recordsVerified 100 with failures 0 and outOfWindow 0, and the gap is
    // entirely records the target deliberately did not write. Without this in the pack, support sees the
    // gap and nothing that accounts for it, which is the ticket this projection exists to answer.
    ok("configEvents projects recordsSkipped, so a shortfall in the pack is explainable", rv !== undefined && rv["recordsSkipped"] === 4);
    ok("configEvents projects the readback-hash proof counts + the per-DB(D1) apply outcome",
      rv !== undefined && rv["readbackVerified"] === 8 && rv["readbackMismatched"] === 2 && rv["d1Total"] === 4);
    ok("configEvents DROPS a malformed (negative) restore count -- redaction/shape guard holds", rv !== undefined && rv["d1Verified"] === undefined);
    ok("the restore summary carries only counts/booleans -- no record name, value, key or content hash",
      rv !== undefined && !JSON.stringify(rv).includes("receiptSha384") && !JSON.stringify(rv).includes("01RESTORE"));

    // v:2 dest-change STRUCTURED projection (WS-D config-change): the excerpt carries the CLOSED signals so the
    // config-change modes the bare dest-config action name could not convey become visible — a FORCED removal
    // that orphaned runs (dest-removed-force-orphans-runs), a silent default PROMOTION (dest-default-promotion-
    // silent-redirect, as a defaultChanged BOOLEAN, not the operator ids), and a REJECTED set with its closed
    // reason + failed outcome (dest-set-validation-reject) — but NEVER the operator dest ids/slugs.
    const removalEvt = cfgEvents.find((e) => e["action"] === "dest-config-cleared" && e["op"] === "remove");
    ok("configEvents projects a FORCED dest removal with the orphan count + default-promotion boolean", removalEvt !== undefined && removalEvt["force"] === true && removalEvt["uncoveredOriginRunCount"] === 3 && removalEvt["defaultChanged"] === true);
    const destReject = cfgEvents.find((e) => e["action"] === "dest-config-set" && e["rejectReason"] !== undefined);
    ok("configEvents projects a REJECTED dest set with its closed reason class + failed outcome", destReject !== undefined && destReject["op"] === "set" && destReject["rejectReason"] === "endpoint-not-https" && destReject["outcome"] === "failed");
    ok("configEvents dest-change NEVER carries the operator dest ids (excerpt keeps operator labels out)", !JSON.stringify(cfgEvents).includes("old-dest-slug") && !JSON.stringify(cfgEvents).includes("promoted-dest-slug") && !JSON.stringify(cfgEvents).includes("bad-dest-slug"));

    // Item 5 (notify-config change legibility): a config-change event's CLOSED-ENUM changeKind is now projected
    // so a NOTIFY-CONFIG mutation is legible in the excerpt ("someone changed a rule and broke alerting"). The
    // config-change-* actions were ALREADY allowlisted; the gap was the DROPPED changeKind.
    // approverEmail / the configchange id / the change params are
    // NEVER projected (the excerpt carries only the closed enum), and a changeKind outside the closed vocabulary
    // is dropped (defence in depth, mirroring the idp connKind/op guard).
    const ccApprove = cfgEvents.find((e) => e["action"] === "config-change-approve");
    ok("configEvents projects a config-change's notify changeKind (a notify-config mutation is legible)", ccApprove !== undefined && ccApprove["changeKind"] === "notify-channel-delete");
    ok("configEvents DROPS a changeKind outside the closed vocabulary (defence in depth)", cfgEvents.some((e) => e["action"] === "config-change-propose") && cfgEvents.find((e) => e["action"] === "config-change-propose")!["changeKind"] === undefined);
    ok("configEvents NEVER leaks a config-change approverEmail, the configchange id, or the change params (redaction)", !text.includes("checker@example.com") && !text.includes("cc-approve-secret-id") && !text.includes("cc-hostile-id") && !JSON.stringify(cfgEvents).includes("approverEmail"));

    // v:2 ssoFailures (D2): the bounded per-code SSO sign-in FAILURE aggregate. Projects ONLY closed-vocabulary
    // classifier codes (drops an out-of-vocab code) with a count + last-seen time; omits a zero-count code; NEVER
    // carries a raw failure reason (the projection is codes + ints + timestamps only, redaction-safe by construction).
    const sso = signed.bundle["ssoFailures"] as Record<string, { count: number; lastAt: string }> | undefined;
    ok("ssoFailures projects a closed-vocab code with its count + lastAt", sso?.["issuer"]?.count === 5 && sso["issuer"].lastAt === "2026-06-10T00:00:00.000Z");
    ok("ssoFailures carries multiple distinct codes (clock-skew)", sso?.["clock-skew"]?.count === 2);
    ok("ssoFailures DROPS a code outside the closed vocabulary", sso !== undefined && !("bogus-injected" in sso) && !text.includes("bogus-injected"));
    ok("ssoFailures OMITS a zero-count code", sso !== undefined && !("connection" in sso));

    // P1 ssoFailuresByKind: the per-connection-KIND split. Projects a member connKind -> member SSO code -> {count},
    // DROPS an out-of-vocab connKind AND an out-of-vocab inner code (both closed enums), OMITS a zero-count code.
    const ssoK = signed.bundle["ssoFailuresByKind"] as Record<string, Record<string, { count: number; lastAt: string }>> | undefined;
    ok("ssoFailuresByKind projects a per-kind classified count (saml/signature, oidc/issuer)", ssoK?.["saml"]?.["signature"]?.count === 4 && ssoK?.["oidc"]?.["issuer"]?.count === 2);
    ok("ssoFailuresByKind DROPS an out-of-vocabulary connKind (never a connId slug either)", ssoK !== undefined && !("bogus-kind" in ssoK) && !text.includes("bogus-kind"));
    ok("ssoFailuresByKind DROPS an out-of-vocab inner code and OMITS a zero-count code", ssoK?.["saml"] !== undefined && !("bogus-code" in ssoK["saml"]) && !("replay" in ssoK["saml"]) && !text.includes("bogus-code"));

    // P2 authSignals: the bounded auth/RBAC defensive-branch counters. Closed vocabulary only; DROPS an out-of-vocab
    // name; OMITS a zero-count. Never an ip/email/connId/subject (codes + ints + timestamps only).
    const asig = signed.bundle["authSignals"] as Record<string, { count: number; lastAt: string }> | undefined;
    ok("authSignals projects closed-vocab signals with their counts (emailless-assertion, scim-unauthorised)", asig?.["emailless-assertion"]?.count === 3 && asig?.["scim-unauthorised"]?.count === 7);
    // P3: the newly-wired closed-vocabulary signals project through unchanged (cf-access denial, SAML SP-initiated,
    // session revocation), which is what makes the idp-auth failure clusters diagnosable from the pack.
    ok("authSignals projects the P3 idp-auth signals (cf-access-aud-mismatch, saml-relaystate-missing, session-revoked-idp-epoch)", asig?.["cf-access-aud-mismatch"]?.count === 4 && asig?.["saml-relaystate-missing"]?.count === 2 && asig?.["session-revoked-idp-epoch"]?.count === 6);
    ok("authSignals DROPS an out-of-vocabulary signal name", asig !== undefined && !("not-a-real-signal" in asig) && !text.includes("not-a-real-signal"));
    ok("authSignals OMITS a zero-count signal", asig !== undefined && !("csrf-origin-mismatch" in asig));

    // P4/P3 authPosture: the session signing-key presence/age/adequate-length (never the key), the do-plaintext-
    // secrets-missing count, and the alternative admin-credential-path counts (token-fallback-lockout cross-check).
    const ap = signed.bundle["authPosture"] as { sessionSigningKey?: { present: boolean; ageMs?: number; adequateLength?: boolean }; doPlaintextSecretsMissing?: number; adminCredentialPaths?: { passkeyCredentials?: number; enabledIdpConnections?: number } } | undefined;
    ok("authPosture carries the session signing-key presence + age (session-signing-key-lost signal) and the missing-secret count", ap?.sessionSigningKey?.present === true && ap?.sessionSigningKey?.ageMs === 123456 && ap?.doPlaintextSecretsMissing === 2);
    ok("authPosture carries the session-key adequateLength (recovery-key-too-short) and the admin-credential-path counts (token-fallback lockout)", ap?.sessionSigningKey?.adequateLength === true && ap?.adminCredentialPaths?.passkeyCredentials === 1 && ap?.adminCredentialPaths?.enabledIdpConnections === 3);

    // P3 keys pre-ceremony: build a bundle with a NO-KEY env (SIGNER_PRIVATE only) so all three sub-blocks report
    // not-configured and carry NO fingerprint/KCV. (This section's main `signed` env sets CONFIG_WRAP_KEY for the
    // wrapKeyHealth probe above, so on THAT bundle keys.configWrapKey IS configured; the all-not-configured
    // pre-ceremony state needs its own no-key env. The block is always present -- itself diagnostic.)
    const preCeremonyEnv = { SIGNER_PRIVATE: signerB64, SCHEDULER: {} as DurableObjectNamespace, RUNSEAL: undefined } as unknown as Env;
    const keys0 = (await signedSupportBundle(preCeremonyEnv, sched.stub)).bundle["keys"] as { breakGlass: { configured: boolean; recipientFingerprint?: string }; configWrapKey: { configured: boolean; keyCheckValue?: string }; vendorSupportPublic: { configured: boolean; willSeal: boolean } };
    ok("keys reports all key material not-configured pre-ceremony with no fingerprints", keys0.breakGlass.configured === false && !("recipientFingerprint" in keys0.breakGlass) && keys0.configWrapKey.configured === false && !("keyCheckValue" in keys0.configWrapKey) && keys0.vendorSupportPublic.configured === false && keys0.vendorSupportPublic.willSeal === false);

    // v:2 notifyConfig inventory: channel kinds + counts only -- never a channel URL/address/secret.
    const nc = signed.bundle["notifyConfig"] as { channelCount: number; channelKinds: string[]; disabledChannelCount?: number; ruleCount: number; danglingChannelRefs?: number; rules: Array<{ events?: unknown; scope?: unknown }> };
    ok("notifyConfig reports the channel inventory (count + kinds)", nc.channelCount === 2 && nc.channelKinds.includes("webhook") && nc.channelKinds.includes("email") && nc.ruleCount === 1);
    ok("notifyConfig never leaks a channel URL/address", !text.includes("hooks.example") && !text.includes("ops@example.com"));
    // NOTIF companions: a rule referencing a DELETED channel is counted (dangling), and a disabled channel
    // is counted, so "an alert never fired because its channel was deleted/disabled" is diagnosable.
    ok("notifyConfig counts a rule referencing a deleted channel (rule-references-deleted-channel)", nc.danglingChannelRefs === 1);
    ok("notifyConfig counts a disabled channel", nc.disabledChannelCount === 1);
    // NOTIF: the deferred success-digest queue depth + oldest deferred entry ride under notifyHealth, PLUS the
    // per-cadence window state (byPeriod: depth/oldest/dueAt), so a never-flushing digest names WHICH cadence.
    const pd = (signed.bundle["notifyHealth"] as { pendingDigest?: { count?: number; oldestAt?: string; byPeriod?: Record<string, { count?: number; oldestAt?: string; dueAt?: string }> } }).pendingDigest;
    ok("notifyHealth.pendingDigest surfaces the deferred digest queue (a never-flushing digest is visible)", pd?.count === 2 && pd?.oldestAt === "2026-06-28T00:00:00.000Z");
    ok("notifyHealth.pendingDigest.byPeriod surfaces the per-cadence window state (depth + oldest + dueAt)", pd?.byPeriod?.["daily"]?.count === 1 && pd?.byPeriod?.["daily"]?.dueAt === "2026-06-30T00:00:00.000Z" && pd?.byPeriod?.["weekly"]?.count === 1 && pd?.byPeriod?.["weekly"]?.dueAt === "2026-07-05T00:00:00.000Z");
    // The rule's events:"all" sentinel is normalised to a single-element ARRAY (the consumer's contract), and
    // scope is projected to its KIND string only (the rule's downpipeId is dropped -- never a target detail).
    ok("notifyConfig normalises a rule's events:'all' to an array and projects scope to its kind", Array.isArray(nc.rules[0]?.events) && (nc.rules[0]!.events as string[])[0] === "all" && nc.rules[0]?.scope === "global");

    // v:2 recovery latch: recoveryRequired surfaces; `refused` is a BOOLEAN (F1), never the DO's free-text
    // reason object; staged is field-projected and DROPS the sourceKey bucket path.
    const rec = signed.bundle["recovery"] as { recoveryRequired: boolean; refused?: unknown; staged?: Record<string, unknown> | null };
    ok("recovery surfaces the amnesia latch", rec.recoveryRequired === true);
    ok("recovery.refused is projected to a boolean, not the DO's free-text reason object (F1)", rec.refused === true);
    ok("recovery.staged is field-projected and drops the sourceKey bucket path", rec.staged != null && rec.staged["version"] === "v42" && rec.staged["downpipes"] === 3 && !("sourceKey" in rec.staged));
    // F1 NO-CUSTODY: the refusal reason embedded a secret field name + a storage JSON path; it must NOT
    // appear anywhere in the signed bundle. (The static top-level latch reason is safe and may appear.)
    ok("the refusal reason free-text (secret field name + path) never reaches the bundle (no-custody, F1)", !text.includes("secretAccessKey") && !text.includes("no-custody violation") && !text.includes("destinations[0]"));
    // Phase-3 needs-new-logging: the recovery projection now also carries the CLOSED refusal code, the
    // recovery latch's own amnesia-probe class, the deterministic deploy-identity marker, the export-pass
    // health, and the staged resume diagnostics — all redaction-safe (closed enums / ints / flags).
    const recX = signed.bundle["recovery"] as { refusedCode?: string; amnesiaProbe?: { probe?: string }; deploy?: { changesObserved?: number; cfVersionIdAbsent?: boolean; baselineEstablished?: boolean }; exportHealth?: { skipped?: string; wroteAny?: boolean; perDest?: Array<{ id: string; ok: boolean }> }; staged?: Record<string, unknown> | null };
    ok("recovery.refusedCode forwards the CLOSED auto-heal refusal classifier (signer-rotation vs missing export)", recX.refusedCode === "shape-check");
    ok("recovery.amnesiaProbe surfaces the latch's own detection class (the two blind spots become visible)", recX.amnesiaProbe?.probe === "runs-present");
    ok("recovery.deploy surfaces the deterministic deploy marker (baseline/change/cf-absent)", recX.deploy?.changesObserved === 2 && recX.deploy?.cfVersionIdAbsent === false && recX.deploy?.baselineEstablished === true);
    ok("recovery.exportHealth surfaces the skip reason + per-dest write outcome (stale/partial generation)", recX.exportHealth?.skipped === "budget-yield" && recX.exportHealth?.perDest?.some((d) => d.id === "offsite-s3" && d.ok === false) === true);
    ok("recovery.staged surfaces resumeSkipped + appliedVersion (malformed-skip + stale-rollback visible)", recX.staged?.["resumeSkipped"] === 1 && recX.staged?.["appliedVersion"] === 42);

    // CPR audit-chain verify verdict + rollover + near-cap + verify cost (the pack's `audit`).
    const aud = signed.bundle["audit"] as { intact?: boolean; rolledOver?: boolean; rolledOverCount?: number; auditNearCap?: boolean; verify?: { entriesChecked?: number } } | undefined;
    ok("audit surfaces the chain verify verdict + rollover state + near-cap + verify cost", aud?.intact === true && aud?.rolledOver === true && aud?.rolledOverCount === 2 && aud?.auditNearCap === false && aud?.verify?.entriesChecked === 25);
    // CPR audit-feed grant state (a SIEM PULL channel is wired + being pulled); no-PII projection.
    const af = signed.bundle["auditFeed"] as { configured?: boolean; expired?: boolean; pullCount?: number; lastPullAt?: string } | undefined;
    ok("auditFeed surfaces the SIEM pull credential state + last-pull recency", af?.configured === true && af?.expired === false && af?.pullCount === 2 && af?.lastPullAt === "2026-06-29T00:00:00.000Z");
    ok("auditFeed drops the grantedBy email + the clientId (no-PII)", !text.includes("siem-admin@example.com") && !text.includes("dpc_feed"));
    // CPR wrap-key health: the env key decrypts the encrypted-at-rest credential => class "ok".
    const wk = signed.bundle["wrapKeyHealth"] as { class?: string; encryptedDestCount?: number } | undefined;
    ok("wrapKeyHealth reports the wrap key still decrypts the encrypted-at-rest credential (class ok)", wk?.class === "ok" && wk?.encryptedDestCount === 1);
    ok("wrapKeyHealth never surfaces the decrypted credential", !text.includes("a-destination-secret-access-key"));
    // NOTIF pipeline drop counters (the pack's `notifyHealth`).
    const nhb = signed.bundle["notifyHealth"] as { passSkips?: number; recordSkips?: number; parseRejects?: number } | undefined;
    ok("notifyHealth surfaces the pipeline drop counters (passes/records/parse-rejects)", nhb?.passSkips === 1 && nhb?.recordSkips === 2 && nhb?.parseRejects === 3);

    // NOTIF dns-rebinding-gap: the send-time sinkScreen verdict rides on the notify history rows. A DELIVERED
    // webhook to a bare hostname surfaces sinkScreen:"hostname" (the residual rebind-exposed class, on SUCCESS),
    // and an out-of-vocab verdict is DROPPED (never propagated).
    const notifyRows = signed.bundle["notify"] as Array<Record<string, unknown>>;
    const okHostnameRow = notifyRows.find((r) => r["delivered"] === true && r["channelKind"] === "webhook");
    ok("notify row surfaces the send-time sinkScreen verdict on a DELIVERED hostname sink (rebind-exposed observed)", okHostnameRow?.["sinkScreen"] === "hostname");
    const badScreenRow = notifyRows.find((r) => r["deliveryCode"] === "credential-undecryptable");
    ok("notify row DROPS an out-of-vocabulary sinkScreen verdict (defence in depth)", badScreenRow !== undefined && badScreenRow["sinkScreen"] === undefined);
    ok("the bundle never carries a raw sinkScreen injection string", !text.includes("id=secret-leak"));

    // NOTIF canary-transition-only-pages-once: the canary's liveness + its bounded transition ring ride as
    // `canary`, so a standing "paged once" death stays observable. A transition with an out-of-vocab `to` is DROPPED.
    const can = signed.bundle["canary"] as { enabled?: boolean; status?: string; deadDestinations?: number; transitions?: Array<Record<string, unknown>> } | undefined;
    ok("canary surfaces the aggregate liveness + dead-destination count (a standing death is visible)", can?.enabled === true && can?.status === "dead" && can?.deadDestinations === 1);
    ok("canary surfaces the bounded transition ring (WHEN each destination flipped dead/recovered)", can?.transitions?.length === 1 && can?.transitions?.[0]?.["to"] === "dead" && can?.transitions?.[0]?.["destinationId"] === "offsite-s3" && can?.transitions?.[0]?.["runSeq"] === 12);
    ok("canary DROPS a transition with an out-of-vocabulary to-state", can?.transitions?.every((t) => t["to"] === "dead" || t["to"] === "recovered") === true && !text.includes("bogus"));

    // NOTIF cooldown-suppresses-renudge-1h: the per-downpipe alert-cooldown state rides as `alertCooldowns`, so
    // "why didn't I get re-alerted about a still-broken pipe" is answerable. An out-of-vocab state is DROPPED.
    const cd = signed.bundle["alertCooldowns"] as { cooldownMs?: number; alert?: Array<Record<string, unknown>>; replication?: Array<Record<string, unknown>> } | undefined;
    ok("alertCooldowns surfaces the per-downpipe staleness/failure cooldown state (downpipe + state + at)", cd?.cooldownMs === 3_600_000 && cd?.alert?.length === 1 && cd?.alert?.[0]?.["downpipeId"] === "dp1" && cd?.alert?.[0]?.["state"] === "failed");
    ok("alertCooldowns surfaces the replication-stream cooldown state", cd?.replication?.length === 1 && cd?.replication?.[0]?.["state"] === "replication-degraded");
    ok("alertCooldowns DROPS a cooldown row with an out-of-vocabulary state", cd?.alert?.every((r) => r["state"] === "failed" || r["state"] === "stale") === true && !text.includes("not-a-state"));
    // CPR configEvents fetch marker: the excerpt was read successfully (empty != unavailable).
    ok("configEventsFetched marks the audit excerpt as read (empty != unavailable)", signed.bundle["configEventsFetched"] === true);

    // B4 control-plane export-lag: the export-state pointer rides as controlPlaneExport -- the config VERSION
    // the last signed control-plane export covered + WHEN -- so support sees how STALE the recovery backup is
    // (complements the recovery latch). It carries the integer version + the timestamp ONLY; the
    // configContentHash must NOT leak into the pack (redaction-safe: int + timestamp).
    const cpe = signed.bundle["controlPlaneExport"] as { configVersion?: number; exportedAt?: string; configContentHash?: string };
    ok("controlPlaneExport carries the config version + exportedAt and drops the configContentHash", cpe.configVersion === 7 && cpe.exportedAt === "2026-06-29T00:00:00.000Z" && !("configContentHash" in cpe) && !text.includes("sha384:x"));

    // v:2 source selector (A3): include/exclude globs + the CF accountId the downpipe ran under.
    const dpMain = (signed.bundle["downpipes"] as Array<Record<string, unknown>>)[0]!;
    const sel = dpMain["selector"] as { include: string[]; exclude: string[] };
    ok("the downpipe carries its source selector (include/exclude globs) + accountId", sel.include[0] === "uploads/*" && sel.exclude[0] === "uploads/tmp/*" && dpMain["accountId"] === "acct-123");

    // SCHED per-downpipe nextRunAt rides (a clamped timestamp for the wedged/overdue signal). A cronResolve
    // class OUTSIDE the closed vocabulary never reaches the pack (redaction defence), and it does not take the
    // whole cronResolve block with it: the block rides with the "unknown-code" PLACEHOLDER, so a writer/pack
    // skew is legible instead of reading as "this downpipe has no cron" (the healthy state).
    ok("the downpipe carries its clamped nextRunAt", dpMain["nextRunAt"] === 1_700_000_050_000);
    ok(
      "a cronResolve class outside the closed vocabulary rides as the unknown-code placeholder, never the raw value",
      (dpMain["cronResolve"] as { class?: unknown })?.class === "unknown-code" && !text.includes("bogus-class"),
    );

    // config-shape counts in an ISOLATED nested bundle build (a secrets source with 3 rows + 2
    // blackout windows, and a manual cf-config source with a 2-entry include), so a silently dropped form row
    // is detectable. Counts only, never the secret names or window bounds. Own scheduler double so it does not
    // perturb the estate-rollup assertions in the enclosing block.
    await (async () => {
    function shapeScheduler(): DurableObjectStub {
      return {
        async fetch(input: RequestInfo | URL): Promise<Response> {
          const url = new URL(input instanceof Request ? input.url : String(input));
          if (url.pathname === "/downpipes") return new Response(JSON.stringify([
            { config: { id: "dp2", name: "vault", enabled: true, cadenceSeconds: 3600, source: { type: "secrets", secrets: [{ name: "a" }, { name: "b" }, { name: "c" }] }, schedule: { blackoutWindows: [{ from: 1 }, { to: 2 }] } }, lastRunId: null, inFlight: false },
            { config: { id: "dp3", name: "cfg", enabled: true, cadenceSeconds: 3600, source: { type: "cf-config", cfConfigMode: "manual", include: ["dns", "zone-settings"] } }, lastRunId: null, inFlight: false },
          ]));
          return new Response(JSON.stringify({}));
        },
      } as unknown as DurableObjectStub;
    }
    const shapeEnv = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const built = await signedSupportBundle(shapeEnv, shapeScheduler());
    const allDps = built.bundle["downpipes"] as Array<Record<string, unknown>>;
    const dpSecrets = allDps.find((d) => d["id"] === "dp2")!;
    const dpCfg = allDps.find((d) => d["id"] === "dp3")!;
    ok("a secrets downpipe carries secretsRowCount (a dropped secret row is detectable)", dpSecrets["secretsRowCount"] === 3);
    ok("a downpipe carries scheduleWindowCount for its blackout windows", dpSecrets["scheduleWindowCount"] === 2);
    ok("a manual cf-config downpipe carries cfConfigIncludeCount", dpCfg["cfConfigIncludeCount"] === 2);
    ok("the shape counts never carry the values (secret names / window bounds absent)", !JSON.stringify(built.bundle["downpipes"]).includes("\"name\":\"a\"") && !JSON.stringify(dpSecrets).includes("blackout"));
    })();

    // A3.2 replication attribution: WHICH destination is down. The down replica is recorded only in the
    // replication heartbeats (never on the run row), so this is the sole place it is attributable. The coarse
    // reason rides; a down dest carries its reason, a healthy one does not.
    const repl = (dpMain["replication"] as { destinations: Array<{ id: string; ok: boolean; reason?: string }> }).destinations;
    const downDest = repl.find((d) => d.ok === false);
    const okDest = repl.find((d) => d.ok === true);
    ok("replication attributes the DOWN destination with its coarse reason, healthy ones without", downDest?.id === "replica-s3" && downDest?.reason === "unreachable" && okDest?.id === "origin-r2" && !("reason" in (okDest ?? {})));

    // INFRA bundle-degrades-silently-on-do-blip / platform-wide-outage: the per-section fetch-status health
    // vector. Every section the dense double serves with data reads "ok"; a section it does not serve (the
    // default {} route, e.g. the scheduler-signals/update-status routes not on this double) reads "empty",
    // NOT "error" — an honest absence, distinct from a fault (proven by the throwing double below).
    const secs = signed.bundle["sections"] as Record<string, string>;
    ok("sections marks the served data sections ok (downpipes/runs/notify/notifyConfig/recovery/configEvents)", secs["downpipes"] === "ok" && secs["runs"] === "ok" && secs["notify"] === "ok" && secs["notifyConfig"] === "ok" && secs["recovery"] === "ok" && secs["configEvents"] === "ok");
    ok("sections is a closed 3-value enum (ok/empty/error) — never operator text", Object.values(secs).every((s) => s === "ok" || s === "empty" || s === "error"));
    // INFRA no-runtime-logs-in-pack: the sections vector is the redaction-safe stand-in for raw runtime logs, so
    // it must be COMPLETE and EXPLICIT. Every roster subsystem is present (the produced keys EXACTLY equal
    // SUPPORT_SECTION_NAMES — a new fetch added without a section() wrapper would break this), and sectionsSummary
    // is the explicit ok/empty/error/expected header a reader consults first (the "which subsystems answered" answer).
    ok("sections is COMPLETE: the produced keys exactly equal the closed SUPPORT_SECTION_NAMES roster", [...SUPPORT_SECTION_NAMES].slice().sort().join(",") === Object.keys(secs).slice().sort().join(","));
    const summary = signed.bundle["sectionsSummary"] as { expected: number; ok: number; empty: number; error: number };
    ok("sectionsSummary is the explicit ok/empty/error/expected header (counts reconcile with the vector)", summary.expected === SUPPORT_SECTION_NAMES.length && summary.ok + summary.empty + summary.error === summary.expected && summary.ok === Object.values(secs).filter((s) => s === "ok").length);

    // volumes (self-serve volume-based licensing, estate.ts): the roster grew by exactly one member
    // (INFRA no-runtime-logs-in-pack: SUPPORT_SECTION_NAMES is the closed, explicit contract every
    // section() call is pinned against), and the estate rollup computed cleanly off the SAME dp1
    // fixture (kv, accountId acct-123, one "ok" run of recordCount 12 / bytes 4096) the downpipes/runs
    // sections above already read, so it must sum to the identical figures.
    ok("SUPPORT_SECTION_NAMES grew to include the new volumes section", SUPPORT_SECTION_NAMES.includes("volumes"));
    // The ENGINE SELF-DIAGNOSTIC sections (round-2 gap audit): each new recorder got a gatherer, a roster entry
    // and a section() wrapper, so the health vector stays COMPLETE (a gatherer added without a wrapper would
    // already have broken the exact-equality check above). Their PROJECTIONS and their redaction posture are
    // proven end to end in validate-support-diag-projection.ts; this pins the roster contract itself.
    for (const name of ["schedDiag", "sealErrors", "metricsHealth", "webauthnFaults", "droppedWrites"] as const) {
      ok(`SUPPORT_SECTION_NAMES carries the new '${name}' diagnostic section, and the health vector reports it`, SUPPORT_SECTION_NAMES.includes(name) && typeof secs[name] === "string");
    }
    // The advertised capability vector rides on the engine block (booleans + a count only, no account or
    // resource data), so a console that shows no Cloudflare-wide sources tier is diagnosable as an engine that
    // does not advertise it, rather than as a console bug.
    const caps = (signed.bundle["engine"] as Record<string, unknown>)["capabilities"] as Record<string, unknown>;
    ok(
      "engine.capabilities carries the advertised source-tier vector",
      caps["addedSourcesSupported"] === true && caps["tokenSourceOfferedCount"] === 5 && (caps["tokenSourceTypes"] as string[]).length === 5 && caps["workersSupported"] === true,
    );
    // A bundle built with NO request context honestly OMITS accessPerimeter rather than fabricating a
    // false "no Access perimeter fronts this host" (which would send a collector-credential diagnosis the wrong way).
    ok("accessPerimeter is OMITTED when the caller supplied no request context (never a fabricated false)", !("accessPerimeter" in signed.bundle));
    ok("sections marks volumes ok too (the estate rollup computed cleanly off the same DO fixture)", secs["volumes"] === "ok");
    const vol = signed.bundle["volumes"] as { totalProtectedBytes: number; accounts: number; zones: number; downpipes: number; byType: Record<string, { records: number; bytes: number }>; asOf: string | null };
    ok(
      "volumes carries the estate rollup computed from the SAME roster + run history the bundle itself reads (dp1: kv, 1 account, 12 records, 4096 bytes)",
      vol.downpipes === 1 && vol.accounts === 1 && vol.zones === 0 && vol.totalProtectedBytes === 4096 && vol.byType["kv"]?.records === 12 && vol.byType["kv"]?.bytes === 4096 && vol.asOf === "2026-06-10T00:00:00.000Z",
    );

    // INFRA slice-knobs-misconfigured / cpu-ms-misconfigured-low; SCHED free-plan-subrequest-cap: the resolved
    // scale knobs. With no SCALE_* env set, both resolve to their defaults (subrequests 700, wall 20000) with
    // source "default" and the platform ceilings surfaced. rateLimitDoConfigured is false (no RATELIMIT_DO binding).
    const infra = signed.bundle["infra"] as {
      scaleKnobs: { sliceSubrequests: { resolved: number; ceiling: number; source: string }; sliceWallMs: { resolved: number; ceiling: number; source: string } };
      rateLimitDoConfigured: boolean;
      cpuMs?: number;
      planTier: { freePlanSubrequestCeiling: number; budgetExceedsFreeCeiling: boolean; maxObservedSubrequestSpend: number; paidPlanProven: boolean };
      lowSliceWallMs: number;
      sliceWallUnusuallyLow: boolean;
      sliceWallWithinCpuMs?: boolean;
    };
    ok("infra.scaleKnobs surfaces the resolved slice subrequest budget + ceiling (default 700, ceiling 940)", infra.scaleKnobs.sliceSubrequests.resolved === 700 && infra.scaleKnobs.sliceSubrequests.ceiling === 940 && infra.scaleKnobs.sliceSubrequests.source === "default");
    ok("infra.scaleKnobs surfaces the resolved slice wall budget + ceiling (default 20000, ceiling 120000)", infra.scaleKnobs.sliceWallMs.resolved === 20000 && infra.scaleKnobs.sliceWallMs.ceiling === 120000 && infra.scaleKnobs.sliceWallMs.source === "default");
    ok("infra.rateLimitDoConfigured is false with no RATELIMIT_DO binding, and cpuMs is omitted with no CPU_MS", infra.rateLimitDoConfigured === false && !("cpuMs" in infra));

    // SCHED free-plan-subrequest-cap: the OBSERVE-side plan-tier indicator. The default budget (700) exceeds the
    // free-plan 50-subrequest ceiling; a recorded tick spent 720 (> 50) and SURVIVED, which PROVES a paid plan
    // (a free plan would have died at the cap). maxObservedSubrequestSpend is the largest recorded per-tick spend.
    ok("infra.planTier anchors the free-plan subrequest ceiling (a known platform limit)", infra.planTier.freePlanSubrequestCeiling === FREE_PLAN_SUBREQUEST_CEILING && FREE_PLAN_SUBREQUEST_CEILING === 50);
    ok("infra.planTier flags the resolved budget exceeding the free-plan ceiling (700 > 50)", infra.planTier.budgetExceedsFreeCeiling === true);
    ok("infra.planTier PROVES a paid plan from an observed tick that survived past the free ceiling (720 > 50)", infra.planTier.paidPlanProven === true && infra.planTier.maxObservedSubrequestSpend === 720);
    // INFRA cpu-ms-misconfigured-low: the default 20000 slice wall is well above the 'unusually low' floor
    // (LOW_SLICE_WALL_MS), so the flag is false; with no CPU_MS mirror the sliceWallWithinCpuMs cross-check is omitted.
    ok("infra.sliceWallUnusuallyLow is false for the default 20000 wall (above the low floor)", infra.sliceWallUnusuallyLow === false && infra.lowSliceWallMs === LOW_SLICE_WALL_MS && LOW_SLICE_WALL_MS === 5000);
    ok("infra.sliceWallWithinCpuMs is omitted with no CPU_MS mirror", !("sliceWallWithinCpuMs" in infra));

    // RUNS-SCHEDULER + INFRA scheduler-liveness: the per-tick outcome ring (the false-green detector), the
    // due-index parity snapshot, and the runlog counter vs max history index all ride into the pack.
    const sch = signed.bundle["scheduler"] as { ticks: Array<Record<string, number | boolean>>; dueIndex: Record<string, number | boolean>; runlog: { counter: number; maxHistoryIndex: number; reset: boolean } };
    ok("scheduler carries the per-tick outcome ring", Array.isArray(sch.ticks) && sch.ticks.length === 2);
    // The FALSE-GREEN tick: dispatched 0 of 5 due, over budget, a crashed pass, carried the tail, and a huge
    // interval — every one of the "cron reported green but backups stalled" signals in a single record.
    const fg = sch.ticks[1]!;
    ok("scheduler surfaces the false-green tick: dispatched 0 of 5 due, carried 3, coalesced 2, a crashed pass", fg["due"] === 5 && fg["dispatched"] === 0 && fg["carried"] === 3 && fg["coalesced"] === 2 && fg["passErrors"] === 1);
    ok("scheduler surfaces the subrequest OVERDRAW (spent 720 > cap 700, overBudget) and the missed-tick interval", fg["overBudget"] === true && fg["budgetSpent"] === 720 && fg["budgetCap"] === 700 && fg["intervalMs"] === 899_000);
    // SCHED due-index-drift / rebuild-partial-or-too-big: the parity snapshot shows the index disagreed with dp: truth.
    ok("scheduler surfaces the due-index parity snapshot with matched=false (drift)", sch.dueIndex["matched"] === false && sch.dueIndex["indexEntriesBeforeRebuild"] === 4 && sch.dueIndex["indexEntriesRequired"] === 5 && sch.dueIndex["dpTotal"] === 5);
    // SCHED runlog-counter-reset: the derived reset flag fires when the counter is below a run index already recorded.
    ok("scheduler derives the runlog reset flag (counter 3 < maxHistoryIndex 7)", sch.runlog.counter === 3 && sch.runlog.maxHistoryIndex === 7 && sch.runlog.reset === true);
    // INFRA do-list-pagination-cap: the DO list page size + paging guard + the live history-ring count, so a
    // fleet nearing pageSize*maxPages (silent read truncation) is visible against the caps.
    const lc = (signed.bundle["scheduler"] as { listCaps: { pageSize: number; maxPages: number; historyRings: number } }).listCaps;
    ok("scheduler surfaces the DO list caps + live history-ring count (do-list-pagination-cap)", lc.pageSize === 1000 && lc.maxPages === 1000 && lc.historyRings === 5);
    // SCHED persist-state-storage-fault / INFRA do-value-size-limit: the DISTINCT persist-state storage-fault
    // counter rides into the pack — the total + the per-class sub-counts (value-too-large vs generic put-failed)
    // + the last class/time — isolating the storage-fault subset from the generic tick sealErrors/passErrors.
    const sf = (signed.bundle["scheduler"] as { storageFaults?: { total: number; valueTooLarge: number; putFailed: number; lastAt: number; lastKind?: string } }).storageFaults;
    ok("scheduler surfaces the distinct storage-fault counter (total 3, 1 value-too-large, 2 put-failed)", sf?.total === 3 && sf.valueTooLarge === 1 && sf.putFailed === 2);
    ok("scheduler surfaces the last storage-fault class + a clamped timestamp", sf?.lastKind === "value-too-large" && sf.lastAt === 950_000);
    ok("the scheduler section is a pure counts/flags surface (no id/name/value strings)", Object.values(fg).every((v) => typeof v === "number" || typeof v === "boolean"));

    // UPDATES-LIFECYCLE: the safe-apply state machine rides into the pack — pending (versions + riskClass), the
    // last outcome + REASON + canary verdict (previously presence-only, no reason/outcome), the rollback latch,
    // the high-water mark, and engineAccountMarked (the config-level gate). Answers "my update/rollback failed".
    const upd = signed.bundle["updates"] as { pending?: Record<string, unknown>; last?: Record<string, unknown>; rollbackNeeded?: Record<string, unknown>; settledHighWaterMark?: string; engineAccountMarked?: boolean };
    ok("updates carries the pending promote (versions + riskClass + promotedAt)", upd.pending?.["toVersion"] === "2026.07.01-abc" && upd.pending?.["riskClass"] === "migration" && upd.pending?.["promotedAt"] === 1_700_000_800_000);
    // The free-text `reason` is NO LONGER projected, and this assertion used to REQUIRE it. It was asserting the
    // leak: the update paths interpolate the raw Cloudflare deploy-driver error into that sentence
    // (`...: ${msg(e)}`), so a platform message carrying a URL, an account id or a script name was riding into
    // the sealed bundle behind a 200-char clamp, and a clamp is not a redaction. The pack now carries the closed
    // reasonClass instead, and the operator still sees the full sentence in their own console.
    // See test/validate-update-reason-redaction.ts.
    ok("updates carries the last OUTCOME + closed reason CLASS + canary verdict (the 'my update failed' diagnosis)", upd.last?.["outcome"] === "rolled-back" && upd.last?.["canaryVerdict"] === "dead" && upd.last?.["reasonClass"] !== undefined);
    ok("updates does NOT carry the free-text reason (it now embeds the raw platform error)", upd.last?.["reason"] === undefined);
    // The DECISION TRACE ( observability): the pack must carry selfCheckOk + the per-attempt
    // settleTrace, so a self-apply rollback is diagnosable FROM THE PACK -- was it a dead canary (data) or a
    // swap-window flake -- without a live tail. This is the exact gap the owner surfaced by dogfooding it.
    // Each step carries its closed detailClass, NOT the engine's sentence. update-gate.ts's catch arm
    // interpolates the raw canary-flight exception (which embeds the canary URL and hostname) into that
    // sentence, and it was riding into the sealed bundle behind a 160-char clamp. A clamp bounds the LENGTH of
    // a leak, not its content. See test/validate-support-update-detail.ts.
    const lastTrace = upd.last as { selfCheckOk?: unknown; settleTrace?: Array<{ step?: string; ok?: boolean; detail?: string; detailClass?: string }> } | undefined;
    ok("updates.last carries selfCheckOk (dead-canary vs swap-window-flake discriminator)", lastTrace?.selfCheckOk === true);
    ok("updates.last carries the per-attempt settleTrace (the retry story a rollback is diagnosed from)", Array.isArray(lastTrace?.settleTrace) && lastTrace!.settleTrace!.length === 2 && lastTrace!.settleTrace![0]?.step === "canary-flight" && lastTrace!.settleTrace![1]?.detailClass === "dead");
    ok("updates.last carries NO raw settleTrace detail (the canary-flight catch arm interpolates the platform's exception into it)", lastTrace!.settleTrace!.every((a) => a.detail === undefined));
    ok("updates carries the rollback-needed latch + the anti-rollback high-water mark", upd.rollbackNeeded?.["canaryVerdict"] === "dead" && upd.settledHighWaterMark === "2026.06.30");
    ok("updates.engineAccountMarked is true when an engineAccountId is stored", upd.engineAccountMarked === true);
    ok("the updates block carries no deploy token / secret (version ids + engine-authored reason only)", !text.includes("dps_") && !JSON.stringify(upd).toLowerCase().includes("token"));

    // scheduled-restore-fail-reason: the persisted CLOSED failure code + consecutive-failure streak project
    // onto the downpipe, so a pack read after the notify ring rolled over still carries WHY (and how many in
    // a row). The code is a member of the closed vocabulary; the streak is a positive int; never a raw reason.
    ok("the downpipe carries the restore-test failure coarse code + consecutive-failure streak", dpMain["lastRestoreTestReason"] === "integrity" && dpMain["restoreTestConsecutiveFailures"] === 3);

    // reconcile (support-pack modes reconcile-orphans-invisible / runlog-corrupt-parse): the per-destination
    // orphan inventory + RUNLOG health the report-only reconcile pass persisted (previously only logged).
    // One destination has recoverable-but-invisible orphan runs; another has a corrupt/unverifiable RUNLOG.
    const recon = signed.bundle["reconcile"] as Array<{ destKey: string; runlogPresent: boolean; runlogSigVerified: boolean; runlogHealth?: string; orphanedRecoverable: number; neverReferenced: number; freshnessResiduals?: number; deferred?: string }>;
    const origin = recon.find((r) => r.destKey === "origin-r2");
    const replica = recon.find((r) => r.destKey === "replica-s3");
    ok("reconcile attributes recoverable-but-invisible orphan runs to a destination (RUNLOG present+verified)", origin?.orphanedRecoverable === 2 && origin?.neverReferenced === 3 && origin?.runlogSigVerified === true);
    ok("reconcile surfaces a corrupt / unverifiable destination RUNLOG (the runlog-unverifiable abstain)", replica?.runlogPresent === true && replica?.runlogSigVerified === false && replica?.deferred === "runlog-unverifiable");
    // runlog-sig-stale-window: the closed runlogHealth diagnosis rides (ok on the verified dest, corrupt on
    // the unverifiable one). freshness-rollback-residual: the dangling-prev-link count rides on the verified dest.
    ok("reconcile carries the runlogHealth diagnosis + freshnessResiduals count", origin?.runlogHealth === "ok" && origin?.freshnessResiduals === 1 && replica?.runlogHealth === "corrupt");

    // sealFaults (Phase 3 seal-integrity modes shard-list-truncated / orphan-root-worm-leak /
    // signer-rotation-strands-runs): the bounded seal-fault OBSERVE ring, projected with its coarse kind +
    // the customer's own ids + the counts / WORM flag the fault computed. The hostile out-of-vocabulary kind
    // is dropped by the pack's defence-in-depth gate and never reaches the bundle.
    const sealF = signed.bundle["sealFaults"] as Array<{ kind: string; runId?: string; found?: number; expected?: number; wormBlocked?: boolean }>;
    ok("sealFaults carries the truncated-archive refuse with its found/expected shard counts", sealF.some((f) => f.kind === "shard-list-truncated" && f.found === 968 && f.expected === 970 && f.runId === "01RUN"));
    ok("sealFaults carries the orphan-root reclaim with the WORM-blocked signal", sealF.some((f) => f.kind === "orphan-root-reclaim" && f.wormBlocked === true));
    ok("an out-of-vocabulary seal-fault kind is DROPPED (never reaches the pack)", !sealF.some((f) => f.kind === "hostile-not-a-kind") && !JSON.stringify(signed.bundle).includes("hostile-not-a-kind"));
    // engine.cfVersionId (two-engines-flapping-ledger): this engine's immutable Cloudflare deploy id, co-located
    // with accountTag so `accountTag + cfVersionId` is the per-engine identity that disambiguates two engines
    // flapping one licence-ledger row (the ledger correlation is vendor-side). engine.deployBaseline (engine-
    // version-change-baseline-suppressed / same-version-redeploy): the deploy identity observed at the last
    // status-snapshot baseline, so a snapshot RESET a same-version redeploy would hide is attributable (a changed
    // `at` reveals a reset; cfVersionId names the deploy).
    const eng2 = signed.bundle["engine"] as { accountTag?: string; cfVersionId?: string; deployBaseline?: { version?: string; cfVersionId?: string; at?: number } };
    ok("engine.cfVersionId surfaces the running deploy id (per-engine identity = accountTag + cfVersionId)", eng2.cfVersionId === "cfv-running-xyz" && eng2.accountTag === "acct-eng-xyz");
    ok("engine.deployBaseline surfaces the deploy identity at the snapshot baseline (reset attribution)", eng2.deployBaseline?.version === "2026.07.01" && eng2.deployBaseline?.cfVersionId === "cfv-baseline-abc" && eng2.deployBaseline?.at === 1_700_000_070_000);

    // driveBudgetYields (failover-probe-budget-exhaustion): the cron seal loop ran out of the shared subrequest
    // budget and carried due downpipes over — otherwise only a log line. The pack surfaces the count + last carried.
    const dby = signed.bundle["driveBudgetYields"] as { count: number; lastCarried?: number; lastAt?: number };
    ok("driveBudgetYields surfaces the cron seal-loop budget-yield count + last carried-over", dby.count === 2 && dby.lastCarried === 7 && dby.lastAt === 1_700_000_050_000);

    // configIntegrity (CONFIG-domain OBSERVE signals): snapshotFailures (config-snapshot-best-effort-gap), history
    // (config-history-session-key-regen — signingKeyRotated distinguishes a rotated in-DO signing key from content
    // tamper), and changeControlRefusals (change-number-required-refusal — read WITHOUT touching the CR ledger).
    const ci = signed.bundle["configIntegrity"] as { snapshotFailures?: { count: number }; history?: { intact: boolean; brokenAt?: number; signingKeyRotated?: boolean }; changeControlRefusals?: { count: number; lastActionKind?: string } };
    ok("configIntegrity.snapshotFailures surfaces the swallowed auto-snapshot failure count (config-snapshot-gap)", ci.snapshotFailures?.count === 2);
    ok("configIntegrity.history distinguishes a rotated signing key from content tamper (signingKeyRotated)", ci.history?.intact === false && ci.history?.brokenAt === 4 && ci.history?.signingKeyRotated === true);
    ok("configIntegrity.changeControlRefusals surfaces refused changes + the closed action kind (CR ledger untouched)", ci.changeControlRefusals?.count === 3 && ci.changeControlRefusals?.lastActionKind === "dest-remove");

    // licenceActivationRefusals (failed-activation-no-trace): console activations refused by verify-before-store,
    // with the CLOSED reason code — so "I pasted my licence but it still says community" is diagnosable, never the token.
    const lar = signed.bundle["licenceActivationRefusals"] as { count: number; lastReasonCode?: string; lastAt?: number };
    ok("licenceActivationRefusals surfaces the refusal count + the closed reason code (expired)", lar.count === 4 && lar.lastReasonCode === "expired" && lar.lastAt === 1_700_000_060_000);

    // licenceExpiryTracker (expiry-tracker-stale): the OBSERVED `licence` expiry-registry row's tracked notAfter +
    // coarse state, surfaced alongside licence.notAfter so a DRIFTED (stale) tracked row is visible bot-side. NEVER
    // the registry row's operator label.
    const let2 = signed.bundle["licenceExpiryTracker"] as { trackedNotAfter?: string; state?: string; source?: string };
    // The instant is the one the double was built from, so this cannot drift apart from it; the state is
    // still pinned to a CONCRETE "ok" rather than recomputed here, because a check that re-derives the
    // expectation from the same function the double used would assert nothing about the projection.
    ok("licenceExpiryTracker surfaces the observed licence row's tracked notAfter + state (stale-drift visible)", let2.trackedNotAfter === LICENCE_TRACKED_NOT_AFTER && let2.state === "ok" && let2.source === "observed");
    ok("licenceExpiryTracker NEVER carries the registry row's operator label", !text.includes("my licence"));

    // sourcesDetached (sources-detached-binding-names-absent): WHICH bindings are detached (the count already rides
    // in status; the pack adds the NAMES — operator labels, the same class as source.binding in the config snapshot).
    const sd = signed.bundle["sourcesDetached"] as { count: number; bindings: string[] };
    ok("sourcesDetached names the detached binding(s) (not just a count)", sd.count === 1 && sd.bindings.includes("UPLOADS_KV"));

    // multipart-abort-stranded-parts: a FAILED multipart abort left invisible stranded parts; the pack must
    // surface the BOOLEAN on the run row so the otherwise-swallowed cost/clutter fault is visible.
    ok("the pack run row surfaces multipartAbortFailed (stranded multipart parts)", run0["multipartAbortFailed"] === true);

    const sigOk = await hybridVerify(verifier, canonicalJSON(signed.bundle), b64urlDecode(signed.signature));
    ok("the bundle signature verifies against the engine signer", sigOk);

    // Phase 3 sealKnobs (seal-integrity: verify-at-seal-disabled / seal-verify-knobs-invisible /
    // scale-knobs-invisible / sliced-runs-disabled). The block carries the RESOLVED seal tuning as ints +
    // bools. This env sets NO knobs, so the block reports the running DEFAULTS, verify-at-seal ON, and
    // OMITS the shard/segment knobs the operator did not set (canonicalJSON rejects an explicit undefined).
    const sk = signed.bundle["sealKnobs"] as {
      verifyAtSeal: { enabled: boolean; sample: number; maxBytes: number; fullBytes: number; attempts: number; fullShards: number; shardSample: number };
      slice: { subrequests: number; wallMs: number };
      shardMaxRecords?: number;
      segmentTargetBytes?: number;
      slicedRunsDisabled: boolean;
    };
    ok("sealKnobs surfaces verify-at-seal ON with the resolved sample/attempt/shard defaults", sk.verifyAtSeal.enabled === true && sk.verifyAtSeal.sample === 3 && sk.verifyAtSeal.attempts === 3 && sk.verifyAtSeal.fullShards === 900 && sk.verifyAtSeal.shardSample === 64);
    ok("sealKnobs surfaces the resolved per-slice budget defaults (700 subrequests / 20000 ms)", sk.slice.subrequests === 700 && sk.slice.wallMs === 20_000);
    ok("sealKnobs reports slicedRunsDisabled=false by default and OMITS unset shard/segment knobs", sk.slicedRunsDisabled === false && !("shardMaxRecords" in sk) && !("segmentTargetBytes" in sk));
    ok("sealKnobs is redaction-safe (ints + bools only, no key/value/name)", typeof sk.verifyAtSeal.maxBytes === "number" && typeof sk.verifyAtSeal.fullBytes === "number");
  }

  // ---------------------------------------------------------------------------------------------------
  // The support-pack GAP-AUDIT expansion: every new field the Record agents made the engine record must
  // actually RIDE the bundle, be gated on its CLOSED vocabulary, and carry nothing custody-unsafe.
  // Covers: scheduler health + state refusals, blackout resolution, retention prune evidence, reconcile
  // splits, per-destination immutability posture, the async-create ack outcome, key-material classes, and
  // the unknown-code placeholder (never a silent drop).
  console.log("\nthe support bundle carries the gap-audit evidence (closed-gated, redaction-safe):");
  {
    const sched = schedulerDouble();
    const env = {
      SIGNER_PRIVATE: b64urlEncode(concat(rand(32), rand(32))),
      SCHEDULER: {} as DurableObjectNamespace,
      RUNSEAL: undefined,
      // The signer above is a REAL 64-byte key, so it classifies clean. These two are the classic
      // paste faults: a PEM blob into a base64url slot, and the 96-byte PRIVATE identity pasted into the
      // PUBLIC recipient slot (which wants 1600 bytes) -- the exact "I pasted the wrong key" support ticket.
      BREAK_GLASS_PUBLIC: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----",
      OPERATIONAL_PUBLIC: b64urlEncode(rand(96)),
    } as unknown as Env;
    const built = await signedSupportBundle(env, sched.stub);
    const b = built.bundle;
    const bStr = JSON.stringify(b);

    // --- the scheduler housekeeping + state-refusal evidence --------------------------------------------
    const schedSec = b["scheduler"] as Record<string, unknown>;
    const sh = schedSec["schedHealth"] as { sweepFaults: { count: number }; listTruncations: { count: number }; parityStampFailures: { count: number }; parityStampStale: boolean };
    ok("scheduler.schedHealth rides the housekeeping faults that were fully silent (sweep/list-truncation/parity)", sh !== undefined && sh.sweepFaults.count === 4 && sh.listTruncations.count === 2 && sh.parityStampFailures.count === 1);
    ok("scheduler.schedHealth.parityStampStale flags a STALE dueIndex snapshot being served as if fresh", sh.parityStampStale === true);
    const sf = schedSec["storageFaults"] as { lastDownpipeId?: string; valueTooLarge?: number };
    ok("scheduler.storageFaults.lastDownpipeId ATTRIBUTES the persist fault to a downpipe", sf.lastDownpipeId === "dp1" && sf.valueTooLarge === 1);
    const refusals = schedSec["stateRefusals"] as { total: number; downpipes: Array<{ downpipeId: string; class: string; storedVersion: number; supportedVersion: number }> };
    ok("scheduler.stateRefusals rides the refused downpipes with their closed class + version pair", refusals.downpipes.length === 1 && refusals.downpipes[0]!.downpipeId === "dp1" && refusals.downpipes[0]!.class === "schema-newer" && refusals.downpipes[0]!.storedVersion === 4 && refusals.downpipes[0]!.supportedVersion === 3);
    ok("a HOSTILE state-refusal class is DROPPED at the pack boundary (closed-vocabulary gate)", !bStr.includes("not-a-real-class") && !bStr.includes("dp-hostile"));

    // The per-downpipe JOIN: an INDETERMINATE "stale, no runs, no errors" downpipe now names its cause.
    const dpRow = (b["downpipes"] as Array<Record<string, unknown>>)[0]!;
    const refused = dpRow["stateRefused"] as { class: string; count: number } | undefined;
    ok("downpipes[].stateRefused joins the refusal onto its row (rollback-skew, not INDETERMINATE staleness)", refused !== undefined && refused.class === "schema-newer" && refused.count === 9);

    // --- the blackout (change-freeze) resolution -----------------------------------------------------------
    const br = dpRow["blackoutResolve"] as { class: string; at: number } | undefined;
    ok("downpipes[].blackoutResolve rides the closed class (a run firing INSIDE a declared change freeze)", br !== undefined && br.class === "hop-ceiling-fired-inside-window" && br.at === 1_700_000_060_000);
    ok("blackoutResolve NEVER carries the window minutes/days (only the class + when), like the cron strings", !JSON.stringify(br).includes("startMinute") && !JSON.stringify(br).includes("endMinute"));

    // --- the retention prune evidence ------------------------------------------------------------------
    const faults = b["sealFaults"] as Array<Record<string, unknown>>;
    const deferred = faults.find((f) => f["kind"] === "prune-deferred");
    ok("sealFaults carries prune-deferred with its CLOSED defer class + the BLOCKING retained run", deferred !== undefined && deferred["deferClass"] === "retained-run-unreadable" && deferred["runId"] === "01BLOCK" && deferred["skipped"] === 2 && deferred["unparseableTime"] === 1);
    const partial = faults.find((f) => f["kind"] === "prune-partial-apply");
    ok("sealFaults carries prune-partial-apply: a HALF-APPLIED prune, with WORM refusing the delete", partial !== undefined && partial["partial"] === true && partial["wormBlocked"] === true && partial["superseded"] === 5 && partial["reclaimed"] === 12);
    const skippedRow = faults.find((f) => f["kind"] === "prune-runs-skipped");
    ok("a HOSTILE deferClass (an S3 key + free text) is DROPPED while its row survives (defence in depth)", skippedRow !== undefined && skippedRow["deferClass"] === undefined && skippedRow["skipped"] === 3);
    ok("the poison S3 object key planted in a deferClass NEVER reaches the pack", !bStr.includes("s3://bucket/secret-key.txt"));

    const ret = b["retention"] as { replicationUnreadable: boolean; auditWriteFailures: number; passSkipCode?: string; destinations: Array<Record<string, unknown>>; downpipes: Array<Record<string, unknown>> };
    ok("retention section rides the pass record", ret !== undefined && ret.downpipes.length === 2);
    ok("retention.replicationUnreadable: the coverage gate ran on NO proof, so every replicated run was HELD", ret.replicationUnreadable === true && ret.auditWriteFailures === 2);
    const retDeferred = ret.downpipes.find((d) => d["id"] === "dp1");
    ok("retention.downpipes[] carries the closed outcome + deferral class (the perpetual-deferral case)", retDeferred !== undefined && retDeferred["outcome"] === "deferred" && retDeferred["deferralClass"] === "retained-run-unreadable" && retDeferred["volumeHeld"] === 1);
    const retDry = ret.downpipes.find((d) => d["id"] === "dp-dry");
    ok("retention.downpipes[] names the commonest cause of all: a dry-run (enforce was never set)", retDry !== undefined && retDry["outcome"] === "dry-run" && retDry["runTreeObjects"] === 40);
    ok("a HOSTILE retention outcome drops the WHOLE row (the outcome is load-bearing, not decorative)", ret.downpipes.every((d) => d["id"] !== "dp-bad") && !bStr.includes("not-a-real-outcome"));
    ok("retention.destinations[] carries the closed skip code (an unreadable RUNLOG stops the prune)", ret.destinations[0]!["skipCode"] === "runlog-unreadable");
    ok("sections.retention is 'ok' (a served pass), so an empty retention is distinguishable from a read fault", (b["sections"] as Record<string, string>)["retention"] === "ok");

    // --- the reconcile splits the three-way summary folded away ---------------------------------------------
    const rec = b["reconcile"] as Array<Record<string, unknown>>;
    const origin = rec.find((r) => r["destKey"] === "origin-r2")!;
    ok("reconcile[] splits `undetermined` into within-grace / unreadable / pending-classify", origin["undeterminedWithinGrace"] === 1 && origin["undeterminedUnreadable"] === 2 && origin["undeterminedPendingClassify"] === 3);
    ok("reconcile[] splits `neverReferenced` into TAMPER vs a CRASHED FINALISE (same count, opposite tickets)", origin["neverReferencedSigInvalid"] === 1 && origin["neverReferencedAttestIncomplete"] === 2);
    const tripped = rec.find((r) => r["destKey"] === "cold-s3")!;
    ok("reconcile[] carries the circuit-breaker FRACTION as two counts, never a ratio sentence", tripped["orphanFractionNumerator"] === 9 && tripped["orphanFractionDenominator"] === 10 && tripped["deferred"] === "circuit-breaker");

    // --- the per-destination immutability posture -----------------------------------------------------------
    const dests = (b["destResolution"] as { destinations: Array<Record<string, unknown>> }).destinations;
    const dR2 = dests.find((d) => d["id"] === "d-r2")!;
    ok("destResolution[] exposes the immutability SHADOW: a WORM policy set against a NON-enforcing bucket", dR2["wormPolicyConfigured"] === true && dR2["bucketEnforces"] === "not-enforced" && dR2["deleteProbe"] === "ok");
    const dS3 = dests.find((d) => d["id"] === "d-s3")!;
    ok("a HOSTILE objectLock value is DROPPED while the row's other closed fields survive", dS3["bucketEnforces"] === undefined && dS3["deleteProbe"] === "denied" && !bStr.includes("hostile-not-a-state"));
    ok("destResolution STILL never carries an endpoint host or bucket name (4.22's contract is unchanged)", !bStr.includes("my.dotted.bucket") && !bStr.includes("r2.cloudflarestorage.com") && !bStr.includes("plainbucket"));

    // --- the async-create ack outcome ------------------------------------------------------------------------
    const notif = b["notify"] as Array<Record<string, unknown>>;
    const jsmRow = notif.find((n) => n["channelKind"] === "jsm")!;
    ok("notify[] carries ackOutcome: a delivered:true row whose async create the provider says FAILED", jsmRow["delivered"] === true && jsmRow["unconfirmed"] === true && jsmRow["ackOutcome"] === "async-create-failed");
    const snowRow = notif.find((n) => n["channelKind"] === "servicenow")!;
    ok("a HOSTILE ackOutcome is DROPPED while `unconfirmed` still rides (closed-vocabulary gate)", snowRow["ackOutcome"] === undefined && snowRow["unconfirmed"] === true && !bStr.includes("hostile-not-an-outcome"));
    ok("notify[] carries the rotated-wrap-key code, not masquerading as `no-transport`", notif.some((n) => n["deliveryCode"] === "credential-undecryptable"));

    // --- the key-material classes ----------------------------------------------------------------------------
    const keys = b["keys"] as { signer: { configured: boolean; malformed?: boolean }; recipients: { configuredCount: number; malformedCount: number; malformedSlots: string[]; slots: Array<{ slot: string; malformClass?: string }> } };
    ok("keys.signer classifies the REAL signer as configured + well-formed", keys.signer.configured === true && keys.signer.malformed === undefined);
    const bg = keys.recipients.slots.find((s) => s.slot === "break-glass")!;
    const op = keys.recipients.slots.find((s) => s.slot === "operational")!;
    ok("keys.recipients names WHICH slot is malformed and WHAT is wrong (a PEM paste = bad-encoding)", bg.malformClass === "bad-encoding");
    ok("keys.recipients catches the 96-byte PRIVATE identity pasted into a PUBLIC slot (wrong-length)", op.malformClass === "wrong-length" && keys.recipients.malformedSlots.includes("operational"));
    ok("keys.recipients counts the malformed slots (2 configured, 2 malformed)", keys.recipients.configuredCount === 2 && keys.recipients.malformedCount === 2);
    // The decoded byte LENGTH is deliberately not reported: it is an open integer derived from a customer-
    // pasted value, and the closed class already carries everything support needs to act.
    const keysStr = JSON.stringify(keys);
    ok("keys NEVER carries the key material, the decoder's message, or a decoded byte length", !keysStr.includes("BEGIN PUBLIC KEY") && !keysStr.includes("MIIBIjANBg") && !/\b(96|1600|64)\b/.test(keysStr) && !keysStr.includes("invalid") && !keysStr.includes("base64url"));

    // --- The whole-bundle redaction sweep over every new fixture value --------------------------------
    ok("NO poison value from ANY new fixture reaches the bundle (whole-bundle redaction sweep)", !bStr.includes("secret-key.txt") && !bStr.includes("not-a-real-class") && !bStr.includes("not-a-real-outcome") && !bStr.includes("hostile-not-a-state") && !bStr.includes("hostile-not-an-outcome") && !bStr.includes("hostile-not-a-kind"));
  }

  // The per-row projector's remaining arms, driven directly (the bundle fixture above pins the wired-up path;
  // these pin the arms a single roster row cannot exercise at once). The degraded self-identity posture is
  // the one that matters most: a source that cannot re-identify itself CANNOT be reconstructed after a
  // control-plane loss.
  console.log("\nthe per-downpipe projector (self-identity + the closed-vocabulary gates):");
  {
    const noRefusals = new Map<string, { downpipeId: string; class: string; at: number; count: number; storedVersion: number; supportedVersion: number }>();
    const src = (source: Record<string, unknown>) => ({ config: { id: "d", source } }) as unknown as SupportDownpipeRow;

    // A kv source WITHOUT its namespaceId cannot be re-identified from its own config: buildAdapter falls back
    // on exactly this field, so the derivation cannot drift from the behaviour it describes.
    const degraded = projectDownpipeDiagnostics(src({ type: "kv", binding: "UPLOADS_KV" }), noRefusals);
    ok("a kv source missing its namespaceId is flagged selfIdentityDegraded / native-id-absent", degraded["selfIdentityDegraded"] === true && degraded["selfIdentityClass"] === "native-id-absent");
    const healthy = projectDownpipeDiagnostics(src({ type: "kv", binding: "UPLOADS_KV", namespaceId: "ns-1" }), noRefusals);
    ok("a fully-identified source contributes NOTHING (a clean fleet's rows are byte-identical to before)", Object.keys(healthy).length === 0);
    const secretsDegraded = projectDownpipeDiagnostics(src({ type: "secrets", secrets: [{ name: "API_KEY" }] }), noRefusals);
    ok("a secrets source whose binding lacks a Secrets Store storeId is secrets-store-absent", secretsDegraded["selfIdentityClass"] === "secrets-store-absent");
    ok("selfIdentityDegradedCount counts the fleet's un-reconstructable downpipes", selfIdentityDegradedCount([src({ type: "kv" }), src({ type: "kv", namespaceId: "ns-1" }), src({ type: "r2" })]) === 2);

    // The blackout gate: a class outside the closed vocabulary is DROPPED, never propagated.
    const hostileBlackout = projectDownpipeDiagnostics({ config: { id: "d", source: { type: "kv", namespaceId: "ns-1" } }, blackoutResolve: { class: "'; DROP TABLE--", at: 1 } } as unknown as SupportDownpipeRow, noRefusals);
    ok("a HOSTILE blackoutResolve class is DROPPED at the pack boundary (closed-vocabulary gate)", hostileBlackout["blackoutResolve"] === undefined && !JSON.stringify(hostileBlackout).includes("DROP TABLE"));
    const okBlackout = projectDownpipeDiagnostics({ config: { id: "d", source: { type: "kv", namespaceId: "ns-1" } }, blackoutResolve: { class: "degenerate-window-inert", at: 7 } } as unknown as SupportDownpipeRow, noRefusals);
    ok("a degenerate blackout window (start === end, so the freeze NEVER applied) rides as its own class", (okBlackout["blackoutResolve"] as { class: string }).class === "degenerate-window-inert");

    // stateRefusalIndex must not fabricate a join from a faulted/absent scheduler section.
    ok("stateRefusalIndex is empty when the scheduler section faulted (no false rollback-skew claim)", stateRefusalIndex({}).size === 0);
    ok("stateRefusalIndex drops an out-of-vocabulary class rather than indexing it", stateRefusalIndex({ stateRefusals: { downpipes: [{ downpipeId: "x", class: "bogus" }] } }).size === 0);
  }

  console.log("\nthe support bundle sealKnobs (operator-set + OFF + clamp paths):");
  {
    const sched = schedulerDouble();
    // An env that DISABLES verify-at-seal, SETS the shard/segment knobs, turns ON SLICED_RUNS_DISABLED, and
    // OVER-SETS the slice budget (must clamp to the platform-survivable ceilings 940 / 120000).
    const env = {
      SIGNER_PRIVATE: b64urlEncode(concat(rand(32), rand(32))),
      SCHEDULER: {} as DurableObjectNamespace,
      RUNSEAL: undefined,
      VERIFY_AT_SEAL: "0",
      SEAL_VERIFY_SAMPLE: "0",
      SCALE_SHARD_MAX_RECORDS: "1000",
      SCALE_SEGMENT_TARGET_BYTES: "1048576",
      SCALE_SLICE_SUBREQUESTS: "99999",
      SCALE_SLICE_WALL_MS: "99999999",
      SLICED_RUNS_DISABLED: "true",
    } as unknown as Env;
    const signed = await signedSupportBundle(env, sched.stub);
    const sk = signed.bundle["sealKnobs"] as {
      verifyAtSeal: { enabled: boolean; sample: number };
      slice: { subrequests: number; wallMs: number };
      shardMaxRecords?: number;
      segmentTargetBytes?: number;
      slicedRunsDisabled: boolean;
    };
    ok("sealKnobs reflects verify-at-seal turned OFF (enabled=false) and a decrypt sample of 0", sk.verifyAtSeal.enabled === false && sk.verifyAtSeal.sample === 0);
    ok("sealKnobs INCLUDES the operator-set shard/segment knobs", sk.shardMaxRecords === 1000 && sk.segmentTargetBytes === 1_048_576);
    ok("sealKnobs reflects SLICED_RUNS_DISABLED=true (the no-resume large-value posture)", sk.slicedRunsDisabled === true);
    ok("sealKnobs CLAMPS an over-set slice budget to the platform-survivable ceilings (940 / 120000)", sk.slice.subrequests === 940 && sk.slice.wallMs === 120_000);
  }

  console.log("\nthe restore-test failure-reason gate (defence-in-depth redaction):");
  {
    // A downpipe whose persisted lastRestoreTestReason is OUTSIDE the closed vocabulary (a corrupt / hostile
    // internal value) must be DROPPED by the projection, so only closed codes ever reach the bundle.
    const bogusScheduler = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/downpipes") {
          return new Response(JSON.stringify([{ config: { id: "dpX", name: "x", enabled: true, cadenceSeconds: 3600, source: { type: "kv" } }, lastRunId: null, inFlight: false, lastRestoreTestOk: false, lastRestoreTestReason: "hostile-not-a-code-<script>", restoreTestConsecutiveFailures: 2 }]));
        }
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const env = { SIGNER_PRIVATE: signerB64, SCHEDULER: {} as DurableObjectNamespace, RUNSEAL: undefined } as unknown as Env;
    const signed = await signedSupportBundle(env, bogusScheduler);
    const dp = (signed.bundle["downpipes"] as Array<Record<string, unknown>>)[0]!;
    // The RAW code is never carried (the redaction guarantee is absolute), but the field does not
    // VANISHES -- a downpipe whose restore tests have failed for weeks used to read as though it had never
    // reported a cause at all. The drift placeholder rides in its place.
    ok(
      "an out-of-vocabulary restore-test reason code rides as the unknown-code placeholder, never the raw value",
      dp["lastRestoreTestReason"] === "unknown-code" && !JSON.stringify(signed.bundle).includes("hostile-not-a-code"),
    );
    ok("the consecutive-failure streak still rides beside the placeholder", dp["restoreTestConsecutiveFailures"] === 2);
  }

  console.log("\nthe support bundle (WORM / Object-Lock posture):");
  {
    // Item 3: a configured WORM policy (env DEST_WORM_*) + an in-account R2 destination. The pack carries the
    // POLICY verdict (configured + mode + days) AND the LIVE capability-probe result. R2's native binding
    // cannot read a bucket's Object-Lock configuration, so objectLockStatus honestly returns "unknown" (the
    // safe cannot-confirm reading) — the pack surfaces that verbatim rather than a false enforcement claim.
    // Redaction-safe by construction: closed enums (mode) + integers + "unknown"/booleans only.
    const env = { SIGNER_PRIVATE: signerB64, DEST_R2: {} as R2Bucket, DEST_KIND: "r2", DEST_WORM_MODE: "compliance", DEST_WORM_RETENTION_DAYS: "7" } as unknown as Env;
    const built = await signedSupportBundle(env, schedulerDouble().stub);
    const wp = built.bundle["wormPosture"] as Record<string, unknown>;
    ok("wormPosture carries the configured policy (configured + mode + retentionDays)", wp["configured"] === true && wp["misconfigured"] === false && wp["mode"] === "compliance" && wp["retentionDays"] === 7);
    ok("wormPosture carries the LIVE probe verdict (R2 native binding cannot confirm Object-Lock -> 'unknown')", wp["bucketEnforces"] === "unknown");
    ok(
      "wormPosture is redaction-safe (closed enums / ints / booleans only; no endpoint/bucket/credential)",
      !JSON.stringify(wp).includes("cloudflarestorage") && Object.values(wp).every((v) => typeof v === "string" || typeof v === "number" || typeof v === "boolean"),
    );
  }

  console.log("\nthe sealed bundle (vendor key):");
  {
    const sched = schedulerDouble();
    const xk = x25519.keygen();
    const kemSeed = rand(64);
    const vendorPubB64 = b64urlEncode(concat(xk.publicKey, mlkemKeygen(kemSeed).encapKey));
    // A VALID DEST_RATE_PER_SEC here exercises destResolution's valid-rate branch (carried as-is, not flagged).
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64, DEST_RATE_PER_SEC: "25" } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, sched.stub)) as { kind: string; capsule: Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>; iv: string; ciphertext: string };
    ok("the sealed form is emitted when the vendor key is set", sealed.kind === "downpipe-support-bundle-sealed");
    // Open it as vendor support would: decapsulate, derive, decrypt.
    const identity = parseIdentity(concat(xk.secretKey, kemSeed));
    const aad = utf8("downpipe/engine support-bundle v1");
    const k = await openCapsule(parseWraps(sealed.capsule), identity, aad);
    const dek = await hkdfSha384(k, new Uint8Array(0), utf8("downpipe/engine support-bundle-key v1"), 32);
    const plain = await aesGcmOpen(dek, b64urlDecode(sealed.iv), b64urlDecode(sealed.ciphertext), aad);
    const inner = JSON.parse(new TextDecoder().decode(plain)) as { kind: string; signature: string; bundle: { keys?: { vendorSupportPublic?: { recipientFingerprint?: string } } } };
    ok("the vendor identity opens it to the signed bundle", inner.kind === "downpipe-support-bundle-signed" && inner.signature.length > 0);
    // DERIVATION-IDENTITY PROOF (keys security review): the sealed envelope's capsule wrap
    // fingerprint, the envelope-level recipientFingerprint, and the INNER pack's keys.vendorSupportPublic
    // fingerprint must all agree -- one derivation for "which vendor key can open this", asserted where a
    // divergence would strand a real sealed bundle.
    const sealedEnv = sealed as unknown as { recipientFingerprint?: string };
    const innerVsFp = inner.bundle.keys?.vendorSupportPublic?.recipientFingerprint;
    ok("sealed envelope wrap fingerprint == envelope recipientFingerprint == inner keys.vendorSupportPublic fingerprint", sealed.capsule.length === 1 && sealed.capsule[0]!.fingerprint === sealedEnv.recipientFingerprint && innerVsFp === sealedEnv.recipientFingerprint);

    // Band manifest: the sealed envelope carries the CLEAR-SIGNED
    // manifest alongside the ciphertext. It must verify under its own CARRIED keys, its fingerprint
    // must recompute from those keys, its bodySha256 must hash the exact raw ciphertext bytes, and
    // its cleartext volumes/licence must agree with what is inside the sealed body.
    const bandEnv = sealed as unknown as { v: number; manifest?: Record<string, unknown>; manifestSignature?: string };
    const man = bandEnv.manifest;
    ok("the sealed envelope carries the band manifest and its signature", typeof man === "object" && man !== null && typeof bandEnv.manifestSignature === "string" && bandEnv.manifestSignature !== "");
    if (man && typeof bandEnv.manifestSignature === "string") {
      ok("the manifest carries the exact domain label inside the signed bytes", man["kind"] === "downpipe-support-band-manifest" && man["v"] === 1);
      const sp = man["signerPublic"] as { ed: string; mldsa: string };
      const carriedEd = b64urlDecode(sp.ed);
      const carriedMldsa = b64urlDecode(sp.mldsa);
      ok("the carried signer publics have the exact hybrid lengths (32/2592)", carriedEd.length === 32 && carriedMldsa.length === 2592);
      ok("the manifest signature verifies under the CARRIED keys over canonicalJSON(manifest)", await hybridVerify({ ed: carriedEd, mldsa: carriedMldsa }, canonicalJSON(man), b64urlDecode(bandEnv.manifestSignature)));
      ok("the manifest fingerprint recomputes from the carried keys", man["signerFingerprint"] === (await signerFingerprint({ ed: carriedEd, mldsa: carriedMldsa })));
      ok("bodySha256 binds the manifest to THIS sealed body (sha256 of the raw ciphertext bytes)", man["bodySha256"] === (await sha256Hex(b64urlDecode(sealed.ciphertext))));
      const innerFull = inner as unknown as { signerFingerprint: string; bundle: { volumes?: { totalProtectedBytes: number; accounts: number } | null; licence?: { tier?: string } | null } };
      ok("the manifest fingerprint matches the inner bundle's signer", man["signerFingerprint"] === innerFull.signerFingerprint);
      const mv = man["volumes"] as { totalProtectedBytes: number; accounts: number } | null;
      const iv2 = innerFull.bundle.volumes;
      ok("the manifest volumes is exactly the inner rollup's {totalProtectedBytes, accounts} pair", iv2 != null && mv !== null && mv.totalProtectedBytes === iv2.totalProtectedBytes && mv.accounts === iv2.accounts && Object.keys(mv).length === 2);
      const mlic = man["licence"] as { present: boolean; tier?: string };
      ok("the manifest licence mirrors the inner bundle (present + closed-vocabulary tier)", mlic.present === (innerFull.bundle.licence != null) && mlic.tier === innerFull.bundle.licence?.tier);
    }
  }

  console.log("\nthe band manifest on the signed-plain and pre-ceremony envelopes:");
  {
    // Signed-plain (no vendor key): the manifest still rides, WITHOUT bodySha256 -- the inner hybrid
    // signature already covers the whole body, so there is no separate sealed body to bind to.
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const plain = (await sealedSupportBundle(env, schedulerDouble().stub)) as { kind: string; manifest?: Record<string, unknown>; manifestSignature?: string };
    ok("the signed-plain envelope carries the band manifest", plain.kind === "downpipe-support-bundle-signed" && typeof plain.manifest === "object" && plain.manifest !== null && typeof plain.manifestSignature === "string");
    ok("the signed-plain manifest carries NO bodySha256 (no sealed body to bind to)", plain.manifest !== undefined && !("bodySha256" in plain.manifest!));
    if (plain.manifest && plain.manifestSignature) {
      const sp = plain.manifest["signerPublic"] as { ed: string; mldsa: string };
      ok("the signed-plain manifest verifies under its carried keys", await hybridVerify({ ed: b64urlDecode(sp.ed), mldsa: b64urlDecode(sp.mldsa) }, canonicalJSON(plain.manifest), b64urlDecode(plain.manifestSignature)));
    }

    // Pre-ceremony (no SIGNER_PRIVATE): no manifest at all, on either form. An unsigned manifest
    // would be an unverifiable claim, worse than honest absence.
    const prePlain = (await sealedSupportBundle({} as unknown as Env, schedulerDouble().stub)) as Record<string, unknown>;
    ok("a pre-ceremony signed-plain envelope carries no manifest", !("manifest" in prePlain) && !("manifestSignature" in prePlain));
    const xk2 = x25519.keygen();
    const vendorPubB64b = b64urlEncode(concat(xk2.publicKey, mlkemKeygen(rand(64)).encapKey));
    const preSealed = (await sealedSupportBundle({ VENDOR_SUPPORT_PUBLIC: vendorPubB64b } as unknown as Env, schedulerDouble().stub)) as Record<string, unknown>;
    ok("a pre-ceremony sealed envelope carries no manifest", preSealed["kind"] === "downpipe-support-bundle-sealed" && !("manifest" in preSealed) && !("manifestSignature" in preSealed));
  }

  console.log("\nbuildBandManifest edge projections (never zero-fill; closed tier vocabulary):");
  {
    const freshSigner = async (): Promise<Awaited<ReturnType<typeof loadSigner>>> => loadSigner(b64urlEncode(concat(rand(32), rand(32))));
    const mk = async (bundle: Record<string, unknown>): Promise<Record<string, unknown>> =>
      (await buildBandManifest({ bundle, signature: "", signerFingerprint: "" }, await freshSigner(), null)).manifest;

    // A null rollup (the "error"-marked volumes section resolves the field to null) must ride as
    // null, never a zero-filled pair: "unmeasured" and "empty" are different states.
    const mNull = await mk({ volumes: null, licence: null });
    ok("volumes:null rides as null when the rollup was not measurable", mNull["volumes"] === null);
    ok("licence.present is false when the bundle carries no licence", (mNull["licence"] as { present: boolean }).present === false && !("tier" in (mNull["licence"] as object)));

    // A malformed volumes object (non-numeric members) also collapses to null, never zero-filled.
    const mBad = await mk({ volumes: { totalProtectedBytes: "lots", accounts: 3 }, licence: null });
    ok("a malformed volumes object collapses to null (never zero-filled)", mBad["volumes"] === null);

    // A tier outside the closed vocabulary is OMITTED (presence still rides); a member tier is carried.
    const mHostile = await mk({ volumes: null, licence: { tier: "platinum-hostile" } });
    ok("a tier outside the closed vocabulary is omitted from the manifest", (mHostile["licence"] as { present: boolean; tier?: string }).present === true && !("tier" in (mHostile["licence"] as object)));
    const mTiered = await mk({ volumes: { totalProtectedBytes: 1024, accounts: 2 }, licence: { tier: "business-1" } });
    ok("a closed-vocabulary tier is carried, and well-formed volumes ride as the exact pair", (mTiered["licence"] as { tier?: string }).tier === "business-1" && (mTiered["volumes"] as { totalProtectedBytes: number }).totalProtectedBytes === 1024);
  }

  console.log("\nconfigEvents keystone breadth under churn (truncation review 2026-07-02):");
  {
    // A worst-case busy account: the recent window is 100% role-change churn -- EVERY diagnostic
    // keystone has scrolled past the server-capped page and is reachable ONLY via the per-action
    // filter. The excerpt must still retain the latest of ALL NINE keystone actions, each with its
    // redaction-safe projection intact, so the bot signals that key on excerpt events
    // (owner-#1 deploy/detach, dest-config-change-risky, restore-apply-incomplete,
    // idp-connection-disrupted, the notify changeKind correlation) survive any noise level.
    const KEYSTONES: Record<string, { seq: number; ts: string; action: string; outcome?: string; target?: Record<string, unknown>; prevHash: string; hash: string }> = {
      "engine-version-change": { seq: 2, ts: "2026-06-01T00:00:00.000Z", action: "engine-version-change", target: { detail: "2026.07.02-noise" }, prevHash: "sha384:n1", hash: "sha384:n2" },
      "sources-detached": { seq: 3, ts: "2026-06-01T01:00:00.000Z", action: "sources-detached", prevHash: "sha384:n2", hash: "sha384:n3" },
      "sources-attached": { seq: 4, ts: "2026-06-01T02:00:00.000Z", action: "sources-attached", prevHash: "sha384:n3", hash: "sha384:n4" },
      "dest-config-set": { seq: 5, ts: "2026-06-01T03:00:00.000Z", action: "dest-config-set", outcome: "failed", target: { kind: "dest-change", op: "set", id: "noise-dest", rejectReason: "endpoint-not-https" }, prevHash: "sha384:n4", hash: "sha384:n5" },
      "dest-config-cleared": { seq: 6, ts: "2026-06-01T04:00:00.000Z", action: "dest-config-cleared", outcome: "success", target: { kind: "dest-change", op: "remove", id: "noise-old", force: true, uncoveredOriginRunCount: 2 }, prevHash: "sha384:n5", hash: "sha384:n6" },
      "restore-verified": { seq: 7, ts: "2026-06-01T05:00:00.000Z", action: "restore-verified", outcome: "failed", target: { kind: "restore-receipt", runId: "01NOISE", recordsRestored: 4, allVerified: false, complete: false, recordsVerified: 5, failures: 1 }, prevHash: "sha384:n6", hash: "sha384:n7" },
      "restore-apply": { seq: 8, ts: "2026-06-01T06:00:00.000Z", action: "restore-apply", outcome: "success", prevHash: "sha384:n7", hash: "sha384:n8" },
      "idp-connection-change": { seq: 9, ts: "2026-06-01T07:00:00.000Z", action: "idp-connection-change", outcome: "success", target: { kind: "idpconnection", connId: "noise-saml-slug", connKind: "saml", op: "delete" }, prevHash: "sha384:n8", hash: "sha384:n9" },
      "config-change-approve": { seq: 10, ts: "2026-06-01T08:00:00.000Z", action: "config-change-approve", outcome: "success", target: { kind: "configchange", id: "cc-noise-id", changeKind: "notify-channel-delete", approverEmail: "checker@example.com" }, prevHash: "sha384:n9", hash: "sha384:n10" },
    };
    const churn = Array.from({ length: 60 }, (_, i) => ({ seq: 400 + i, ts: "2026-06-10T00:00:00.000Z", action: "role-change", outcome: "ok", prevHash: `sha384:c${i}`, hash: `sha384:c${i + 1}` }));
    const noiseScheduler = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/audit/export") {
          const action = url.searchParams.get("action");
          if (action !== null) {
            const e = KEYSTONES[action];
            return new Response(JSON.stringify({ events: e ? [e] : [], headSeq: 460, headHash: "sha384:h", exportedAt: "2026-06-10T01:00:00.000Z" }));
          }
          return new Response(JSON.stringify({ events: churn, headSeq: 460, headHash: "sha384:h", exportedAt: "2026-06-10T01:00:00.000Z" }));
        }
        if (url.pathname === "/downpipes") return new Response(JSON.stringify([]));
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const noisy = await signedSupportBundle({ SIGNER_PRIVATE: signerB64 } as unknown as Env, noiseScheduler);
    const nEvents = noisy.bundle["configEvents"] as Array<Record<string, unknown>>;
    const nActions = new Set(nEvents.map((e) => e["action"]));
    const wanted = Object.keys(KEYSTONES);
    ok("ALL NINE keystone actions survive a churn-only recent window (per-action filter retention)", wanted.every((a) => nActions.has(a)));
    ok("keystone projections ride the retained events (toVersion / dest rejectReason+force / restore counts / idp connKind+op / changeKind)",
      nEvents.some((e) => e["action"] === "engine-version-change" && e["toVersion"] === "2026.07.02-noise") &&
      nEvents.some((e) => e["action"] === "dest-config-set" && e["rejectReason"] === "endpoint-not-https") &&
      nEvents.some((e) => e["action"] === "dest-config-cleared" && e["force"] === true && e["uncoveredOriginRunCount"] === 2) &&
      nEvents.some((e) => e["action"] === "restore-verified" && e["complete"] === false && e["failures"] === 1) &&
      nEvents.some((e) => e["action"] === "idp-connection-change" && e["connKind"] === "saml" && e["op"] === "delete") &&
      nEvents.some((e) => e["action"] === "config-change-approve" && e["changeKind"] === "notify-channel-delete"));
    const nText = JSON.stringify(nEvents);
    ok("retained keystones stay redaction-safe under churn (no connId slug / approver email / operator dest id)", !nText.includes("noise-saml-slug") && !nText.includes("checker@example.com") && !nText.includes("noise-dest") && !nText.includes("noise-old") && !nText.includes("cc-noise-id"));
  }

  console.log("\nthe credentialed pull routes:");
  {
    const sched = schedulerDouble();
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const minted = await mintIngestCredential("audit-feed", "owner@example.com.au", undefined);
    sched.grants["audit-feed"] = minted.grant;

    const noAuth = await handleSupportPull(new Request("https://e/support/audit-feed"), env, sched.stub);
    ok("a pull without a bearer is a plain 401", noAuth.status === 401 && (await noAuth.text()) === "unauthorised");
    const wrong = await handleSupportPull(new Request("https://e/support/audit-feed", { headers: { Authorization: `Bearer ${minted.clientId}.dps_${b64urlEncode(rand(24))}` } }), env, sched.stub);
    ok("a wrong secret is a plain 401", wrong.status === 401);
    const diagWithFeedCred = await handleSupportPull(new Request("https://e/support/diagnostics", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    ok("a credential is scope-bound (the audit-feed credential cannot pull diagnostics)", diagWithFeedCred.status === 401);

    const page1 = await handleSupportPull(new Request("https://e/support/audit-feed?afterSeq=0&limit=10", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    ok("the right bearer pulls the feed", page1.status === 200);
    const body1 = (await page1.json()) as { count: number; nextAfterSeq: number; headSeq: number; events: Array<{ seq: number; prevHash: string; hash: string }> };
    ok("the feed pages ascending from afterSeq", body1.count === 10 && body1.events[0]!.seq === 1 && body1.nextAfterSeq === 10);
    ok("the feed carries the chain fields for SIEM continuity checks", body1.events.every((e) => e.prevHash && e.hash) && body1.headSeq === 25);
    const page2 = await handleSupportPull(new Request(`https://e/support/audit-feed?afterSeq=${body1.nextAfterSeq}&limit=100`, { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    const body2 = (await page2.json()) as { count: number; events: Array<{ seq: number }> };
    ok("the next checkpointed pull continues without overlap", body2.events[0]!.seq === 11 && body2.count === 15);
    ok("every pull was recorded on the grant (customer-visible)", sched.pulls.filter((p) => p.scope === "audit-feed").length === 2);

    sched.grants["diagnostics"] = (await mintIngestCredential("diagnostics", null, undefined)).grant;
    // Re-mint and use the matching secret for the diagnostics pull.
    const diag = await mintIngestCredential("diagnostics", null, undefined);
    sched.grants["diagnostics"] = diag.grant;
    const pull = await handleSupportPull(new Request("https://e/support/diagnostics", { headers: { Authorization: `Bearer ${diag.clientId}.${diag.secret}` } }), env, sched.stub);
    ok("the diagnostics credential pulls the bundle", pull.status === 200 && /downpipe-support-bundle/.test(await pull.text()));
  }

  // A scheduler double whose history, notify and downpipe shapes are SPARSE: the
  // /history reply omits byDownpipe entirely, the single run row omits every optional
  // count, the notify entry omits its deliveries array, and the downpipe omits the
  // restore-test, integrity and seal-verify fields. This drives the falsy side of every
  // conditional spread and the nullish fallbacks (?? {} and ?? []) in buildSupportBundle.
  function sparseScheduler(): DurableObjectStub {
    return {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        switch (url.pathname) {
          case "/downpipes":
            return new Response(JSON.stringify([{ config: { id: "dp1", name: "uploads", enabled: true, cadenceSeconds: 3600, source: { type: "kv" } }, lastRunId: null, inFlight: false }]));
          case "/history":
            // No byDownpipe key at all: exercises the `byDownpipe ?? {}` fallback.
            return new Response(JSON.stringify({}));
          case "/notify/history":
            // A FLAT entry carrying only ts+event: drives the FALSY side of every optional-field spread
            // (severity/downpipeId/channelKind/delivered omitted) so canonicalJSON never sees an undefined.
            return new Response(JSON.stringify([{ seq: 1, ts: "2026-06-10T00:00:01.000Z", event: "backup-ok" }]));
          case "/tick-info":
            return new Response(JSON.stringify({ lastTickAt: Date.now() }));
          default:
            return new Response(JSON.stringify({}));
        }
      },
    } as unknown as DurableObjectStub;
  }

  console.log("\nthe support bundle (sparse and edge shapes):");
  {
    // No SIGNER_PRIVATE: the pre-ceremony path returns the bundle UNSIGNED.
    const unsignedEnv = {} as unknown as Env;
    const unsigned = await signedSupportBundle(unsignedEnv, sparseScheduler());
    ok("a pre-ceremony bundle (no signer) is returned unsigned", unsigned.signature === "" && unsigned.signerFingerprint === "" && (unsigned.bundle["kind"] as string) === "downpipe-support-bundle");

    // ARTEFACT_SHA384 and RELEASE_SIGNER_PIN set: the truthy side of the engine-provenance spreads. The infra
    // block also exercises the knob-resolution edges: SCALE_SLICE_SUBREQUESTS over-set (clamped DOWN to 940),
    // SCALE_SLICE_WALL_MS a valid operator value (source "env"), CPU_MS mirrored, RATELIMIT_DO present.
    const provEnv = { SIGNER_PRIVATE: signerB64, ARTEFACT_SHA384: "sha384:artefact", RELEASE_SIGNER_PIN: "pin-abc", SCALE_SLICE_SUBREQUESTS: "5000", SCALE_SLICE_WALL_MS: "15000", CPU_MS: "300000", RATELIMIT_DO: {} } as unknown as Env;
    const prov = await signedSupportBundle(provEnv, sparseScheduler());
    const engine = prov.bundle["engine"] as Record<string, unknown>;
    ok("engine provenance carries artefactSha384 and releaseSignerPin when configured", engine["artefactSha384"] === "sha384:artefact" && engine["releaseSignerPin"] === "pin-abc");
    // INFRA slice-knobs-misconfigured: an over-set subrequest knob is reported CLAMPED to the ceiling (the value
    // a slice actually runs with), a valid wall knob is reported as-is with source "env", and cpuMs/rateLimitDo
    // reflect the operator config. This is the signal that "a knob was set past the platform-survivable ceiling".
    const provInfra = prov.bundle["infra"] as {
      scaleKnobs: { sliceSubrequests: { resolved: number; source: string }; sliceWallMs: { resolved: number; source: string } };
      rateLimitDoConfigured: boolean;
      cpuMs?: number;
      planTier: { budgetExceedsFreeCeiling: boolean; maxObservedSubrequestSpend: number; paidPlanProven: boolean };
      sliceWallUnusuallyLow: boolean;
      sliceWallWithinCpuMs?: boolean;
    };
    ok("an over-set SCALE_SLICE_SUBREQUESTS is reported clamped to the 940 ceiling with source 'clamped'", provInfra.scaleKnobs.sliceSubrequests.resolved === 940 && provInfra.scaleKnobs.sliceSubrequests.source === "clamped");
    ok("a valid SCALE_SLICE_WALL_MS is reported as-is (15000) with source 'env'", provInfra.scaleKnobs.sliceWallMs.resolved === 15000 && provInfra.scaleKnobs.sliceWallMs.source === "env");
    ok("rateLimitDoConfigured is true with the binding present and cpuMs mirrors CPU_MS", provInfra.rateLimitDoConfigured === true && provInfra.cpuMs === 300000);
    // SCHED free-plan-subrequest-cap RISK state: the budget (940) exceeds the free ceiling, but NO recorded tick
    // has proven a paid plan (this double serves no scheduler-signals, so maxObservedSubrequestSpend is 0) — the
    // "possibly free-plan, and the configured budget would die at the platform cap" signal a diagnoser reads.
    ok("infra.planTier flags the free-plan RISK state (budget over the ceiling, no paid proof yet)", provInfra.planTier.budgetExceedsFreeCeiling === true && provInfra.planTier.paidPlanProven === false && provInfra.planTier.maxObservedSubrequestSpend === 0);
    // INFRA cpu-ms-misconfigured-low: with a mirrored cpu_ms (300000) and a 15000 slice wall, sliceWallWithinCpuMs
    // is true (the slice wall is comfortably inside the CPU limit) and the wall is above the unusually-low floor.
    ok("infra.sliceWallWithinCpuMs is true when the slice wall is inside the mirrored cpu_ms", provInfra.sliceWallWithinCpuMs === true && provInfra.sliceWallUnusuallyLow === false);
    // An INVALID (non-numeric) knob falls back to the default and is flagged source "invalid" (a typo signal).
    const badKnobEnv = { SIGNER_PRIVATE: signerB64, SCALE_SLICE_SUBREQUESTS: "not-a-number" } as unknown as Env;
    const badKnob = await signedSupportBundle(badKnobEnv, sparseScheduler());
    const badInfra = (badKnob.bundle["infra"] as { scaleKnobs: { sliceSubrequests: { resolved: number; source: string } } }).scaleKnobs;
    ok("a non-numeric SCALE_* knob falls back to the default and is flagged source 'invalid'", badInfra.sliceSubrequests.resolved === 700 && badInfra.sliceSubrequests.source === "invalid");

    // INFRA cpu-ms-misconfigured-low edges: a typo'd-LOW slice wall (200ms) is FLAGGED unusuallyLow, and a slice
    // wall NOT comfortably inside a low mirrored cpu_ms (100000 wall vs 50000 cpu_ms) sets sliceWallWithinCpuMs
    // FALSE — the invocation would be CPU-killed before it could yield (an uncatchable kill wedges the run).
    const lowWallEnv = { SIGNER_PRIVATE: signerB64, SCALE_SLICE_WALL_MS: "200" } as unknown as Env;
    const lowWall = (await signedSupportBundle(lowWallEnv, sparseScheduler())).bundle["infra"] as { sliceWallUnusuallyLow: boolean; sliceWallWithinCpuMs?: boolean; scaleKnobs: { sliceWallMs: { resolved: number } } };
    ok("infra.sliceWallUnusuallyLow is true for a typo'd-low 200ms slice wall (below the low floor)", lowWall.sliceWallUnusuallyLow === true && lowWall.scaleKnobs.sliceWallMs.resolved === 200 && !("sliceWallWithinCpuMs" in lowWall));
    const tightCpuEnv = { SIGNER_PRIVATE: signerB64, SCALE_SLICE_WALL_MS: "100000", CPU_MS: "50000" } as unknown as Env;
    const tightCpu = (await signedSupportBundle(tightCpuEnv, sparseScheduler())).bundle["infra"] as { sliceWallWithinCpuMs?: boolean };
    ok("infra.sliceWallWithinCpuMs is false when the slice wall (100000) exceeds a low mirrored cpu_ms (50000)", tightCpu.sliceWallWithinCpuMs === false);

    // UPD engine-account-unmarked-blocks-update: the sparse double serves no discovery config and provEnv has
    // no CF_ACCOUNT_ID, so engineAccountMarked is FALSE (every self-apply update is blocked until it is marked).
    const provUpd = prov.bundle["updates"] as { engineAccountMarked?: boolean; pending?: unknown };
    ok("updates.engineAccountMarked is false when neither CF_ACCOUNT_ID nor a marked engineAccountId is set", provUpd.engineAccountMarked === false && !("pending" in provUpd));
    // The CF_ACCOUNT_ID env deploy var alone marks the account (the env path, no discovery-config fetch needed).
    const cfEnv = { SIGNER_PRIVATE: signerB64, CF_ACCOUNT_ID: "acct-from-env" } as unknown as Env;
    const cfBundle = await signedSupportBundle(cfEnv, sparseScheduler());
    ok("updates.engineAccountMarked is true when CF_ACCOUNT_ID is set in env", (cfBundle.bundle["updates"] as { engineAccountMarked?: boolean }).engineAccountMarked === true);

    // Item 2 gap-B6 (the env-fallback side): the sparse double answers {} for /dest-status, so consoleDestSet
    // stays absent and the status honestly reports statusSource "env-fallback" with destResolved "unknown"
    // (no env destination configured) — the tell a consumer reads to distinguish a degraded/absent DO read
    // from a live one, rather than the two being indistinguishable.
    const sparseStatus = prov.bundle["status"] as Record<string, unknown>;
    ok("a bundle whose DO dest read did not resolve reports statusSource 'env-fallback' + destResolved 'unknown' (gap-B6)", sparseStatus["statusSource"] === "env-fallback" && sparseStatus["destResolved"] === "unknown");

    // The sparse shapes leave runs empty and the optional fields off the downpipe.
    const dp0 = (prov.bundle["downpipes"] as Array<Record<string, unknown>>)[0]!;
    ok("a downpipe with no restore/integrity/seal fields omits them", !("lastRestoreTestAt" in dp0) && !("integrityVerified" in dp0) && !("lastSealVerify" in dp0) && dp0["lastRunId"] === null);
    // A downpipe with no in-flight lease start / no drill marker omits the stalled indicators (honest absence).
    ok("a downpipe without an in-flight lease omits the stalled indicator", !("stalled" in dp0) && !("inFlightSince" in dp0));
    ok("a downpipe with no drill in flight omits the restore-test stalled indicator", !("restoreTestStalled" in dp0) && !("restoreTestStartedAt" in dp0));
    ok("a sparse history yields an empty runs map", Object.keys(prov.bundle["runs"] as Record<string, unknown>).length === 0);
    // sealFaults is OMITTED entirely when no seal-fault has been observed (the healthy fleet steady state):
    // the sparse double returns no /seal-faults ring, so the field must be absent, not an empty array.
    ok("sealFaults is omitted when the seal-fault ring is empty (honest absence)", !("sealFaults" in prov.bundle));
    // The flat notify entry kept ts+event; every ABSENT optional field (severity/downpipeId/channelKind/
    // delivered) is OMITTED -- never emitted as undefined, which canonicalJSON would reject.
    const notify0 = (prov.bundle["notify"] as Array<Record<string, unknown>>)[0]!;
    ok("a sparse flat notify entry keeps event/at and omits the absent optional fields", notify0["event"] === "backup-ok" && notify0["at"] === "2026-06-10T00:00:01.000Z" && !("severity" in notify0) && !("channelKind" in notify0) && !("delivered" in notify0));
  }

  // A scheduler double whose shapes are the MIRROR of the sparse one: the downpipe carries
  // every optional field (restore-test, integrity, seal-verify), so their truthy spreads
  // run; the single run row OMITS recordCount/bytes/durationMs (driving the `: {}` falsy
  // side of those spreads) yet carries error and sealVerification (driving the `? {...}`
  // truthy side of those two); and /notify/history returns an object with NO entries key,
  // driving the `body.entries ?? []` fallback. Together these reach the conditional
  // branches that neither the dense nor the sparse double touches.
  function richScheduler(): DurableObjectStub {
    return {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        switch (url.pathname) {
          case "/downpipes":
            return new Response(
              JSON.stringify([
                {
                  config: { id: "dp1", name: "uploads", enabled: true, cadenceSeconds: 3600, source: { type: "kv" } },
                  lastRunId: "01RUN",
                  inFlight: true,
                  // SCHED cron-resolution fault: the downpipe's stored timezone is not recognised at runtime, so
                  // it silently runs on cadence. The closed class + timestamp ride; the cron/timezone never do.
                  // The lease start is also far in the past (> the 30-min INFLIGHT_LEASE_MS) -> a WEDGED /
                  // crashed / OOM-killed run -> stalled:true (cpu-kill-wedged-slice / sliced-runs-disabled-oom).
                  nextRunAt: 1_700_000_600_000,
                  inFlightSince: 1_700_000_200_000,
                  cronResolve: { class: "tz-invalid", at: 1_700_000_600_000 },
                  // restore-test-tick-killed: a drill in-flight marker far in the past (> the lease) -> a
                  // scheduled restore test whose cron tick was killed mid-drill -> restoreTestStalled:true.
                  restoreTestStartedAt: 1_700_000_000_000,
                  lastRestoreTestAt: 1_700_000_000_000,
                  lastRestoreTestOk: true,
                  // INFRA isolate-oom-restore: the restore-subsystem OOM-risk marker — the last restore-test drill
                  // buffered a record (40 MiB) over the 32 MiB memory-safe ceiling, so overSafe is re-derived TRUE.
                  lastRestoreOom: { at: 1_700_000_050_000, maxRecordBytes: 40 * 1024 * 1024, safeBytes: 32 * 1024 * 1024, overSafe: true },
                  integrityVerified: { at: 1_700_000_100_000, how: "sampled-open" },
                  lastSealVerify: { status: "ok", tier: "full", sampled: 3, at: 1_700_000_200_000 },
                  // B2 restorability assurance. restoreProven.by is a verified Access EMAIL -- it must be
                  // projected to `attributed:true` and the address dropped (no-custody). recoverySamples is a
                  // ring the pack must fold to count+last.
                  restoreProven: { at: 1_700_000_300_000, by: "operator@example.com.au", method: "blind-test", runId: "01PROVEN" },
                  deepVerify: { runId: "01DV", cursor: 40, records: 100, updatedAt: 1_700_000_400_000, lastFullPassAt: 1_700_000_350_000 },
                  recoverySamples: [
                    { at: 1_700_000_100_000, durationMs: 1200, bytesVerified: 4096, recordsVerified: 10 },
                    { at: 1_700_000_500_000, durationMs: 1500, bytesVerified: 8192, recordsVerified: 20 },
                  ],
                  // WS-D #2 cf-config surface discovery. present/empty carry whole (both under the 64 cap);
                  // `gated` (the BENIGN plan/entitlement bucket) and `unavailable` are BOTH deliberately oversized
                  // -- a total outage can fill them with the whole ~214 surface catalogue -- so each head is the
                  // meaningful ids the pack must surface and the rest pads PAST 64, exercising the .slice(0, 64)
                  // cap for real (gated 65 -> 64, unavailable 70 -> 64, heads kept). `unavailableCount` must report
                  // the TRUE uncapped 70 so the bot's "could not read N surfaces" prose stays accurate past the cap.
                  cfConfigDiscovery: {
                    at: 1_700_000_900_000,
                    present: ["dns", "zone-settings"],
                    empty: ["workers-routes"],
                    gated: ["account-waf", "bot-management", ...Array.from({ length: 63 }, (_, i) => `gated-${i}`)],
                    unavailable: ["managed-headers", "page-rules", ...Array.from({ length: 68 }, (_, i) => `surface-${i}`)],
                  },
                },
              ]),
            );
          case "/history":
            // A run row with NO counts (recordCount/bytes/durationMs absent) but WITH
            // an error string and a sealVerification verdict.
            return new Response(
              JSON.stringify({
                byDownpipe: {
                  dp1: [
                    {
                      runId: "01RUN",
                      index: 7,
                      startedAt: "2026-06-10T00:00:00.000Z",
                      status: "error",
                      error: "destination-unreachable",
                      // The 12-hex correlation digest a failed completion stamps on the row (byte-identical to
                      // the Logpush `[cause <hex>]` line). The pack must carry it through (the bot consumes it).
                      causeDigest: "ab12cd34ef56",
                      // The verdict-projection passthrough carries the WHOLE redaction-safe verdict, so the
                      // Phase-3 additions ride too: tier0Cause (mode tier0-only-reason-unknown) + attempts/
                      // recovered (mode runlog-sig-stale-window, the self-healed read-after-write window).
                      sealVerification: { status: "ok", tier: "sampled", sampled: 2, at: 1_700_000_300_000, reason: "scheduled", tier0Cause: "too-large", attempts: 3, recovered: true },
                      // The predecessor chain pointer + the DO's own honest verdict on it, so a
                      // downloaded pack lets an auditor reconstruct the chain offline, not only via a live
                      // GET /admin/history call. "pruned" here: a real predecessor aged out of the DO's ring.
                      prevRunId: "00PRIOR",
                      prevRunIdStatus: "pruned",
                    },
                  ],
                  // dp2 has no matching /downpipes entry (an orphan history-only ring is still processed by
                  // fetchRunHistory) and carries a HOSTILE, out-of-vocab prevRunIdStatus: the pack must DROP it
                  // (defence in depth, PREV_RUN_ID_STATUSES) while keeping the run's other honest fields.
                  dp2: [{ runId: "02RUN", index: 1, startedAt: "2026-06-10T00:00:00.000Z", status: "ok", prevRunId: "hostile-not-a-real-id", prevRunIdStatus: "bogus-status" }],
                },
              }),
            );
          case "/notify/history":
            // No entries key: drives the `(body.entries ?? [])` fallback to an empty list.
            return new Response(JSON.stringify({}));
          case "/tick-info":
            return new Response(JSON.stringify({ lastTickAt: Date.now() }));
          case "/licence-token":
            // ML-45 (no-custody): a console-activated record. The token itself need not verify (it has no
            // "." so readLicence's verify path fails closed to a community/segments status regardless of
            // any pinned key) -- setAt/setBy are attached unconditionally by readLicence, which is exactly
            // what must be redacted: the activating owner's verified Access e-mail must never reach the pack.
            return new Response(JSON.stringify({ token: "not-a-real-signed-token", setAt: 1_700_000_500_000, setBy: "owner@example.com.au" }));
          default:
            return new Response(JSON.stringify({}));
        }
      },
    } as unknown as DurableObjectStub;
  }

  console.log("\nthe support bundle (rich and present shapes):");
  {
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const built = await signedSupportBundle(env, richScheduler());

    // The downpipe present-field spreads ran: restore-test, integrity and seal-verify
    // are all carried through redaction-safe.
    const dp0 = (built.bundle["downpipes"] as Array<Record<string, unknown>>)[0]!;
    ok(
      "a downpipe with restore/integrity/seal fields carries them through",
      dp0["lastRestoreTestAt"] === 1_700_000_000_000 &&
        dp0["lastRestoreTestOk"] === true &&
        (dp0["integrityVerified"] as { how: string }).how === "sampled-open" &&
        (dp0["lastSealVerify"] as { tier: string }).tier === "full" &&
        dp0["inFlight"] === true,
    );
    // cpu-kill-wedged-slice / sliced-runs-disabled-oom (OOM part): an in-flight run whose lease has expired is
    // surfaced as stalled:true with its lease start -- the read-side wedged/crashed/OOM-killed indicator.
    ok("a wedged in-flight run (lease expired) is flagged stalled with its lease start", dp0["stalled"] === true && dp0["inFlightSince"] === 1_700_000_200_000);
    // restore-test-tick-killed: a drill in-flight marker older than the lease is surfaced as restoreTestStalled.
    ok("a killed-mid-drill restore test is flagged restoreTestStalled with its marker time", dp0["restoreTestStalled"] === true && dp0["restoreTestStartedAt"] === 1_700_000_000_000);

    // INFRA isolate-oom-restore: the restore-subsystem OOM-risk marker rides into the pack per-downpipe — the
    // largest record the last restore-test drill buffered whole, the memory-safe ceiling, and overSafe RE-DERIVED
    // in the projection (so a spoofed flag can't ride). 40 MiB > 32 MiB, so overSafe is true. Sizes + a flag only.
    const oom = dp0["lastRestoreOom"] as { at: number; maxRecordBytes: number; safeBytes: number; overSafe: boolean } | undefined;
    ok("a downpipe carries the restore-subsystem OOM-risk marker with overSafe re-derived (40 MiB > 32 MiB ceiling)", oom?.maxRecordBytes === 40 * 1024 * 1024 && oom.safeBytes === 32 * 1024 * 1024 && oom.overSafe === true && oom.at === 1_700_000_050_000);

    // SCHED cron-runtime-fallback: a valid fault class (tz-invalid) rides through with its timestamp, alongside
    // the clamped nextRunAt + inFlightSince — the per-downpipe "my cron isn't resolving; it's on cadence" signal.
    const cr = dp0["cronResolve"] as { class: string; at: number } | undefined;
    ok("a valid cronResolve fault class rides through with its timestamp", cr?.class === "tz-invalid" && cr.at === 1_700_000_600_000);
    ok("the downpipe carries nextRunAt + inFlightSince (clamped timestamps)", dp0["nextRunAt"] === 1_700_000_600_000 && dp0["inFlightSince"] === 1_700_000_200_000);

    // B2 restorability assurance. restoreProven carries at/method/runId + a BOOLEAN `attributed` derived from
    // `by` -- the prover's verified Access EMAIL must NOT appear anywhere in the bundle (no-custody).
    const rp = dp0["restoreProven"] as { at: number; method: string; runId: string; attributed: boolean; by?: unknown };
    ok(
      "restoreProven carries at/method/runId and projects the prover email to attributed:true",
      rp.at === 1_700_000_300_000 && rp.method === "blind-test" && rp.runId === "01PROVEN" && rp.attributed === true && !("by" in rp),
    );
    ok("the prover email never reaches the bundle (no-custody)", !JSON.stringify(built.bundle).includes("operator@example.com.au"));

    // ML-45: licence.setBy is the SAME no-custody class as restoreProven.by (a verified Access e-mail) but
    // was, until now, the one section spread whole into the bundle with no projection. It must now be
    // projected the same way: setAt/tier/valid/source ride verbatim, setBy is replaced by a boolean.
    const lic = built.bundle["licence"] as { tier: string; valid: boolean; source?: string; setAt?: number; activatedByKnown?: boolean; setBy?: unknown };
    ok(
      "licence carries setAt + activatedByKnown and drops setBy (no-custody, mirrors restoreProven.attributed)",
      lic.tier === "community" && lic.valid === false && lic.source === "console" && lic.setAt === 1_700_000_500_000 && lic.activatedByKnown === true && !("setBy" in lic),
    );
    ok("the licence-activating owner's email never reaches the bundle (no-custody)", !JSON.stringify(built.bundle).includes("owner@example.com.au"));
    // deepVerify (rotating full-decrypt coverage) carries its cursor/records + lastFullPassAt recency.
    const dv = dp0["deepVerify"] as { cursor: number; records: number; lastFullPassAt: number };
    ok("deepVerify carries cursor/records/lastFullPassAt", dv.cursor === 40 && dv.records === 100 && dv.lastFullPassAt === 1_700_000_350_000);
    // recoverySamples ring is FOLDED to count + the most-recent sample (counts/ms only).
    const rs = dp0["recoverySamples"] as { count: number; last: { recordsVerified: number; durationMs: number } };
    ok("recoverySamples is folded to count + most-recent sample", rs.count === 2 && rs.last.recordsVerified === 20 && rs.last.durationMs === 1500);

    // WS-D #2 cf-config surface discovery: the present/empty/unavailable surface-id sets + the probe timestamp
    // ride into the pack so a "my CF config backup is silently missing surfaces" fault is visible. Surface ids
    // are a FIXED product vocabulary (redaction-safe, not customer data). present/empty are under the cap and
    // carry whole; `unavailable` was oversized (70) so each list's .slice(0, 64) cap is genuinely exercised --
    // the two meaningful head ids survive and the overflow tail (a total outage's worth of surfaces) is dropped.
    const cfd = dp0["cfConfigDiscovery"] as { at: number; present: string[]; empty: string[]; gated: string[]; unavailable: string[]; unavailableCount: number } | undefined;
    ok(
      "cfConfigDiscovery carries the present/empty surface-id sets and the probe timestamp",
      cfd !== undefined &&
        cfd.at === 1_700_000_900_000 &&
        cfd.present.length === 2 &&
        cfd.present[0] === "dns" &&
        cfd.present[1] === "zone-settings" &&
        cfd.empty.length === 1 &&
        cfd.empty[0] === "workers-routes",
    );
    ok(
      "cfConfigDiscovery surfaces the unavailable list and caps each array to 64 (a total outage can't bloat the pack)",
      cfd !== undefined &&
        cfd.unavailable[0] === "managed-headers" &&
        cfd.unavailable[1] === "page-rules" &&
        cfd.unavailable.length === 64 &&
        !cfd.unavailable.includes("surface-67"),
    );
    // The BENIGN gated bucket (split from unavailable): the plan/entitlement surfaces the diagnosis bot ignores.
    // Capped to 64 like the others (head kept, overflow dropped) so a fleet-wide gate can't bloat the pack.
    ok(
      "cfConfigDiscovery surfaces the gated (plan/entitlement) bucket and caps it to 64",
      cfd !== undefined &&
        cfd.gated[0] === "account-waf" &&
        cfd.gated[1] === "bot-management" &&
        cfd.gated.length === 64 &&
        !cfd.gated.includes("gated-62"),
    );
    // unavailableCount is the TRUE, UNCAPPED unavailable length (70 here) so the bot's "could not read N
    // surfaces" prose is accurate even though the array itself is capped at 64. This is the review's Q5 minor.
    ok(
      "cfConfigDiscovery reports unavailableCount as the TRUE uncapped count (70), distinct from the capped array (64)",
      cfd !== undefined && cfd.unavailableCount === 70 && cfd.unavailable.length === 64,
    );

    // The run-row spreads ran on their non-default sides: the counts were omitted (their
    // `: {}` falsy side) while error and sealVerification were kept (their truthy side).
    const row = ((built.bundle["runs"] as Record<string, Array<Record<string, unknown>>>)["dp1"] ?? [])[0]!;
    ok(
      "a run row without counts but with error/seal omits the counts and keeps error and seal",
      !("recordCount" in row) &&
        !("bytes" in row) &&
        !("durationMs" in row) &&
        row["error"] === "destination-unreachable" &&
        (row["sealVerification"] as { reason: string }).reason === "scheduled" &&
        row["status"] === "error",
    );
    // The Phase-3 diagnostic verdict fields ride the same whole-object passthrough (modes
    // tier0-only-reason-unknown + runlog-sig-stale-window): the pack must carry them onto the run row.
    ok(
      "the run-row seal verdict carries tier0Cause + attempts + recovered through to the pack",
      (row["sealVerification"] as { tier0Cause?: string; attempts?: number; recovered?: boolean }).tier0Cause === "too-large" &&
        (row["sealVerification"] as { attempts?: number }).attempts === 3 &&
        (row["sealVerification"] as { recovered?: boolean }).recovered === true,
    );
    // The failed-run correlation digest rides through to the pack row (revives the diagnostics-bot's
    // causeDigest consumer): byte-identical to the Logpush `[cause <hex>]` line, so support joins a log
    // line to this row. Stamped only on failed rows, carried by fetchRunHistory's conditional spread.
    ok("a failed run row carries causeDigest through to the pack row", row["causeDigest"] === "ab12cd34ef56");
    // The predecessor chain pointer + its honest status ride through to the pack row too, so a
    // downloaded pack lets an auditor reconstruct the chain offline (not only via a live admin read).
    ok(
      "the run-row predecessor chain (prevRunId + honest status) rides through to the pack row",
      row["prevRunId"] === "00PRIOR" && row["prevRunIdStatus"] === "pruned",
    );
    // dp2's orphan history-only ring (no matching /downpipes entry) is still processed, and its HOSTILE
    // out-of-vocab prevRunIdStatus is dropped by the closed-vocabulary gate while the id (redaction-safe,
    // not vocabulary-gated, same class as runId itself) still rides through.
    const dp2Row = ((built.bundle["runs"] as Record<string, Array<Record<string, unknown>>>)["dp2"] ?? [])[0]!;
    ok(
      "an orphan history ring is still projected, and a hostile prevRunIdStatus is dropped while the id rides",
      dp2Row["prevRunId"] === "hostile-not-a-real-id" && !("prevRunIdStatus" in dp2Row),
    );

    // A /notify/history object with no entries key falls back to an empty notify list.
    ok("a notify-history reply with no entries key yields an empty notify list", Array.isArray(built.bundle["notify"]) && (built.bundle["notify"] as unknown[]).length === 0);
  }

  // A scheduler double that THROWS on /notify/history so buildSupportBundle's catch runs
  // and the bundle simply lacks notify history (honest absence, no fabricated value).
  function notifyThrowsScheduler(): DurableObjectStub {
    return {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        switch (url.pathname) {
          case "/downpipes":
            return new Response(JSON.stringify([]));
          case "/history":
            return new Response(JSON.stringify({ byDownpipe: {} }));
          case "/notify/history":
            throw new Error("notify store unavailable");
          // A failing canary-transitions / cooldowns fetch must degrade to honest absence (the pack simply
          // omits `canary` / `alertCooldowns`), never a fabricated value or a thrown bundle build.
          case "/canary/transitions":
            throw new Error("canary store unavailable");
          case "/notify/cooldowns":
            throw new Error("cooldown store unavailable");
          case "/tick-info":
            return new Response(JSON.stringify({ lastTickAt: Date.now() }));
          default:
            return new Response(JSON.stringify({}));
        }
      },
    } as unknown as DurableObjectStub;
  }

  {
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const bundle = await signedSupportBundle(env, notifyThrowsScheduler());
    ok("a failing notify-history fetch leaves notify empty (honest absence)", Array.isArray(bundle.bundle["notify"]) && (bundle.bundle["notify"] as unknown[]).length === 0);
    ok("a failing canary-transitions fetch omits `canary` (honest absence, no fabricated value)", bundle.bundle["canary"] === undefined);
    ok("a failing cooldowns fetch omits `alertCooldowns` (honest absence)", bundle.bundle["alertCooldowns"] === undefined);
    // INFRA bundle-degrades-silently-on-do-blip: the section that THREW is marked "error" (a fault), NOT
    // "empty" (honest absence). This is the whole point of the vector — a mid-outage read is self-describing,
    // and the bundle still BUILDS (the throw no longer crashes the whole bundle as the unguarded fetch once did).
    const tsecs = bundle.bundle["sections"] as Record<string, string>;
    ok("a section whose fetch THREW is marked error (distinct from an honestly-empty section)", tsecs["notify"] === "error");
    ok("the bundle still builds and signs despite one section faulting (no whole-bundle crash)", bundle.signature.length > 0 && (bundle.bundle["kind"] as string) === "downpipe-support-bundle");
  }

  // A scheduler double that THROWS on /downpipes so computeEstateRollup itself resolves to null (its own
  // internal catch): the volumes section() wrapper must RE-THROW that null so sections.volumes reads
  // "error" (a genuine compute fault), never "empty" (which would wrongly read as an honestly-quiet
  // fleet with zero downpipes). This proves the section()-wrapper re-throw trick actually fires, the one
  // branch the estate-rollup unit tests (test/validate-estate.ts) cannot exercise on their own since they
  // call computeEstateRollup directly, never through buildSupportBundle's section() wrapper.
  function estateThrowsScheduler(): DurableObjectStub {
    return {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/downpipes") throw new Error("scheduler unavailable");
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
  }
  {
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const bundle = await signedSupportBundle(env, estateThrowsScheduler());
    ok("a /downpipes fault makes the estate rollup unavailable: volumes rides as null, not a fabricated value", bundle.bundle["volumes"] === null);
    const esecs = bundle.bundle["sections"] as Record<string, string>;
    ok("volumes reads 'error' on a genuine compute fault (never 'empty', which would misread as a quiet zero-downpipe fleet)", esecs["volumes"] === "error");
    ok("the SAME /downpipes fault also marks the downpipes section itself error (both readers of the same faulting fetch agree)", esecs["downpipes"] === "error");
    ok("the bundle still builds and signs despite the estate rollup faulting (no whole-bundle crash)", bundle.signature.length > 0 && (bundle.bundle["kind"] as string) === "downpipe-support-bundle");
  }

  // The auth + notify posture gatherers must let a fault PROPAGATE to section() rather than swallowing it in a
  // try/catch that returns {} on ANY fault: a DO-unreachable read reaching section() as a value would be
  // recorded "empty" (honest absence) -- byte-identical to a genuinely quiet aggregate. On the two highest-
  // frequency ticket classes ("SSO is broken", "alerts stopped") that would mean a mid-outage snapshot reads
  // clean. The gatherers use the same bare-block pattern fetchSsoFailures and fetchNotifyHistory use, so the
  // section reads "error". This drives buildSupportBundle with a stub that throws on each endpoint and
  // asserts the section vector reads "error", never "empty".
  console.log("\nauth/notify gather faults read 'error', not a clean 'empty':");
  {
    function endpointThrowsScheduler(paths: Set<string>): DurableObjectStub {
      return {
        async fetch(input: RequestInfo | URL): Promise<Response> {
          const url = new URL(input instanceof Request ? input.url : String(input));
          // Match on pathname+search so a scoped endpoint (e.g. /ingest-credential?scope=audit-feed) is
          // distinguishable from the same path with a different scope.
          if (paths.has(url.pathname + url.search) || paths.has(url.pathname)) throw new Error(`store unavailable: ${url.pathname}`);
          if (url.pathname === "/downpipes") return new Response(JSON.stringify([]));
          return new Response(JSON.stringify({}));
        },
      } as unknown as DurableObjectStub;
    }
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const cases: Array<[string, string]> = [
      ["/sso-failures-by-kind", "ssoFailuresByKind"],
      ["/auth-signals", "authSignals"],
      ["/auth-posture", "authPosture"],
      ["/notify/health", "notifyHealth"],
      ["/notify/cooldowns", "alertCooldowns"],
      // audit / config / seal gatherers use the same bare-block pattern.
      ["/audit/verify", "audit"],
      ["/ingest-credential?scope=audit-feed", "auditFeed"],
      ["/control-plane/export", "wrapKeyHealth"],
      ["/beacon-state", "beacon"],
      ["/reconcile-inventory", "reconcile"],
      ["/seal-faults", "sealFaults"],
      ["/canary/transitions", "canary"],
    ];
    for (const [path, section] of cases) {
      const b = await signedSupportBundle(env, endpointThrowsScheduler(new Set([path])));
      const secs = b.bundle["sections"] as Record<string, string>;
      ok(`a failing ${path} fetch marks '${section}' error (not empty, which would misread as an honestly-quiet aggregate)`, secs[section] === "error");
    }
    // And the converse: a genuinely-quiet aggregate (DO answers {} everywhere) still reads "empty", not "error",
    // so the fix did not turn honest absence into a false fault.
    const quiet = await signedSupportBundle(env, endpointThrowsScheduler(new Set()));
    const qsecs = quiet.bundle["sections"] as Record<string, string>;
    ok("a genuinely-empty authSignals still reads 'empty' (honest absence preserved, not a false 'error')", qsecs["authSignals"] === "empty");
    ok("the bundle still builds and signs when an auth/notify section faults (no whole-bundle crash)", quiet.signature.length > 0);

    // destResolution is a MIXED-source section (env-derived rate knobs always present), so a /destinations
    // fault cannot flip the section() status; instead the block carries an explicit destinationsUnavailable
    // flag so "could not read the destinations" is distinct from "no destinations configured".
    const destFault = await signedSupportBundle(env, endpointThrowsScheduler(new Set(["/destinations"])));
    const dr = destFault.bundle["destResolution"] as { destinationsUnavailable?: unknown; effectiveRatePerSec?: unknown } | undefined;
    ok("a /destinations fault flags destResolution.destinationsUnavailable (not a silent empty list)", dr?.destinationsUnavailable === true);
    ok("a /destinations fault keeps the env-derived rate knob in destResolution (partial data preserved)", dr !== undefined && dr.effectiveRatePerSec !== undefined);

    // The OFF-ROSTER blocks (called outside section(), so they cannot use the sections vector) each keep their
    // own catch but flag a read fault instead of returning a silent {} that is omitted from the pack
    // (byte-identical to honest absence). A fault makes the block PRESENT with an *Unavailable marker.
    const offRoster: Array<[string, string, string]> = [
      ["/drive-budget-yield", "driveBudgetYields", "driveBudgetUnavailable"],
      ["/licence-activation-refusal", "licenceActivationRefusals", "licenceRefusalsUnavailable"],
      ["/expiry", "licenceExpiryTracker", "licenceExpiryUnavailable"],
      ["/roster-hygiene", "rosterIntegrity", "rosterIntegrityUnavailable"],
    ];
    for (const [path, block, marker] of offRoster) {
      const b = await signedSupportBundle(env, endpointThrowsScheduler(new Set([path])));
      const blk = b.bundle[block] as Record<string, unknown> | undefined;
      ok(`a failing ${path} flags ${block}.${marker} (a fault is visible, not omitted as honest absence)`, blk?.[marker] === true);
    }
    // And the converse: with every off-roster read answering {} the block stays OMITTED (honest absence), not a
    // false Unavailable marker.
    ok("an off-roster block with a genuinely-empty read stays omitted (no false Unavailable marker)", quiet.bundle["driveBudgetYields"] === undefined && quiet.bundle["rosterIntegrity"] === undefined);

    // configIntegrity is a MULTI-PROBE off-roster block (three independent sub-reads). A single sub-probe fault
    // now lists that probe in unavailableProbes rather than being omitted with the clean ones.
    const ciFault = await signedSupportBundle(env, endpointThrowsScheduler(new Set(["/config-history-health"])));
    const ci = ciFault.bundle["configIntegrity"] as { unavailableProbes?: unknown } | undefined;
    ok("a /config-history-health fault lists 'config-history' in configIntegrity.unavailableProbes", Array.isArray(ci?.unavailableProbes) && (ci!.unavailableProbes as string[]).includes("config-history"));
    ok("configIntegrity omits unavailableProbes when every sub-probe reads clean", (quiet.bundle["configIntegrity"] as { unavailableProbes?: unknown } | undefined)?.unavailableProbes === undefined);

    // sourcesDetached faults if the roster read or the live-binding enumeration throws (its endpoint is the
    // shared /downpipes, so other sections also error here; we assert only its own marker).
    const sdFault = await signedSupportBundle(env, endpointThrowsScheduler(new Set(["/downpipes"])));
    ok("a /downpipes fault flags sourcesDetached.sourcesDetachedUnavailable (not a silent 'nothing detached')", (sdFault.bundle["sourcesDetached"] as { sourcesDetachedUnavailable?: unknown } | undefined)?.sourcesDetachedUnavailable === true);
  }

  console.log("\nthe storage-fault projection edges (omit + redaction):");
  {
    // A double serving ONLY /scheduler-signals with a chosen storageFaults shape (empty everywhere else), to
    // exercise the projection's omit-when-zero + drop-out-of-vocab-lastKind branches.
    const signalsOnly = (storageFaults: unknown): DurableObjectStub =>
      ({
        async fetch(input: RequestInfo | URL): Promise<Response> {
          const url = new URL(input instanceof Request ? input.url : String(input));
          if (url.pathname === "/scheduler-signals") return new Response(JSON.stringify({ ticks: [], dueIndex: {}, runlog: { counter: 0, maxHistoryIndex: 0 }, listCaps: { pageSize: 1000, maxPages: 1000, historyRings: 0 }, storageFaults }));
          if (url.pathname === "/downpipes") return new Response(JSON.stringify([]));
          if (url.pathname === "/history") return new Response(JSON.stringify({ byDownpipe: {} }));
          return new Response(JSON.stringify({}));
        },
      }) as unknown as DurableObjectStub;
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;

    // total 0: a never-faulted counter is OMITTED entirely (a healthy engine carries no storageFaults key).
    const zero = (await signedSupportBundle(env, signalsOnly({ total: 0, valueTooLarge: 0, putFailed: 0, lastAt: 0, lastKind: null }))).bundle["scheduler"] as Record<string, unknown>;
    ok("storageFaults with total 0 is omitted from the pack (a healthy engine carries no fault counter)", !("storageFaults" in zero));

    // total > 0 with an out-of-vocab lastKind: the counter rides but the hostile lastKind is DROPPED (redaction).
    const hostile = (await signedSupportBundle(env, signalsOnly({ total: 4, valueTooLarge: 1, putFailed: 3, lastAt: 123, lastKind: "frobnicate" }))).bundle["scheduler"] as { storageFaults?: { total: number; lastKind?: string } };
    ok("storageFaults with total>0 rides, but an out-of-vocab lastKind is dropped (defence-in-depth redaction)", hostile.storageFaults?.total === 4 && !("lastKind" in (hostile.storageFaults ?? {})));
  }

  console.log("\nthe sealed bundle (no vendor key):");
  {
    // No VENDOR_SUPPORT_PUBLIC: sealedSupportBundle returns the SIGNED form, not sealed.
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const out = (await sealedSupportBundle(env, sparseScheduler())) as { kind: string; signature: string };
    ok("with no vendor key the sealed call returns the signed form", out.kind === "downpipe-support-bundle-signed" && out.signature.length > 0);
  }

  console.log("\ngrant and credential edge cases:");
  {
    // redactGrant on a null grant returns null (the absent-grant branch).
    ok("redactGrant returns null for an absent grant", redactGrant(null) === null);

    // checkIngestCredential rejects a stored hash that is the wrong length or non-hex,
    // even when the clientId and secret prefix are otherwise well formed.
    const minted = await mintIngestCredential("diagnostics", "owner@example.com.au", undefined);
    const shortHash: IngestGrant = { ...minted.grant, secretSha384: "abcd" };
    ok("a stored hash of the wrong length is refused", !(await checkIngestCredential(`${minted.clientId}.${minted.secret}`, shortHash)));
    const nonHexHash: IngestGrant = { ...minted.grant, secretSha384: "z".repeat(96) };
    ok("a non-hex stored hash is refused", !(await checkIngestCredential(`${minted.clientId}.${minted.secret}`, nonHexHash)));
    // A bearer with a leading dot has dot index 0, which is rejected (dot <= 0).
    ok("a bearer beginning with a dot is refused", !(await checkIngestCredential(".secretvalue", minted.grant)));
    // A clientId-matching bearer whose secret lacks the dps_ prefix is refused.
    ok("a secret without the dps_ prefix is refused", !(await checkIngestCredential(`${minted.clientId}.xyz_${b64urlEncode(rand(24))}`, minted.grant)));

    // A floor-clamped TTL: a tiny value is raised to the 60-second minimum.
    const tiny = await mintIngestCredential("diagnostics", null, 1);
    const tinyTtl = Date.parse(tiny.grant.expiresAt) - Date.now();
    ok("a sub-minimum TTL is floored to 60 seconds", tinyTtl > 55_000 && tinyTtl <= 61_000);
  }

  console.log("\nthe pull routes (rejection and bound edges):");
  {
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env;
    const sched = schedulerDouble();

    // An unknown path is a 404 (scope resolves to null).
    const unknown = await handleSupportPull(new Request("https://e/support/other"), env, sched.stub);
    ok("an unknown support path is a 404", unknown.status === 404 && (await unknown.text()) === "not found");
    // A non-GET method on a known path is a 404 (the method guard).
    const posted = await handleSupportPull(new Request("https://e/support/diagnostics", { method: "POST" }), env, sched.stub);
    ok("a non-GET method on a known path is a 404", posted.status === 404);

    // The grant lookup THROWS: the route returns 503 unavailable.
    const throwingStub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/ingest-credential") throw new Error("DO unavailable");
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const unavailable = await handleSupportPull(new Request("https://e/support/audit-feed", { headers: { Authorization: "Bearer dpc_x.dps_y" } }), env, throwingStub);
    ok("an unavailable grant store is a 503", unavailable.status === 503 && (await unavailable.text()) === "unavailable");

    // The audit feed CURSOR is strict (finding F6): a present-but-non-numeric afterSeq is a 400, not a
    // silent replay from 0 (which would hide a client bug re-sending a corrupt cursor). The LIMIT stays
    // leniently clamped (a page-size hint), so a garbage limit alone still falls back to the default.
    const minted = await mintIngestCredential("audit-feed", "owner@example.com.au", undefined);
    sched.grants["audit-feed"] = minted.grant;
    const badCursor = await handleSupportPull(new Request("https://e/support/audit-feed?afterSeq=notanumber&limit=notanumber", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    ok("a non-numeric afterSeq is a 400 (strict cursor, finding F6)", badCursor.status === 400);
    const goodCursorGarbageLimit = await handleSupportPull(new Request("https://e/support/audit-feed?limit=notanumber", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    ok("an absent afterSeq + garbage limit falls back to the defaults (afterSeq 0, limit 500)", goodCursorGarbageLimit.status === 200);
    const gbody = (await goodCursorGarbageLimit.json()) as { afterSeq: number; count: number; events: Array<{ seq: number }> };
    ok("absent afterSeq defaults to 0 and a non-numeric limit defaults to 500", gbody.afterSeq === 0 && gbody.count === 25 && gbody.events[0]!.seq === 1);

    // A zero limit is falsy, so `Number("0") || 500` falls back to the 500 default
    // before any clamp runs: the feed serves the full 25-event set, not a single row.
    const zeroLimit = await handleSupportPull(new Request("https://e/support/audit-feed?afterSeq=0&limit=0", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    const zbody = (await zeroLimit.json()) as { count: number };
    ok("a falsy zero limit falls back to the 500 default (all 25 events)", zbody.count === 25);

    // A limit above the 1000 ceiling is clamped down by Math.min(...,1000).
    const overLimit = await handleSupportPull(new Request("https://e/support/audit-feed?afterSeq=0&limit=5000", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    const obody = (await overLimit.json()) as { count: number };
    ok("a limit above 1000 is clamped down to the ceiling (here all 25 events fit)", obody.count === 25);

    // An afterSeq beyond the head returns zero events; nextAfterSeq then echoes afterSeq.
    const past = await handleSupportPull(new Request("https://e/support/audit-feed?afterSeq=9999&limit=10", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    const pbody = (await past.json()) as { count: number; afterSeq: number; nextAfterSeq: number };
    ok("an exhausted feed returns no events and echoes afterSeq as nextAfterSeq", pbody.count === 0 && pbody.nextAfterSeq === 9999 && pbody.afterSeq === 9999);

    // No afterSeq and no limit query params at all: searchParams.get returns null for
    // each, so the `?? "0"` and `?? "500"` string fallbacks supply the parse inputs.
    // The result must be afterSeq 0 with the full 25-event default page.
    const noParams = await handleSupportPull(new Request("https://e/support/audit-feed", { headers: { Authorization: `Bearer ${minted.clientId}.${minted.secret}` } }), env, sched.stub);
    const npbody = (await noParams.json()) as { afterSeq: number; count: number; events: Array<{ seq: number }> };
    ok("absent afterSeq/limit params use the ?? string fallbacks (afterSeq 0, default page)", noParams.status === 200 && npbody.afterSeq === 0 && npbody.count === 25 && npbody.events[0]!.seq === 1);
  }

  console.log("\nthe keys health block (P3, security-sensitive: public fingerprints + KCV only):");
  {
    const sched = schedulerDouble();
    // Valid 1600-byte hybrid recipient publics (x25519(32) || ML-KEM-1024 ek(1568)) for break-glass + vendor, and a
    // valid 32-byte AES-256 wrap key. These are the shapes loadRecipientPublic / loadConfigWrapKey accept.
    const bgPub = b64urlEncode(concat(x25519.keygen().publicKey, mlkemKeygen(rand(64)).encapKey));
    const vsPub = b64urlEncode(concat(x25519.keygen().publicKey, mlkemKeygen(rand(64)).encapKey));
    const wrapKey = b64urlEncode(rand(32));
    const env = { SIGNER_PRIVATE: signerB64, BREAK_GLASS_PUBLIC: bgPub, CONFIG_WRAP_KEY: wrapKey, VENDOR_SUPPORT_PUBLIC: vsPub } as unknown as Env;
    const built = await signedSupportBundle(env, sched.stub);
    const keys = built.bundle["keys"] as {
      breakGlass: { configured: boolean; recipientFingerprint?: string; malformed?: boolean };
      configWrapKey: { configured: boolean; keyCheckValue?: string; malformed?: boolean };
      vendorSupportPublic: { configured: boolean; willSeal: boolean; recipientFingerprint?: string; malformed?: boolean };
    };
    ok("keys.breakGlass carries a dpr1 fingerprint of PUBLIC break-glass material (data-loss keystone cross-check)", keys.breakGlass.configured === true && typeof keys.breakGlass.recipientFingerprint === "string" && keys.breakGlass.recipientFingerprint!.startsWith("dpr1:") && !("malformed" in keys.breakGlass));
    ok("keys.configWrapKey carries a dpk1 KCV that commits to WHICH key without revealing it", keys.configWrapKey.configured === true && typeof keys.configWrapKey.keyCheckValue === "string" && keys.configWrapKey.keyCheckValue!.startsWith("dpk1:"));
    ok("keys.vendorSupportPublic reports willSeal:true + a fingerprint when the vendor key parses", keys.vendorSupportPublic.configured === true && keys.vendorSupportPublic.willSeal === true && (keys.vendorSupportPublic.recipientFingerprint ?? "").startsWith("dpr1:"));
    // The KCV is HMAC of a FIXED label under the key, so it is STABLE across builds for the same key — the property
    // support uses to cross-check the recovery sheet — and is NOT the key bytes.
    const built2 = await signedSupportBundle(env, schedulerDouble().stub);
    const keys2 = built2.bundle["keys"] as { configWrapKey: { keyCheckValue?: string } };
    ok("keys.configWrapKey KCV is stable for the same key (recovery-sheet cross-check)", keys.configWrapKey.keyCheckValue === keys2.configWrapKey.keyCheckValue);
    ok("keys never carries raw key material anywhere (only dpr1 fingerprints + the dpk1 KCV)", !JSON.stringify(built.bundle).includes(bgPub) && !JSON.stringify(built.bundle).includes(vsPub) && !JSON.stringify(built.bundle).includes(wrapKey));
    // DERIVATION-IDENTITY PROOF (keys security review, item 5a): the pack's break-glass
    // fingerprint must equal the fingerprint a REAL archive capsule wrap gets when sealing to the SAME env
    // key through the REAL seal path (loadRecipients -> sealToRecipients). This pins the two code paths to
    // one derivation forever: a future refactor that changes either parse or fingerprint construction on one
    // side breaks here, so the pack can never print a fingerprint that disagrees with what archives actually
    // wrap to -- exactly the false-panic/false-match failure this design was meant to rule out.
    const sealWraps = await sealToRecipients(rand(32), loadRecipients(bgPub).map((r) => r.pub), utf8("derivation-identity-proof"), () => rand(16));
    ok("keys.breakGlass.recipientFingerprint is BYTE-IDENTICAL to a real seal-path capsule wrap fingerprint for the same env key", sealWraps.length === 1 && sealWraps[0]!.fingerprint === keys.breakGlass.recipientFingerprint);

    // Present-but-malformed values: parse fails -> `malformed:true` and the fingerprint/KCV/willSeal are dropped.
    // Short valid-b64url values reliably trip the length check (want 1600 / 32 bytes) regardless of decoder strictness.
    const badEnv = { SIGNER_PRIVATE: signerB64, BREAK_GLASS_PUBLIC: b64urlEncode(rand(10)), CONFIG_WRAP_KEY: b64urlEncode(rand(10)), VENDOR_SUPPORT_PUBLIC: b64urlEncode(rand(10)) } as unknown as Env;
    const badKeys = (await signedSupportBundle(badEnv, schedulerDouble().stub)).bundle["keys"] as {
      breakGlass: { configured: boolean; malformed?: boolean; recipientFingerprint?: string };
      configWrapKey: { configured: boolean; malformed?: boolean; keyCheckValue?: string };
      vendorSupportPublic: { configured: boolean; malformed?: boolean; willSeal: boolean };
    };
    ok("keys.breakGlass flags a malformed break-glass public and drops the fingerprint", badKeys.breakGlass.configured === true && badKeys.breakGlass.malformed === true && !("recipientFingerprint" in badKeys.breakGlass));
    ok("keys.configWrapKey flags a malformed wrap key and drops the KCV", badKeys.configWrapKey.configured === true && badKeys.configWrapKey.malformed === true && !("keyCheckValue" in badKeys.configWrapKey));
    ok("keys.vendorSupportPublic flags a malformed vendor key (malformed + willSeal:false -> bundle ships signed-only)", badKeys.vendorSupportPublic.configured === true && badKeys.vendorSupportPublic.malformed === true && badKeys.vendorSupportPublic.willSeal === false);

    // A present-but-whitespace wrap key parses to undefined (loadConfigWrapKey trims): configured:true, no KCV, not malformed.
    const wsKeys = (await signedSupportBundle({ SIGNER_PRIVATE: signerB64, CONFIG_WRAP_KEY: "   " } as unknown as Env, schedulerDouble().stub)).bundle["keys"] as { configWrapKey: { configured: boolean; malformed?: boolean; keyCheckValue?: string } };
    ok("keys.configWrapKey treats a whitespace-only key as configured-but-empty (no KCV, not malformed)", wsKeys.configWrapKey.configured === true && !("keyCheckValue" in wsKeys.configWrapKey) && !("malformed" in wsKeys.configWrapKey));

    // Best-effort: a failing /sso-failures-by-kind and /auth-signals fetch leaves those blocks ABSENT (honest absence).
    const base = schedulerDouble();
    const throwStub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/sso-failures-by-kind" || u.pathname === "/auth-signals" || u.pathname === "/auth-posture") throw new Error("do unavailable");
        return base.stub.fetch(input, init);
      },
    } as unknown as DurableObjectStub;
    const tb = (await signedSupportBundle({ SIGNER_PRIVATE: signerB64 } as unknown as Env, throwStub)).bundle;
    ok("a failing /sso-failures-by-kind + /auth-signals + /auth-posture fetch leaves those blocks absent (honest absence)", !("ssoFailuresByKind" in tb) && !("authSignals" in tb) && !("authPosture" in tb));

    // authPosture edge shapes: a session-key-absent posture reports present:false + drops ageMs, a non-numeric
    // missing-count is dropped, a non-boolean adequateLength is dropped, and an adminCredentialPaths whose members
    // are all non-numeric drops the block entirely (defence-in-depth on the projection).
    const base2 = schedulerDouble();
    const posStub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/auth-posture") return Promise.resolve(new Response(JSON.stringify({ sessionSigningKey: { present: false, adequateLength: "yes" }, doPlaintextSecretsMissing: "not-a-number", adminCredentialPaths: { passkeyCredentials: "x", enabledIdpConnections: null } })));
        return base2.stub.fetch(input, init);
      },
    } as unknown as DurableObjectStub;
    const posAp = (await signedSupportBundle({ SIGNER_PRIVATE: signerB64 } as unknown as Env, posStub)).bundle["authPosture"] as { sessionSigningKey?: { present: boolean; ageMs?: number; adequateLength?: boolean }; doPlaintextSecretsMissing?: number; adminCredentialPaths?: unknown };
    ok("authPosture: an absent session key reports present:false, drops ageMs, and drops a non-numeric missing count", posAp.sessionSigningKey?.present === false && !("ageMs" in (posAp.sessionSigningKey ?? {})) && !("doPlaintextSecretsMissing" in posAp));
    ok("authPosture: a non-boolean adequateLength is dropped and an all-non-numeric adminCredentialPaths block is omitted", !("adequateLength" in (posAp.sessionSigningKey ?? {})) && !("adminCredentialPaths" in posAp));
  }

  console.log("the round-4 fault ledgers are in the ROSTER, and a bundle built against a silent DO says so:");
  {
    // The campaign's hardest-won lesson: a gap is not closed until its evidence is IN THE BUNDLE. Twice, a
    // recorder was built, fired on the fault path, wrote a durable record -- and nothing read it. The roster is
    // the structural defence: buildSupportBundle stamps any roster member MISSING from the produced map as
    // "error", and this suite pins the produced keys to the roster, so a gatherer that is added to the roster
    // and never called (or called without a section() wrapper) fails the gate rather than silently carrying
    // nothing. The DEEP end-to-end + redaction proof for these ten lives in validate-support-round4.ts.
    const round4 = ["unwrapFaults", "bindingAlarms", "updateFaults", "adminRefusals", "integrityFaults", "dispatchFaults", "cronHealth", "destProbeFaults", "destBuildHealth", "costSizing"];
    const sched = schedulerDouble();
    const bundle = (await signedSupportBundle({ SIGNER_PRIVATE: signerB64 } as unknown as Env, sched.stub)).bundle;
    const sections = bundle.sections as Record<string, string>;
    for (const name of round4) {
      ok(`${name} is in the roster AND was actually gathered (not recorded into a void)`, (SUPPORT_SECTION_NAMES as readonly string[]).includes(name) && name in sections);
    }
    // A DO that answers every round-4 route with an empty record must produce an honestly EMPTY section and
    // OMIT the field entirely: the healthy fleet's steady state here is silence, not a wall of zeroes.
    ok("a clean fleet reports the round-4 sections \"empty\" and omits every field", round4.every((n) => sections[n] === "empty" && !(n in bundle)));
    // And the pack must still name the routes it read: a section that was never fetched is a silent hole.
    ok("every round-4 DO route was actually fetched during the build", ["/unwrap-faults", "/binding-alarms", "/update-faults", "/admin-refusals", "/integrity-faults", "/dispatch-faults", "/cron-health", "/dest-probe-faults", "/dest-build-health", "/cost-sizing"].every((r) => sched.calls.includes(`GET ${r}`)));
  }

  console.log(failures === 0 ? "\nSUPPORTABILITY SURFACE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
