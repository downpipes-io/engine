// The SIEM push drain: on each cron tick, if a push destination is
// configured AND enabled, read audit events since the last-pushed cursor (the same DO-side pushdown the
// pull feed uses), shape them per the configured format, and POST through the bespoke egress-secure sender
// (notify/siem-push-sender.ts) with the one configured auth header. The cursor advances ONLY on a delivery
// the sink ACCEPTED; on any other outcome it holds so the SAME events retry next tick (at-least-once -- every
// audit event carries a stable seq + hash a SIEM dedups on, so a re-delivered batch is safe).
//
// WHAT "ACCEPTED" IS, AND WHAT IT IS NOT. For the http sink acceptance is the sink's own answer to the POST,
// and for splunk-hec that answer lives in the BODY, not the status (see HecBodyClass in the sender). It is
// acceptance, not indexing: a sink that takes the request and then drops the events downstream (a deleted or
// wrong index, a routing transform that discards them, a blocked indexer queue) has still accepted, and this
// were indexed needs the sink's own acknowledgement protocol (for HEC, a request channel plus an ack poll),
// which is state that has to survive the tick that sent the batch, and is deliberately NOT half-built here:
// an ack path that advanced the cursor anyway would be worse than this honest limit. OPT-IN: no destination
// configured, or the operator has it disabled, is a silent no-op (no phone-home unless wired), mirroring
// runBeaconEmitPass's opt-in gate. The outbound fetch lives here (the Worker/pass layer), never the DO.

import type { AuditEvent } from "../admin/audit.ts";
import { loadConfigWrapKey, PUSH_S3_SECRET_AAD, PUSH_SECRET_AAD, resolveConfigSecret } from "../admin/config-secret.ts";
// Imported from the leaf router-helpers.ts, NOT the router.ts hub: router-push.ts (an admin spoke router.ts
// dispatches to) imports fetchPushConfig from this module, so importing schedulerStub/doURL from router.ts
// here would create admin/router-push.ts -> cron/siem-push-pass.ts -> admin/router.ts -> admin/router-push.ts,
// a genuine cycle. router-helpers.ts is the true leaf both router.ts and this module depend on.
import { doURL, type schedulerStub } from "../admin/router-helpers.ts";
import { utf8 } from "../crypto/bytes.ts";
import { type DestDownReason, destDownReason } from "../dest/classify.ts";
import type { DestFaultSnapshot } from "../dest/fault-log.ts";
import { type Addressing, S3Destination } from "../dest/s3.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { deliverSiemPush, type SiemPushSendResult } from "../notify/siem-push-sender.ts";
import { deliverSiemSyslog, type SiemSyslogSendResult } from "../notify/siem-syslog-sender.ts";
import type { PushDestinationRecord, PushFormat, PushSink } from "../sched/scheduler-do-base.ts";
import { causeDigest } from "../seal/slice.ts";
import { assertSiemBatchCapSound, notePushTrailWriteFailure, noteSiemShapingFallback } from "./cron-fault-ledger.ts";
import { objectExtensionForFormat, type PushCursorMeta, SIEM_PUSH_BATCH_CAP, shapeForFormat, shapeGelf } from "./siem-push-shape.ts";

// ResolvedPushConfig is the push destination with its auth secret(s) RESOLVED to plaintext (at the moment of
// use only; never persisted or logged). gen is the config's generation id (the straggler guard): the drain
// carries it in the outcome it posts back so the DO can drop an outcome for a since-cleared/replaced config.
// sink/authInUrl/s3/syslog carry the delivery-mechanism fields (the s3 secretAccessKey is resolved from its
// OWN PUSH_S3_SECRET_AAD envelope, independent of the http auth header secret).
export interface ResolvedPushConfig {
  endpoint: string;
  format: PushFormat;
  authHeaderName: string;
  authHeaderValue: string;
  enabled: boolean;
  gen: string;
  sink: PushSink;
  authInUrl: boolean;
  s3?: ResolvedS3Target;
  syslog?: { host: string; port: number };
}

// ResolvedS3Target is the S3-drop sink's destination with its secretAccessKey resolved to plaintext, ready to
// build an S3Destination. prefix is defaulted here so the drain never has to.
export interface ResolvedS3Target {
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  addressing?: Addressing;
  storageClass?: string;
  prefix: string;
}

// PushDeliveryResult is the sink-agnostic outcome the drain records + the test-send reports: ok, an optional
// HTTP status (http sink only), and an optional coarse reason on failure (a DeliveryFailCode string, or an
// s3/syslog reason). It NEVER carries a body, a url, or a secret.
export interface PushDeliveryResult {
  ok: boolean;
  status?: number;
  reason?: string;
  // causeDigest (G164): the 12-hex one-way digest of the RAW fault behind `reason`, the SAME construction the
  // failed run rows use. The coarse reason tells support the CLASS of fault; this tells them WHICH ONE, and it
  // is byte-identical to the `[cause <hex>]` the engine's own log line carries -- so a customer's Workers Logs
  // line and the pack's trail row can be proven to be the same failure. Only set where a RAW throw existed.
  causeDigest?: string;
}

const DEFAULT_S3_PREFIX = "downpipes-audit";

// PUSH_CONFIG_UNREADABLE_PREFIX is the ONE message prefix fetchPushConfig throws when the DO round-trip
// itself failed (as opposed to the secret unwrap failing underneath it). classifyPushConfigFault matches on
// this engine-owned literal ONLY, to pick a closed code; the message itself is never recorded anywhere.
const PUSH_CONFIG_UNREADABLE_PREFIX = "push destination configuration unreadable";

// PUSH_PASS_FAIL_CODES is the CLOSED vocabulary of PASS-LEVEL failure reasons the SIEM/OTLP push drains
// record on the DO delivery trail (support-pack G134/G247). Before these existed, EVERY pre-delivery fault
// (a rotated/malformed CONFIG_WRAP_KEY, an unreadable DO, an unreadable cursor or audit export, an
// unreadable metrics snapshot) took an early `return false` that wrote NOTHING to the trail: the customer's
// "our SIEM/metrics push silently stopped" ticket arrived with an empty trail, indistinguishable from a
// drain that was never enabled. Each member is a closed code, never a message, status line, endpoint or
// secret; the coarsening happens HERE, at the recording site, so the pack's push sections carry a class the
// bot can reason over. "shape-or-deliver-fault" pre-dates this list and is kept as its member.
export const PUSH_PASS_FAIL_CODES = [
  "wrap-key-invalid", // CONFIG_WRAP_KEY is present but malformed: the drain cannot open its own sealed auth secret
  "config-unreadable", // the scheduler DO did not serve the push destination record this tick
  "secret-unresolvable", // the record was readable but its sealed auth secret would not unwrap (a rotated wrap key)
  "cursor-unreadable", // GET /push (the last-pushed cursor) faulted: SIEM drain only
  "export-unreadable", // GET /audit/export faulted: SIEM drain only
  "snapshot-unreadable", // GET /otlp-metrics-snapshot faulted: OTLP drain only
  "shape-or-deliver-fault", // a contract-violating throw out of the shaper/sender tail
] as const;
export type PushPassFailCode = (typeof PUSH_PASS_FAIL_CODES)[number];

// PUSH_SINK_FAIL_CODES is the closed set of sink-level reasons deliverResolvedPush itself produces (the
// remaining trail reasons come from the senders' own closed DeliveryFailCode vocabulary). Exported so the
// pack projection and the validator can pin the trail's `reason` to a closed union rather than free text.
//
// G164 (push-failure-detail-below-triage-threshold): the S3-drop sink used to record ONE fixed string,
// "s3-put-failed", for every possible cause -- so "our SIEM S3-drop retries forever" reached support with no
// way to tell the customer whether it is THEIR bucket policy, THEIR expired STS session, an Object-Lock
// refusal or OUR signing. The single string is now SPLIT into the same closed class set the destination
// probes already use (dest/classify.ts DEST_DOWN_REASONS + the fault log's closed S3 <Code> allow-list), so
// the row names an operator action. Still a closed enum: the S3 error body is never carried.
export const PUSH_S3_FAIL_CODES = [
  "s3-auth-denied", // a broken/wrong credential or a bucket/IAM policy denial (InvalidAccessKeyId, SignatureDoesNotMatch, AccessDenied): THEIR policy or OUR key, and the S3 code says which
  "s3-expired-credential", // a lapsed STS session (ExpiredToken / TokenRefreshRequired / InvalidToken): the credential was valid and aged out
  "s3-no-such-bucket", // the target bucket does not exist / the name is invalid (a typo, or a bucket deleted under a live drain)
  "s3-worm-denied", // an Object-Lock / retention policy REFUSED the write (an irreducible refusal, not a flake)
  "s3-throttled", // real backpressure (SlowDown / ServiceUnavailable): the drain is being rate-limited, not rejected
  "s3-timeout", // the request never completed
  "s3-network", // the endpoint could not be reached (DNS / egress / connection fault)
  "s3-tls", // a transport-security failure at the endpoint (a wrong / expired certificate)
  "s3-unknown", // residual: a fault the closed classifiers could not name (never the store's text)
] as const;
export type PushS3FailCode = (typeof PUSH_S3_FAIL_CODES)[number];

export const PUSH_SINK_FAIL_CODES = [...PUSH_S3_FAIL_CODES, "s3-target-missing", "syslog-target-missing"] as const;

// S3_CODE_TO_PUSH_FAIL maps the fault log's CLOSED S3 <Code> allow-list (dest/fault-log.ts) to the push
// class. Only the codes that name a DIFFERENT operator action are mapped; anything else falls through to the
// message-shape classifier below. Both inputs are already closed enums, so no text can pass through here.
const S3_CODE_TO_PUSH_FAIL: Readonly<Record<string, PushS3FailCode>> = {
  AccessDenied: "s3-auth-denied",
  AccountProblem: "s3-auth-denied",
  AllAccessDisabled: "s3-auth-denied",
  AuthorizationHeaderMalformed: "s3-auth-denied",
  InvalidAccessKeyId: "s3-auth-denied",
  SignatureDoesNotMatch: "s3-auth-denied",
  UnauthorizedAccess: "s3-auth-denied",
  ExpiredToken: "s3-expired-credential",
  InvalidSecurity: "s3-expired-credential",
  InvalidToken: "s3-expired-credential",
  TokenRefreshRequired: "s3-expired-credential",
  InvalidBucketName: "s3-no-such-bucket",
  NoSuchBucket: "s3-no-such-bucket",
  InvalidRetentionPeriod: "s3-worm-denied",
  ObjectLockConfigurationNotFoundError: "s3-worm-denied",
  ServiceUnavailable: "s3-throttled",
  SlowDown: "s3-throttled",
};

// DOWN_REASON_TO_PUSH_FAIL maps the destination probes' closed DEST_DOWN_REASONS to the push class, so the
// S3-drop sink and the archive-destination probe answer "why is this store refusing us" in the SAME words.
const DOWN_REASON_TO_PUSH_FAIL: Readonly<Record<DestDownReason, PushS3FailCode>> = {
  auth: "s3-auth-denied",
  "worm-refused": "s3-worm-denied",
  throttled: "s3-throttled",
  timeout: "s3-timeout",
  network: "s3-network",
  tls: "s3-tls",
  other: "s3-unknown",
};

/**
 * classifyPushS3Fault coarsens a failed S3-drop PUT into a closed PushS3FailCode (G164). It reads the driver's
 * OWN bounded fault snapshot first (whose s3Code is already a member of a closed, documented, vendor-defined
 * allow-list and whose wormChecksumComplaint is a boolean), and falls back to the shared destDownReason
 * message-shape classifier. It RETURNS an enum member: the S3 error body, the endpoint, the bucket and the
 * key never leave the driver.
 *
 * @param e - the thrown PUT fault.
 * @param snapshot - the S3 driver's bounded fault snapshot (its newest shape is this PUT's).
 * @returns the closed push class.
 */
export function classifyPushS3Fault(e: unknown, snapshot?: DestFaultSnapshot): PushS3FailCode {
  const newest = snapshot?.faults[0];
  if (newest) {
    if (newest.wormChecksumComplaint) return "s3-worm-denied";
    const mapped = S3_CODE_TO_PUSH_FAIL[newest.s3Code];
    if (mapped !== undefined) return mapped;
  }
  return DOWN_REASON_TO_PUSH_FAIL[destDownReason(e)];
}

// classifyPushConfigFault coarsens a config-step throw into a closed PushPassFailCode. It reads the error
// message ONLY to match the engine's own literal prefix above, and returns an enum member; the message,
// the DO status and the unwrap error text never leave this function.
export function classifyPushConfigFault(e: unknown): Extract<PushPassFailCode, "config-unreadable" | "secret-unresolvable"> {
  const m = e instanceof Error ? e.message : "";
  return m.startsWith(PUSH_CONFIG_UNREADABLE_PREFIX) ? "config-unreadable" : "secret-unresolvable";
}

// fetchPushConfig reads the RAW push destination record (GET /push-config, INTERNAL-ONLY, never a public
// admin route) and resolves the sealed auth secret(s) to plaintext, mirroring dest/factory.ts's
// fetchDestConfig. wrapKey is the resolved CONFIG_WRAP_KEY; a present envelope with no key configured
// throws loudly (resolveConfigSecret), exactly like the destination credential path. The http auth header
// resolves under PUSH_SECRET_AAD and the s3 secretAccessKey under the DISTINCT PUSH_S3_SECRET_AAD, so the two
// secret classes are opened only in their own domain. Exported so the admin test-send route (router-push.ts)
// shares this exact read+unwrap path with the drain.
export async function fetchPushConfig(scheduler: ReturnType<typeof schedulerStub>, wrapKey: Uint8Array | undefined): Promise<ResolvedPushConfig | null> {
  const resp = await scheduler.fetch(doURL("/push-config"), { method: "GET" });
  if (!resp.ok) throw new Error(`${PUSH_CONFIG_UNREADABLE_PREFIX} (DO responded ${resp.status})`);
  const { record } = (await resp.json()) as { record?: PushDestinationRecord | null };
  if (!record) return null;
  const authHeaderValue = await resolveConfigSecret(wrapKey, record.authHeaderValue, PUSH_SECRET_AAD);
  const sink: PushSink = record.sink ?? "http";
  let s3: ResolvedS3Target | undefined;
  if (record.s3Target) {
    const secretAccessKey = await resolveConfigSecret(wrapKey, record.s3Target.secretAccessKey, PUSH_S3_SECRET_AAD);
    s3 = {
      endpoint: record.s3Target.endpoint,
      bucket: record.s3Target.bucket,
      region: record.s3Target.region,
      accessKeyId: record.s3Target.accessKeyId,
      secretAccessKey,
      ...(record.s3Target.addressing !== undefined ? { addressing: record.s3Target.addressing } : {}),
      ...(record.s3Target.storageClass !== undefined ? { storageClass: record.s3Target.storageClass } : {}),
      prefix: record.s3Target.prefix && record.s3Target.prefix.trim() !== "" ? record.s3Target.prefix : DEFAULT_S3_PREFIX,
    };
  }
  return {
    endpoint: record.endpoint,
    format: record.format,
    authHeaderName: record.authHeaderName,
    authHeaderValue,
    enabled: record.enabled,
    gen: record.gen,
    sink,
    authInUrl: record.authInUrl === true,
    ...(s3 !== undefined ? { s3 } : {}),
    ...(record.syslog !== undefined ? { syslog: record.syslog } : {}),
  };
}

// spliceUrlToken appends the auth secret to the endpoint as a trailing path segment (the Devo-style
// path-token intake). The endpoint is already SSRF/https-validated at config time; deliverSiemPush re-screens
// this final url at send time (hostname only). The final url carries the secret, so it is built HERE at the
// moment of use and handed straight to the sender, never logged, audited, trailed or returned.
function spliceUrlToken(endpoint: string, token: string): string {
  return `${endpoint.replace(/\/+$/, "")}/${encodeURIComponent(token)}`;
}

// putSiemBatchToS3 drops ONE object shaped by the CONFIGURED format into the S3-drop sink's bucket, keyed
// <prefix>/<ISO>-<fromSeq>-<toSeq>.<ext> where the extension describes that format's wire shape. It reuses the
// archive S3Destination.put client (the same SigV4 signing, redirect:"manual" guard and https-only
// construction), so there is NO bespoke SigV4 here. It NEVER throws: an S3 failure returns ok:false with a
// coarse reason, so the cursor holds and the batch retries next tick, exactly like an http non-2xx.
//
// The format has to be THREADED IN here rather than a fixed shaper, so all eight formats a customer could
// choose are actually written in their configured wire shape (never silently substituted for one another).
async function putSiemBatchToS3(s3: ResolvedS3Target, format: PushFormat, events: AuditEvent[], meta: PushCursorMeta): Promise<PushDeliveryResult> {
  // The driver is constructed OUTSIDE the try so its bounded fault log (dest/fault-log.ts) is reachable from
  // the catch: that log already holds this PUT's closed S3 <Code> and its Object-Lock complaint boolean, which
  // is what turns the old fixed "s3-put-failed" into a class an operator can act on (G164).
  const dest = new S3Destination(s3.endpoint, s3.bucket, s3.region, s3.accessKeyId, s3.secretAccessKey, {
    ...(s3.addressing !== undefined ? { addressing: s3.addressing } : {}),
    ...(s3.storageClass !== undefined ? { storageClass: s3.storageClass } : {}),
  });
  try {
    const shaped = shapeForFormat(format, events, meta);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const key = `${s3.prefix}/${stamp}-${meta.afterSeq}-${meta.nextAfterSeq}.${objectExtensionForFormat(format)}`;
    await dest.put(key, utf8(shaped.body));
    return { ok: true };
  } catch (e) {
    // A CLOSED class only, never the endpoint/bucket/key or the store's raw error text. The causeDigest is a
    // one-way 12-hex prefix of that same raw text (G164): it identifies WHICH fault without carrying any of it.
    return { ok: false, reason: classifyPushS3Fault(e, dest.destFaults()), causeDigest: await causeDigest((e as Error)?.message ?? "") };
  }
}

// deliverGelfHttp sends ONE GELF object per HTTP request, never a newline-joined batch: Graylog's GELF HTTP
// input has "Enable Bulk Receiving" OFF by default, so a batched multi-line POST silently drops every event
// input has "Enable Bulk Receiving" OFF by default, so a batched multi-line POST silently drops every event
// past the first. This is the one format-specific carve-out in the http
// branch below; every other format still sends the whole batch in a single POST. Mirrors the generic http
// branch exactly (the url-token splice + the one configured auth header), just looped per event. A single
// request's failure fails the WHOLE result (ok:false, the first failure's status/reason), so the cursor
// holds and the SAME events retry next tick -- safe, since every audit event carries a stable seq+hash a
// SIEM dedups on, and the loop stops sending further events once the sink has shown itself down rather than
// hammering it. Never throws (deliverSiemPush is non-throwing by contract).
async function deliverGelfHttp(cfg: ResolvedPushConfig, events: AuditEvent[], meta: PushCursorMeta): Promise<PushDeliveryResult> {
  let lastStatus: number | undefined;
  for (const e of events) {
    const shaped = shapeGelf([e], meta);
    const r = cfg.authInUrl
      ? await deliverSiemPush(spliceUrlToken(cfg.endpoint, cfg.authHeaderValue), shaped.body, shaped.contentType, cfg.authHeaderName, cfg.authHeaderValue, { omitAuthHeader: true })
      : await deliverSiemPush(cfg.endpoint, shaped.body, shaped.contentType, cfg.authHeaderName, cfg.authHeaderValue);
    if (!r.ok) return toPushDeliveryResult(r);
    lastStatus = r.status;
  }
  return { ok: true, ...(lastStatus !== undefined ? { status: lastStatus } : {}) };
}

// deliverResolvedPush is the SINGLE sink-dispatch shared by the cron drain and the admin test-send, so the
// two can never diverge on how a sink is delivered. s3 drops ONE object shaped by the configured format, the
// same shapeForFormat the http branch uses, keyed with that format's own extension; syslog-tls shapes each event to
// CEF/LEEF and writes the batch as RFC 5424 records (RFC 6587 octet-counted) over one implicit-TLS socket;
// http shapes per format and sends, splicing the url token first when authInUrl -- EXCEPT gelf, which sends
// one request per event (deliverGelfHttp; item 1: Graylog's GELF HTTP input drops a batched body by
// default). It NEVER throws.
export async function deliverResolvedPush(cfg: ResolvedPushConfig, events: AuditEvent[], meta: PushCursorMeta): Promise<PushDeliveryResult> {
  if (cfg.sink === "s3") {
    if (!cfg.s3) return { ok: false, reason: "s3-target-missing" };
    return putSiemBatchToS3(cfg.s3, cfg.format, events, meta);
  }
  if (cfg.sink === "syslog-tls") {
    if (!cfg.syslog) return { ok: false, reason: "syslog-target-missing" };
    return toPushDeliveryResultSyslog(await deliverSiemSyslog(cfg.syslog.host, cfg.syslog.port, cfg.format, events, meta));
  }
  if (cfg.format === "gelf") {
    return deliverGelfHttp(cfg, events, meta);
  }
  const shaped = shapeForFormat(cfg.format, events, meta);
  // HEC ENVELOPE: splunk-hec is the ONE format whose response contract this engine knows, so it is the one
  // format whose response body the sender reads rather than cancels. HEC states its own status in the BODY
  // ({"text":"...","code":N}), and code 0 alone means the batch was taken: a 2xx with a non-zero code is a
  // refusal that used to advance the cursor past audit events Splunk had thrown away. Every other format is
  // sent with this off, so its result is byte-identical to before.
  const hecEnvelope = cfg.format === "splunk-hec";
  if (cfg.authInUrl) {
    const finalUrl = spliceUrlToken(cfg.endpoint, cfg.authHeaderValue);
    const r = await deliverSiemPush(finalUrl, shaped.body, shaped.contentType, cfg.authHeaderName, cfg.authHeaderValue, { omitAuthHeader: true, hecEnvelope });
    return toPushDeliveryResult(r);
  }
  const r = await deliverSiemPush(cfg.endpoint, shaped.body, shaped.contentType, cfg.authHeaderName, cfg.authHeaderValue, { hecEnvelope });
  return toPushDeliveryResult(r);
}

// toPushDeliveryResult folds the http sender's SiemPushSendResult into the sink-agnostic shape.
function toPushDeliveryResult(r: SiemPushSendResult): PushDeliveryResult {
  return { ok: r.ok, ...(r.status !== undefined ? { status: r.status } : {}), ...(r.code !== undefined ? { reason: r.code } : {}) };
}

// toPushDeliveryResultSyslog folds the syslog sender's SiemSyslogSendResult into the sink-agnostic shape (a
// syslog write has no HTTP status, so only the coarse code maps to reason), mirroring toPushDeliveryResult.
function toPushDeliveryResultSyslog(r: SiemSyslogSendResult): PushDeliveryResult {
  return { ok: r.ok, ...(r.code !== undefined ? { reason: r.code } : {}) };
}

// recordOutcome posts ONE delivery attempt outcome back to the DO (the trail + cursor authority), stamped
// with the config's gen so the DO can drop it if the destination was cleared/replaced mid-delivery.
// Best-effort: a record hiccup is logged and swallowed rather than turning an already-classified delivery
// outcome into a crashed pass (the trail/cursor simply is not updated this tick; the next tick's export
// still reads from the last-recorded cursor, so nothing is silently skipped).
async function recordOutcome(
  scheduler: ReturnType<typeof schedulerStub>,
  attempt: { ok: boolean; httpStatus?: number; reason?: string; count?: number; fromSeq?: number; toSeq?: number; gen: string; causeDigest?: string },
): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/push-record"), {
      method: "POST",
      body: JSON.stringify(attempt),
      headers: { "content-type": "application/json" },
    });
    // G293: the response was NEVER READ, so a non-2xx passed for a recorded outcome. That is not a cosmetic
    // loss: the cursor authority lives in this record, so a dropped write on a SUCCESSFUL delivery leaves the
    // cursor where it was and the NEXT tick re-sends the same batch -- the "our SIEM is receiving duplicate
    // events" ticket, with an anonymous passErrors integer as its only trace. Count the lost trail write.
    if (!resp.ok) notePushTrailWriteFailure("siem");
  } catch (e) {
    notePushTrailWriteFailure("siem");
    log("error", `siem push outcome record skipped: ${(e as Error).message}`);
  }
}

// recordPassFault records a PRE-DELIVERY fault on the SIEM push trail (support-pack G134): the drain never
// reached a send this tick, so there is no sender outcome to fold, but the trail must still show WHY the push
// stopped rather than going silent. The DO drops any outcome whose gen does not match the live config
// (the straggler guard), so a fault raised BEFORE the config resolved re-reads the raw record for its gen
// alone -- a probe that also answers the only other question worth asking: if the record is absent, push is
// not configured and there is nothing to report; if the DO itself is unreachable, nothing can be recorded at
// all (the scheduler tick ring carries that fault) and this returns quietly. `reason` is a closed
// PushPassFailCode: never a message, a status line, an endpoint or a secret. ok:false, so the cursor is
// never advanced by a fault row.
// `cause` (G164) is the RAW throw behind the closed reason, when there was one. It is reduced to a 12-hex
// one-way digest HERE and nowhere else; the message itself never leaves this function.
async function recordPassFault(scheduler: ReturnType<typeof schedulerStub>, reason: PushPassFailCode, gen?: string, cause?: unknown): Promise<void> {
  let g = gen;
  if (g === undefined) {
    try {
      const resp = await scheduler.fetch(doURL("/push-config"), { method: "GET" });
      if (!resp.ok) return;
      const { record } = (await resp.json()) as { record?: { gen?: unknown } | null };
      if (!record || typeof record.gen !== "string") return; // no destination configured: nothing to record
      g = record.gen;
    } catch {
      return; // the DO is unreachable: the trail lives IN the DO, so there is nowhere to write this
    }
  }
  const digest = cause !== undefined ? await causeDigest((cause as Error)?.message ?? "") : undefined;
  await recordOutcome(scheduler, { ok: false, reason, count: 0, gen: g, ...(digest !== undefined ? { causeDigest: digest } : {}) });
}

// runSiemPushPass is the cron drain, wired into drive() LAST. Returns whether the pass COMPLETED (true) or
// bailed unexpectedly (false), the same false-green signal every tallyPass'd pass reports. A REJECTED
// delivery to the customer's own SIEM endpoint is still a COMPLETED pass (the outcome is recorded on the
// trail and the tamper-evident chain), exactly as a failed webhook alert does not fail runAlertPass; only
// an unreadable DO round-trip counts against passErrors.
export async function runSiemPushPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<boolean> {
  // loadConfigWrapKey is guarded: a malformed CONFIG_WRAP_KEY throws
  // loudly (by design, so a misconfigured key is never mistaken for "unset"), and that throw must land on
  // THIS pass's own trail-writing path, not escape runSiemPushPass. It has its OWN arm so the trail can name
  // the wrap key as the cause (wrap-key-invalid) instead of blaming the DO read that never ran.
  let wrapKey: Uint8Array | undefined;
  try {
    wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
  } catch (e) {
    log("error", `siem push pass: config wrap key unusable: ${(e as Error).message}`);
    await recordPassFault(scheduler, "wrap-key-invalid", undefined, e);
    return false;
  }
  let cfg: ResolvedPushConfig | null;
  try {
    cfg = await fetchPushConfig(scheduler, wrapKey);
  } catch (e) {
    log("error", `siem push pass: configuration unreadable: ${(e as Error).message}`);
    // config-unreadable (the DO round-trip failed) vs secret-unresolvable (the record read back, but its
    // sealed auth secret would not unwrap: the classic rotated-wrap-key silent stop). Both are recorded as
    // closed codes on the trail; neither message is ever carried.
    await recordPassFault(scheduler, classifyPushConfigFault(e), undefined, e);
    return false;
  }
  // Opt-in: no destination configured, or the operator has it disabled, is a silent no-op.
  if (!cfg?.enabled) return true;
  let cursor: number;
  try {
    const cursorResp = await scheduler.fetch(doURL("/push"), { method: "GET" });
    const view = (await cursorResp.json()) as { lastPushedSeq?: number };
    // G084: a lastPushedSeq that is not a number (a DO shape drift after a partial deploy, or a storage
    // anomaly) silently RESETS the cursor to 0 -- and the very next tick re-pushes the ENTIRE audit history.
    // "Our SIEM suddenly received thousands of duplicate historical events" is exactly this branch, and it
    // leaves no trace anywhere. Count the reset (a count; never the cursor value or the events).
    if (typeof view.lastPushedSeq !== "number") noteSiemShapingFallback("cursor-reset");
    cursor = typeof view.lastPushedSeq === "number" ? view.lastPushedSeq : 0;
  } catch (e) {
    log("error", `siem push pass: cursor unreadable: ${(e as Error).message}`);
    await recordPassFault(scheduler, "cursor-unreadable", cfg.gen);
    return false;
  }
  let doc: { events: AuditEvent[]; headSeq: number; headHash: string };
  try {
    const exportResp = await scheduler.fetch(doURL(`/audit/export?afterSeq=${cursor}&limit=${SIEM_PUSH_BATCH_CAP}`), { method: "GET" });
    doc = (await exportResp.json()) as { events: AuditEvent[]; headSeq: number; headHash: string };
  } catch (e) {
    log("error", `siem push pass: audit export unreadable: ${(e as Error).message}`);
    await recordPassFault(scheduler, "export-unreadable", cfg.gen);
    return false;
  }
  // G084 (LATENT DATA LOSS, closed here). The drain asks for SIEM_PUSH_BATCH_CAP events and the shapers
  // independently slice to SIEM_PUSH_BATCH_CAP. Those are the SAME constant today, so nothing is lost -- but
  // the cursor below used to advance to the last event the DRAIN returned, not the last event the SHAPER
  // actually sent. Part those two limits (one edit, in either file) and the batch TAIL is shaped away while
  // the cursor advances past it and the trail records a full, successful delivery: silent, permanent,
  // undetectable audit-log loss. Two guards, belt and braces:
  //   1. assert the two constants agree, so the divergence cannot be introduced silently at all;
  //   2. derive the cursor from the CAPPED set, so even if it were introduced the un-sent tail is re-drained
  //      next tick rather than skipped forever.
  assertSiemBatchCapSound(SIEM_PUSH_BATCH_CAP, SIEM_PUSH_BATCH_CAP);
  const events = doc.events.slice(0, SIEM_PUSH_BATCH_CAP);
  if (events.length === 0) return true; // nothing new since the cursor
  const nextAfterSeq = events[events.length - 1]!.seq;
  // The delivery TAIL (shape -> send -> record) is in its own try/catch, like every DO round-trip above it:
  // deliverSiemPush is non-throwing by contract and the shapers are pure, but a contract-violating throw
  // must still record a failure (never advance the cursor -- recordOutcome only moves it on ok:true) and
  // surface as the false-green signal, rather than escaping runSiemPushPass or skipping the tick silently.
  try {
    const result = await deliverResolvedPush(cfg, events, { afterSeq: cursor, nextAfterSeq, headSeq: doc.headSeq, headHash: doc.headHash });
    await recordOutcome(scheduler, {
      ok: result.ok,
      ...(result.status !== undefined ? { httpStatus: result.status } : {}),
      ...(result.reason !== undefined ? { reason: result.reason } : {}),
      // G164: the S3 leg is the one delivery path with a RAW throw, so it is the one that can carry a join key.
      ...(result.causeDigest !== undefined ? { causeDigest: result.causeDigest } : {}),
      count: events.length,
      fromSeq: cursor,
      toSeq: nextAfterSeq,
      gen: cfg.gen,
    });
    return true;
  } catch (e) {
    log("error", `siem push pass: delivery tail faulted: ${(e as Error).message}`);
    // Record the fault as a failure (ok:false, so the cursor never advances) so the tick is not lost
    // silently; a record hiccup here is itself swallowed by recordOutcome.
    await recordOutcome(scheduler, { ok: false, reason: "shape-or-deliver-fault", count: events.length, fromSeq: cursor, toSeq: nextAfterSeq, gen: cfg.gen, causeDigest: await causeDigest((e as Error)?.message ?? "") });
    return false;
  }
}
