// The Jira Service Management / Opsgenie channel adapter (contract section 2.2). JSM (Jira Service
// Management) absorbed Opsgenie's alerting engine, and the two accept the SAME Alert API shape today;
// Opsgenie itself is sunsetting in, so this adapter is built against the JSM endpoint
// contract, which both providers honour identically now and for the foreseeable future. Unlike
// PagerDuty's single trigger/resolve envelope, the Alert API is a POST-create / POST-close-by-alias
// PAIR: a new or continuing condition CREATEs (or, re-POSTed with the same alias, de-duplicates onto)
// an alert; a RECOVERED emission CLOSEs that alert by its alias.
//
// AUTH: the GenieKey API token rides ONLY in the Authorization header (`GenieKey <token>`), NEVER the
// body. The token is sealed at rest under JSM_SECRET_AAD (src/admin/config-secret.ts), domain-separated
// from every other secret class the engine seals, and is decrypted here, in the Worker, only for the
// instant of the POST.
//
// REDACTION: the alert body carries only the emission's safe surface (event/severity enums, the
// downpipe name + state one-liner, the alias); never a secret, key, value or fingerprint. FAIL-OPEN:
// deliver never throws (deliverPayload swallows all send-time failures; the secret-resolve step below
// is wrapped in its own try/catch so an undecryptable/rotated wrap key degrades to a clean non-delivery
// rather than an unhandled rejection).

import { JSM_SECRET_AAD, loadConfigWrapKey, resolveConfigSecret } from "../../admin/config-secret.ts";
import { drainResponseBounded } from "../../dest/s3-stream.ts";
import type { Env } from "../../env.d.ts";
import type { AckOutcome, ChannelDeliveryResult, DeliveryFailCode, NotifyChannel, NotifyEmission, SinkScreenVerdict } from "../types.ts";
import { classifyHttpDeliveryStatus, classifyNetworkFailure, screenSinkHost, WEBHOOK_TIMEOUT_MS } from "../types.ts";

// JsmPriority is the closed P1 (highest) .. P5 (lowest) scale the Alert API's `priority` field takes.
export type JsmPriority = "P1" | "P2" | "P3" | "P4" | "P5";

// jsmPriority maps our three-level severity to JSM/Opsgenie's five-level priority. critical pages at
// the highest priority; warning sits in the middle (leaving P1/P2 headroom for an operator's own
// hand-raised alerts); info (a success/recovery-adjacent signal) is the lowest.
export function jsmPriority(severity: NotifyEmission["severity"]): JsmPriority {
  switch (severity) {
    case "critical":
      return "P1";
    case "warning":
      return "P3";
    case "info":
      return "P5";
  }
}

// jsmAlias derives the STABLE dedup key JSM/Opsgenie correlates a create with its later close, mirroring
// pagerdutyDedupKey exactly (the same downpipe id + event scoping), so an operator running both channels
// sees an identical correlation shape. For an account-level event (downpipeId null) it keys on the event
// alone.
export function jsmAlias(emission: NotifyEmission): string {
  return emission.downpipeId !== null ? `downpipe:${emission.downpipeId}:${emission.event}` : `account:${emission.event}`;
}

// JSM_MESSAGE_MAX is the Alert API's documented cap on the `message` field.
const JSM_MESSAGE_MAX = 130;
// JSM_SOURCE_MAX bounds the `source` field (item 10, HARDENING.md): a generous ceiling so an
// unusually long downpipe name cannot land oversized on a field the Alert API treats as a short label.
const JSM_SOURCE_MAX = 100;

// truncateSource caps a source label to JSM_SOURCE_MAX chars (truncate-and-drop the tail; a real downpipe
// name is short, so this rarely bites).
function truncateSource(s: string): string {
  return s.length <= JSM_SOURCE_MAX ? s : s.slice(0, JSM_SOURCE_MAX);
}

// JsmCreatePayload is the Alert API v2 create body. alias is the dedup key (a re-POST with the SAME
// alias on an already-open alert is treated by JSM/Opsgenie as a de-duplicated update, not a new alert).
// message is the redaction-safe one-line summary, capped to the API's 130-char limit; description
// carries the untruncated detail (a much higher cap, so the plain one-liner always fits). priority is
// the mapped P1..P5.
export interface JsmCreatePayload {
  message: string;
  alias: string;
  description: string;
  priority: JsmPriority;
  source: string;
}

// JsmClosePayload is the close-by-alias body (the Alert API accepts an optional note/source/user; only
// the redaction-safe source label is supplied here).
export interface JsmClosePayload {
  source: string;
}

// format renders the create-alert body from the emission's safe surface. source is capped at
// JSM_SOURCE_MAX (item 10).
export function format(emission: NotifyEmission): JsmCreatePayload {
  const message = emission.detail.length > JSM_MESSAGE_MAX ? emission.detail.slice(0, JSM_MESSAGE_MAX) : emission.detail;
  return {
    message,
    alias: jsmAlias(emission),
    description: emission.detail,
    priority: jsmPriority(emission.severity),
    source: truncateSource(emission.downpipeName ?? "downpipe"),
  };
}

// formatClose renders the close-by-alias body from the emission's safe surface. source is capped at
// JSM_SOURCE_MAX (item 10).
export function formatClose(emission: NotifyEmission): JsmClosePayload {
  return { source: truncateSource(emission.downpipeName ?? "downpipe") };
}

// closeUrlFor derives the documented close-by-alias endpoint from the channel's own alert-create url
// (e.g. https://api.opsgenie.com/v2/alerts, or a customer's JSM Cloud alert-api base -- the region/
// tenant choice is the customer's own, so it is SSRF-screened like any other customer url, never a
// fixed provider constant). A single trailing slash on the stored url is tolerated so the derived path
// never doubles up.
function closeUrlFor(baseUrl: string, alias: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  return `${base}/${encodeURIComponent(alias)}/close?identifierType=alias`;
}

// requestStatusUrlFor derives the documented async-request-status endpoint (GET /v2/alerts/requests/{id},
// the Alert API's "Get Request Status") from the channel's OWN alert-create url, mirroring closeUrlFor's
// derivation exactly (the same base, a different path tail) so a customer's region/tenant base is
// respected without a fixed provider constant.
function requestStatusUrlFor(baseUrl: string, requestId: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  return `${base}/requests/${encodeURIComponent(requestId)}`;
}

// JSM_RESPONSE_MAX_BYTES bounds the create/close/poll response body read (the same "bound by the ACTUAL
// bytes read, never trust Content-Length" discipline dest/s3.ts applies, V12.3.1): the Alert API's ack
// body is a tiny JSON envelope ({result,took,requestId} or, for a poll, {data:{...},requestId}), so 16 KiB
// is a generous ceiling that defends against a misbehaving endpoint streaming an unbounded body without
// ever legitimately truncating a real response.
const JSM_RESPONSE_MAX_BYTES = 16_384;

// JsmSendOutcome is what deliverJsmRequest reports: ok/status/code/sinkScreen mirror deliverPayload's own
// result shape exactly (the same send hygiene), plus requestId -- the Alert API's async tracking id,
// present only when a 202's body carried one (item 10, HARDENING.md).
interface JsmSendOutcome {
  ok: boolean;
  status?: number;
  code?: DeliveryFailCode;
  sinkScreen?: SinkScreenVerdict;
  requestId?: string;
}

// deliverJsmRequest POSTs the create/close body with the SAME hygiene deliverPayload gives every other
// channel (a 5s AbortController timeout, redirect:"manual", the send-time SSRF re-screen via
// screenSinkHost, non-throwing), but additionally reads the (bounded) response body on a 2xx so a 202's
// requestId can be captured. The Alert API's create/close is ASYNC-ACCEPTED on 202, not confirmed, and
// deliverPayload deliberately never reads a body (no other channel has a use for one), so this is JSM's
// OWN bespoke sender rather than a change to the shared one every other channel relies on.
async function deliverJsmRequest(url: string, payload: unknown, allowInternal: boolean, headers: Record<string, string>): Promise<JsmSendOutcome> {
  const sinkScreen = screenSinkHost(url);
  if (!allowInternal) {
    if (sinkScreen === "url-invalid") return { ok: false, code: "url-invalid", sinkScreen };
    if (sinkScreen === "internal-literal") return { ok: false, code: "internal-sink-blocked", sinkScreen };
  }
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, WEBHOOK_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(payload),
      signal: controller.signal,
      redirect: "manual",
    });
    const status = resp.status;
    if (!resp.ok) {
      void resp.body?.cancel();
      return { ok: false, status, code: classifyHttpDeliveryStatus(status), sinkScreen };
    }
    let requestId: string | undefined;
    try {
      const bytes = await drainResponseBounded(resp, JSM_RESPONSE_MAX_BYTES, "jsm response");
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { requestId?: unknown };
      if (typeof parsed.requestId === "string" && parsed.requestId.length > 0 && parsed.requestId.length <= 200) requestId = parsed.requestId;
    } catch {
      // A non-JSON, absent or oversized body is not fatal: the send itself succeeded (2xx); requestId
      // simply stays unavailable, and the caller falls back to the plain accepted-unconfirmed outcome.
    }
    return { ok: true, status, sinkScreen, ...(requestId !== undefined ? { requestId } : {}) };
  } catch (e) {
    // The transport fault is coarsened to its CLOSED sub-cause here (gap G248); the exception text never leaves.
    return { ok: false, code: timedOut ? "timeout" : classifyNetworkFailure(e), sinkScreen };
  } finally {
    clearTimeout(timer);
  }
}

// pollJsmRequestStatus makes ONE bounded GET to the Alert API's "Get Request Status" endpoint, the
// documented way to learn a 202's real outcome (item 10). Bounded by the SAME WEBHOOK_TIMEOUT_MS budget
// as the send; a non-2xx, a malformed/ambiguous body, a timeout or a network fault all resolve to
// undefined ("could not confirm") rather than throwing -- this poll is a best-effort UPGRADE from
// accepted-unconfirmed to a positively-confirmed verdict, never a new way to fail the whole delivery.
async function pollJsmRequestStatus(baseUrl: string, requestId: string, headers: Record<string, string>): Promise<boolean | undefined> {
  const url = requestStatusUrlFor(baseUrl, requestId);
  const sinkScreen = screenSinkHost(url);
  if (sinkScreen === "url-invalid" || sinkScreen === "internal-literal") return undefined;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
  try {
    const resp = await fetch(url, { method: "GET", headers, signal: controller.signal, redirect: "manual" });
    if (!resp.ok) {
      void resp.body?.cancel();
      return undefined;
    }
    const bytes = await drainResponseBounded(resp, JSM_RESPONSE_MAX_BYTES, "jsm poll response");
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { data?: { success?: unknown } };
    return typeof parsed.data?.success === "boolean" ? parsed.data.success : undefined;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

// deliver creates (or, on a recovered emission, closes) the alert against the channel's OWN url. The
// GenieKey token is resolved from its sealed envelope for the instant of the call and rides ONLY in the
// Authorization header; the body never carries it. A channel missing its url or apiKey (should be
// impossible after validateChannel) is a non-delivery, the same "no-transport" class deliverPayload's
// siblings use.
//
// ASYNC-ACCEPTED 202 (item 10, HARDENING.md): the Alert API's create/close normally answers
// 202 (accepted for async processing), not a synchronous 200 -- a bare 202 is NOT a confirmed delivery,
// and a create-then-fails-async would otherwise read as "delivered" and could strand a recovery incident
// open. So a 202 carrying a requestId triggers ONE bounded poll of the documented Get Request Status
// endpoint: a positive confirmation (data.success:true) reports a clean, fully-confirmed delivery; every
// other outcome (no requestId, the poll failed/timed out, or came back ambiguous/negative) reports
// ok:true with unconfirmed:true -- still counted as reached (JSM's create is idempotent-by-alias, so
// treating an inherently-async 202 as a hard failure would retry-storm every tick against a healthy
// integration), but honestly caveated rather than silently folded into a plain "delivered".
export async function deliver(env: Env, channel: NotifyChannel, emission: NotifyEmission): Promise<ChannelDeliveryResult> {
  // G280: THE gap. "My JSM channel never delivers" -- and the pack could not say whether the URL or the
  // GenieKey was the missing one, because both guards emitted the same code. Two fields, two codes.
  if (!channel.url) return { ok: false, code: "no-url" };
  if (channel.apiKey === undefined) return { ok: false, code: "no-credential" };
  let token: string;
  try {
    token = await resolveConfigSecret(loadConfigWrapKey(env.CONFIG_WRAP_KEY), channel.apiKey, JSM_SECRET_AAD);
  } catch {
    // The stored envelope will not open (CONFIG_WRAP_KEY absent or ROTATED since the token was sealed) or the
    // key is malformed: there is no usable credential. This is its OWN closed code (gap G004), NOT no-transport,
    // so a rotated wrap key is diagnosable separately from a genuinely misconfigured channel. The fix here is
    // the wrap key / re-sealing the credential. Never throw (fail-open).
    return { ok: false, code: "credential-undecryptable" };
  }
  const headers = { Authorization: `GenieKey ${token}` };
  const allowInternal = channel.allowInternalSink === true;
  const url = emission.recovered === true ? closeUrlFor(channel.url, jsmAlias(emission)) : channel.url;
  const payload = emission.recovered === true ? formatClose(emission) : format(emission);
  const sent = await deliverJsmRequest(url, payload, allowInternal, headers);
  if (!sent.ok) {
    return { ok: false, ...(sent.code !== undefined ? { code: sent.code } : {}), ...(sent.sinkScreen !== undefined ? { sinkScreen: sent.sinkScreen } : {}) };
  }
  if (sent.status === 202) {
    // A bare 202 is ASYNC-ACCEPTED, never a confirmed delivery (do NOT report it as a plain "delivered"):
    // the ONLY way to clear the unconfirmed caveat is a requestId AND a poll that POSITIVELY confirms
    // success. No requestId (an unparseable/absent body) means no poll is even possible, so it stays
    // unconfirmed by default, exactly like a poll that failed/timed out/came back negative or ambiguous.
    const confirmed = sent.requestId !== undefined ? await pollJsmRequestStatus(channel.url, sent.requestId, headers) : undefined;
    // ackOutcome (gap G033) splits the flat unconfirmed:true flag into its two very different meanings. A poll
    // that came back data.success:FALSE is JSM POSITIVELY telling us the alert was NEVER CREATED (a critical
    // page that never appeared), distinct from a poll that simply could not reach the status endpoint.
    // ok/unconfirmed are UNCHANGED (a create is idempotent-by-alias, and flipping ok would retry-storm a
    // healthy async provider); this is a diagnosis, not a behaviour change.
    const ackOutcome: AckOutcome = confirmed === true ? "confirmed" : confirmed === false ? "async-create-failed" : "confirmation-unavailable";
    return { ok: true, ...(confirmed !== true ? { unconfirmed: true } : {}), ackOutcome, ...(sent.sinkScreen !== undefined ? { sinkScreen: sent.sinkScreen } : {}) };
  }
  return { ok: true, ...(sent.sinkScreen !== undefined ? { sinkScreen: sent.sinkScreen } : {}) };
}
