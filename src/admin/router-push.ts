// router-push.ts -- the outbound SIEM audit-log push destination admin routes: GET /push (the redacted
// view), POST /push (set/replace, owner + dual-control), POST /push/delete (owner,
// no dual control) and POST /push/test (owner, a synthetic send). Mirrors router-destinations.ts: the
// router validates the endpoint + wraps the secret BEFORE forwarding to the DO (the dual-control + storage
// authority for set/clear), so an invalid submission never gets queued as a pending approval only to fail
// at execute time. The test-send drives the bespoke egress-secure sender directly (egress fetches never
// happen in the DO, design rule F11), sharing the exact shape + send path the cron drain uses.

import { deliverResolvedPush, fetchPushConfig } from "../cron/siem-push-pass.ts";
import { addressingRejected, STORAGE_CLASSES, validateStorageClass } from "../dest/factory-validators.ts";
import { buildSyntheticPushEvent } from "../cron/siem-push-shape.ts";
import { isAllowedWebhookUrl } from "../notify.ts";
import { isForbiddenPushHeaderName, isValidPushHeaderValue, isValidPushVendor, PUSH_FORMAT_SET, PUSH_FORMATS, pushSinkFormatError } from "../sched/scheduler-do-limits.ts";
import { loadConfigWrapKey, maybeWrapConfigSecret, PUSH_S3_SECRET_AAD, PUSH_SECRET_AAD, type WrappedSecret } from "./config-secret.ts";
import { recordAdminRefusal } from "./diag-admin.ts";
import { noteTestOutcome } from "./diag-counters.ts";
import { callerHeaders, gate, jsonError, jsonResponse, rateLimited } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";

// fireInBackground: see router-identity.ts's identical helper.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// DEFAULT_SYSLOG_PORT mirrors the DO's own default (scheduler-do-siem-push.ts). The sink allow-list is a
// three-member inline check below (a Set would be over-engineered for three literals compared inline once).
const DEFAULT_SYSLOG_PORT = 6514;
// PUSH_HEADER_NAME_RE mirrors the DO's own re-check (scheduler-do-siem-push.ts): the RFC 7230 token
// character set, 1..100 chars.
const PUSH_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$/;

// ValidatedPushShape is the router's normalised, UNWRAPPED submission. The two secrets (the http auth header
// value and the s3 secret access key) are carried SEPARATELY (authHeaderValue / s3SecretAccessKey) and only
// when the operator supplied them, so the route wraps exactly those before forwarding, and an absent one
// means keep-secret at the DO. s3Target here is secret-free (the route splices the wrapped secret in).
interface ValidatedPushShape {
  ok: true;
  format: string;
  sink: "http" | "s3" | "syslog-tls";
  enabled: boolean;
  endpoint?: string; // http sink
  authHeaderName?: string; // http sink
  authInUrl?: boolean; // http sink
  authHeaderValue?: string; // present only when supplied (to wrap under PUSH_SECRET_AAD)
  s3Target?: { endpoint: string; bucket: string; region: string; accessKeyId: string; addressing?: string; storageClass?: string; prefix?: string };
  s3SecretAccessKey?: string; // present only when supplied (to wrap under PUSH_S3_SECRET_AAD)
  syslog?: { host: string; port: number };
  vendor?: string; // the console's opaque destination-identity tag, present only when supplied
}

// validatePushVendor screens the console's OPTIONAL destination-identity tag (PushDestinationRecord.vendor).
// Absent is valid on every sink: a caller that does not say which vendor it is (the generic form, an older
// console, a direct API call) leaves the field off, and the console then reads "the config does not record a
// vendor" rather than any particular one. A SUPPLIED value must be a bounded catalogue slug; anything else is
// a 400 here rather than a stored value the view and the pack would echo unchecked.
function validatePushVendor(v: unknown): { ok: true; vendor?: string } | { ok: false; response: Response } {
  if (v === undefined || v === null || v === "") return { ok: true };
  if (typeof v !== "string" || !isValidPushVendor(v)) {
    return { ok: false, response: jsonError("push destination vendor must be a lowercase slug of up to 64 characters (letters, digits and single hyphens)", 400) };
  }
  return { ok: true, vendor: v };
}

// validatePushSetShape validates + normalises a POST /push submission at the router (the SAME discipline
// validateAndProbeDestConfig applies before a destination reaches the DO), so a malformed submission is
// refused 400 BEFORE it can ever be queued as a pending dual-control approval, per sink. Returns the
// normalised, UNWRAPPED fields or a Response the route returns verbatim.
//
// KEEP-SECRET: both secrets are OPTIONAL here -- an absent/empty value is ALLOWED (not a 400) and means "keep
// the currently sealed secret unchanged", so the console can toggle `enabled` or edit a non-secret field
// without resupplying a write-only secret. Each secret is present in the result ONLY when the operator
// supplied a non-empty one; the DO enforces that a FIRST-ever create still carries the secret its sink needs.
function validatePushSetShape(body: {
  endpoint?: unknown;
  format?: unknown;
  authHeaderName?: unknown;
  authHeaderValue?: unknown;
  enabled?: unknown;
  sink?: unknown;
  authInUrl?: unknown;
  s3Target?: unknown;
  syslog?: unknown;
  vendor?: unknown;
}): ValidatedPushShape | { ok: false; response: Response } {
  const format = body.format;
  // The enumeration in the message is BUILT from the authority (scheduler-do-limits.ts PUSH_FORMATS), so a
  // ninth format cannot leave the operator reading a list of eight.
  if (typeof format !== "string" || !PUSH_FORMAT_SET.has(format)) {
    return { ok: false, response: jsonError(`push destination format must be one of: ${PUSH_FORMATS.join(", ")}`, 400) };
  }
  const sinkRaw = body.sink;
  let sink: "http" | "s3" | "syslog-tls";
  if (sinkRaw === undefined) sink = "http";
  else if (sinkRaw === "http" || sinkRaw === "s3" || sinkRaw === "syslog-tls") sink = sinkRaw;
  else return { ok: false, response: jsonError("push destination sink must be http, s3 or syslog-tls", 400) };
  if (typeof body.enabled !== "boolean") return { ok: false, response: jsonError("enabled must be a boolean", 400) };
  // The cross-field rule: syslog-tls carries CEF or LEEF only. Refused HERE, before the secret is wrapped and
  // before the submission can be queued as a pending dual-control approval, because the alternative was worse
  // than a 400: the combination used to validate and then ship CEF under whatever format was chosen.
  const pairError = pushSinkFormatError(format, sink);
  if (pairError !== null) return { ok: false, response: jsonError(pairError, 400) };
  const vendorCheck = validatePushVendor(body.vendor);
  if (!vendorCheck.ok) return vendorCheck;
  const vendorField = vendorCheck.vendor !== undefined ? { vendor: vendorCheck.vendor } : {};

  if (sink === "s3") {
    const s3 = body.s3Target;
    if (s3 === null || typeof s3 !== "object" || Array.isArray(s3)) return { ok: false, response: jsonError("push destination s3 target is required for the s3 sink", 400) };
    const o = s3 as Record<string, unknown>;
    // SSRF/https-screen the s3 endpoint (the SAME default-deny the http endpoint gets).
    const v = isAllowedWebhookUrl(typeof o.endpoint === "string" ? o.endpoint.trim() : "");
    if (!v.ok) return { ok: false, response: jsonError(`push destination s3 endpoint invalid: ${v.reason}`, 400) };
    const bucket = typeof o.bucket === "string" ? o.bucket.trim() : "";
    const region = typeof o.region === "string" ? o.region.trim() : "";
    const accessKeyId = typeof o.accessKeyId === "string" ? o.accessKeyId.trim() : "";
    if (bucket === "" || region === "" || accessKeyId === "") return { ok: false, response: jsonError("push destination s3 target needs a bucket, a region and an access key id", 400) };
    const s3Secret = typeof o.secretAccessKey === "string" ? o.secretAccessKey : "";
    // These two are forwarded as bare strings and the DO
    // then runs validateAddressing / validateStorageClass, both of which DROP an unrecognised value and let
    // the push destination save 200 addressed and tiered differently from what the operator chose. The
    // destination surface carries the refusal twin for exactly these two fields (router-destinations.ts);
    // this is the same pair on the audit-export surface, with the same rules, read from the same functions so
    // the two cannot drift.
    //
    // CORRECTED: when this comment was written the destination surface refused storageClass but still DROPPED
    // an out-of-enum addressing, so the claim above was only half true and the drift it warns about was
    // already there. Both surfaces now read the same addressingRejected predicate, which is what makes the
    // claim true rather than aspirational.
    if (addressingRejected(o.addressing)) {
      return { ok: false, response: jsonError('push destination s3 addressing must be "auto", "path" or "vhost"', 400) };
    }
    if (typeof o.storageClass === "string" && o.storageClass.trim() !== "" && validateStorageClass(o.storageClass) === undefined) {
      return { ok: false, response: jsonError(`push destination s3 storage class is not supported; downpipes writes to the immediately-readable classes only (${STORAGE_CLASSES.join(", ")})`, 400) };
    }
    const addressing = typeof o.addressing === "string" ? o.addressing : undefined;
    const storageClass = typeof o.storageClass === "string" ? o.storageClass : undefined;
    const prefix = typeof o.prefix === "string" ? o.prefix : undefined;
    return {
      ok: true,
      format,
      sink,
      enabled: body.enabled,
      s3Target: { endpoint: v.url, bucket, region, accessKeyId, ...(addressing !== undefined ? { addressing } : {}), ...(storageClass !== undefined ? { storageClass } : {}), ...(prefix !== undefined ? { prefix } : {}) },
      ...(s3Secret !== "" ? { s3SecretAccessKey: s3Secret } : {}),
      ...vendorField,
    };
  }

  if (sink === "syslog-tls") {
    const sl = body.syslog;
    if (sl === null || typeof sl !== "object" || Array.isArray(sl)) return { ok: false, response: jsonError("push destination syslog target is required for the syslog-tls sink", 400) };
    const o = sl as Record<string, unknown>;
    const host = typeof o.host === "string" ? o.host.trim() : "";
    if (host === "") return { ok: false, response: jsonError("push destination syslog target needs a host", 400) };
    // ABSENT means the 6514 default. A PRESENT port outside 1..65535, or a fractional one, is REFUSED rather
    // than replaced by 6514: an operator who typed the
    // wrong port was told the push destination was saved and their audit stream went to a port they never
    // chose, which on an audit-export surface is a silently misdirected security log.
    if (o.port !== undefined && o.port !== null && (typeof o.port !== "number" || !Number.isInteger(o.port) || o.port < 1 || o.port > 65535)) {
      return { ok: false, response: jsonError("push destination syslog port must be a whole number from 1 to 65535 (omit it for the 6514 default)", 400) };
    }
    const port = typeof o.port === "number" && Number.isInteger(o.port) && o.port > 0 && o.port <= 65535 ? o.port : DEFAULT_SYSLOG_PORT;
    return { ok: true, format, sink, enabled: body.enabled, syslog: { host, port }, ...vendorField };
  }

  // http sink (default).
  const v = isAllowedWebhookUrl(typeof body.endpoint === "string" ? body.endpoint.trim() : "");
  if (!v.ok) return { ok: false, response: jsonError(`push destination endpoint invalid: ${v.reason}`, 400) };
  // ABSENT (or null) means false, the default: the token rides in a header. A PRESENT value that is not a
  // boolean is REFUSED rather than coerced (POSTCONDITION). This test used to be a bare
  // `=== true`, so the JSON string "true" was accepted with a 200 and stored as the OPPOSITE of what the
  // caller asked for, byte-identical in status and message to a body that never mentioned the flag. A
  // silently inverted boolean is not a truncated string: it is a value the caller believes they set, and
  // this flag decides WHERE THE CREDENTIAL RIDES -- spliced into the endpoint URL, or sent as a header --
  // and it relaxes the forbidden-header-name check below. Nothing legitimate sends a non-boolean here; the
  // console's push form emits a real boolean from a checkbox.
  if (body.authInUrl !== undefined && body.authInUrl !== null && typeof body.authInUrl !== "boolean") {
    return { ok: false, response: jsonError("push destination: carry the auth token in the url must be true or false (omit it to send the token in a header)", 400) };
  }
  const authInUrl = body.authInUrl === true;
  const authHeaderNameRaw = typeof body.authHeaderName === "string" ? body.authHeaderName.trim() : "";
  const authHeaderName = authHeaderNameRaw === "" ? "Authorization" : authHeaderNameRaw;
  if (!PUSH_HEADER_NAME_RE.test(authHeaderName)) {
    return { ok: false, response: jsonError("push destination auth header name must be a valid HTTP header name", 400) };
  }
  // The forbidden-name check is RELAXED when the token rides in the url (authInUrl): the header is never sent.
  if (!authInUrl && isForbiddenPushHeaderName(authHeaderName)) {
    return { ok: false, response: jsonError("push destination auth header name must not be content-type or a runtime-controlled header (e.g. host, content-length, connection)", 400) };
  }
  const authHeaderValue = typeof body.authHeaderValue === "string" ? body.authHeaderValue : "";
  // Screen the auth header VALUE at config time (finding F3): an absent/empty value is the keep-secret signal
  // (unchanged), but a SUPPLIED value carrying a control char (CR/LF header injection) or exceeding the length
  // cap is rejected with a clear 400 here -- BEFORE it is sealed -- rather than surfacing later as an opaque
  // send-time network error. The name is already screened above; this closes the matching gap on the value.
  if (authHeaderValue !== "" && !isValidPushHeaderValue(authHeaderValue)) {
    return { ok: false, response: jsonError("push destination auth header value must be within the length cap and free of control characters (no CR/LF)", 400) };
  }
  return { ok: true, format, sink, enabled: body.enabled, endpoint: v.url, authHeaderName, ...(authInUrl ? { authInUrl: true } : {}), ...(authHeaderValue !== "" ? { authHeaderValue } : {}), ...vendorField };
}

// handlePush dispatches the SIEM push destination group. Returns the route's Response, or null when no
// case here matched (the hub falls to the next spoke).
export async function handlePush(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // GET /push is the redacted admin view (any authenticated role, the same reconnaissance class as
    // GET /destinations): the endpoint, format, header NAME, enabled flag, who/when, the cursor lag and the
    // bounded trail. The secret and its ciphertext NEVER appear (the DO's getSiemPushView never reads them
    // into the response); this route is a byte-for-byte forward of the DO's own reply.
    // The redaction argument above is a claim about the BODY and was the only one
    // ever made here; nothing was said about the caller and nothing checked one. The forward carries no
    // callerHeaders, so the DO's getSiemPushView() has no principal and the router is the only possible
    // home. posture.read is the floor this data already sits behind: support-sections-push.ts fetches
    // doURL("/push") into the posture.read-gated support pack. Viewer-floor capability, so no reachable
    // principal is refused, and "any authenticated role" stays true while becoming checkable.
    case "GET /push": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/push"), { method: "GET" });
    }

    // POST /push sets or replaces the push destination. Owner-exclusive (keys.ceremony) + rate-limited, then
    // forwarded to the DO's dual-control gate (push-dest-set): with a second owner present (or the opt-in
    // gate on), this queues a pending approval (202) instead of repointing the egress inline. The endpoint
    // is SSRF/shape-validated and the secret is WRAPPED under the sibling PUSH_SECRET_AAD here, BEFORE the
    // DO ever sees it, so an invalid submission never reaches the approval queue.
    case "POST /push": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as {
        endpoint?: unknown;
        format?: unknown;
        authHeaderName?: unknown;
        authHeaderValue?: unknown;
        enabled?: unknown;
        sink?: unknown;
        authInUrl?: unknown;
        s3Target?: unknown;
        syslog?: unknown;
        vendor?: unknown;
      };
      const validated = validatePushSetShape(body);
      if (!validated.ok) {
        // G245: "we could never get SIEM push configured" -- every rejection lived in an HTTP response and the
        // pack held no record that the customer had even TRIED. A closed (surface, reason) pair rides; never
        // the submitted endpoint, header name or secret.
        fireInBackground(runtime, recordAdminRefusal(scheduler, "push-config", "validation"));
        return validated.response;
      }
      // KEEP-SECRET: wrap + forward each secret ONLY when the operator supplied a non-empty one, each under its
      // OWN AAD (the http auth header under PUSH_SECRET_AAD, the s3 key under PUSH_S3_SECRET_AAD). When absent,
      // the record is forwarded WITHOUT that secret so the DO keeps the existing sealed one (a first-ever
      // create with no secret is rejected by the DO's buildPushRecord, not here). The DO never sees plaintext.
      let wrappedHeader: string | WrappedSecret | undefined;
      let s3TargetForward: Record<string, unknown> | undefined = validated.s3Target;
      try {
        const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
        if (validated.authHeaderValue !== undefined) {
          wrappedHeader = await maybeWrapConfigSecret(wrapKey, validated.authHeaderValue, PUSH_SECRET_AAD);
        }
        if (validated.s3SecretAccessKey !== undefined && s3TargetForward !== undefined) {
          const wrappedS3 = await maybeWrapConfigSecret(wrapKey, validated.s3SecretAccessKey, PUSH_S3_SECRET_AAD);
          s3TargetForward = { ...s3TargetForward, secretAccessKey: wrappedS3 };
        }
      } catch (e) {
        return jsonError(`the engine's CONFIG_WRAP_KEY is misconfigured (${(e as Error).message}); fix it in the Secrets Store before setting a push destination (the auth secrets are encrypted at rest under this key)`, 400);
      }
      return scheduler.fetch(doURL("/push"), {
        method: "POST",
        body: JSON.stringify({
          format: validated.format,
          sink: validated.sink,
          enabled: validated.enabled,
          ...(validated.endpoint !== undefined ? { endpoint: validated.endpoint } : {}),
          ...(validated.authHeaderName !== undefined ? { authHeaderName: validated.authHeaderName } : {}),
          ...(validated.authInUrl !== undefined ? { authInUrl: validated.authInUrl } : {}),
          ...(wrappedHeader !== undefined ? { authHeaderValue: wrappedHeader } : {}),
          ...(s3TargetForward !== undefined ? { s3Target: s3TargetForward } : {}),
          ...(validated.syslog !== undefined ? { syslog: validated.syslog } : {}),
          ...(validated.vendor !== undefined ? { vendor: validated.vendor } : {}),
        }),
        headers: callerHeaders(caller),
      });
    }

    // POST /push/delete clears the push destination. Owner-exclusive; NOT dual-control gated (closing an
    // egress of identity-bearing audit data is the safe direction, mirroring the un-retire/disarm asymmetry
    // elsewhere in the product). It IS change-controlled: callerHeaders forwards the operator's change
    // reference and the DO route enforces the change-number policy on it (kind "push-clear") before clearing.
    case "POST /push/delete": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/push/delete"), { method: "POST", headers: callerHeaders(caller) });
    }

    // POST /push/test sends ONE synthetic audit-shaped event through the SAME egress-secure sender + shaper
    // the drain uses, and reports the endpoint's HONEST outcome (a real SIEM 401, a timeout, an
    // egress-blocked reason). It never advances the cursor and never touches the delivery trail: it is a
    // pre-enable wiring check, not a drain tick. Owner-exclusive.
    case "POST /push/test": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const started = Date.now();
      let cfg: Awaited<ReturnType<typeof fetchPushConfig>>;
      try {
        cfg = await fetchPushConfig(scheduler, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      } catch (e) {
        fireInBackground(runtime, noteTestOutcome(scheduler, "push", { ok: false, reason: `config-unreadable: ${(e as Error).message}` }));
        return jsonResponse({ ok: false, reason: `config-unreadable: ${(e as Error).message}`, ms: Date.now() - started });
      }
      if (!cfg) {
        fireInBackground(runtime, noteTestOutcome(scheduler, "push", { ok: false, reason: "not-configured" }));
        return jsonResponse({ ok: false, reason: "not-configured", ms: Date.now() - started });
      }
      // Drive the SAME sink dispatch the cron drain uses (deliverResolvedPush): an http/url-token POST, a real
      // s3 PUT of one synthetic NDJSON object, or a real RFC 5424/6587 write over an implicit-TLS socket for
      // syslog-tls. One synthetic, clearly-labelled event only; it never advances the cursor or touches the
      // trail (a wiring probe).
      const event = buildSyntheticPushEvent();
      const result = await deliverResolvedPush(cfg, [event], { afterSeq: 0, nextAfterSeq: 0, headSeq: 0, headHash: "" });
      // G246: "the push test failed with a 401 yesterday but works when support asks us to retry." The 401 is
      // the whole diagnosis and it lived for exactly as long as the browser tab. The STATUS CLASS is carried
      // (401 split out from 4xx on purpose: it is the customer's answer), never the SIEM endpoint or its token.
      fireInBackground(runtime, noteTestOutcome(scheduler, "push", { ok: result.ok === true, ...(result.reason !== undefined ? { reason: result.reason } : {}), ...(result.status !== undefined ? { status: result.status } : {}) }));
      return jsonResponse({
        ok: result.ok,
        ...(result.status !== undefined ? { httpStatus: result.status } : {}),
        ...(result.reason !== undefined ? { reason: result.reason } : {}),
        ms: Date.now() - started,
      });
    }
    default:
      return null;
  }
}
