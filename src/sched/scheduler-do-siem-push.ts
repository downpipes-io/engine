// SIEM audit-log push destination: the outbound egress config + cursor + bounded delivery trail for
// forwarding the hash-chained audit events to a customer SIEM. Architecturally a sibling of an archive
// DESTINATION (scheduler-do-dest-config.ts): console-set, owner-exclusive, and the engine must
// reconstruct the live secret on every delivery (unlike the ingest-credential grant, which only ever
// stores a one-way hash). This mixin owns the storage read/write + validation + redaction + audit; the
// outbound fetch itself lives OUTSIDE the DO (cron/siem-push-pass.ts, design rule F11 -- the DO never
// makes a network call to a customer-controlled host).

import { isWrappedSecret, type WrappedSecret } from "../admin/config-secret.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { validateAddressing, validateStorageClass } from "../dest/factory.ts";
import { isAllowedWebhookUrl } from "../notify.ts";
import {
  AuthError,
  isForbiddenPushHeaderName,
  isValidPushHeaderValue,
  isValidPushVendor,
  PUSH_FORMAT_SET,
  PUSH_FORMATS,
  PUSH_SINK_SET,
  type PushDeliveryAttempt,
  type PushDestinationRecord,
  type PushDestinationView,
  type PushS3Target,
  type PushSink,
  type PushSyslogTarget,
  pushSinkFormatError,
  type SchedulerDOCtor,
  SIEM_PUSH_CONFIG_KEY,
  SIEM_PUSH_CURSOR_KEY,
  SIEM_PUSH_TRAIL_CAP,
  SIEM_PUSH_TRAIL_KEY,
} from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

// PUSH_HEADER_NAME_RE bounds the auth header NAME to the RFC 7230 token character set (the same set an
// HTTP header name may use), 1..100 chars. This is shape defence only; the value it names is the secret.
const PUSH_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$/;

// The runtime allow-lists (isOwnerActionKind's discipline: a crafted/stale value can never reach storage,
// even from a replayed dual-control record) are IMPORTED from the one authority in scheduler-do-limits.ts
// rather than re-typed here, so the format list can never drift between the storage boundary and the
// support pack.

// DEFAULT_SYSLOG_PORT is the RFC 5425 syslog-over-TLS port used when a syslog target omits one.
const DEFAULT_SYSLOG_PORT = 6514;

// classifyPushRejectReason maps a buildPushRecord throw to a CLOSED reject-reason class for the audit
// (never the submitted endpoint/header name/secret), mirroring classifyDestRejectReason. The s3/syslog target
// validators are worded so an invalid endpoint carries the word "endpoint" (endpoint-invalid) and a missing
// field carries neither "endpoint" nor "format" (missing-fields), keeping the closed classes accurate.
export function classifyPushRejectReason(e: unknown): "endpoint-invalid" | "format-invalid" | "missing-fields" {
  const msg = e instanceof Error ? e.message : "";
  if (msg.includes("endpoint")) return "endpoint-invalid";
  if (msg.includes("format")) return "format-invalid";
  return "missing-fields";
}

// countTrailingFailures derives the CONSECUTIVE failed-attempt count from the tail of the (already capped)
// trail, so the push-delivery-failure audit event's failureCount needs no separate storage key: it is a
// pure read of data the trail already retains. Capped implicitly at SIEM_PUSH_TRAIL_CAP by the trail's own
// bound (a persistently-failing destination reports "at least 50", never an unbounded count).
function countTrailingFailures(trail: PushDeliveryAttempt[]): number {
  let n = 0;
  for (let i = trail.length - 1; i >= 0; i--) {
    if (trail[i]!.ok) break;
    n++;
  }
  return n;
}

// sanitisePrefix bounds an operator-supplied S3 key prefix: strip control characters (so a crafted prefix
// cannot inject one into the object key) and drop leading/trailing slashes. Returns the cleaned prefix, or
// undefined when nothing usable remains (the drain then applies its own default). THROWS on an over-length
// prefix rather than trimming it to fit.
//
// POSTCONDITION: the returned value NEVER ends in a slash. Cleaning happens BEFORE the length cap is
// applied (not after), so a legal prefix carrying a stray control character is not refused for a length
// it does not have, and the no-trailing-slash postcondition holds unconditionally on the value returned.
//
// The repair is a REFUSAL rather than a third ordering. An S3 key prefix's only job is to name a location,
// so a value trimmed to fit addresses somewhere else, which is the change-number argument (a value whose
// only job is to match something elsewhere must not be silently reshaped) rather than the justification
// argument (a tail that costs detail rather than identity). No legitimate prefix approaches 512 characters.
// The length cap applies AFTER cleaning, so a legal prefix carrying a stray control character is not refused
// for a length it does not have; and because nothing slices the cleaned value, the no-trailing-slash
// postcondition now holds unconditionally.
// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping C0 control characters from an operator-supplied S3 key prefix is the deliberate guard against a control character reaching the object key.
const PREFIX_CONTROLS = /[\x00-\x1f]/g;
const PREFIX_MAX = 512;
function sanitisePrefix(raw: string): string | undefined {
  const cleaned = raw.trim().replace(PREFIX_CONTROLS, "").replace(/^\/+|\/+$/g, "");
  if (cleaned.length > PREFIX_MAX) {
    throw new Error(`push destination s3 key prefix must be ${PREFIX_MAX} characters or fewer once leading and trailing slashes are removed (yours is ${cleaned.length})`);
  }
  return cleaned === "" ? undefined : cleaned;
}

// buildPushS3Target validates a client-supplied s3Target into the stored shape (throws -> a 400 / a closed
// reject-reason class). The endpoint is SSRF/https-screened by isAllowedWebhookUrl (the SAME default-deny the
// http endpoint gets), bucket/region/accessKeyId are required, and the secretAccessKey arrives either as a
// plaintext string (no wrap key, the floor) or a WrappedSecret envelope the router already sealed under
// PUSH_S3_SECRET_AAD (the DO never holds the key); anything else collapses to "" and is rejected. The keep-
// secret splice in setSiemPushDestination supplies the existing secret before this runs on an edit, so a
// first-ever create with no s3 secret is the only path that reaches the "needs a secret access key" throw.
function buildPushS3Target(raw: unknown): PushS3Target {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("push destination s3 target is required for the s3 sink (missing fields)");
  }
  const o = raw as Record<string, unknown>;
  const endpointRaw = typeof o.endpoint === "string" ? o.endpoint.trim() : "";
  const v = isAllowedWebhookUrl(endpointRaw);
  if (!v.ok) throw new Error(`push destination s3 endpoint invalid: ${v.reason}`);
  const bucket = typeof o.bucket === "string" ? o.bucket.trim() : "";
  const region = typeof o.region === "string" ? o.region.trim() : "";
  const accessKeyId = typeof o.accessKeyId === "string" ? o.accessKeyId.trim() : "";
  if (bucket === "" || region === "" || accessKeyId === "") {
    throw new Error("push destination s3 target needs a bucket, a region and an access key id (missing fields)");
  }
  const secretAccessKey: string | WrappedSecret =
    typeof o.secretAccessKey === "string" ? o.secretAccessKey : isWrappedSecret(o.secretAccessKey) ? o.secretAccessKey : "";
  if (secretAccessKey === "") throw new Error("push destination s3 target needs a secret access key (missing fields)");
  const addressing = validateAddressing(o.addressing);
  const storageClass = validateStorageClass(o.storageClass);
  const prefix = typeof o.prefix === "string" ? sanitisePrefix(o.prefix) : undefined;
  return {
    endpoint: v.url,
    bucket,
    region,
    accessKeyId,
    secretAccessKey,
    ...(addressing !== undefined ? { addressing } : {}),
    ...(storageClass !== undefined ? { storageClass } : {}),
    ...(prefix !== undefined ? { prefix } : {}),
  };
}

// buildPushSyslogTarget validates a client-supplied syslog target (host + optional port, default 6514). The
// syslog-tls TRANSPORT is stage B; this only bounds the config shape now (host required; a bad/absent port
// falls back to the default). The message carries neither "endpoint" nor "format", so a missing host files as
// the missing-fields reject class. The syslog host is NOT internal-SSRF-refused: an on-prem SIEM on a private
// address is the norm for syslog, and no delivery happens from this stage anyway.
function buildPushSyslogTarget(raw: unknown): PushSyslogTarget {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("push destination syslog target is required for the syslog-tls sink (missing fields)");
  }
  const o = raw as Record<string, unknown>;
  const host = typeof o.host === "string" ? o.host.trim() : "";
  if (host === "") throw new Error("push destination syslog target needs a host (missing fields)");
  const port = typeof o.port === "number" && Number.isInteger(o.port) && o.port > 0 && o.port <= 65535 ? o.port : DEFAULT_SYSLOG_PORT;
  return { host, port };
}

export function SiemPushMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // getSiemPushRecordRaw is the INTERNAL full record (including the sealed secret): reached only by
    // GET /push-config (the router's drain + test-send resolution), never a public admin route.
    async getSiemPushRecordRaw(): Promise<PushDestinationRecord | null> {
      return (await this.state.storage.get<PushDestinationRecord>(SIEM_PUSH_CONFIG_KEY)) ?? null;
    }

    async getSiemPushCursor(): Promise<number> {
      return (await this.state.storage.get<number>(SIEM_PUSH_CURSOR_KEY)) ?? 0;
    }

    async getSiemPushTrail(): Promise<PushDeliveryAttempt[]> {
      return (await this.state.storage.get<PushDeliveryAttempt[]>(SIEM_PUSH_TRAIL_KEY)) ?? [];
    }

    // getSiemPushView is the REDACTED admin view (GET /admin/push): the secret and its ciphertext NEVER
    // appear here. headSeq reuses the audit chain's own head pointer (loadAuditHead) so the console can
    // show the cursor lag (headSeq - lastPushedSeq) without a second source of truth for "where is head".
    async getSiemPushView(): Promise<PushDestinationView> {
      const record = await this.getSiemPushRecordRaw();
      const trail = await this.getSiemPushTrail();
      if (!record) return { present: false, trail };
      const lastPushedSeq = await this.getSiemPushCursor();
      const head = await this.loadAuditHead();
      const sink: PushSink = record.sink ?? "http";
      return {
        present: true,
        // http-specific fields ride only for the http sink; endpoint is "" for the other sinks. authInUrl is a
        // boolean POSTURE only, never the token. The s3/syslog views carry the redaction-safe location only
        // (NEVER the s3 access key id or secret, NEVER any credential).
        ...(sink === "http" ? { endpoint: record.endpoint, authHeaderName: record.authHeaderName, ...(record.authInUrl === true ? { authInUrl: true } : {}) } : {}),
        format: record.format,
        enabled: record.enabled,
        sink,
        ...(record.s3Target ? { s3: { endpoint: record.s3Target.endpoint, bucket: record.s3Target.bucket, region: record.s3Target.region, ...(record.s3Target.prefix !== undefined ? { prefix: record.s3Target.prefix } : {}) } } : {}),
        ...(record.syslog ? { syslog: { host: record.syslog.host, port: record.syslog.port } } : {}),
        ...(record.vendor !== undefined ? { vendor: record.vendor } : {}),
        setBy: record.setBy,
        setAt: new Date(record.setAt).toISOString(),
        lastPushedSeq,
        headSeq: head.headSeq,
        trail,
      };
    }

    // buildPushRecord validates a client-supplied push-destination submission into a stored record
    // (throws -> mapped to a 400 by fetch()). The router has already run the SAME isAllowedWebhookUrl check
    // before wrapping the secret; this is shape/SSRF defence in depth, mirroring buildDestRecord.
    buildPushRecord(
      req: { endpoint?: unknown; format?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown; sink?: unknown; authInUrl?: unknown; s3Target?: unknown; syslog?: unknown; vendor?: unknown },
      caller: { email: string | null } | null,
    ): PushDestinationRecord {
      // The format applies to every sink and is validated first.
      const format = req.format;
      if (typeof format !== "string" || !PUSH_FORMAT_SET.has(format)) {
        throw new Error(`push destination format must be one of: ${PUSH_FORMATS.join(", ")}`);
      }
      // The sink (default "http") selects which target fields are required. A crafted/stale value never reaches
      // storage (the runtime allow-list, even from a replayed dual-control record).
      const sinkRaw = req.sink;
      let sink: PushSink;
      if (sinkRaw === undefined) sink = "http";
      else if (typeof sinkRaw === "string" && PUSH_SINK_SET.has(sinkRaw)) sink = sinkRaw as PushSink;
      else throw new Error("push destination sink must be http, s3 or syslog-tls (missing fields)");
      if (typeof req.enabled !== "boolean") throw new Error("push destination enabled must be a boolean (missing fields)");
      // The cross-field rule (shared with the router, so the two boundaries cannot disagree): syslog-tls
      // carries CEF or LEEF only. Re-checked here so a REPLAYED dual-control approval minted before the rule
      // existed cannot land a combination whose format the sender would have to substitute.
      const pairError = pushSinkFormatError(format, sink);
      if (pairError !== null) throw new Error(pairError);
      // The console's OPAQUE destination-identity tag. Absent means the caller did not say which vendor this
      // is; a SUPPLIED value must be a bounded catalogue slug (the router screens it first, this is the
      // defence-in-depth re-check on the storage boundary). The message carries neither "endpoint" nor
      // "format", so classifyPushRejectReason files it as the missing-fields class.
      const vendorRaw = req.vendor;
      let vendor: string | undefined;
      if (typeof vendorRaw === "string" && vendorRaw !== "") {
        if (!isValidPushVendor(vendorRaw)) throw new Error("push destination vendor must be a bounded lowercase slug (missing fields)");
        vendor = vendorRaw;
      }
      const setAt = Date.now();
      const setBy = caller?.email ? caller.email : null;
      // A fresh generation id on every set/replace (the straggler guard, see PushDestinationRecord.gen).
      const gen = crypto.randomUUID();
      const common = { format: format as PushDestinationRecord["format"], enabled: req.enabled, setAt, setBy, gen, ...(vendor !== undefined ? { vendor } : {}) };

      // S3-drop sink: the http endpoint/header fields are unused; the s3Target carries the destination + its
      // own sealed secret. endpoint/authHeaderValue are stored as "" so the record shape stays uniform.
      if (sink === "s3") {
        const s3Target = buildPushS3Target(req.s3Target);
        return { endpoint: "", authHeaderName: "Authorization", authHeaderValue: "", sink: "s3", s3Target, ...common };
      }
      // syslog-tls sink: only the target host/port is stored now (the transport is stage B).
      if (sink === "syslog-tls") {
        const syslog = buildPushSyslogTarget(req.syslog);
        return { endpoint: "", authHeaderName: "Authorization", authHeaderValue: "", sink: "syslog-tls", syslog, ...common };
      }

      // http sink (default): the SSRF/https-screened endpoint + the one auth header (or the url-token option).
      const endpoint = typeof req.endpoint === "string" ? req.endpoint.trim() : "";
      const v = isAllowedWebhookUrl(endpoint);
      if (!v.ok) throw new Error(`push destination endpoint invalid: ${v.reason}`);
      // Defence in depth for the router's own check (POSTCONDITION): absent/null is false, and a
      // present non-boolean throws rather than collapsing to false. The router refuses this before the DO is
      // reached on the live path, so this branch stands behind a replayed dual-control approval; it is here
      // because a flag that decides whether the credential rides in the URL must never be inverted silently
      // on ANY path. classifyPushRejectReason keys on "endpoint"/"format" first, and this message carries
      // neither, so it files as the missing-fields class.
      if (req.authInUrl !== undefined && req.authInUrl !== null && typeof req.authInUrl !== "boolean") {
        throw new Error("push destination: carry the auth token in the url must be true or false (missing fields)");
      }
      const authInUrl = req.authInUrl === true;
      const authHeaderNameRaw = typeof req.authHeaderName === "string" ? req.authHeaderName.trim() : "";
      const authHeaderName = authHeaderNameRaw === "" ? "Authorization" : authHeaderNameRaw;
      if (!PUSH_HEADER_NAME_RE.test(authHeaderName)) {
        throw new Error("push destination auth header name must be a valid HTTP header name");
      }
      // Reject a header name that collides with the content-type the sender sets per format, or a
      // runtime-forbidden / hop-by-hop header. RELAXED when authInUrl (the header is never sent then).
      // classifyPushRejectReason keys on "endpoint"/"format" first, so this message (neither word) files as
      // the missing-fields class, the correct closed audit reason.
      if (!authInUrl && isForbiddenPushHeaderName(authHeaderName)) {
        throw new Error("push destination auth header name must not be content-type or a runtime-controlled header");
      }
      // The secret arrives either as a plaintext string (no CONFIG_WRAP_KEY, the legacy floor) or as a
      // WrappedSecret envelope the router already sealed under PUSH_SECRET_AAD (the DO never holds the
      // key). Both are stored verbatim; anything else collapses to "" and is rejected below. When authInUrl
      // this same value is the url token (spliced by the sender's caller), so it is still required.
      const authHeaderValue: string | WrappedSecret =
        typeof req.authHeaderValue === "string" ? req.authHeaderValue : isWrappedSecret(req.authHeaderValue) ? req.authHeaderValue : "";
      if (authHeaderValue === "") throw new Error("push destination needs an auth header value (missing fields)");
      // Defence in depth for the plaintext no-wrap-key floor (finding F3): a wrapped value was already screened
      // by the router before sealing (the DO cannot inspect sealed ciphertext), but a plaintext value stored on
      // an engine with no CONFIG_WRAP_KEY is re-checked here so a control char / over-long value can never be
      // stored on any path. classifyPushRejectReason keys on "endpoint"/"format" first, so this neutral message
      // files as the missing-fields class.
      if (typeof authHeaderValue === "string" && !isValidPushHeaderValue(authHeaderValue)) {
        throw new Error("push destination auth header value must be within the length cap and free of control characters");
      }
      return { endpoint: v.url, authHeaderName, authHeaderValue, sink: "http", ...(authInUrl ? { authInUrl: true } : {}), ...common };
    }

    // summarisePushConfig builds the REDACTION-SAFE inbox summary for the push-dest-set owner action: the
    // format + the endpoint HOST only, NEVER the auth header value (which is in the replay params, like the
    // destination secret access key, but must never reach the inbox summary or the audit).
    summarisePushConfig(req: unknown): string {
      if (req === null || typeof req !== "object") return "Set the SIEM push destination";
      const c = req as { endpoint?: unknown; format?: unknown; sink?: unknown; s3Target?: unknown; syslog?: unknown };
      const format = typeof c.format === "string" ? c.format : "(format)";
      const sink = typeof c.sink === "string" ? c.sink : "http";
      const hostOf = (u: unknown): string => {
        if (typeof u !== "string") return "";
        try {
          return new URL(u).host;
        } catch {
          return ""; // a malformed endpoint never leaks; buildPushRecord will reject it at execute time
        }
      };
      // The summary is the redaction-safe inbox line: sink + format + the destination HOST (and s3 bucket)
      // only, NEVER the auth header value NOR the s3 secret access key (both live in the replay params and are
      // stripped from the listing by redactOwnerActionParamsForListing).
      if (sink === "s3") {
        const s3 = c.s3Target !== null && typeof c.s3Target === "object" ? (c.s3Target as Record<string, unknown>) : {};
        const bucket = typeof s3.bucket === "string" ? s3.bucket : "";
        return `Set the SIEM push destination: ${format} dropped to s3 bucket ${bucket || "(bucket)"} at ${hostOf(s3.endpoint) || "(host)"}`;
      }
      if (sink === "syslog-tls") {
        const sl = c.syslog !== null && typeof c.syslog === "object" ? (c.syslog as Record<string, unknown>) : {};
        const host = typeof sl.host === "string" ? sl.host : "";
        return `Set the SIEM push destination: ${format} over syslog-tls to ${host || "(host)"}`;
      }
      return `Set the SIEM push destination: ${format} to ${hostOf(c.endpoint) || "(host)"}`;
    }

    // auditPushChange records a push-destination-set/-cleared event with the REDACTION-SAFE `push-destination`
    // target (op + a closed reject-reason class only), mirroring auditDestChange. outcome is "failed" for a
    // rejected set, "success" otherwise.
    async auditPushChange(
      caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null,
      action: "push-destination-set" | "push-destination-cleared",
      detail: { op: "set" | "clear"; rejectReason?: "endpoint-invalid" | "format-invalid" | "missing-fields" },
    ): Promise<void> {
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action,
        outcome: detail.rejectReason ? "failed" : "success",
        target: { kind: "push-destination", op: detail.op, ...(detail.rejectReason ? { rejectReason: detail.rejectReason } : {}) },
      });
    }

    // setSiemPushDestination is the OWNER-EXCLUSIVE set/replace, dispatched through gatedOwnerAction
    // (push-dest-set, DO-executed) so the proposer's owner ceiling is re-checked live on every execution
    // (defence in depth over the router's gate).
    //
    // KEEP-SECRET (the write-only-secret-field UX, a deliberate divergence from buildDestRecord which
    // demands the credential on every set): the console cannot resupply a write-only secret merely to toggle
    // `enabled` or edit a non-secret field, so an ABSENT/empty authHeaderValue on a set that has an EXISTING
    // record means "keep the currently sealed secret unchanged". The FIRST-ever create still requires a
    // secret (no existing record to keep, so buildPushRecord's "needs an auth header value" 400s).
    //
    // FRESH-CREATE RESET (the straggler-guard companion): a set that CREATES a config where none existed
    // resets the cursor + trail to 0/empty so a fresh destination starts clean; an in-place REPLACE of an
    // existing destination leaves the cursor + trail intact (a new gen alone invalidates any in-flight
    // straggler, see recordSiemPushOutcome). Replacing an existing destination kills the old secret unless
    // keep-secret reuses it (the new record overwrites the key; nothing of a superseded secret is retained).
    async setSiemPushDestination(
      req: { endpoint?: unknown; format?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown; sink?: unknown; authInUrl?: unknown; s3Target?: unknown; syslog?: unknown; vendor?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PushDestinationView> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may set the SIEM push destination");
      const existing = await this.getSiemPushRecordRaw();
      // KEEP-SECRET (http auth header): an absent/empty incoming value reuses the existing sealed secret (a
      // plaintext string or a WrappedSecret envelope, either way non-empty and stored verbatim). With no
      // existing record it stays empty so buildPushRecord rejects the first-ever set that carries no secret.
      const incomingValue = typeof req.authHeaderValue === "string" ? req.authHeaderValue : isWrappedSecret(req.authHeaderValue) ? req.authHeaderValue : "";
      let effectiveReq: typeof req = incomingValue === "" && existing ? { ...req, authHeaderValue: existing.authHeaderValue } : req;
      // INDEPENDENT S3 KEEP-SECRET: a set that carries an s3Target whose secretAccessKey is absent/empty, when
      // the EXISTING record already holds an s3 secret, reuses that sealed s3 secret. This is a SEPARATE branch
      // from the auth-header keep-secret above: the http header secret and the s3 secret have INDEPENDENT
      // lifecycles, so editing the bucket/region/prefix (or toggling enabled) never forces re-supplying the
      // write-only s3 key, and rotating one secret never disturbs the other. A first-ever s3 create with no s3
      // secret has nothing to keep, so buildPushS3Target rejects it.
      const incomingS3 = req.s3Target;
      if (incomingS3 !== null && typeof incomingS3 === "object" && !Array.isArray(incomingS3) && existing?.s3Target) {
        const s3o = incomingS3 as Record<string, unknown>;
        const incomingS3Secret = typeof s3o.secretAccessKey === "string" ? s3o.secretAccessKey : isWrappedSecret(s3o.secretAccessKey) ? s3o.secretAccessKey : "";
        if (incomingS3Secret === "") {
          effectiveReq = { ...effectiveReq, s3Target: { ...s3o, secretAccessKey: existing.s3Target.secretAccessKey } };
        }
      }
      let rec: PushDestinationRecord;
      try {
        rec = this.buildPushRecord(effectiveReq, caller);
      } catch (e) {
        // A submission that failed validation at set time: record it with a CLOSED reason class (never the
        // submitted endpoint/header name/secret), then rethrow (400 unchanged).
        await this.auditPushChange(caller, "push-destination-set", { op: "set", rejectReason: classifyPushRejectReason(e) });
        throw e;
      }
      await this.state.storage.put(SIEM_PUSH_CONFIG_KEY, rec);
      // FRESH-CREATE RESET: only when there was no prior record; an in-place replace keeps the cursor+trail.
      if (!existing) {
        await this.state.storage.delete(SIEM_PUSH_CURSOR_KEY);
        await this.state.storage.delete(SIEM_PUSH_TRAIL_KEY);
      }
      await this.auditPushChange(caller, "push-destination-set", { op: "set" });
      return this.getSiemPushView();
    }

    // clearSiemPushDestination is the OWNER-EXCLUSIVE delete. NOT dual-control gated (closing an egress of
    // identity-bearing data is the safe direction, mirroring the un-retire/disarm asymmetry elsewhere): a
    // lone owner may always shut it off. Wipes the cursor + trail too, so a destination configured again
    // later starts from a clean slate rather than inheriting a stale lag/history.
    async clearSiemPushDestination(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may clear the SIEM push destination");
      const removed = await this.state.storage.delete(SIEM_PUSH_CONFIG_KEY);
      if (removed) {
        await this.state.storage.delete(SIEM_PUSH_CURSOR_KEY);
        await this.state.storage.delete(SIEM_PUSH_TRAIL_KEY);
        await this.auditPushChange(caller, "push-destination-cleared", { op: "clear" });
      }
      return { ok: true };
    }

    // recordSiemPushOutcome is the drain's (and nothing else's) outcome recorder: append ONE bounded trail
    // entry, and on a 2xx advance the cursor MONOTONICALLY toward toSeq; on a failure the cursor is left
    // untouched (at-least-once retry next tick) and a push-delivery-failure audit event is recorded with the
    // CONSECUTIVE failure count derived from the trail itself (no extra storage key). Internal (the cron
    // drain's own scheduler.fetch); the test-send never calls this (it must not advance the cursor).
    //
    // STRAGGLER GUARD (the clear+reconfigure data-loss race): the whole call is a NO-OP unless the CURRENT
    // config exists AND its gen equals the outcome's gen. A delivery that was in flight when the owner
    // cleared the destination (no current config) or replaced it (a different gen) therefore cannot advance
    // a stale cursor onto a freshly-configured destination and silently skip its events; its outcome is
    // dropped, and the next tick re-reads from the current destination's own cursor. No trail entry, no
    // cursor move, and no failure audit is written for a stale straggler (there is no live destination the
    // record would truthfully describe).
    //
    // MONOTONIC CURSOR (overlapping-tick hardening): the cursor only ever moves FORWARD -- max(current,
    // toSeq) -- so two overlapping ticks cause at most a redelivery (which at-least-once + seq/hash dedup
    // tolerates), never a backward jump that redelivers a large already-pushed range.
    async recordSiemPushOutcome(req: {
      ok?: unknown;
      httpStatus?: unknown;
      reason?: unknown;
      count?: unknown;
      fromSeq?: unknown;
      toSeq?: unknown;
      gen?: unknown;
      causeDigest?: unknown;
    }): Promise<{ ok: true }> {
      const current = await this.getSiemPushRecordRaw();
      const gen = typeof req.gen === "string" ? req.gen : undefined;
      // No live config, or a gen mismatch, means the destination was cleared or replaced while this delivery
      // was in flight: drop the outcome entirely (see STRAGGLER GUARD above).
      if (!current || current.gen !== gen) return { ok: true };
      const entry: PushDeliveryAttempt = {
        at: nowMillisISO(),
        ok: req.ok === true,
        ...(typeof req.httpStatus === "number" ? { httpStatus: req.httpStatus } : {}),
        ...(typeof req.reason === "string" ? { reason: req.reason } : {}),
        ...(typeof req.count === "number" ? { count: req.count } : {}),
        ...(typeof req.fromSeq === "number" ? { fromSeq: req.fromSeq } : {}),
        ...(typeof req.toSeq === "number" ? { toSeq: req.toSeq } : {}),
      // G164: the join key is a 12-hex one-way digest by construction. SHAPE-GATE it here (the redaction
      // chokepoint): anything that is not bare 12-hex did not come from the engine's causeDigest and is
      // dropped, so a drifted or hostile recorder can never turn this field into a free-text seam.
      ...(typeof req.causeDigest === "string" && /^[0-9a-f]{12}$/.test(req.causeDigest) ? { causeDigest: req.causeDigest } : {}),
      };
      const prior = await this.getSiemPushTrail();
      const trail = [...prior, entry].slice(-SIEM_PUSH_TRAIL_CAP);
      await this.state.storage.put(SIEM_PUSH_TRAIL_KEY, trail);
      if (entry.ok) {
        if (typeof req.toSeq === "number") {
          const cursor = await this.getSiemPushCursor();
          await this.state.storage.put(SIEM_PUSH_CURSOR_KEY, Math.max(cursor, req.toSeq));
        }
        return { ok: true };
      }
      const failureCount = countTrailingFailures(trail);
      await this.appendAudit({
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "push-delivery-failure",
        outcome: "failed",
        target: { kind: "push-destination", op: "delivery-failure", failureCount },
      });
      return { ok: true };
    }
  };
}
