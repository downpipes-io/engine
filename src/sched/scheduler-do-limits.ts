// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): part 2 of the SchedulerDO's shared TYPE +
// CONSTANT vocabulary, split out of scheduler-do-base.ts so that foundation file holds only the irreducible
// DO surface (the constructor + the SchedulerDOSurface instance API every mixin extends). This leaf declares
// the DESTINATION config types (DestinationPricing, DestinationConfig, StoredDestination,
// DestinationCollection, DestStatusView) + the this-free validateDestPricing helper, the DO storage LIMITS
// and KEYS (the rate-limit + recovery-rate caps/windows/prefixes, RING_CAP, DO_LIST_PAGE/MAX_PAGES, the due:
// index prefix + the reconcile cadence + tick key, and the audit rollover/head keys + shapes), the pad16
// index-key helper, and the AUDIT_CAP re-export (defined in audit.ts, enforced in the DO). It is a pure leaf
// (no `this`, no DO state) that base.ts re-exports verbatim, so every module importing these by name from
// scheduler-do-base.ts is unchanged. The sibling scheduler-do-records.ts holds the at-rest record shapes and
// the notify/expiry/discovery vocabulary. Move-only: every value, key, cap, bound and type is byte-identical.
// A leaf the base depends on, never the reverse.

import { AUDIT_CAP } from "../admin/audit.ts";
import type { WrappedSecret } from "../admin/config-secret.ts";
import type { DestPruneState } from "../cron/retention-dest-prune.ts";
import type { AssumeRolePolicy, AzureEntraDirectory } from "../dest/factory.ts";
import type { Addressing } from "../dest/s3.ts";
import type { WormPolicy } from "../dest/types.ts";
import type { TestDeleteProbe } from "./sched-fault-ledger.ts";

// DestinationPricing is the OPTIONAL per-destination unit pricing the owner attaches so the console can
// estimate the storage bill. It is operator-supplied CONFIGURATION, never
// a secret, and is NEVER read by the seal/restore runtime: it exists only to feed the cost estimate, and
// a source that writes to several destinations rolls their pricing up. All rates are per-unit and
// non-negative; currency is a short display label; source records whether the rates came from a provider
// preset or were typed by the operator.
export interface DestinationPricing {
  storagePerGBMonth: number;
  classAPerMillion: number;
  classBPerMillion: number;
  egressPerGB: number;
  currency?: string;
  source?: "preset" | "operator";
}

// validateDestPricing reads an UNTRUSTED pricing value into a sanitised DestinationPricing, or null when
// it is absent or carries no rate. Every rate is coerced to a finite, non-negative number, so a stray
// negative or NaN in operator input can never reach a cost calculation; currency is a short string and
// source is the enum or omitted (exactOptionalPropertyTypes: optional fields are spread, never undefined).
export function validateDestPricing(v: unknown): DestinationPricing | null {
  if (v === null || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  const num = (x: unknown): number => (typeof x === "number" && Number.isFinite(x) && x >= 0 ? x : 0);
  const rateKeys = ["storagePerGBMonth", "classAPerMillion", "classBPerMillion", "egressPerGB"];
  if (!rateKeys.some((k) => typeof o[k] === "number")) return null;
  // POSTCONDITION: the stored currency label is trimmed on both ends. Trim, then slice to 8, then trim
  // again, so a truncation can never leave trailing whitespace from a longer input; the truncation itself
  // stays (a currency label's tail costs detail rather than identity, and the console defaults to USD), and
  // the second trim can never empty the value because the guard above already established a non-space first
  // character.
  const currency = typeof o.currency === "string" && o.currency.trim() !== "" ? o.currency.trim().slice(0, 8).trim() : undefined;
  const source = o.source === "operator" || o.source === "preset" ? o.source : undefined;
  return {
    storagePerGBMonth: num(o.storagePerGBMonth),
    classAPerMillion: num(o.classAPerMillion),
    classBPerMillion: num(o.classBPerMillion),
    egressPerGB: num(o.egressPerGB),
    ...(currency !== undefined ? { currency } : {}),
    ...(source !== undefined ? { source } : {}),
  };
}

export interface DestinationConfig {
  endpoint: string; // https S3 endpoint (R2: https://<account>.r2.cloudflarestorage.com)
  bucket: string;
  region: string; // "auto" for R2
  accessKeyId: string;
  // The one secret in the record (with assumeRole, this is the PRINCIPAL secret). A plaintext string
  // (the legacy / no-wrap-key floor) OR a WrappedSecret envelope when CONFIG_WRAP_KEY is configured
  // (AES-256-GCM at rest; the DO stores and returns the opaque envelope, the engine Worker context
  // wraps/unwraps it). See config-secret.ts.
  secretAccessKey: string | WrappedSecret;
  // assumeRole is the OPTIONAL STS AssumeRole policy. When present, accessKeyId/secretAccessKey above are
  // the long-lived PRINCIPAL authorised only to assume the role, and the run path mints short-lived
  // credentials per invocation. The role ARN is not secret; the externalId inside the policy is
  // credential-class (the cross-account confused-deputy guard) and is never surfaced in a status view.
  assumeRole?: AssumeRolePolicy;
  // addressing is the OPTIONAL S3 request-addressing style ("auto" | "path" | "vhost"). Non-secret.
  addressing?: Addressing;
  // storageClass is the OPTIONAL S3 storage class (an immediately-readable tier). Non-secret.
  storageClass?: string;
  // azureEntra is the OPTIONAL Microsoft Entra service principal for an AZURE BLOB destination: the
  // directory (tenant) id and the application (client) id. NEITHER IS SECRET. The principal's third value,
  // the client secret, is secretAccessKey above: on an Entra destination that field holds the client secret
  // exactly as it holds the storage account key on a Shared Key one, so this record still carries one
  // secret in one place and the export projection, the at-rest envelope and the plaintext census are
  // unchanged. Its presence is what selects Entra authentication; absent means a Shared Key.
  azureEntra?: AzureEntraDirectory;
  setAt: number; // epoch ms
  setBy: string | null; // the verified owner email that stored it (null on the token break-glass)
  verifiedAt: number; // when the router's pre-store write probe passed (epoch ms)
  // deleteProbe records what the verification's cleanup DELETE actually measured (the closed
  // TestDeleteProbe vocabulary): "ok" (the destination prunes), "denied" (a 401/403: the credential
  // may not delete, so backups work and retention pruning never will), "transient" (a 429/5xx or a
  // dropped socket: the store was busy and nothing is known about the credential) or "other".
  // G246 (R5): a bare `catch` used to call every one of those "denied", which is a permission fact
  // only a 401/403 establishes.
  deleteProbe: TestDeleteProbe;
  // worm is the OPTIONAL per-destination immutability policy (S3 Object-Lock: mode + retention days).
  // The runtime arms it on every archive write to THIS destination (fetchDestConfig reads it back, the
  // writer adds the lock headers). Absent means OFF (writes unchanged). Non-secret operator config.
  worm?: WormPolicy;
  // objectLock is the LIVE capability verdict from the store at verification time: whether the bucket
  // actually ENFORCES Object-Lock ("enforced"), demonstrably does not ("not-enforced"), or could not be
  // determined ("unknown"). The console keys its immutability claim on THIS, never on the presence of a
  // worm policy, so a policy on a bucket that silently ignores lock headers is never shown as protected.
  objectLock?: "enforced" | "not-enforced" | "unknown";
  // pricing is the OPTIONAL per-destination unit pricing for the cost estimate (never used by the
  // runtime, never a secret). Absent means the console falls back to a provider preset.
  pricing?: DestinationPricing;
}

// StoredDestination is one named destination in the collection: a DestinationConfig plus a stable
// id (referenced by a downpipe's destinationId) and a human label for the console list.
export interface StoredDestination extends DestinationConfig {
  id: string;
  label: string;
  // source: "deploy" marks the ONE synthetic, engine-minted record (id DEPLOY_DEST_ID) standing in for
  // the deploy-time/env-configured destination (a wrangler DEST_R2 binding or DEST_* env vars) once the
  // FIRST console-managed destination is added alongside it (DEST-REPLACE-REASSIGN). It
  // carries no real credential (every DestinationConfig field on it is a blank placeholder) and its
  // config is NEVER built from those placeholders: fetchDestConfig (dest/factory.ts) treats a
  // source:"deploy" record as "no console override", the exact null it already returns for "no console
  // destination configured", so resolving it builds the SAME env-backed Destination (R2 binding or env S3)
  // a single-destination deployment always has, byte for byte. Its only job is to give that bucket a
  // stable id so a run's proven-copy bookkeeping can name it explicitly instead of falling back to
  // "whichever destination is the default right now" -- see ensureDeployDestSeeded's citation for why
  // that fallback is what made "Replace from the console" reassign 19 runs' history to an empty bucket.
  source?: "deploy";
}

// DEPLOY_DEST_ID is the one reserved, engine-minted id for the synthetic deploy-time destination record
// (source:"deploy" above). Reserved so a console-submitted id can never collide with it: putDest's
// caller-supplied id path is for EDITING an existing console destination, and the router only ever
// forwards an id it read back from a prior add/list response, so a customer-chosen collision is not a
// live path, but a defence in depth is a citation and an equality check, not a comment.
export const DEPLOY_DEST_ID = "deploy";

// DestinationCollection is the persisted shape under DESTINATIONS_KEY.
export interface DestinationCollection {
  list: StoredDestination[];
  defaultId: string;
  // priorDefaultIds: every destination id that HAS BEEN this estate's console default, most recent
  // first, bounded at PRIOR_DEFAULT_IDS_MAX. It exists for exactly one reader, the only-proven-copy
  // removal guard.
  //
  // WHY IT IS NEEDED, measured rather than argued. An UNPINNED downpipe (what the console wizard
  // creates) seals to whatever the default is and records NO origin id on its history row --
  // selectSealDestination returns `destinationId: primaryDestinationId(config)`, which is undefined
  // when nothing is pinned. uncoveredOriginRuns therefore has to ATTRIBUTE those rows to a
  // destination, and it did so using the CURRENT default. That is the right answer only while the
  // default has never moved: repointing the default from A to B and then removing A made every
  // default-routed run invisible to the guard, so the destination holding their only copy was
  // removed with no refusal, no force flag and `uncoveredOriginRunCount: 0` in the audit.
  //
  // A destination that has ever been the default may hold default-routed runs, so it stays a
  // candidate origin for as long as it is remembered here. This is a lower bound, not a proof of
  // which runs sealed where; the guard's direction on an unprovable question is the safe one
  // (block the removal), the same direction the holdsFrom floor bound already takes.
  priorDefaultIds?: string[];
}

// PRIOR_DEFAULT_IDS_MAX bounds the remembered default history so an estate that repoints its default
// repeatedly cannot grow this record without limit. It is generous against real use (a default move
// is a deliberate owner action, not an automatic one) and every entry is an engine-minted id.
// Overflow drops the OLDEST remembered default, which is the safe direction to lose: the oldest
// entry is the one whose runs are most likely to have aged out of the history rings the guard scans.
export const PRIOR_DEFAULT_IDS_MAX = 32;

// DEST_STATUS fields shared by the singular and list status views (redaction-safe: never a credential).
export interface DestStatusView {
  present: boolean;
  id?: string;
  label?: string;
  isDefault?: boolean;
  endpointHost?: string;
  bucket?: string;
  region?: string;
  setAt?: number;
  setBy?: string | null;
  verifiedAt?: number;
  deleteProbe?: TestDeleteProbe;
  // worm + objectLock are the redaction-safe immutability view: the configured policy (mode + days, the
  // INTENT) and the live store verdict (the REALITY). Non-secret. The console shows the policy but keys
  // the "immutable" badge on objectLock === "enforced" only (honest: a policy alone is not protection).
  worm?: WormPolicy;
  objectLock?: "enforced" | "not-enforced" | "unknown";
  // authMode + assumeRoleArn are the redaction-safe authentication view: "keys" (a stored long-lived key)
  // or "sts" (AssumeRole temporary credentials), with the role ARN (NOT secret) when STS. The externalId
  // and the principal secret are NEVER surfaced. honest: STS still stores a long-lived principal key, so
  // the console copy must not claim keys are eliminated.
  authMode?: "keys" | "sts" | "entra";
  assumeRoleArn?: string;
  // source: "deploy" passes StoredDestination.source through redaction-safe (it names a KIND, never a
  // credential): the console renders this row as the deploy-time binding it is, never offers Replace on
  // it (it has no stored credential to replace) and explains why Remove stays blocked until every run it
  // holds has a proven copy elsewhere -- the same guard every other destination's removal already runs.
  source?: "deploy";
  // azureEntra is the redaction-safe view of an Azure Blob destination's Microsoft Entra service
  // principal: the directory it signs in to and the application it is. NEITHER IS SECRET, and
  // dest/factory-validators.ts says so where the type is declared: the third value, the client secret,
  // rides in the credential slot and is never surfaced here or anywhere else.
  //
  // IT IS REPORTED SO THE CONSOLE CAN SEED ITS EDIT FORM, which is not a convenience. The write boundary
  // rebuilds the stored config from the submitted body, so a destination re-saved from a form that could
  // not show its existing principal would be stored WITHOUT one, and the next run would try to use the
  // client secret as a storage account key. assumeRoleArn is surfaced for exactly the same reason.
  //
  // "entra" is surfaced because the console renders an Authentication row keyed on authMode: without it, an
  // Entra destination reads "keys" and the card shows nothing distinguishing a service principal from a
  // stored storage-account key, when they carry different revocation stories.
  //
  // ENTRA WINS OVER STS WHEN BOTH ARE SOMEHOW SET. They are mutually exclusive in practice, because
  // assumeRole is an AWS mechanism and admin/router-destinations.ts refuses azureEntra on any endpoint
  // that is not Azure. The order is stated anyway rather than left to whichever branch happened to come
  // first: if a stored record carries both, the Entra principal is what the writes will actually use.
  azureEntra?: { tenantId: string; clientId: string };
  // addressing is the redaction-safe S3 request-addressing style (operator config, non-secret).
  addressing?: Addressing;
  // storageClass is the redaction-safe S3 storage class (operator config, non-secret).
  storageClass?: string;
  // pricing is the redaction-safe per-destination unit pricing (operator-supplied config, never a
  // secret), surfaced so the console cost estimate can prefill rates without re-asking the owner.
  pricing?: DestinationPricing;
  // lastPrune is the per-destination retention-prune sidecar (B61): what the most recent prune pass (cron
  // or attended) did against THIS destination's bucket, split so a deferral never erases the last
  // reclaim. Redaction-safe by construction (closed enums + clamped counts + timestamps). Additive and
  // optional on the wire: absent until a pass first records one, so an older engine and a not-yet-run
  // pass are indistinguishable to a reader, deliberately.
  lastPrune?: DestPruneState;
}

// ---- SIEM audit-log push destination (SIEM-PUSH-DESIGN.md) --------------------------------
// Outbound egress of the hash-chained audit events to a customer SIEM. Architecturally a sibling of an
// archive DESTINATION (console-set, owner-exclusive, a live secret the engine must reconstruct on every
// delivery), not the ingest-credential grant (which only ever stores a one-way hash).

// PUSH_FORMATS is the ONE AUTHORITY for the closed envelope-shape selector. raw-json is the pull feed's own
// body shape, POSTed instead of GET-returned;
// ndjson is one raw audit event object per line (the split-friendly DEFAULT for a new destination);
// json-array is a bare [event, ...] array; splunk-hec is one HEC event object per audit event; datadog is a
// JSON array of Datadog log objects; cef and leef are one ArcSight-CEF / IBM-LEEF line per event
// (injection-safe shapers); gelf is one Graylog GELF object per line. One shaper per member; see
// cron/siem-push-shape.ts.
//
// WHY THE ARRAY IS THE AUTHORITY AND THE TYPE IS DERIVED FROM IT, not the other way round: every runtime
// allow-list (the router boundary, the DO boundary, the support pack) reads this single array rather than
// holding its own hand-typed copy, so a new member reaches every boundary that imports it with one edit, and
// a boundary that re-types the list becomes a compile error rather than a silent subset that can drift.
export const PUSH_FORMATS = ["raw-json", "ndjson", "json-array", "splunk-hec", "datadog", "cef", "leef", "gelf"] as const;
export type PushFormat = (typeof PUSH_FORMATS)[number];

// PUSH_FORMAT_SET is the runtime membership test over that authority, for the boundaries that screen an
// unknown wire value (the router, the DO's buildPushRecord, the support pack's projection). A caller that
// needs the ORDER (an error message enumerating the choices) reads PUSH_FORMATS instead.
export const PUSH_FORMAT_SET: ReadonlySet<string> = new Set<string>(PUSH_FORMATS);

// PUSH_SINKS is the ONE AUTHORITY for the closed delivery-mechanism selector. "http"
// (the default) dials the endpoint out through the bespoke egress-secure sender with the one configured auth
// header; "s3" drops one NDJSON object per drain batch into an S3-compatible bucket the SIEM already reads
// (reusing the archive S3 PUT client); "syslog-tls" delivers CEF/LEEF lines as RFC 5424 records over a
// Cloudflare TCP socket (the enterprise auto-parse path, notify/siem-syslog-sender.ts). Same derivation
// discipline as PUSH_FORMATS above, and for the same reason: the pack's hand-typed copy of this list said
// "syslog" where the engine says "syslog-tls", so a syslog destination's sink never rode into the bundle.
export const PUSH_SINKS = ["http", "s3", "syslog-tls"] as const;
export type PushSink = (typeof PUSH_SINKS)[number];

// PUSH_SINK_SET is the runtime membership test over the sink authority, same role as PUSH_FORMAT_SET.
export const PUSH_SINK_SET: ReadonlySet<string> = new Set<string>(PUSH_SINKS);

// SYSLOG_TLS_FORMATS is the closed set of formats the syslog-tls sink can actually carry, and it is the
// cross-field rule behind pushSinkFormatError below.
//
// An RFC 5424 record's MSG is a CEF or a LEEF line; there is no HEC-over-syslog, no NDJSON-over-syslog and no
// GELF-over-syslog on the enterprise auto-parse path. Both boundaries (the router and the DO) refuse a
// format/sink combination no receiver can parse, and the sender's own record builder takes a narrowed
// two-member type so an unsupported format can never fall through to a default shaper.
export const SYSLOG_TLS_FORMATS = ["cef", "leef"] as const;
export const SYSLOG_TLS_FORMAT_SET: ReadonlySet<string> = new Set<string>(SYSLOG_TLS_FORMATS);

// pushSinkFormatError reports a format/sink combination no receiver can parse, or null when the pair is
// deliverable. Pure, and shared by the router (a 400 before the submission can be queued as a pending
// dual-control approval) and the DO's buildPushRecord (defence in depth, including a replayed approval), so
// the two boundaries cannot disagree. The message carries the word "format" deliberately:
// classifyPushRejectReason keys on it to file the refusal under the closed "format-invalid" audit class.
//
// THE RULE HAS TWO DIRECTIONS: which formats may travel over syslog-tls, and which sinks CEF and LEEF may
// travel to. Both boundaries call THIS function so the console and the API enforce the same closed set and
// cannot disagree.
export function pushSinkFormatError(format: string, sink: string): string | null {
  if (SYSLOG_TLS_FORMAT_SET.has(format) && sink !== "syslog-tls") {
    return `push destination format ${format} requires the syslog-tls sink: no SIEM auto-parses CEF or LEEF delivered over http or dropped into a bucket`;
  }
  if (sink === "syslog-tls" && !SYSLOG_TLS_FORMAT_SET.has(format)) {
    return `push destination format must be ${SYSLOG_TLS_FORMATS.join(" or ")} for the syslog-tls sink: an RFC 5424 record carries a CEF or LEEF line, and no other format can be sent over syslog`;
  }
  return null;
}

// PushS3Target is the S3-drop sink's destination. It mirrors the archive
// RuntimeDestConfig shape (endpoint/bucket/region/accessKeyId + the sealed secret + optional addressing/
// storageClass) so the drain can build the SAME S3Destination.put client with no bespoke SigV4. prefix is the
// optional key prefix the per-batch object lands under (default "downpipes-audit"). secretAccessKey is the
// ONE secret here: stored VERBATIM as a plaintext string (the no-wrap-key floor) or a WrappedSecret envelope
// sealed under the DISTINCT PUSH_S3_SECRET_AAD (config-secret.ts), so a push-header secret and an archive
// credential can never be cross-opened as this key, and vice versa.
export interface PushS3Target {
  endpoint: string; // https S3 endpoint (isAllowedWebhookUrl-screened: SSRF default-deny, https only)
  bucket: string;
  region: string; // "auto" for R2
  accessKeyId: string;
  secretAccessKey: string | WrappedSecret; // the one secret; sealed at rest under PUSH_S3_SECRET_AAD
  addressing?: Addressing; // "auto" | "path" | "vhost"; non-secret
  storageClass?: string; // an immediately-readable S3 storage class; non-secret
  prefix?: string; // key prefix for the per-batch object; default "downpipes-audit"
}

// PushSyslogTarget is the syslog-tls sink's destination (host + port, default 6514). No secret (syslog auth
// is network/mTLS, out of scope for this stage; the feed is the customer's own SIEM). The transport itself is
// stage B; this shape lets the config + console carry it now.
export interface PushSyslogTarget {
  host: string;
  port: number; // default 6514 (RFC 5425 syslog-over-TLS)
}

// PushDestinationRecord is the raw, at-rest DO record under SIEM_PUSH_CONFIG_KEY. authHeaderValue is
// stored VERBATIM as a plaintext string (the legacy/no-wrap-key floor) or a WrappedSecret envelope sealed
// under the DISTINCT PUSH_SECRET_AAD (config-secret.ts), exactly as a destination's secretAccessKey is
// sealed under CONFIG_SECRET_AAD: the DO never holds the wrap key, it only stores and returns the opaque
// value the router wrapped and the drain/test-send resolve at the moment of use.
export interface PushDestinationRecord {
  endpoint: string; // https URL, isAllowedWebhookUrl-validated (SSRF default-deny, no userinfo, not workers.dev)
  format: PushFormat;
  authHeaderName: string; // the header NAME only (e.g. "Authorization", "DD-API-KEY"); defaults to "Authorization"
  authHeaderValue: string | WrappedSecret; // the header VALUE (the secret); sealed at rest
  enabled: boolean; // draining on the cron tick
  // sink selects the delivery mechanism (default "http"). "s3" drops NDJSON batches into s3Target; "syslog-tls"
  // (transport is stage B) targets syslog. Absent on a legacy record reads as "http" (byte-compatible).
  sink?: PushSink;
  // authInUrl (http sink only) splices the auth secret (authHeaderValue) into the endpoint URL by the caller
  // instead of sending it as a header (the Devo-style path-token intake). When true the auth header is NOT
  // sent; the final URL carrying the token is NEVER logged, audited, trailed, or surfaced in the redacted view.
  authInUrl?: boolean;
  // s3Target is the S3-drop sink's destination (present only when sink === "s3"). Its secretAccessKey is the
  // sealed s3 secret (PUSH_S3_SECRET_AAD), independent of authHeaderValue's own keep-secret lifecycle.
  s3Target?: PushS3Target;
  // syslog is the syslog-tls sink's destination (present only when sink === "syslog-tls"). No secret.
  syslog?: PushSyslogTarget;
  // vendor is the console's OPAQUE identity tag for the destination the operator actually chose, set from the
  // Integrations vendor tile they configured it on (isValidPushVendor bounds it). The engine never interprets
  // it, never branches on it and never sends it on the wire: it stores it, echoes it in the redacted view and
  // carries it into the support pack, so the one thing the config could not previously say is on the record.
  //
  // WHY IT EXISTS. The push is a SINGLETON identified only by format crossed with sink, and that pair is not
  // injective over the vendor catalogue: Splunk and CrowdStrike Falcon Next-Gen SIEM both take
  // splunk-hec over http. One live Splunk push therefore lit BOTH tiles Active in the console and both panels
  // claimed the config, and the Splunk-only "paste the token as Splunk <token>" instruction rendered on the
  // CrowdStrike form, where it is actively wrong (Falcon takes a bearer token). Absent on a record stored
  // before this field existed, which reads as "the console cannot tell which vendor" rather than as any
  // particular vendor.
  vendor?: string;
  setAt: number; // epoch ms
  setBy: string | null; // the verified owner email that stored it (null on the token break-glass)
  // gen is a fresh random generation id minted on EVERY set/replace (crypto.randomUUID). It is the
  // straggler guard behind the clear+reconfigure data-loss race: a drain reads gen with the config, carries
  // it in the outcome it posts back, and the DO advances the cursor/trail ONLY when the CURRENT config's gen
  // still equals the outcome's gen. A delivery in flight when the owner clears + reconfigures therefore
  // cannot resurrect a stale cursor onto a freshly-configured (different-gen) destination and silently skip
  // events; its outcome no-ops instead, and the next tick re-reads from the new destination's own cursor.
  gen: string;
}

// PushDeliveryAttempt is one entry of the bounded delivery trail (SIEM_PUSH_TRAIL_KEY): the outcome of one
// drain tick, or the test-send. reason is a coarse DeliveryFailCode-style string, NEVER a raw response body.
export interface PushDeliveryAttempt {
  at: string; // ISO
  ok: boolean;
  httpStatus?: number; // the SIEM's HTTP status, when a request completed
  reason?: string; // a coarse reason on failure, never a response body
  count?: number; // events in the batch
  fromSeq?: number;
  toSeq?: number;
  // causeDigest (G164) is the 12-hex one-way SHA-384 prefix of the RAW fault the coarse `reason` was derived
  // from -- byte-identical to the `[cause <hex>]` the engine's own redacted log line carries for the same
  // fault, and the SAME construction the failed run rows already use. It is the JOIN KEY: the customer can
  // read their Workers Logs, support can read only the pack, and without a shared identifier neither side can
  // prove they are looking at the same failure. A closed vocabulary tells you the CLASS of the fault; this
  // tells you WHICH ONE. One-way and prefix-truncated, so the raw message (which can embed an endpoint, a
  // bucket or a key) is unrecoverable from it.
  causeDigest?: string;
}

// PushDestinationView is the REDACTED admin-facing view (GET /admin/push): the secret and its ciphertext
// NEVER appear here (a validator asserts this). setAt is rendered as an ISO string (unlike a destination's
// numeric epoch-ms setAt) to match the published engine API contract. lastPushedSeq/headSeq let the
// console show the cursor lag (how far behind head the push destination is).
export interface PushDestinationView {
  present: boolean;
  endpoint?: string;
  format?: PushFormat;
  authHeaderName?: string;
  enabled?: boolean;
  // sink echoes the delivery mechanism. authInUrl echoes whether the http sink carries the token in the URL
  // (a boolean posture, never the token). s3 echoes the S3-drop location (endpoint/bucket/region/prefix only,
  // NEVER the access key id or the secret). syslog echoes the host/port. All redaction-safe.
  sink?: PushSink;
  authInUrl?: boolean;
  s3?: { endpoint: string; bucket: string; region: string; prefix?: string };
  syslog?: { host: string; port: number };
  // vendor echoes the console's opaque destination-identity tag (see PushDestinationRecord.vendor). It is a
  // catalogue slug the console itself supplied, never operator free text and never a secret, so it is
  // redaction-safe. Absent when the record predates the field.
  vendor?: string;
  setBy?: string | null;
  setAt?: string | null; // ISO
  lastPushedSeq?: number;
  headSeq?: number;
  trail: PushDeliveryAttempt[];
}

export const SIEM_PUSH_CONFIG_KEY = "siemPushConfig";
export const SIEM_PUSH_CURSOR_KEY = "siemPushCursor";
export const SIEM_PUSH_TRAIL_KEY = "siemPushTrail";
// SIEM_PUSH_TRAIL_CAP bounds the delivery trail ring: the most recent 50 attempts are retained (the same
// .slice(-50) idiom the ingest-credential pull list uses), older entries roll off.
export const SIEM_PUSH_TRAIL_CAP = 50;

// ---- OTLP/HTTP metrics push destination (mon-otlp, PLAN.md M2) --------------------------------
// Outbound egress of the canonical backup-health metric snapshot (downpipe_backup_last_success_timestamp_
// seconds / _success / _attempt|success|failure_total / _duration_seconds / _size_bytes /
// destination_healthy) to a customer OTLP/HTTP collector (Datadog, New Relic, Dynatrace, Elastic, Splunk
// Observability, or any OTLP-compatible receiver), zero-agent, no scraper. Architecturally the SNAPSHOT
// sibling of the SIEM audit-log push above: both are console-set, owner-exclusive egress configs with a
// sealed bearer/API-key secret and a bounded delivery trail. UNLIKE the SIEM push it carries NO cursor: there
// is no log to drain, every cron tick re-reads the CURRENT metric state and pushes a fresh snapshot, so a
// missed tick is simply a gap in the customer's own time series, never a backlog or a redelivery concern.

// OtlpPushDestinationRecord is the raw, at-rest DO record under OTLP_PUSH_CONFIG_KEY. authHeaderValue is
// stored VERBATIM as a plaintext string (the legacy/no-wrap-key floor) or a WrappedSecret envelope sealed
// under the DISTINCT OTLP_PUSH_SECRET_AAD (config-secret.ts), exactly as the SIEM push header secret is
// sealed under PUSH_SECRET_AAD: the DO never holds the wrap key, it only stores and returns the opaque
// value the router wrapped and the drain resolves at the moment of use.
export interface OtlpPushDestinationRecord {
  endpoint: string; // https URL, isAllowedWebhookUrl-validated (SSRF default-deny, no userinfo, not workers.dev)
  authHeaderName: string; // the header NAME only (e.g. "Authorization", "Api-Key"); defaults to "Authorization"
  authHeaderValue: string | WrappedSecret; // the header VALUE (the bearer/API-key secret); sealed at rest
  enabled: boolean; // pushing on the cron tick
  setAt: number; // epoch ms
  setBy: string | null; // the verified owner email that stored it (null on the token break-glass)
  // gen is a fresh random generation id minted on EVERY set/replace (crypto.randomUUID), the SAME straggler
  // guard as the SIEM push destination's gen: a delivery in flight when the owner clears/reconfigures cannot
  // record its outcome against a freshly-configured (different-gen) destination's trail.
  gen: string;
}

// OtlpPushDeliveryAttempt is one entry of the bounded delivery trail (OTLP_PUSH_TRAIL_KEY): the outcome of
// one cron-tick push. reason is a coarse DeliveryFailCode-style string, NEVER a raw response body.
export interface OtlpPushDeliveryAttempt {
  at: string; // ISO
  ok: boolean;
  httpStatus?: number; // the collector's HTTP status, when a request completed
  reason?: string; // a coarse reason on failure, never a response body
  // downpipeCount is the ACTUAL number of downpipes shaped into the pushed body (post-cap), never the pre-cap
  // snapshot length, so the trail can never over-report what was sent (mon-otlp F3).
  downpipeCount?: number;
  // truncated is set when the snapshot exceeded OTLP_PUSH_DOWNPIPE_CAP and rows were dropped from this push;
  // an over-cap fleet is thus a LOUD trail signal, never a silent partial (mon-otlp F3).
  truncated?: boolean;
  // droppedCount is HOW MANY downpipes the cap dropped (G164: truncated:true rode alone, so support could not
  // answer "how many of our downpipes are missing from the dashboards?" once the fleet outgrew the 5000-point
  // cap -- a boolean cannot size a loss). A non-negative int; absent when nothing was dropped.
  droppedCount?: number;
  // causeDigest (G164) is the 12-hex one-way SHA-384 prefix of the RAW fault the coarse `reason` was derived
  // from -- byte-identical to the `[cause <hex>]` the engine's own redacted log line carries for the same
  // fault, and the SAME construction the failed run rows already use. It is the JOIN KEY: the customer can
  // read their Workers Logs, support can read only the pack, and without a shared identifier neither side can
  // prove they are looking at the same failure. A closed vocabulary tells you the CLASS of the fault; this
  // tells you WHICH ONE. One-way and prefix-truncated, so the raw message (which can embed an endpoint, a
  // bucket or a key) is unrecoverable from it.
  causeDigest?: string;
  // rejectedDataPoints records an OTLP partial_success: the collector answered 200 but dropped this many
  // datapoints server-side (a cardinality/quota reject). The push counts as delivered (ok true) yet this is a
  // real partial loss, so it is surfaced on the trail as its own LOUD signal rather than read as a clean
  // success (destsim finding F1, HARDENING.md item 15). Absent when nothing was rejected.
  rejectedDataPoints?: number;
}

// OtlpPushDestinationView is the REDACTED admin-facing view: the secret and its ciphertext NEVER appear
// here (a validator asserts this), mirroring PushDestinationView.
export interface OtlpPushDestinationView {
  present: boolean;
  endpoint?: string;
  authHeaderName?: string;
  enabled?: boolean;
  setBy?: string | null;
  setAt?: string | null; // ISO
  trail: OtlpPushDeliveryAttempt[];
}

export const OTLP_PUSH_CONFIG_KEY = "otlpPushConfig";
export const OTLP_PUSH_TRAIL_KEY = "otlpPushTrail";
// OTLP_PUSH_TRAIL_CAP bounds the delivery trail ring, mirroring SIEM_PUSH_TRAIL_CAP.
export const OTLP_PUSH_TRAIL_CAP = 50;

// OtlpDestinationHealth is ONE configured destination's last-known-good flag for a downpipe, read VERBATIM
// off DestReplState.lastOk (no recomputation): the destination_healthy series in the canonical metric set,
// labelled by destination. Absent from a downpipe's `destinations` list entirely when no repl: row exists
// yet for that destination (nothing proven either way), rather than asserting healthy or unhealthy.
export interface OtlpDestinationHealth {
  id: string;
  healthy: boolean;
}

// OtlpDownpipeMetrics is ONE downpipe's canonical backup-health facts (mon-otlp, PLAN.md M2), the
// snapshot input BOTH the OTLP push drain (cron/otlp-push-pass.ts) and, eventually, the Prometheus /metrics
// endpoint (M1, a sibling build) read from scheduler-do-otlp-push.ts's otlpMetricsSnapshot(). Every field
// besides id/name/attempts/success/failure is OPTIONAL and OMITTED (never a false zero) when the downpipe
// has no run to report it from: absence is the honest "no data yet", exactly the Prometheus/OTLP convention
// of a missing series rather than a misleading default value.
export interface OtlpDownpipeMetrics {
  id: string;
  name: string;
  // enabled is the downpipe's own config.enabled, surfaced as the downpipe_enabled gauge so a consumer can
  // tell a PAUSED/decommissioned downpipe (whose last-known success would otherwise read as eternally fresh)
  // from a live green job before firing a staleness alert (mon-otlp F4a).
  enabled: boolean;
  // lastSuccessTimestampSeconds is the newest OK run's completion time (startedAt + durationMs, falling back
  // to startedAt alone when durationMs is absent), epoch SECONDS. Absent when no run has ever succeeded.
  lastSuccessTimestampSeconds?: number;
  // backupSuccess is whether the newest RESOLVED (non-in-flight) run succeeded: 1 ok, 0 failed/abandoned.
  // Absent when no run has ever resolved (a brand-new or still-in-flight-only downpipe). Deliberately NOT a
  // staleness judgement (no threshold/freshness math here): the SRE's own alerting applies
  // time - last_success > threshold, the idiom PLAN.md names.
  backupSuccess?: 0 | 1;
  // attemptsTotal/successTotal/failureTotal are WINDOWED counts over the bounded run-history ring (RING_CAP
  // entries per downpipe), NOT a true cumulative lifetime counter (the engine keeps no separate persistent
  // tally). Always present (0 when the ring is empty); see otlp-push-shape.ts for why they ship as OTLP
  // gauges rather than monotonic sums despite the conventional "_total" metric name.
  attemptsTotal: number;
  successTotal: number;
  failureTotal: number;
  // durationSeconds / sizeBytes are the newest RESOLVED run's wall-clock duration and archive byte total
  // (archiveBytesWritten, falling back to the plaintext bytes total when absent). Absent on a legacy row
  // that predates these optional fields, or when there is no resolved run yet.
  durationSeconds?: number;
  sizeBytes?: number;
  destinations: OtlpDestinationHealth[];
}

// FORBIDDEN_PUSH_HEADER_NAMES is the closed set of header names the operator's configured auth header MUST
// NOT use, checked case-insensitively at BOTH validation boundaries (the router and the DO). content-type
// is the critical one: the sender sets content-type itself per format (siem-push-sender.ts), so an auth
// header named content-type would collide and silently corrupt the request. The rest are the Fetch
// forbidden / hop-by-hop request headers the runtime controls, which a customer SIEM auth header would
// never legitimately be (an HEC token, a Datadog key, a bearer live under Authorization / DD-API-KEY / a
// vendor header, none of these). Authorization and DD-API-KEY are deliberately NOT here.
const FORBIDDEN_PUSH_HEADER_NAMES: ReadonlySet<string> = new Set([
  "content-type",
  "content-length",
  "host",
  "connection",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "expect",
]);

// isForbiddenPushHeaderName reports whether an auth header NAME collides with a header the sender sets or
// the runtime forbids (case-insensitive). Pure; shared by the router and the DO so the two agree.
export function isForbiddenPushHeaderName(name: string): boolean {
  return FORBIDDEN_PUSH_HEADER_NAMES.has(name.toLowerCase());
}

// PUSH_HEADER_VALUE_MAX_LEN caps the operator-supplied auth header VALUE (a bearer token / API key). 8 KiB is
// generous for any real token (even a long JWT is ~1-2 KiB) while refusing a pathological value that would
// bloat the sealed record.
export const PUSH_HEADER_VALUE_MAX_LEN = 8192;

// PUSH_HEADER_VALUE_CONTROL_RE matches any character illegal in an HTTP field value: the C0 control set
// (\x00-\x1f, which includes CR, LF and TAB) and DEL (\x7f). A legitimate auth token is base64 / hex / a JWT /
// a "Scheme <token>" string -- all printable, and SPACE (0x20) is deliberately allowed so "Basic <b64>",
// "Splunk <token>" and "GenieKey <token>" pass. A CR/LF here is header-injection shaped and would otherwise
// surface only as an opaque send-time network error; screening it at config time turns it into a clear 400.
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting the C0 controls is the deliberate auth-header-value injection guard (a CR/LF in a header value must never reach the sender).
const PUSH_HEADER_VALUE_CONTROL_RE = /[\x00-\x1f\x7f]/;

// isValidPushHeaderValue reports whether a NON-EMPTY plaintext auth header value is safe to store and send:
// within the length cap and free of control characters. An empty value is NOT valid here (the empty case is a
// keep-secret / missing-secret signal the caller handles BEFORE this runs), so callers only pass a genuinely
// supplied value. Pure; shared by the routers (before sealing the value) and the DO (the plaintext no-wrap-key
// floor), so the two boundaries agree -- exactly the discipline isForbiddenPushHeaderName keeps for the name.
export function isValidPushHeaderValue(value: string): boolean {
  return value.length > 0 && value.length <= PUSH_HEADER_VALUE_MAX_LEN && !PUSH_HEADER_VALUE_CONTROL_RE.test(value);
}

// PUSH_VENDOR_RE bounds the console's opaque destination-identity tag (PushDestinationRecord.vendor): a
// lowercase slug of 1 to 64 characters, letters, digits and single hyphens, which is exactly the shape the
// console's catalogue slugs take. The engine never interprets the value, so the only question here is whether
// it is safe to store and echo: a bounded slug cannot carry a control character, a quote, an angle bracket, a
// URL, an email or a secret, so it stays redaction-safe in the view, in the support pack and in the
// owner-approval inbox summary without any escaping at those seams.
const PUSH_VENDOR_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const PUSH_VENDOR_MAX_LEN = 64;

// isValidPushVendor reports whether a supplied vendor tag is within those bounds. An absent tag is valid and
// is NOT this function's business (the callers treat undefined as "the console did not say"); only a supplied
// value is checked, so a crafted or over-long tag is refused at both boundaries rather than stored.
export function isValidPushVendor(value: string): boolean {
  return value.length <= PUSH_VENDOR_MAX_LEN && PUSH_VENDOR_RE.test(value);
}

export const RATE_LIMIT_PREFIX = "ratelimit:";

// RATE_LIMIT_WINDOW_MS is the fixed window the per-caller counter resets on (60 seconds). A
// fixed window is chosen over a sliding/token-bucket on purpose: it is one storage read + one
// write per check (cheap on the single-threaded DO), it is trivial to reason about, and the
// coarse boundary behaviour (a burst can straddle two windows) is acceptable for an internal
// authenticated admin API whose goal is anti-automation, not precise shaping.
// Exported so the router can emit an accurate IETF RateLimit-Policy header (limit;w=window-seconds)
// from the same source of truth, with no second literal to drift.
export const RATE_LIMIT_WINDOW_MS = 60_000;

// RATE_LIMIT_MAX_PER_WINDOW is the default ceiling on MUTATING admin requests one caller may make
// per window (120 per minute, i.e. two per second sustained). It sits far above any plausible
// human console session (a person clicking through the SPA never approaches two writes a second)
// while still capping a scripted caller hammering the write surface. cost lets a single check
// account for more than one logical request if a future route needs it; it defaults to 1.
export const RATE_LIMIT_MAX_PER_WINDOW = 120;

// AUTH_RATE_LIMIT_MAX_PER_WINDOW is the per-IP ceiling on UNAUTHENTICATED /admin/auth/* ceremony requests
// (register/login begin+finish) in one window. These run heavy crypto and have no verified caller to key
// on, so they are limited per source IP (CF-Connecting-IP) to bound a CPU-DoS and slow enumeration. 30 per
// minute per IP is far above any human sign-in cadence (a person completes one ceremony in a few seconds)
// while capping a scripted flood. It is deliberately separate from RATE_LIMIT_MAX_PER_WINDOW (the
// per-caller mutating-write cap) and keyed in a separate `ip:` namespace so the two never collide. The
// per-IP key is acceptable HERE (unlike the authenticated admin routes, where the cost/rate-limit audit
// warns a per-IP limiter harms shared-NAT customers) because there is no authenticated identity yet AND it
// FAILS OPEN, so a shared egress is at worst briefly throttled on sign-in attempts, never locked out.
// Exported so the router's authRateLimited passes the same cap to /rate-check (no second literal to drift).
export const AUTH_RATE_LIMIT_MAX_PER_WINDOW = 30;

// ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW is the per-IP ceiling on the bare ADMIN_TOKEN break-glass compare
// in one window (ASVS V6.3.1: authorise()'s bare-token branch had no throttle at all). Keyed per-IP, like
// AUTH_RATE_LIMIT_MAX_PER_WINDOW, because there is no verified identity to key on until AFTER the compare
// succeeds - but capped far tighter, because this credential is a rare break-glass bootstrap, never a
// high-frequency automation surface by design, so 10 attempts a minute costs a legitimate operator
// nothing while sharply narrowing an online guessing window. Kept in its own `admin-token-ip:` key
// namespace (never `ip:`) so it neither shares nor drifts the auth-ceremony bucket above.
export const ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW = 10;

// RECOVERY_PREFIX keys the per-EMAIL recovery-code record (`recovery:<canonical-email>`), one record per
// email, alongside the role:/dp:/orgpolicy keys. The record holds only salted HMAC hashes + consumed flags
// (recovery.ts owns the shape); it never holds a plaintext code. Per email so one user's codes are never in
// another user's record and a recover/regenerate/count is always scoped to one email.
export const RECOVERY_PREFIX = "recovery:";

// RECOVERY_STAGED_PREFIX keys a MINTED-BUT-NOT-YET-LIVE recovery set (`recovery-staged:<canonical-email>`),
// one per email. STAGED-RECOVERY-CODES-CONFIRM-GATE: an enrolment that runs while a live record
// ALREADY exists (self-add -- including the forced re-enrolment after a recovery-code sign-in), the staged
// key lets the DO show the fresh plaintext (generateRecoveryStaged) without touching the live record; only
// confirmRecoveryStaged (POST /admin/auth/recovery-codes/confirm, fired by the console's save-confirm
// "Continue") promotes it to live, which is the ACTUAL invalidation boundary. A staged set the operator
// never confirms is simply abandoned: the live (old) set keeps working, which is the safe failure. A
// bootstrap or invite enrolment has no prior record to protect, so it mints straight to the live key via
// generateRecoveryFor; this key exists only for the case where there is something to lose.
export const RECOVERY_STAGED_PREFIX = "recovery-staged:";

// There is deliberately NO recovery-ack latch key here any more. `recovery-owner-ack` was an account-level
// boolean set the moment an Owner's codes were generated and never re-evaluated, and the lockout pre-flight
// plus the break-glass-token dispose gate both read it as proof that a way back in existed
// (LOCKOUT-PREFLIGHT-COUNTS-RECORDS-NOT-USABLE-FACTORS). Because it recorded a past event rather
// than a present fact it stayed true through every way that fact can stop being true. The verdict is now
// derived live by SchedulerDO.recoveryBreakGlassVerdict from the role table, the record and the signing key,
// so no key holds this answer and none should be reintroduced.

// RECOVERY_RATE_PREFIX / the recovery rate caps: the recover endpoint is a brute-force target on a
// high-value credential, so it is limited HARDER than ordinary sign-in AND FAILS CLOSED (unlike the
// fail-open per-IP auth limiter): if the limiter's own store hiccups, deny rather than admit, because an
// oracle/guessing attack must never benefit from knocking the limiter over. Two independent buckets are
// checked, both must pass: per source IP (RECOVERY_RATE_MAX_PER_IP) and per target email
// (RECOVERY_RATE_MAX_PER_EMAIL), each over RECOVERY_RATE_WINDOW_MS. The per-email bucket stops a distributed
// guess against ONE account; the per-IP bucket stops one host spraying many accounts. Caps are deliberately
// low (a human using a recovery code needs one or two tries).
//
// recoveryRateCheck answers a bare `{ allowed: false }` on refusal, with no retryAfterMs anywhere on this
// path: recoveryRateAllow narrows to a boolean, recoveryRecover returns { ok:false, alert }, and
// handleRecovery answers a bare 401 with no Retry-After header. This is deliberate: recovery is
// anti-enumeration by design (a wrong code, an unknown email, an exhausted set and a throttle all return ONE
// generic 401 so no oracle exists), and a Retry-After on the per-EMAIL bucket would tell an unauthenticated
// caller that somebody is currently attempting recovery on that address.
//
// The limiter is NOT self-deepening: a denied attempt does not increment the counter and does not push
// windowStart, so a caller who keeps retrying cannot extend their own lockout, and the wait is bounded at
// RECOVERY_RATE_WINDOW_MS. That matters because the console's copy on a failed recovery ends "then try
// again": walking a partly-spent sheet costs nothing extra even when several codes in a row are already
// spent.
export const RECOVERY_RATE_PREFIX = "recovery-rate:";
export const RECOVERY_RATE_WINDOW_MS = 60_000;
export const RECOVERY_RATE_MAX_PER_IP = 5;
export const RECOVERY_RATE_MAX_PER_EMAIL = 5;

// RING_CAP bounds the per-downpipe run-history ring so DO storage never grows unboundedly:
// only the most recent RING_CAP runs survive (newest at the tail; the head is shifted off
// once the cap is exceeded). It is a recent-activity view, not the durable record (the
// signed RUNLOG in the archive is the authority); 50 is enough for an at-a-glance console.
export const RING_CAP = 50;

// FLEET_DRILL_ACTIVE_KEY / FLEET_DRILL_LAST_KEY are the single-object storage keys for an on-demand bulk
// restore-test campaign (SCALE-2): the in-progress campaign and the most-recently finished one. Singletons
// (one campaign at a time) so an operator cannot accidentally fan two overlapping fleet drills.
export const FLEET_DRILL_ACTIVE_KEY = "fleetdrill:active";
export const FLEET_DRILL_LAST_KEY = "fleetdrill:last";
// FLEET_DRILL_MAX bounds how many downpipes one campaign may enqueue, so the single campaign record (which
// holds the pending id worklist) cannot grow past a sane DO value size. A larger fleet must be drilled in
// narrower selections (the start route accepts a downpipeIds subset). 5000 ids is well under the DO value
// limit and far beyond any realistic single drill.
export const FLEET_DRILL_MAX = 5000;
// FLEET_DRILL_FAILED_SAMPLE caps how many not-passed downpipe ids the campaign record retains for at-a-glance
// surfacing; the full per-downpipe pass/fail outcome lives in the durable drill-evidence log, so this is only
// a convenience sample and stays small regardless of fleet size.
export const FLEET_DRILL_FAILED_SAMPLE = 25;
// FLEET_DRILL_INFLIGHT_TIMEOUT_MS is how long a dispatched-but-never-completed fleet-drill member stays
// "in flight" before the next batch re-queues it (self-heal): a drill normally completes within the same
// cron tick it is dispatched, so this only bites when a completion callback was lost (a DO blip) or the
// per-tick budget ran out after the batch was marked in flight but before every member was drilled. 30
// minutes comfortably exceeds the */15 tick so a healthy intra-tick completion is never spuriously re-queued.
export const FLEET_DRILL_INFLIGHT_TIMEOUT_MS = 30 * 60 * 1000;

// DO_LIST_PAGE is the page size for the paginated full-prefix scan (listAllByPrefix). The
// Cloudflare DO storage list() returns at most one page; 1000 is the platform's own default page
// limit, so a prefix with more than one page's worth of entries (an account beyond ~1000
// downpipes, ENG-SCALE-08) is enumerated by looping with a startAfter cursor instead of silently
// truncating at the first page. DO_LIST_MAX_PAGES bounds the loop (defence in depth against a
// degenerate backing store that never returns a short page): 1000 pages * 1000 = up to a million
// entries, far beyond any real fleet, so a real account never hits it and a pathological store
// terminates rather than spinning.
export const DO_LIST_PAGE = 1000;
export const DO_LIST_MAX_PAGES = 1000;

// ---- Persisted due-time index (ENG-SCALE-09: due() in O(due), not O(N)) ----------------------------
// A naive due() would scan EVERY downpipe (listDownpipes -> listAllByPrefix("dp:")) on every cron tick to
// find the few whose nextRunAt has fallen due, which is O(N) per tick and caps the single account-wide
// SchedulerDO at a few thousand downpipes. A SECONDARY index keyed by due time lets the dispatcher read only
// the due candidates:
//
//   due:<pad16(nextRunAt)>:<id>   value 1
//
// pad16 left-pads the epoch-ms nextRunAt to 16 digits so the keys sort lexicographically in the SAME
// order as chronologically (the DO list() returns keys ascending). An index entry exists ONLY for a
// downpipe that is ENABLED and has a NUMERIC nextRunAt; a disabled downpipe, or one whose nextRunAt
// is null/non-numeric, has NO index entry. due(now) then lists the half-open range
// ["due:", "due:" + pad16(now+1)) which is exactly the entries with nextRunAt <= now (O(due)).
//
// DRIFT SAFETY (the index is an OPTIMISATION, never the source of truth):
//   - due() re-fetches each candidate's dp: state and re-applies the EXACT existing predicate
//     (enabled && !leased && nextRunAt <= now), so a STALE index entry can never cause a wrong
//     dispatch (a deleted/disabled/rescheduled downpipe is filtered out against live state).
//   - rebuildDueIndex() full-scans dp: and rebuilds every due: key from the dp: truth. It runs
//     LAZILY on first deploy (index empty but dp: non-empty -> existing downpipes had no index yet)
//     AND periodically (every RECONCILE_EVERY_TICKS ticks), so any drift (a missed write, a manual
//     storage edit) self-heals within at most that many ticks. A drifted downpipe is therefore at
//     most RECONCILE_EVERY_TICKS ticks late, NEVER silently lost.
export const DUE_INDEX_PREFIX = "due:";
// RECONCILE_EVERY_TICKS is how often (in alarm/tick wakeups) due() runs the O(N) rebuildDueIndex
// backstop. 20 keeps the reconcile infrequent (so even at 100k downpipes the O(N) rebuild is rare
// relative to the O(due) fast path) while bounding worst-case drift to a handful of ticks. The
// lazy first-deploy reconcile (empty index, non-empty dp:) is separate and unconditional, so the
// index is always present after the first due() on a populated DO regardless of this counter.
export const RECONCILE_EVERY_TICKS = 20;
// DUE_RECONCILE_TICK_KEY persists the small tick counter due() bumps so the periodic reconcile
// survives isolate eviction (a fresh isolate does not restart the count from 0 and skip reconciles).
export const DUE_RECONCILE_TICK_KEY = "dueReconcileTick";

// TICK_OUTCOME_KEY holds the bounded per-cron-tick OUTCOME ring (scheduler-helpers.ts appendTickOutcome):
// the cron driver posts a TickReport at the end of each invocation and the DO keeps the most-recent
// TICK_RING_CAP derived TickOutcomes, so the support pack can see a false-green tick (dispatched nothing,
// overdrew the budget, a pass crashed, or a missed-tick interval gap). Redaction-safe (counts + flags only).
export const TICK_OUTCOME_KEY = "tickOutcomeRing";
// DUE_INDEX_HEALTH_KEY holds the last-reconcile due-index parity snapshot (indexCount vs enabled-dp count +
// when), stamped by maybeReconcileDueIndex/rebuildDueIndex, so the pack can see a drifted/partial index
// (SCHED due-index-drift / rebuild-partial-or-too-big) without an O(N) scan on the read path.
export const DUE_INDEX_HEALTH_KEY = "dueIndexHealth";
// STORAGE_FAULT_KEY holds the DISTINCT, cumulative persisted storage-fault counter (scheduler-helpers.ts
// applyStorageFault): a bounded {total, valueTooLarge, putFailed, lastAt, lastKind} record the persist-state
// writer (persistDownpipeState) bumps when a storage.put THROWS. It PROMOTES the indirect tick sealErrors/
// passErrors -- which conflate a storage fault with any other dispatch error -- into a fault-CLASS signal that
// isolates the persist/storage subset (SCHED persist-state-storage-fault) and, via the valueTooLarge sub-count,
// the DO-value-too-large subset (INFRA do-value-size-limit). The counter write is best-effort: a value-too-large
// fault is per-KEY (the small counter write succeeds), and a transient blip clears; only a TOTAL storage outage
// prevents even the counter write, where the existing tick sealErrors/passErrors + the interval gap remain the
// evidence. Redaction-safe (ints + a closed lastKind enum + a clamped timestamp; no id/name/value ever rides).
export const STORAGE_FAULT_KEY = "storageFaultCounter";
// SCHED_HEALTH_KEY holds the scheduler HOUSEKEEPING-health counters (scheduler-helpers.ts applySchedHealth): a
// bounded {sweepFaults, listTruncations, parityStampFailures} record of the three faults that are otherwise fully
// silent (G040) -- an alarm housekeeping sweep that keeps THROWING (DO storage grows unbounded for months until
// the limits bite), a listAllByPrefix enumeration TRUNCATED by the DO_LIST_MAX_PAGES guard (downpipes past the cap
// are never enumerated, so they are never scheduled and read as nonexistent), and a due-index parity stamp whose
// write FAILED (the pack then serves the prior snapshot as if it were fresh). Every write is best-effort and can
// never break the path it observes. Redaction-safe: counts + clamped timestamps only.
export const SCHED_HEALTH_KEY = "schedHealthCounters";
// STATE_REFUSED_PREFIX namespaces the per-downpipe read-time REFUSAL stamp (G095 / G210): staterefused:<id> holds
// {class, at, count, storedVersion, supportedVersion} for a downpipe whose persisted dp:<id> record was refused by
// migrateOrRejectConfig -- a record stamped by a NEWER engine (this one was rolled back) or carrying a malformed
// version stamp. Such a downpipe is silently skipped by due() and 500s on trigger(): NO run row is ever created,
// so the pack sees only growing staleness with zero failed runs and the one fact that explains it lives only in a
// Workers Logs line the vendor cannot pull. The stamp is a SEPARATE key on purpose: writing it back onto the dp:
// record would re-stamp that record with THIS engine's schemaVersion and clobber the very new-shape state the
// guard exists to protect. A successful trigger() read CLEARS the stamp, so a repaired downpipe stops reporting.
export const STATE_REFUSED_PREFIX = "staterefused:";
// STATE_REFUSED_READ_CAP bounds how many refusal stamps the support-pack read returns (a fleet-wide rollback would
// otherwise emit one row per downpipe). The count is reported alongside so a truncated list is honest.
export const STATE_REFUSED_READ_CAP = 25;

// ---- DEP-04: the cron-independent staleness dead-man (the dead-man's-dead-man) -----------------
// The staleness/failure alert sweep (reconcileAlerts) runs ONLY from the Worker cron path
// (scheduled() -> drive() -> runAlertPass -> POST /reconcile-alerts). A deploy that drops a
// downpipe's [triggers].crons silences that path, which stops the backups AND the only detector of
// the resulting staleness together (the detector is driven by the very heartbeat it monitors). The
// SchedulerDO's own platform alarm() is the ONE timer that survives such a deploy, so it carries a
// throttled BACKSTOP: when the cron-driven sweep has gone silent it runs reconcileAlerts itself.
//
// CRON_CADENCE_MS is the shipped Worker cron-trigger cadence (wrangler.toml: crons = ["*/15 * * * *"]).
// The dead-man thresholds below are multiples of it, so an operator who retunes the cron updates the
// cadence in one place. It is the EXPECTED interval between cron-driven alert sweeps. Module-local (a
// derivation input for the two thresholds, not part of the public surface), so it is not re-exported.
const CRON_CADENCE_MS = 15 * 60 * 1000;
// CRON_ALERT_SWEEP_AT_KEY persists the epoch-ms of the LAST cron-driven alert sweep (stamped by the
// /reconcile-alerts route, which only the cron reaches; the alarm backstop calls reconcileAlerts()
// directly and never stamps it, so this is a pure cron-liveness heartbeat the alarm reads).
export const CRON_ALERT_SWEEP_AT_KEY = "cronAlertSweepAt";
// CRON_DEADMAN_STALL_MS is how long the alarm waits without a cron-driven sweep before presuming the
// cron driver DEAD and sweeping itself. Three missed cadences (45 min) mirrors the per-downpipe
// STALE_CADENCE_MULTIPLE (3): "about two expected beats missed" is a genuine silence, not one slow or
// skipped */15 tick (a transient DO outage skips a tick), so the backstop never fires on a healthy cron.
export const CRON_DEADMAN_STALL_MS = 3 * CRON_CADENCE_MS;
// CRON_DEADMAN_SWEEP_AT_KEY persists the epoch-ms of the last BACKSTOP sweep the alarm ran, so the
// backstop can throttle itself (see below). Distinct from the cron heartbeat above: conflating them
// would make a backstop sweep look like a cron drive and silence the next backstop.
export const CRON_DEADMAN_SWEEP_AT_KEY = "cronDeadManSweepAt";
// CRON_DEADMAN_SWEEP_INTERVAL_MS throttles the backstop sweep once the cron looks dead. While downpipes
// sit overdue (their nextRunAt is never advanced because completeRun never runs) rearmAlarm floors the
// next alarm to now + ALARM_MIN_DELAY_MS, so the alarm re-fires ~1 Hz; without this throttle the backstop
// would sweep on every wakeup. Capped at the cron's OWN cadence, the backstop stands in for the missing
// */15 tick (one sweep per ~15 min) rather than hammering the fleet, so it adds no redundant load.
export const CRON_DEADMAN_SWEEP_INTERVAL_MS = CRON_CADENCE_MS;

// pad16 left-pads an epoch-ms timestamp to a fixed 16-character decimal string so due: index keys
// sort lexicographically in chronological order. 16 digits covers epoch ms up to the year 33658
// (>10^15), far beyond any real schedule, and a value that somehow overflows 16 digits simply sorts
// last (still after `now`), so it is never wrongly treated as due. Defined as a module function (not
// a method) so it has no `this` and is trivially unit-reasoned.
export function pad16(epochMs: number): string {
  return String(epochMs).padStart(16, "0");
}

// AUDIT_CAP is the retention cap on the tamper-evident audit chain this DO holds (P4 / DEF-03 /
// C8-02). It is defined canonically in audit.ts (the audit domain) and re-exported HERE because the
// DO is where the cap is ENFORCED: appendAudit rolls over the oldest entries once the retained count
// would exceed it. Re-exporting keeps the constant available "in the DO" without a second literal to
// drift from the audit module's value.
export { AUDIT_CAP };

// AUDIT_ROLLOVER_KEY records the retention rollover state under a single DO storage key: the earliest
// seq still retained and how many entries have been rolled over (pruned) in total. It is written only
// when a rollover actually occurs, so a log that has never reached the cap has no record and reads as
// "no rollover" (earliestRetainedSeq follows the true genesis). verifyAudit reads it to tell
// verifyChain whether genesis is legitimately gone and to surface the rolled-over count to the
// console; status reads the live count (not this record) to decide auditNearCap. Exported so the
// audit validator can assert the rollover-aware verify path without a magic-string literal.
export const AUDIT_ROLLOVER_KEY = "auditRollover";

// AuditRolloverState is the persisted retention-rollover record (see AUDIT_ROLLOVER_KEY). It carries
// only counts/seqs; no entry content, no key material, no value, so it is redaction-safe like the
// rest of the DO's audit state.
export interface AuditRolloverState {
  earliestRetainedSeq: number; // the lowest seq still held after the most recent rollover
  rolledOverCount: number; // how many entries have been pruned across all rollovers, cumulative
}

// AUDIT_VERIFY_META_KEY records the last chain-verify's cost/completeness (CPR needs-logging:
// verify-cpu-cost-near-cap). verifyAudit recomputes SHA-384 over the whole retained chain, which is
// CPU-heavy near the AUDIT_CAP; a verify that runs long or is near the cap risks the platform CPU wall.
// This holds the last verify's duration, entries checked and completeness flag + a timestamp, so the
// support pack can see "a full audit verify is CPU-costly on this account" (an int/flag/timestamp only).
export const AUDIT_VERIFY_META_KEY = "auditVerifyMeta";

// AuditVerifyMeta is the persisted last-verify cost record. Redaction-safe (ints + a flag + a timestamp).
export interface AuditVerifyMeta {
  at: string; // when the verify ran
  entriesChecked: number; // how many retained entries were hashed
  durationMs: number; // wall time the recompute took
  complete: boolean; // whether the verify ran to completion (a future CPU-killed verify never records, so a stale meta + near-cap tells the story)
}

// AUDIT_HEAD_KEY persists the audit chain HEAD pointer (E3/E6): the highest seq, its hash, and the
// live retained count, in ONE DO key updated transactionally alongside each entry put. It makes
// appendAudit O(1): the next entry chains off head.hash and is keyed head.seq+1 WITHOUT a full list
// over the chain (which, at AUDIT_CAP=10000 entries with values, was an O(n) read on a HOT auth/config
// path). The chain INTEGRITY is unchanged: the next entry's prevHash is still the prior head's hash
// and the seq is still strictly monotonic, so verifyChain (the tamper-evidence proof) is byte-for-byte
// identical; only the way the head is LOCATED changes (a pointer read, not a scan). It carries only
// seq/hash/count, the hash is the head entry's own already-public chain hash, no entry content, no
// key material, so it is redaction-safe like the rollover record. A deployment upgraded mid-life has
// no pointer yet, so appendAudit reconstructs it ONCE from the existing entries (the only remaining
// full list, taken at most once per isolate-lifetime on the first post-upgrade append) and persists it.
export const AUDIT_HEAD_KEY = "auditHead";

// AuditHead is the persisted head pointer. headSeq 0 / count 0 is the empty-chain sentinel (no entry
// yet, so the next append is genesis). headHash is the head entry's chain hash, the prevHash the next
// entry links to. count is the number of RETAINED entries (post-rollover), the value AUDIT_CAP bounds
// and auditNearCap reports, kept in lockstep with the rollover so it never drifts from storage.
export interface AuditHead {
  headSeq: number; // the highest seq in the chain, or 0 when empty
  headHash: string; // the head entry's hash (the next entry's prevHash), or GENESIS_PREV_HASH when empty
  count: number; // the number of retained entries
}
