// Credential and key LIFECYCLE registry (contract section 4, extended into a credential-aware registry).
// A redaction-safe list of dated items (a destination access key, the signer or break-glass key, a
// licence, a TLS/SAML certificate, an ephemeral Cloudflare token) the platform watches so an expiring
// or spent credential surfaces BEFORE it lapses and silently breaks a backup or a recovery. Beyond the
// original operator-typed expiry, the registry now records what a credential is FOR (purpose +
// lifecycle class + a usage link), a redaction-safe permission summary, and, for an engine-OBSERVED
// item, the expiry the engine read off a verifiable artefact it ALREADY legitimately holds (a SAML
// signing cert's notAfter, the licence token's notAfter, a minted bearer's expiresAt, a Cloudflare
// token's expires_on read once at attach time). The engine still NEVER reads an expiry off a secret it
// retains for that purpose, and never holds a Cloudflare API token to do so.
//
// NO-CUSTODY + REDACTION (sacred). An ExpiryItem carries ONLY redaction-safe metadata: a label, a kind
// enum, an OPTIONAL RFC-3339 expiry, a source enum, a lifecycle class, an optional purpose, an optional
// permission SUMMARY (descriptive text, e.g. "Workers Scripts: Edit", never a secret), an optional
// usage-link id (a STABLE entity id such as a destinationId/connId/binding name, never a value), an
// optional Cloudflare token-id DESCRIPTOR (the PUBLIC token id, modelled on idpconn.ts SecretRef.ref, 
// never the token value, and the registry can never act on it), and optional observed/used timestamps +
// a cleanup state. It NEVER carries a credential value, key material, or a fingerprint/hash/prefix/
// length of a secret; the type has no field that could. The notification detail derived from it is the
// label + the days-remaining only.
//
// FAIL-OPEN (sacred). The cron's expiry emission is observability, never a control: it is computed from
// stored items and routed through the same fail-open notification path as the stale/failure stream, so
// a tracker hiccup or a delivery failure degrades to "no expiry notice this tick", never a blocked or
// crashed backup. The transition machinery mirrors the alert cooldown exactly (emit on a NEWLY-crossed
// threshold, not every tick).
//
// This module is pure logic plus the storage-shape constants, so the DO (storage), the cron driver
// (index.ts) and the status probe share one definition of "approaching", one threshold ladder and one
// transition rule, and none of them can compute those three things two different ways. Node 25
// strip-types compatible: no enums, no parameter properties, explicit declarations.
// exactOptionalPropertyTypes: optional keys are spread in only when they carry a value.

// ExpiryKind is the closed set of things worth tracking an expiry for. credential = a destination
// access key or similar bearer credential; key = a signing/encryption key (the signer, a break-glass
// recipient); licence = the assurance licence; certificate = a TLS/SAML/client certificate; token = a
// short-lived Cloudflare/portal token (the ephemeral attach/deploy token, a minted scoped bearer). The
// kind groups the item AND selects the first notification rung (long-lead certificate/licence start at
// 60 days, everything else at 30, see laddersFor); the COARSE "approaching"/posture boundary stays 30
// for every kind.
export type ExpiryKind = "credential" | "key" | "licence" | "certificate" | "token";

// ExpiryLifecycleClass is the retention intent, orthogonal to kind: "ephemeral" = a one-shot/short-lived
// token meant to be DELETED after use (a Cloudflare attach token, a portal-minted diagnostics bearer);
// "functional" = a standing credential the platform keeps depending on (a destination key, an IdP
// secret/cert, the licence, the signer). Posture exempts an ephemeral pending-cleanup item from the
// credential-expiry FAIL (it is a hygiene nudge, not a backup-breaking expiry).
export type ExpiryLifecycleClass = "ephemeral" | "functional";

// UsageLinkKind is the closed set of things a credential can power, so the console can render "what it
// is used for" and the roll-impact ("Breaks: <downpipes>") and deep-link to the owning screen. refId is
// always a STABLE entity id already non-secret elsewhere (a destinationId, an IdP connId, a source
// binding name), NEVER a credential value. The console builds a deep-link from the closed kind plus an
// allowlisted/encoded path; it never interpolates refId raw into an href.
export type UsageLinkKind = "destination" | "idpConnection" | "sourceBinding";
export interface UsageLink {
  kind: UsageLinkKind;
  refId: string;
}

// CleanupState applies only to an ephemeral item: "pending" = the operator has not confirmed deletion;
// "attested-deleted" = the operator confirmed (an attestation ONLY, the engine holds no Cloudflare API
// token and cannot verify Cloudflare-side state, so the copy is honest and never reads "verified").
export type CleanupState = "pending" | "attested-deleted";

// ExpiryItem is one tracked item, stored under `expiry:${id}`. label is the operator's own redaction-safe
// description; kind groups it; expiresAt is the RFC-3339 expiry, OPTIONAL, because some functional
// credentials do not expire by default (an Okta/Google/GitHub OIDC client secret) and a Cloudflare token
// can be created with no expiry; an ABSENT expiresAt is the no-expiry case (state "no-expiry", never a
// false "ok"/green). source records whether the operator entered it ("manual") or the engine observed it
// from a verifiable artefact it already holds ("observed"). The remaining fields are all optional,
// redaction-safe metadata (see the module header). It carries NO secret, key, value or fingerprint.
export interface ExpiryItem {
  id: string; // storage key `expiry:${id}`
  label: string; // operator label, redaction-safe (e.g. "S3 destination access key")
  kind: ExpiryKind;
  expiresAt?: string; // RFC-3339; ABSENT = no-expiry (does not expire / never-expires token)
  source: "manual" | "observed";
  note?: string;
  lifecycleClass?: ExpiryLifecycleClass; // ephemeral | functional (defaulted at write: token -> ephemeral, else functional)
  purpose?: string; // operator "what this credential is for"
  permissionSummary?: string; // descriptive permission text (e.g. neededCapabilities labels); NEVER a secret
  usageLink?: UsageLink; // what the credential powers (stable entity id, never a value)
  tokenRef?: string; // a PUBLIC Cloudflare token id descriptor (modelled on SecretRef.ref); NEVER the token value
  observedAt?: string; // RFC-3339; when the engine last auto-observed/refreshed this item (source "observed")
  usedAt?: string; // RFC-3339; when an ephemeral token was used (the attach moment)
  cleanupState?: CleanupState; // ephemeral only: pending | attested-deleted (operator attestation)
}

// ExpiryStatus is the computed view the GET /admin/expiry route returns and the cron/status read: the
// item's identity plus the derived daysRemaining and a coarse state. state is "expired" once the expiry
// is in the past, "approaching" within APPROACHING_DAYS, "no-expiry" when the item has no expiresAt
// (deliberately not "ok"/green, an unknown/never-expiring credential is a distinct, honest state), else
// "ok". daysRemaining is the whole-day count to expiry (negative once expired), absent for a no-expiry
// item. source is promoted so the console can badge an auto-observed item. The redaction-safe metadata
// is carried through (purpose/lifecycleClass/permissionSummary/usageLink/...) so the row + detail-drawer
// can render it; the operator note stays internal (never returned), and tokenRef is populated ONLY on
// the ephemeral cleanup projection, never on the generic status row.
export interface ExpiryStatus {
  id: string;
  label: string;
  kind: ExpiryKind;
  expiresAt?: string; // absent for a no-expiry item
  daysRemaining?: number; // absent for a no-expiry item
  state: "ok" | "approaching" | "expired" | "no-expiry";
  source: "manual" | "observed";
  lifecycleClass?: ExpiryLifecycleClass;
  purpose?: string;
  permissionSummary?: string;
  usageLink?: UsageLink;
  observedAt?: string;
  usedAt?: string;
  cleanupState?: CleanupState;
  tokenRef?: string; // ephemeral cleanup projection only (set by a later wave), never the generic row
}

// APPROACHING_DAYS is the COARSE state boundary: an item with daysRemaining <= 30 reads "approaching"
// (contract section 4). It is deliberately NOT kind-aware: a long-lead certificate/licence earns an
// earlier (60-day) NOTIFICATION rung via laddersFor, but it does not read "approaching" or fail the
// posture check until 30 days, so the early alert never inflates the at-a-glance band or the posture
// score for a credential that is still comfortably in date.
export const APPROACHING_DAYS = 30;

// The notification ladders. NOTIFY_THRESHOLDS_LONG (certificate, licence) earns a 60-day first rung so a
// coordinated rollover (the IdP and the platform both updated in a maintenance window) has a full extra
// month; NOTIFY_THRESHOLDS_SHORT (credential, key, token) starts at 30. The cron emits a credential-
// expiry notification when an item FIRST crosses to at or below a rung it has not yet been notified
// about (transition-based, like the alert cooldown), so a long-lived approaching credential alerts at
// most once per rung. Rungs are ordered high-to-low so crossingThreshold finds the lowest reached rung.
// The kind-aware first rung is selected by laddersFor (SHORT is the default; LONG for certificate/licence).
export const NOTIFY_THRESHOLDS_LONG: readonly number[] = [60, 30, 14, 7, 1];
export const NOTIFY_THRESHOLDS_SHORT: readonly number[] = [30, 14, 7, 1];

// laddersFor returns the notification ladder for a kind (long-lead certificate/licence -> the 60-day
// first rung; everything else -> 30). The COARSE state boundary (APPROACHING_DAYS) stays 30 for every
// kind; only the FIRST notification rung is kind-dependent, deliberately decoupled from "approaching".
export function laddersFor(kind: ExpiryKind): readonly number[] {
  return kind === "certificate" || kind === "licence" ? NOTIFY_THRESHOLDS_LONG : NOTIFY_THRESHOLDS_SHORT;
}

// MS_PER_DAY is the whole-day divisor used to turn a millisecond delta into daysRemaining. Kept here
// so the DO, the cron and status all compute daysRemaining the same way.
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// EXPIRY_PREFIX keys one tracked item per id under `expiry:<id>`, alongside the dp:/hist:/role:/
// notify-channel: keys in the scheduler DO. EXPIRY_COOLDOWN_PREFIX keys the per-item last-notified
// threshold record the cron uses to make the credential-expiry emission transition-based (emit on a
// newly-crossed rung, not every tick), mirroring the ALERT_COOLDOWN_PREFIX discipline. Kept here (the
// expiry domain) so the DO and any reader agree on the exact strings, mirroring NOTIFY_CHANNEL_PREFIX.
export const EXPIRY_PREFIX = "expiry:";
export const EXPIRY_COOLDOWN_PREFIX = "expiry-cooldown:";

// daysRemainingFor computes the whole-day count from now to an RFC-3339 expiry. It floors the
// millisecond delta to whole days so a credential with 29.6 days left reads 29 (the conservative
// rounding for an alert ladder: round DOWN so a rung fires a hair early, never a hair late). A
// negative value means already expired. An ABSENT expiry (no-expiry item) OR an unparseable expiry
// yields NaN, which callers treat as "cannot assess / does not apply" (no emit, no false expired).
export function daysRemainingFor(expiresAt: string | undefined, now: number): number {
  if (expiresAt === undefined) return Number.NaN;
  const t = Date.parse(expiresAt);
  if (!Number.isFinite(t)) return Number.NaN;
  return Math.floor((t - now) / MS_PER_DAY);
}

// stateFor maps a daysRemaining to the coarse numeric state. <= 0 is expired (the expiry is now or
// past); <= APPROACHING_DAYS is approaching; otherwise ok. An unparseable expiry (NaN) is treated as ok
// so a malformed item never shows a false "expired" badge (the validator rejects a malformed expiresAt
// at write time anyway; this is defence in depth for a legacy/garbled stored value). The no-expiry case
// (an ABSENT expiresAt) is handled in expiryStatuses, which returns state "no-expiry" directly, so
// stateFor only ever sees a number and never returns "no-expiry".
function stateFor(daysRemaining: number): "ok" | "approaching" | "expired" {
  if (!Number.isFinite(daysRemaining)) return "ok";
  if (daysRemaining <= 0) return "expired";
  if (daysRemaining <= APPROACHING_DAYS) return "approaching";
  return "ok";
}

// projectMeta carries the redaction-safe metadata fields through to the status via the conditional
// spread (exactOptionalPropertyTypes-safe). source is always present; the operator note and tokenRef
// are intentionally NOT projected onto the generic status row.
function projectMeta(item: ExpiryItem): Pick<ExpiryStatus, "source"> & Partial<ExpiryStatus> {
  return {
    source: item.source,
    ...(item.lifecycleClass !== undefined ? { lifecycleClass: item.lifecycleClass } : {}),
    ...(item.purpose !== undefined ? { purpose: item.purpose } : {}),
    ...(item.permissionSummary !== undefined ? { permissionSummary: item.permissionSummary } : {}),
    ...(item.usageLink !== undefined ? { usageLink: item.usageLink } : {}),
    ...(item.observedAt !== undefined ? { observedAt: item.observedAt } : {}),
    ...(item.usedAt !== undefined ? { usedAt: item.usedAt } : {}),
    ...(item.cleanupState !== undefined ? { cleanupState: item.cleanupState } : {}),
    // tokenRef is a PUBLIC Cloudflare token id (never a secret) and is only ever set on an ephemeral
    // cleanup row, so projecting it "when present" surfaces it for the console's cleanup affordance (so
    // the operator can find WHICH token to delete) without it appearing on any other kind of row.
    ...(item.tokenRef !== undefined ? { tokenRef: item.tokenRef } : {}),
  };
}

// expiryStatuses is the pure projection the route/cron/status share (contract section 4): map each
// stored item to its computed status (daysRemaining + state) at `now`. It sorts soonest-first (smallest
// daysRemaining first) so the console and any reader see the most urgent item at the top; an item with
// an unparseable expiry (NaN) sorts after the finite items, and a no-expiry item (absent expiry) sorts
// LAST (least urgent). It reads only the redaction-safe fields and can never surface a secret.
// THE EXPIRY ROW THAT READS GREEN FOR EVER. "Our destination key expired with zero warning" is this.
// A stored row whose expiresAt does NOT parse yields a NaN daysRemaining, and BOTH consumers coerce that to
// silence: stateFor(NaN) returns "ok" (the console shows a green badge) and crossingThreshold(NaN) returns
// null (the notify ladder never crosses a rung, so no warning is ever sent). A row whose KIND is not a member
// of the closed set is skipped by the kind-aware ladder the same way. Each coercion is defensible on its own
// -- a garbled row must never raise a FALSE "expired" alarm -- and together they mean the one thing the expiry
// tracker exists to do silently stops for that credential, until the day it expires and everything breaks.
//
// PURE, so the DO can count the anomaly at its single read chokepoint. It carries counts only: never the row,
// the label, the kind token or the timestamp text that would not parse.
const EXPIRY_KIND_SET: ReadonlySet<string> = new Set(["credential", "key", "licence", "certificate", "token"]);
export function expiryRowAnomalies(items: readonly ExpiryItem[]): { unparseableTimestamp: number; unknownKind: number } {
  let unparseableTimestamp = 0;
  let unknownKind = 0;
  for (const item of items) {
    // An ABSENT expiresAt is the honest "no-expiry" state (a never-expiring token), NOT an anomaly: counting
    // it would cry wolf on a legitimate row, which devalues every true signal.
    // THE TYPE TEST COMES FIRST, and it was missing. `Date.parse` takes a string, so a stored value that is
    // not one is COERCED before it is parsed, and the coercion can succeed: a numeric `0` becomes "0" and
    // parses to the year 2000. So a wrong-typed record was not counted as unreadable at all; it was read as a
    // real date, and a date in 2000 reads as expired. The engine has no idea what that row says, and it was
    // stating a year. `storage.get<T>`'s type parameter is an assertion rather than a check, so the only place
    // this can be caught is here, at the read.
    if (item.expiresAt !== undefined && (typeof item.expiresAt !== "string" || !Number.isFinite(Date.parse(item.expiresAt)))) unparseableTimestamp++;
    if (!EXPIRY_KIND_SET.has(item.kind as string)) unknownKind++;
  }
  return { unparseableTimestamp, unknownKind };
}

export function expiryStatuses(items: ExpiryItem[], now: number): ExpiryStatus[] {
  const out: ExpiryStatus[] = items.map((item) => {
    const meta = projectMeta(item);
    if (item.expiresAt === undefined) {
      // No-expiry: a distinct, honest state. No daysRemaining; never "ok"/green.
      const status: ExpiryStatus = { id: item.id, label: item.label, kind: item.kind, state: "no-expiry", ...meta };
      return status;
    }
    const daysRemaining = daysRemainingFor(item.expiresAt, now);
    const status: ExpiryStatus = {
      id: item.id,
      label: item.label,
      kind: item.kind,
      expiresAt: item.expiresAt,
      daysRemaining,
      state: stateFor(daysRemaining),
      ...meta,
    };
    return status;
  });
  // Soonest-first. A finite daysRemaining precedes a non-finite one; among non-finite, a NaN
  // (unassessable but dated) precedes an undefined (no-expiry, least urgent).
  out.sort((a, b) => {
    const av = a.daysRemaining;
    const bv = b.daysRemaining;
    const aFin = av !== undefined && Number.isFinite(av);
    const bFin = bv !== undefined && Number.isFinite(bv);
    if (aFin && bFin) return (av as number) - (bv as number);
    if (aFin) return -1;
    if (bFin) return 1;
    // Both non-finite: undefined (no-expiry) sorts after NaN (dated-but-unparseable).
    const aUndef = av === undefined;
    const bUndef = bv === undefined;
    if (aUndef && !bUndef) return 1;
    if (bUndef && !aUndef) return -1;
    return 0;
  });
  return out;
}

// countWarnings counts the FUNCTIONAL items whose state is approaching OR expired (the
// status.expiryWarnings figure). A no-expiry item is NOT a warning (a deliberate state, not an
// impending lapse), and an EPHEMERAL item is excluded entirely: a spent token pending cleanup is a
// hygiene item (counted separately by countCleanupPending, and exempt from the posture expiry check),
// not an expiry to renew. status.ts surfaces this presence-safe so the console can badge the
// credentials surface without reading the whole list.
export function countWarnings(statuses: ExpiryStatus[]): number {
  let n = 0;
  for (const s of statuses) {
    if (s.lifecycleClass === "ephemeral") continue;
    if (s.state === "approaching" || s.state === "expired") n++;
  }
  return n;
}

// countCleanupPending counts the EPHEMERAL items still awaiting the operator's deletion confirmation
// (cleanupState "pending"), the spent one-shot tokens the registry reminds the operator to delete in
// Cloudflare. Surfaced presence-safe as status.cleanupPending and in the console's Needs-attention tier.
export function countCleanupPending(statuses: ExpiryStatus[]): number {
  let n = 0;
  for (const s of statuses) if (s.lifecycleClass === "ephemeral" && s.cleanupState === "pending") n++;
  return n;
}

// crossingThreshold returns the LOWEST notification rung an item has reached (the most urgent rung at or
// above its daysRemaining is crossed) for the GIVEN ladder, or null when the item is still above the
// highest rung (not yet approaching) or unassessable (NaN). It is the basis of the transition test: an
// item at 6 days on the short ladder has crossed the 7 rung (its lowest reached rung is 7); at 0 days
// (expired) it has crossed the 1 rung. The rung is the value the cooldown records, so a later move to a
// LOWER rung re-alerts and a stay at the same rung does not. The ladder defaults to the SHORT ladder so
// existing callers are unchanged; the cron passes laddersFor(kind) to make the first rung kind-aware.
//
// Returns the smallest threshold T in `ladder` such that daysRemaining <= T. Long ladder [60,30,14,7,1]:
// dr=70 -> null; dr=60 -> 60; dr=31 -> 30; dr=30 -> 30; dr=15 -> 14; dr=7 -> 7; dr=0 -> 1. Short ladder
// [30,14,7,1]: dr=55 -> null; dr=30 -> 30; ... An unparseable daysRemaining (NaN) yields null.
export function crossingThreshold(daysRemaining: number, ladder: readonly number[] = NOTIFY_THRESHOLDS_SHORT): number | null {
  if (!Number.isFinite(daysRemaining)) return null;
  let crossed: number | null = null;
  for (const t of ladder) {
    if (daysRemaining <= t) crossed = crossed === null ? t : Math.min(crossed, t);
  }
  return crossed;
}

// shouldNotifyExpiry applies the transition gate on top of crossingThreshold (mirroring notify.ts
// shouldAlert): emit a credential-expiry notification only when the item has reached a rung it has NOT
// yet been notified about (a newly-crossed, or a lower, threshold than last time). Returns the rung to
// emit (and to record as last-notified), or null to stay silent. The ladder defaults to SHORT; the cron
// passes laddersFor(kind). The emit-once-per-rung property depends ONLY on the strictly-lower test and
// the cooldown storing the rung VALUE, both independent of ladder length, so it holds for either ladder.
//  - not yet approaching (crossingThreshold null): silent, and the caller clears any stale cooldown.
//  - first time at a rung (no lastNotifiedThreshold): emit that rung.
//  - moved to a LOWER rung than last notified: emit the new, lower rung (the urgency increased).
//  - still at the same rung (or a higher rung, e.g. the expiry was pushed out): do not re-emit.
export function shouldNotifyExpiry(daysRemaining: number, lastNotifiedThreshold: number | undefined, ladder: readonly number[] = NOTIFY_THRESHOLDS_SHORT): number | null {
  const rung = crossingThreshold(daysRemaining, ladder);
  if (rung === null) return null;
  if (lastNotifiedThreshold === undefined) return rung;
  // Only a STRICTLY lower rung than last time is a new, more-urgent transition worth re-emitting.
  if (rung < lastNotifiedThreshold) return rung;
  return null;
}

// EXPIRY_LABEL_MAX / EXPIRY_NOTE_MAX and the new field bounds keep a malformed item from storing an
// oversized value, matching validateConfig's discipline. EXPIRY_ID_PATTERN matches the downpipe-id key
// pattern so an id is a safe, bounded DO storage-key fragment. USAGE_LINK_KINDS is the closed set the
// validator checks usageLink.kind against.
const EXPIRY_LABEL_MAX = 256;
const EXPIRY_NOTE_MAX = 1000;
const EXPIRY_PURPOSE_MAX = 200;
const EXPIRY_PERM_SUMMARY_MAX = 512;
const USAGE_REF_MAX = 256;
const TOKEN_REF_MAX = 128;
const EXPIRY_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const USAGE_LINK_KINDS = new Set<string>(["destination", "idpConnection", "sourceBinding"]);

// boundedScreened is the shared bounds + control-character screen for every operator/engine free-text
// field (note, purpose, permissionSummary, usageLink.refId, tokenRef). It rejects a non-string, an
// over-long value, and any bare control character except tab/newline (allowed for multi-line text). It
// is a SHAPE/BOUNDS gate, NOT an XSS/CSS-injection sanitiser, the console's textContent-only render is
// the load-bearing protection for any auto-ingested string; this is defence in depth.
function boundedScreened(v: unknown, max: number): { ok: true; value: string } | { ok: false; reason: string } {
  if (typeof v !== "string") return { ok: false, reason: "must be a string" };
  if (v.length > max) return { ok: false, reason: `must not exceed ${max} characters` };
  for (let i = 0; i < v.length; i++) {
    const code = v.charCodeAt(i);
    if (code === 0x09 || code === 0x0a) continue; // tab and newline are allowed (multi-line text)
    if (code < 0x20 || code === 0x7f) return { ok: false, reason: "must not contain control characters" };
  }
  return { ok: true, value: v };
}

// isExpiryKind is the runtime guard for the kind enum at the authority boundary (the DO route),
// mirroring isRole / isNotifyEvent.
export function isExpiryKind(v: unknown): v is ExpiryKind {
  return v === "credential" || v === "key" || v === "licence" || v === "certificate" || v === "token";
}

// validateExpiryItem checks a client- or engine-supplied item at the authority boundary (the DO route /
// the internal observed writer), the same discipline validateChannel applies to a notify channel. It
// enforces: a valid id; a 1..256-char label; a valid kind; a CONDITIONAL expiresAt (a parseable RFC-3339
// when present; absent only for the no-expiry case, rejected for certificate/licence, and for any other
// kind only when noExpiry is set OR the writer is an engine observer); a source of manual/observed; a
// lifecycle class (defaulted: token -> ephemeral, else functional); and bounded+screened optional
// purpose/permissionSummary/usageLink/tokenRef/note + optional observed/used timestamps + cleanupState.
// It returns the normalised item (optional keys spread only when set, exactOptionalPropertyTypes-safe)
// or a typed rejection the route maps to a 400. No field is inspected for secrets here (the type cannot
// carry one); this validates the shape and bounds only. `noExpiry` is a control flag (not stored): it
// signals the operator's deliberate no-expiry choice.
// ExpiryConditions captures the kind/source/noExpiry context validateExpiryExpiry needs to decide whether
// an absent expiresAt is permitted.
interface ExpiryConditions {
  kind: ExpiryKind;
  source: ExpiryItem["source"];
  noExpiry: boolean;
}

// validateExpiryExpiry resolves the CONDITIONALLY-required expiresAt. Present -> a parseable RFC-3339.
// Absent -> allowed ONLY as the no-expiry case: a certificate/licence always has a date, so absence is
// rejected for those; for any other kind, absence is allowed only when the operator set noExpiry OR an
// engine observer wrote it (source "observed", e.g. a Cloudflare token created with no expiry).
function validateExpiryExpiry(rawExpiry: unknown, cond: ExpiryConditions): { ok: true; expiresAt: string | undefined } | { ok: false; reason: string } {
  if (rawExpiry !== undefined) {
    if (typeof rawExpiry !== "string" || !Number.isFinite(Date.parse(rawExpiry))) {
      return { ok: false, reason: "expiresAt must be an RFC-3339 timestamp" };
    }
    return { ok: true, expiresAt: rawExpiry };
  }
  if (cond.kind === "certificate" || cond.kind === "licence") {
    return { ok: false, reason: "expiresAt is required for a certificate or licence" };
  }
  if (!cond.noExpiry && cond.source !== "observed") {
    return { ok: false, reason: "expiresAt is required unless noExpiry is set" };
  }
  return { ok: true, expiresAt: undefined }; // the no-expiry case
}

// validateUsageLink validates the optional usageLink: an object with a closed kind + a bounded+screened
// stable refId.
function validateUsageLink(raw: unknown): { ok: true; usageLink: UsageLink } | { ok: false; reason: string } {
  if (typeof raw !== "object" || raw === null) return { ok: false, reason: "usageLink must be an object" };
  const uk = (raw as Record<string, unknown>).kind;
  if (typeof uk !== "string" || !USAGE_LINK_KINDS.has(uk)) {
    return { ok: false, reason: "usageLink.kind must be destination/idpConnection/sourceBinding" };
  }
  const r = boundedScreened((raw as Record<string, unknown>).refId, USAGE_REF_MAX);
  if (!r.ok) return { ok: false, reason: `usageLink.refId ${r.reason}` };
  return { ok: true, usageLink: { kind: uk as UsageLinkKind, refId: r.value } };
}

// optScreened validates an optional bounded+screened string field, prefixing the field name onto a reason.
function optScreened(raw: unknown, max: number, field: string): { ok: true; value: string | undefined } | { ok: false; reason: string } {
  if (raw === undefined) return { ok: true, value: undefined };
  const r = boundedScreened(raw, max);
  if (!r.ok) return { ok: false, reason: `${field} ${r.reason}` };
  return { ok: true, value: r.value };
}

// optTimestamp validates an optional parseable RFC-3339 timestamp field.
function optTimestamp(raw: unknown, field: string): { ok: true; value: string | undefined } | { ok: false; reason: string } {
  if (raw === undefined) return { ok: true, value: undefined };
  if (typeof raw !== "string" || !Number.isFinite(Date.parse(raw))) {
    return { ok: false, reason: `${field} must be an RFC-3339 timestamp` };
  }
  return { ok: true, value: raw };
}

// resolveSource validates the optional source enum, defaulting to manual. It is resolved first because the
// expiresAt no-expiry allowance depends on it.
function resolveSource(raw: unknown): { ok: true; source: ExpiryItem["source"] } | { ok: false; reason: string } {
  if (raw === undefined) return { ok: true, source: "manual" };
  if (raw !== "manual" && raw !== "observed") return { ok: false, reason: "source must be manual or observed" };
  return { ok: true, source: raw };
}

// resolveLifecycleClass validates the optional lifecycleClass enum, defaulting token -> ephemeral, else
// functional.
function resolveLifecycleClass(raw: unknown, kind: ExpiryKind): { ok: true; lifecycleClass: ExpiryLifecycleClass } | { ok: false; reason: string } {
  if (raw === undefined) return { ok: true, lifecycleClass: kind === "token" ? "ephemeral" : "functional" };
  if (raw !== "ephemeral" && raw !== "functional") return { ok: false, reason: "lifecycleClass must be ephemeral or functional" };
  return { ok: true, lifecycleClass: raw };
}

// resolveCleanupState validates the optional cleanupState enum.
function resolveCleanupState(raw: unknown): { ok: true; cleanupState: CleanupState | undefined } | { ok: false; reason: string } {
  if (raw === undefined) return { ok: true, cleanupState: undefined };
  if (raw !== "pending" && raw !== "attested-deleted") return { ok: false, reason: "cleanupState must be pending or attested-deleted" };
  return { ok: true, cleanupState: raw };
}

export function validateExpiryItem(raw: unknown): { ok: true; item: ExpiryItem } | { ok: false; reason: string } {
  if (typeof raw !== "object" || raw === null) return { ok: false, reason: "item must be an object" };
  const c = raw as Record<string, unknown>;

  const id = c.id;
  if (typeof id !== "string" || !EXPIRY_ID_PATTERN.test(id)) {
    return { ok: false, reason: "id must be 1 to 128 chars of [A-Za-z0-9._-]" };
  }
  const labelRaw = c.label;
  if (typeof labelRaw !== "string" || labelRaw.trim().length < 1 || labelRaw.length > EXPIRY_LABEL_MAX) {
    return { ok: false, reason: "label must be 1 to 256 characters" };
  }
  const kind = c.kind;
  if (!isExpiryKind(kind)) {
    return { ok: false, reason: "kind must be credential/key/licence/certificate/token" };
  }
  const sourceR = resolveSource(c.source);
  if (!sourceR.ok) return sourceR;
  const expiry = validateExpiryExpiry(c.expiresAt, { kind, source: sourceR.source, noExpiry: c.noExpiry === true });
  if (!expiry.ok) return expiry;
  const lifecycle = resolveLifecycleClass(c.lifecycleClass, kind);
  if (!lifecycle.ok) return lifecycle;

  const note = optScreened(c.note, EXPIRY_NOTE_MAX, "note");
  if (!note.ok) return note;
  const purpose = optScreened(c.purpose, EXPIRY_PURPOSE_MAX, "purpose");
  if (!purpose.ok) return purpose;
  const permissionSummary = optScreened(c.permissionSummary, EXPIRY_PERM_SUMMARY_MAX, "permissionSummary");
  if (!permissionSummary.ok) return permissionSummary;
  const tokenRef = optScreened(c.tokenRef, TOKEN_REF_MAX, "tokenRef");
  if (!tokenRef.ok) return tokenRef;

  let usageLink: UsageLink | undefined;
  if (c.usageLink !== undefined) {
    const u = validateUsageLink(c.usageLink);
    if (!u.ok) return u;
    usageLink = u.usageLink;
  }

  const observedAt = optTimestamp(c.observedAt, "observedAt");
  if (!observedAt.ok) return observedAt;
  const usedAt = optTimestamp(c.usedAt, "usedAt");
  if (!usedAt.ok) return usedAt;
  const cleanup = resolveCleanupState(c.cleanupState);
  if (!cleanup.ok) return cleanup;

  const item: ExpiryItem = {
    id,
    label: labelRaw.trim(),
    kind,
    source: sourceR.source,
    lifecycleClass: lifecycle.lifecycleClass,
    ...(expiry.expiresAt !== undefined ? { expiresAt: expiry.expiresAt } : {}),
    ...(note.value !== undefined ? { note: note.value } : {}),
    ...(purpose.value !== undefined ? { purpose: purpose.value } : {}),
    ...(permissionSummary.value !== undefined ? { permissionSummary: permissionSummary.value } : {}),
    ...(usageLink !== undefined ? { usageLink } : {}),
    ...(tokenRef.value !== undefined ? { tokenRef: tokenRef.value } : {}),
    ...(observedAt.value !== undefined ? { observedAt: observedAt.value } : {}),
    ...(usedAt.value !== undefined ? { usedAt: usedAt.value } : {}),
    ...(cleanup.cleanupState !== undefined ? { cleanupState: cleanup.cleanupState } : {}),
  };
  return { ok: true, item };
}
