// The CRON + ADMIN diagnostic RECORDS: their closed vocabularies, their bounded record shapes, the pure
// classifiers that coarsen free text into an enum, and the pure appliers that are the single redaction
// chokepoint for each aggregate.
//
// This is a LEAF module by design (its ONLY import is admin/posture-counters.ts, itself a pure leaf that
// imports nothing: the posture half of ADMIN_COUNTER_NAMES, split out under this module's size ceiling and
// spread back in below, so the vocabulary and the applier that gates on it still move together). The records are written by the cron passes
// (cron/seal-loop-pass.ts), the Worker edge (admin/metrics.ts, admin/router*.ts, admin/scim.ts,
// admin/support-ingest.ts) and the DO itself (sched/scheduler-do-support-diag.ts), and projected into the
// support pack (admin/support-sections-*.ts). If any of these shapes lived in one of those layers, the DO's
// type-only import of it would drag that layer's whole graph into the DO base and close an import cycle. It
// imports nothing, so every layer can agree on ONE vocabulary with no cycle -- the same reason
// cron/retention-record.ts and admin/auth-signals.ts exist.
//
// NO-CUSTODY (binding): every field written here is a CLOSED ENUM, a COUNT, a CLAMPED INT, a BOOLEAN, a
// clamped timestamp, or the customer's OWN opaque downpipe id (the class the pack already carries in
// downpipes[] / sealFaults). The classifiers READ an error message ONLY to SELECT an enum member and RETURN
// that enum: no message, stack, secret, token, key, URL, endpoint, bucket, header or customer value can
// reach a record (the classifyCoarseError / isWormRefusal idiom).

import { POSTURE_COUNTER_NAMES } from "./posture-counters.ts";

// ---------------------------------------------------------------------------------------------------------
// PRE-RUN SEAL FAILURES (cron/seal-dispatch.ts, cron/seal-loop-pass.ts)
//
// A throw BEFORE the run index is allocated leaves no run row: the loop's /complete is a runId-"" history
// no-op, so run history shows only a GAP and the pack shows an anonymous scheduler.ticks.sealErrors integer.
// "One downpipe silently stopped producing runs" (its destination record was deleted) is then undiagnosable.
// These classes ATTRIBUTE that throw to the downpipe and name its cause.
// ---------------------------------------------------------------------------------------------------------

export const SEAL_ERROR_CLASSES = [
  "dest-not-configured", // the downpipe PINS a destination the DO holds no config for: resolveDestForState fails loud rather than silently writing to the env fallback (which would split the archive). The destination record was deleted / renamed under a live downpipe.
  "dest-config-unreadable", // the destination config round-trip to the scheduler DO faulted, or its sealed credential would not unwrap (a rotated CONFIG_WRAP_KEY): the destination may be perfectly healthy, we could not READ its config
  "wrap-key-invalid", // CONFIG_WRAP_KEY is present but malformed, so no destination credential can be opened at all (the whole fleet stops, not one downpipe)
  "trigger-transport", // the /trigger round-trip to the scheduler DO faulted: no run index was ever allocated (a DO availability fault, not a destination fault)
  "lock-clear-failed", // the best-effort completion that CLEARS the in-flight lock after a failed dispatch itself faulted: the downpipe's lease stays wedged and it reads as permanently in-flight ("stalled") until a later tick clears it
  "other", // residual: a dispatch throw outside the named classes (never a message)
] as const;
export type SealErrorClass = (typeof SEAL_ERROR_CLASSES)[number];
const SEAL_ERROR_CLASS_SET: ReadonlySet<string> = new Set(SEAL_ERROR_CLASSES);

// DEST_NOT_CONFIGURED_MARK is the ONE engine-owned literal resolveDestForState interpolates into its throw
// ("destination <id> for downpipe <id> is not configured"). classifySealDestError matches on this literal
// ONLY, to select an enum member; the message itself (which carries the customer's ids) is never recorded.
const DEST_NOT_CONFIGURED_MARK = "is not configured";
// WRAP_KEY_MARK is the engine-owned literal loadConfigWrapKey throws on a malformed CONFIG_WRAP_KEY.
const WRAP_KEY_MARK = "CONFIG_WRAP_KEY";

/**
 * Coarsens a destination-RESOLUTION throw (selectSealDestination / resolveDestForState / loadConfigWrapKey)
 * into a closed SealErrorClass. It reads the message ONLY to match the engine's own literals above and
 * RETURNS the enum; the text never leaves this function.
 *
 * @param e - the thrown value.
 * @returns the closed class.
 */
export function classifySealDestError(e: unknown): SealErrorClass {
  const m = e instanceof Error ? e.message : "";
  if (m.includes(WRAP_KEY_MARK)) return "wrap-key-invalid";
  if (m.includes(DEST_NOT_CONFIGURED_MARK)) return "dest-not-configured";
  return "dest-config-unreadable";
}

/**
 * SealDispatchError TAGS a pre-run dispatch throw with its closed class at the site that knows it (the
 * destination resolution, the /trigger round-trip), so the seal loop's catch does not have to re-read a raw
 * message to attribute it. The original error is kept as `cause` for the Workers Logs line ONLY; the class
 * is the only thing that is ever recorded.
 */
export class SealDispatchError extends Error {
  readonly sealErrorClass: SealErrorClass;
  constructor(sealErrorClass: SealErrorClass, cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = "SealDispatchError";
    this.sealErrorClass = sealErrorClass;
    this.cause = cause;
  }
}

/**
 * sealErrorClassOf reads the class off a tagged SealDispatchError, and coarsens anything else to "other".
 * It NEVER inspects an untagged error's message: an untagged throw is by definition one no site classified,
 * so guessing from its text would be exactly the free-text leak this vocabulary exists to prevent.
 *
 * @param e - the thrown value caught by the seal loop.
 * @returns the closed class.
 */
export function sealErrorClassOf(e: unknown): SealErrorClass {
  const cls = (e as { sealErrorClass?: unknown } | null)?.sealErrorClass;
  return typeof cls === "string" && SEAL_ERROR_CLASS_SET.has(cls) ? (cls as SealErrorClass) : "other";
}

/** The per-downpipe last-seal-error stamp. Closed class + a clamped time + a count. Never a message. */
export interface SealErrorStamp {
  readonly cls: SealErrorClass;
  readonly at: number; // epoch ms of the most recent fault of this class
  readonly consecutive: number; // consecutive faults of the SAME class (resets to 1 when the class changes)
}

// SEAL_ERROR_PREFIX is the per-downpipe DO key prefix (sealerr:<downpipeId>), mirroring STATE_REFUSED_PREFIX:
// a per-downpipe key, never a fleet map, so one downpipe's churn cannot grow another's record.
export const SEAL_ERROR_PREFIX = "sealerr:";
// The count ceiling: a downpipe faulting every tick for years re-bumps this rather than growing storage.
const SEAL_ERROR_COUNT_CAP = 1_000_000;

/**
 * applySealErrorStamp folds ONE fault into a downpipe's stamp. PURE, so the DO recorder and the validator
 * pin the same arithmetic: the same class increments `consecutive`; a DIFFERENT class restarts the run at 1
 * (the cause changed, so the old streak says nothing about the new one).
 *
 * @param prior - the stored stamp, if any.
 * @param cls - the closed class of this fault.
 * @param now - the DO clock (injected, so the test is deterministic).
 * @returns the new stamp.
 */
export function applySealErrorStamp(prior: SealErrorStamp | undefined, cls: SealErrorClass, now: number): SealErrorStamp {
  const consecutive = prior !== undefined && prior.cls === cls ? Math.min(SEAL_ERROR_COUNT_CAP, prior.consecutive + 1) : 1;
  return { cls, at: now, consecutive };
}

// ---------------------------------------------------------------------------------------------------------
// THE PROMETHEUS /metrics SCRAPE SURFACE (admin/metrics.ts)
//
// Nothing metrics-specific reaches the pack today: a DO hiccup that 401s a scrape, a SHAPE fallback that
// silently empties every series while `up == 1`, and a record-pull write that keeps failing (so the grant's
// pull trail stops updating and support misreads an ACTIVE scrape as abandoned) are all invisible.
// ---------------------------------------------------------------------------------------------------------

export const METRICS_SCRAPE_OUTCOMES = [
  "ok", // a bearer-authorised scrape rendered the fleet
  "no-grant", // no metrics-scope ingest credential exists at all: every scrape 401s (the credential was never minted, or was revoked)
  "credential-expired", // the metrics grant EXISTS but is past its expiresAt: the customer's "Prometheus started 401ing with a credential we never rotated"
  "credential-expiry-unreadable", // G312: the metrics grant's stored expiresAt does not PARSE, so it can never expire and every reader agreed it was live. The scrape is refused FAIL-CLOSED and the corruption is finally named
  "bearer-malformed", // the presented Authorization header was absent / not Bearer / not <clientId>.<secret>
  "client-id-mismatch", // a well-formed bearer presented a clientId that is not the stored grant's (a stale credential from a prior mint)
  "secret-mismatch", // the clientId matched but the secret did not (a rotated grant the scraper was never updated with)
  "auth-check-unavailable", // the grant could not be READ (the DO round-trip faulted): the scrape is refused 401 FAIL-CLOSED, so a DO hiccup is misreported to the operator as "unauthorised"
  "do-read-failed", // authorised, but the fleet read faulted / the DO answered non-2xx: the scrape 500s and Prometheus's own `up` goes to 0 (the honest signal)
  "shape-fallback", // authorised and the DO answered 2xx, but a body was NOT the expected shape, so the renderer coerced it to empty: EVERY downpipe series silently vanishes while up == 1
] as const;
export type MetricsScrapeOutcome = (typeof METRICS_SCRAPE_OUTCOMES)[number];
const METRICS_SCRAPE_OUTCOME_SET: ReadonlySet<string> = new Set(METRICS_SCRAPE_OUTCOMES);

/** The bounded metrics-endpoint health record. Closed outcome enums, counts and clamped timestamps only. */
export interface MetricsHealth {
  readonly lastScrapeAt: number; // epoch ms of the most recent scrape ATTEMPT (authorised or not)
  readonly lastOutcome: MetricsScrapeOutcome;
  readonly outcomes: Record<string, number>; // closed outcome -> count
  readonly shapeFallbacks: number; // cumulative bodies coerced to empty (the silent-empty-series signal)
  readonly recordPullFailures: number; // cumulative best-effort pull-trail writes that FAILED (the grant's "last read" stops advancing while scrapes are live)
}

export const METRICS_HEALTH_KEY = "metrics:health";
const METRICS_COUNT_CAP = 1_000_000_000;

const EMPTY_METRICS_HEALTH: MetricsHealth = { lastScrapeAt: 0, lastOutcome: "ok", outcomes: {}, shapeFallbacks: 0, recordPullFailures: 0 };

/**
 * applyMetricsScrape folds ONE scrape observation into the health record. PURE (the DO recorder and the
 * validator share it). An out-of-vocabulary outcome is DROPPED (defence in depth: the record is returned
 * unchanged), so no caller can inject a key into the bounded outcome map.
 *
 * @param prior - the stored record, if any.
 * @param outcome - the closed scrape outcome.
 * @param now - the DO clock (injected).
 * @param opts - shapeFallback: the render coerced a malformed body to empty; pullFailed: the best-effort
 *               record-pull write failed.
 * @returns the new record.
 */
export function applyMetricsScrape(prior: MetricsHealth | undefined, outcome: string, now: number, opts?: { shapeFallback?: boolean; pullFailed?: boolean }): MetricsHealth {
  const base = prior ?? EMPTY_METRICS_HEALTH;
  if (!METRICS_SCRAPE_OUTCOME_SET.has(outcome)) return base;
  const outcomes = { ...base.outcomes };
  outcomes[outcome] = Math.min(METRICS_COUNT_CAP, (outcomes[outcome] ?? 0) + 1);
  return {
    lastScrapeAt: now,
    lastOutcome: outcome as MetricsScrapeOutcome,
    outcomes,
    shapeFallbacks: Math.min(METRICS_COUNT_CAP, base.shapeFallbacks + (opts?.shapeFallback === true ? 1 : 0)),
    recordPullFailures: Math.min(METRICS_COUNT_CAP, base.recordPullFailures + (opts?.pullFailed === true ? 1 : 0)),
  };
}

// ---------------------------------------------------------------------------------------------------------
// THE STRUCTURAL WebAuthn / PASSKEY FAULT CLASSES (admin/passkey-cose.ts, admin/passkey-authdata.ts)
//
// Every CBOR / COSE / DER / authData defect coarsens to the single ceremony reason "bad_request" (which the
// pack counts as passkey-bad-request) and its real shape lives only in an errId'd Workers Logs line the
// vendor structurally cannot read. So "our whole fleet of Ed25519-only keys will not enrol" and "one user's
// previously-working passkey is now rejected on every login" (a CORRUPTED stored COSE key -- login re-decodes
// the stored key through this same path) are the same counter. These 14 classes are the actionable split.
//
// The CLIENT-facing response is UNCHANGED and stays coarse ("bad_request"), so no class is ever oracled back
// to a caller: the split is recorded pack-side only.
// ---------------------------------------------------------------------------------------------------------

export const WEBAUTHN_FAULT_CLASSES = [
  // --- CBOR framing (the bounded decoder) ---
  "cbor-truncated", // the item ran past the end of the buffer
  "cbor-depth", // nesting past the decoder's depth ceiling (a hostile / pathological structure)
  "cbor-items-cap", // more items than the decoder's total-item ceiling
  "cbor-utf8", // a CBOR text string was not valid UTF-8 (the fatal decoder arm)
  "cbor-duplicate-key", // a CBOR map repeated a key (a canonicalisation attack surface)
  "cbor-trailing", // trailing bytes after the top-level item, or after the COSE key with no extension-data flag
  "cbor-unsupported", // a major type / additional-info encoding the decoder does not accept (indefinite length, a reserved value)
  // --- authenticatorData / clientDataJSON framing ---
  "authdata-truncated", // authData was shorter than its declared structure (header, attested-credential header, credential id)
  "authdata-credid-range", // the attested credential-id length was zero or past the accepted ceiling
  "clientdata-malformed", // clientDataJSON was not valid UTF-8 / not JSON / not an object / missing a required field
  // --- COSE_Key semantics: the ones that tell a fleet from a corruption ---
  "cose-unsupported-kty", // the COSE key type is not one this build imports (the Ed25519-only / OKP security-key fleet that can NEVER enrol)
  "cose-unsupported-alg", // the COSE alg is not ES256/RS256 (recorded WITH the offered alg int, see coseAlg)
  "cose-shape", // the COSE_Key is structurally wrong for its own kty (a missing/short crv, x, y, n or e)
  "der-signature-malformed", // the ECDSA signature was not a well-formed DER SEQUENCE of two INTEGERs
  "key-import-failed", // crypto.subtle.importKey REFUSED the COSE key bytes. On the LOGIN phase this is the clean signal that the STORED key record is corrupt (the device is fine); on ENROL it is a device the runtime will not accept
] as const;
export type WebauthnFaultClass = (typeof WEBAUTHN_FAULT_CLASSES)[number];
const WEBAUTHN_FAULT_CLASS_SET: ReadonlySet<string> = new Set(WEBAUTHN_FAULT_CLASSES);

// WEBAUTHN_PHASES splits the SAME class by the ceremony it fired in. This is the whole diagnostic point of
// the aggregate: key-import-failed on ENROL is an incompatible device; the identical class on LOGIN is a
// CORRUPTED STORED CREDENTIAL (the user enrolled fine and can no longer sign in).
export const WEBAUTHN_PHASES = ["enrol", "login"] as const;
const WEBAUTHN_PHASE_SET: ReadonlySet<string> = new Set(WEBAUTHN_PHASES);

/**
 * PasskeyFault is thrown by the CBOR/COSE/authData parsers to TAG a structural defect with its closed class
 * (and, for cose-unsupported-alg, the offered COSE alg integer -- a small negative int from a fixed IANA
 * registry, never a key or a credential id). It is NOT the ceremony error: the parsers still throw the
 * coarse PasskeyError("bad_request", ...) the ceremony contract requires, and this tag rides on it, so the
 * client-facing response and the anti-enumeration property are byte-identical.
 */
export interface PasskeyFaultTag {
  readonly webauthnFaultClass: WebauthnFaultClass;
  readonly coseAlg?: number;
}

/**
 * webauthnFaultOf reads the structural tag off a thrown ceremony error. An UNTAGGED error yields null (it is
 * one no parser classified, and guessing from its message is precisely the free-text leak this vocabulary
 * prevents). The alg is accepted ONLY as a small integer in the IANA COSE algorithm range.
 *
 * @param e - the thrown ceremony error.
 * @returns the closed class (+ the offered alg int when the parser tagged one), or null when untagged.
 */
export function webauthnFaultOf(e: unknown): PasskeyFaultTag | null {
  const cls = (e as { webauthnFaultClass?: unknown } | null)?.webauthnFaultClass;
  if (typeof cls !== "string" || !WEBAUTHN_FAULT_CLASS_SET.has(cls)) return null;
  const alg = (e as { coseAlg?: unknown }).coseAlg;
  const algOk = typeof alg === "number" && Number.isInteger(alg) && alg >= -65536 && alg <= 65536;
  return { webauthnFaultClass: cls as WebauthnFaultClass, ...(algOk ? { coseAlg: alg } : {}) };
}

/** The bounded WebAuthn fault aggregate: "<phase>:<class>" -> { count, lastAt, algs }. */
export interface WebauthnFaultEntry {
  readonly count: number;
  readonly lastAt: string;
  readonly algs?: number[]; // cose-unsupported-alg only: the DISTINCT offered alg ints (bounded), so support can say "your fleet offers -8 (EdDSA)"
}
export type WebauthnFaults = Record<string, WebauthnFaultEntry>;

export const WEBAUTHN_FAULTS_KEY = "webauthn:faults";
const WEBAUTHN_COUNT_CAP = 1_000_000;
// The distinct-alg ceiling: a real fleet offers one or two. This bounds a hostile client that iterates the
// whole IANA registry to grow the record.
const WEBAUTHN_ALGS_MAX = 8;

/**
 * applyWebauthnFault folds ONE structural ceremony fault into the bounded aggregate. PURE. An
 * out-of-vocabulary class or phase is DROPPED (the record is returned unchanged), so the key space is bounded
 * by the two closed sets and a flood of malformed ceremonies can only re-bump a capped counter, never add a
 * storage row.
 *
 * @param prior - the stored aggregate, if any.
 * @param phase - the closed ceremony phase.
 * @param cls - the closed fault class.
 * @param nowIso - the DO clock as an ISO string (injected).
 * @param coseAlg - the offered COSE alg int, for cose-unsupported-alg only.
 * @returns the new aggregate.
 */
export function applyWebauthnFault(prior: WebauthnFaults | undefined, phase: string, cls: string, nowIso: string, coseAlg?: number): WebauthnFaults {
  const map: WebauthnFaults = { ...(prior ?? {}) };
  if (!WEBAUTHN_PHASE_SET.has(phase) || !WEBAUTHN_FAULT_CLASS_SET.has(cls)) return map;
  const key = `${phase}:${cls}`;
  const prev = map[key];
  const algs = new Set<number>(prev?.algs ?? []);
  if (cls === "cose-unsupported-alg" && typeof coseAlg === "number" && Number.isInteger(coseAlg) && algs.size < WEBAUTHN_ALGS_MAX) algs.add(coseAlg);
  const next: WebauthnFaultEntry = {
    count: Math.min(WEBAUTHN_COUNT_CAP, (prev?.count ?? 0) + 1),
    lastAt: nowIso,
    ...(algs.size > 0 ? { algs: [...algs].sort((a, b) => a - b) } : {}),
  };
  map[key] = next;
  return map;
}

// ---------------------------------------------------------------------------------------------------------
// THE DIAGNOSTIC RECORDERS' OWN DROPPED WRITES (the meta-finding)
//
// Every best-effort bookkeeping / diagnostic write in the engine is a `.catch(() => {})` or an unchecked
// fetch: an audit append, an attach-token observe, a restore stamp, a support-pull trail, an auth/SCIM signal,
// a licence-refusal persist, an update settled/pending record. When the DO is unavailable, those writes are
// dropped SILENTLY -- so the pack UNDER-COUNTS during the exact outage it exists to explain: a lockout window
// shows zero auth signals, a post-deploy pack lacks the deploy keystone, an expiry warning never fires and
// nothing says why. Absence of evidence reads as absence of problems.
//
// The fix is a droppedWrites aggregate mirroring scheduler.storageFaults: the writer CHECKS its response and,
// on failure, NOTES the kind in an isolate-local pending tally which is flushed (piggy-backed) on the NEXT
// successful diagnostic write. This needs no in-flight persistence and survives a DO-unavailable window: the
// gap is recorded the moment the DO comes back. An isolate that dies with a pending tally loses it -- an
// irreducible floor, and strictly better than the prior zero durability.
// ---------------------------------------------------------------------------------------------------------

export const DROPPED_WRITE_KINDS = [
  "auth-signal", // an auth/RBAC/passkey/SCIM defensive-branch signal (admin/auth-signals.ts) never landed: the pack shows a QUIET auth aggregate during a lockout
  "support-pull-trail", // a support/metrics pull was served but its "last read" trail write failed: an ACTIVE integration reads as abandoned
  "licence-refusal", // a REFUSED licence activation was not persisted: the customer's "it just says community" has no recorded reason
  "update-pending", // an update was marked in flight but the record did not persist: the console cannot offer a rollback ("no recorded prior version" right after a successful update)
  "update-settled", // an update SETTLED but the record did not persist: the same rollback blindness, plus a canary that can never be confirmed
  "seal-error", // a per-downpipe pre-run seal fault (G163) could not be attributed: the downpipe's silence has no cause
  "metrics-health", // a /metrics scrape outcome (G049) could not be recorded: the scrape surface's own health is blind
  "webauthn-fault", // a structural WebAuthn fault (G158) could not be recorded: a total-lockout window shows no WebAuthn evidence
  "restore-fault", // a restore/drill/verify fault row (G070) could not be recorded: the pack shows a restore that failed with NO per-record or per-phase attribution
  "admin-counter", // an admin diagnostic counter bump (G080/G081/G082) could not be recorded: a licence source-flip, a reclaimed apply lease or a silent row exclusion left no trace
  "dest-build-health", // a destination BUILD outcome (G136/G137) could not be recorded: the pack cannot say the destination has been unbuildable since a given moment, nor WHICH knob broke it -- so the highest-impact failure mode (a redeploy that wiped DEST_* / CONFIG_WRAP_KEY) reads as an ordinary run failure
  // the RUN-COMPLETION post itself. Not a diagnostic write but a FUNCTIONAL one -- and its loss is the
  // only evidence of its own failure, which is why it belongs in this aggregate. When the manual (run-now)
  // dispatch fails before sealing, the engine posts a FAILED /complete to resolve the run and free the
  // in-flight lease; that post used to be `.catch(() => {})`. A dropped post leaves the downpipe dangling
  // in flight until the 30-minute lease expires, so the pack showed the STALL (downpipes[].stalled) with no
  // cause -- indistinguishable from a genuinely wedged seal. The DO is by definition unreachable at fault
  // time (that is usually WHY the post failed), so the pending-tally + flush-on-recovery protocol is exactly
  // right: the loss lands the moment the DO comes back, which is when the pack is generated.
  "run-completion",
  // The SOURCE + DESTINATION fault evidence of one finished crawl (admin/run-fault-records.ts). A dropped
  // post means the pack's sourceFaults / destFaults sections are missing a downpipe's most recent cause --
  // the run row still shows the failure, but not WHY (a 403 scope gap vs a 5xx outage vs a page cap), which
  // is the whole diagnosis. The drain is unconditional, so the ledger is still cleared: only the report is
  // lost, and this counter is what says so.
  "run-faults",
  // The 10 remaining best-effort ADMIN-ROUTER DO writes: each was an `await`ed fetch whose response
  // was never checked, or a bare `.catch(() => {})`. Their losses are now counted by surface, because each
  // loss makes a DIFFERENT pack section quietly incomplete: an unverified audit chain reads as intact, a
  // discovery refresh reads as "nothing found", a key-ceremony event never joins the audit trail, a restore
  // receipt never anchors, and the deploy keystone (the highest-impact failure mode: a deploy that wiped source
  // bindings) simply never appears -- indistinguishable from "no redeploy happened".
  "audit-write", // an audit-chain append / verify / rollover bookkeeping write (router-audit.ts)
  "discovery-refresh", // a source-discovery refresh result (router-discovery.ts / router-sources-discovery.ts)
  "key-ceremony-audit", // a key install / removal / rotation audit event (router-keys.ts)
  // G-DEMO: the demo fresh-first-run marker CLEAR after a landed key install. A demo reset cannot delete
  // the engine's Worker Secrets, so it sets a marker that MASKS them and forces the wizard back to the
  // ceremony. /keys/install clears that marker once the real keys land. When the clear is lost the
  // estate is stuck reporting keyless while holding keys, and installRekeyDecision reads the SAME masked
  // view, so the already-provisioned guard is blind and every subsequent "first install" silently
  // RE-KEYS the estate for real. Measured on harness-crud: install returned 200, the keys
  // were written, and /admin/status still read signer=false breakGlass=false ready=false.
  "demo-first-run-clear",
  "restore-receipt", // a restore-apply receipt / outcome anchor (router-restore.ts)
  "status-observation", // the deploy-identity status observation, i.e. the engine-version-change keystone (router-status.ts)
  // An ingest-credential mint / revoke that never reached the DO (router-status.ts). The mint SHOWS the
  // operator a bearer exactly once; if the grant did not persist, their collector 401s forever against a
  // credential they are certain they configured, and a revoke that did not land is worse -- the operator
  // believes a pull credential is dead while it is still live.
  "ingest-credential",
  // The FORMAT + CRYPTO core's drained integrity evidence (format/integrity-fault-ledger.ts). A dropped post
  // means the pack cannot say WHICH verification stage failed, WHICH record or shard, or that a key was simply
  // pasted short: the run row still shows a coarse failure, which is the whole gap.
  "integrity-faults",
  // A last-resort dispatch fault. Self-referential by nature: the surface that 500s may be the support
  // pull itself, so a lost record here is exactly the evidence support needed.
  "dispatch-fault",
  // The per-destination selection-probe reasons: without them a run says "all destinations unreachable"
  // and names no cause for any of them.
  "dest-probe-faults",
  // A cost sizing-probe outcome: a lost record hides a measured-zero, which is a WRONG answer presented
  // to the customer as a right one.
  "cost-sizing",
  // The CRON pass-health ledger (cron/cron-fault-ledger.ts). A dropped write means the pack's cron-health
  // vector is missing a tick's verdict, so a pass that has been silently failing reads as one that never ran.
  "cron-health",
  // The SOURCE-DISCOVERY outcome (admin/router-discovery.ts). A dropped write means the pack cannot tell
  // a scope-blind discovery (an empty setup form the customer configures their whole estate against) from an
  // account that genuinely holds nothing.
  "discovery-health",
  // An AUDIT-EXPORT attempt (admin/router-rbac.ts + admin/support-ingest.ts). A dropped write means the
  // pack cannot say the customer was unable to get their tamper-evident evidence OUT of the account -- and the
  // export path's failure is, by construction, the one thing the exported log itself can never record.
  "audit-export-attempt",
  // An ATTACH / RE-ATTACH outcome (admin/router-discovery.ts). A dropped write means the pack cannot say
  // the heal for the highest-impact failure mode (a deploy that wiped the source bindings) was TRIED and FAILED -- which
  // is the exact window in which a pack is taken, and the exact window in which the DO may also be sick.
  "attach-health",
  // An ADMIN-ROUTE outer-catch error (admin/router-updates*.ts). A dropped write means the pack loses
  // the only server-side trace of an update/licence route that threw past its last checkpoint, which is the
  // whole point of the aggregate: without it, "nothing was changed" cannot be checked against anything.
  "admin-route-error",
  // A CONTROL-PLANE import / recovery refusal (admin/router-identity.ts). This is the disaster-recovery
  // path, where the pack may be the ONLY artefact that survives -- so a dropped write here is the worst-placed
  // loss in the product, and the one most worth counting.
  "recovery-refusal",
  "test-outcome", // G246: a wiring-check (Test button) outcome was lost, so the pack again cannot say whether the operator's test passed
  // The RETENTION pass record (cron/retention-pass.ts recordRetentionPass, POST /retention-record). This was the
  // last best-effort DO write in the engine still wrapped in a bare `catch {}`. A dropped post means the pack's
  // `retention` section shows the PREVIOUS pass as the latest one, so a prune that deleted too much, or that
  // silently stopped pruning, reads as a pass that never happened. Retention is the one place a wrong answer
  // is unrecoverable in both directions, which is why its record is the last write that may go uncounted.
  "retention-record",
] as const;
export type DroppedWriteKind = (typeof DROPPED_WRITE_KINDS)[number];
const DROPPED_WRITE_KIND_SET: ReadonlySet<string> = new Set(DROPPED_WRITE_KINDS);

/** The bounded dropped-write aggregate: closed kind -> { count, lastAt }. Counts only, never a payload. */
export interface DroppedWriteEntry {
  readonly count: number;
  readonly lastAt: string;
}
export type DroppedWrites = Record<string, DroppedWriteEntry>;

export const DROPPED_WRITES_KEY = "diag:droppedwrites";
const DROPPED_WRITE_COUNT_CAP = 1_000_000;
// The per-flush ceiling on a single kind's reported count: a flush body is CLAMPED, so a malformed or
// hostile body can never fabricate an enormous loss claim (nor overflow the counter in one call).
const DROPPED_WRITE_FLUSH_CAP = 100_000;

/**
 * applyDroppedWrites folds ONE flushed tally ({kind: count}) into the aggregate. PURE, and the single
 * redaction chokepoint: an out-of-vocabulary kind is DROPPED and every count is clamped to a non-negative
 * bounded integer, so the key space is bounded by DROPPED_WRITE_KINDS and no payload, message or id can
 * enter the record.
 *
 * @param prior - the stored aggregate, if any.
 * @param drops - the posted {kind: count} tally (untrusted).
 * @param nowIso - the DO clock as an ISO string (injected).
 * @returns the new aggregate.
 */
export function applyDroppedWrites(prior: DroppedWrites | undefined, drops: unknown, nowIso: string): DroppedWrites {
  const map: DroppedWrites = { ...(prior ?? {}) };
  if (typeof drops !== "object" || drops === null || Array.isArray(drops)) return map;
  for (const [kind, raw] of Object.entries(drops as Record<string, unknown>)) {
    if (!DROPPED_WRITE_KIND_SET.has(kind)) continue; // defence in depth: never a caller-injected key
    const n = typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? Math.min(DROPPED_WRITE_FLUSH_CAP, Math.floor(raw)) : 0;
    if (n === 0) continue;
    const prev = map[kind];
    map[kind] = { count: Math.min(DROPPED_WRITE_COUNT_CAP, (prev?.count ?? 0) + n), lastAt: nowIso };
  }
  return map;
}

// ---------------------------------------------------------------------------------------------------------
// THE RESTORE / DRILL / VERIFY FAULT RING (admin/restore*.ts, admin/router-restore.ts)
//
// Restore evidence in the pack is OUTCOME-PLUS-COUNTS today: a restore-apply keystone with {complete,
// recordsVerified, failures, readbackMismatched, d1Total/d1Verified}. So "the restore failed" arrives with
// no answer to any of the questions support actually has -- WHICH record failed, in WHICH phase, and in
// WHICH failure mode (a GCM/hash integrity abort vs a WORM-refused write vs an object that was written but
// vanished on readback vs a cf-config surface the CF API refused vs a D1 half-load). Worse: a THROWN apply
// leaves NO outcome row at all (the router's finally releases the reservation and the throw propagates past
// the recordAudit below it), and EVERY dry-run refusal -- oversized in-account window, reserved target
// binding, a plan that could not be opened -- persists nowhere, so "we could not even preview a restore for
// a week" is invisible.
//
// This is a BOUNDED RING (cap 64, newest-last) of closed-vocabulary rows, written by the Worker edge from
// the ALREADY-COMPUTED result (no restore behaviour changes, and the pure core stays free of a DO stub).
//
// NO-CUSTODY: op / phase / cls are closed enums; errId is the engine's existing 8-hex FNV exception id (the
// Workers-Logs join key, irreversible); recordName is the customer's OWN record label -- the same class the
// pack already carries in incompleteIds -- clamped to 128 chars. The raw S3 / Cloudflare / SQLite / reader
// message is NEVER carried: classifyRestoreFaultClass READS it only to SELECT an enum member and returns
// that member. No plan, no value, no key, no bucket, no endpoint, no token.
// ---------------------------------------------------------------------------------------------------------

export const RESTORE_FAULT_OPS = [
  "dry-run", // a read-only preview (confirm omitted/false): writes nothing, so a refusal here is pure diagnosis
  "apply", // the destructive write-back into live in-account resources
  "drill", // the scheduled / manual restore DRILL (decrypt + verify, nothing written)
  "blind-test", // POST /restore/verify: the blind restore test (every record decrypted to a discard sink)
  "attest", // POST /restore/attest: the Tier 0 KEYLESS attestation (signature + completeness + anti-rollback)
] as const;
export type RestoreFaultOp = (typeof RESTORE_FAULT_OPS)[number];
const RESTORE_FAULT_OP_SET: ReadonlySet<string> = new Set(RESTORE_FAULT_OPS);

export const RESTORE_FAULT_PHASES = [
  "open", // opening + verifying the sealed run (signature / chain / freshness) -- nothing was planned yet
  "plan", // scope resolution + the reserved-binding guard + the in-account window ceiling
  "verify", // the read-only verify-all pass (a failure here aborts with NOTHING written: the archive is suspect)
  "write", // the per-record write into the live resource
  "readback", // the POST-WRITE proof: the object was written, then re-read and re-hashed
  "cf-config", // a cf-config surface re-apply against the live Cloudflare API
  "media", // a media (Images/Stream) re-upload + its post-upload proof
  "dest-fallback", // the 3-2-1 replica walk: which destination refused, before the fallback masked it
  "receipt", // building / anchoring the signed restore receipt
] as const;
export type RestoreFaultPhase = (typeof RESTORE_FAULT_PHASES)[number];
const RESTORE_FAULT_PHASE_SET: ReadonlySet<string> = new Set(RESTORE_FAULT_PHASES);

export const RESTORE_FAULT_CLASSES = [
  // --- integrity (never an availability fault; a replica holds the SAME signed run and cannot remedy it) ---
  "integrity", // a plaintext-hash / GCM-auth / Merkle / completeness / structural failure: the ARCHIVE is suspect
  "freshness", // the anti-rollback verifier fired (a stale / rolled-back run)
  // --- availability ---
  "object-missing", // the object is absent from this destination (404 / "is missing")
  "dest-access", // the destination was REACHED and refused/faulted with an HTTP status (403 rotated creds, 5xx, 429, redirect) -- includes a WORM/Object-Lock refusal on the restore TARGET
  "recovery-check", // a network/transport fault with no HTTP status (a fetch that threw, a reset, a DNS failure)
  "origin-removed", // every destination this run was recorded to has been REMOVED: no credential can address the bytes
  "not-configured", // the engine cannot restore in-account at all (no operational read-back key: break-glass-only posture)
  // --- post-write proofs (the distinction "did my restore write anything?" turns on) ---
  "readback-failed", // the object WAS written but could not be read back to prove it (recoverable offline; NOT loss)
  "readback-mismatch", // the object WAS written and does NOT hash to the signed plaintext (the bucket ate or mangled the write)
  // readback-failed's two halves, which coarsening threw away. The bucket ATE the write (the get came back
  // absent) is a different fault from the bucket returning a BODYLESS object -- one is a lost write, the other a
  // store/proxy that is mangling reads -- and support cannot ask the right next question without the split.
  "readback-absent", // the just-written object was ABSENT on the read-back (the store accepted the write and does not have it)
  "readback-bodyless", // the object was present on the read-back but carried NO BODY (a store or proxy stripping the payload)
  // an over-single-put-limit refusal is DEFINED as OFFLINE-RECOVERABLE. The value was faithfully chained
  // across segments on backup and restores perfectly with the offline CLI; only the in-account path (one R2 PUT,
  // ~4.995 GiB) cannot land it. Recording it as a distinct class is what stops the bot and support reading a
  // steerable refusal as data loss.
  "over-single-put-limit",
  "d1-partial", // a D1 write faulted mid-way: the target database is written over several NON-ATOMIC batches, so it may be half-loaded
  // the fresh-target refusal is a REFUSAL that wrote nothing, not a partial apply -- and a customer whose
  // D1 restore "keeps refusing" needs to be told the target is not empty, not that their archive is suspect.
  "d1-target-not-empty",
  // a secret could not be restored because the operator never wired a runtime WRITE path (Secrets Store
  // bindings are read-only at runtime). It is a CONFIGURATION gap discovered in the disaster, and it is
  // recoverable out of band -- never a corrupt archive.
  "secret-sink-unwired",
  // --- the in-account apply surfaces ---
  "cf-config-write-failed", // a cf-config surface write was refused by the Cloudflare API
  "media-upload-failed", // a media re-upload threw against the Cloudflare API
  "media-readback-mismatch", // the media file uploaded but FAILED its post-upload proof (an image whose live blob does not hash, a video uid that does not resolve)
  // --- refusals that wrote nothing (all invisible today) ---
  "binding-missing", // the record's TARGET BINDING is not present in this engine's environment, so the record was SKIPPED: the classic "the restore reported success and wrote nothing" (every record skipped on a missing binding)
  "reserved-binding", // the target binding is one the engine reserves (the confused-deputy guard): the WHOLE restore refused before any write
  "too-large", // the combined in-account window exceeds the single-invocation ceiling: steer to the offline CLI -- OFFLINE-RECOVERABLE, never data loss
  "windowed", // maxRecords capped the apply: records beyond the window were never restored (an honest partial, not a failure)
  "scope-miss", // the requested record / D1 table / database is not in this run (a typo, or the wrong run)
  "marker-skipped", // the captured value is an INCOMPLETENESS MARKER (the object vanished or was skipped at capture), so nothing was written back: writing it would re-create a deleted key with marker JSON as its value
  // --- the two that had no row at all ---
  "apply-threw", // the apply THREW out of the restore core: the reservation was released and the router's audit row was never reached, so this apply left NO outcome anywhere
  "apply-crashed-lease-reclaimed", // an EARLIER apply reserved the approval, died mid-write and never released it; this reserve RECLAIMED the stale lease (proof a half-written apply happened, which the retry's overwrite otherwise erases)
  // the BREAK-GLASS-ONLY posture's honest refusal. It used to coarsen into "not-configured", so a drill
  // that CANNOT be exercised in-account by design read shape-identical to a drill that genuinely FAILED --
  // and a fleet of amber "failed last test" rows had support hunting a fault that does not exist. This says
  // "the engine holds no in-account read-back key; recovery is exercised offline with the break-glass key".
  "posture-unexercisable",
  // --- the D1 decode / validation refusals, which used to land in `other` with no locus at all ---
  // The three route to COMPLETELY different diagnoses, and telling them apart is the whole gap: support could
  // not distinguish a tampered archive from a writer bug, and could not spot that an unknown format hint means
  // ENGINE VERSION SKEW (the archive was written by a NEWER engine than the one restoring it, e.g. after a
  // rollback) -- a one-line diagnosis that was invisible.
  "d1-decode-tamper", // a CREATE statement in the archive carried MORE THAN ONE statement: a tamper signature in a signed archive, never a writer bug
  "d1-decode-corrupt", // the archive's D1 body failed a structural/decode validator (bad JSON, bad shape, bad base64, a non-finite REAL, a giant row, a bad rowid)
  "d1-format-unknown", // the D1 format hint is one this reader does not understand: ENGINE VERSION SKEW, not corruption -- the remedy is to restore with the newer engine
  "other", // residual: a refusal outside the named classes (never a message)
] as const;
export type RestoreFaultClass = (typeof RESTORE_FAULT_CLASSES)[number];
const RESTORE_FAULT_CLASS_SET: ReadonlySet<string> = new Set(RESTORE_FAULT_CLASSES);

// the three ENGINE BINDINGS a drill / restore can be missing. Naming WHICH one is the whole diagnosis:
// a wiped SIGNER_PRIVATE (a deploy that dropped the secret) and a break-glass-only posture and a deleted
// destination record all produce the same "restore test failed" row today.
export const RESTORE_BINDING_NAMES = ["signer-private", "operational-private", "dest-config"] as const;
export type RestoreBindingName = (typeof RESTORE_BINDING_NAMES)[number];
const RESTORE_BINDING_NAME_SET: ReadonlySet<string> = new Set(RESTORE_BINDING_NAMES);

/** One bounded restore-fault row. Closed enums + a clamped record label + the 8-hex log join key. */
export interface RestoreFaultRow {
  readonly at: number; // epoch ms (the DO clock)
  readonly op: RestoreFaultOp;
  readonly phase: RestoreFaultPhase;
  readonly cls: RestoreFaultClass;
  readonly recordName?: string; // the customer's OWN record label (incompleteIds class), clamped to 128. For a drill this is the ENGINE-WRITTEN archive object key that is missing -- engine-generated, never a customer record name
  readonly errId?: string; // the engine's 8-hex FNV exception id: the ONLY join key to the Workers-Logs line
  readonly count?: number; // for a class that aggregates (windowed: how many records were left unrestored; a drill: how many records of the window FAILED to decrypt-and-verify)
  // the drill's discriminating detail. index is the FIRST failing record's index in the run (so support
  // can say "records 0-400 verify and 401 does not" -- a lifecycle-expired chunk -- rather than "1 or 500?");
  // binding names WHICH engine binding was absent, so a wiped SIGNER_PRIVATE stops reading as a bad archive.
  readonly index?: number; // clamped non-negative int
  readonly binding?: RestoreBindingName;
}

export const RESTORE_FAULTS_KEY = "restore:faults";
// The ring ceiling. A restore that fails 5,000 records must not be able to grow storage: the per-op writer
// caps what it SENDS (RESTORE_FAULT_ROWS_PER_OP) and the ring caps what it KEEPS.
export const RESTORE_FAULTS_RING_CAP = 64;
export const RESTORE_FAULT_ROWS_PER_OP = 16;
// The record-label clamp: the same 128-char ceiling incompleteIds uses.
const RESTORE_FAULT_NAME_MAX = 128;
const RESTORE_FAULT_COUNT_CAP = 1_000_000;

/**
 * classifyRestoreFaultClass coarsens a restore failure REASON (or a per-record failure reason) into a closed
 * RestoreFaultClass. It reads the text ONLY to match the ENGINE'S OWN reason literals (restore-reasons.ts's
 * REASON_* constants and the per-record guidance sentences restore-apply.ts writes) and RETURNS the enum:
 * the text -- which may embed a sanitised S3 <Code>, a Cloudflare API message or a SQLite error -- never
 * leaves this function and can never reach a record.
 *
 * ORDERING is load-bearing and mirrors classifyRestoreFailure: the INTEGRITY tests run before any
 * availability test, so a corrupt archive can never be recorded as a destination-access fault.
 *
 * @param reason - the engine-produced reason string (never a raw provider message; may be undefined).
 * @returns the closed class.
 */
export function classifyRestoreFaultClass(reason: string | undefined): RestoreFaultClass {
  const m = reason ?? "";
  if (m === "") return "other";
  // the D1 decode refusals FIRST. They key on the ENGINE'S OWN throw literals (sources/d1-format.ts),
  // never a provider message, and the TAMPER test runs before the corruption test so a multi-statement DDL --
  // a tamper signature in a signed archive -- can never be absorbed into the generic corruption bucket. The
  // reason string embeds the customer's TABLE NAME; it is read here to select the enum and is never stored.
  if (/more than one statement|content after its terminating|unterminated BEGIN or CASE|is not a CREATE TABLE statement/i.test(m)) return "d1-decode-tamper";
  if (/unsupported D1 (backup|record) format/i.test(m)) return "d1-format-unknown";
  if (/D1 backup (body|table)|D1 rows record|D1 cell of unsupported|non-finite numeric value|D1 export:/i.test(m)) return "d1-decode-corrupt";
  // The post-write proof classes FIRST: their sentences also contain the word "verify"/"read back", and they
  // are the distinction ("was anything written?") that must never be coarsened away.
  if (m.includes("failed post-write readback verification")) return "readback-mismatch";
  if (m.includes("failed post-upload readback verification") || m.includes("restored uid could not be confirmed")) return "media-readback-mismatch";
  // the two halves of a failed read-back, keyed on the engine's OWN literals (dest/restore-sink.ts). They
  // are tested BEFORE the generic readback-failed arm, which stays as the residual for every other sink.
  if (m.includes("was absent on read-back")) return "readback-absent";
  if (m.includes("carried no body on read-back")) return "readback-bodyless";
  // the in-account single-PUT ceiling. Tested before the generic too-large arm because it is a DIFFERENT
  // remedy (the offline CLI restores this object today; the archive is intact).
  if (m.includes("too large for the in-account path")) return "over-single-put-limit";
  // the D1 fresh-target refusal and the unwired secret sink -- both refusals that wrote NOTHING.
  if (m.includes("D1 restore target is not empty")) return "d1-target-not-empty";
  if (m.includes("has no runtime write path")) return "secret-sink-unwired";
  if (m.includes("could not be read back to verify")) return "readback-failed";
  if (m.startsWith("partial restore:")) return "d1-partial";
  if (m.startsWith("Cloudflare config write failed")) return "cf-config-write-failed";
  if (m.startsWith("media re-upload failed")) return "media-upload-failed";
  if (m.includes("incompleteness marker") || m.includes("the captured value was a marker")) return "marker-skipped";
  // Integrity / freshness (non-fallback) before availability, exactly as classifyRestoreFailure orders them.
  if (m === "integrity check failed") return "integrity";
  // Both freshness reason literals coarsen to the one class, on the same ground as
  // coarseRestoreTestReasonCode: the fine split lives in the reason string, and the ring's closed class set
  // is read by surfaces outside this repo.
  if (m === "freshness check failed" || m === "freshness check could not run") return "freshness";
  // The refusals that wrote nothing. Each keys on the ENGINE'S OWN literal (restore-sinks.ts RESERVED_REASON /
  // inAccountTooLargeReason / windowSkippedReason / BREAK_GLASS_REASON, restore-plan.ts's skip reasons), so a
  // provider message can never reach one of these arms. windowSkippedReason ALSO mentions the offline CLI, so
  // it is tested BEFORE the oversized refusal: a windowed partial is not the same fault as a refused apply.
  if (m.includes("target binding is reserved")) return "reserved-binding";
  if (m.startsWith("windowed restore:")) return "windowed";
  if (m.includes("more than the in-account limit of")) return "too-large";
  // the break-glass-only refusal is NOT a failure and must stop being recorded as one (see the class).
  if (m.startsWith("break-glass-only posture")) return "posture-unexercisable";
  if (m.includes("not fully configured") || m.startsWith("missing required configuration")) return "not-configured";
  if (m === "target binding not present") return "binding-missing";
  if (m.includes("not found in run") || m.includes("table not found") || m.includes("database not found") || m.includes("cannot be combined")) return "scope-miss";
  // Availability.
  if (m.includes("only copy was on a removed destination")) return "origin-removed";
  if (m === "object missing") return "object-missing";
  if (m === "destination access error" || m.startsWith("destination access error (")) return "dest-access";
  if (m === "recovery check failed") return "recovery-check";
  return "other";
}

/**
 * stripControls removes C0/C1 control characters from a customer-owned label, so a record name can never
 * inject a line break (or a terminal escape) into an operator's view of the ring. It is a character-code
 * filter rather than a control-character regex, matching the codebase's existing idiom (admin/coverage.ts).
 *
 * @param s - the raw label.
 * @returns the label with every control character removed.
 */
function stripControls(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) continue;
    out += s[i];
  }
  return out;
}

/**
 * applyRestoreFault folds ONE untrusted row into the bounded ring. PURE, and the SINGLE REDACTION CHOKEPOINT
 * for this aggregate: an out-of-vocabulary op / phase / class is DROPPED (the ring is returned unchanged);
 * recordName is coerced to a string, stripped of ASCII control characters and CLAMPED to 128 chars; errId is
 * accepted ONLY as exactly 8 lower-case hex digits (so no message can ride in that field); count is clamped
 * to a bounded non-negative integer. NOTHING else on the posted body is read, so a raw error message, a
 * stack, a token or a bucket name structurally cannot enter the record even if a future call site posts one.
 *
 * @param prior - the stored ring, if any.
 * @param row - the posted row (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new ring (newest LAST, capped at RESTORE_FAULTS_RING_CAP).
 */
export function applyRestoreFault(prior: RestoreFaultRow[] | undefined, row: unknown, now: number): RestoreFaultRow[] {
  const ring = Array.isArray(prior) ? [...prior] : [];
  if (typeof row !== "object" || row === null) return ring;
  const r = row as Record<string, unknown>;
  const op = typeof r.op === "string" && RESTORE_FAULT_OP_SET.has(r.op) ? (r.op as RestoreFaultOp) : null;
  const phase = typeof r.phase === "string" && RESTORE_FAULT_PHASE_SET.has(r.phase) ? (r.phase as RestoreFaultPhase) : null;
  const cls = typeof r.cls === "string" && RESTORE_FAULT_CLASS_SET.has(r.cls) ? (r.cls as RestoreFaultClass) : null;
  if (op === null || phase === null || cls === null) return ring; // out-of-vocabulary: DROP, never persist
  const name = typeof r.recordName === "string" ? stripControls(r.recordName).slice(0, RESTORE_FAULT_NAME_MAX) : "";
  const eid = typeof r.errId === "string" && /^[0-9a-f]{8}$/.test(r.errId) ? r.errId : "";
  const n = typeof r.count === "number" && Number.isFinite(r.count) && r.count > 0 ? Math.min(RESTORE_FAULT_COUNT_CAP, Math.floor(r.count)) : 0;
  // an out-of-vocabulary binding is DROPPED and the index is clamped to a bounded non-negative int, so
  // neither field can carry a message, a path or a value.
  const binding = typeof r.binding === "string" && RESTORE_BINDING_NAME_SET.has(r.binding) ? (r.binding as RestoreBindingName) : null;
  const idx = typeof r.index === "number" && Number.isFinite(r.index) && r.index >= 0 ? Math.min(RESTORE_FAULT_COUNT_CAP, Math.floor(r.index)) : -1;
  ring.push({
    at: now,
    op,
    phase,
    cls,
    ...(name !== "" ? { recordName: name } : {}),
    ...(eid !== "" ? { errId: eid } : {}),
    ...(n > 0 ? { count: n } : {}),
    ...(idx >= 0 ? { index: idx } : {}),
    ...(binding !== null ? { binding } : {}),
  });
  return ring.slice(-RESTORE_FAULTS_RING_CAP);
}

// ---------------------------------------------------------------------------------------------------------
// THE ADMIN DIAGNOSTIC COUNTERS (the silent-fallback / silent-exclusion aggregate)
//
// Three separate audit gaps share one shape: an engine branch quietly SUBSTITUTES or EXCLUDES something and
// reports success. A crashed apply's reservation lease is reclaimed as a pure read-time projection (so the
// retry's overwrite erases the only trace that an apply died mid-write); a DO storage incident silently flips
// a console-activated Enterprise licence to the deploy-token tier; a corrupt run timestamp or a mis-shaped
// audit row is silently dropped from a point-in-time window or a signed compliance report, so a run that
// COVERS T reads as "no run exists" and a report shows a change that "was never recorded".
//
// None of these is a per-event ring: they are RATES. One bounded {closed name -> count, lastAt} aggregate,
// with the same defence-in-depth applier the droppedWrites tally uses, answers all three -- and a non-zero
// counter is exactly the signal that says "the surface you are reading is NOT telling you everything".
// ---------------------------------------------------------------------------------------------------------

export const ADMIN_COUNTER_NAMES = [
  // --- the crashed restore apply ---
  "restore-apply-lease-reclaimed", // an apply RESERVED the approval, died mid-write and never released it; a later reserve reclaimed the stale lease. The ONLY durable proof a half-written apply happened
  // --- the licence edge cases ---
  "licence-internal-error", // the licence backstop catch fired: an ENGINE fault (not a token fault) read as "malformed" and sent support chasing token corruption for days
  "licence-source-flip", // a console-activated licence silently resolved from the DEPLOY token instead (the DO read threw or answered non-2xx): the customer's Enterprise tier drops to whatever env holds
  // --- the silent exclusions ---
  "pit-corrupt-run-excluded", // a run row with an UNPARSEABLE startedAt was excluded from point-in-time resolution: a successful run covering T is invisible and the customer is told no run exists
  "report-row-excluded-unparseable-ts", // a signed compliance report silently dropped a row whose timestamp could not be placed in the window
  "report-row-excluded-shape", // a signed compliance report silently dropped a row whose target shape did not match the report's contract (a producer/consumer drift)
  "report-data-read-unavailable", // a report-data DO read FAULTED or answered non-2xx and used to be cast straight into the report body: the report would have been signed over garbage
  // --- destination configuration an operator SET and the engine silently DISCARDED ---
  // Each names the FIELD, never its value. The env-knob half is DERIVED at pack-build time from env
  // (dest/config-anomalies.ts classifyEnvDestAnomalies), so it needs no counter; the STORED half cannot be
  // derived (the DO's /destinations read returns the already-sanitised row), so the drop is counted HERE at
  // the read-for-use site (dest/factory.ts fetchDestConfig).
  "dest-config-worm-policy-dropped", // a stored WORM policy failed validation and was dropped: the console claims immutability and writes are NOT locked
  "dest-config-assume-role-policy-dropped", // a stored STS AssumeRole policy was dropped: the engine signs with the long-lived principal, so every cross-account write is AccessDenied
  "dest-config-storage-class-dropped", // a stored storage class was dropped: writes land in the bucket default tier and the operator's cost lever does nothing
  "dest-config-addressing-dropped", // a stored addressing style was dropped: the engine re-derives auto, which can be the wrong style for a non-AWS store
  "dest-config-incomplete", // the stored destination config is missing a required field: the read throws and NO backup can run against it
  // --- destination DEGRADATION on runs that still SUCCEEDED ---
  // The swallowed-by-design branches that make a green run take ten times as long, or cost ten times as much
  // (dest/dest-io.ts). Counts only: no key, status, header or endpoint can enter these.
  "dest-io-throttled", // the store answered 503/429 (real backpressure) and the pacer halved its rate: THE "why is it suddenly slow" signal
  "dest-io-retry-attempt", // a multipart step was re-issued after a transient fault: a retry that succeeds is invisible today, and is also the cost
  "dest-io-timeout", // an outbound destination request hit the finite fetch bound and was aborted: the endpoint black-holed rather than refused
  "dest-io-conditional-put-conflict", // a conditional PUT lost its precondition: a concurrent writer won (on the RUNLOG, two engines are fighting)
  "dest-io-head-collapsed-absent", // a HEAD answered neither 200 nor 404 (a 403 lost permission, a 5xx outage) and exists() collapsed it to "absent", so the segment RE-UPLOADS: the dedup-defeating fault
  "dest-io-retry-after-unparseable", // the store sent a Retry-After the engine could not read, so it backed off on a guess instead of on the store's instruction
  // --- DEGRADED READS: a DO read faulted and the surface answered from a SAFE DEFAULT rather than failing ---
  // Each names the surface that quietly told the operator "nothing here" when the truth was "I could not look".
  "degraded-read-preflight-roster",
  "degraded-read-dest-status",
  "degraded-read-setup-state",
  "degraded-read-discovery-config",
  "degraded-read-providers-list",
  "degraded-read-lockout-preflight",
  "degraded-read-engine-account",
  "degraded-read-status-presence",
  "ingest-pull-audit-export-failed",
  "ingest-pull-auth-failed",
  "ingest-pull-bad-cursor",
  "ingest-pull-gap-served",
  "ingest-pull-grant-unreadable",
  "ingest-pull-seal-failed",
  // --- WHICH of the five ways a /support pull's bearer was refused -------------------------------
  // The generic `ingest-pull-auth-failed` above counts refused pulls and cannot say what to DO about them.
  // The gate already decides between these five (classifyIngestCredentialCheck) and the two /support scopes
  // threw the answer away, while the /metrics scrape carried the same five through to
  // METRICS_SCRAPE_OUTCOMES. See admin/support-ingest.ts's INGEST_PULL_REFUSAL_COUNTERS for the full reasoning.
  "ingest-pull-refused-no-grant", // no credential exists for the scope at all: never minted, or revoked, and the collector is still polling
  "ingest-pull-refused-credential-expired", // the grant exists and is past its expiresAt: re-mint (the pack's `expired` boolean is the same fact from the other side)
  "ingest-pull-refused-credential-expiry-unreadable", // G312's fifth registration: the stored grant's expiresAt does not PARSE, so before this it could never expire and the gate authenticated for ever. Re-mint, and treat a corrupt stored record as its own incident
  "ingest-pull-refused-bearer-malformed", // the Authorization value was not <clientId>.<secret>: a truncated / re-wrapped / double-encoded field in the collector's config
  "ingest-pull-refused-client-id-mismatch", // a well-formed bearer carrying a clientId that is not the stored grant's: a STALE credential from a prior mint
  "ingest-pull-refused-secret-mismatch", // the clientId matched and the secret did not: a ROTATED grant the collector was never updated with
  "degraded-read-whoami", // the caller's role resolution read faulted or answered non-2xx: a genuine Owner can resolve to the VIEWER default and be told their own console is read-only ("every security-centre control is greyed out")
  // --- the compliance report the customer could not download ---
  "report-pdf-unparseable-ts", // the PDF renderer met a timestamp it could not render and coerced it to "unknown". BEFORE the guard this threw a RangeError deep inside PDF assembly and 500'd the whole DOWNLOAD, so an auditor's report could not be produced at all and nothing anywhere said why
  "report-pdf-render-failed", // the PDF render itself threw: the operator got a 500 and the pack held no evidence of it
  // --- the replication-degraded detector that silently switched itself OFF ---
  "replication-copy-count-invalid", // the configured copy count was unreadable, so classifyReplication could not decide degraded-vs-healthy and the whole replication-degraded ALERT quietly stopped firing. An alert that never fires reads exactly like a fleet with nothing wrong
  // --- the notify digest's conservative suppressions ---
  "notify-timestamp-parse-failed", // a digest window / group / summary timestamp did not parse and the pipeline SUPPRESSED conservatively: an alert the customer expected was never sent, and the suppression left no trace
  // --- the REJECTED runId shape (the restore / verify endpoints' 400s) ---
  // "Our integration script keeps getting 'invalid runId'": the rejection reached only the immediate HTTP
  // caller and NOTHING was persisted, so support could not say whether the ids arrive truncated, case-mangled
  // or out of range -- three different fixes on the customer's side. The KIND is the counter; the candidate
  // string (which could be any value a caller chose) is classified at the edge and DISCARDED there.
  "invalid-runid-length", // not 26 characters: a truncated / padded / concatenated id
  "invalid-runid-charset", // a non-Crockford character: a lower-cased id, a UUID, an O-for-0 transcription slip
  "invalid-runid-overflow", // 26 valid characters whose first overflows 128 bits: a home-made id generator
  // --- the estate rollup + coverage matcher degrading SILENTLY TO ZERO ---
  // Each of these reports a NUMBER the customer is billed and audited against, and each substitutes a WRONG one
  // rather than admitting it could not compute. "The licence page shows 0 protected bytes for a working fleet"
  // is the roster read below failing and being coerced to an empty list; "the gap view marks a clearly-backed-up
  // namespace unprotected" is a downpipe silently excluded from matching. Counts only: no resource label, no id.
  "volumes-read-failed-downpipes", // the downpipe ROSTER read faulted, so the rollup aggregated over an EMPTY fleet and reported ZERO protected bytes for a healthy estate
  "volumes-read-failed-history", // the RUN-HISTORY read faulted, so every downpipe's protected bytes read as zero
  "coverage-inventory-rejected-shape", // a submitted inventory was refused on shape: the customer believes they uploaded one and the gap view stays empty forever
  "coverage-inventory-rejected-over-cap", // an ENTERPRISE inventory exceeded the per-type ceiling and was refused WHOLE: a big account can never store an inventory, and nothing anywhere says why
  "coverage-downpipe-excluded-unknown-source-type", // a downpipe was silently excluded from coverage matching (its source type is not one the matcher knows), so the resource it protects reads UNPROTECTED
  "coverage-downpipe-excluded-no-identity-key", // a downpipe was silently excluded from coverage matching (no identity key to match on): the same false "unprotected" verdict
  // --- CORRUPT STORED GOVERNANCE / REGISTRY RECORDS that fail OPEN or fail QUIET ---
  // Each is a stored record the engine reads back, cannot parse, and quietly substitutes a safe-LOOKING default
  // for while reporting success. The consequences: an approval usable far past its TTL, a destination key that
  // expires with ZERO warning (its garbled expiry row reads green forever), and a stored custom role silently
  // shedding a tampered owner-reserved capability. All invisible remotely; the first two are security-relevant.
  // Counts only: never the record content, the label, or the timestamp text that would not parse.
  "stored-approval-unparseable-timestamp", // an approval's stored timestamp did not parse, so its 24h TTL could not be enforced: the approval may be usable indefinitely
  "stored-owner-action-unparseable-timestamp", // the same, on an owner-action queue row
  "stored-expiry-unparseable-timestamp", // an expiry-registry row's timestamp did not parse, so the item is never warned about. "Our destination key expired with zero warning" is THIS
  // REMOVED: `stored-expiry-unknown-kind`. It named a read-time SKIP that does not exist. Nothing on
  // the warning path gates on the kind: reconcileExpiry walks every stored row, laddersFor is TOTAL (an unknown
  // kind takes the default 30-day ladder rather than being dropped), and daysRemaining is computed from the
  // expiry alone -- so a row with a garbled kind is still counted, still laddered and still warned about. The
  // only kind check in the system (isExpiryKind) is at WRITE time, and its refusal already has a producer, the
  // one below. A counter for a skip the code does not perform is a promise that cannot be kept.
  "stored-expiry-write-rejected", // an expiry OBSERVATION was refused at write time, so the item was never enrolled at all: no warning can EVER fire for it
  "stored-custom-role-reserved-capability-dropped", // a stored custom role claimed an OWNER-RESERVED capability and the clamp dropped it. The clamp is correct; the drop is a TAMPER signal that was recorded nowhere
  // --- OPERATOR-SUBMITTED CONFIG the engine silently DROPPED at the SUBMIT boundary ---
  // The read-for-use half of this already exists above (dest-config-worm-policy-dropped, at dest/factory.ts).
  // These are the SUBMIT half: the request SUCCEEDED, the console shows the setting, and the engine never stored
  // it. "We configured WORM and ransomware deleted our archive copies" is the first one. The submitted VALUE
  // never rides -- it was rejected precisely for being unusable, and carrying it would be the leak.
  "dest-config-worm-policy-submitted-dropped", // a submitted WORM policy failed validation and was DROPPED while the destination was still stored and the request still answered 2xx: the console claims immutability and writes are NOT locked
  "restore-buffered-max-invalid", // RESTORE_BUFFERED_MAX_BYTES is set and unreadable, so the engine silently used its default: "we set the knob and records still buffer" (the destResolution.rateKnobInvalid precedent, mirrored)
  // --- the RTO drill samples the estimate SILENTLY EXCLUDED ---
  // "basedOnDrills says 2 but we ran 15 restore tests": 13 samples carried a non-finite duration or a zero byte
  // count and were dropped from the throughput maths. The DROP is correct (a zero-duration sample carries no
  // throughput signal and would corrupt the estimate); its INVISIBILITY is the gap.
  "rto-sample-rejected-non-finite-duration", // a drill sample's duration was NaN / Infinity / negative: excluded from the estimate, and the count-vs-basedOnDrills discrepancy had no explanation at all
  "rto-sample-rejected-non-positive-bytes", // a drill sample verified ZERO bytes: the same exclusion, a different cause (an empty archive, or a drill that verified nothing)
  // --- the CRON plane's loudest facts ---
  // The RICH, structured evidence for each of these lives in the bounded cron-health record
  // (cron/cron-fault-ledger.ts: the closed event that was never delivered, the per-destination export fail
  // class, the per-downpipe restore-test skip class). These are the ALARM BELLS: one closed name each, raised
  // at the drain (noteAdminAlarm, the single place any of them can be set), so a pack carries the HEADLINE
  // fact of each gap. A non-zero counter here says "look at cronHealth".
  "notify-critical-alert-undelivered", // G184: a ONE-SHOT critical alert was CONSUMED (its claim spent, its dedupe latched) and delivered to NO channel. The page is permanently lost -- nobody was told backups had stopped
  "notify-history-append-failed", // G294: a notify history append was DROPPED, so a delivered alert can leave no row at all: "was our critical alert delivered?" is unanswerable from the pack in exactly the case that matters
  "update-channel-verify-failed", // G319: the signed update channel stopped VERIFYING (a signing-key rotation, or tamper) and the alert pass returns silently: "we were never told a critical update existed"
  "cp-export-dest-failed", // G292: a destination REFUSED the signed control-plane recovery artefact, so ITS recovery generation is stale while export health looks green (the closed cause is in cronHealth.cpExport.perDestFail)
  "cp-export-record-write-failed", // G292: the export-health record write ITSELF was lost, so the pack reads a stale export health as if it were this tick's verdict
  "cp-export-plaintext-purge-pending", // G292: readable PLAINTEXT control-plane exports could not be purged from a sealed-posture bucket, so the roster/topology stays readable in the destination and nothing said so
  "push-trail-write-failed", // G293: a SIEM/OTLP delivery-trail write was dropped. On a SUCCESSFUL delivery that strands the cursor, so the next tick re-sends the same batch: the duplicate-events ticket
  "restore-test-not-run", // G295: a scheduled restore test did NOT run (a pre-drill throw, chronic budget starvation, a lost outcome write). "Never tested for months", with a perfectly healthy-looking engine behind it
  "reconcile-pass-skipped", // G333: the orphan-reconcile pass recorded no signal this tick, so its last signal may be months old -- and a stale signal is indistinguishable from a fresh one
  // --- the onboarding cost projection that reads as an EMPTY ACCOUNT ---
  // "The cost projection shows 0 records for our account with thousands of images/videos/scripts." The estate
  // probe fails SOFT to an honest-looking zero, and a dead or under-scoped discovery token -- at the exact
  // moment it is cheapest to catch, before any run -- is presented to the customer as an empty account.
  "cost-estate-token-missing", // no account id / discovery token could be resolved, so the probe never ran and the projection answered available:false (which the console renders as nothing to back up)
  "cost-estate-probe-failed", // the estate-size probe THREW, so the whole projection collapsed to the same mute zero
  // --- the POSTURE family: the controls the customer believes are in force ---
  // Spread from admin/posture-counters.ts, which holds the per-member rationale. They share this aggregate,
  // this applier and this redaction chokepoint; they live in their own leaf only because this module is at its
  // size ceiling and because they are one coherent family (a control that silently stopped applying).
  ...POSTURE_COUNTER_NAMES,
] as const;
export type AdminCounterName = (typeof ADMIN_COUNTER_NAMES)[number];
const ADMIN_COUNTER_NAME_SET: ReadonlySet<string> = new Set(ADMIN_COUNTER_NAMES);

/** The bounded admin-counter aggregate: closed name -> { count, lastAt }. Counts only, never a payload. */
export interface AdminCounterEntry {
  readonly count: number;
  readonly lastAt: string;
}
export type AdminCounters = Record<string, AdminCounterEntry>;

export const ADMIN_COUNTERS_KEY = "diag:admincounters";
const ADMIN_COUNTER_COUNT_CAP = 1_000_000_000;
const ADMIN_COUNTER_BUMP_CAP = 100_000;

/**
 * applyAdminCounters folds ONE posted {name: count} tally into the aggregate. PURE, and the single redaction
 * chokepoint: an out-of-vocabulary name is DROPPED and every count is clamped to a bounded non-negative
 * integer, so the key space is bounded by ADMIN_COUNTER_NAMES and no message, id or value can enter.
 *
 * @param prior - the stored aggregate, if any.
 * @param bumps - the posted {name: count} tally (untrusted).
 * @param nowIso - the DO clock as an ISO string (injected).
 * @returns the new aggregate.
 */
export function applyAdminCounters(prior: AdminCounters | undefined, bumps: unknown, nowIso: string): AdminCounters {
  const map: AdminCounters = { ...(prior ?? {}) };
  if (typeof bumps !== "object" || bumps === null || Array.isArray(bumps)) return map;
  for (const [name, raw] of Object.entries(bumps as Record<string, unknown>)) {
    if (!ADMIN_COUNTER_NAME_SET.has(name)) continue; // defence in depth: never a caller-injected key
    const n = typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? Math.min(ADMIN_COUNTER_BUMP_CAP, Math.floor(raw)) : 0;
    if (n === 0) continue;
    const prev = map[name];
    map[name] = { count: Math.min(ADMIN_COUNTER_COUNT_CAP, (prev?.count ?? 0) + n), lastAt: nowIso };
  }
  return map;
}

// ---------------------------------------------------------------------------------------------------------
// THE INTEGRITY FAULT AGGREGATE (the format + crypto core)
//
// The seal / verify / restore core is a PURE computation with no DO stub, so its faults could only ever be
// THROWN -- and by the time a throw reaches a catch that owns a stub it has been coarsened to "integrity check
// failed" or "RUNLOG absent". format/integrity-fault-ledger.ts is the isolate-local accumulator the fault SITE
// records into; this is the DO-side aggregate it is drained into, and applyIntegrityFaults below is the SINGLE
// REDACTION CHOKEPOINT: it re-validates every field against the closed vocabularies (an out-of-vocabulary
// stage / class / kind / role / leg is DROPPED, every count is clamped, every digest and fingerprint must pass
// a hex shape gate), so even a drifted or compromised caller cannot land a raw exception message, an object
// key, a bucket, an endpoint or a byte of key material here.
//
// Keyed per-downpipe (the customer's OWN opaque id, the class the pack already carries in downpipes[]), so the
// pack can say "THIS downpipe's archive fails at the capsule unwrap, THAT one at the record hash".
// ---------------------------------------------------------------------------------------------------------

// The closed vocabularies, re-declared here rather than imported: this module is a LEAF by construction (it
// imports NOTHING, see the header), and the DO must be able to re-gate a posted body without dragging the
// format layer's whole graph into the DO base. The two are pinned to each other by validate-integrity-faults,
// which asserts the sets are identical members for members.
const INTEGRITY_FETCH_SITES: ReadonlySet<string> = new Set(["runlog", "root-manifest", "recovery-bundle"]);
const INTEGRITY_FETCH_CLASSES: ReadonlySet<string> = new Set(["not-found", "access-denied", "throttled", "cold-storage", "network", "other"]);
const INTEGRITY_FETCH_STATUS: ReadonlySet<string> = new Set(["4xx", "5xx", "none"]);
export const VERIFY_FAIL_STAGE_NAMES = [
  "capsule-unwrap",
  "root-structure",
  "format-version",
  "shard-hash",
  "freshness-signature",
  "freshness-index",
  "freshness-chain",
  "recovery-bundle",
] as const;
const VERIFY_FAIL_STAGE_SET: ReadonlySet<string> = new Set(VERIFY_FAIL_STAGE_NAMES);
const CLASSIFIED_BY_SET: ReadonlySet<string> = new Set(["typed", "keyword-fallback"]);
export const INTEGRITY_FAULT_KIND_NAMES = [
  "absent",
  "chunk-range",
  "decompress-overflow",
  "malformed-object-key",
  "defaulted-empty-record",
  "checkpoint-corrupt",
] as const;
const INTEGRITY_FAULT_KIND_SET: ReadonlySet<string> = new Set(INTEGRITY_FAULT_KIND_NAMES);
export const CRYPTO_FAULT_CLASS_NAMES = [
  "key-wrong-label",
  "key-malformed-b64url",
  "recipient-no-capsule-match",
  "recipient-noncontributory",
  "verify-structural-fault",
  "verify-mismatch",
] as const;
const CRYPTO_FAULT_CLASS_SET: ReadonlySet<string> = new Set(CRYPTO_FAULT_CLASS_NAMES);
export const CRYPTO_KEY_ROLE_NAMES = ["signer", "operational", "break-glass", "recipient", "verifier"] as const;
const CRYPTO_KEY_ROLE_SET: ReadonlySet<string> = new Set(CRYPTO_KEY_ROLE_NAMES);
const STREAM_LEG_SET: ReadonlySet<string> = new Set(["source-read", "dest-write", "decrypt-open"]);
export const STREAM_FAULT_CLASS_NAMES = ["short-nonce", "no-chunks", "short-chunk", "over-limit-chunks", "gcm-auth-fail", "container-framing", "master-length-mismatch"] as const;
const STREAM_FAULT_CLASS_SET: ReadonlySet<string> = new Set(STREAM_FAULT_CLASS_NAMES);
// the anti-rollback / RUNLOG anomaly kinds (format/integrity-fault-ledger.ts RUNLOG_ANOMALY_KINDS).
export const RUNLOG_ANOMALY_KIND_NAMES = ["duplicate-index", "forked-prev", "dangling-prev", "chain-break", "index-regression", "parse-field", "sig-invalid", "runlog-absent", "run-missing", "root-disagreement"] as const;
const RUNLOG_ANOMALY_KIND_SET: ReadonlySet<string> = new Set(RUNLOG_ANOMALY_KIND_NAMES);
// the writer's loud refusals (format/integrity-fault-ledger.ts WRITER_REFUSAL_KINDS).
export const WRITER_REFUSAL_KIND_NAMES = ["source-enumerated-zero", "stream-no-destination", "secrets-streamed"] as const;
const WRITER_REFUSAL_KIND_SET: ReadonlySet<string> = new Set(WRITER_REFUSAL_KIND_NAMES);
// the attestation coverage modes (format/integrity-fault-ledger.ts KEYLESS_COVERAGE_MODES). Only the
// DEGRADED members are ever posted, but the full set is re-declared so the pin test can assert no drift.
export const KEYLESS_COVERAGE_NAMES = ["full", "sampled", "sampled-no-presence"] as const;
const KEYLESS_COVERAGE_SET: ReadonlySet<string> = new Set(KEYLESS_COVERAGE_NAMES);

// The shape gates on the ONLY two non-enum, non-integer values permitted: a 12-hex one-way digest (the
// causeDigest class, joinable to the customer's own bucket listing and reversible by nobody) and a hex
// fingerprint of PUBLIC key material (the class the pack already carries under keys.*).
const INTEGRITY_DIGEST_RE = /^[0-9a-f]{12}$/;
const INTEGRITY_FP_RE = /^(?:dpr1:)?[0-9a-f]{8,96}$/;
// The format-major label is a FIXED PRODUCT vocabulary shape, never a manifest value.
const FORMAT_MAJOR_RE = /^downpipe\/\d{1,3}\.x$/;

/** One per-downpipe integrity-fault record: closed-vocabulary counts plus three bounded rings. */
export interface IntegrityFaultRecord {
  readonly fetchFaults: Record<string, number>; // "<site>|<class>|<statusClass>" -> count
  readonly failStages: Record<string, number>; // closed stage -> count
  readonly classifiedBy: Record<string, number>; // typed | keyword-fallback -> count (a keyword-fallback class is LOWER-CONFIDENCE evidence)
  readonly locators: IntegrityLocatorRow[];
  readonly cryptoFaults: CryptoFaultRow[];
  readonly streamFaults: StreamFaultRow[];
  readonly defaultedEmptyRecords: number; // records SEALED AS ZERO BYTES behind a green run
  readonly formatVersionSeen?: string; // format-version only: the encountered major label
  // the FORENSICS of an anti-rollback / RUNLOG anomaly -- which anomaly, the two disagreeing indices,
  // the unparseable line's ordinal, the chain length, and a 12-hex one-way digest of the RUNLOG bytes the
  // customer can reproduce from their own object. This is the record behind "the engine says our backup
  // history may have been rewritten"; before it, that detection persisted nothing at all.
  readonly runlogAnomalies: RunlogAnomalyRow[];
  // the writer's loud refusals, closed kind -> count. source-enumerated-zero is a CUSTOMER fault (an
  // emptied namespace, a de-scoped token); the other two are ENGINE wiring invariants. The run row could only
  // ever say "run failed".
  readonly writerRefusals: Record<string, number>;
  // the DEGRADED coverage mode of this downpipe's most recent keyless attestation ("sampled" or
  // "sampled-no-presence"). Absent when every attestation read back in full. sampled-no-presence is the mode
  // in which complete:true OVERCLAIMS (no per-shard presence pass ran).
  readonly attestCoverage?: string;
  readonly at: number; // epoch ms of the most recent fold
}

/** One RUNLOG anomaly row: closed kind, the disagreeing index pair, the locus, and a one-way digest. */
export interface RunlogAnomalyRow {
  readonly kind: string;
  readonly indexA?: number;
  readonly indexB?: number;
  readonly lineOrdinal?: number;
  readonly entryCount?: number;
  readonly digest?: string; // 12 lower-case hex over the RUNLOG BYTES; never a line, a run id or a downpipe id
}

export interface IntegrityLocatorRow {
  readonly kind: string;
  readonly shardOrdinal?: number;
  readonly declaredCount?: number;
  readonly recoveredCount?: number;
  readonly digest?: string;
}
export interface CryptoFaultRow {
  readonly cls: string;
  readonly role: string;
  readonly heldFingerprint?: string;
  readonly wantFingerprint?: string;
  readonly lengthClass?: number;
}
export interface StreamFaultRow {
  readonly leg: string;
  readonly cls: string;
  readonly segmentOrdinal?: number;
  readonly chunkIndex?: number;
  readonly receivedBytes?: number;
  readonly expectedBytes?: number;
}

export type IntegrityFaults = Record<string, IntegrityFaultRecord>;
export const INTEGRITY_FAULTS_KEY = "diag:integrityfaults";
// The per-downpipe ceiling: only a FAULTING downpipe holds a row.
//
// THE EDGE IS RIGHT AND THE REFUSAL WAS SILENT. This is not a ring: past the cap it
// admits NOBODY, so the 101st faulting downpipe is ABSENT rather than late, and a downpipe absent from an
// integrity-fault record reads as one whose archives VERIFIED. The cap stays at 100 and the refusal is
// DECLARED instead, so the pack carries the sentence a diagnosis needs: this list is a LOWER BOUND.
export const INTEGRITY_FAULTS_DOWNPIPE_CAP = 100;
const INTEGRITY_RING_CAP = 16;
const INTEGRITY_COUNT_CAP = 1_000_000;
const INTEGRITY_KEY_CAP = 64; // the bounded key space of the "<site>|<class>|<status>" composite map

// intOrUndef is the numeric gate: NaN, Infinity, a negative and an absent value are DROPPED.
function intOrUndef(n: unknown): number | undefined {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return undefined;
  return Math.min(Number.MAX_SAFE_INTEGER, Math.floor(n));
}

// foldCounts folds an untrusted {key: count} map into a bounded aggregate, keeping ONLY keys the supplied
// predicate accepts. Every count is clamped; the key space is bounded. This is why no caller-authored string
// can become a storage key here.
function foldCounts(prior: Record<string, number>, posted: unknown, accept: (k: string) => boolean): Record<string, number> {
  const out: Record<string, number> = { ...prior };
  if (typeof posted !== "object" || posted === null || Array.isArray(posted)) return out;
  for (const [k, raw] of Object.entries(posted as Record<string, unknown>)) {
    if (!accept(k)) continue;
    if (out[k] === undefined && Object.keys(out).length >= INTEGRITY_KEY_CAP) continue;
    const n = intOrUndef(raw);
    if (n === undefined || n === 0) continue;
    out[k] = Math.min(INTEGRITY_COUNT_CAP, (out[k] ?? 0) + n);
  }
  return out;
}

// acceptFetchKey gates the composite "<site>|<class>|<statusClass>" key: all THREE halves must be closed-set
// members, so the key space is exactly |sites| x |classes| x |statuses| and nothing else can enter.
function acceptFetchKey(k: string): boolean {
  const parts = k.split("|");
  return parts.length === 3 && INTEGRITY_FETCH_SITES.has(parts[0]!) && INTEGRITY_FETCH_CLASSES.has(parts[1]!) && INTEGRITY_FETCH_STATUS.has(parts[2]!);
}

/**
 * applyIntegrityFaults folds ONE drained ledger snapshot into a downpipe's bounded record. PURE, and the
 * SINGLE REDACTION CHOKEPOINT for this aggregate: every enum is re-checked against its closed set, every count
 * and ordinal is clamped, every digest and fingerprint must pass a hex shape gate, and the format label must
 * match the fixed product shape. NOTHING else on the posted body is read, so a raw error message, a stack, an
 * object key, a bucket, an endpoint or a byte of key material structurally cannot enter the record even if a
 * future call site posts one.
 *
 * @param prior - the stored aggregate, if any.
 * @param downpipeId - the customer's own opaque downpipe id (already shape-gated by the caller).
 * @param snap - the posted snapshot (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new aggregate.
 */
export function applyIntegrityFaults(prior: IntegrityFaults | undefined, downpipeId: string, snap: unknown, now: number): IntegrityFaults {
  return applyIntegrityFaultsCounted(prior, downpipeId, snap, now).record;
}
/**
 * applyIntegrityFaultsCounted is applyIntegrityFaults plus the ONE fact the caller could not previously
 * learn: whether the cap REFUSED this downpipe. It carries the whole implementation, so the redaction
 * chokepoint stays single and the wrapper above is only a convenience. The count is booked cumulatively
 * against capTruncations, so a non-zero count means "some downpipe rows are missing", never "exactly N are".
 * WHICH downpipe needs no return value here: the caller passes the id it just handed in, because a refusal
 * of 1 is always a refusal of THAT downpipe.
 *
 * @param prior - the stored aggregate, if any.
 * @param downpipeId - the customer's own opaque downpipe id (already shape-gated by the caller).
 * @param snap - the posted snapshot (untrusted).
 * @param now - the DO clock (injected).
 * @returns the aggregate, and 1 when the cap refused this downpipe.
 */
export function applyIntegrityFaultsCounted(prior: IntegrityFaults | undefined, downpipeId: string, snap: unknown, now: number): { record: IntegrityFaults; refusedSubjects: number } {
  const map: IntegrityFaults = { ...(prior ?? {}) };
  // A malformed body is not a cap refusal: nothing was dropped for want of room, so nothing is declared.
  if (typeof snap !== "object" || snap === null || Array.isArray(snap)) return { record: map, refusedSubjects: 0 };
  // THE REFUSAL, NOW AUDIBLE. A downpipe already in the map is always folded: the cap bounds the SUBJECT
  // space, never the evidence about a subject already known to be faulting.
  if (map[downpipeId] === undefined && Object.keys(map).length >= INTEGRITY_FAULTS_DOWNPIPE_CAP) return { record: map, refusedSubjects: 1 };
  const s = snap as Record<string, unknown>;
  const prev = map[downpipeId];

  const locators: IntegrityLocatorRow[] = [...(prev?.locators ?? [])];
  for (const raw of Array.isArray(s.locators) ? s.locators.slice(0, INTEGRITY_RING_CAP) : []) {
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    if (typeof r.kind !== "string" || !INTEGRITY_FAULT_KIND_SET.has(r.kind)) continue; // out of vocabulary: DROP
    const digest = typeof r.digest === "string" && INTEGRITY_DIGEST_RE.test(r.digest) ? r.digest : undefined;
    locators.push({
      kind: r.kind,
      ...(intOrUndef(r.shardOrdinal) !== undefined ? { shardOrdinal: intOrUndef(r.shardOrdinal)! } : {}),
      ...(intOrUndef(r.declaredCount) !== undefined ? { declaredCount: intOrUndef(r.declaredCount)! } : {}),
      ...(intOrUndef(r.recoveredCount) !== undefined ? { recoveredCount: intOrUndef(r.recoveredCount)! } : {}),
      ...(digest !== undefined ? { digest } : {}),
    });
  }

  const cryptoFaults: CryptoFaultRow[] = [...(prev?.cryptoFaults ?? [])];
  for (const raw of Array.isArray(s.cryptoFaults) ? s.cryptoFaults.slice(0, INTEGRITY_RING_CAP) : []) {
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    if (typeof r.cls !== "string" || !CRYPTO_FAULT_CLASS_SET.has(r.cls)) continue;
    if (typeof r.role !== "string" || !CRYPTO_KEY_ROLE_SET.has(r.role)) continue;
    const held = typeof r.heldFingerprint === "string" && INTEGRITY_FP_RE.test(r.heldFingerprint) ? r.heldFingerprint : undefined;
    const want = typeof r.wantFingerprint === "string" && INTEGRITY_FP_RE.test(r.wantFingerprint) ? r.wantFingerprint : undefined;
    cryptoFaults.push({
      cls: r.cls,
      role: r.role,
      ...(held !== undefined ? { heldFingerprint: held } : {}),
      ...(want !== undefined ? { wantFingerprint: want } : {}),
      ...(intOrUndef(r.lengthClass) !== undefined ? { lengthClass: intOrUndef(r.lengthClass)! } : {}),
    });
  }

  const streamFaults: StreamFaultRow[] = [...(prev?.streamFaults ?? [])];
  for (const raw of Array.isArray(s.streamFaults) ? s.streamFaults.slice(0, INTEGRITY_RING_CAP) : []) {
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    if (typeof r.leg !== "string" || !STREAM_LEG_SET.has(r.leg)) continue;
    if (typeof r.cls !== "string" || !STREAM_FAULT_CLASS_SET.has(r.cls)) continue;
    streamFaults.push({
      leg: r.leg,
      cls: r.cls,
      ...(intOrUndef(r.segmentOrdinal) !== undefined ? { segmentOrdinal: intOrUndef(r.segmentOrdinal)! } : {}),
      ...(intOrUndef(r.chunkIndex) !== undefined ? { chunkIndex: intOrUndef(r.chunkIndex)! } : {}),
      ...(intOrUndef(r.receivedBytes) !== undefined ? { receivedBytes: intOrUndef(r.receivedBytes)! } : {}),
      ...(intOrUndef(r.expectedBytes) !== undefined ? { expectedBytes: intOrUndef(r.expectedBytes)! } : {}),
    });
  }

  // the RUNLOG anomaly ring. The kind must be a closed member, every index / ordinal / count is clamped,
  // and the digest must pass the same 12-hex shape gate as causeDigest -- so the anomaly REASON (which names
  // the customer's runs and downpipes), a RUNLOG line and any raw value are structurally excluded, exactly as
  // they are for the locator ring above.
  const runlogAnomalies: RunlogAnomalyRow[] = [...(prev?.runlogAnomalies ?? [])];
  for (const raw of Array.isArray(s.runlogAnomalies) ? s.runlogAnomalies.slice(0, INTEGRITY_RING_CAP) : []) {
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    if (typeof r.kind !== "string" || !RUNLOG_ANOMALY_KIND_SET.has(r.kind)) continue; // out of vocabulary: DROP
    const digest = typeof r.digest === "string" && INTEGRITY_DIGEST_RE.test(r.digest) ? r.digest : undefined;
    runlogAnomalies.push({
      kind: r.kind,
      ...(intOrUndef(r.indexA) !== undefined ? { indexA: intOrUndef(r.indexA)! } : {}),
      ...(intOrUndef(r.indexB) !== undefined ? { indexB: intOrUndef(r.indexB)! } : {}),
      ...(intOrUndef(r.lineOrdinal) !== undefined ? { lineOrdinal: intOrUndef(r.lineOrdinal)! } : {}),
      ...(intOrUndef(r.entryCount) !== undefined ? { entryCount: intOrUndef(r.entryCount)! } : {}),
      ...(digest !== undefined ? { digest } : {}),
    });
  }

  const label = typeof s.formatVersionSeen === "string" && FORMAT_MAJOR_RE.test(s.formatVersionSeen) ? s.formatVersionSeen : prev?.formatVersionSeen;
  const defaulted = intOrUndef(s.defaultedEmptyRecords) ?? 0;
  // the coverage mode. Only a closed member is kept, and the WEAKER claim wins: once a downpipe has been
  // attested WITHOUT the presence pass, a later sampled-with-presence run must not overwrite the record of the
  // weaker one -- that is the whole finding ("this run's complete:true was the degraded kind").
  const postedCoverage = typeof s.attestCoverage === "string" && KEYLESS_COVERAGE_SET.has(s.attestCoverage) && s.attestCoverage !== "full" ? s.attestCoverage : undefined;
  const coverage = prev?.attestCoverage === "sampled-no-presence" ? prev.attestCoverage : (postedCoverage ?? prev?.attestCoverage);

  map[downpipeId] = {
    fetchFaults: foldCounts(prev?.fetchFaults ?? {}, s.fetchFaults, acceptFetchKey),
    failStages: foldCounts(prev?.failStages ?? {}, s.failStages, (k) => VERIFY_FAIL_STAGE_SET.has(k)),
    classifiedBy: foldCounts(prev?.classifiedBy ?? {}, s.classifiedBy, (k) => CLASSIFIED_BY_SET.has(k)),
    locators: locators.slice(-INTEGRITY_RING_CAP),
    cryptoFaults: cryptoFaults.slice(-INTEGRITY_RING_CAP),
    streamFaults: streamFaults.slice(-INTEGRITY_RING_CAP),
    defaultedEmptyRecords: Math.min(INTEGRITY_COUNT_CAP, (prev?.defaultedEmptyRecords ?? 0) + defaulted),
    ...(label !== undefined ? { formatVersionSeen: label } : {}),
    runlogAnomalies: runlogAnomalies.slice(-INTEGRITY_RING_CAP),
    writerRefusals: foldCounts(prev?.writerRefusals ?? {}, s.writerRefusals, (k) => WRITER_REFUSAL_KIND_SET.has(k)),
    ...(coverage !== undefined ? { attestCoverage: coverage } : {}),
    at: now,
  };
  return { record: map, refusedSubjects: 0 };
}

// ---------------------------------------------------------------------------------------------------------
// THE LAST-RESORT DISPATCH FAULT RING (index.ts's four catch-all handlers, log.ts)
//
// The Worker's four last-resort catches (the /admin dispatch, the non-admin dispatch that serves /support and
// /metrics, the SCIM facade, the manual canary) each log an errId and return a 500. Nothing touches DO state,
// so the pack carries ZERO trace of which surface threw or how often -- and the non-admin case is
// self-referential: a broken support endpoint cannot report itself into a pack that never gets built. A ring
// here surfaces it in the NEXT successful pull.
//
// NO-CUSTODY: surface and routeFamily are closed enums; errId is the engine's existing irreversible FNV
// exception id (the ONLY join key to the Workers-Logs line); httpStatus is an integer. The exception message,
// the stack, the raw path, the query string and the caller identity NEVER ride.
// ---------------------------------------------------------------------------------------------------------

export const DISPATCH_SURFACES = ["admin", "scim", "fetch", "canary-manual"] as const;
export type DispatchSurface = (typeof DISPATCH_SURFACES)[number];
const DISPATCH_SURFACE_SET: ReadonlySet<string> = new Set(DISPATCH_SURFACES);

// The route FAMILY is derived from the path PREFIX at the call site and is a closed product vocabulary: it
// says which console screen is 500ing without ever carrying the path, the query string or an id from it.
export const DISPATCH_ROUTE_FAMILIES = ["downpipes", "notify", "restore", "support", "keys", "identity", "destinations", "other"] as const;
export type DispatchRouteFamily = (typeof DISPATCH_ROUTE_FAMILIES)[number];
const DISPATCH_ROUTE_FAMILY_SET: ReadonlySet<string> = new Set(DISPATCH_ROUTE_FAMILIES);

/** One last-resort dispatch fault. Closed enums + the irreversible 8-hex log join key + an int status. */
export interface DispatchFaultRow {
  readonly at: number;
  readonly surface: DispatchSurface;
  readonly routeFamily?: DispatchRouteFamily;
  readonly errId?: string;
  readonly httpStatus?: number;
}

export const DISPATCH_FAULTS_KEY = "diag:dispatchfaults";
export const DISPATCH_FAULTS_CAP = 64;
const DISPATCH_ERRID_RE = /^[0-9a-f]{8}$/;

/**
 * applyDispatchFault folds ONE untrusted dispatch-fault row into the bounded ring. PURE, and the single
 * redaction chokepoint: an out-of-vocabulary surface or route family is DROPPED, the errId is accepted ONLY as
 * exactly 8 lower-case hex digits (so no message can ride in that field), and the status is clamped to a plain
 * HTTP range. Nothing else on the body is read.
 *
 * @param prior - the stored ring, if any.
 * @param row - the posted row (untrusted).
 * @param now - the DO clock (injected).
 * @returns the new ring (newest LAST, capped).
 */
export function applyDispatchFault(prior: DispatchFaultRow[] | undefined, row: unknown, now: number): DispatchFaultRow[] {
  const ring = Array.isArray(prior) ? [...prior] : [];
  if (typeof row !== "object" || row === null) return ring;
  const r = row as Record<string, unknown>;
  if (typeof r.surface !== "string" || !DISPATCH_SURFACE_SET.has(r.surface)) return ring; // out of vocabulary: DROP
  const fam = typeof r.routeFamily === "string" && DISPATCH_ROUTE_FAMILY_SET.has(r.routeFamily) ? (r.routeFamily as DispatchRouteFamily) : undefined;
  const eid = typeof r.errId === "string" && DISPATCH_ERRID_RE.test(r.errId) ? r.errId : undefined;
  const st = typeof r.httpStatus === "number" && Number.isInteger(r.httpStatus) && r.httpStatus >= 100 && r.httpStatus <= 599 ? r.httpStatus : undefined;
  ring.push({
    at: now,
    surface: r.surface as DispatchSurface,
    ...(fam !== undefined ? { routeFamily: fam } : {}),
    ...(eid !== undefined ? { errId: eid } : {}),
    ...(st !== undefined ? { httpStatus: st } : {}),
  });
  return ring.slice(-DISPATCH_FAULTS_CAP);
}

// ---------------------------------------------------------------------------------------------------------
// THE PER-DESTINATION SELECTION-PROBE FAULTS
//
// A run that fails "all destinations unreachable" (or "destination configuration unreadable") carries the
// down destination IDS and no reasons at all, so support must guess between an expired credential on one
// destination, a deleted bucket on another, a network policy, and a corrupt destination config. The probes
// INSIDE selectSealDestination know the answer per destination and throw it away. These are those answers.
//
// NO-CUSTODY: the destination id is the customer's OWN label (the class the pack already carries in
// replication[] and downpipes[]), clamped; the reason is a closed enum. Never an endpoint, a bucket, a
// credential or a raw error.
// ---------------------------------------------------------------------------------------------------------

export const DEST_PROBE_REASONS = [
  "auth", // the credential was rejected: rotated, revoked, or the bucket policy narrowed
  "not-found", // the bucket / prefix answered 404: deleted or renamed under a live downpipe
  "timeout", // the probe hit the finite fetch bound: the endpoint black-holed rather than refused
  "network", // DNS / TLS / a reset: no HTTP exchange happened
  "http-5xx", // the store answered a server error: a provider-side outage
  "config-unreadable", // the destination's stored config would not read/unwrap (a rotated CONFIG_WRAP_KEY): the destination may be perfectly healthy
  // The three verdicts the FAILOVER WRITE probe can reach that a read-only reachability probe cannot
  // (cron/seal-dispatch.ts destinationReachable, which probes with the SAME put the seal needs). They are
  // additive and disjoint: a store that ANSWERED and refused the write is neither a credential fault nor a
  // missing bucket, and collapsing it into http-5xx would send triage to a provider outage that is not there.
  "throttled", // the store answered 429/503 (SlowDown): real backpressure, not an outage -- the probe should be retried, not the credential rotated
  "worm-refused", // the store answered and refused the WRITE on immutability/Object-Lock grounds: the bucket is reachable and healthy, and this downpipe can never seal to it
  "probe-other", // the store refused the probe write for a reason outside the named classes (never a message)
] as const;
export type DestProbeReason = (typeof DEST_PROBE_REASONS)[number];
const DEST_PROBE_REASON_SET: ReadonlySet<string> = new Set(DEST_PROBE_REASONS);

export interface DestProbeFaultEntry {
  readonly reason: DestProbeReason;
  readonly count: number;
  readonly at: number;
}
export type DestProbeFaults = Record<string, DestProbeFaultEntry>;
export const DEST_PROBE_FAULTS_KEY = "diag:destprobefaults";
// The destination fleet ceiling: only a FAILING destination holds a row.
//
// RAISED 32 -> 64 BY ANOTHER PASS, AND THE NUMBER IS NOT A PREFERENCE. Two caps here bound the SAME
// subject space and disagreed: `recordControlPlaneExportHealth` slices perDest at 64 and DECLARES the drop;
// this one refused at 32 and said nothing. Nothing caps how many destinations an estate may hold (only
// destinationIds PER DOWNPIPE, at 20), so that other 64 is the only statement the product makes about the
// size of a destination fleet. Settled from harm: this record answers "all destinations unreachable" by
// naming a cause for EACH one, so its cap bites in precisely the state it was built for and the
// destinations past it read as ones that probed fine. 32 costs a total outage diagnosed as a partial one.
export const DEST_PROBE_FAULTS_CAP = 64;
const DEST_PROBE_ID_MAX = 128; // the same clamp replication ids use
const DEST_PROBE_COUNT_CAP = 1_000_000;

/**
 * applyDestProbeFaults folds ONE probe result per destination into the bounded map. PURE, and the redaction
 * chokepoint: an out-of-vocabulary reason is DROPPED, the destination label is control-stripped and clamped,
 * and the map is capped. The raw probe error never crosses the wire in the first place (the caller classifies
 * it), and could not land here if it did.
 *
 * @param prior - the stored map, if any.
 * @param rows - the posted [{id, reason}] rows (untrusted).
 * @param now - the DO clock (injected).
 * @returns the new map.
 */
export function applyDestProbeFaults(prior: DestProbeFaults | undefined, rows: unknown, now: number): DestProbeFaults {
  return applyDestProbeFaultsCounted(prior, rows, now).record;
}
/**
 * applyDestProbeFaultsCounted is applyDestProbeFaults plus the fact the caller could not previously learn:
 * how many posted rows this writer could not admit. It carries the whole implementation, so the redaction
 * chokepoint stays single and the wrapper above is only a convenience.
 *
 * THERE ARE TWO CUTS HERE, NOT ONE, and both were silent: the per-CALL slice discards everything past the
 * cap even when the map is empty, and the per-SUBJECT guard then refuses a destination the map has no room
 * for. Both count into the same number, because both mean the same thing to a reader -- a destination that
 * FAILED its probe is missing from a record whose absence reads as "it probed fine". It counts ROWS rather
 * than distinct destinations: a row past the slice is never inspected, so over-declaring is the safe
 * direction, and "there may be more than you can see" is recoverable where "this is all of them" is not.
 *
 * AND IT NAMES THEM. `refusedIds` carries the destination labels the two caps refused, gated through the SAME
 * `stripControls`/clamp the admitted key takes, so a named refusal can never carry a class the admitted key
 * does not. It is a SUBSET of `refusedRows`, deliberately: a row past cut one that fails the vocabulary or id
 * gate is counted and NOT named, so the caller books the difference as unnamed rather than as enumerated.
 *
 * @param prior - the stored map, if any.
 * @param rows - the posted [{id, reason}] rows (untrusted).
 * @param now - the DO clock (injected).
 * @returns the new map, the number of rows the two caps refused, and the refused ids that could be gated.
 */
export function applyDestProbeFaultsCounted(prior: DestProbeFaults | undefined, rows: unknown, now: number): { record: DestProbeFaults; refusedRows: number; refusedIds: string[] } {
  const map: DestProbeFaults = { ...(prior ?? {}) };
  const refusedIds: string[] = [];
  if (!Array.isArray(rows)) return { record: map, refusedRows: 0, refusedIds };
  // CUT ONE: the per-call batch slice, which bites before the map is even consulted.
  const admitted = rows.slice(0, DEST_PROBE_FAULTS_CAP);
  let refusedRows = rows.length - admitted.length;
  // The rows past the slice are never CONSULTED, but they can still be NAMED: the same gate the admitted key
  // takes is run over them here purely to recover the label, and a row that fails it stays a count.
  for (const raw of rows.slice(DEST_PROBE_FAULTS_CAP)) {
    const id = destProbeRowId(raw);
    if (id !== null && !refusedIds.includes(id)) refusedIds.push(id);
  }
  for (const raw of admitted) {
    if (typeof raw !== "object" || raw === null) continue;
    const r = raw as Record<string, unknown>;
    // An out-of-vocabulary reason or an unusable id is a VOCABULARY drop, never a capacity one.
    if (typeof r.reason !== "string" || !DEST_PROBE_REASON_SET.has(r.reason)) continue;
    if (typeof r.id !== "string" || r.id.length === 0) continue;
    const id = stripControls(r.id).slice(0, DEST_PROBE_ID_MAX);
    if (id === "") continue;
    // CUT TWO: the map REFUSES a new destination once full rather than evicting the oldest, so the refused
    // destination is ABSENT from the pack rather than late in it.
    if (map[id] === undefined && Object.keys(map).length >= DEST_PROBE_FAULTS_CAP) {
      refusedRows++;
      if (!refusedIds.includes(id)) refusedIds.push(id);
      continue;
    }
    const prev = map[id];
    map[id] = { reason: r.reason as DestProbeReason, count: Math.min(DEST_PROBE_COUNT_CAP, (prev?.count ?? 0) + 1), at: now };
  }
  return { record: map, refusedRows, refusedIds };
}

/** destProbeRowId runs the ADMITTED key's own gate over an untrusted row, and returns null when it fails. */
function destProbeRowId(raw: unknown): string | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.reason !== "string" || !DEST_PROBE_REASON_SET.has(r.reason)) return null;
  if (typeof r.id !== "string" || r.id.length === 0) return null;
  const id = stripControls(r.id).slice(0, DEST_PROBE_ID_MAX);
  return id === "" ? null : id;
}

// ---------------------------------------------------------------------------------------------------------
// THE COST SIZING-PROBE OUTCOMES
//
// Sizing is advisory-by-contract, so all four failure modes (a token without the Account Analytics:Read scope,
// a Cloudflare Analytics schema field rename, an unsupported source type, a missing namespace/bucket
// identifier) collapse to basis:'unavailable' -- or, far worse, to a SILENT ZERO that is presented to the
// customer as a MEASURED answer ("your 2 TB bucket is 0 bytes"). Nothing is persisted and there is no cost
// section in the bundle at all.
//
// The measured-zero is called out as its OWN class, because a drift-induced 0 masquerading as a real size is
// the one failure the customer cannot possibly detect.
//
// NO-CUSTODY: the source TYPE is a closed engine vocabulary (kv, r2, d1, ...); the class is a closed enum.
// Never the namespaceId, the bucket name, the endpoint, the token, the scope string or the GraphQL errors[].
// ---------------------------------------------------------------------------------------------------------

export const COST_SIZING_CLASSES = [
  "ok", // a real measurement landed
  "measured-zero", // basis:'analytics' returned ZERO bytes: a schema drift presenting as a measured answer, NOT a real empty bucket
  "analytics-auth-or-scope", // the Analytics API refused: the token lacks Account Analytics:Read (the "size unavailable forever" ticket)
  "analytics-schema-drift", // the response parsed but the expected field was absent: a Cloudflare schema rename
  "unsupported-source-type", // sizing is not implemented for this source type (honest, and worth showing)
  "missing-identifier", // the source config carries no namespaceId / bucketName to size against
  "network", // the probe threw with no HTTP status
] as const;
export type CostSizingClass = (typeof COST_SIZING_CLASSES)[number];
const COST_SIZING_CLASS_SET: ReadonlySet<string> = new Set(COST_SIZING_CLASSES);

// The source TYPE vocabulary the sizing probe reports against: a closed engine product vocabulary.
export const COST_SIZING_SOURCE_TYPES = ["kv", "r2", "d1", "secrets", "cf-config", "images", "stream", "queues", "vectorize", "workers", "other"] as const;
const COST_SIZING_SOURCE_TYPE_SET: ReadonlySet<string> = new Set(COST_SIZING_SOURCE_TYPES);

export interface CostSizingEntry {
  readonly sized: number; // measurements that landed with a real, non-zero size
  readonly unavailable: number; // measurements that could not be made at all
  readonly measuredZero: number; // THE drift signal: a 'measured' zero
  readonly lastClass: CostSizingClass;
  readonly lastAt: string;
}
export type CostSizing = Record<string, CostSizingEntry>;
export const COST_SIZING_KEY = "diag:costsizing";
const COST_SIZING_COUNT_CAP = 1_000_000;

/**
 * applyCostSizing folds ONE sizing-probe outcome into the per-source-type record. PURE, and the redaction
 * chokepoint: an out-of-vocabulary source type or class is DROPPED (so the key space is exactly the closed
 * product vocabulary), and every count is clamped.
 *
 * @param prior - the stored record, if any.
 * @param sourceType - the closed source type.
 * @param cls - the closed outcome class.
 * @param nowIso - the DO clock as an ISO string (injected).
 * @returns the new record.
 */
export function applyCostSizing(prior: CostSizing | undefined, sourceType: unknown, cls: unknown, nowIso: string): CostSizing {
  const map: CostSizing = { ...(prior ?? {}) };
  if (typeof sourceType !== "string" || !COST_SIZING_SOURCE_TYPE_SET.has(sourceType)) return map;
  if (typeof cls !== "string" || !COST_SIZING_CLASS_SET.has(cls)) return map;
  const prev = map[sourceType];
  const bump = (n: number, add: boolean): number => Math.min(COST_SIZING_COUNT_CAP, n + (add ? 1 : 0));
  map[sourceType] = {
    sized: bump(prev?.sized ?? 0, cls === "ok"),
    unavailable: bump(prev?.unavailable ?? 0, cls !== "ok" && cls !== "measured-zero"),
    measuredZero: bump(prev?.measuredZero ?? 0, cls === "measured-zero"),
    lastClass: cls as CostSizingClass,
    lastAt: nowIso,
  };
  return map;
}

// ---------------------------------------------------------------------------------------------------------
// THE RUNTIME WRAP-KEY UNWRAP FAULT TIMELINE (admin/config-secret.ts, read at dest/factory.ts)
//
// CONFIG_WRAP_KEY is the documented DATA-LOSS keystone: it opens the at-rest envelope around every off-account
// destination credential. Rotate it and nothing breaks LOUDLY -- the next run, days later, simply cannot open
// the credential. The pack's wrapKeyHealth is a PROBE-TIME verdict ("does the key open a sample envelope
// now?"), so it can say the key is wrong today but never WHEN reads started failing, and it cannot separate a
// rotated key from a corrupted DO record or a dropped env binding: the run rows coarsen all three into one
// generic destination error.
//
// This is the RUNTIME half: a {closed cause -> count, firstAt, lastAt} record bumped at the moment of use.
// firstAt is the whole point -- it is the timestamp support asks for first ("when did this start?") and the
// one fact a probe can never reconstruct.
//
// NO-CUSTODY: causes, counts and clamped timestamps. Never the plaintext, the envelope bytes, the key, or any
// key-check value beyond the existing KCV (which is computed elsewhere and is a PRF commitment, not the key).
// ---------------------------------------------------------------------------------------------------------

export const UNWRAP_FAULT_CAUSES = [
  "aead-tag", // the envelope is WELL-FORMED and the configured key does not open it: the AEAD tag failed. The classic ROTATED CONFIG_WRAP_KEY (restore the prior key, or re-enter the credential to re-wrap it)
  "envelope-corrupt", // the envelope's base64url would not decode: the STORED RECORD is damaged, not the key (restoring the old key will NOT help)
  "envelope-shape", // the stored value is neither a plaintext string nor a v1 envelope: a corrupted / half-written DO record
  "key-missing", // the credential IS encrypted at rest but CONFIG_WRAP_KEY is not bound on the engine at all: a deploy dropped the env binding (the key may be perfectly fine, it is simply not wired)
  "key-malformed", // CONFIG_WRAP_KEY is bound but is not base64url of 32 bytes: NO destination credential in the account can be opened (the whole fleet stops, not one downpipe)
] as const;
export type UnwrapFaultCause = (typeof UNWRAP_FAULT_CAUSES)[number];
const UNWRAP_FAULT_CAUSE_SET: ReadonlySet<string> = new Set(UNWRAP_FAULT_CAUSES);

/**
 * UnwrapFaultError TAGS a config-secret resolution throw with its closed cause at the site that KNOWS it, so
 * the recording catch (dest/factory.ts) never has to re-read a raw crypto message to attribute it. The
 * operator-facing message is UNCHANGED (this subclasses Error and carries the same text), so every existing
 * response, test and log line is byte-identical: only the tag is new, and only the tag is ever recorded.
 */
export class UnwrapFaultError extends Error {
  readonly unwrapFaultCause: UnwrapFaultCause;
  constructor(unwrapFaultCause: UnwrapFaultCause, message: string) {
    super(message);
    this.name = "UnwrapFaultError";
    this.unwrapFaultCause = unwrapFaultCause;
  }
}

/**
 * unwrapFaultCauseOf reads the closed cause off a tagged throw. An UNTAGGED error yields null: it is one no
 * site classified, and guessing from its text is exactly the free-text leak this vocabulary prevents.
 *
 * @param e - the thrown value.
 * @returns the closed cause, or null when untagged.
 */
export function unwrapFaultCauseOf(e: unknown): UnwrapFaultCause | null {
  const c = (e as { unwrapFaultCause?: unknown } | null)?.unwrapFaultCause;
  return typeof c === "string" && UNWRAP_FAULT_CAUSE_SET.has(c) ? (c as UnwrapFaultCause) : null;
}

/** One cause's bounded runtime record. firstAt is the "when did this start?" fact a probe cannot recover. */
export interface UnwrapFaultEntry {
  readonly count: number;
  readonly firstAt: number; // epoch ms of the FIRST fault of this cause (never overwritten)
  readonly lastAt: number; // epoch ms of the most recent
}
export type UnwrapFaults = Record<string, UnwrapFaultEntry>;

export const UNWRAP_FAULTS_KEY = "diag:unwrapfaults";
const UNWRAP_FAULT_COUNT_CAP = 1_000_000_000;

/**
 * applyUnwrapFault folds ONE fault into the bounded record. PURE, and the single redaction chokepoint: an
 * out-of-vocabulary cause is DROPPED (the record is returned unchanged), so the key space is bounded by
 * UNWRAP_FAULT_CAUSES and no envelope, key or plaintext can enter.
 *
 * @param prior - the stored record, if any.
 * @param cause - the closed cause.
 * @param now - the clock (injected, so the validator is deterministic).
 * @returns the new record.
 */
export function applyUnwrapFault(prior: UnwrapFaults | undefined, cause: string, now: number): UnwrapFaults {
  const map: UnwrapFaults = { ...(prior ?? {}) };
  if (!UNWRAP_FAULT_CAUSE_SET.has(cause)) return map;
  const prev = map[cause];
  map[cause] = {
    count: Math.min(UNWRAP_FAULT_COUNT_CAP, (prev?.count ?? 0) + 1),
    firstAt: prev?.firstAt ?? now, // NEVER overwritten: this is the first-failure timestamp support asks for
    lastAt: now,
  };
  return map;
}

// ---------------------------------------------------------------------------------------------------------
// THE POST-WRITE BINDING-SAFETY ALARMS (admin/attach-plan.ts verifyAfter, admin/cf-api.ts)
//
// The attach pipeline's post-write verification is the highest-impact failure mode made into a guard: after PATCHing the
// engine's Workers settings it RE-READS them and alarms if a binding it did not intend to touch went missing,
// if the Durable Object bindings vanished, or if a binding it never sent appeared (proof a concurrent writer's
// PATCH raced ours and one of the two writes was a silent lost update). Every one of those alarms was thrown
// into an HTTP response and read by exactly one operator, in one browser tab, once. The pack then holds two
// healthy-looking sources-attached audit rows and no trace of the alarm, its timing, or the race -- while a
// source quietly stopped backing up.
//
// NO-CUSTODY: binding NAMES only, the operator-label class the pack already ships in sourcesDetached (4.33).
// Never a resource id, an account id, a token or a Cloudflare message.
// ---------------------------------------------------------------------------------------------------------


// BINDING_NAME_RE is the STRUCTURAL gate on an operator binding label. Workers binding names are identifiers
// (letters, digits, underscore, hyphen), so anything else -- a slash, a space, an @, a quote -- is not a
// binding name at all and is DROPPED rather than clamped. This is defence in depth on top of the clamp: it
// means a secret, an email, an endpoint or a bucket path structurally CANNOT ride in these fields even if a
// future call site were to pass one, because none of them is shaped like a binding name.
const BINDING_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;

export const BINDING_ALARM_KINDS = [
  "postwrite-binding-missing", // a binding that existed BEFORE the change, and was not an intended removal, is GONE from the after-read: the settings PATCH dropped it (the source it backs will fail on its next run)
  "postwrite-do-missing", // the engine's own Durable Object bindings are absent from the after-read: the engine is broken until it is redeployed with wrangler
  "lost-update-race", // the after-read holds a binding the change neither added nor saw before it: a CONCURRENT attach/detach landed between our read and our write, so one of the two writes was silently lost
  "postwrite-addition-absent", // an intended ADDITION is not present afterwards: the change reported success and did not take (nothing else was harmed)
  "postwrite-removal-survived", // an intended REMOVAL is still bound afterwards: the change reported success and did not take
  "postwrite-reread-failed", // the post-write RE-READ itself failed, so the change could not be verified AT ALL: neither safe nor unsafe, simply unproven
] as const;
export type BindingAlarmKind = (typeof BINDING_ALARM_KINDS)[number];
const BINDING_ALARM_KIND_SET: ReadonlySet<string> = new Set(BINDING_ALARM_KINDS);

/** One bounded binding-safety alarm row. A closed kind, a clamped time, and the operator's binding labels. */
export interface BindingAlarmRow {
  readonly at: number;
  readonly kind: BindingAlarmKind;
  readonly bindingNames: string[]; // the operator's OWN binding labels (sourcesDetached class), capped + clamped
}

export const BINDING_ALARMS_KEY = "diag:bindingalarms";
export const BINDING_ALARMS_RING_CAP = 32;
const BINDING_ALARM_NAMES_MAX = 16;
const BINDING_ALARM_NAME_LEN = 64; // a Workers binding name ceiling; well above any real label

/**
 * applyBindingAlarm folds ONE untrusted alarm into the bounded ring. PURE, and the single redaction chokepoint:
 * an out-of-vocabulary kind is DROPPED; every binding name is coerced to a string, control-stripped, clamped to
 * 64 chars and the list capped at 16. Nothing else on the posted body is read, so a Cloudflare message, an
 * account id or a token structurally cannot enter the record even if a future call site posts one.
 *
 * @param prior - the stored ring, if any.
 * @param row - the posted row (untrusted).
 * @param now - the DO clock (injected).
 * @returns the new ring (newest LAST, capped).
 */
export function applyBindingAlarm(prior: BindingAlarmRow[] | undefined, row: unknown, now: number): BindingAlarmRow[] {
  const ring = Array.isArray(prior) ? [...prior] : [];
  if (typeof row !== "object" || row === null) return ring;
  const r = row as Record<string, unknown>;
  if (typeof r.kind !== "string" || !BINDING_ALARM_KIND_SET.has(r.kind)) return ring; // out-of-vocabulary: DROP
  const names = Array.isArray(r.bindingNames) ? r.bindingNames : [];
  const bindingNames: string[] = [];
  for (const n of names) {
    if (typeof n !== "string") continue;
    const clean = stripControls(n).slice(0, BINDING_ALARM_NAME_LEN);
    // Shape-gated, not merely clamped: a value that is not shaped like a Workers binding name is DROPPED.
    if (BINDING_NAME_RE.test(clean) && bindingNames.length < BINDING_ALARM_NAMES_MAX) bindingNames.push(clean);
  }
  ring.push({ at: now, kind: r.kind as BindingAlarmKind, bindingNames });
  return ring.slice(-BINDING_ALARMS_RING_CAP);
}

// ---------------------------------------------------------------------------------------------------------
// THE SELF-UPDATE PIPELINE'S FAULT RING
//
// The self-update pipeline is the highest-impact failure mode (a deploy that wipes source bindings) and its failure
// evidence was one 200-char free-text `reason`, already coarsened by msg() before it was written. So:
//   - a canary that failed AND whose auto-rollback ALSO failed left no durable proof (the engine limps on a
//     bad version and the pack says only "reverted");
//   - a truncated channel.json told the customer "signature did not verify" (verifyChannel collapses
//     sig-fail / json-parse / shape-invalid into ONE null), sending support on a key-pinning chase;
//   - six distinct artefact-download failures (404 vs redirect vs oversize vs empty body vs network) landed as
//     the single fixed audit detail "artefact-download-failed";
//   - a CF API shape change made the provenance read-back report "unavailable" fleet-wide with no fixture;
//   - the post-update binding diff computed the EXACT names of the dropped source bindings and persisted only
//     their COUNT: support can prove bindings were dropped and cannot say WHICH to re-attach;
//   - and the lifecycle records themselves (pending / settled / superseded / the ramp pending) were unchecked
//     DO writes, so an engine could be LIVE on a new version with no record of it at all.
//
// ONE bounded ring answers all five, because they are one pipeline and support reads them together.
//
// NO-CUSTODY: closed step + closed cause + a clamped HTTP status + Cloudflare's OWN integer error codes + the
// sha384 of a PUBLIC release artefact + the operator's binding labels (sourcesDetached class). NEVER a
// response body, a module byte, an artefact URL, a redirect target or a Cloudflare message.
// ---------------------------------------------------------------------------------------------------------

export const UPDATE_FAIL_STEPS = [
  "channel-fetch", // fetching the signed channel document from the CDN
  "channel-verify", // verifying / parsing / shape-checking the channel document
  "artefact-download", // downloading the release artefact named by the verified channel
  "digest-check", // hashing the downloaded artefact against the channel's sha384
  "parse-bundle", // decoding + shape-checking the console bundle (its assets, their hashes, their sizes)
  "read-settings", // reading the live script's settings so its bindings/secrets are PRESERVED across the upload
  "read-deployments", // reading the live deployment so a rollback target can be recorded BEFORE anything changes
  "binding-guard", // the safe-apply refusal: a binding TYPE the pipeline cannot guarantee to carry across the upload
  "asset-session", // opening the Cloudflare asset-upload session (the console's static assets)
  "asset-upload", // uploading an asset bucket into that session
  "version-post", // POSTing the new version (uploaded, NOT yet live)
  "promote", // making the uploaded version the live deployment (or starting the gradual ramp)
  "readback", // reading the uploaded version back to confirm what is actually deployed (the provenance read-back)
  "rollback", // reverting to the recorded prior version after a failed canary
  "bookkeeping", // the LIFECYCLE RECORD write itself (G101): the deploy happened, the record of it did not
] as const;
export type UpdateFailStep = (typeof UPDATE_FAIL_STEPS)[number];
const UPDATE_FAIL_STEP_SET: ReadonlySet<string> = new Set(UPDATE_FAIL_STEPS);

export const UPDATE_CAUSE_CLASSES = [
  // --- channel: the three-way collapse verifyChannel used to report as one wrong reason ---
  "sig-invalid", // the detached signature did not verify against the PINNED release signer: a genuine trust failure
  "json-parse", // the signature VERIFIED and the bytes did not parse as JSON: a TRUNCATED / corrupted CDN object, NOT a signature problem (the misdiagnosis this class exists to end)
  "shape-invalid", // valid JSON that is not a channel document: a producer/consumer drift, NOT a signature problem
  "url-config", // UPDATE_CHANNEL_URL is unset, unparseable or not https
  "key-config", // UPDATE_SIGNER_PUBLIC is unset or unusable
  // --- transport: the download modes that all collapsed to one fixed audit detail ---
  "fetch-status-4xx", // the CDN answered 4xx (a 404 = the artefact the signed channel names does not exist)
  "fetch-status-5xx", // the CDN answered 5xx (wait and retry; not a tamper signal)
  "redirect-refused", // the fetch was REDIRECTED and refused (redirect:manual): a signed update must never be steered elsewhere
  "empty-body", // a 200 with no bytes
  "oversize", // the artefact exceeded the download ceiling
  "network", // the fetch threw (DNS, TLS, reset): no HTTP status exists
  // --- integrity ---
  "digest-mismatch", // the artefact downloaded and does NOT hash to the sha384 the SIGNED channel declares: CDN corruption or tamper (the observed digest rides, so the two can be told apart)
  // --- deploy ---
  "upload-4xx", // Cloudflare refused the upload (token scope, a rejected module, a quota)
  "upload-5xx", // Cloudflare failed the upload
  "promote-failed", // the version uploaded and could NOT be made live: the previously-live version is still serving (safe, but the update did not take)
  "quota", // a Cloudflare quota/limit refusal
  "binding-uncarryable", // the live script has a binding TYPE the pipeline will not risk dropping: it refuses rather than upload blind (the highest-impact failure mode, honoured)
  "no-rollback-target", // Cloudflare returned no deployment / no version id, so no rollback target could be recorded: the pipeline refuses BEFORE changing anything
  "readback-unknown-shape", // the CF API answered a shape the read-back parser does not recognise: provenance reads "unavailable" fleet-wide (the sandbox-experiment fixture case; a bounded shape descriptor rides)
  "asset-hash-unknown", // Cloudflare asked for an asset hash that is NOT in the verified bundle: refuse the upload
  "asset-token-absent", // the asset-upload session returned no token / no completion token
  "bundle-invalid", // the console bundle is not valid / not the declared format / an asset failed its declared sha256
  // --- lifecycle bookkeeping ---
  "record-write-failed", // the lifecycle DO write (pending / settled / superseded / audit) was refused or unreachable: the engine may be LIVE on a version nothing recorded
  // the post-update binding diff found source bindings the update DROPPED. The count was audited; the
  // NAMES rode the HTTP response and were gone. Support could prove bindings were dropped and could not say
  // WHICH to re-attach -- the highest-impact failure mode, half-instrumented. The names ride on the row.
  "sources-dropped",
  "rollback-failed", // the auto-rollback ITSELF failed after a failed canary: the engine is limping on a BAD version and nothing else says so
  "other", // residual: a fault outside the named classes (never a message)
] as const;
export type UpdateCauseClass = (typeof UPDATE_CAUSE_CLASSES)[number];
const UPDATE_CAUSE_CLASS_SET: ReadonlySet<string> = new Set(UPDATE_CAUSE_CLASSES);

// The lifecycle PHASE a bookkeeping loss belongs to, so "the engine is live and nothing recorded it"
// can be told from "an audit row is missing".
export const UPDATE_RECORD_PHASES = ["pending", "settled", "superseded", "expired", "audit"] as const;
export type UpdateRecordPhase = (typeof UPDATE_RECORD_PHASES)[number];
const UPDATE_RECORD_PHASE_SET: ReadonlySet<string> = new Set(UPDATE_RECORD_PHASES);

// The COMPONENT the fault belongs to: an engine apply and a console apply fail in different steps, and a
// customer reporting "the update failed" never says which.
export const UPDATE_COMPONENTS = ["engine", "console", "channel"] as const;
export type UpdateComponent = (typeof UPDATE_COMPONENTS)[number];
const UPDATE_COMPONENT_SET: ReadonlySet<string> = new Set(UPDATE_COMPONENTS);

/**
 * The bounded read-back SHAPE descriptor (a captured fixture). The gap asked for the CF response's top-level
 * key NAMES; we carry a strictly stronger-redacted form that answers the same question -- how many top-level
 * keys the body had and whether the three the parser needs were present -- with NO strings at all, so not even
 * a Cloudflare key name (let alone a value) can ride.
 */
export interface UpdateReadbackShape {
  readonly topLevelKeys: number; // clamped 0..64
  readonly hasSuccess: boolean;
  readonly hasResult: boolean;
  readonly hasErrors: boolean;
}

/** One bounded update-fault row. Closed enums, clamped ints, public release digests, operator binding labels. */
export interface UpdateFaultRow {
  readonly at: number;
  readonly component: UpdateComponent;
  readonly step: UpdateFailStep;
  readonly cause: UpdateCauseClass;
  readonly httpStatus?: number; // clamped 0..599 (0 = no HTTP exchange happened)
  readonly cfCodes?: number[]; // Cloudflare's OWN integer error codes, capped at 8 (a fixed vendor vocabulary)
  readonly observedSha384?: string; // digest-mismatch ONLY: the digest we COMPUTED over a PUBLIC release artefact (96 lower-case hex). Tells CDN corruption from tamper
  readonly recordPhase?: UpdateRecordPhase; // bookkeeping ONLY
  readonly droppedSources?: string[]; // the source-binding NAMES an update dropped (the operator's own labels, deduped, capped 64, clamped 64 chars)
  readonly readbackShape?: UpdateReadbackShape; // readback-unknown-shape ONLY
  readonly rollbackFailed?: boolean; // the auto-rollback ITSELF failed: the engine is LIVE on a bad version
}

export const UPDATE_FAULTS_KEY = "diag:updatefaults";
export const UPDATE_FAULTS_RING_CAP = 32;
const UPDATE_FAULT_CODES_MAX = 8;
const UPDATE_FAULT_DROPPED_MAX = 64; // matches the sourcesDetached cap the pack already ships
const UPDATE_FAULT_NAME_LEN = 64;

/**
 * applyUpdateFault folds ONE untrusted row into the bounded ring. PURE, and the single redaction chokepoint:
 * an out-of-vocabulary component / step / cause is DROPPED (the ring is returned unchanged); httpStatus is
 * clamped to 0..599; cfCodes are accepted ONLY as integers and capped at 8; observedSha384 ONLY as exactly 96
 * lower-case hex digits (so no message can ride in that field); droppedSources are control-stripped, clamped
 * and capped; the read-back descriptor is reduced to a clamped count and three booleans. NOTHING else on the
 * body is read, so a CF message, a response body, a URL or a module byte structurally cannot enter the record.
 *
 * @param prior - the stored ring, if any.
 * @param row - the posted row (untrusted).
 * @param now - the DO clock (injected).
 * @returns the new ring (newest LAST, capped).
 */
export function applyUpdateFault(prior: UpdateFaultRow[] | undefined, row: unknown, now: number): UpdateFaultRow[] {
  const ring = Array.isArray(prior) ? [...prior] : [];
  if (typeof row !== "object" || row === null) return ring;
  const r = row as Record<string, unknown>;
  const component = typeof r.component === "string" && UPDATE_COMPONENT_SET.has(r.component) ? (r.component as UpdateComponent) : null;
  const step = typeof r.step === "string" && UPDATE_FAIL_STEP_SET.has(r.step) ? (r.step as UpdateFailStep) : null;
  const cause = typeof r.cause === "string" && UPDATE_CAUSE_CLASS_SET.has(r.cause) ? (r.cause as UpdateCauseClass) : null;
  if (component === null || step === null || cause === null) return ring; // out-of-vocabulary: DROP, never persist
  const status = typeof r.httpStatus === "number" && Number.isFinite(r.httpStatus) ? Math.max(0, Math.min(599, Math.trunc(r.httpStatus))) : 0;
  const codes = (Array.isArray(r.cfCodes) ? r.cfCodes : []).filter((c): c is number => typeof c === "number" && Number.isInteger(c)).slice(0, UPDATE_FAULT_CODES_MAX);
  const sha = typeof r.observedSha384 === "string" && /^[0-9a-f]{96}$/.test(r.observedSha384) ? r.observedSha384 : "";
  const phase = typeof r.recordPhase === "string" && UPDATE_RECORD_PHASE_SET.has(r.recordPhase) ? (r.recordPhase as UpdateRecordPhase) : null;
  const dropped: string[] = [];
  for (const n of Array.isArray(r.droppedSources) ? r.droppedSources : []) {
    if (typeof n !== "string") continue;
    const clean = stripControls(n).slice(0, UPDATE_FAULT_NAME_LEN);
    // Shape-gated (see BINDING_NAME_RE): a secret, an email, an endpoint or an object key is not shaped like a
    // Workers binding name, so it cannot ride here even if a future call site were to pass one.
    if (BINDING_NAME_RE.test(clean) && !dropped.includes(clean) && dropped.length < UPDATE_FAULT_DROPPED_MAX) dropped.push(clean);
  }
  const rs = typeof r.readbackShape === "object" && r.readbackShape !== null ? (r.readbackShape as Record<string, unknown>) : null;
  const readbackShape: UpdateReadbackShape | null =
    rs === null
      ? null
      : {
          topLevelKeys: typeof rs.topLevelKeys === "number" && Number.isFinite(rs.topLevelKeys) ? Math.max(0, Math.min(64, Math.trunc(rs.topLevelKeys))) : 0,
          hasSuccess: rs.hasSuccess === true,
          hasResult: rs.hasResult === true,
          hasErrors: rs.hasErrors === true,
        };
  ring.push({
    at: now,
    component,
    step,
    cause,
    ...(status > 0 ? { httpStatus: status } : {}),
    ...(codes.length > 0 ? { cfCodes: codes } : {}),
    ...(sha !== "" ? { observedSha384: sha } : {}),
    ...(phase !== null ? { recordPhase: phase } : {}),
    ...(dropped.length > 0 ? { droppedSources: dropped } : {}),
    ...(readbackShape !== null ? { readbackShape } : {}),
    ...(r.rollbackFailed === true ? { rollbackFailed: true } : {}),
  });
  return ring.slice(-UPDATE_FAULTS_RING_CAP);
}

// ---------------------------------------------------------------------------------------------------------
// THE ADMIN REFUSAL AGGREGATE (every refused write the pack could not see)
//
// "We tried to add our S3 destination three times last week / could never get SIEM push configured / the key
// install failed halfway / Run now does nothing / our approved restore said not-approved during the DO
// outage": each of those is a REFUSED WRITE whose reason went into an HTTP response the operator has closed.
// The audit excerpt carries a bare "failed"/"denied" for a few of them and nothing at all for the rest, so
// support has no record of the attempts, of which validator refused, or -- the worst one -- that a
// "not approved" denial was actually a DO FAULT rather than a genuinely missing approval.
//
// Shaped like the WebAuthn aggregate: a 2-D {surface}:{reason} key over TWO closed sets, so the key space is
// bounded by their product and a flood of refusals only ever re-bumps a capped counter.
//
// NO-CUSTODY: two closed enums, a count and a timestamp. Never the submitted endpoint, header, key material,
// token, bucket, cron string or validator prose.
// ---------------------------------------------------------------------------------------------------------

export const ADMIN_REFUSAL_SURFACES = [
  "dest-add", // adding / editing an archive destination (the console-set S3 credential)
  "push-config", // configuring the SIEM audit-log push destination
  "otlp-config", // configuring the OTLP/HTTP metrics push destination
  "key-install", // installing a recipient / signer key (the key ceremony)
  "key-rotate", // rotating a key, or the break-glass posture switch
  "run-trigger", // "Run now" (a manual seal dispatch)
  "drill", // a manual restore drill / fleet drill start
  "restore-apply", // a restore APPLY (the destructive one)
  "owner-gate", // an owner-only gate refusal (dual control, the owner-action queue)
  "update-apply", // an update apply / rollback refusal at the router
  "downpipe-write", // a downpipe create / upsert the DO REFUSED (a validator, or a custom role that may not change the restore-test cadence)
  // ---- THE GOVERNANCE, PEOPLE AND NOTIFY WRITES, NONE OF WHICH WAS RECORDED ON REFUSAL ---------------
  //
  // "I turned dual control / sign-in alerts / change-number enforcement on last week, and it is off." The save
  // REFUSED or FAILED, and the only thing that ever said so was a toast the operator dismissed.
  //
  // The console's own admin-write row cannot answer this, and that is STRUCTURAL rather than an oversight: its
  // ring is in-memory with deliberately no sessionStorage, and is reset on every pack download, while the
  // ticket is TIME-DISPLACED BY CONSTRUCTION ("last week"). A refusal from a prior session or from before a
  // reload is simply gone, so three states produced an identical pack -- refused last week, never attempted,
  // applied and later turned off. The gap therefore asked for an ENGINE-SIDE ring with count + lastAt, and
  // this is it: the engine remembers across sessions, reloads and tabs, which is exactly what a browser cannot.
  //
  // The OP rides IN the surface name wherever the remedy differs (a failed channel CREATE and a failed channel
  // DELETE are different tickets), so the aggregate stays a bounded 2-D {surface}:{reason} key rather than
  // growing a third dimension the projector and the bot would both have to learn.
  "approval-policy", // POST /config/approval-policy -- the dual-control switch itself
  "change-number-policy", // POST /config/change-number-policy -- the change-number requirement
  "signin-context-policy", // POST /config/signin-context-policy -- the sign-in alert / context policy
  "notify-channel-set", // POST /notify/channels
  "notify-channel-delete", // POST /notify/channels/delete
  "notify-rule-set", // POST /notify/rules
  "notify-rule-delete", // POST /notify/rules/delete
  "expiry-item-set", // POST /expiry
  "expiry-item-delete", // POST /expiry/delete
  "custom-role-create", // POST /custom-roles
  "custom-role-delete", // POST /custom-roles/delete
  "posture-accept", // POST /posture/accept -- the owner-reserved risk acceptance
  "posture-unaccept", // POST /posture/unaccept
  "recovery-codes-regenerate", // POST /auth/recovery-codes/regenerate -- the gap's stated WORST case
  "break-glass-retire", // POST /policy/retire-break-glass-token
  "restore-proof", // a restorability PROOF (a blind verify or a keyless attest) refused BEFORE it ran (G285). It runs no restore, writes no evidence and stamps no downpipe, so a week of refused proofs and a week in which nobody drilled leave the pack IDENTICAL: a stale lastRestoreProvenAt and nothing else
] as const;
export type AdminRefusalSurface = (typeof ADMIN_REFUSAL_SURFACES)[number];
const ADMIN_REFUSAL_SURFACE_SET: ReadonlySet<string> = new Set(ADMIN_REFUSAL_SURFACES);

export const ADMIN_REFUSAL_REASONS = [
  "validation", // the submitted shape / value failed a validator (a typo, a missing field, an unusable value)
  "forbidden", // the caller's role / capability does not permit the write
  "not-approved", // dual control: the write needs an approval it does not have
  "gate-unavailable", // THE ONE THAT WAS INDISTINGUISHABLE: the approval gate could not be READ (a DO fault), so the write was refused FAIL-CLOSED. The approval may exist. "Our approved restore said not-approved" is THIS, not a missing approval
  "rate-limited", // the per-caller limiter refused the attempt
  "conflict", // the write lost a precondition (a concurrent writer, an in-flight campaign, a blocked removal)
  "not-configured", // the surface cannot accept the write at all (no key, no binding, no posture for it)
  "reserved", // the write named a RESERVED engine binding/name (the confused-deputy guard): security-significant, and it used to be indistinguishable from a typo
  "too-large", // the request exceeded a bound (an oversized restore window, an over-cap bulk)
  "do-fault", // the DO round-trip for the write itself faulted / answered non-2xx: the write never landed and the operator was told something else
  "other", // residual (never a message)
] as const;
//
// ON WHY THERE IS NO `change-control` REASON HERE. A member was
// written and then DELETED rather than shipped, deliberately.
//
// The change-number gate lives INSIDE the DO (scheduler-do-change-management.ts gatedConfigMutation) and refuses
// by throwing a plain Error, which the router turns into a 400 that is byte-identical to a shape refusal. The
// hub recorder classifies from the STATUS, so it CANNOT tell the two apart, and a member it can only ever guess
// at is worse than no member: it would mislabel every ordinary validation failure on a change-controlled route
// as a governance refusal, and send support to the wrong fix with a confident-looking row. A vocabulary member
// nothing can honestly write is dead evidence wearing a discriminator's clothes -- which is exactly the finding
// that killed `last-owner-guard` on the console RBAC path.
//
// It is not lost. A change-control refusal is ALREADY discriminated in the same pack, by the surfaces that CAN
// see it because they sit at the gate: configIntegrity.changeControlRefusals ({count, lastAt, lastActionKind}),
// the governanceRefusals ring (the SEQUENCE of refused action kinds), and the change-ref stage's own closed
// reasons (change-ref-missing / -no-justification / -garbled / -truncated). So {approval-policy, validation} in
// this ring, read beside a bumped changeControlRefusals carrying lastActionKind, IS the change-control fork; the
// same row with changeControlRefusals at zero is a genuine shape refusal. The join is in one pack.
export type AdminRefusalReason = (typeof ADMIN_REFUSAL_REASONS)[number];
const ADMIN_REFUSAL_REASON_SET: ReadonlySet<string> = new Set(ADMIN_REFUSAL_REASONS);

/** The bounded admin-refusal aggregate: "<surface>:<reason>" -> { count, lastAt }. Counts only. */
export interface AdminRefusalEntry {
  readonly count: number;
  readonly lastAt: string;
}
export type AdminRefusals = Record<string, AdminRefusalEntry>;

export const ADMIN_REFUSALS_KEY = "diag:adminrefusals";
const ADMIN_REFUSAL_COUNT_CAP = 1_000_000;

/**
 * applyAdminRefusal folds ONE refusal into the bounded aggregate. PURE, and the single redaction chokepoint:
 * an out-of-vocabulary surface or reason is DROPPED (the aggregate is returned unchanged), so the key space is
 * bounded by the PRODUCT of the two closed sets and no submitted value, endpoint, key or validator text can
 * enter the record.
 *
 * @param prior - the stored aggregate, if any.
 * @param surface - the closed surface.
 * @param reason - the closed reason class.
 * @param nowIso - the DO clock as an ISO string (injected).
 * @returns the new aggregate.
 */
export function applyAdminRefusal(prior: AdminRefusals | undefined, surface: string, reason: string, nowIso: string): AdminRefusals {
  const map: AdminRefusals = { ...(prior ?? {}) };
  if (!ADMIN_REFUSAL_SURFACE_SET.has(surface) || !ADMIN_REFUSAL_REASON_SET.has(reason)) return map;
  const key = `${surface}:${reason}`;
  const prev = map[key];
  map[key] = { count: Math.min(ADMIN_REFUSAL_COUNT_CAP, (prev?.count ?? 0) + 1), lastAt: nowIso };
  return map;
}

/**
 * classifyUpdateFailStep coarsens an update-pipeline throw into the closed (step, cause) pair. It reads the
 * message ONLY to match the ENGINE'S OWN literals (the fixed sentences cf-deploy.ts / cf-assets-deploy.ts /
 * update-apply.ts throw) and RETURNS the two enum members: the text -- which interpolates script names, binding
 * names and Cloudflare's prose -- never leaves this function and can never reach a record. This is the same
 * idiom as classifySealDestError / classifyRestoreFaultClass.
 *
 * ORDERING is load-bearing: the bundle / binding-guard / read-back refusals are tested BEFORE the generic
 * upload arms, because their sentences also contain the words "upload" and "version".
 *
 * @param e - the thrown value.
 * @returns the closed step + cause.
 */
/**
 * channelFaultStep places a CHANNEL-consult cause on the pipeline's step axis. The two steps are different
 * FAULT DOMAINS and different owners: `channel-fetch` is the document not arriving (the address is wrong, or
 * the CDN did not answer), `channel-verify` is a document that DID arrive and is not one this engine can
 * trust or read (a wrong signer, a truncated object, a producer drift, or a signer key this engine cannot
 * even parse). Support asks completely different questions of the two, and telling them apart is why the step
 * axis exists.
 *
 * @param cause - the closed cause the channel consult failed with.
 * @returns the closed step.
 */
export function channelFaultStep(cause: UpdateCauseClass): UpdateFailStep {
  if (cause === "sig-invalid" || cause === "json-parse" || cause === "shape-invalid" || cause === "key-config") return "channel-verify";
  return "channel-fetch";
}

export function classifyUpdateFailStep(e: unknown): { step: UpdateFailStep; cause: UpdateCauseClass } {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (m === "") return { step: "version-post", cause: "other" };
  // --- THE DIGEST CHECK, which had no arm at all and so landed as {version-post, other}: a Cloudflare upload
  // fault, reported for a downloaded artefact that does not hash to what the SIGNED channel declares. That is
  // CDN corruption or TAMPER, the pipeline changed NOTHING, and Cloudflare had not been called yet -- three
  // wrong facts in one row, in the highest-impact failure mode domain. It is tested FIRST: nothing else can produce these
  // sentences (verifyAndGuard's own three verify arms), and a later arm must never be able to swallow them.
  if (m.includes("did not match the signed channel's hash")) return { step: "digest-check", cause: "digest-mismatch" };
  if (m.includes("did not declare a hash for this version") || m.includes("could not be hashed for verification")) return { step: "digest-check", cause: "other" };
  // --- the pipeline's own REFUSALS (it changed nothing): these must never read as Cloudflare faults ---
  if (m.includes("binding type(s) the safe-apply pipeline cannot guarantee") || m.includes("binding type(s) the update pipeline cannot guarantee") || m.includes("no service binding pointing at this engine")) {
    return { step: "binding-guard", cause: "binding-uncarryable" };
  }
  // The asset-hash refusal names the "verified console bundle" in its sentence, so it MUST be tested before
  // the bundle-parse arm: it is a Cloudflare/asset-session fault, not a malformed bundle.
  if (m.includes("asset hash that is not in the verified")) return { step: "asset-upload", cause: "asset-hash-unknown" };
  if (m.includes("console bundle")) return { step: "parse-bundle", cause: "bundle-invalid" };
  if (m.includes("read-back response shape was not recognised")) return { step: "readback", cause: "readback-unknown-shape" };
  if (m.includes("could not be read back")) return { step: "readback", cause: "other" };
  // --- the two PRE-CHANGE reads (a failure here means nothing was uploaded at all) ---
  if (m.includes("current settings") || m.includes("without a readable bindings list")) return { step: "read-settings", cause: "other" };
  if (m.includes("no deployments for") || m.includes("did not include a version id; cannot record a rollback target")) {
    return { step: "read-deployments", cause: "no-rollback-target" };
  }
  if (m.includes("current deployment to record a rollback target")) return { step: "read-deployments", cause: "other" };
  // --- the asset legs (console only) ---
  if (m.includes("asset manifest was not accepted") || m.includes("asset-upload session returned no token")) return { step: "asset-session", cause: "asset-token-absent" };
  if (m.includes("asset hash that is not in the verified")) return { step: "asset-upload", cause: "asset-hash-unknown" };
  if (m.includes("asset-upload completion token")) return { step: "asset-upload", cause: "asset-token-absent" };
  if (m.includes("asset bucket failed to upload")) return { step: "asset-upload", cause: "other" };
  // --- the write legs ---
  if (m.includes("the live deployment") || m.includes("gradual ramp")) return { step: "promote", cause: "promote-failed" };
  if (m.includes("could not be uploaded") || m.includes("did not return a version id")) return { step: "version-post", cause: "other" };
  return { step: "version-post", cause: "other" };
}

/**
 * cfCauseFromStatus refines an update fault's cause with the HTTP status of the Cloudflare exchange that
 * produced it, when there was one. A 4xx on an upload is a TOKEN/scope problem the operator fixes; a 5xx is a
 * Cloudflare incident they wait out. Pure; ints in, enum out.
 *
 * @param step - the closed step.
 * @param cause - the cause classifyUpdateFailStep chose.
 * @param httpStatus - the observed HTTP status (0 when no exchange happened).
 * @returns the refined cause.
 */
export function cfCauseFromStatus(step: UpdateFailStep, cause: UpdateCauseClass, httpStatus: number): UpdateCauseClass {
  if (cause !== "other" || httpStatus <= 0) return cause;
  if (step === "promote" || step === "rollback") return "promote-failed";
  if (httpStatus === 429) return "quota";
  if (httpStatus >= 500) return "upload-5xx";
  if (httpStatus >= 400) return "upload-4xx";
  return cause;
}

/**
 * classifyChannelFetchCause coarsens a channel / artefact FETCH outcome into its closed cause. The engine
 * already knows the status (or that the fetch threw), so this is a total function over integers, not text.
 *
 * @param status - the HTTP status; 0 means the fetch threw (no status exists).
 * @param opts - redirected: the response was a 3xx and was refused (redirect:manual); empty: a 2xx with no bytes.
 * @returns the closed cause.
 */
export function classifyChannelFetchCause(status: number, opts?: { redirected?: boolean; empty?: boolean }): UpdateCauseClass {
  if (opts?.redirected === true) return "redirect-refused";
  if (status <= 0) return "network";
  if (status >= 300 && status < 400) return "redirect-refused";
  if (status >= 500) return "fetch-status-5xx";
  if (status >= 400) return "fetch-status-4xx";
  if (opts?.empty === true) return "empty-body";
  return "other";
}

// ---------------------------------------------------------------------------------------------------------
// THE FAILED AUDIT-LOG EXPORT ATTEMPT (admin/router-rbac.ts, admin/support-ingest.ts)
//
// The tamper-evident audit log is the artefact a customer reaches for when they must PROVE what happened --
// a breach notification, an APRA/ISO evidence request, a dispute. Its whole value is that it can be taken OUT
// of the account and verified independently. Every export path in the engine is a pass-through: the console's
// download forwards GET /audit/export to the DO and hands back whatever it gets, and the collector feed pulls
// the same route on a schedule. When that forward FAILS -- the DO is unreachable, or the whole-log scan dies
// on a big chain -- the operator gets an error in the browser (or the collector gets a 5xx it retries
// forever) and the ENGINE RECORDS NOTHING AT ALL. There is no exportAttempts recorder anywhere.
//
// So "we cannot get our audit log out" is invisible in the pack: the chain verifies intact, the events are
// all there, and every artefact says the audit trail is healthy. The customer cannot prove they have not lost
// the evidence, which is the same class of harm as losing it. The AVAILABILITY of the export is a first-class
// fact and this is the record of it.
//
// (Deliberately NOT recorded here: the audit ROLLOVER. A legitimate retention rollover is not tamper and not
// a failure, and shipping it as a signal was refused on purpose -- see NO-SHIP-DECISIONS.md. That decision
// stands. This records the failed ATTEMPT, which is a real availability fact about a real operator action.)
// ---------------------------------------------------------------------------------------------------------

// EXPORT_CHANNELS is WHO was denied their evidence. The two are different tickets: an operator download that
// fails is a person staring at an error, a collector pull that fails is a SIEM silently missing a day.
export const EXPORT_CHANNELS = ["admin-download", "collector-feed"] as const;
export type ExportChannel = (typeof EXPORT_CHANNELS)[number];
const EXPORT_CHANNEL_SET: ReadonlySet<string> = new Set(EXPORT_CHANNELS);

// EXPORT_FORMATS is the shape asked for. A CSV export takes the SLOW whole-log path, so a chain that exports
// fine as a JSON feed page and dies as a CSV download is a size/scan fault, not an availability fault.
export const EXPORT_FORMATS = ["json", "csv"] as const;
export type ExportFormatClass = (typeof EXPORT_FORMATS)[number];
const EXPORT_FORMAT_SET: ReadonlySet<string> = new Set(EXPORT_FORMATS);

// EXPORT_ATTEMPT_OUTCOMES is the closed verdict of ONE export attempt, as seen at the Worker edge (which is
// the only place that sees BOTH failure modes: the DO answering badly, and the DO not answering at all).
export const EXPORT_ATTEMPT_OUTCOMES = [
  "ok", // the export was produced and handed to the caller
  "do-error", // the DO answered a non-2xx: the export itself faulted (the whole-log scan died, storage refused)
  "do-unavailable", // the round-trip THREW: the DO could not be reached, so no export exists and none was served
] as const;
export type ExportAttemptOutcome = (typeof EXPORT_ATTEMPT_OUTCOMES)[number];
const EXPORT_ATTEMPT_OUTCOME_SET: ReadonlySet<string> = new Set(EXPORT_ATTEMPT_OUTCOMES);

/**
 * One export attempt, built at the edge that performed it. Closed enums and a boolean only: the filter the
 * caller supplied (which can carry an actor e-mail, a downpipe name and a date range) is reduced to the single
 * boolean `filtered` and is NEVER carried, and the exported bytes are of course never touched.
 */
export interface ExportAttempt {
  readonly channel: ExportChannel;
  readonly format: ExportFormatClass;
  readonly outcome: ExportAttemptOutcome;
  readonly filtered: boolean; // the caller narrowed the export (an actor/action/date filter or a feed cursor)
}

/** The bounded audit-export-attempt aggregate. Counts, closed enums and clamped timestamps only. */
export interface ExportAttempts {
  readonly attempts: number; // every export attempt seen, so a failure has a denominator
  readonly failures: number; // the attempts that produced NO exportable evidence
  readonly byOutcome: Record<string, number>; // closed outcome -> count
  readonly byChannel: Record<string, number>; // closed channel -> FAILURE count (who was denied their evidence)
  readonly byFormat: Record<string, number>; // closed format -> FAILURE count (a CSV-only failure is a scan-size fault)
  readonly filteredFailures: number; // failures on a NARROWED export: a whole-log export may still work
  readonly lastAt: number; // epoch ms of the most recent attempt
  readonly lastFailureAt?: number; // epoch ms of the most recent FAILURE (absent while every export has worked)
  readonly lastFailureOutcome?: ExportAttemptOutcome;
}

export const EXPORT_ATTEMPTS_KEY = "diag:exportattempts";
const EXPORT_ATTEMPT_COUNT_CAP = 1_000_000;

/**
 * applyExportAttempt folds ONE attempt into the standing record. PURE, and the SINGLE REDACTION CHOKEPOINT for
 * this aggregate: the channel, the format and the outcome are each re-checked against their closed set (an
 * out-of-vocabulary value DROPS the attempt whole rather than storing it, so the key space is exactly the three
 * vocabularies), `filtered` is coerced to a boolean, and every count is clamped. NOTHING else on the posted
 * body is read -- so an actor e-mail, a downpipe name, a date range, a cursor, an error message or a byte of
 * the log itself structurally cannot enter the record even if a future call site were to post one.
 *
 * @param prior - the stored record, if any.
 * @param att - the posted attempt (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record, or the prior one unchanged when the attempt is out of vocabulary.
 */
export function applyExportAttempt(prior: ExportAttempts | undefined, att: unknown, now: number): ExportAttempts {
  const base: ExportAttempts = prior ?? { attempts: 0, failures: 0, byOutcome: {}, byChannel: {}, byFormat: {}, filteredFailures: 0, lastAt: 0 };
  const a = (typeof att === "object" && att !== null ? att : {}) as Partial<ExportAttempt>;
  const channel = typeof a.channel === "string" && EXPORT_CHANNEL_SET.has(a.channel) ? (a.channel as ExportChannel) : null;
  const format = typeof a.format === "string" && EXPORT_FORMAT_SET.has(a.format) ? (a.format as ExportFormatClass) : null;
  const outcome = typeof a.outcome === "string" && EXPORT_ATTEMPT_OUTCOME_SET.has(a.outcome) ? (a.outcome as ExportAttemptOutcome) : null;
  // A drifted / hostile writer records NOTHING rather than a half-classified row: a fabricated channel would
  // misattribute the outage, which is worse than not recording it.
  if (channel === null || format === null || outcome === null) return sanitiseExportAttempts(base);
  const failed = outcome !== "ok";
  const clean = sanitiseExportAttempts(base);
  const bump = (m: Record<string, number>, k: string): Record<string, number> => ({ ...m, [k]: Math.min(EXPORT_ATTEMPT_COUNT_CAP, (m[k] ?? 0) + 1) });
  const at = clampCount(now, Number.MAX_SAFE_INTEGER);
  return {
    attempts: Math.min(EXPORT_ATTEMPT_COUNT_CAP, clean.attempts + 1),
    failures: Math.min(EXPORT_ATTEMPT_COUNT_CAP, clean.failures + (failed ? 1 : 0)),
    byOutcome: bump(clean.byOutcome, outcome),
    byChannel: failed ? bump(clean.byChannel, channel) : clean.byChannel,
    byFormat: failed ? bump(clean.byFormat, format) : clean.byFormat,
    filteredFailures: Math.min(EXPORT_ATTEMPT_COUNT_CAP, clean.filteredFailures + (failed && a.filtered === true ? 1 : 0)),
    lastAt: at,
    ...(failed ? { lastFailureAt: at, lastFailureOutcome: outcome } : clean.lastFailureAt !== undefined ? { lastFailureAt: clean.lastFailureAt, ...(clean.lastFailureOutcome !== undefined ? { lastFailureOutcome: clean.lastFailureOutcome } : {}) } : {}),
  };
}

// clampCount is the numeric gate for this aggregate: a NaN, an Infinity, a negative or a non-number is 0.
function clampCount(n: unknown, cap: number): number {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return 0;
  return Math.min(cap, Math.floor(n));
}

// sanitiseExportAttempts re-gates a STORED record on the way back in (defence in depth: the record may have
// been written by an older build, so its key space is re-checked against today's vocabularies before it is
// folded into a new one).
function sanitiseExportAttempts(r: ExportAttempts): ExportAttempts {
  const gate = (m: unknown, allowed: ReadonlySet<string>): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const [k, v] of Object.entries(typeof m === "object" && m !== null ? (m as Record<string, unknown>) : {})) {
      if (!allowed.has(k)) continue;
      out[k] = clampCount(v, EXPORT_ATTEMPT_COUNT_CAP);
    }
    return out;
  };
  const lastFailureOutcome = typeof r.lastFailureOutcome === "string" && EXPORT_ATTEMPT_OUTCOME_SET.has(r.lastFailureOutcome) ? r.lastFailureOutcome : undefined;
  return {
    attempts: clampCount(r.attempts, EXPORT_ATTEMPT_COUNT_CAP),
    failures: clampCount(r.failures, EXPORT_ATTEMPT_COUNT_CAP),
    byOutcome: gate(r.byOutcome, EXPORT_ATTEMPT_OUTCOME_SET),
    byChannel: gate(r.byChannel, EXPORT_CHANNEL_SET),
    byFormat: gate(r.byFormat, EXPORT_FORMAT_SET),
    filteredFailures: clampCount(r.filteredFailures, EXPORT_ATTEMPT_COUNT_CAP),
    lastAt: clampCount(r.lastAt, Number.MAX_SAFE_INTEGER),
    ...(r.lastFailureAt !== undefined ? { lastFailureAt: clampCount(r.lastFailureAt, Number.MAX_SAFE_INTEGER) } : {}),
    ...(lastFailureOutcome !== undefined ? { lastFailureOutcome } : {}),
  };
}

// ---------------------------------------------------------------------------------------------------------
// THE ADMIN-ROUTE OUTER CATCH (admin/router-updates.ts, admin/router-updates-ramp.ts)
//
// THE GAP. The update, rollback, ramp and licence-activation routes each end in an outermost
// `catch { return jsonError("... nothing was changed ...", 400) }`. Three things are wrong with that, and
// they compound:
//
//   1. The exception is DISCARDED. Nothing, anywhere, server-side, records that the route threw. The only
//      statement of the failure is an HTTP response, which dies with the browser tab.
//   2. The prose is FIXED, and sometimes FALSE. "nothing was changed" is asserted unconditionally -- but the
//      throw can land AFTER the deploy has gone live (the promote redeploys the engine, which momentarily
//      resets the very DO the follow-up write needs). So the customer is told nothing happened while their
//      engine is, in fact, running the new version.
//   3. There is no LOCUS. "Update apply always fails with a generic message" cannot be triaged: was it the
//      Durable Object, the signed channel fetch, the version gate, Cloudflare's deploy API, or the
//      bookkeeping write afterwards? Each is a different owner and a different fix.
//
// THE RECORD. A bounded {route, stage} -> {count, lastAt} aggregate. `stage` is set at the LAST CHECKPOINT
// PASSED, not guessed from the exception, so it is a fact rather than a classification -- and it is what makes
// the "nothing was changed" claim CHECKABLE: a fault recorded at `deploy-driver` or `persist` means the deploy
// very possibly DID land, and the pack now says so.
//
// NO-CUSTODY: two closed enums and an integer. The exception text -- which interpolates versions, ids,
// Cloudflare messages and, on the licence path, could echo a token fragment -- never persists.
// ---------------------------------------------------------------------------------------------------------

// ADMIN_ROUTE_NAMES is the closed set of routes whose outermost catch is instrumented.
export const ADMIN_ROUTE_NAMES = [
  "update-apply", // POST /update/apply: phase 1 (verify + upload + promote)
  "update-settle", // POST /update/settle: phase 2 (canary + keep-or-roll-back)
  "update-rollback", // POST /update/rollback: the standalone revert to the recorded known-good
  "ramp-start", // POST /update/ramp: the opt-in gradual traffic split
  "ramp-settle", // POST /update/ramp/settle: verify the ramped slice
  "licence-activate", // POST /admin/licence: activate a vendor-issued licence token
  "runs-at", // GET /admin/runs/at: point-in-time run resolution (the recovery-timeline pick)
] as const;
export type AdminRouteName = (typeof ADMIN_ROUTE_NAMES)[number];
const ADMIN_ROUTE_NAME_SET: ReadonlySet<string> = new Set(ADMIN_ROUTE_NAMES);

// ADMIN_ROUTE_STAGES is the LAST CHECKPOINT the route passed before it threw. Ordered by how far the request
// got, which is exactly the order of how much may have changed.
export const ADMIN_ROUTE_STAGES = [
  "do-read", // reading state from the scheduler DO (the status, the pending record, the licence). NOTHING was changed
  "channel-fetch", // fetching + verifying the signed update channel / licence token. NOTHING was changed
  "gate", // the version / risk / migration / floor gate. NOTHING was changed
  "deploy-driver", // driving Cloudflare's versions+deployments API. Something MAY HAVE been changed: an upload can land and the promote still throw, and a promote can land and the response still die
  "persist", // writing the lifecycle record / audit row AFTER a deploy went live. Something WAS changed: the engine is on the new version and the record of it did not land
] as const;
export type AdminRouteStage = (typeof ADMIN_ROUTE_STAGES)[number];
const ADMIN_ROUTE_STAGE_SET: ReadonlySet<string> = new Set(ADMIN_ROUTE_STAGES);

/** One admin-route outer-catch fault: WHERE it threw, and HOW FAR it got. */
export interface AdminRouteError {
  readonly route: AdminRouteName;
  readonly stage: AdminRouteStage;
}

/** The bounded admin-route-error aggregate: "<route>|<stage>" -> count, plus the last occurrence. */
export interface AdminRouteErrors {
  readonly byRouteStage: Record<string, number>; // "<closed route>|<closed stage>" -> count
  readonly total: number;
  readonly lastRoute?: AdminRouteName;
  readonly lastStage?: AdminRouteStage;
  readonly lastAt: number;
  // mutatingFaults counts the faults at `deploy-driver` or `persist`: the ones where the route's fixed
  // "nothing was changed" sentence may be a LIE. This is the number a diagnosis reads first.
  readonly mutatingFaults: number;
}

export const ADMIN_ROUTE_ERRORS_KEY = "diag:adminrouteerrors";
const ADMIN_ROUTE_COUNT_CAP = 1_000_000;
// The stages at which the route's "nothing was changed" claim is NOT safe to believe.
const MUTATING_STAGES: ReadonlySet<string> = new Set(["deploy-driver", "persist"]);

/**
 * applyAdminRouteError folds ONE fault into the standing record. PURE, and the SINGLE REDACTION CHOKEPOINT
 * for this aggregate: the route and the stage are each re-checked against their closed set (an
 * out-of-vocabulary value DROPS the fault whole rather than storing it, so the key space is exactly
 * routes x stages), and every count is re-clamped DO-side. NOTHING else on the posted body is read, so an
 * exception message, a version string, a token or a Cloudflare error cannot enter the record.
 *
 * @param prior - the stored record, if any.
 * @param err - the posted fault (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record, or the prior one when the fault is out of vocabulary.
 */
export function applyAdminRouteError(prior: AdminRouteErrors | undefined, err: unknown, now: number): AdminRouteErrors {
  const base: AdminRouteErrors = prior ?? { byRouteStage: {}, total: 0, lastAt: 0, mutatingFaults: 0 };
  const e = (typeof err === "object" && err !== null ? err : {}) as Partial<AdminRouteError>;
  const route = typeof e.route === "string" && ADMIN_ROUTE_NAME_SET.has(e.route) ? (e.route as AdminRouteName) : null;
  const stage = typeof e.stage === "string" && ADMIN_ROUTE_STAGE_SET.has(e.stage) ? (e.stage as AdminRouteStage) : null;

  // Re-gate the STORED record on the way back in (it may have been written by an older build).
  const byRouteStage: Record<string, number> = {};
  for (const [k, v] of Object.entries(base.byRouteStage ?? {})) {
    const [r, s] = k.split("|");
    if (r === undefined || s === undefined || !ADMIN_ROUTE_NAME_SET.has(r) || !ADMIN_ROUTE_STAGE_SET.has(s)) continue;
    byRouteStage[k] = clampCount(v, ADMIN_ROUTE_COUNT_CAP);
  }
  const clean: AdminRouteErrors = {
    byRouteStage,
    total: clampCount(base.total, ADMIN_ROUTE_COUNT_CAP),
    ...(typeof base.lastRoute === "string" && ADMIN_ROUTE_NAME_SET.has(base.lastRoute) ? { lastRoute: base.lastRoute } : {}),
    ...(typeof base.lastStage === "string" && ADMIN_ROUTE_STAGE_SET.has(base.lastStage) ? { lastStage: base.lastStage } : {}),
    lastAt: clampCount(base.lastAt, Number.MAX_SAFE_INTEGER),
    mutatingFaults: clampCount(base.mutatingFaults, ADMIN_ROUTE_COUNT_CAP),
  };
  if (route === null || stage === null) return clean;

  const key = `${route}|${stage}`;
  const at = clampCount(now, Number.MAX_SAFE_INTEGER);
  return {
    byRouteStage: { ...clean.byRouteStage, [key]: Math.min(ADMIN_ROUTE_COUNT_CAP, (clean.byRouteStage[key] ?? 0) + 1) },
    total: Math.min(ADMIN_ROUTE_COUNT_CAP, clean.total + 1),
    lastRoute: route,
    lastStage: stage,
    lastAt: at,
    mutatingFaults: Math.min(ADMIN_ROUTE_COUNT_CAP, clean.mutatingFaults + (MUTATING_STAGES.has(stage) ? 1 : 0)),
  };
}

// ---------------------------------------------------------------------------------------------------------
// THE CONTROL-PLANE RECOVERY REFUSAL (admin/router-identity.ts, admin/posture-checks.ts)
//
// THE GAP. This is the DISASTER-RECOVERY path: the estate is gone, the customer is rebuilding it from a
// signed export and their offline recovery kit, and the support pack may be the ONLY artefact that survives
// to explain what happened. Every refusal on that path lived in the operator's browser: the import's
// signature refusal, the recovery-kit download's 500/502, the apply-staged 409 on a corrupt staged artefact,
// the reconcile's rejection.
//
// And the SHARPEST edge: a THROWN crypto fault (a corrupt kit signer.pub that will not import, an
// unparseable signature blob) and a genuine signature MISMATCH (a modified export -- tamper) both fell
// through to the SAME `sigOk = false` and the SAME "the export signature did not verify" refusal. Those are
// opposite diagnoses: one says "your kit file is damaged, get another copy", the other says "someone has
// altered your recovery artefact". "Estate import says signature invalid but the kit is correct" is exactly
// the ticket that cannot be answered when they are byte-identical.
//
// NO-CUSTODY: closed surfaces, closed classes and counts. No signature material, no verifier bytes, no export
// contents, no bucket key and no free-text refusal reason (the same discipline the auto-heal refusal already
// keeps: its `reason` can embed a JSON path from the shape check and is deliberately never projected).
// ---------------------------------------------------------------------------------------------------------

// RECOVERY_REFUSAL_SURFACES is WHICH recovery action was refused. Each is a different operator standing in
// front of a different broken thing.
export const RECOVERY_REFUSAL_SURFACES = [
  "export-download", // GET /control-plane/export-download: the operator cannot even OBTAIN a fresh recovery artefact
  "estate-import", // POST /control-plane/import: the cross-environment rebuild from a kit-verified export
  "estate-import-sealed", // POST /control-plane/import-sealed: the SAME rebuild, fed a browser-unsealed export
  "reconcile", // POST /control-plane/restore: the break-glass rebuild of a wiped plane from a bucket export
  "reconcile-sealed", // POST /control-plane/restore-sealed: the SAME break-glass authority rebuild, fed a
  // browser-unsealed export -- for the estate whose engine holds no CONFIG_RECIPIENT_PRIVATE (so the cron
  // auto-heal cannot open its own sealed export either), where the operator's OWN break-glass identity.key
  // unseals it instead. Same-account, so verified against THIS engine's own signer, never an operator-supplied
  // kit key (that is estate-import-sealed's job, for a different account).
  "apply-staged", // the break-glass confirm of the export the auto-heal already staged
  // CP-RECOVERY-LATCH defect 23: POST /control-plane/acknowledge-recovery, the acknowledge-only latch clear.
  // It is its own surface and not a variant of `reconcile` because the operator standing in front of it is a
  // different one: an AUTHENTICATED owner on an estate whose configuration is back, not a break-glass holder
  // over a wiped plane. Folding the two would put "the estate recovered and the banner would not go down" and
  // "the rebuild was refused" in one row, and they have opposite remedies.
  "acknowledge",
] as const;
export type RecoveryRefusalSurface = (typeof RECOVERY_REFUSAL_SURFACES)[number];
const RECOVERY_REFUSAL_SURFACE_SET: ReadonlySet<string> = new Set(RECOVERY_REFUSAL_SURFACES);

// RECOVERY_REFUSAL_CLASSES is WHY. The first four are the crypto verdict, and they are the pair-of-pairs the
// whole gap turns on. They are NOT a structural guess about the signature STRING: they are the closed verdict
// hybridVerifyDetailed (crypto/sign.ts) already computes and used to throw away, so the four worlds a bare
// `false` collapsed into stay four rows.
//
//   verify-threw       the .sig FILE is damaged. Re-copy the signature. The export and the key are both fine.
//   verifier-invalid   the KEY is damaged (the kit's signer.pub, or this engine's SIGNER_PRIVATE). Re-copy the
//                      key. The export is fine, and telling this customer their artefact was TAMPERED WITH --
//                      which is what the old structural proxy did, because a right-length corrupt key sails
//                      through a length check and fails inside the verify -- is the exact inversion this gap
//                      exists to stop.
//   signature          NEITHER half verified: the wrong key, or the export was ALTERED. Tamper lives here and
//                      ONLY here, because tamper is the only world that can break both halves at once.
//   classical-half-damaged
//                      the POST-QUANTUM half verified and the classical half did not, so the ML-DSA half checked
//                      these exact export bytes under the kit's own key: THE EXPORT IS PROVABLY INTACT and the
//                      damage is confined to the Ed25519 half of the KEY FILE or of the SIGNATURE. This is a
//                      corrupt / partially-restored / half-written signer.pub, a mangled .sig, or a partial
//                      signer rotation. It used to be scored `signature` (the verify short-circuited on the
//                      classical half and never ran the second one), which told the customer their disaster-
//                      recovery artefact had been TAMPERED WITH when the remedy was "take another copy of your
//                      kit". Tamper cannot reach this class: altering the export breaks BOTH halves.
//   signature-pq       the classical half verified and the POST-QUANTUM half did not, so whatever is wrong is
//                      confined to the ML-DSA half of the KEY PAIR: a partial/mixed SIGNER ROTATION, or a kit
//                      signer.pub whose ML-DSA half has rotted (a corrupt right-length ML-DSA key verifies
//                      false rather than throwing, so it lands here, not on verifier-invalid). It can never be
//                      a modified export or a corrupted signature: either of those fails the CLASSICAL half
//                      first and comes back `signature`. So the EXPORT IS INTACT whenever this row is written,
//                      and the remedy is "find out which signer signed this, and re-copy your kit key", never
//                      "someone has attacked you".
export const RECOVERY_REFUSAL_CLASSES = [
  "signature", // NEITHER signature half verified: the wrong key, or the export was modified. Tamper, or the wrong kit. The ONLY class a tamper can reach
  "signature-pq", // the classical half verified and the ML-DSA-87 half did not: a partial/mixed signer rotation, or a rotted ML-DSA half of the kit key. NEVER tamper: the export is intact
  "classical-half-damaged", // the ML-DSA-87 half verified and the CLASSICAL half did not: the post-quantum half checked these exact export bytes under the kit's own key, so the EXPORT IS PROVABLY INTACT and the damage is confined to the Ed25519 half of the KEY FILE or of the .sig (bit rot, a partially-restored or half-written signer.pub, a mangled signature, a partial signer rotation). NEVER tamper: altering the export breaks BOTH halves. The remedy is "take another copy of your recovery kit", the OPPOSITE of the remedy for `signature`
  "verify-threw", // the detached signature BLOB would not decode (a truncated / half-written .sig). The signature FILE is damaged; the export was never checked at all
  "verifier-invalid", // the VERIFIER would not import: the kit's signer.pub is corrupt, or this engine's own SIGNER_PRIVATE will not load. The KEY is damaged, NOT the export -- the opposite remedy, and previously byte-identical to `signature`
  "malformed", // the request body is not valid JSON, or a required field is absent
  "shape", // the body parsed and is not a control-plane export artefact (a version pin or a structural field failed)
  "no-custody", // the artefact carries a PLAINTEXT SECRET and was refused on the no-custody assertion (a hand-edited or hostile export)
  "no-signer", // the engine has no SIGNER_PRIVATE, so it cannot verify (or, on download, cannot sign) at all
  "build-failed", // the DO could not BUILD the export to be downloaded: there is nothing to hand over
  "reconcile-refused", // the artefact verified and the DO refused the rebuild (a non-fresh plane, an authority guard)
  "staged-malformed", // the staged artefact the auto-heal parked is itself corrupt: the confirm can never succeed until it is re-staged
  // browser-unseal-specific classes. The sealed wrapper's OWN signature verify reuses the five crypto
  // classes above unchanged (verifySealedControlPlaneSignatureDetailed returns the same HybridVerifyVerdict);
  // these two are for the two failure modes that exist ONLY on this route, because it is handed a plaintext
  // export the browser already decrypted rather than one the engine parsed straight off the wire.
  "sealed-body-mismatch", // the recovered plaintext's hash does not match the SIGNED bodyHash: the sealed signature verified, but the plaintext handed to this route is not what it committed to
  "sealed-unhashed", // the sealed artefact predates bodyHash: written before this field existed, so this route cannot cross-check the plaintext and refuses rather than trust it unverified
  // CP-RECOVERY-LATCH defect 23: the two ways the acknowledge-only latch clear refuses. Separate classes,
  // because the operator's next step differs completely and because the console maps a class to the stable
  // code a customer reads out. Neither is reachable by a break-glass caller (the route refuses the bare token
  // upstream of both), so neither can ever coalesce with a reconcile refusal.
  "ack-role-table-empty", // the estate's role table is empty, so clearing the latch would remove the only explanation for every caller resolving to viewer (the G061 deadlock guard). NOT a wiped-plane refusal
  "ack-no-latch", // there was no recovery in effect by the time the acknowledge arrived: another operator, another tab or a reconcile had already cleared it. Benign, and distinct from a refusal
] as const;
export type RecoveryRefusalClass = (typeof RECOVERY_REFUSAL_CLASSES)[number];
const RECOVERY_REFUSAL_CLASS_SET: ReadonlySet<string> = new Set(RECOVERY_REFUSAL_CLASSES);

/** One refused recovery action. Two closed enums; nothing else is representable. */
export interface RecoveryRefusal {
  readonly surface: RecoveryRefusalSurface;
  readonly cls: RecoveryRefusalClass;
}

/** The bounded recovery-refusal aggregate. */
export interface RecoveryRefusals {
  readonly bySurfaceClass: Record<string, number>; // "<closed surface>|<closed class>" -> count
  readonly total: number;
  readonly lastSurface?: RecoveryRefusalSurface;
  readonly lastClass?: RecoveryRefusalClass;
  readonly lastAt: number;
  // stagedMalformed latches the one state a retry can never clear: the export the auto-heal staged is corrupt,
  // so the break-glass confirm 409s forever until it is re-staged. It is a standing FLAG, not a count, because
  // it describes the engine's CURRENT condition rather than a history of attempts.
  readonly stagedMalformed: boolean;
}

export const RECOVERY_REFUSALS_KEY = "diag:recoveryrefusals";
const RECOVERY_REFUSAL_COUNT_CAP = 1_000_000;

/**
 * applyRecoveryRefusal folds ONE refusal into the standing record. PURE, and the SINGLE REDACTION CHOKEPOINT
 * for this aggregate: the surface and the class are re-checked against their closed sets (an out-of-vocabulary
 * value DROPS the refusal whole), and every count is re-clamped DO-side. NOTHING else on the posted body is
 * read, so a signature, a verifier, an export body, a bucket key or a refusal sentence cannot enter the record.
 *
 * @param prior - the stored record, if any.
 * @param refusal - the posted refusal (untrusted).
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record, or the prior one when the refusal is out of vocabulary.
 */
export function applyRecoveryRefusal(prior: RecoveryRefusals | undefined, refusal: unknown, now: number): RecoveryRefusals {
  const base: RecoveryRefusals = prior ?? { bySurfaceClass: {}, total: 0, lastAt: 0, stagedMalformed: false };
  const r = (typeof refusal === "object" && refusal !== null ? refusal : {}) as Partial<RecoveryRefusal>;
  const surface = typeof r.surface === "string" && RECOVERY_REFUSAL_SURFACE_SET.has(r.surface) ? (r.surface as RecoveryRefusalSurface) : null;
  const cls = typeof r.cls === "string" && RECOVERY_REFUSAL_CLASS_SET.has(r.cls) ? (r.cls as RecoveryRefusalClass) : null;

  const bySurfaceClass: Record<string, number> = {};
  for (const [k, v] of Object.entries(base.bySurfaceClass ?? {})) {
    const [s, c] = k.split("|");
    if (s === undefined || c === undefined || !RECOVERY_REFUSAL_SURFACE_SET.has(s) || !RECOVERY_REFUSAL_CLASS_SET.has(c)) continue;
    bySurfaceClass[k] = clampCount(v, RECOVERY_REFUSAL_COUNT_CAP);
  }
  const clean: RecoveryRefusals = {
    bySurfaceClass,
    total: clampCount(base.total, RECOVERY_REFUSAL_COUNT_CAP),
    ...(typeof base.lastSurface === "string" && RECOVERY_REFUSAL_SURFACE_SET.has(base.lastSurface) ? { lastSurface: base.lastSurface } : {}),
    ...(typeof base.lastClass === "string" && RECOVERY_REFUSAL_CLASS_SET.has(base.lastClass) ? { lastClass: base.lastClass } : {}),
    lastAt: clampCount(base.lastAt, Number.MAX_SAFE_INTEGER),
    stagedMalformed: base.stagedMalformed === true,
  };
  if (surface === null || cls === null) return clean;

  const key = `${surface}|${cls}`;
  const at = clampCount(now, Number.MAX_SAFE_INTEGER);
  return {
    bySurfaceClass: { ...clean.bySurfaceClass, [key]: Math.min(RECOVERY_REFUSAL_COUNT_CAP, (clean.bySurfaceClass[key] ?? 0) + 1) },
    total: Math.min(RECOVERY_REFUSAL_COUNT_CAP, clean.total + 1),
    lastSurface: surface,
    lastClass: cls,
    lastAt: at,
    stagedMalformed: clean.stagedMalformed || cls === "staged-malformed",
  };
}
