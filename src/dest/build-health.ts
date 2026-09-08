// DESTINATION BUILD HEALTH (gaps G137 "destination unbuildable is not a standing state" and G136 "the STS
// AssumeRole failure cause is a black box").
//
// THE PROBLEM. Every backup starts by CONSTRUCTING a destination (dest/factory.ts buildDestination). When
// that construction throws -- a redeploy wiped DEST_ENDPOINT or CONFIG_WRAP_KEY (the owner's confirmed #1
// fear), DEST_KIND is a typo, the stored endpoint is not https, an explicit vhost bucket is unsafe, the
// region is "auto" under an STS policy, the scheduler DO would not answer, or STS refused the AssumeRole --
// the ONLY evidence is the failing run's COARSE error class. Nothing says the destination has been
// unbuildable SINCE a particular moment, and nothing says WHICH knob broke it. Worse, every STS refusal
// (AccessDenied on the trust policy, an ExpiredToken principal, a mismatched ExternalId, a deleted role)
// collapses to an identical "status 403": sts.ts deliberately never reads the response body, because that
// body carries LIVE temporary credentials.
//
// THE SHAPE. One bounded standing record: the last build outcome, the moment the destination STARTED failing
// (failingSinceAt, which is the fact a coarse run error can never carry), the closed cause, and per-cause /
// per-STS-class counters. It is a LEAF (imports nothing), so the Worker edge, dest/factory.ts and the
// scheduler DO can all agree on one vocabulary with no import cycle -- the same reason config-anomalies.ts
// and admin/diag-records.ts exist.
//
// NO-CUSTODY REDACTION (binding).
//   - cause is a member of the CLOSED DEST_BUILD_CAUSES vocabulary. Nothing else is ever a cause.
//   - varName is a member of the CLOSED DEST_BUILD_VARS vocabulary: the engine's OWN fixed env-var / stored-
//     field names. It is an ALLOW-LIST, not a charset gate, so a value, an endpoint, a bucket, a role ARN or
//     a credential structurally cannot ride in it even if a future call site passed one.
//   - stsFailureClass is a member of the CLOSED STS_FAILURE_CLASSES vocabulary. classifyStsFailure READS the
//     STS error document ONLY to SELECT one of those members and RETURNS the enum: the body -- which on the
//     SUCCESS path carries a live SecretAccessKey and SessionToken -- is never returned, stored or forwarded,
//     and is only ever read on a NON-2xx response (an error document, never a credential document).
//   - everything else is a count, a clamped timestamp or a clamped HTTP status.

/**
 * DEST_BUILD_CAUSES is the CLOSED vocabulary of "the destination could not be CONSTRUCTED, and this is why".
 * Each member names a DIFFERENT operator remedy:
 *   env-missing              a required DEST_* env var is absent (varName names WHICH). The redeploy-wiped-vars
 *                            case: every backup fails at construction and the run row says only "run failed".
 *   kind-unrecognised        DEST_KIND is set to something other than "r2" / "s3" (a typo): refused, never
 *                            silently defaulted.
 *   kind-ambiguous           no DEST_KIND, but BOTH an R2 binding and S3 credentials are present: refused rather
 *                            than guessing which store the archive belongs in (guessing would SPLIT the archive).
 *   r2-binding-missing       DEST_KIND=r2 but the DEST_R2 binding is not in the environment (the deploy dropped it).
 *   endpoint-not-https       the stored/env endpoint is not https (the engine refuses to put a SigV4 credential
 *                            and archive bytes on the wire in cleartext).
 *   endpoint-unparseable     the endpoint is not a URL at all.
 *   vhost-bucket-unsafe      an explicit vhost addressing whose bucket name would break out of the request host.
 *   vhost-bucket-doubled     the endpoint ALREADY carries the bucket as its leading host label, and virtual-hosted
 *                            addressing would prepend it a second time ("mybucket.mybucket.s3.amazonaws.com").
 *                            The operator pasted their provider console's per-bucket URL into the endpoint box.
 *                            Distinct from vhost-bucket-unsafe (a hostile bucket NAME) and from a plain
 *                            unreachable endpoint: the remedy is one specific edit, and without this cause the
 *                            doubled host fails as a DNS lookup and the operator is told to check credentials
 *                            that were never wrong.
 *   sts-region-invalid       an AssumeRole policy with a region that is not an AWS region (the R2 "auto"
 *                            convention, which STS cannot use).
 *   sts-assume-role-failed   STS REFUSED the AssumeRole (stsFailureClass names which refusal).
 *   config-do-unreadable     the scheduler DO would not answer the destination-config read (doStatus carries the
 *                            clamped HTTP status): the destination may be perfectly healthy, we could not READ it.
 *   config-incomplete        the STORED destination config is missing a required field: no backup can run.
 *   other                    residual: a construction throw outside the named causes (never a message).
 *
 * There is NO member for a CONFIG_WRAP_KEY fault, though that one stops the WHOLE fleet rather than one
 * downpipe: an unopenable stored credential throws from resolveConfigSecret rather than as a DestBuildError,
 * so it lands on "other" here, and its own closed cause is kept by the unwrap-fault ledger that
 * dest/factory.ts fetchDestConfig writes at the read-for-use site.
 */
export const DEST_BUILD_CAUSES = [
  "env-missing",
  "kind-unrecognised",
  "kind-ambiguous",
  "r2-binding-missing",
  "endpoint-not-https",
  "endpoint-unparseable",
  "vhost-bucket-unsafe",
  "vhost-bucket-doubled",
  "sts-region-invalid",
  "sts-assume-role-failed",
  "config-do-unreadable",
  "config-incomplete",
  "other",
] as const;
/**
 * One member of DEST_BUILD_CAUSES: the closed reason a destination could not be constructed. It is the
 * `buildCause` a DestBuildError carries from its throw site and the `lastCause` on the standing health
 * record. A POSTED cause outside the vocabulary is coerced to "other" by applyDestBuildHealth rather than
 * carried as text, so the field stays closed even if a future call site posts something else.
 */
export type DestBuildCause = (typeof DEST_BUILD_CAUSES)[number];
const DEST_BUILD_CAUSE_SET: ReadonlySet<string> = new Set(DEST_BUILD_CAUSES);

/**
 * DEST_BUILD_VARS is the CLOSED allow-list of knob NAMES a build fault may name. These are the engine's OWN
 * product vocabulary (fixed env vars and stored field names), never operator data. An ALLOW-LIST rather than a
 * charset gate is what makes this seam un-smugglable: a bucket, an endpoint, a role ARN or a secret cannot be a
 * member, so no drifted call site can turn varName into a free-text field.
 */
export const DEST_BUILD_VARS = [
  "DEST_ENDPOINT",
  "DEST_BUCKET",
  "DEST_REGION",
  "DEST_ACCESS_KEY_ID",
  "DEST_SECRET_ACCESS_KEY",
  "DEST_KIND",
  "DEST_R2",
  "CONFIG_WRAP_KEY",
  // the STORED (console-set) destination's field names, for config-incomplete
  "endpoint",
  "bucket",
  "region",
  "accessKeyId",
  "secretAccessKey",
] as const;
/**
 * One member of DEST_BUILD_VARS: the knob a build fault points at. Typing it as the allow-list rather than
 * `string` means a call site cannot pass an endpoint, a bucket or a credential as a varName. The throw sites
 * hand DestBuildError an untyped string, so its constructor re-checks the same set and simply omits anything
 * that is not a member.
 */
export type DestBuildVar = (typeof DEST_BUILD_VARS)[number];
const DEST_BUILD_VAR_SET: ReadonlySet<string> = new Set(DEST_BUILD_VARS);

/**
 * STS_FAILURE_CLASSES (G136) is the CLOSED vocabulary for WHY an AssumeRole was refused. Each names a different
 * team and a different fix: access-denied is the role's TRUST POLICY (or a principal without sts:AssumeRole);
 * expired-token / invalid-client-token-id is the PRINCIPAL credential (rotated or deleted under the engine);
 * malformed-policy is the session policy; invalid-identity-token is the federation path; no-such-entity is a
 * DELETED role; throttled is real STS backpressure; network is a request that never got an answer;
 * response-unparseable is a 200 whose document carried no credentials (a proxy in the path).
 */
export const STS_FAILURE_CLASSES = [
  "access-denied",
  "expired-token",
  "invalid-client-token-id",
  "signature-mismatch",
  "malformed-policy",
  "invalid-identity-token",
  "no-such-entity",
  "throttled",
  "network",
  "response-unparseable",
  "other",
] as const;
/**
 * One member of STS_FAILURE_CLASSES: the closed reason STS refused an AssumeRole. It is the ONLY thing
 * classifyStsErrorBody can return, which is what keeps the STS document out of every record downstream.
 * sts.ts reads that document only on a NON-2xx response, because a 2xx AssumeRole document carries a live
 * SecretAccessKey and SessionToken while an error document does not.
 */
export type StsFailureClass = (typeof STS_FAILURE_CLASSES)[number];
const STS_FAILURE_CLASS_SET: ReadonlySet<string> = new Set(STS_FAILURE_CLASSES);

// STS_CODE_RE is deliberately TIGHT (a leading letter then up to 63 letters/digits, nothing else), the same
// discipline dest/fault-log.ts CODE_RE and s3-worm.ts use: a hostile or proxied body cannot even reach the
// mapping below with punctuation or whitespace smuggled in. The extracted token is then mapped through a fixed
// table, so ONLY a member of STS_FAILURE_CLASSES can ever leave classifyStsErrorBody.
const STS_CODE_RE = /<Code>\s*([A-Za-z][A-Za-z0-9]{0,63})\s*<\/Code>/;

// STS_CODE_TO_CLASS maps AWS's documented STS error codes (a fixed, vendor-defined enum -- never secret, never
// customer data) to the closed class. A code OUTSIDE this table records as "other".
const STS_CODE_TO_CLASS: Readonly<Record<string, StsFailureClass>> = {
  AccessDenied: "access-denied",
  AccessDeniedException: "access-denied",
  ExpiredToken: "expired-token",
  ExpiredTokenException: "expired-token",
  TokenRefreshRequired: "expired-token",
  InvalidClientTokenId: "invalid-client-token-id",
  IncompleteSignature: "signature-mismatch",
  SignatureDoesNotMatch: "signature-mismatch",
  MalformedPolicyDocument: "malformed-policy",
  PackedPolicyTooLarge: "malformed-policy",
  InvalidIdentityToken: "invalid-identity-token",
  IDPRejectedClaim: "invalid-identity-token",
  IDPCommunicationError: "invalid-identity-token",
  NoSuchEntity: "no-such-entity",
  RegionDisabledException: "access-denied",
  Throttling: "throttled",
  ThrottlingException: "throttled",
  TooManyRequestsException: "throttled",
  ServiceUnavailable: "throttled",
};

/**
 * classifyStsErrorBody reduces an STS ERROR DOCUMENT to a CLOSED StsFailureClass. It is the G136 redaction
 * chokepoint: it READS the body ONLY to match the documented <Code> token against a fixed table and RETURNS the
 * enum. The body itself never leaves this function, is never stored and is never logged.
 *
 * It must ONLY ever be called on a NON-2xx STS response. A 2xx AssumeRole document carries a live
 * SecretAccessKey and SessionToken; an error document does not.
 *
 * @param body - the already-bounded STS error body (never retained).
 * @returns the closed failure class.
 */
export function classifyStsErrorBody(body: string): StsFailureClass {
  const raw = STS_CODE_RE.exec(body)?.[1];
  if (raw === undefined) return "other";
  return STS_CODE_TO_CLASS[raw] ?? "other";
}

/**
 * DestBuildError is the TYPED form of a destination-construction fault. It extends Error and keeps the EXISTING
 * message verbatim, so every downstream behaviour (the coarse run-error classification, the strike ladder, the
 * log line) is byte-unchanged. The closed `cause`, `varName`, `stsFailureClass` and `doStatus` are the ADDITIVE
 * evidence, set from the engine's own vocabulary at the throw site -- never parsed back out of a message.
 */
export class DestBuildError extends Error {
  readonly buildCause: DestBuildCause;
  readonly varName?: DestBuildVar;
  readonly stsFailureClass?: StsFailureClass;
  readonly doStatus?: number;
  constructor(cause: DestBuildCause, message: string, opts?: { varName?: string; stsFailureClass?: StsFailureClass; doStatus?: number }) {
    super(message);
    this.name = "DestBuildError";
    this.buildCause = cause;
    // The allow-list gate is applied AT CONSTRUCTION as well as at the applier, so a non-vocabulary label never
    // even exists on the error object the run path later reads.
    if (typeof opts?.varName === "string" && DEST_BUILD_VAR_SET.has(opts.varName)) this.varName = opts.varName as DestBuildVar;
    if (opts?.stsFailureClass !== undefined && STS_FAILURE_CLASS_SET.has(opts.stsFailureClass)) this.stsFailureClass = opts.stsFailureClass;
    if (typeof opts?.doStatus === "number" && Number.isFinite(opts.doStatus)) this.doStatus = Math.min(999, Math.max(0, Math.trunc(opts.doStatus)));
  }
}

/** The redaction-safe evidence ONE build fault yields. Closed enums + a clamped status. */
export interface DestBuildFault {
  readonly cause: DestBuildCause;
  readonly varName?: DestBuildVar;
  readonly stsFailureClass?: StsFailureClass;
  readonly doStatus?: number;
}

/**
 * destBuildFaultOf classifies a CAUGHT construction error into its build evidence. It matches on the TYPE (a
 * DestBuildError raised at the throw site), never on the message text: the message can embed an endpoint, a
 * bucket or a region, and this classifier must never be the thing that reads it. An UNTAGGED throw yields the
 * residual "other" cause -- honest, and never a guess made from free text.
 *
 * @param e - the thrown value.
 * @returns the closed evidence.
 */
export function destBuildFaultOf(e: unknown): DestBuildFault {
  if (!(e instanceof DestBuildError) || !DEST_BUILD_CAUSE_SET.has(e.buildCause)) return { cause: "other" };
  return {
    cause: e.buildCause,
    ...(e.varName !== undefined ? { varName: e.varName } : {}),
    ...(e.stsFailureClass !== undefined ? { stsFailureClass: e.stsFailureClass } : {}),
    ...(e.doStatus !== undefined ? { doStatus: e.doStatus } : {}),
  };
}

/**
 * DestBuildHealth is the STANDING record (G137). The field a coarse run error can never carry is failingSinceAt:
 * "every backup has been failing to even construct its destination since 03:14 on Tuesday" is the whole answer to
 * the ticket, and it is unrecoverable after the fact from run rows alone.
 */
export interface DestBuildHealth {
  readonly lastAt: number; // epoch ms of the most recent BUILD attempt (ok or failed)
  readonly lastOutcome: "ok" | "failed";
  readonly failingSinceAt?: number; // epoch ms the destination FIRST failed to build in the current failing streak; cleared by a successful build
  readonly lastCause?: DestBuildCause;
  readonly lastVarName?: DestBuildVar;
  readonly lastStsFailureClass?: StsFailureClass;
  readonly lastDoStatus?: number;
  readonly consecutiveFailures: number;
  readonly causes: Record<string, number>; // closed cause -> count
  readonly stsClasses: Record<string, number>; // closed STS class -> count (G136)
}

/**
 * The scheduler DO storage key the standing DestBuildHealth record lives under. The DO's support-diag routes
 * read the prior record at this key, fold one posted outcome in through applyDestBuildHealth and write it
 * back, so the writer and the pack read agree on one key rather than repeating a literal.
 */
export const DEST_BUILD_HEALTH_KEY = "diag:destbuild";
const DEST_BUILD_COUNT_CAP = 1_000_000_000;

/**
 * applyDestBuildHealth folds ONE build outcome into the standing record. PURE, and the SINGLE REDACTION
 * CHOKEPOINT for this aggregate: an out-of-vocabulary cause / var name / STS class is DROPPED (never coerced,
 * never carried as text), the status is clamped, and NOTHING else on the posted body is read -- so a raw error
 * message, an endpoint, a bucket, a role ARN or a credential structurally cannot enter the record even if a
 * future call site posted one.
 *
 * A SUCCESSFUL build clears failingSinceAt and the consecutive count (the destination is healthy again) but
 * KEEPS the cumulative counters, so a flapping destination is still legible.
 *
 * @param prior - the stored record, if any.
 * @param posted - the posted outcome (untrusted): {ok, cause, varName, stsFailureClass, doStatus}.
 * @param now - the DO clock (injected, so the validator is deterministic).
 * @returns the new record.
 */
export function applyDestBuildHealth(prior: DestBuildHealth | undefined, posted: unknown, now: number): DestBuildHealth {
  const base: DestBuildHealth = prior ?? { lastAt: 0, lastOutcome: "ok", consecutiveFailures: 0, causes: {}, stsClasses: {} };
  const p = (typeof posted === "object" && posted !== null ? posted : {}) as Record<string, unknown>;
  if (p.ok === true) {
    return { lastAt: now, lastOutcome: "ok", consecutiveFailures: 0, causes: { ...base.causes }, stsClasses: { ...base.stsClasses } };
  }
  const cause: DestBuildCause = typeof p.cause === "string" && DEST_BUILD_CAUSE_SET.has(p.cause) ? (p.cause as DestBuildCause) : "other";
  const varName = typeof p.varName === "string" && DEST_BUILD_VAR_SET.has(p.varName) ? (p.varName as DestBuildVar) : undefined;
  const sts = typeof p.stsFailureClass === "string" && STS_FAILURE_CLASS_SET.has(p.stsFailureClass) ? (p.stsFailureClass as StsFailureClass) : undefined;
  const doStatus = typeof p.doStatus === "number" && Number.isFinite(p.doStatus) && p.doStatus > 0 ? Math.min(999, Math.trunc(p.doStatus)) : undefined;
  const causes = { ...base.causes };
  causes[cause] = Math.min(DEST_BUILD_COUNT_CAP, (causes[cause] ?? 0) + 1);
  const stsClasses = { ...base.stsClasses };
  if (sts !== undefined) stsClasses[sts] = Math.min(DEST_BUILD_COUNT_CAP, (stsClasses[sts] ?? 0) + 1);
  return {
    lastAt: now,
    lastOutcome: "failed",
    // The failing streak starts at the FIRST failure after a healthy build (or continues an existing streak).
    failingSinceAt: base.lastOutcome === "failed" && base.failingSinceAt !== undefined ? base.failingSinceAt : now,
    lastCause: cause,
    ...(varName !== undefined ? { lastVarName: varName } : {}),
    ...(sts !== undefined ? { lastStsFailureClass: sts } : {}),
    ...(doStatus !== undefined ? { lastDoStatus: doStatus } : {}),
    consecutiveFailures: Math.min(DEST_BUILD_COUNT_CAP, base.consecutiveFailures + 1),
    causes,
    stsClasses,
  };
}
