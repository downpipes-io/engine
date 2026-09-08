// classify.ts -- the ONE shared destination-fault classifier (adaptive-dest-backpressure Layer 1a).
//
// Every credentialed call to a destination ends in exactly one of five outcomes, and which one it is
// must be decided by an explicit, single function -- never by which call site happened to wrap a retry.
// This module promotes the de-facto rules (previously the regex inside seal/retry.ts isTransient) into a
// named classifier consumed by withRetry, the RUNLOG read-modify-write, the buffered seal loop, and the
// inline-throttle routing in seal/runstate.ts. A throttle/transient fault is RETRYABLE; an auth/permanent
// fault FAILS LOUD and must never be retried, never clamped, never park-and-resumed (integrity != avail-
// ability, Section 9 of the design). The classifier's DEFAULT for an error it cannot read is "permanent":
// we never retry-loop on a fault we do not understand.
//
// This is a LEAF module (zero engine imports) so it can be shared by both dest/* and seal/* without a
// circular dependency: seal/retry.ts imports from here, never the reverse.

/**
 * The five outcomes a credentialed destination call can end in. "throttle" and "transient" are the RETRYABLE
 * pair; "auth" and "permanent" fail loud and are never retried, clamped or park-and-resumed; "ok" is the
 * success class Layer 2's AIMD recovers its rate on. A fault the classifier cannot read lands on "permanent"
 * rather than a retryable class, so an unreadable fault stops a run instead of looping on it.
 */
export type DestFault = "throttle" | "transient" | "auth" | "permanent" | "ok";

/**
 * classifyDestStatus maps an HTTP status to a fault class. retryAfterMs is accepted for signature
 * stability (Layer 2's per-bucket AIMD uses it for clamp DEPTH); it does not change the CLASS here -- a
 * 503 is a throttle whether or not the store volunteered a Retry-After.
 *
 *   429, 503                  -> throttle   (retry; honour Retry-After; AIMD clamp at Layer 2)
 *   408 + any other 5xx       -> transient  (retry; a 500/502/504 is a server blip, not pushback)
 *   401, 403                  -> auth       (FAIL LOUD; a credential/permission fault never self-heals)
 *   2xx                       -> ok         (AIMD recover)
 *   400, 404, 405, 411, 413,  -> permanent  (FAIL LOUD; e.g. WORM Content-MD5 = 400; a 404 on a
 *   422, other 4xx                           conditional path that expected the object is terminal)
 *
 * A 1xx or a nonsense status falls through to "permanent" with the rest of the residual, which is the
 * fail-loud side of the default.
 */
export function classifyDestStatus(status: number, _retryAfterMs?: number): DestFault {
  if (status === 429 || status === 503) return "throttle";
  if (status === 401 || status === 403) return "auth";
  if (status >= 200 && status < 300) return "ok";
  if (status === 408) return "transient";
  if (status >= 500 && status < 600) return "transient";
  // Every other 4xx (400/404/405/411/413/422/…) is a request the store will reject identically on retry.
  return "permanent";
}

// retryAfterMsOf reads a server-requested delay an error carried (a 429 the API client tagged as
// err.retryAfterMs). Kept here as a tiny self-contained copy so this module stays import-free; seal/retry
// keeps its own copy for the withRetry backoff maths. An error tagged with a Retry-After is, by
// definition, a throttle the server asked us to back off from.
function retryAfterMsOf(e: unknown): number | null {
  const v = (e as { retryAfterMs?: unknown } | null)?.retryAfterMs;
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null;
}

// statusOnError reads the HTTP status a TYPED fault carries ON THE OBJECT: DestStatusError (dest/types.ts)
// and CfApiError (sources/cf-config-core.ts) both stamp the status the response actually answered with, read
// off the response at the throw site. This is the AUTHORITATIVE fact, and it is checked before any text.
//
// WHY IT HAD TO BE. CfApiError's message is built as the joined Cloudflare error text `|| \`HTTP ${status}\``
// (cf-config-core.ts callEnvelope), so the status reaches the message ONLY when Cloudflare returned no error
// text at all. Whenever Cloudflare DID answer with prose, which is the common case for a 4xx, the status
// vanished from the message and the retry decision fell to NETWORK_RE over Cloudflare's own wording, then to
// the fail-loud default. Both directions were wrong and both are production-reachable through withRetry:
// a 503 whose prose reads "Service temporarily unavailable" matched nothing and was NOT retried, so a
// Cloudflare blip failed a backup that should have ridden it out; a 400 whose prose happens to contain
// "connection" or "network" matched the network arm and WAS retried, six attempts deep, per surface.
//
// Read STRUCTURALLY, for the same reason retryAfterMsOf is: this module is a LEAF (zero engine imports) so
// dest/* and seal/* can both share it without a cycle. Bounded to a real HTTP status range, so a `.status`
// that is not one (a socket close code, a string, some other library's enum) can never be read as one.
function statusOnError(e: unknown): number | null {
  const v = (e as { status?: unknown } | null)?.status;
  return typeof v === "number" && Number.isInteger(v) && v >= 100 && v <= 599 ? v : null;
}

// statusInMessage extracts the HTTP status the dest/API layers stamp into a thrown message: the dest
// layer throws "PUT <key>: status NNN" / "GET <key>: status NNN"; the CF account-API clients throw
// "... HTTP NNN". The space anchor matches the historical isTransient regex exactly, so a bare digit in a
// key name (e.g. seg/3f/…) is never mistaken for a status. It is the FALLBACK for an untyped throw; a fault
// that carries its status as a field is decided by statusOnError above and never reaches here.
function statusInMessage(m: string): number | null {
  const match = /(?:status|HTTP) (\d{3})/.exec(m);
  return match ? Number(match[1]) : null;
}

// NETWORK_RE matches the runtime's connection-fault vocabulary (a TypeError "fetch failed", a timeout,
// etc.). These are transient by nature -- the request never reached the store. Identical to the historical
// isTransient network regex, so re-pointing isTransient at this classifier changes no current behaviour.
const NETWORK_RE = /fetch failed|network|timed? ?out|internal error|too many requests|connection/i;

/**
 * classifyDestError reduces a thrown fault to its class. A status the error carries as a FIELD decides it
 * first (the authoritative fact, read off the response at the throw site); failing that, a status embedded
 * in the message; failing that, a Retry-After tag means throttle, a network shape means transient, and
 * anything else is permanent (fail loud -- we do not retry a fault we cannot read).
 *
 * The structured-before-prose order is load-bearing, not a tidy-up. Matching a regex against the provider's
 * own error wording, while the status sat unread on the object, made the retry decision a function of what
 * Cloudflare happened to call the fault: see statusOnError for the two failures that produced, one of which
 * silently gave up on a retryable 5xx.
 *
 * It takes `unknown` and never throws, so a non-Error rejection is classified on its String() form rather
 * than crashing the caller. It DELEGATES to classifyDestErrorArm, which reports the same class plus WHICH
 * branch decided it; the two used to be two copies of one decision order held in step by hand, and the
 * Object-Lock override below is exactly the kind of arm that would have been added to one and not the other.
 */
export function classifyDestError(e: unknown): DestFault {
  return classifyDestErrorArm(e).fault;
}

/**
 * DestClassifierArm names WHICH branch of classifyDestError decided the class. It is the missing half of a
 * destination-fault diagnosis (G135): "permanent" alone cannot be trusted, because the classifier's DEFAULT
 * for an error whose shape it could not read is ALSO "permanent". Recording the arm separates a real 4xx
 * ("matched-status" / "embedded-status") from a fault we simply could not parse ("default-permanent"), which
 * is the difference between "the store refused you" and "we have no idea what happened".
 *   matched-status       -- a real HTTP status was observed on the response itself.
 *   typed-status         -- the THROWN error carried the status as a field (DestStatusError / CfApiError),
 *                           so the class came from the status the response answered with, not from its text.
 *   embedded-status      -- a status was parsed out of a thrown message ("… status NNN").
 *   matched-retry-after  -- no status, but the error carried a server Retry-After tag (a throttle).
 *   matched-network      -- no status, but the message matched the runtime's connection-fault vocabulary.
 *   default-permanent    -- nothing was readable; the classifier FELL BACK to permanent (fail loud).
 *   object-lock-refusal  -- the throw site read the store's own body and stamped an Object-Lock refusal, and
 *                           the status alone would have made it RETRYABLE. The store's answer is the same
 *                           every time, so this arm records that the retryable reading was overruled by a
 *                           fact the status could not carry, rather than by the status.
 *
 * classifyDestErrorArm returns every member except "matched-status", which is set by the fault ring when it
 * noted a real response rather than a throw. "typed-status" and "embedded-status" are the same quality of fact from two
 * carriers, and keeping them apart is what shows support that a class came from the authoritative field
 * rather than from a string the provider wrote.
 *
 * ADDING A MEMBER HERE IS NOT SELF-CONTAINED: admin/run-fault-records.ts re-declares this vocabulary as a
 * runtime Set and DROPS any fault record whose arm is not in it, so an arm added here and forgotten there
 * makes the fault vanish from the support pack. That list is now pinned to this union by a total Record, so
 * the omission is a compile error rather than a silent hole.
 */
export type DestClassifierArm = "matched-status" | "typed-status" | "embedded-status" | "matched-retry-after" | "matched-network" | "default-permanent" | "object-lock-refusal";

/**
 * classifyDestErrorArm is classifyDestError with its REASONING exposed: the same class, plus the arm that
 * decided it and the HTTP status it read (0 when none was readable). It is the diagnostic twin of
 * classifyDestError and shares its exact decision order, so the two can never disagree.
 *
 * No text from the error is returned: only the class, the closed arm and the status int.
 *
 * @param e - the thrown fault.
 * @returns the fault class, the closed classifier arm, and the status (0 when none).
 */
export function classifyDestErrorArm(e: unknown): { fault: DestFault; arm: DestClassifierArm; status: number } {
  const decided = classifyDestErrorArmByStatus(e);
  // A STAMPED Object-Lock refusal is never retried. R2 answers a lock-bearing PUT to a bucket that is not
  // Object-Lock enabled with 501, which classifyDestStatus reads as a transient server blip, so withRetry
  // spent six attempts per write waiting for a bucket to acquire a property it can only be created with.
  // The bucket will refuse the next attempt identically, for ever.
  //
  // NARROW ON PURPOSE, and this is the whole reason it is not a reclassification of 501. A 501 the engine
  // did not stamp still reads transient, because NotImplemented from a store that was NOT asked for a lock
  // is a different fault with a different answer. And the override only fires on a RETRYABLE reading: the
  // AWS 400 (permanent) and the lock-protected-overwrite 403 (auth) keep the exact class and arm they had,
  // so this adds a case rather than moving one.
  if (isRetryable(decided.fault) && isObjectLockRefusalStamped(e)) return { ...decided, fault: "permanent", arm: "object-lock-refusal" };
  return decided;
}

// isRetryable is the "would this have been retried" predicate the Object-Lock override is gated on. Written
// over the CLASS rather than the status so it cannot drift from withRetry's own isThrottleOrTransient.
function isRetryable(fault: DestFault): boolean {
  return fault === "throttle" || fault === "transient";
}

/**
 * isObjectLockRefusalStamped reads the boolean the throw site put on the error, with the strict === true
 * OBJECT_LOCK_REFUSAL_PROP documents: a foreign object carrying a truthy value of this name must not be able
 * to steer a fault away from the class the status gave it.
 *
 * Exported because the multipart step retries on its OWN message regex rather than through this classifier
 * (its "status NNN" wording is load-bearing for that loop), so it has to be able to ask the same question.
 *
 * @param e - the thrown fault.
 * @returns true when the throw site established an Object-Lock refusal from the store's own body.
 */
export function isObjectLockRefusalStamped(e: unknown): boolean {
  return typeof e === "object" && e !== null && (e as Record<string, unknown>)[OBJECT_LOCK_REFUSAL_PROP] === true;
}

// classifyDestErrorArmByStatus is the status-and-shape half: the historical decision order, unchanged.
function classifyDestErrorArmByStatus(e: unknown): { fault: DestFault; arm: DestClassifierArm; status: number } {
  const typed = statusOnError(e);
  if (typed !== null) return { fault: classifyDestStatus(typed), arm: "typed-status", status: typed };
  const m = e instanceof Error ? e.message : String(e);
  const status = statusInMessage(m);
  if (status !== null) return { fault: classifyDestStatus(status), arm: "embedded-status", status };
  if (retryAfterMsOf(e) !== null) return { fault: "throttle", arm: "matched-retry-after", status: 0 };
  if (NETWORK_RE.test(m)) return { fault: "transient", arm: "matched-network", status: 0 };
  return { fault: "permanent", arm: "default-permanent", status: 0 };
}

/**
 * DEST_DOWN_REASONS is the CLOSED vocabulary for "why is this destination down" (G120). The replication
 * view today collapses EVERY down destination to the literal "unreachable", which sends triage to the wrong
 * side: an expired credential, a WORM refusal, a throttling store and a black-holed endpoint all read the
 * same. These seven classes are the actionable split, and each maps to a different operator action.
 */
export const DEST_DOWN_REASONS = ["auth", "worm-refused", "throttled", "timeout", "network", "tls", "other"] as const;
/**
 * One member of DEST_DOWN_REASONS, as returned by destDownReason and carried in place of the bare string
 * "unreachable". canary/types.ts widens it into CanaryAilingCause, and cron/siem-push-pass.ts holds a TOTAL
 * Record from it to a push failure code, so adding a member there is a compile error rather than a silent
 * hole in the SIEM mapping.
 */
export type DestDownReason = (typeof DEST_DOWN_REASONS)[number];

/**
 * OBJECT_LOCK_REFUSAL_PROP is the name of the boolean property `s3WriteFailure` (dest/s3-worm.ts) stamps on
 * the errors it throws when the RESPONSE BODY said the bucket's own Object-Lock or retention policy refused
 * the write. It is declared here, in the only module that READS it, so the writer and the reader cannot
 * drift apart to two spellings of the same idea.
 *
 * It exists because the message could not carry the fact. `destDownReason` decides the auth arm on the
 * STATUS, and S3 refuses a lock-protected overwrite with a 403, so the credentials answer was returned
 * before any Object-Lock text was consulted. Matching harder on the message was the wrong repair: the
 * message reaching this function has already been through the redaction seam, and reading provider prose
 * for a fact that was structured at the throw site is the defect shape this repo has now found three times.
 * The evidence is the raw body, the body exists only inside `s3WriteFailure`, so the verdict is computed
 * there and travels as a boolean.
 *
 * Read with a STRICT `=== true`. A foreign object carrying a truthy value of this name (a string, a
 * number, a nested error's leaked field) must not be able to steer a fault away from "auth", because
 * "auth" is the answer that tells an operator to go and look at a credential.
 */
export const OBJECT_LOCK_REFUSAL_PROP = "objectLockRefusal";

// WORM_REFUSAL_RE recognises the store REFUSING a write because of Object-Lock/retention (the s3WriteFailure
// hint text and the documented lock error codes). Matched as a boolean only; no body text is forwarded.
// It remains the arm for faults that reach here WITHOUT the stamp, e.g. a non-S3 driver's own refusal text.
const WORM_REFUSAL_RE = /object[- ]lock|InvalidRetentionPeriod|retention/i;
// TLS_RE recognises a transport-security failure (a wrong/expired certificate on the destination endpoint),
// which the network arm would otherwise bury as a generic connection fault.
const TLS_RE = /\btls\b|\bssl\b|certificate|handshake/i;
// TIMEOUT_RE recognises a request that never completed (the driver's own abort bound, or the runtime's).
const TIMEOUT_RE = /timed? ?out|timeout|aborted/i;

/**
 * destDownReason reduces a destination fault to the CLOSED replication reason. It is the vocabulary the
 * per-destination down indicator records instead of the fixed string "unreachable": {auth, worm-refused,
 * throttled, timeout, network, tls, other}. Ordered most-specific-first, so a WORM refusal is not eaten by
 * the generic permanent arm and a TLS failure is not eaten by the generic network arm.
 *
 * The STAMPED Object-Lock verdict is read first, above the auth arm, and it is the only arm that outranks
 * auth. S3 answers a lock-protected overwrite with a 403, so without this the operator was told to go and
 * rotate a credential while the destination's own immutability policy was refusing the write, and rotating
 * a credential cannot clear a retention period. Only a strict boolean stamped by s3WriteFailure from the
 * real response body can take that place; nothing a message says can.
 *
 * Closed classes only: never an S3 error body, an endpoint host or a bucket name.
 *
 * @param e - the thrown destination fault.
 * @returns the closed down-reason class.
 */
export function destDownReason(e: unknown): DestDownReason {
  const m = e instanceof Error ? e.message : String(e);
  const { fault } = classifyDestErrorArm(e);
  if (isObjectLockRefusalStamped(e)) return "worm-refused";
  if (fault === "auth") return "auth";
  if (WORM_REFUSAL_RE.test(m)) return "worm-refused";
  if (fault === "throttle") return "throttled";
  if (TIMEOUT_RE.test(m)) return "timeout";
  if (TLS_RE.test(m)) return "tls";
  if (NETWORK_RE.test(m)) return "network";
  return "other";
}

/**
 * isThrottleOrTransient is the predicate withRetry consumes: retry a throttle or a transient fault, fail
 * loud on auth/permanent. It is a behavioural SUPERSET-equal of the historical isTransient (5xx/429 in
 * the message, a Retry-After tag, or a network shape) so existing retry call sites are unchanged.
 *
 * It reads a THROWN fault, so false means "do not retry this one", never "the call succeeded".
 */
export function isThrottleOrTransient(e: unknown): boolean {
  const c = classifyDestError(e);
  return c === "throttle" || c === "transient";
}

/**
 * isThrottleClass is the NARROW predicate the inline park-and-resume routing (Layer 1c) and the
 * coarseRunError re-order (Layer 1d) use: a THROTTLE specifically (429/503), not a generic transient
 * 5xx. Only a throttle is routed to the patient resume ladder; a transient 5xx that exhausts its retry
 * still fails inline (today's behaviour), and an auth/permanent fault always fails loud.
 *
 * A Retry-After tag on the error also lands here even with no status to read, since a server that asked us
 * to back off has by definition throttled us.
 */
export function isThrottleClass(e: unknown): boolean {
  return classifyDestError(e) === "throttle";
}
