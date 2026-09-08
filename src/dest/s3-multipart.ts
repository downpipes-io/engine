import type { DestIo } from "./dest-io.ts";

/**
 * Multipart sizing: a streamed body past MULTIPART_THRESHOLD uploads as
 * 32 MiB parts, so a maximal sealed segment (just over 1 GiB) is ~33 parts and never
 * buffered whole. 32 MiB sits at the top of the contract's 16-32 MiB guidance: large
 * enough that a 1 GiB segment fits comfortably inside an invocation's subrequest budget,
 * small enough that one part buffers harmlessly within the isolate memory limit. Below
 * the threshold a single length-known PUT is simpler and cheaper (one subrequest), and
 * is byte-identical on the wire to what multipart would have assembled.
 *
 * PART_SIZE is the EXACT size every part but the last is carved to (S3 requires every
 * non-final part to be at least 5 MiB, so a uniform carve is the simplest way to comply).
 */
export const PART_SIZE = 32 * 1024 * 1024;
/**
 * MULTIPART_THRESHOLD is the size at which putStream switches from a single buffered PUT to a
 * multipart upload. It is compared against the SEALED bound (sealedSegmentLength of the plaintext
 * size), not the plaintext size, and a body whose size the caller does not declare always takes the
 * multipart path because there is no bound to compare. It happens to equal PART_SIZE, so a body that
 * just crosses it uploads as two parts, but the two are separate knobs: one sizes the switch, the
 * other sizes the parts.
 */
export const MULTIPART_THRESHOLD = 32 * 1024 * 1024;

/**
 * MULTIPART_RETRY_ATTEMPTS bounds the per-step retry inside a multipart upload (initiate,
 * each part, complete). Retrying a single part on a transient 5xx/429 is what makes a
 * 33-part upload survivable; retrying the WHOLE upload from the caller would re-send a
 * gigabyte. This is deliberately local to the destination (the data path's own retry in
 * seal/retry.ts covers single-call ops at the slice layer).
 *
 * It counts ATTEMPTS, not retries: 3 means one initial call and at most two re-issues. A fault the
 * step does not classify as transient throws immediately without consuming the remaining attempts.
 */
export const MULTIPART_RETRY_ATTEMPTS = 3;

/**
 * MULTIPART_MAX_BACKOFF_MS caps a single multipart-step backoff sleep so honouring a large Retry-After
 * (or a deep exponential step) cannot blow the slice's wall budget; a throttle that needs longer than
 * this is carried across invocations by the run's own resume, exactly as the slice-layer retry does
 * (it mirrors seal/retry.ts MAX_RETRY_SLEEP_MS, kept local to avoid a dest -> seal layering import).
 *
 * The cap is applied LAST, after the store's Retry-After has already won over the jittered exponential
 * step, so a store asking for a minute is waited on for 8 seconds and then re-tried anyway.
 */
export const MULTIPART_MAX_BACKOFF_MS = 8_000;

/**
 * parseRetryAfterMs reads an HTTP Retry-After header into milliseconds: delta-seconds ("30") or an
 * HTTP-date. Returns null when absent or unparseable, so the caller falls back to jittered backoff.
 *
 * An HTTP-date already in the past, or a negative delta, clamps to 0 rather than going negative, so a
 * stale header can never shorten a backoff below the caller's own jittered floor. PURE apart from the
 * Date.now() reading the HTTP-date form needs.
 */
export function parseRetryAfterMs(value: string | null): number | null {
  if (!value) return null;
  const secs = Number(value.trim());
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(value);
  return Number.isFinite(when) ? Math.max(0, when - Date.now()) : null;
}

/**
 * retryAfterMsOf reads the server-requested delay a multipart error carried (attached by throttleError
 * on a 503/429). Returns null when absent. Pure; used by multipartStep.
 *
 * It accepts any value, including null and a non-Error throw, and re-validates the property rather than
 * trusting it: a non-finite or negative retryAfterMs reads as absent. So a caught value from anywhere in
 * the multipart path can be passed straight in.
 */
export function retryAfterMsOf(e: unknown): number | null {
  const v = (e as { retryAfterMs?: unknown } | null)?.retryAfterMs;
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null;
}

/**
 * throttleError builds the "<label>: status NNN" error a failed multipart step throws, attaching the
 * parsed Retry-After (ms) when the store signalled backpressure (503 SlowDown / 429) so multipartStep
 * waits the server-requested time before re-issuing instead of blindly re-hitting a throttling store.
 * A non-throttle status carries no delay (the existing transient classification still decides whether to
 * retry at all), so this is purely additive: a store that sends no Retry-After behaves exactly as before.
 *
 * It RETURNS the error rather than throwing it, so every call site reads `throw throttleError(...)`. The
 * "status NNN" message shape is load-bearing: multipartStep decides whether a fault is transient by
 * matching that text, so changing the wording would silently turn retries off. The optional io is the
 * degradation counter set; passing it lets an unreadable Retry-After be counted, and omitting it is the
 * behaviour every in-memory test double relies on.
 */
export function throttleError(label: string, resp: Response, io?: DestIo): Error {
  const e = new Error(`${label}: status ${resp.status}`) as Error & { retryAfterMs?: number };
  if (resp.status === 503 || resp.status === 429) {
    const raw = resp.headers.get("retry-after");
    const ra = parseRetryAfterMs(raw);
    if (ra !== null) e.retryAfterMs = ra;
    // The store TOLD us how long to wait and we could not read it (G186): the backoff silently degrades to a
    // blind jittered guess against a destination that is already pushing back. Counted, never the header
    // VALUE -- a count is what says "this store's Retry-After format is one we do not parse". The optional io
    // means every existing caller (and the in-memory doubles) behaves exactly as before.
    else if (raw !== null) io?.note("retryAfterUnparseable");
  }
  return e;
}
