import { concat } from "../crypto/bytes.ts";

/**
 * xmlDecode reverses the minimal XML entity escaping a ListObjectsV2 response applies to an
 * object key (a key may legitimately contain & < >). The archive's own keys are hex/ULID and
 * fixed prefixes (seg/, run/, _RECOVERY/), so in practice no entity appears, but decode
 * defensively so a key with a special character round-trips to the exact stored key the prune
 * then deletes. Order matters: &amp; last, so a literal "&lt;" in a key is not double-decoded.
 *
 * It handles exactly the five forms S3 emits: &lt; &gt; &quot; &#39; &amp;. The apostrophe arrives as
 * the numeric reference &#39;, not as &apos;, so &apos; and every other named or numeric reference is
 * left as written. That is the safe reading: the prune deletes the literal key it was handed rather
 * than one this function guessed at.
 */
export function xmlDecode(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}

/**
 * drainBounded reads a stream fully into one byte array, throwing if the running total would
 * exceed limit. The bound is defence in depth: the caller bounds a sealed segment by its
 * exact sealed length before draining, so a stream that overruns here is a bug, and we
 * fail loud rather than buffering an unbounded body into the isolate.
 *
 * The check is on bytes ACTUALLY read, so it holds for a chunked body and for one whose declared
 * length understates it. On overrun it releases the reader lock and throws naming key, which is a
 * caller-supplied label for the message and not necessarily an object key. The stream is left
 * un-cancelled, so a caller that needs the connection closed must do that itself.
 */
export async function drainBounded(body: ReadableStream<Uint8Array>, limit: number, key: string): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.length;
    if (total > limit) {
      reader.releaseLock();
      throw new Error(`segment ${key} stream exceeds its ${limit}-byte sealed bound`);
    }
    parts.push(value);
  }
  return concat(...parts);
}

/**
 * drainResponseBounded is the same bound applied to a fetch Response instead of a raw stream: every
 * destination response read (get/list/probe/error-body) goes through this so a store that omits
 * Content-Length (chunked) or advertises a value that understates its real body is caught by the ACTUAL
 * byte count as it streams in, never by trusting the (omittable, lie-able) header (V12.3.1). A response
 * with no body (e.g. a HEAD reply, or a 204/304) drains to nothing rather than throwing -- there is
 * nothing to bound.
 *
 * label names the read in the overrun message; it is free text for diagnosis, not a key. An over-cap
 * body throws part way through, so the caller gets nothing rather than a truncated prefix.
 */
export async function drainResponseBounded(resp: Response, limit: number, label: string): Promise<Uint8Array> {
  if (!resp.body) return new Uint8Array(0);
  return drainBounded(resp.body, limit, label);
}
