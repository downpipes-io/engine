import type { Destination } from "../dest/types.ts";
import { integrityCategoryOf } from "../format/integrity-error.ts";
import { CANARY_NAMESPACE_PREFIX, type CanaryAilingCause, type CanaryAspectResult, type CanaryCheckResult } from "./types.ts";

// Small pure helpers and the result/cleanup plumbing for the canary cycle, factored out of
// cycle.ts so the flight itself reads as named steps. Behaviour is identical to the originals.

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// byteDelta counts how many bytes differ between two arrays (the tail of the longer counts as
// strayed), so the dead reason can say precisely how far the data drifted.
export function byteDelta(a: Uint8Array, b: Uint8Array): number {
  const min = Math.min(a.length, b.length);
  let d = Math.abs(a.length - b.length);
  for (let i = 0; i < min; i++) if (a[i] !== b[i]) d++;
  return d;
}

// nowIso renders the millisecond RFC 3339 stamp the run pipeline uses.
export function nowIso(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export function reqEnv(v: string | undefined, name: string): string {
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
}

// classifyReadFailure maps a thrown read-back error to (aspect, dead?) without leaking the raw
// message. A signature / integrity / freshness verification failure on the canary's OWN
// freshly-written archive is a real drift (dead, evacuate); an object-missing or transport
// fault stopped the check completing (ailing).
//
// THE TYPED CATEGORY IS READ FIRST, and here that is not a tidy-up, because `dead` is an ACTION rather
// than a sentence: it fires the canary-dead page, which cron/notify-passes.ts documents as one that is
// never re-attempted, and it rolls a self-update back (admin/update-types.ts decideKeep).
//
// The category distinguishes "the check found a rollback" from "the check could not run": reader.ts
// raises freshnessUnverifiableError when the anti-rollback check COULD NOT RUN, which is an
// availability fault about ONE destination (ailing), not a data-integrity death on the canary's own
// freshly-written archive.
//
// A check that RAN and found a rollback, and any integrity failure, stays a death. format-unsupported is
// also a death: the canary reads back an archive this same build has just written, so a build that
// cannot read its own writer is not a transport problem.
export function classifyReadFailure(e: unknown): { aspect: "read-signature" | "runlog-freshness"; dead: boolean; detail: string } {
  const category = integrityCategoryOf(e);
  if (category === "freshness-unverifiable") {
    return { aspect: "runlog-freshness", dead: false, detail: "the RUNLOG freshness check could not run against this destination" };
  }
  if (category === "freshness") {
    return { aspect: "runlog-freshness", dead: true, detail: "the RUNLOG entry did not verify fresh and chained" };
  }
  if (category === "integrity") {
    return { aspect: "read-signature", dead: true, detail: "a manifest signature or record hash did not verify" };
  }
  if (category === "format-unsupported") {
    return { aspect: "read-signature", dead: true, detail: "this build could not read the archive format it has just written" };
  }
  // Below here the throw carried no category: a store fault, a runtime error, a non-Error rejection. The
  // nets are unchanged and remain the answer for those, including the fail-closed default.
  const message = e instanceof Error ? e.message : String(e);
  if (/RUNLOG|freshness|latest run|stale|rollback|below the min/i.test(message)) {
    return { aspect: "runlog-freshness", dead: true, detail: "the RUNLOG entry did not verify fresh and chained" };
  }
  if (/signature|key commitment|hash|Merkle|recipient|manifest|plaintext hash|capsule/i.test(message)) {
    return { aspect: "read-signature", dead: true, detail: "a manifest signature or record hash did not verify" };
  }
  if (/is missing|status 404/i.test(message)) {
    return { aspect: "read-signature", dead: false, detail: "an archive object was missing on read-back" };
  }
  if (/status \d/i.test(message)) {
    return { aspect: "read-signature", dead: false, detail: "the destination refused the read-back" };
  }
  // Fail closed: a read-back failure that matches none of the transport patterns above (object
  // missing, an HTTP status) is treated as a real integrity death on the canary's own freshly
  // written archive until proven a transport fault, so an unrecognised message still raises the
  // evacuation alert rather than degrading quietly to ailing.
  return { aspect: "read-signature", dead: true, detail: "the read-back failed verification for an unrecognised reason" };
}

// finalise assembles the result from the accumulated aspects and the dominant outcome. ailingCause on
// the override is threaded straight onto the result: it is set only by the specific cycle.ts call sites
// that pass one, so a "pending" override (no destination configured yet) and the dead/alive falls
// below never carry a cause.
export function finalise(aspects: CanaryAspectResult[], destinationId: string | null, startMs: number, override?: { status: "ailing" | "pending"; reason: string; ailingCause?: CanaryAilingCause }): CanaryCheckResult {
  const durationMs = Date.now() - startMs;
  if (override) {
    // exactOptionalPropertyTypes: an absent cause must OMIT the key, never assign it the value
    // undefined, so the conditional spread mirrors the same fold pattern scheduler-do-canary.ts uses.
    return { status: override.status, durationMs, destinationId, aspects, byteDelta: null, deadReason: null, ...(override.ailingCause ? { ailingCause: override.ailingCause } : {}) };
  }
  const dead = aspects.find((a) => a.outcome === "fail");
  if (dead) {
    return { status: "dead", durationMs, destinationId, aspects, byteDelta: null, deadReason: `${dead.key}: ${dead.detail}` };
  }
  return { status: "alive", durationMs, destinationId, aspects, byteDelta: 0, deadReason: null };
}

// cleanup deletes a prior flight's whole _CANARY/runs/<id>/ cell, best-effort. It lists through
// the BASE destination (unprefixed) so it sees the real namespaced keys, and swallows every
// error: a failed cleanup never fails a flight (the next flight retries, and the residue is tiny).
export async function cleanup(baseDest: Destination, cleanupRunId: string | null): Promise<void> {
  if (!cleanupRunId) return;
  try {
    const keys = await baseDest.list(`${CANARY_NAMESPACE_PREFIX}${cleanupRunId}/`);
    for (const key of keys) await baseDest.delete(key).catch(() => {});
  } catch {
    // Best-effort: leave the residue for the next flight to clear.
  }
}
