// A NAMED failure for "the source binding is truthy but the underlying resource is gone".
//
// The classic silent trap: a deploy carries the KV/R2/D1 binding (so env[binding] is present and
// preflight's source-bindings probe is green) but the namespace/bucket/database it points at was
// DELETED at Cloudflare. Nothing notices until the crawl issues its first real call, which throws a
// raw platform error that coarseRunError() folds into the generic "run failed". The operator is left
// guessing whether they misconfigured a binding, lost a resource, or hit a destination outage.
//
// The fix is a cheap LIVENESS PROBE (KV list({limit:1}) / D1 SELECT 1 / R2 list({limit:1})) run
// before the crawl, plus this dedicated error class so the failure is named, not generic, and carries
// the actionable triple: which source TYPE, which BINDING/resource identifier, and WHY (a binding the
// engine cannot drive vs a resource that no longer answers). No value is ever read by the probe.

// SourceLivenessKind classifies WHY a liveness probe failed, so the operator knows which lever to pull:
//   "misconfigured" - the bound object is the wrong shape (no list()/prepare()); the binding points at
//                     something the engine cannot drive as this source type. Fix the binding/deploy.
//   "deleted"       - the probe answer proves the resource is gone (ABSENCE_PROOF below). Re-create it
//                     (or re-point the source) and re-attach.
//   "unavailable"   - the probe call threw for another reason (a timeout, a 5xx, a 429, a network fault,
//                     or an answer that proves nothing); the resource may still exist. Retry.
export type SourceLivenessKind = "misconfigured" | "deleted" | "unavailable";

import { classifySourceFaultStatus, recordSourceFatal, type SourceFaultStatusClass } from "./source-fault-ledger.ts";

// SourceResourceMissingError is thrown by a source adapter's liveness probe when the binding is present
// but the resource did not answer the probe. It carries the structured fields a preflight surface or a
// status line renders WITHOUT re-parsing the message. Its MESSAGE depends on the kind, because the run row
// is derived from the message (coarseRunError):
//   - "deleted" and "misconfigured" begin with "source resource missing", the class that tells the operator
//     to re-create or re-point the resource. Only a probe answer that PROVES absence is "deleted".
//   - "unavailable" begins with "source probe failed". The resource may still exist (a timeout, a 5xx, a
//     429, a network fault), so the run row reads the transient source class "source read error".
export class SourceResourceMissingError extends Error {
  readonly sourceType: string;
  readonly resource: string; // the binding name / native id the adapter holds (an operator label, not archive data)
  readonly kind: SourceLivenessKind;
  // faultClass is the CLOSED transport verdict behind this liveness failure. `kind`
  // already says WHAT the engine concluded (deleted / unavailable / misconfigured), but the run row could not
  // say what the platform actually ANSWERED, so a transient outage mislabelled "deleted" would have support
  // advising a customer to re-create a bucket that still exists, with no way to check. This carries the
  // status class the classifier saw, alongside the verdict it drew from it. Never the platform's message.
  readonly faultClass: SourceFaultStatusClass;

  // `cause` is the probe's own throw, when there is one. It is the standard Error cause, so it is not
  // enumerable and a JSON dump of this error does not carry it. The preflight reads it ONLY to select a
  // closed class for an unproven fault (classifyProbeError); nothing logs or stores it.
  constructor(sourceType: string, resource: string, kind: SourceLivenessKind, detail?: string, faultClass?: SourceFaultStatusClass, cause?: unknown) {
    super(
      kind === "unavailable"
        ? `source probe failed: ${sourceType} resource ${resource} ${kindPhrase(kind)}${detail ? ` (${detail})` : ""}`
        : `source resource missing: ${sourceType} resource ${resource} is ${kindPhrase(kind)}${detail ? ` (${detail})` : ""}`,
      cause !== undefined ? { cause } : undefined,
    );
    this.name = "SourceResourceMissingError";
    this.sourceType = sourceType;
    this.resource = resource;
    this.kind = kind;
    // A misconfigured binding is a SHAPE fault (the bound object is not the source type it claims to be); a
    // classified probe fault passes its own status class in.
    this.faultClass = faultClass ?? (kind === "misconfigured" ? "shape" : "other");
    // Record the run-fatal fault at the exact throw site (this error IS the run's fatal outcome: the run
    // path calls probeLiveness() because it WANTS the throw). Stage "probe" separates "the resource is gone"
    // from "the list worked but the reads failed", which the coarse run-row class alone could never do.
    // Coarse classes only: the source type is a product token, the resource NAME is never recorded here.
    recordSourceFatal({ sourceType, statusClass: this.faultClass, stage: "probe" });
  }
}

function kindPhrase(kind: SourceLivenessKind): string {
  switch (kind) {
    case "misconfigured":
      return "not drivable as this source type (binding misconfigured)";
    case "deleted":
      return "gone (resource deleted)";
    case "unavailable":
      return "did not answer the liveness probe (not proven missing; it may be a transient fault)";
  }
}

// ABSENCE_PROOF is, per source type, the probe answer that PROVES the resource is gone. Only this makes a
// probe fault "deleted" (re-create the resource). Anything else (a timeout, a 5xx, a 429, a network fault,
// an answer not listed here) is "unavailable": the resource may still exist, and the run row must not say
// it is missing. The patterns are the vendor's own codes and texts:
//   r2: error 10006 NoSuchBucket, "The specified bucket does not exist" (developers.cloudflare.com/r2/api/
//       error-codes). The binding answered "list: The specified bucket does not exist. (10006)" for a deleted
//       source bucket on a fresh estate on 28 Sep 2026 (its run-row cause digest was fd070eff6737).
//   kv: error 10041, "No KV namespace found with ID <id>" (the answer for a deleted namespace in
//       github.com/cloudflare/wrangler-legacy/issues/1441).
//   d1: error 7404 "the database cannot be found" and error 10181 "the D1 database UUID could not be found"
//       (github.com/cloudflare/developer-platform/issues/69). The D1 debug page lists no binding text for a
//       deleted database, so only these codes and texts count.
// A source type with no entry (and the "unknown" of probeSourceLiveness) can never be proven missing.
const ABSENCE_PROOF: Readonly<Record<string, RegExp>> = {
  r2: /\b10006\b|The specified bucket does not exist/i,
  kv: /\b10041\b|No KV namespace found with ID/i,
  d1: /\b7404\b|\b10181\b|database cannot be found|D1 database UUID could not be found/i,
};

// classifyLivenessFault maps a raw platform throw from a probe call into a SourceResourceMissingError:
// "deleted" only when the answer proves absence (ABSENCE_PROOF), else "unavailable". The raw text is NOT
// carried into the error detail (it can be a verbose platform string); only the classification is kept,
// so the run-path log (digested by redactedRunError) and any preflight evidence stay clean.
export function classifyLivenessFault(sourceType: string, resource: string, e: unknown): SourceResourceMissingError {
  if (e instanceof SourceResourceMissingError) return e;
  const m = e instanceof Error ? e.message : String(e);
  const proof = ABSENCE_PROOF[sourceType];
  const kind: SourceLivenessKind = proof?.test(m) === true ? "deleted" : "unavailable";
  // Keep the platform's own transport verdict (a closed class) beside the engine's kind, so the pack can
  // separate "404, the resource really is gone" from "a 5xx/network fault we conservatively called unavailable".
  return new SourceResourceMissingError(sourceType, resource, kind, undefined, classifySourceFaultStatus(e), e);
}

// LivenessProbe is the optional capability a binding-backed source (KV/R2/D1) implements: ONE cheap
// read that proves the resource still exists. It returns normally when live and throws a
// SourceResourceMissingError when the binding is present but the resource is gone. It never reads a
// value (list({limit:1}) / SELECT 1), so it adds at most one trivial subrequest to the run.
export interface LivenessProbe {
  probeLiveness(): Promise<void>;
}

// hasLivenessProbe reports whether a source exposes the liveness capability, so the run path and the
// preflight can probe where supported and degrade cleanly (skip, not fail) where it is absent
// (secrets/API sources have no single cheap "is the resource there" call).
export function hasLivenessProbe(s: unknown): s is LivenessProbe {
  return typeof (s as { probeLiveness?: unknown }).probeLiveness === "function";
}

// SourceLivenessResult is the structured outcome a detect-and-alert surface (preflight) consumes
// without throwing: a live resource, a missing one (with the named error), or a source that cannot be
// probed cheaply (skipped, reported as unproven rather than failed).
export type SourceLivenessResult =
  | { status: "live" }
  | { status: "missing"; error: SourceResourceMissingError }
  | { status: "unprobeable" };

// probeSourceLiveness runs the liveness probe if the source supports it and folds the outcome into a
// structured result, so a caller that wants to ALERT (not crash) on a dead resource never has to catch.
// The run path calls probeLiveness() directly (it WANTS the throw); this is the detect-and-alert form.
export async function probeSourceLiveness(source: unknown): Promise<SourceLivenessResult> {
  if (!hasLivenessProbe(source)) return { status: "unprobeable" };
  try {
    await source.probeLiveness();
    return { status: "live" };
  } catch (e) {
    return { status: "missing", error: e instanceof SourceResourceMissingError ? e : classifyLivenessFault("unknown", "unknown", e) };
  }
}
