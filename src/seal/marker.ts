// An incompleteness SENTINEL is a record a source adapter emits in place of real bytes when it
// cannot fully capture a resource: a list past its page cap (_truncated), a surface/object the
// token could not read (_unavailable), an oversized blob skipped by the size gate (_skipped), a
// Stream download not yet ready (_pending), a download URL that failed the host allow-list
// (_refused), or a KV/R2 object the LIST returned but that was DELETED before its value could be
// read (_vanished -- a mid-crawl live-source race, SPEC 12.5, WS-P2). The stream/images/artifacts/
// workers/cloudflare-config adapters emit the first five, and the KV/R2 adapters emit _vanished, so a
// partial capture is HONEST in the archive rather than a silent gap, but each one still seals as a
// valid record, so the run otherwise reports a clean "ok" with NO run-level signal that the backup
// is short of the live source. The seal COUNTS them (CheckpointCounts.recordsIncomplete), so the
// completion and the notification can say "completed with N items not fully captured" (R1-1).
//
// CR-04: classification is an ADAPTER ASSERTION, not a content-shape guess. Each emitter above sets
// SourceRecord.markerKind (sources/types.ts) at the exact call site that builds a substitute value in
// place of real bytes, and the seal (slice.ts/pipeline.ts) stamps meta.incompleteMarker from THAT field.
// Restore (restore-apply.ts/restore-plan.ts) then gates its write-skip on the resulting signed manifest
// field (ShardRecord.incompleteMarker), never by re-parsing decrypted bytes. Classifying by the record's
// VALUE BYTES instead (incompleteMarkerKind/isIncompleteMarkerValue below) would make a real customer
// value that happens to be a small JSON object carrying one of the MARKER_KEYS names (e.g.
// `{"_pending":false,"orderId":42}`) indistinguishable from a genuine sentinel and silently dropped on
// restore. incompleteMarkerKind/isIncompleteMarkerValue remain below as a content-shape
// classifier ONLY (used by the format-level round-trip test, validate-incomplete-marker.ts); they are
// NOT consulted by the seal-time stamp or the restore-time write-skip gate, and must never
// be reintroduced as either one's authority.
//
// The sentinel keys mirror the capture-side emitters (grep "_unavailable" across src/sources). The
// restore-side detector (src/admin/media-restore.ts isMarkerValue, which additionally guards a media
// re-upload) is NOT a parallel copy: it delegates to isIncompleteMarkerValue here, so both sides are
// SINGLE-SOURCED on MARKER_KEYS and can never drift to recognise a different set of sentinels. The size
// guard keeps the JSON.parse cheap and rejects real binary outright (a real value almost never parses as
// a small object carrying exactly one of these keys).

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";

export const MARKER_KEYS = ["_truncated", "_unavailable", "_skipped", "_pending", "_refused", "_vanished"] as const;

// VANISHED_MARKER_REASON is the fixed, NO-CUSTODY reason a _vanished sentinel carries. It names the RACE
// (the object was listed but deleted before its value could be read), NEVER anything about the object; the
// object's identity lives in the record NAME, which is protected-class data (encrypted end-to-end in the
// archive, exactly like any real record's name), never in this value.
export const VANISHED_MARKER_REASON = "object was listed but deleted before its value could be read (mid-crawl)";

// vanishedMarkerValue builds the tiny buffered value for a _vanished sentinel RECORD -- the single form BOTH
// the KV and R2 adapters emit for an in-scope object that raced the crawl (listed, then gone at value-read).
// The caller pairs this value with `markerKind: "_vanished"` on the yielded SourceRecord (CR-04: the adapter's
// own assertion, not a content guess), so the seal COUNTS it (recordsIncomplete + incompleteByMarker._vanished
// + the distinct recordsVanished) AND the RESTORE side SKIPS it (via the signed rec.incompleteMarker manifest
// field) -- never writing this marker JSON back as the deleted key's live value, which would silently
// re-create a deleted key with sentinel bytes (data corruption). The value is a fixed reason string ONLY
// (NO-CUSTODY), so a churning source cannot smuggle per-object detail into it.
export function vanishedMarkerValue(): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ _vanished: VANISHED_MARKER_REASON }));
}

// MarkerKey is one closed incompleteness-sentinel key, named so the per-kind maps below read clearly.
export type MarkerKey = (typeof MARKER_KEYS)[number];

// IncompleteByMarker is the PER-MARKER breakdown of a run's incompleteness sentinels (the support pack's
// run row, consumed by the diagnostics-bot): WHICH of the closed MARKER_KEYS the run sealed and how many of
// each. Only NON-ZERO keys are present (an empty object means the run sealed no markers). It is the per-kind
// companion to the aggregate recordsIncomplete, the same shape relation OpCounts (meter.ts) has to the
// subrequest total, and like OpCounts it lives beside its vocabulary (MARKER_KEYS) so the two never drift.
// NO-CUSTODY: it carries the marker KEY identity + an integer count ONLY, never the marker's JSON payload,
// which can hold a free-text reason / record-specific detail (counts, never content; same posture as opCounts).
export type IncompleteByMarker = Partial<Record<MarkerKey, number>>;

// IncompleteIds is the PER-KIND ATTRIBUTION companion to IncompleteByMarker (WS-P1): for each marker kind a
// run sealed, a bounded, deduplicated list of WHICH surface/object was short -- so the support pack can say
// not just "2 surfaces were _unavailable" but "dns_records and rulesets were _unavailable this run". It is
// the run-scoped analogue of the discovery cache's per-surface list, and shares the SAME redaction posture:
// NO-CUSTODY, so ONLY a CLOSED-registry / product-token id is ever recorded here (see safeMarkerAttribution --
// today ONLY cf-config surface ids, the exact cfConfigDiscovery precedent), NEVER a KV/R2 object key or any
// operator/customer free-text record name. Every list is capped (MARKER_ATTRIBUTION_MAX_PER_KIND) and every id
// length-bounded (MARKER_ATTRIBUTION_ID_MAX_LEN), so a pathological run can never grow it unbounded; only
// non-empty kinds are present. It rides the run-history row exactly as IncompleteByMarker does.
export type IncompleteIds = Partial<Record<MarkerKey, string[]>>;

// MARKER_ATTRIBUTION_MAX_PER_KIND bounds how many distinct ids we retain PER marker kind: past it the run's
// attribution is a representative sample (the count in IncompleteByMarker stays exact), so a run that shorts
// hundreds of surfaces cannot bloat the checkpoint / history row / pack. 25 comfortably covers the realistic
// case (a handful of surfaces gated/erroring) while staying small.
export const MARKER_ATTRIBUTION_MAX_PER_KIND = 25;
// MARKER_ATTRIBUTION_ID_MAX_LEN bounds each id's length. A cf-config surface id is short (e.g. "dns_records");
// this is a defensive clamp so an unexpectedly long id can never balloon the row, mirroring the bounded
// surface ids the cfConfigDiscovery cache already carries.
export const MARKER_ATTRIBUTION_ID_MAX_LEN = 128;

// MARKER_HANDLE_HEX_LEN is how many hex chars of a custody name's SHA-384 a stable HANDLE carries: 12 (48
// bits), matching the causeDigest correlation-digest convention (slice.ts). It keeps the <=25 handles a run
// retains per kind collision-free while staying compact; a longer prefix would not add secrecy (the whole
// hash is derivable from any GUESSED name, so a low-entropy name stays a commitment regardless of length).
const MARKER_HANDLE_HEX_LEN = 12;

// markerNameHandle is the STABLE, one-way HANDLE for a CUSTODY record name (a KV/R2/D1 key, a workers/
// artifacts/stream/images object name): the first MARKER_HANDLE_HEX_LEN hex of SHA-384(name), prefixed "h:"
// so it is visibly a handle (never mistaken for a raw id). Stable (the same object always yields the same
// handle -> it correlates across runs and across two marker kinds in one run) and one-way (the raw name never
// appears). Async because SHA-384 is; only ever computed for a bounded number of markers per kind.
async function markerNameHandle(name: string): Promise<string> {
  return `h:${hexEncode(await sha384(new TextEncoder().encode(name))).slice(0, MARKER_HANDLE_HEX_LEN)}`;
}

// safeMarkerAttribution returns the REDACTION-SAFE attribution id for a marker record. This is the single
// NO-CUSTODY gate for the pack's per-object attribution: the raw record NAME reaches the pack ONLY when it is
// a closed-registry / product token; every operator/customer name is reduced to a one-way HANDLE first, so the
// pack can say WHICH object was short WITHOUT ever carrying the customer's key/object name.
//   - cf-config: the record NAME is a surface id from the CLOSED CF_CONFIG_SURFACES registry -- a product
//     token, not customer data -- so it is carried RAW (e.g. "dns_records"), length-clamped. The diagnostics
//     bot correlates it directly, exactly as before.
//   - every OTHER source (KV/R2/D1 keys; workers/artifacts/stream/images object names) is operator/customer
//     free-text = CUSTODY. Attributing it by raw name would LEAK the name into the vendor bundle, so it is
//     reduced to a STABLE markerNameHandle instead. This SHOWS which object (distinct objects -> distinct
//     handles; a recurring object -> the same handle) while the raw name is never present. The honest residual:
//     a LOW-entropy name's handle is a commitment a determined vendor could dictionary-guess -- acceptable
//     because it is customer-recomputable (the point of a stable handle) and the raw name never leaks.
// It is async because the handle hashes; the id is length-clamped so the caller never has to.
export async function safeMarkerAttribution(sourceType: string, name: string): Promise<string | undefined> {
  if (sourceType === "cf-config") return name.slice(0, MARKER_ATTRIBUTION_ID_MAX_LEN);
  return markerNameHandle(name);
}

// addIncompleteId records one attribution id under a marker kind, DEDUPLICATED and CAPPED in place. It is the
// single writer the seal paths (slice.ts sealOne, pipeline.ts runBackup) use, so the dedup + cap discipline
// lives in one place. A full bucket silently drops further ids (the exact count is preserved separately in
// IncompleteByMarker), and a duplicate is ignored so the same re-yielded surface never double-lists.
export function addIncompleteId(map: IncompleteIds, kind: MarkerKey, id: string): void {
  let arr = map[kind];
  if (arr === undefined) {
    arr = [];
    map[kind] = arr;
  }
  if (arr.length >= MARKER_ATTRIBUTION_MAX_PER_KIND) return;
  if (arr.includes(id)) return;
  arr.push(id);
}

// cloneIncompleteIds returns a DEEP copy (fresh per-kind arrays) so a slice's per-record increments never
// mutate the inbound checkpoint's map -- the same discipline the incompleteByMarker deep-copy keeps in slice.ts.
export function cloneIncompleteIds(map: IncompleteIds): IncompleteIds {
  const out: IncompleteIds = {};
  for (const k of MARKER_KEYS) {
    const arr = map[k];
    if (arr !== undefined) out[k] = [...arr];
  }
  return out;
}

// mergeIncompleteIds folds b into a (a fresh result, neither input mutated), UNIONing each kind's ids with the
// same dedup + cap as addIncompleteId, so a fan-out run's global attribution carries each parallel worker's
// shorted surfaces without duplicates and without exceeding the per-kind cap. It is the attribution analogue of
// addCheckpointCounts's incompleteByMarker fold.
export function mergeIncompleteIds(a: IncompleteIds, b: IncompleteIds): IncompleteIds {
  const out = cloneIncompleteIds(a);
  for (const k of MARKER_KEYS) {
    const arr = b[k];
    if (arr === undefined) continue;
    for (const id of arr) addIncompleteId(out, k, id);
  }
  return out;
}

// MARKER_VALUE_MAX bounds how large a value we will even attempt to parse as a sentinel. The
// adapters write tiny JSON objects (a reason string plus a count/percent), well under this; a real
// captured value past it is never a marker and the cheap length check skips the parse entirely.
const MARKER_VALUE_MAX = 4096;

// incompleteMarkerKind PARSES a value's bytes and returns WHICH incompleteness sentinel key it carries (the
// FIRST MARKER_KEYS member present at the top of the small JSON object), or undefined when the bytes do not
// have that shape. NOT AUTHORITATIVE (CR-04): a real customer value can coincidentally have this exact
// shape, so neither the seal (slice.ts/pipeline.ts, which stamp meta.incompleteMarker from the adapter-
// asserted SourceRecord.markerKind) nor restore (which gates its write-skip on the resulting signed
// ShardRecord.incompleteMarker) call this any more. It is kept as a pure content-shape classifier for the
// format-level round-trip test (validate-incomplete-marker.ts); do not wire it back into either decision.
// NO-CUSTODY: it returns only the KEY identity from the closed MARKER_KEYS set, never the marker's payload.
export function incompleteMarkerKind(bytes: Uint8Array | undefined): (typeof MARKER_KEYS)[number] | undefined {
  if (bytes === undefined || bytes.length === 0 || bytes.length > MARKER_VALUE_MAX) return undefined;
  // A JSON object starts with '{' (0x7b) after optional whitespace; cheap reject for binary.
  let i = 0;
  while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d)) i++;
  if (bytes[i] !== 0x7b) return undefined;
  try {
    const o = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown> | null;
    if (o === null || typeof o !== "object") return undefined;
    return MARKER_KEYS.find((k) => k in o);
  } catch {
    return undefined;
  }
}

// isIncompleteMarkerValue is the BOOLEAN view over incompleteMarkerKind: same NOT-AUTHORITATIVE caveat
// (CR-04) applies. media-restore.ts isMarkerValue delegates here but is likewise no longer the restore-side
// write-skip gate (see restore-apply.ts/restore-plan.ts, which read ShardRecord.incompleteMarker instead);
// this stays available for tests/tooling that want a pure content-shape check.
export function isIncompleteMarkerValue(bytes: Uint8Array | undefined): boolean {
  return incompleteMarkerKind(bytes) !== undefined;
}
