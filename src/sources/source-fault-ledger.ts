// SOURCE FAULT LEDGER (support-pack gaps G015/G042/G068/G110/G144).
//
// WHY: the source adapters already fail HONESTLY into the archive (an "_unavailable"/"_truncated"/
// "_skipped"/"_pending"/"_refused"/"_vanished" sentinel record, seal/marker.ts), and the seal counts
// WHICH KINDS (incompleteByMarker) and, boundedly, WHICH ids (incompleteIds). But the WHY and the
// MAGNITUDE only ever existed inside the sentinel's JSON payload, which is end-to-end encrypted at the
// customer's own destination (NO-CUSTODY). A support pack therefore proved "surface X was unavailable in
// every run" and could never say whether that was a 403 scope gap, a 5xx outage, a size ceiling, a page
// cap or a stuck render, and a run-fatal source failure collapsed to one coarse class with no HTTP status
// and no stage. Worse, the tolerant-parse fallbacks (Array.isArray(...) ? ... : [], "if the id is not a
// string, continue") silently DROP items on a Cloudflare API shape change while the run still reports ok.
//
// WHAT: this module is the one place a source adapter records, at the exact fault site, a COARSENED,
// redaction-safe fact about a fault it is about to absorb:
//   - the closed REASON class behind each incompleteness sentinel it seals (G015), plus the truncation
//     magnitude (pages read / records accumulated) and a stuck render's age;
//   - a fault that never becomes a record at all: a failed SUB-PART read inside a surface (G042), a failed
//     PER-ITEM read nested inside a surface read (G068), a tolerant-parse drop (G110);
//   - the run-fatal throw's HTTP status class and pipeline stage (G144).
//
// REDACTION (binding, NO-CUSTODY): every field here is a CLOSED ENUM, a CLAMPED INT or a bounded,
// redaction-safe id. The raw Cloudflare error message, the request path, the numeric CF code list, the
// customer's object/script/secret name and the malformed API object NEVER enter this ledger. Attribution
// ids follow the existing seal/marker.ts safeMarkerAttribution rule: a CLOSED-registry product token
// (a cf-config surface id, an aspect name) is carried raw and length-clamped; a CUSTOMER-owned name (a
// script id, a video uid, a secret name, a ruleset id) is reduced to a stable one-way HANDLE first.
//
// STATE: a module-level, BOUNDED accumulator. The run path RESETS it before a crawl (or a slice) and
// DRAINS it after, exactly as the seal folds CheckpointCounts; a drained snapshot is what the run row
// (and from there the support pack) carries. It is bounded in every dimension (closed enums, capped id
// lists, clamped counters), so a pathological run can never grow it.

import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { MarkerKey } from "../seal/marker.ts";

// SOURCE_FAULT_REASONS is the CLOSED vocabulary of WHY a source could not fully capture something. It is
// the reason companion to seal/marker.ts MARKER_KEYS (which says WHICH KIND of shortfall): a "_unavailable"
// surface is now "_unavailable BECAUSE auth", and a "_truncated" one is "_truncated BECAUSE page-cap".
//   auth              - the token was rejected or lacks the read scope (401/403 that is not an entitlement gate)
//   entitlement       - the account plan does not include the surface (a definite CF plan gate, never actionable)
//   not-found         - the resource answered 404 (deleted, or never existed)
//   rate-limited      - a 429 that survived the retry/pacer
//   server-error      - a 5xx that survived the retry (a Cloudflare-side outage, not a customer misconfiguration)
//   redirect-refused  - a download URL failed the host allow-list and was never fetched
//   size-cap          - the value/serialised surface exceeded the buffered-capture ceiling
//   page-cap          - the paginator hit its max-pages guard without exhausting the list
//   cursor-stall      - a list cursor could not advance (a timestamp bucket wider than one page)
//   render-pending    - the platform has not finished producing the downloadable artefact yet
//   changed-mid-crawl - the object was listed but was gone by the time its value was read (a live-source race)
//   envelope-absent   - the expected response envelope/capability was absent (a degraded read, e.g. no metadata)
//   shape             - the response did not have the expected shape and a tolerant parser dropped/coerced it
//   not-attempted     - the run never issued the read: a CACHED probe had already found the resource unreadable
//                       and the cost-narrowing selector left it out, so the shortfall is a carried-forward
//                       fault rather than one this run observed. Distinct from `auth`/`server-error` on
//                       purpose: the status class belongs to the DISCOVERY row (cfConfigDiscovery
//                       .unavailableByClass), and pinning this run's marker to a stale class would assert
//                       something the run did not measure.
//   other             - anything else (kept deliberately last so an unrecognised fault is never mislabelled)
export const SOURCE_FAULT_REASONS = [
  "auth",
  "entitlement",
  "not-found",
  "rate-limited",
  "server-error",
  "redirect-refused",
  "size-cap",
  "page-cap",
  "cursor-stall",
  "render-pending",
  "changed-mid-crawl",
  "envelope-absent",
  "shape",
  "not-attempted",
  "other",
] as const;
export type SourceFaultReason = (typeof SOURCE_FAULT_REASONS)[number];

// SOURCE_FAULT_STATUS_CLASSES is the CLOSED vocabulary for a RUN-FATAL source failure's transport verdict
// (G144). It is deliberately a CLASS, not the status: the numeric CF error-code list and the message never
// leave the throw site. It answers the classic setup ticket ("my Images backup fails after a token
// rotation"): 401 expired token vs 403 missing scope vs entitlement gate vs 5xx outage vs network.
export const SOURCE_FAULT_STATUS_CLASSES = ["401", "403", "404", "429", "5xx", "network", "shape", "entitlement", "other"] as const;
export type SourceFaultStatusClass = (typeof SOURCE_FAULT_STATUS_CLASSES)[number];

// SOURCE_FAULT_STAGES is the CLOSED vocabulary for WHERE in the crawl a fatal fault happened (G144), which
// is what separates "the token cannot even LIST" (a scope/auth problem) from "the list worked but every
// item read failed" (a narrower scope, or an outage) from "the liveness PROBE failed" (the resource is gone).
// REMOVED: `sub-read`. No adapter has a sub-read FATAL to record it at. Every nested read the
// crawlers do -- a Worker script's per-aspect reads, an image's blob, a Stream video's download -- is part of
// that ITEM's read, and the two adapters with an every-item-failed guard (workers, cf-config) both record it,
// correctly, as `item-read`. Producing this stage would have meant INVENTING a new run-fatal throw at a level
// that currently absorbs its faults into per-item markers, which is a change to what fails a backup, not a
// recorder. A stage no throw site can select tells support a distinction the crawl never made.
export const SOURCE_FAULT_STAGES = ["list", "item-read", "probe", "resume"] as const;
export type SourceFaultStage = (typeof SOURCE_FAULT_STAGES)[number];

// SNAPSHOT_CONSISTENCY_CLASSES is the CLOSED vocabulary for whether a D1 crawl actually held the
// point-in-time guarantee it claims (G096). This is a DATA-INTEGRITY signal, not a failure signal: all three
// values ride on runs that report ok, which is precisely the bug ("restored D1 shows rows referencing rows
// that do not exist", "the restored table has duplicated rows", behind a clean run).
//   pinned       - a session bookmark was held for the whole crawl; the archive is ONE snapshot.
//   unpinned     - the binding exposed no withSession(), so reads were NOT snapshot-isolated. Rows may be
//                  drawn from different points in time (a torn read); referential integrity is not promised.
//   re-anchored  - a resume token carried a bookmark the engine could not honour, so the crawl re-anchored
//                  mid-run to a DIFFERENT snapshot. This is the mixed-snapshot archive: strictly worse than
//                  unpinned, because the tear is invisible and spans a resume boundary.
// Worst-wins when folded (re-anchored > unpinned > pinned), so a single degraded slice is never masked by
// pinned slices either side of it.
export const SNAPSHOT_CONSISTENCY_CLASSES = ["pinned", "unpinned", "re-anchored"] as const;
export type SnapshotConsistencyClass = (typeof SNAPSHOT_CONSISTENCY_CLASSES)[number];

// RESUME_TOKEN_DEFECTS is the CLOSED vocabulary for HOW a resume token was corrupt (G213/G096). A wedged
// downpipe ("every slice fails after a DO storage anomaly") currently reads as a generic "run failed",
// because the adapters' token throws match no coarse-error branch. The defect class is what maps the ticket
// to its known remediation (clear the resume token), and it separates a one-off from a wedge.
//   unparseable   - the token was not JSON at all (the raw JSON.parse SyntaxError path).
//   bad-shape     - it parsed, but was not an object.
//   bad-phase     - the phase field was absent or not a member of the closed phase set.
//   bad-index     - the table index was not a non-negative integer.
//   bad-cursor    - the row cursor (afterRowid) was present but not a decimal integer string. Coercing this
//                   to null RESTARTS the table and re-emits already-sealed rows (the duplicate-rows bug).
//   bad-bookmark  - the snapshot bookmark was present but not a string. Coercing it to null silently
//                   RE-ANCHORS the crawl to a different snapshot (the mixed-snapshot bug).
export const RESUME_TOKEN_DEFECTS = ["unparseable", "bad-shape", "bad-phase", "bad-index", "bad-cursor", "bad-bookmark"] as const;
export type ResumeTokenDefect = (typeof RESUME_TOKEN_DEFECTS)[number];

// SOURCE_SECURITY_REFUSAL_KINDS is the CLOSED vocabulary for a refusal the source layer made on SECURITY
// grounds (G327). Today these are anonymous: the refusal is archive-sealed behind a "_refused" marker count,
// so an operator cannot tell a benign misconfiguration from a redirect that tried to steer a byte read off
// Cloudflare. The refused HOST/URL is exactly what must never be recorded, so the KIND is all we keep.
//   redirect-refused        - a byte-fetch target answered a 3xx (or the opaque-redirect status 0) and was
//                             refused rather than followed (byte-fetch.ts). Written by the crawl.
//   host-refused            - a download URL failed the Cloudflare host allow-list and was never fetched
//                             (stream.ts). Written by the crawl.
//   ddl-injection-rejected  - a D1 CREATE statement carried more than one statement (a multi-statement DDL
//                             in an archive is a tamper signature, not a writer bug).
//
// RESERVED MEMBER: ddl-injection-rejected is part of the closed vocabulary the pack section carries, but it is
// deliberately NOT written by THIS ledger. Its fault site (d1-format.ts assertSingleStatement) runs on the
// RESTORE/decode path, and this ledger is a CRAWL-scoped, isolate-local accumulator that the restore path
// never resets or drains. Recording it here would let a restore-time refusal survive in a warm isolate and be
// drained onto an unrelated later BACKUP run's row: a mis-attributed security signal, which is worse than a
// missing one. It belongs in the restore-path evidence sink, which is owned by the restore/support layer.
// CF_SELECTOR_MODES is the CLOSED vocabulary for WHICH surface selector a cf-config run actually used
// (G006). It is the missing attribution behind "our runs suddenly take 10x longer and trip rate limits": an
// auto-mode downpipe whose discovery cache has gone STALE (>25h, because the discovery pass is being skipped)
// silently fail-safes to crawling EVERY surface in the registry, every run, forever. The run row records which mode it
// ran under, so the cost explosion is attributable to the stale cache instead of looking like a mystery.
//   configured          - the operator's explicit include/exclude selection (manual mode)
//   auto                - the discovered PRESENT set: the read-cost optimisation working as designed
//   stale-fallback-all  - auto mode with NO or STALE discovery: the fail-safe crawl of every surface
export const CF_SELECTOR_MODES = ["configured", "auto", "stale-fallback-all"] as const;
export type CfSelectorMode = (typeof CF_SELECTOR_MODES)[number];

// D1_DEFECT_CLASSES is the CLOSED vocabulary for a D1 decode / validation refusal (G069). Today every one of
// these collapses to a generic reason at the sink, so support cannot tell a TAMPERED archive from a writer
// bug, cannot spot that an unknown format hint means ENGINE VERSION SKEW after a rollback (a one-line
// diagnosis), and the customer is left to bisect their own tables to find the single NaN cell or giant row.
//   bad-json          - the body is not JSON at all
//   shape             - it parsed but the structure is wrong (no tables array, bad column list, bad cell)
//   multi-statement-ddl - a CREATE statement carried more than one statement: a TAMPER signature in an
//                       archive, never a writer bug (it is also a security refusal)
//   unknown-format    - the format hint is one this reader does not understand: ENGINE VERSION SKEW (the
//                       archive was written by a NEWER engine than the one restoring it, e.g. after a rollback)
//   non-finite-real   - a REAL cell was Infinity/-Infinity/NaN: JSON has no form for it, and emitting `null`
//                       would silently turn the value into NULL (data corruption with no signal)
//   unsupported-type  - a cell type the writer does not know how to represent
//   bad-base64        - a tagged BLOB's base64 would not decode
//   giant-row         - a single row/page exceeded the byte ceiling
//   bad-rowid         - the binding returned a non-integer rowid (a contract violation)
export const D1_DEFECT_CLASSES = [
  "bad-json",
  "shape",
  "multi-statement-ddl",
  "unknown-format",
  "non-finite-real",
  "unsupported-type",
  "bad-base64",
  "giant-row",
  "bad-rowid",
] as const;
export type D1DefectClass = (typeof D1_DEFECT_CLASSES)[number];

// REMOVED: `ddl-injection-rejected`. This ledger rides on a BACKUP run's row, and the backup crawl
// never parses DDL: d1.ts reads the schema text out of the database and encodes it verbatim. The
// single-statement guard (d1-format.ts) runs on the RESTORE decode path, which has no source-run ledger to
// write to -- and the refusal there is already classified, twice: as the restore fault class `d1-decode-tamper`
// and as the D1 defect class `multi-statement-ddl`. The two live members here are what they always were: the
// crawl's SSRF refusals (a redirected byte fetch, a download host that is not the vendor's).
export const SOURCE_SECURITY_REFUSAL_KINDS = ["redirect-refused", "host-refused"] as const;
export type SourceSecurityRefusalKind = (typeof SOURCE_SECURITY_REFUSAL_KINDS)[number];

// Bounds. The id caps mirror seal/marker.ts (25 ids per kind, 128 chars each) so the ledger can never
// outgrow the run row it rides on; the counter clamp mirrors admin/support-shared.ts clampInt.
export const FAULT_IDS_MAX_PER_KIND = 25;
export const FAULT_ID_MAX_LEN = 128;
const FAULT_COUNT_MAX = 1_000_000;
// RETRY_AFTER_SECONDS_MAX clamps the platform's Retry-After ask (G170) to a day, so a hostile or garbled
// header can never write an unbounded number onto a run row.
const RETRY_AFTER_SECONDS_MAX = 86_400;
// FAULT_HANDLE_HEX_LEN matches seal/marker.ts markerNameHandle: 12 hex (48 bits) of SHA-384, enough to keep
// the <=25 retained handles per kind collision-free, prefixed "h:" so a handle is never mistaken for a raw id.
const FAULT_HANDLE_HEX_LEN = 12;

// SourceFatalFault is the run-fatal throw's coarsened identity (G144): which source type, which transport
// class, which stage, and (for the all-aspects-failed guards) how many reads were attempted vs succeeded.
export interface SourceFatalFault {
  sourceType: string; // a closed product token (the adapter's own sourceType), never customer data
  statusClass: SourceFaultStatusClass;
  stage: SourceFaultStage;
  attempted?: number; // clamped
  succeeded?: number; // clamped
}

// SourceFaultLedger is the drained, redaction-safe snapshot the run path folds onto the run row.
export interface SourceFaultLedger {
  // incompleteReasons: per marker kind, the closed reason class -> count map (G015). The per-kind COUNTS
  // stay exact even when the id lists below are capped.
  incompleteReasons: Partial<Record<MarkerKey, Partial<Record<SourceFaultReason, number>>>>;
  // incompleteIds: per marker kind, the bounded attribution ids for the faults recorded here. This is what
  // gives a failing SUB-PART (G042: "r2-bucket-config/lock") or a failing nested ITEM (G068:
  // "rulesets/h:ab12...") an identity, neither of which is ever its own archive record and so neither of
  // which the seal's own incompleteIds can ever see.
  incompleteIds: Partial<Record<MarkerKey, string[]>>;
  // shapeAnomalies: how many times a tolerant parser dropped or coerced a Cloudflare response it did not
  // recognise (G110). This is the ONLY signal that a silent API-shape drift is voiding coverage while every
  // run still reports ok, so it is a first-class clamped counter, not a marker (these sites emit no record).
  shapeAnomalies: number;
  // shapeAnomalyIds: WHERE the drift is, as bounded product tokens ("workers/versions", "stream/list").
  shapeAnomalyIds: string[];
  // truncation: the WORST truncation magnitude seen this run (G015): how many pages were read and how many
  // records accumulated before the paginator gave up. "Is our monorepo fully backed up?" is answerable only
  // with a shortfall magnitude; the exact object list stays archive-sealed.
  truncation?: { pagesRead: number; recordsAccumulated: number };
  // oldestPendingAgeMs: the age of the OLDEST still-rendering artefact this run left as a "_pending" marker
  // (G015): a video stuck at percentComplete 40 for three weeks reads as a large age here, where a fresh
  // upload reads as minutes. Clamped.
  oldestPendingAgeMs?: number;
  // fatal: the run-fatal fault, when the crawl threw rather than degraded (G144). Last write wins (a crawl
  // only ever dies once).
  fatal?: SourceFatalFault;
  // snapshotConsistency: whether the D1 crawl actually held its point-in-time guarantee (G096). Absent for a
  // non-D1 run. Worst-wins across slices, so one re-anchored slice colours the whole run.
  snapshotConsistency?: SnapshotConsistencyClass;
  // rowidProbeFallbacks: how many tables silently fell back to an UNBOUNDED single-pass read because the
  // _rowid_ probe threw (G096). The fallback is correct for a genuine WITHOUT ROWID table, but a TRANSIENTLY
  // failing probe on a rowid table produces the same silent fallback, which is what later OOMs "unrelatedly".
  // A count is the only way to tell "two WITHOUT ROWID tables" from "the probe is failing across the board".
  rowidProbeFallbacks: number;
  // resumeTokenDefects: the closed defect class -> count map for corrupt resume tokens (G213). The COUNT is
  // what distinguishes a one-off from a WEDGE (every slice failing on the same corrupt token).
  resumeTokenDefects: Partial<Record<ResumeTokenDefect, number>>;
  // resumeTokenSourceTypes: WHICH adapters saw a corrupt token, as closed product tokens ("d1", "kv").
  resumeTokenSourceTypes: string[];
  // cfSelectorMode: WHICH cf-config surface selector this run actually used (G006). Absent for a non-cf-config
  // run. `stale-fallback-all` is the cost-explosion signal: the discovery cache went stale and the run is
  // crawling every surface in the registry.
  cfSelectorMode?: CfSelectorMode;
  // d1Defects: the closed defect class -> count map for a D1 decode/validation refusal (G069). Worth a first-
  // class counter because the classes route to COMPLETELY different diagnoses: multi-statement-ddl is a tamper
  // signature, unknown-format is engine version skew, non-finite-real is a writer bug.
  d1Defects: Partial<Record<D1DefectClass, number>>;
  // d1DefectTables: WHICH tables carry the defect, so the customer does not have to bisect their own schema to
  // find the one NaN cell. A D1 table name is a CUSTOMER schema label, so it follows the ledger's existing
  // rule for customer-owned names and is reduced to a stable one-way HANDLE (`h:<12 hex>`) before it is
  // recorded -- never the raw name. Support asks the customer to hash their table names to join, or simply
  // uses the COUNT (one table vs every table is the diagnosis that actually matters).
  d1DefectTables: string[];
  // throttle429Count: every 429 the crawl absorbed, INCLUDING the ones a retry swallowed (G170). This is the
  // signal that is invisible today: a chronically throttled account looks perfectly healthy right up to the
  // day retries exhaust, because withRetry only ever surfaces the terminal outcome.
  throttle429Count: number;
  // retryExhaustedCount: how many times the retry ladder gave up entirely (G170).
  retryExhaustedCount: number;
  // maxRetryAfterSeconds: the LARGEST Retry-After the platform asked for (G170), clamped. A rising figure is
  // how mounting back-pressure reads before it becomes an outage.
  maxRetryAfterSeconds?: number;
  // securityRefusals: the closed security-refusal kind -> count map (G327). Counts only; the refused host,
  // URL and DDL text never enter the ledger.
  securityRefusals: Partial<Record<SourceSecurityRefusalKind, number>>;
}

function emptyLedger(): SourceFaultLedger {
  return {
    incompleteReasons: {},
    incompleteIds: {},
    shapeAnomalies: 0,
    shapeAnomalyIds: [],
    d1Defects: {},
    d1DefectTables: [],
    rowidProbeFallbacks: 0,
    resumeTokenDefects: {},
    resumeTokenSourceTypes: [],
    throttle429Count: 0,
    retryExhaustedCount: 0,
    securityRefusals: {},
  };
}

// SNAPSHOT_SEVERITY ranks the consistency classes so a fold is WORST-WINS: a run that re-anchored on one
// slice must never be reported as pinned because the other slices were clean.
const SNAPSHOT_SEVERITY: Record<SnapshotConsistencyClass, number> = { pinned: 0, unpinned: 1, "re-anchored": 2 };

function worseSnapshot(a: SnapshotConsistencyClass | undefined, b: SnapshotConsistencyClass | undefined): SnapshotConsistencyClass | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return SNAPSHOT_SEVERITY[b] > SNAPSHOT_SEVERITY[a] ? b : a;
}

let ledger: SourceFaultLedger = emptyLedger();

// clamp keeps every recorded integer a bounded non-negative int, so a pathological source can never write
// an unbounded / NaN / negative number into a run row (the clampInt discipline, admin/support-shared.ts).
function clamp(v: number, max = FAULT_COUNT_MAX): number {
  if (!Number.isFinite(v)) return 0;
  const n = Math.floor(v);
  if (n < 0) return 0;
  return n > max ? max : n;
}

// faultHandle is the STABLE, one-way handle for a CUSTOMER-owned name (a script id, a video uid, a secret
// name, a ruleset id): the first 12 hex of SHA-384(name), prefixed "h:". Same convention and same honest
// residual as seal/marker.ts markerNameHandle: distinct objects give distinct handles and a recurring
// object gives the same handle across runs, while the raw name NEVER leaves the customer's account.
export async function faultHandle(name: string): Promise<string> {
  return `h:${hexEncode(await sha384(new TextEncoder().encode(name))).slice(0, FAULT_HANDLE_HEX_LEN)}`;
}

// faultItemId builds the attribution id for a fault. `scope` is a CLOSED product token the ENGINE chose
// (a cf-config surface id, "workers/settings", "r2-bucket-config/lock"): carried raw, length-clamped. `item`,
// when present, is the CUSTOMER-owned id of the specific thing that failed: hashed to a handle first, so the
// pack can say WHICH item sank the surface without ever carrying the item's name.
export async function faultItemId(scope: string, item?: string): Promise<string> {
  const base = scope.slice(0, FAULT_ID_MAX_LEN);
  if (item === undefined || item === "") return base;
  return `${base}/${await faultHandle(item)}`.slice(0, FAULT_ID_MAX_LEN);
}

function addId(map: Partial<Record<MarkerKey, string[]>>, kind: MarkerKey, id: string): void {
  let arr = map[kind];
  if (arr === undefined) {
    arr = [];
    map[kind] = arr;
  }
  if (arr.length >= FAULT_IDS_MAX_PER_KIND) return; // full: the exact count still rides in incompleteReasons
  if (arr.includes(id)) return;
  arr.push(id);
}

// recordIncompleteFault is the single writer for "I am absorbing a fault and sealing/degrading in its place".
// It is called at the EXACT site that decides to substitute a marker (or to swallow a sub-read), so the
// reason is an adapter ASSERTION, never a later guess. Every argument is already coarse; nothing is parsed
// out of an error message here beyond the closed classification the caller did.
export function recordIncompleteFault(
  kind: MarkerKey,
  reason: SourceFaultReason,
  opts?: { id?: string; pagesRead?: number; recordsAccumulated?: number; pendingAgeMs?: number },
): void {
  let byReason = ledger.incompleteReasons[kind];
  if (byReason === undefined) {
    byReason = {};
    ledger.incompleteReasons[kind] = byReason;
  }
  byReason[reason] = clamp((byReason[reason] ?? 0) + 1);
  if (opts?.id !== undefined && opts.id !== "") addId(ledger.incompleteIds, kind, opts.id.slice(0, FAULT_ID_MAX_LEN));
  if (opts?.pagesRead !== undefined || opts?.recordsAccumulated !== undefined) {
    const pagesRead = clamp(opts.pagesRead ?? 0);
    const recordsAccumulated = clamp(opts.recordsAccumulated ?? 0);
    // Keep the WORST (largest) magnitude seen: one run row carries one shortfall figure, and the biggest
    // truncation is the one an operator must act on.
    const cur = ledger.truncation;
    if (cur === undefined || recordsAccumulated > cur.recordsAccumulated) ledger.truncation = { pagesRead, recordsAccumulated };
  }
  if (opts?.pendingAgeMs !== undefined) {
    const age = clamp(opts.pendingAgeMs, Number.MAX_SAFE_INTEGER);
    if (ledger.oldestPendingAgeMs === undefined || age > ledger.oldestPendingAgeMs) ledger.oldestPendingAgeMs = age;
  }
}

// recordShapeAnomaly is the writer for a TOLERANT-PARSE fallback (G110): the response did not have the shape
// the adapter expected, so the adapter dropped the item / coerced to an empty list / returned early. These
// sites emit NO record and NO marker (that is the whole bug: months of green runs with whole namespaces
// missing), so this counter is the only trace. `scope` is a product token; never the malformed object.
export function recordShapeAnomaly(scope: string): void {
  ledger.shapeAnomalies = clamp(ledger.shapeAnomalies + 1);
  const id = scope.slice(0, FAULT_ID_MAX_LEN);
  if (ledger.shapeAnomalyIds.length < FAULT_IDS_MAX_PER_KIND && !ledger.shapeAnomalyIds.includes(id)) ledger.shapeAnomalyIds.push(id);
}

// recordResumeFatal is the RESUME-STAGE fatal (G144). A resume token the adapter cannot parse is run-fatal --
// the crawl throws before it reads a single key -- and it was the one fatal the run row could not PLACE:
// `fatal` was simply absent, so the row said the run failed and nothing more, and a downpipe wedged forever on
// the same corrupt token (re-read, re-thrown, every tick) was indistinguishable from an ordinary flaky source.
//
// The status class is `shape`: a token that will not parse is a shape fault, and there is no HTTP exchange to
// have a status. The token bytes are never read, forwarded or recorded; the closed defect class beside it
// (recordResumeTokenDefect) says WHICH way the token was malformed, and this says WHERE the run died.
export function recordResumeFatal(sourceType: string): void {
  recordSourceFatal({ sourceType, statusClass: "shape", stage: "resume" });
}

// recordSourceFatal is the writer for a RUN-FATAL source failure (G144): the crawl is about to throw, and the
// run row would otherwise carry only a coarse class with no status and no stage.
export function recordSourceFatal(f: SourceFatalFault): void {
  ledger.fatal = {
    sourceType: f.sourceType.slice(0, FAULT_ID_MAX_LEN),
    statusClass: f.statusClass,
    stage: f.stage,
    ...(f.attempted !== undefined ? { attempted: clamp(f.attempted) } : {}),
    ...(f.succeeded !== undefined ? { succeeded: clamp(f.succeeded) } : {}),
  };
}

// recordSnapshotConsistency is the writer for the D1 point-in-time verdict (G096). Called by the reader at the
// moment it learns what guarantee it actually has: when it opens a session (pinned / unpinned) and when a
// resume token's bookmark could not be honoured (re-anchored). Worst-wins, so a later "pinned" table can
// never overwrite an earlier "re-anchored" crawl.
export function recordSnapshotConsistency(c: SnapshotConsistencyClass): void {
  const next = worseSnapshot(ledger.snapshotConsistency, c);
  if (next !== undefined) ledger.snapshotConsistency = next;
}

// recordRowidProbeFallback is the writer for a table that fell back to an unbounded single-pass read because
// its _rowid_ probe threw (G096). The probe's own error is DISCARDED at the call site (it is a legitimate
// WITHOUT ROWID signal as often as it is a fault); only the count is kept.
export function recordRowidProbeFallback(): void {
  ledger.rowidProbeFallbacks = clamp(ledger.rowidProbeFallbacks + 1);
}

// recordResumeTokenDefect is the writer for a corrupt resume token (G213). `sourceType` is the adapter's own
// closed product token; the token BYTES and the offending field value are never recorded.
export function recordResumeTokenDefect(sourceType: string, defect: ResumeTokenDefect): void {
  ledger.resumeTokenDefects[defect] = clamp((ledger.resumeTokenDefects[defect] ?? 0) + 1);
  const t = sourceType.slice(0, FAULT_ID_MAX_LEN);
  if (ledger.resumeTokenSourceTypes.length < FAULT_IDS_MAX_PER_KIND && !ledger.resumeTokenSourceTypes.includes(t)) ledger.resumeTokenSourceTypes.push(t);
}

// recordThrottle is the writer for ONE absorbed 429 (G170). It is called INSIDE the retried function, so it
// counts the 429s a retry successfully swallowed, which is the entire point: those are invisible today.
// `retryAfterSeconds` is the platform's own ask, clamped; never a URL or a message.
export function recordThrottle(retryAfterSeconds?: number): void {
  ledger.throttle429Count = clamp(ledger.throttle429Count + 1);
  if (retryAfterSeconds !== undefined) {
    const s = clamp(retryAfterSeconds, RETRY_AFTER_SECONDS_MAX);
    if (ledger.maxRetryAfterSeconds === undefined || s > ledger.maxRetryAfterSeconds) ledger.maxRetryAfterSeconds = s;
  }
}

// recordRetryExhausted is the writer for a retry ladder that gave up (G170): the fault the customer finally
// sees. Counted separately from the absorbed 429s so "throttled but coping" and "throttled into failure" are
// distinguishable on the run row.
export function recordRetryExhausted(): void {
  ledger.retryExhaustedCount = clamp(ledger.retryExhaustedCount + 1);
}

// recordSecurityRefusal is the writer for a refusal made on SECURITY grounds (G327). The KIND is the whole
// record: the refused host/URL is precisely the value that must never be carried, and the DDL text likewise.
export function recordSecurityRefusal(kind: SourceSecurityRefusalKind): void {
  ledger.securityRefusals[kind] = clamp((ledger.securityRefusals[kind] ?? 0) + 1);
}

/**
 * noteCfSelectorMode records WHICH cf-config surface selector this run used (G006). Idempotent per run; the
 * stale fail-safe never gets masked by a later healthy call.
 *
 * @param mode - the closed selector mode.
 */
export function noteCfSelectorMode(mode: CfSelectorMode): void {
  if (ledger.cfSelectorMode === "stale-fallback-all") return;
  ledger.cfSelectorMode = mode;
}

/**
 * recordD1Defect records ONE D1 decode/validation defect (G069): the closed class, and a one-way HANDLE of
 * the table it was found in. The table name is a CUSTOMER schema label, so it is reduced to a handle at the
 * WRITE site by the caller (via faultItemId / d1TableHandle) exactly as every other customer-owned name in
 * this ledger is -- the raw name never enters it, and the DDL text, the cell value and the position never
 * leave the throw site at all.
 *
 * @param defect - the closed defect class.
 * @param tableHandle - the `h:<12 hex>` handle of the table, when the throw site knew one.
 */
export function recordD1Defect(defect: D1DefectClass, tableHandle?: string): void {
  ledger.d1Defects[defect] = clamp((ledger.d1Defects[defect] ?? 0) + 1);
  if (tableHandle !== undefined && tableHandle !== "" && ledger.d1DefectTables.length < FAULT_IDS_MAX_PER_KIND && !ledger.d1DefectTables.includes(tableHandle)) {
    ledger.d1DefectTables.push(tableHandle.slice(0, FAULT_ID_MAX_LEN));
  }
}

function cloneLedger(l: SourceFaultLedger): SourceFaultLedger {
  const incompleteReasons: SourceFaultLedger["incompleteReasons"] = {};
  for (const k of Object.keys(l.incompleteReasons) as MarkerKey[]) incompleteReasons[k] = { ...l.incompleteReasons[k] };
  const incompleteIds: SourceFaultLedger["incompleteIds"] = {};
  for (const k of Object.keys(l.incompleteIds) as MarkerKey[]) incompleteIds[k] = [...(l.incompleteIds[k] ?? [])];
  return {
    incompleteReasons,
    incompleteIds,
    shapeAnomalies: l.shapeAnomalies,
    shapeAnomalyIds: [...l.shapeAnomalyIds],
    ...(l.truncation !== undefined ? { truncation: { ...l.truncation } } : {}),
    ...(l.oldestPendingAgeMs !== undefined ? { oldestPendingAgeMs: l.oldestPendingAgeMs } : {}),
    ...(l.fatal !== undefined ? { fatal: { ...l.fatal } } : {}),
    // Defensive defaults. A SourceFaultLedger is a snapshot that can outlive the isolate that made it: the
    // sliced seal folds one slice's drained ledger into the next across invocations, so once a snapshot is
    // persisted (a checkpoint, a run row) an engine UPDATE mid-run can hand this function a snapshot written
    // by the PREVIOUS version, which has none of the fields below. Reading those as absent rather than
    // assuming they are present keeps a version-skewed merge from throwing (an unbounded-crash on the resume
    // path) instead of degrading to "no evidence for the fields that did not exist yet".
    rowidProbeFallbacks: l.rowidProbeFallbacks ?? 0,
    d1Defects: { ...(l.d1Defects ?? {}) },
    d1DefectTables: [...(l.d1DefectTables ?? [])],
    ...(l.cfSelectorMode !== undefined ? { cfSelectorMode: l.cfSelectorMode } : {}),
    resumeTokenDefects: { ...l.resumeTokenDefects },
    resumeTokenSourceTypes: [...(l.resumeTokenSourceTypes ?? [])],
    throttle429Count: l.throttle429Count ?? 0,
    retryExhaustedCount: l.retryExhaustedCount ?? 0,
    securityRefusals: { ...l.securityRefusals },
    ...(l.snapshotConsistency !== undefined ? { snapshotConsistency: l.snapshotConsistency } : {}),
    ...(l.maxRetryAfterSeconds !== undefined ? { maxRetryAfterSeconds: l.maxRetryAfterSeconds } : {}),
  };
}

// resetSourceFaultLedger clears the accumulator. The run path calls it BEFORE a crawl (or a slice) so a
// previous run's faults in the same warm isolate can never be attributed to this one.
export function resetSourceFaultLedger(): void {
  ledger = emptyLedger();
}

// readSourceFaultLedger returns a deep copy WITHOUT clearing (tests, and any mid-crawl inspection).
export function readSourceFaultLedger(): SourceFaultLedger {
  return cloneLedger(ledger);
}

// drainSourceFaultLedger returns the snapshot and clears: the run path calls it after the crawl (per slice on
// the sliced path, exactly as it folds CheckpointCounts) and folds the result onto the run row.
export function drainSourceFaultLedger(): SourceFaultLedger {
  const out = cloneLedger(ledger);
  ledger = emptyLedger();
  return out;
}

// isEmptyFaultLedger reports whether a drained snapshot carries anything at all, so a clean run adds NOTHING
// to its run row (the omitempty discipline incompleteByMarker already keeps).
export function isEmptyFaultLedger(l: SourceFaultLedger): boolean {
  return (
    Object.keys(l.incompleteReasons).length === 0 &&
    Object.keys(l.incompleteIds).length === 0 &&
    l.shapeAnomalies === 0 &&
    l.truncation === undefined &&
    l.oldestPendingAgeMs === undefined &&
    l.fatal === undefined &&
    // A "pinned" snapshot verdict is the HEALTHY state, so it must not by itself make a clean run's ledger
    // non-empty (the omitempty discipline); only a DEGRADED verdict counts as evidence.
    (l.snapshotConsistency === undefined || l.snapshotConsistency === "pinned") &&
    (l.rowidProbeFallbacks ?? 0) === 0 &&
    Object.keys(l.d1Defects ?? {}).length === 0 &&
    // `configured` and `auto` are the HEALTHY selector modes, so neither by itself makes a clean run's ledger
    // non-empty; only the stale fail-safe (the cost explosion) counts as evidence.
    (l.cfSelectorMode === undefined || l.cfSelectorMode !== "stale-fallback-all") &&
    Object.keys(l.resumeTokenDefects ?? {}).length === 0 &&
    (l.throttle429Count ?? 0) === 0 &&
    (l.retryExhaustedCount ?? 0) === 0 &&
    Object.keys(l.securityRefusals ?? {}).length === 0
  );
}

// mergeSourceFaultLedgers folds b into a (a fresh result, neither input mutated) with the SAME dedup/cap/clamp
// discipline as the writers, so the sliced seal can accumulate a multi-invocation crawl's faults across slices
// (the analogue of addCheckpointCounts / mergeIncompleteIds).
export function mergeSourceFaultLedgers(a: SourceFaultLedger, b: SourceFaultLedger): SourceFaultLedger {
  const out = cloneLedger(a);
  for (const k of Object.keys(b.incompleteReasons) as MarkerKey[]) {
    const src = b.incompleteReasons[k] ?? {};
    let dst = out.incompleteReasons[k];
    if (dst === undefined) {
      dst = {};
      out.incompleteReasons[k] = dst;
    }
    for (const r of Object.keys(src) as SourceFaultReason[]) dst[r] = clamp((dst[r] ?? 0) + (src[r] ?? 0));
  }
  for (const k of Object.keys(b.incompleteIds) as MarkerKey[]) for (const id of b.incompleteIds[k] ?? []) addId(out.incompleteIds, k, id);
  out.shapeAnomalies = clamp(out.shapeAnomalies + b.shapeAnomalies);
  for (const id of b.shapeAnomalyIds) if (out.shapeAnomalyIds.length < FAULT_IDS_MAX_PER_KIND && !out.shapeAnomalyIds.includes(id)) out.shapeAnomalyIds.push(id);
  if (b.truncation !== undefined && (out.truncation === undefined || b.truncation.recordsAccumulated > out.truncation.recordsAccumulated)) out.truncation = { ...b.truncation };
  if (b.oldestPendingAgeMs !== undefined && (out.oldestPendingAgeMs === undefined || b.oldestPendingAgeMs > out.oldestPendingAgeMs)) out.oldestPendingAgeMs = b.oldestPendingAgeMs;
  if (b.fatal !== undefined) out.fatal = { ...b.fatal };
  // Worst-wins: one re-anchored slice colours the whole multi-slice run (G096).
  const snap = worseSnapshot(out.snapshotConsistency, b.snapshotConsistency);
  if (snap !== undefined) out.snapshotConsistency = snap;
  // `b` is read defensively for the same version-skew reason cloneLedger documents: it may be a snapshot an
  // OLDER engine wrote, with none of these fields.
  out.rowidProbeFallbacks = clamp(out.rowidProbeFallbacks + (b.rowidProbeFallbacks ?? 0));
  const bDefects = b.resumeTokenDefects ?? {};
  for (const d of Object.keys(bDefects) as ResumeTokenDefect[]) {
    out.resumeTokenDefects[d] = clamp((out.resumeTokenDefects[d] ?? 0) + (bDefects[d] ?? 0));
  }
  for (const t of b.resumeTokenSourceTypes ?? []) {
    if (out.resumeTokenSourceTypes.length < FAULT_IDS_MAX_PER_KIND && !out.resumeTokenSourceTypes.includes(t)) out.resumeTokenSourceTypes.push(t);
  }
  out.throttle429Count = clamp(out.throttle429Count + (b.throttle429Count ?? 0));
  out.retryExhaustedCount = clamp(out.retryExhaustedCount + (b.retryExhaustedCount ?? 0));
  if (b.maxRetryAfterSeconds !== undefined && (out.maxRetryAfterSeconds === undefined || b.maxRetryAfterSeconds > out.maxRetryAfterSeconds)) {
    out.maxRetryAfterSeconds = b.maxRetryAfterSeconds;
  }
  const bRefusals = b.securityRefusals ?? {};
  for (const k of Object.keys(bRefusals) as SourceSecurityRefusalKind[]) {
    out.securityRefusals[k] = clamp((out.securityRefusals[k] ?? 0) + (bRefusals[k] ?? 0));
  }
  const bD1 = b.d1Defects ?? {};
  for (const k of Object.keys(bD1) as D1DefectClass[]) {
    out.d1Defects[k] = clamp((out.d1Defects[k] ?? 0) + (bD1[k] ?? 0));
  }
  for (const t of b.d1DefectTables ?? []) {
    if (out.d1DefectTables.length < FAULT_IDS_MAX_PER_KIND && !out.d1DefectTables.includes(t)) out.d1DefectTables.push(t);
  }
  // The selector mode is per-RUN, not per-slice, so a later slice's mode simply wins -- except that the stale
  // fail-safe is WORSE than either healthy mode and must never be masked by a slice that ran narrow.
  if (b.cfSelectorMode !== undefined && (out.cfSelectorMode === undefined || b.cfSelectorMode === "stale-fallback-all")) out.cfSelectorMode = b.cfSelectorMode;
  return out;
}

// ---- CLASSIFIERS ------------------------------------------------------------------------------------
// Both classifiers are STRUCTURAL (they read `name` + the coarse fields a thrown error already carries) rather
// than importing CfApiError / CfPaginationTruncated / SourceResourceMissingError, so this leaf stays free of a
// cycle with the modules that record into it. The error MESSAGE is consulted ONLY to pick an enum member for
// the errors that carry no structured status (a network throw, a size-cap guard); it is never stored.

interface CoarseErrorShape {
  name?: unknown;
  status?: unknown;
  planEntitlementGated?: unknown;
  retryAfterMs?: unknown;
  message?: unknown;
  pagesRead?: unknown;
  accumulated?: unknown;
  kind?: unknown; // SourceResourceMissingError's SourceLivenessKind
}

function shapeOf(e: unknown): CoarseErrorShape {
  return (e && typeof e === "object" ? e : {}) as CoarseErrorShape;
}
function messageOf(e: unknown): string {
  const m = shapeOf(e).message;
  return typeof m === "string" ? m : "";
}

const SIZE_CAP_RE = /exceeds the \d+-byte limit|exceeds the .*size|too large/i;
const NETWORK_RE = /fetch failed|network|socket|ECONN|ETIMEDOUT|timed? ?out|aborted/i;

/**
 * classifyD1Defect coarsens a D1 decode / validation / cell-encoding refusal into a closed D1DefectClass
 * (G069). It reads the message ONLY to match the ENGINE'S OWN throw literals (d1-format.ts, d1-reader.ts --
 * never a provider message) and RETURNS the enum. The message, which embeds the customer's TABLE NAME, the
 * DDL text, the cell value and the position, never leaves this function and can never reach a record.
 *
 * ORDER is load-bearing: the multi-statement DDL test runs FIRST, because a tamper signature must never be
 * absorbed into the generic `shape` bucket by a later, looser match.
 *
 * @param e - the thrown fault.
 * @returns the closed class, or null when the fault is not a D1 defect at all.
 */
export function classifyD1Defect(e: unknown): D1DefectClass | null {
  const m = messageOf(e);
  if (m === "") return null;
  // TAMPER first: an archive whose CREATE statement carries a second statement is not a writer bug.
  if (/more than one statement|content after its terminating|unterminated BEGIN or CASE|is not a CREATE TABLE statement/i.test(m)) return "multi-statement-ddl";
  // VERSION SKEW: the archive was written by an engine this one does not understand (e.g. after a rollback).
  if (/unsupported D1 (backup|record) format/i.test(m)) return "unknown-format";
  if (/non-finite numeric value/i.test(m)) return "non-finite-real";
  if (/unsupported array shape|cell of unsupported type/i.test(m)) return "unsupported-type";
  if (/non-integer rowid/i.test(m)) return "bad-rowid";
  if (/exceeds the \d+-byte page limit|too large to carry in one record/i.test(m)) return "giant-row";
  if (/is not valid JSON/i.test(m)) return "bad-json";
  if (/base64|atob|InvalidCharacterError/i.test(m)) return "bad-base64";
  if (/D1 (backup|rows|cell|schema)|malformed (cell|column list|rows list)|has no (name|CREATE statement|tables array|schema array)|is not an object|cell count does not match/i.test(m)) return "shape";
  return null;
}

// isPaginationTruncated: a CfPaginationTruncated by structure (name + the two magnitude fields), so callers
// can read the shortfall magnitude without importing the class.
export function paginationMagnitude(e: unknown): { pagesRead: number; recordsAccumulated: number } | undefined {
  const s = shapeOf(e);
  if (s.name !== "CfPaginationTruncated") return undefined;
  return { pagesRead: clamp(typeof s.pagesRead === "number" ? s.pagesRead : 0), recordsAccumulated: clamp(typeof s.accumulated === "number" ? s.accumulated : 0) };
}

// classifySourceFaultReason maps a raw throw into the closed reason vocabulary. Order matters: the specific,
// structured verdicts (an entitlement gate, a pagination cap) come before the status ranges, and the message
// sniffs come last, so an unrecognised fault degrades to "other" rather than being mislabelled.
export function classifySourceFaultReason(e: unknown): SourceFaultReason {
  const s = shapeOf(e);
  if (s.name === "CfPaginationTruncated") return "page-cap";
  if (s.planEntitlementGated === true) return "entitlement";
  // A CfApiError (cf-config) and a media/Workers failFor error both carry the HTTP status as a bare integer;
  // read it structurally so ONE classifier serves both clients.
  if (typeof s.status === "number" && s.status > 0) {
    const st = s.status;
    if (st === 401 || st === 403) return "auth";
    if (st === 404) return "not-found";
    if (st === 429) return "rate-limited";
    if (st >= 500) return "server-error";
    return "other";
  }
  if (s.name === "SourceResourceMissingError") {
    if (s.kind === "deleted") return "not-found";
    if (s.kind === "misconfigured") return "shape";
    return "other";
  }
  if (typeof s.retryAfterMs === "number") return "rate-limited"; // the rateLimitError shape (seal/retry.ts)
  // The size guards throw a plain Error (they are the engine's OWN buffered-capture ceiling, not a CF fault),
  // so the ONLY way to tell "we refused to buffer this" from a generic fault is its own message shape. The
  // message is matched and DISCARDED; only the enum member is recorded.
  if (SIZE_CAP_RE.test(messageOf(e))) return "size-cap";
  return "other";
}

// classifySourceFaultStatus maps a raw throw into the closed transport-verdict vocabulary used on the FATAL
// path (G144). It is the answer to "token rotated: expired, under-scoped, or is Cloudflare down?".
export function classifySourceFaultStatus(e: unknown): SourceFaultStatusClass {
  const s = shapeOf(e);
  if (s.planEntitlementGated === true) return "entitlement";
  if (typeof s.status === "number" && s.status > 0) {
    const st = s.status;
    if (st === 401) return "401";
    if (st === 403) return "403";
    if (st === 404) return "404";
    if (st === 429) return "429";
    if (st >= 500) return "5xx";
    return "other";
  }
  if (s.name === "CfPaginationTruncated") return "shape";
  if (s.name === "SourceResourceMissingError") {
    if (s.kind === "deleted") return "404";
    if (s.kind === "misconfigured") return "shape";
    return "other";
  }
  if (typeof s.retryAfterMs === "number") return "429";
  if (s.name === "TypeError" || NETWORK_RE.test(messageOf(e))) return "network";
  return "other";
}
