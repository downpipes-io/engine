import { b64urlEncode } from "../crypto/bytes.ts";
import type { DestProvider } from "../dest/provider.ts";
import { immutabilityEnableWhen, immutabilityMechanism, immutabilityStoreNoun } from "../dest/worm-remedy.ts";
import { hybridSign } from "../crypto/sign.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { Signer } from "../format/writer.ts";
import type { DownpipeState, DrillEvidenceEntry, RestoreProvenMethod } from "../sched/types.ts";
import type { AuditEvent } from "./audit-types.ts";
import { type Framework, PACK_SCOPE_STATEMENT } from "./frameworks.ts";
import type { PostureCheck, PostureReport, PostureSeverity, PostureStatus } from "./posture.ts";

// Reporting (contract section 6). Five ReportKind generators read the account's observable state
// (audit / drill-evidence / status / downpipes / posture) and produce a structured, redaction-safe
// Report. The report is then SIGNED with the engine signer (crypto/sign.ts), so it is tamper-evident
// and an auditor can verify it. The generators are PURE over their gathered inputs (the same
// pure-logic-plus-DO separation the rest of the admin surface uses): the DO/router gathers the inputs
// and calls these; the data shaping and the canonical signing live here so they cannot drift.
//
// NO-CUSTODY + REDACTION (sacred). Every report body carries ONLY redaction-safe projections: counts,
// recency timestamps, coarse states, downpipe names/ids (the customer's own config), the named
// destination kind enum, and the posture checks (themselves redaction-safe). NO report can carry a key,
// value, fingerprint, selector, endpoint or credential; the input types have no such field. The audit
// projection drops the hash chain and keeps only the redaction-safe action/outcome/actor surface.
//
// PRECISE CLAIMS (house style). The immutability report is an ATTESTATION of the recoverability
// properties actually in force (post-quantum hybrid sealing, tamper-evident signing, the destination's
// real WORM support), never a false WORM/tamper-proof claim. The signature is "tamper-evident, signed".
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations.
// exactOptionalPropertyTypes: optional keys are spread in only when they carry a value.

// ReportKind is the closed set of reports (contract section 6). evidence-pack is the framework-organised
// compliance pack: the posture report re-projected through a framework's control mapping (frameworks.ts),
// so an auditor sees, per control, the obligation, how downpipes supports it, and the LIVE result of the
// posture checks that evidence it. It is point-in-time and signed like posture/immutability.
// REPORT_KINDS is the single source of truth for the closed set: the union type and the runtime guard
// (isReportKind) both derive from it, so adding a kind updates both at once and they cannot drift.
const REPORT_KINDS = ["restore-tests", "sla-compliance", "immutability", "posture", "evidence-pack", "change-requests"] as const;
export type ReportKind = (typeof REPORT_KINDS)[number];

// Report is the signed report envelope. period is null for a point-in-time report (posture,
// immutability) or a {fromSeconds,toSeconds} window for the time-bounded ones. data is the per-kind body
// (see the *Data interfaces below). signature is "edmldsa1:<b64url>" over canonicalJSON of the
// signed-over view {kind,generatedAt,period,data}; it is OPTIONAL because signing is fail-open: when no
// signer is configured the report is still returned, honestly unsigned (the data is valuable even
// without a signature, and a missing signer must never 500 a read). The signature is a public detached
// value; it carries no private key material.
export interface Report {
  kind: ReportKind;
  generatedAt: string;
  period: { fromSeconds: number; toSeconds: number } | null;
  data: unknown; // per-kind structured body (see below)
  signature?: string; // "edmldsa1:..." hybrid signature over canonicalJSON({kind,generatedAt,period,data})
}

// SIGNATURE_SCHEME_PREFIX tags the report signature with the codebase's hybrid scheme id (the same
// "edmldsa1:" tag the writer uses for the signer fingerprint), so a verifier knows the scheme before
// decoding. The value after the colon is b64url(ed25519Sig(64) || mldsaSig), the exact detached layout
// hybridSign produces and hybridVerify checks.
const SIGNATURE_SCHEME_PREFIX = "edmldsa1:";

// ---- Per-kind data shapes (contract section 6) -----------------------------------------------------

// RestoreTestRecency is the per-downpipe last-test recency line (lastRestoreTestAt/Ok from the downpipe
// state). lastRestoreTestAt/Ok are omitted when the downpipe has never had a scheduled test.
//
// COMPLIANCE-STAMP: restoreProvenAt/By/Method, lastRestoreTestKind/SampleRate and lastRestoreTestDeferred
// carry the durable keyed attested-verification stamp (DownpipeState.restoreProven) and the recency
// completion's own provenance directly from the state, so an auditor reading this signed report can plainly
// separate "restorability proven by a KEYED attended verify" from "a scheduled drill" -- and never the other
// way around: restoreProvenMethod is present ONLY when the engine actually stamped a proof (see
// recordAttendedVerification's full conjunction: a full, 100%-sample, PROVEN-SESSION pass with a real runId),
// never inferred from a bare scheduled pass. All honestly absent when the downpipe has never been proven or
// tested that way. Redaction-safe: timestamps, a verified email (never a key or subject), closed enums, an
// int.
export interface RestoreTestRecency {
  id: string;
  name: string;
  lastRestoreTestAt?: number; // epoch ms
  lastRestoreTestOk?: boolean;
  restoreProvenAt?: number; // epoch ms the keyed/blind proof passed (DownpipeState.restoreProven.at)
  restoreProvenBy?: string | null; // the prover's verified email; null for the unattributable bare-token
  restoreProvenMethod?: RestoreProvenMethod; // present ONLY for a genuine stamped proof; never fabricated
  lastRestoreTestKind?: "scheduled" | "attended"; // how the recency fields above were produced
  lastRestoreTestSampleRate?: number; // attended sample percentage (1..100; 100 = every record)
  // lastRestoreTestDeferred distinguishes a DEFERRAL (no in-account key, or no completed run yet) from a
  // genuine not-ok completion, so the PDF and any downstream reader never mistakes "could not test" for
  // "tested and failed".
  lastRestoreTestDeferred?: "no-run" | "posture" | "no-records";
}

// DrillEvidenceView is the redaction-safe projection of a drill-evidence entry for the report (the entry
// is already redaction-safe; this is a stable view that drops nothing sensitive because there is nothing
// sensitive to drop). note is carried only when present.
export interface DrillEvidenceView {
  runId: string;
  kind: "in-account" | "offline-rehearsal";
  recordedAt: string;
  recordedBy: string | null;
  note?: string;
}

// RestoreTestsData is the restore-tests report body: the drill-evidence entries in the period (pass/fail
// inferred from the note + kind) plus the per-downpipe last-test recency.
export interface RestoreTestsData {
  recency: RestoreTestRecency[];
  evidence: DrillEvidenceView[];
  // attendedCadenceDays is the estate-wide interval the organisation STATED it will prove recoverability
  // within, in whole days, or 0 when none is stated (design/opkey-reduction/ATTENDED-CADENCE.md).
  //
  // It is here because a report that grades recency without carrying the TARGET is not self-contained: an
  // auditor reading it can see when each downpipe was last proven and cannot tell whether that meets what the
  // estate committed to. 0 is reported as 0 and means no stated rhythm, which is honestly different from a
  // zero-day one and must not be rendered as a missed target.
  //
  // Redaction-safe: one integer.
  attendedCadenceDays: number;
}

// SlaDownpipeRow is the per-downpipe SLA line: expected vs successful run counts over the period,
// freshness, and a strikes count (consecutive recent failures / staleness, a coarse health signal).
//   fresh is the RPO/recovery-point signal (the last successful run is within one cadence of now).
//   rtoEstimateSeconds / rtoBasedOnDrills are the RTO companion (E4/C1): the derived recovery-time estimate
//     and the "based on N drills" sample count, surfaced NEXT TO the freshness/RPO signal so an SLA report
//     answers both "how recent is the last copy" (RPO) and "how long to recover it" (RTO). They are present
//     ONLY when an estimate could be DERIVED from observed drill throughput; honestly ABSENT (no fabricated
//     number) when the downpipe has no restore-test history, the same honest-unknown rule the RTO route uses.
//   windowFromSeconds / windowToSeconds are the ACTUAL window expectedRuns was computed over, in epoch
//     seconds -- not necessarily the report's own period. A downpipe that already existed for the whole
//     period reports the period unchanged; one created (or, for a record from before createdAt shipped,
//     whose earliest recorded run started) partway through it has windowFromSeconds clamped FORWARD to
//     that start, so a downpipe 3.5 hours old at hourly cadence reads "expected 4 over a 3.5-hour window"
//     rather than "expected 2160 over 90 days" (the day-one ~0.2%-compliant misread this field exists to
//     fix -- see buildSlaComplianceReport). Present only when the report carries a period; a null,
//     point-in-time period leaves both absent, matching expectedRuns's own null-period fallback to 0.
//   windowStartBasis (closed, redaction-safe) says WHY windowFromSeconds is what it is: "period" when the
//     downpipe existed for the whole report period (no clamp applied), "createdAt" when clamped to the
//     downpipe's recorded creation time, or "earliest-run" when createdAt is absent (a record from before
//     this field shipped) and the earliest run its history ring still holds stood in instead -- a later,
//     more conservative start than the true creation time, never an earlier one.
export interface SlaDownpipeRow {
  id: string;
  name: string;
  expectedRuns: number;
  successfulRuns: number;
  strikes: number;
  fresh: boolean;
  rtoEstimateSeconds?: number;
  rtoBasedOnDrills?: number;
  windowFromSeconds?: number;
  windowToSeconds?: number;
  windowStartBasis?: "period" | "createdAt" | "earliest-run";
}

// SlaComplianceData is the sla-compliance report body.
export interface SlaComplianceData {
  downpipes: SlaDownpipeRow[];
}

// ImmutabilityDestination is one configured destination's recoverability property (an honest attestation,
// not a false WORM claim): the destination kind and whether a WORM/immutability property is actually in
// force. Without a probe-confirmed store lock the property is the platform's own tamper-evidence (signed,
// hash-chained), stated precisely.
export interface ImmutabilityDestination {
  // The four supported providers, or "none" when no destination is configured.
  kind: DestProvider | "none";
  configured: boolean;
  property: string; // the precise recoverability/immutability property in force
}

// ImmutabilityData is the immutability report body: the attestation paragraph plus the per-destination
// property and the break-glass/operational posture.
export interface ImmutabilityData {
  attestation: string;
  destinations: ImmutabilityDestination[];
  breakGlassConfigured: boolean;
  operationalPrivatePresent: boolean;
}

// ---- evidence-pack: framework-organised compliance pack (the posture report by control) ------------

// EvidencePackCheck is one posture check's LIVE result as it appears under a control. status is the real
// posture status, or "not-evaluated" when a mapped check id is not present in this report (defensive: a
// mapping typo yields an honest not-evaluated, never a fabricated pass). note carries the owner's
// override statement when one is recorded (e.g. "Pass (customer attested): MFA is enforced at our IdP -
// attested by o@example.com, "), so an auditor reading the pack sees WHO graded the control,
// HOW and WHY, clearly labelled as the customer's determination and never a platform verification.
export interface EvidencePackCheck {
  id: string;
  title: string;
  status: PostureStatus | "not-evaluated";
  severity?: PostureSeverity;
  note?: string;
}

// EvidencePackControl is one control row resolved against the live posture: the citation, the obligation,
// how downpipes supports it, and the live result of each bound check (empty for a capability-only row).
export interface EvidencePackControl {
  control: string;
  obligation: string;
  capability: string;
  checks: EvidencePackCheck[];
}

// EvidencePackSummary is the per-framework roll-up of the pack: control coverage and the live check tally.
export interface EvidencePackSummary {
  controlsTotal: number; // every control in the framework mapping
  controlsEvidenced: number; // controls bound to at least one posture check
  checksTotal: number; // bound checks resolved across all controls
  checksPassing: number; // resolved checks with status "pass" (platform-verified)
  checksFailing: number; // resolved checks with status "fail"
  checksAccepted: number; // resolved checks graded by the customer as satisfied or accepted: risk-accepted, attested-pass, compensating-control or resolved-alternative
  checksNotApplicable: number; // resolved checks the customer determined not applicable (excluded from the score)
  checksUnattested: number; // resolved checks awaiting the customer's attestation (the platform cannot verify them automatically)
}

// EvidencePackFramework is one framework's section of the pack.
export interface EvidencePackFramework {
  frameworkId: string;
  frameworkTitle: string;
  frameworkDescription: string;
  controls: EvidencePackControl[];
  sources: { label: string; href: string }[];
  summary: EvidencePackSummary;
}

// EvidencePackData is the evidence-pack report body: one or more framework sections (one for a single
// framework, all for the "all" pack), the shared no-custody scope statement, and the overall posture
// score for context. generatedFor is the framework id, or "all". Every field is redaction-safe (static
// framework reference text + the already-redaction-safe posture statuses; no key, value or credential).
export interface EvidencePackData {
  generatedFor: string;
  scope: string;
  postureScore: number;
  packs: EvidencePackFramework[];
}

// buildEvidencePackReport (pure): re-project the posture report through one or more frameworks' control
// mappings. For each control it resolves the bound posture check id(s) to their live status from this
// report, so the pack states the tenant's REAL posture per control rather than a generic capability
// claim. Capability-only rows (no bound check) carry an empty checks list and still appear, so the pack
// is complete. No claim exceeds the framework mapping; a missing check id is reported "not-evaluated".
export function buildEvidencePackReport(frameworks: Framework[], posture: PostureReport, generatedFor: string): EvidencePackData {
  const byId = new Map<string, PostureCheck>(posture.checks.map((c) => [c.id, c]));
  const packs: EvidencePackFramework[] = frameworks.map((fw) => {
    let controlsEvidenced = 0;
    let checksTotal = 0;
    let checksPassing = 0;
    let checksFailing = 0;
    let checksAccepted = 0;
    let checksNotApplicable = 0;
    let checksUnattested = 0;
    const controls: EvidencePackControl[] = fw.controls.map((row) => {
      if (row.checkIds.length > 0) controlsEvidenced++;
      const checks: EvidencePackCheck[] = row.checkIds.map((id) => {
        const c = byId.get(id);
        if (c === undefined) return { id, title: id, status: "not-evaluated" };
        const note = overrideNote(c);
        return { id: c.id, title: c.title, status: c.status, severity: c.severity, ...(note !== null ? { note } : {}) };
      });
      for (const ch of checks) {
        checksTotal++;
        if (ch.status === "pass") checksPassing++;
        else if (ch.status === "fail") checksFailing++;
        else if (ch.status === "not-applicable") checksNotApplicable++;
        else if (ch.status === "unattested") checksUnattested++;
        else if (ch.status === "risk-accepted" || ch.status === "resolved-alternative" || ch.status === "attested-pass" || ch.status === "compensating-control") checksAccepted++;
      }
      return { control: row.control, obligation: row.obligation, capability: row.capability, checks };
    });
    return {
      frameworkId: fw.id,
      frameworkTitle: fw.title,
      frameworkDescription: fw.description,
      controls,
      sources: fw.sources,
      summary: { controlsTotal: fw.controls.length, controlsEvidenced, checksTotal, checksPassing, checksFailing, checksAccepted, checksNotApplicable, checksUnattested },
    };
  });
  return { generatedFor, scope: PACK_SCOPE_STATEMENT, postureScore: posture.score, packs };
}

// postureStatusLabel renders a posture status as the human phrase the reports and PDFs print. It NEVER
// prints a bare "fail" for a customer-graded check: an override reads as what the customer chose ("pass
// (customer attested)", "pass (compensating control)", "not applicable (N/A)"), a deliberate risk stays
// "risk accepted" (an accepted risk is stated as such, never dressed up as a pass), and a control the
// platform cannot verify reads "needs attestation" rather than a failure the operator cannot clear.
export function postureStatusLabel(status: PostureStatus | "not-evaluated"): string {
  switch (status) {
    case "pass": return "pass";
    case "fail": return "fail";
    case "unattested": return "needs attestation";
    case "risk-accepted": return "risk accepted";
    case "attested-pass": return "pass (customer attested)";
    case "compensating-control": return "pass (compensating control)";
    case "not-applicable": return "not applicable (N/A)";
    case "resolved-alternative": return "pass (alternative control)";
    case "not-evaluated": return "not evaluated";
  }
}

// overrideNote renders a check's owner override as the one-line, clearly-attributed statement the
// evidence pack (and the PDF) carries: what the customer graded, why, who and when. Returns null when no
// override is recorded. The date is the day part of the RFC-3339 setAt (redaction-safe operator metadata).
export function overrideNote(check: PostureCheck): string | null {
  const o = check.override;
  if (o === undefined) return null;
  const label =
    o.kind === "attested-pass" ? "Pass (customer attested)"
    : o.kind === "compensating-control" ? "Pass (compensating control)"
    : o.kind === "not-applicable" ? "Not applicable (customer determination)"
    : "Risk accepted";
  const by = o.setBy !== null ? ` - recorded by ${o.setBy}` : " - recorded via break-glass token";
  const on = o.setAt.length >= 10 ? `, ${o.setAt.slice(0, 10)}` : "";
  const dormant = check.autoStatus === "pass" ? " (the automatic check currently passes on its own)" : "";
  return `${label}: ${o.reason}${by}${on}${dormant}`;
}

// ---- Input bundles the DO/router gathers and the generators read (pure over these) -----------------

// ReportPeriod is the optional time window a time-bounded report covers (restore-tests, sla-compliance).
// fromSeconds/toSeconds are epoch seconds. The router derives a sensible default window (e.g. the last 90
// days) when the caller does not supply one; the generators treat null as "all time".
export type ReportPeriod = { fromSeconds: number; toSeconds: number } | null;

// StatusForReport is the slice of the status report the immutability generator reads (presence booleans +
// the selected destination kind), shaped loosely so reports.ts does not import status.ts (no cycle).
export interface StatusForReport {
  destConfigured: boolean;
  destKind: DestProvider | null;
  breakGlassConfigured: boolean;
  operationalConfigured: { public: boolean; private: boolean };
}

// WormForReport is the REAL WORM/Object-Lock signal the immutability report can now carry (the router
// gathers it: config + the live capability probe). When present it lets the report state store-enforced
// immutability HONESTLY (enforced / configured-but-unenforced / not-configured) rather than always falling
// back to "tamper-evidence only". Shaped with inline literals so reports.ts stays free of a dest import; it
// mirrors the posture worm slice. Absent => the report degrades to the prior tamper-evidence statement.
export interface WormForReport {
  configured: boolean;
  misconfigured: boolean;
  mode?: "governance" | "compliance";
  retentionDays?: number;
  bucketEnforces?: boolean | "unknown";
  probeMode?: "governance" | "compliance";
  probeDays?: number;
  // defaultRetention is whether the LOCK-ENABLED bucket carries a DEFAULT RETENTION RULE of its own, read
  // by the same probe (router-posture.ts) and set only when bucketEnforces is true. It is the fourth axis
  // the strong claim below depends on and used to be missing here: ObjectLockEnabled does not retain
  // anything by itself, so an archive written with no retention header to a lock-enabled bucket with no
  // default rule has no retention window at all. Honestly absent means the rule could not be read, which
  // is a cannot-confirm state and never a substitute for either boolean.
  defaultRetention?: boolean;
}

// buildRestoreTestsReport (pure): the drill-evidence entries within the period plus the per-downpipe
// last-test recency. An entry is "in period" when its recordedAt falls in [from,to] (or always when the
// period is null). The pass/fail is left to the consumer to infer from kind+note (the evidence log does
// not store a boolean; the recency on the downpipe state carries the authoritative last outcome). Sorted
// newest-evidence-first and downpipes by name for a stable report.
export function buildRestoreTestsReport(downpipes: DownpipeState[], evidence: DrillEvidenceEntry[], period: ReportPeriod, attendedCadenceDays = 0): RestoreTestsData {
  const inPeriod = evidence.filter((e) => withinPeriod(e.recordedAt, period));
  const evidenceView: DrillEvidenceView[] = inPeriod
    .map((e) => ({
      runId: e.runId,
      kind: e.kind,
      recordedAt: e.recordedAt,
      recordedBy: e.recordedBy,
      ...(e.note !== undefined ? { note: e.note } : {}),
    }))
    .sort((a, b) => (a.recordedAt < b.recordedAt ? 1 : a.recordedAt > b.recordedAt ? -1 : 0));
  const recency: RestoreTestRecency[] = downpipes
    .map((d) => ({
      id: d.config.id,
      name: d.config.name,
      ...(d.lastRestoreTestAt !== undefined ? { lastRestoreTestAt: d.lastRestoreTestAt } : {}),
      ...(d.lastRestoreTestOk !== undefined ? { lastRestoreTestOk: d.lastRestoreTestOk } : {}),
      // The durable keyed attested-verification stamp, read straight off the state (no gather change
      // needed: this generator already receives the full DownpipeState[]). restoreProvenMethod is present
      // ONLY when the engine actually stamped a proof; a scheduled-only pass carries none of these fields.
      ...(d.restoreProven !== undefined
        ? { restoreProvenAt: d.restoreProven.at, restoreProvenBy: d.restoreProven.by, restoreProvenMethod: d.restoreProven.method }
        : {}),
      ...(d.lastRestoreTestKind !== undefined ? { lastRestoreTestKind: d.lastRestoreTestKind } : {}),
      ...(d.lastRestoreTestSampleRate !== undefined ? { lastRestoreTestSampleRate: d.lastRestoreTestSampleRate } : {}),
      ...(d.lastRestoreTestDeferred !== undefined ? { lastRestoreTestDeferred: d.lastRestoreTestDeferred } : {}),
    }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { recency, evidence: evidenceView, attendedCadenceDays: attendedCadenceDays > 0 ? Math.floor(attendedCadenceDays) : 0 };
}

// buildSlaComplianceReport (pure): per-downpipe expected-vs-successful run counts over the period, plus
// freshness and a strikes count. The expected count is derived from the cadence and the period length
// (how many runs SHOULD have happened); the successful count comes from the audit/run signal the DO
// gathers. We read the redaction-safe per-downpipe figures the DO supplies in `runStats` rather than
// re-deriving from raw runs here (the DO holds the run ring; this stays pure over the gathered figures).
// `fresh` is whether the last successful run is within one cadence of `now`; strikes is the DO's coarse
// consecutive-failure/staleness count. With no period the expected count is 0 (cannot bound a window).
// rtoEstimates (OPTIONAL) maps downpipeId -> the DERIVED RTO estimate, so the SLA report can surface the
// recovery-time figure NEXT TO the freshness/RPO signal. The DO derives each (from observed drill
// throughput + archive size) and passes the map; a caller that does not supply it (or a downpipe with no
// derivable estimate) leaves the rto fields honestly absent. estimateSeconds/basedOnDrills are spread in
// only when known is true, so an unknown RTO never becomes a fabricated 0.
// earliestRunSeconds (OPTIONAL) maps downpipeId -> the epoch-seconds start time of the OLDEST run its
// history ring still holds, for the ONLY downpipes that need it: those with no d.createdAt (a record
// written before that field shipped). d.createdAt is read directly off the state when present and takes
// priority; this map is the fallback the DO derives from the same `hist:` run-history ring slaReportData
// already reads for successfulRuns, so a legacy downpipe still gets a real (if more conservative) start
// instead of falling through to the bare, unclamped report period.
export function buildSlaComplianceReport(
  downpipes: DownpipeState[],
  runStats: Map<string, { successfulRuns: number; strikes: number; lastSuccessAt?: number }>,
  period: ReportPeriod,
  now: number,
  rtoEstimates?: Map<string, { known: boolean; estimateSeconds?: number; basedOnDrills?: number }>,
  earliestRunSeconds?: Map<string, number>,
): SlaComplianceData {
  const rows: SlaDownpipeRow[] = downpipes
    .map((d) => {
      const cadence = d.config.cadenceSeconds;
      // effectiveStartSeconds is when THIS downpipe's own existence began, if known: its recorded
      // creation time, or -- for a record from before createdAt shipped -- the earliest run its history
      // ring still holds. Undefined when neither is known (a legacy downpipe that has never run either),
      // in which case the row falls back to the bare report period exactly as before this fix: honestly
      // ungrounded rather than fabricated, never worse than the pre-fix behaviour.
      let effectiveStartSeconds: number | undefined;
      let startBasis: "createdAt" | "earliest-run" | undefined;
      if (d.createdAt !== undefined) {
        effectiveStartSeconds = Math.floor(d.createdAt / 1000);
        startBasis = "createdAt";
      } else {
        const earliest = earliestRunSeconds?.get(d.config.id);
        if (earliest !== undefined) {
          effectiveStartSeconds = earliest;
          startBasis = "earliest-run";
        }
      }
      // expectedRuns is the NOMINAL count the configured cadence owes over the WINDOW THIS DOWNPIPE COULD
      // ACTUALLY HAVE RUN IN, which is the contractual MINIMUM and deliberately not the count the
      // scheduler will actually perform. The window is the report period clamped forward to
      // effectiveStartSeconds when that is later than the period's own start -- a downpipe created (or,
      // absent createdAt, first observed running) partway through the period was never owed a run before
      // that point, so counting the whole period against it would overstate the missed-run count for a
      // newly created downpipe.
      // The cadence path also jitters BACKWARDS (schedule-window.ts jitteredCadence), so real gaps fall in
      // (0.9 x cadence, cadence] and a healthy downpipe over-delivers: about 31.6 runs against a nominal
      // 30 for a daily pipe over 30 days. successfulRuns EXCEEDING expectedRuns is therefore normal
      // over-delivery, not a corrupt figure, and both are rendered as bare counts (no ratio is computed
      // anywhere, see pdf.ts). Do NOT "correct" the divisor to cadence * 0.9: that yields 33 for the same
      // window, above the ~31.6 a healthy pipe actually achieves, so every compliant downpipe would start
      // reporting missed runs.
      let expected = 0;
      let windowFields: Pick<SlaDownpipeRow, "windowFromSeconds" | "windowToSeconds" | "windowStartBasis"> = {};
      if (period) {
        const clampedFrom = effectiveStartSeconds !== undefined ? Math.max(period.fromSeconds, effectiveStartSeconds) : period.fromSeconds;
        expected = cadence > 0 ? Math.max(0, Math.floor((period.toSeconds - clampedFrom) / cadence)) : 0;
        windowFields = {
          windowFromSeconds: clampedFrom,
          windowToSeconds: period.toSeconds,
          // "period" when nothing clamped it forward (the downpipe existed for the whole period), even if
          // effectiveStartSeconds is known -- an auditor reading "period" should be able to trust that the
          // full period was graded, not wonder whether a known-but-inert start basis quietly narrowed it.
          windowStartBasis: clampedFrom > period.fromSeconds && startBasis !== undefined ? startBasis : "period",
        };
      }
      const stats = runStats.get(d.config.id) ?? { successfulRuns: 0, strikes: 0 };
      // Fresh when the last successful run is within one cadence of now (the same staleness notion the
      // alerting uses), and the downpipe is enabled (a disabled downpipe is not expected to be fresh).
      const fresh = d.config.enabled && stats.lastSuccessAt !== undefined && now - stats.lastSuccessAt <= cadence * 1000;
      // The RTO companion to the RPO/freshness signal: surfaced only when an estimate was derivable (known),
      // honestly absent otherwise (no fabricated number for a downpipe with no drill history).
      const rto = rtoEstimates?.get(d.config.id);
      const rtoFields = rto?.known && typeof rto.estimateSeconds === "number"
        ? { rtoEstimateSeconds: rto.estimateSeconds, ...(typeof rto.basedOnDrills === "number" ? { rtoBasedOnDrills: rto.basedOnDrills } : {}) }
        : {};
      return {
        id: d.config.id,
        name: d.config.name,
        expectedRuns: expected,
        successfulRuns: stats.successfulRuns,
        strikes: stats.strikes,
        fresh,
        ...rtoFields,
        ...windowFields,
      };
    })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { downpipes: rows };
}

// buildImmutabilityReport (pure): an honest attestation of recoverability. It states the platform
// properties in force (post-quantum hybrid sealing, tamper-evident signing) precisely, lists the
// configured destination with its real immutability property (NOT a false WORM claim: object-lock is
// asserted only when the operator has confirmed it, which this code path cannot observe, so the property
// is the platform's own tamper-evidence unless a later wave wires a confirmed object-lock flag), and
// surfaces the break-glass/operational posture. NO endpoint/bucket/credential is read or emitted; only
// the destination KIND enum from the status slice.
export function buildImmutabilityReport(status: StatusForReport, worm?: WormForReport): ImmutabilityData {
  const destinations: ImmutabilityDestination[] = [];
  // The platform's own immutability is ALWAYS in force: tamper-evidence (signed, hash-chained
  // manifests/RUNLOG), which holds regardless of the bucket's object-lock. On top of that, when the real
  // WORM signal is available we state store-enforced Object-Lock HONESTLY rather than overclaiming.
  const tamperEvident = "tamper-evident: each archive is signed with a post-quantum hybrid signature and chained in a signed RUNLOG (anti-rollback)";
  if (status.destConfigured && status.destKind !== null) {
    destinations.push({
      kind: status.destKind,
      configured: true,
      // REAL WORM property when the probe confirms enforcement; otherwise the honest tamper-evidence
      // baseline plus, where relevant, a precise note that a configured policy is NOT actually protecting.
      // The destination KIND rides along because it decides WHICH MECHANISM the sentence may name, since
      // the mechanism differs by provider (e.g. S3 Object-Lock vs Azure's version-level immutability).
      property: wormProperty(worm, tamperEvident, status.destKind),
    });
  } else {
    destinations.push({ kind: status.destKind ?? "none", configured: false, property: "no destination configured" });
  }
  const attestation =
    "Archives are sealed with post-quantum hybrid encryption and signed with a post-quantum hybrid signature, and the run log is chained and signed (tamper-evident, anti-rollback). " +
    (status.breakGlassConfigured
      ? "A break-glass recipient is configured, so archives are recoverable offline without the platform. "
      : "No break-glass recipient is configured; offline recovery is not currently possible. ") +
    // This text is an ATTESTATION: a customer hands it to an auditor, so both branches state what is
    // actually true. The present branch states what the operational key buys (the UNATTENDED work), since
    // verification at seal and the canary run on the run's own per-run key regardless. The absent branch
    // states the assurance that REMAINS, not only what is missing, since that is the part an auditor checks.
    (status.operationalConfigured.private
      ? "An operational read-back key is held in-account (a deliberate weakening of strict no-custody, which lets the engine run scheduled restore tests, automated drills and in-account retention pruning unattended). "
      : "No operational read-back key is held; the strict no-custody posture is in force. Every run is still verified at seal and the hourly canary still proves the write, seal, read and decrypt path, both in-account, because each uses that run's own single-run key rather than a stored one. ") +
    wormAttestationClause(worm, status.destKind);
  return {
    attestation,
    destinations,
    breakGlassConfigured: status.breakGlassConfigured,
    operationalPrivatePresent: status.operationalConfigured.private,
  };
}

// wormProperty states the per-destination immutability property HONESTLY from the real WORM signal. THIS
// STRING IS SIGNED AND HANDED TO AN AUDITOR, so each reading gets its own sentence rather than one sentence
// covering all of them. TWO AXES decide it, not one: whether the BUCKET enforces Object-Lock, and whether
// anything actually applies a RETENTION WINDOW to the archives written there.
//   - bucket ENFORCES + a valid policy is armed -> the store-enforced WORM property (mode + window), the
//     strong claim, resting on the retention header the engine writes on every archive.
//   - bucket ENFORCES + nothing armed + the bucket has its OWN default retention rule -> the strong claim,
//     resting on that rule instead, and saying so.
//   - bucket ENFORCES + nothing armed + NO default rule -> the bucket has lock switched on and nothing is
//     retained: no retention window reaches an archive, so the strong claim is refused.
//   - bucket ENFORCES + nothing armed + the default rule could NOT be read -> say only that.
//   - a policy is configured and the bucket does NOT enforce Object-Lock -> the store REFUSES every write
//     that carries the lock headers, so this destination holds no archives at all.
//   - a policy is configured and enforcement could NOT be confirmed -> say only that, and state neither of
//     the other two readings.
//   - a policy is configured but INVALID -> no lock metadata is written, so writes are unaffected and the
//     tamper-evidence baseline is the whole property.
//   - no policy / no signal -> the tamper-evidence baseline alone (the prior, correct statement).
//
// The strong claim ("a compromised delete-credential cannot hard-delete an archive within its retention
// window") is conditioned on the retention axis, not just bucketEnforces: Object-Lock being enabled on a
// bucket does not retain anything by itself, only a per-object retention header or the bucket's own default
// retention rule does (the probe reads the default rule via router-posture.ts). On a bucket that does not
// enforce Object-Lock there are no archives at all: R2 answers a lock-bearing PUT with 501 NotImplemented
// and AWS S3 with ObjectLockConfigurationNotFoundError. Neither store ignores the headers.
//
// It NEVER claims object-lock the probe did not confirm, and it never claims the bucket refuses a write the
// probe did not read as unenforcing. An ABSENT bucketEnforces is the cannot-confirm reading and not the
// not-enforcing one: gatherWormSlice leaves the field off on any probe fault (router-posture.ts), so the
// old `else` branch asserted "the bucket does not enforce Object-Lock (it was not created with it)" from a
// probe that had never run. Only an explicit `false` reaches the refusal sentence.
function wormProperty(worm: WormForReport | undefined, tamperEvident: string, kind: DestProvider | null): string {
  // lock is what THIS store calls write-once retention and store is what it calls the thing archives land
  // in; both fall back to the S3 spelling when the kind is unknown. See dest/worm-remedy.ts.
  const lock = immutabilityMechanism(kind);
  const store = immutabilityStoreNoun(kind);
  if (worm === undefined) return tamperEvident;
  if (worm.bucketEnforces === true) {
    // ARMED: the engine writes an Object-Lock retention header on every archive it puts here, which is
    // exactly the state a VALID configured policy produces (buildDestination arms the policy only when
    // validateWormPolicyValue / parseWormPolicy accept it, so misconfigured means nothing is armed).
    if (worm.configured && !worm.misconfigured) {
      const mode = worm.mode ?? worm.probeMode;
      const days = worm.retentionDays ?? worm.probeDays;
      const detail = `${mode ? `${mode} mode` : "object-lock"}${days !== undefined ? `, ${days} day${days === 1 ? "" : "s"} retention` : ""}`;
      return `store-enforced WORM: the ${store} enforces ${lock} (${detail}); a compromised delete-credential cannot hard-delete an archive within its retention window. Also ${tamperEvident}.`;
    }
    // NOTHING ARMED. Whether any archive here is retained turns entirely on the bucket's own default rule.
    const why = worm.misconfigured ? "the configured WORM policy is invalid" : "no WORM policy is configured";
    if (worm.defaultRetention === true) {
      const detail = `${worm.probeMode ? `${worm.probeMode} mode` : "object-lock"}${worm.probeDays !== undefined ? `, ${worm.probeDays} day${worm.probeDays === 1 ? "" : "s"} retention` : ""}`;
      return `store-enforced WORM: the ${store} enforces ${lock} and applies its own default retention rule (${detail}) to every object written to it, so a compromised delete-credential cannot hard-delete an archive within that window. The engine writes no retention header of its own on this destination (${why}), so the ${store}'s default rule is the whole of the protection. Also ${tamperEvident}.`;
    }
    if (worm.defaultRetention === false) {
      return `store-enforced Object-Lock is NOT in force for the archives on this destination: the ${store} has ${lock} switched on, but it carries no default retention rule and the engine writes no retention header of its own (${why}), so an archive written here carries no retention window and a compromised delete-credential can hard-delete it. Object-Lock enabled on a bucket does not retain anything by itself. Archives are ${tamperEvident}.`;
    }
    // The default rule could not be read. Cannot-confirm on this axis is its own state, exactly as it is on
    // the enforcement axis: assert neither that archives are retained nor that they are not.
    return `store-enforced Object-Lock is NOT in force as a claim of this report: the ${store} enforces ${lock}, but the engine writes no retention header of its own (${why}) and could not read whether the ${store} applies a default retention rule, which is the only thing that would retain an archive here. Cannot-confirm is a state of its own: this report states neither that archives are write-once-locked nor that they are not. Archives are ${tamperEvident}.`;
  }
  if (worm.configured) {
    // An INVALID policy arms nothing (validateWormPolicyValue / parseWormPolicy drop it before any write),
    // so writes carry no lock headers and succeed. This is the one reading the old single sentence fitted.
    if (worm.misconfigured) {
      return `${tamperEvident}. NOTE: the WORM policy is invalid (a mode and a positive number of retention days are both required), so no Object-Lock metadata is written and store-enforced Object-Lock is NOT in force. Writes are unaffected: archives are tamper-evident but not write-once-locked.`;
    }
    // The probe could not read the bucket's Object-Lock configuration. Cannot-confirm is a THIRD state and
    // is reported as itself: this report asserts neither enforcement nor its absence, and says nothing
    // about whether writes to this destination are accepted, because that turns on the unread fact.
    if (worm.bucketEnforces !== false) {
      return `${tamperEvident}. NOTE: a WORM policy is configured and the engine could not read whether the ${store} enforces Object-Lock, so store-enforced Object-Lock is NOT in force as a claim of this report. Cannot-confirm is a state of its own: this report states neither that archives are write-once-locked nor that they are not, and it does not say whether this destination accepts writes.`;
    }
    // The bucket was read as NOT enforcing. The consequence is a refused write, not a weaker guarantee.
    return `store-enforced Object-Lock is NOT in force and this destination cannot be written to: a WORM policy is configured on a ${store} that does not enforce ${lock}, and the store refuses every write carrying the lock headers, so no archive is stored here. ${immutabilityEnableWhen(kind)} Archives written to a destination that accepts them are ${tamperEvident}.`;
  }
  return tamperEvident;
}

// wormAttestationClause adds a one-line WORM posture statement to the attestation paragraph, matching the
// per-destination property. Absent signal => no clause (the paragraph is unchanged from before).
//
// It carries the SAME split as wormProperty above and for the same reason: this paragraph is the attestation
// an auditor reads, and its configured-but-unenforced branch used to read "immutability is tamper-evidence
// only until the bucket enforces Object-Lock", which tells the reader backups are still arriving. On a
// bucket that does not enforce Object-Lock they are not arriving at all.
//
// It carries the RETENTION axis too, for the same reason: its enforced branch made the same unconditional
// strong claim wormProperty did, on a bucket where nothing need be retained. The four enforced readings
// here match the four there, one clause each.
function wormAttestationClause(worm: WormForReport | undefined, kind: DestProvider | null): string {
  const lock = immutabilityMechanism(kind);
  const store = immutabilityStoreNoun(kind);
  if (worm === undefined) return "";
  if (worm.bucketEnforces === true) {
    if (worm.configured && !worm.misconfigured) return `The destination ${store} enforces ${lock} (WORM), so archives cannot be deleted or overwritten within their retention window.`;
    const why = worm.misconfigured ? "the configured WORM policy is invalid" : "no WORM policy is configured";
    if (worm.defaultRetention === true) return `The destination ${store} enforces ${lock} (WORM) and applies its own default retention rule, so archives cannot be deleted or overwritten within that window; the engine writes no retention header of its own here (${why}).`;
    if (worm.defaultRetention === false) return `The destination ${store} has ${lock} switched on, but nothing applies a retention window to the archives written to it (${why}, and the ${store} carries no default retention rule), so they are not write-once-locked.`;
    return `The destination ${store} enforces ${lock}, but the engine writes no retention header of its own (${why}) and could not read whether the ${store} applies a default retention rule, so store-enforced immutability is not asserted here either way.`;
  }
  if (worm.configured && worm.misconfigured) return "A WORM/Object-Lock policy is configured but is invalid, so no lock metadata is written; writes are unaffected and immutability rests on tamper-evidence.";
  if (worm.configured && worm.bucketEnforces === false) return `A WORM/Object-Lock policy is configured on a destination ${store} that does not enforce ${lock}, so the store refuses every write to it and that destination holds no archives.`;
  if (worm.configured) return `A WORM/Object-Lock policy is configured and the engine could not confirm whether the destination ${store} enforces ${lock}, so store-enforced immutability is not asserted here either way.`;
  return "WORM/Object-Lock is not configured (opt-in); immutability rests on tamper-evidence (signed, hash-chained archives).";
}

// buildPostureReport (pure): the posture report IS the body (contract section 6: posture = the posture
// report from section 7), so a report of kind "posture" carries the exact PostureReport the security
// centre computes; computePosture is called by the DO/router and handed here. It returns a shallow
// defensive copy (checks array re-wrapped) so the report body cannot be mutated through a reference the
// caller still holds, matching the redaction-safe-projection contract the other generators follow.
export function buildPostureReport(posture: PostureReport): PostureReport {
  return { ...posture, checks: [...posture.checks] };
}

// ---- change-requests: the CR ledger for the OWNER-OPT-IN "Require Change Number" policy ---------------

// ChangeRequestEntry is one change-controlled action's CR record, projected redaction-safe from a
// change-recorded audit event: when it happened, who did it (verified email + auth method), WHICH
// change-controlled action kind, the operator's change number (null for an emergency without one), whether
// it was an EMERGENCY change (a bypass of the number requirement), and the emergency reason. No hash/seq
// (the chain fields are dropped) and no secret (the source target is already redaction-safe).
export interface ChangeRequestEntry {
  ts: string; // RFC-3339 UTC millis
  actorEmail: string | null;
  actorMethod: string;
  actionKind: string;
  changeNumber: string | null;
  emergency: boolean;
  reason: string | null;
}

// ChangeRequestsData is the change-requests report body: the CR entries in the period (newest-first) and the
// totals an auditor reads first (how many changes, and how many were emergencies needing retrospective review).
export interface ChangeRequestsData {
  entries: ChangeRequestEntry[];
  total: number;
  emergencyTotal: number;
  // The SILENT EXCLUSIONS matter here: this report is SIGNED, so a row the projector quietly dropped becomes a
  // signed statement that the change was never recorded -- the auditor's worst outcome ("the report shows
  // empty data / is missing a change we know we made"). Both counts are surfaced ONLY when non-zero, so a
  // clean report is byte-identical to before; a non-zero one says plainly that this report is INCOMPLETE and
  // by how much. Counts only: neither the excluded row nor its timestamp ever rides.
  excludedUnparseableTs?: number; // rows whose ts could not be placed in the period window (a corrupt timestamp)
  excludedShape?: number; // rows whose action/target shape did not match the report's contract (a producer/consumer drift)
}

// buildChangeRequestsReport (pure): project the change-recorded audit events within the period into the CR
// ledger. It reads ONLY the redaction-safe `change` target fields + the redaction-safe actor surface (email +
// method), never the hash chain. Newest-first; the totals tally the period. An event whose ts cannot be placed
// in the window is excluded (withinPeriod), the conservative choice for a compliance report.
export function buildChangeRequestsReport(events: AuditEvent[], period: ReportPeriod): ChangeRequestsData {
  const entries: ChangeRequestEntry[] = [];
  let emergencyTotal = 0;
  // COUNT what we drop. The DO's gather already filters to change-recorded, so a change-recorded event
  // arriving here WITHOUT the `change` target shape is a real producer/consumer drift (a writer that stopped
  // stamping the target the reader expects), and an unparseable ts is a corrupt row -- both used to vanish in
  // a `continue`, leaving a SIGNED report that under-reports with no hint that it did.
  let excludedShape = 0;
  let excludedUnparseableTs = 0;
  for (const e of events) {
    // Defensive: only change-recorded events with the `change` target shape (the gather already filters to the
    // action, but narrowing the target here keeps the projection total and the type honest).
    if (e.action !== "change-recorded") continue;
    if (e.target.kind !== "change") {
      excludedShape++;
      continue;
    }
    if (!withinPeriod(e.ts, period)) {
      // Only an UNPARSEABLE ts is an exclusion worth counting; a row that simply falls outside the requested
      // window is normal period filtering, not a defect, so it must not inflate the signal.
      if (!Number.isFinite(Date.parse(e.ts))) excludedUnparseableTs++;
      continue;
    }
    const t = e.target;
    if (t.emergency) emergencyTotal++;
    entries.push({
      ts: e.ts,
      actorEmail: e.actorEmail,
      actorMethod: e.actorMethod,
      actionKind: t.actionKind,
      changeNumber: t.changeNumber,
      emergency: t.emergency,
      reason: t.reason,
    });
  }
  entries.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0)); // newest-first
  return {
    entries,
    total: entries.length,
    emergencyTotal,
    ...(excludedUnparseableTs > 0 ? { excludedUnparseableTs } : {}),
    ...(excludedShape > 0 ? { excludedShape } : {}),
  };
}

// withinPeriod reports whether an RFC-3339 timestamp falls within the period (inclusive). A null period
// means "all time" (always true). An unparseable timestamp is excluded (it cannot be placed in a window;
// excluding it is the conservative choice for a compliance report, which should not over-count).
function withinPeriod(ts: string, period: ReportPeriod): boolean {
  if (period === null) return true;
  const t = Date.parse(ts);
  if (!Number.isFinite(t)) return false;
  const sec = Math.floor(t / 1000);
  return sec >= period.fromSeconds && sec <= period.toSeconds;
}

// signedView is the EXACT object that is canonicalised and signed: {kind, generatedAt, period, data}.
// Keeping it a single function means the signer and any verifier serialise the same fields in the same
// shape (canonicalJSON sorts keys, so field order here does not matter, but the field SET must match).
function signedView(report: Report): { kind: ReportKind; generatedAt: string; period: Report["period"]; data: unknown } {
  return { kind: report.kind, generatedAt: report.generatedAt, period: report.period, data: report.data };
}

// signReport signs the canonical JSON of the report's signed-over view and returns a new Report carrying
// the "edmldsa1:<b64url>" signature. The signer is the engine's loaded Signer (the same one the writer
// uses). It is async (Web Crypto). The caller has already built the unsigned Report; this only adds the
// signature field. canonicalJSON THROWS on a non-integer/oversized number; the report bodies are
// integers/strings/booleans, but the throw would propagate, so the route wraps signing in a try/catch
// and returns the unsigned report on any failure (fail-open: a signing hiccup must never 500 a read).
export async function signReport(report: Report, signer: Signer): Promise<Report> {
  const bytes = canonicalJSON(signedView(report));
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, bytes);
  return { ...report, signature: SIGNATURE_SCHEME_PREFIX + b64urlEncode(sig) };
}

// makeReport assembles an unsigned Report from a kind, the generated time, the period and the per-kind
// data. Signing is a separate step (signReport) so a caller without a signer (or one that wants to defer
// signing) still gets a well-formed report. generatedAt is RFC-3339 UTC millis (the codebase form).
export function makeReport(kind: ReportKind, data: unknown, period: ReportPeriod, now: number): Report {
  return {
    kind,
    generatedAt: new Date(now).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    period,
    data,
  };
}

// isReportKind is the runtime guard the route uses to reject an unknown :kind path segment, mirroring
// isExpiryKind / isRole. It checks membership of REPORT_KINDS, the same array the ReportKind union derives
// from, so the guard cannot drift from the type.
export function isReportKind(v: unknown): v is ReportKind {
  return REPORT_KINDS.includes(v as ReportKind);
}
