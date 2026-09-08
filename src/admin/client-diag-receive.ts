// client-diag-receive.ts -- the REQUEST-SCOPED receiver for the console-diagnostics support-pack section
// The console POSTs its bounded, local, closed-class error ring at pack
// generation; this module RE-VALIDATES every record as the MOST UNTRUSTED input in the pack (the first
// client-controlled input ever folded into the signed+sealed artifact) and projects it to the value-free
// `clientDiagnostics` section.
//
// The receiver is PURE over an already-parsed JSON value. The Content-Length cap + the 400 on
// oversized/malformed bodies live at the route boundary (router-status.ts POST /support/bundle), so a parse
// failure never reaches here; a well-formed-but-hostile body is neutralised here by set-membership DROP.
//
// INVARIANT (REQUEST-SCOPED ONLY): the projected section is folded into ONLY the bundle produced by the
// same POST, then discarded. There is no DO write, no SUPPORT_SECTION_NAMES roster entry, no section()
// gatherer, no staging. The vendor bearer-pull path (GET /support/diagnostics) and any scheduled build never
// call this, so they structurally omit the section.
//
// The projection is an ALLOWLIST projection (projectLicence discipline), NOT an object spread: an unknown /
// extra key is never copied, and any field whose value is not a set member DROPS the whole record (fail
// closed, never coerce-to-`other`, never clamp-to-nearest). Every numeric goes through a clamp. Because the
// record has zero free-string fields, a smuggled customer value cannot be a set member and cannot ride.

import {
  CLIENT_DIAG_ADMIN_OPS,
  CLIENT_DIAG_ANOMALIES,
  CLIENT_DIAG_APPLY_CLASSES,
  CLIENT_DIAG_BOOT_CLASSES,
  CLIENT_DIAG_BUILD_CHECK_CLASSES,
  CLIENT_DIAG_BULK_ACTIONS,
  CLIENT_DIAG_CALL_CLASSES,
  CLIENT_DIAG_CAPABILITIES,
  CLIENT_DIAG_CAPABILITY_OUTCOMES,
  CLIENT_DIAG_CATALOGUE_CLASSES,
  CLIENT_DIAG_CEREMONY_FAULTS,
  CLIENT_DIAG_CEREMONY_OUTCOMES,
  CLIENT_DIAG_CEREMONY_STEPS,
  CLIENT_DIAG_CHANNEL_REASON_CLASSES,
  CLIENT_DIAG_CLAIM_RESULTS,
  CLIENT_DIAG_CONTRACT_CLASSES,
  CLIENT_DIAG_COUNT_MAX,
  CLIENT_DIAG_CSP_BLOCKED,
  CLIENT_DIAG_CSP_DIRECTIVES,
  CLIENT_DIAG_CSP_INLINE_ORIGINS,
  CLIENT_DIAG_DEGRADE_CAUSES,
  CLIENT_DIAG_DELETE_FATES,
  CLIENT_DIAG_DISCOVERY_OUTCOMES,
  CLIENT_DIAG_DRIFT_CLASSES,
  CLIENT_DIAG_DRILL_ABORTS,
  CLIENT_DIAG_DRILL_FACTS,
  CLIENT_DIAG_DROP_FACTS,
  CLIENT_DIAG_DROP_SURFACES,
  CLIENT_DIAG_ERROR_CLASSES,
  CLIENT_DIAG_FAULT_CLASSES,
  CLIENT_DIAG_FAULT_SOURCES,
  CLIENT_DIAG_FEATURE_CLASSES,
  CLIENT_DIAG_FEATURE_OUTCOMES,
  CLIENT_DIAG_FIELD_CLASSES,
  CLIENT_DIAG_FIELD_FAMILIES,
  CLIENT_DIAG_FOCUS_OUTCOMES,
  CLIENT_DIAG_FORM_FIELDS,
  CLIENT_DIAG_GATE_BLOCK_CLASSES,
  CLIENT_DIAG_GLOBAL_ROW_CAP,
  CLIENT_DIAG_GOV_GATES,
  CLIENT_DIAG_HANDOFF_CLASSES,
  CLIENT_DIAG_HTTP_CLASSES,
  CLIENT_DIAG_INTENT_CLASSES,
  CLIENT_DIAG_KINDS,
  CLIENT_DIAG_MATERIAL_CLASSES,
  CLIENT_DIAG_MS_MAX,
  CLIENT_DIAG_ONBOARDING_OUTCOMES,
  CLIENT_DIAG_ONBOARDING_SECRETS,
  CLIENT_DIAG_ONBOARDING_STEPS,
  CLIENT_DIAG_OWNER_ACTION_CODES,
  CLIENT_DIAG_PER_KIND_ROW_CAP,
  CLIENT_DIAG_PROBE_OUTCOMES,
  CLIENT_DIAG_PROBE_SURFACES,
  CLIENT_DIAG_REASON_CLASSES,
  CLIENT_DIAG_RECOVERY_CODES,
  CLIENT_DIAG_RECOVERY_OPS,
  CLIENT_DIAG_REJECT_OUTCOMES,
  CLIENT_DIAG_RENDERER_MODES,
  CLIENT_DIAG_ROLLBACK_CLASSES,
  CLIENT_DIAG_SCREENS,
  CLIENT_DIAG_SKEW_CLASSES,
  CLIENT_DIAG_STORAGE_AREAS,
  CLIENT_DIAG_STORAGE_CLASSES,
  CLIENT_DIAG_STORAGE_OPS,
  CLIENT_DIAG_STORAGE_SURFACES,
  CLIENT_DIAG_SURFACES,
  CLIENT_DIAG_TRANSPORT_CLASSES,
  CLIENT_DIAG_WRITE_OUTCOMES,
  CONSOLE_BUILD_RE,
  type ClientDiagAdminOp,
  type ClientDiagAnomaly,
  type ClientDiagApplyClass,
  type ClientDiagBootClass,
  type ClientDiagBuildCheckClass,
  type ClientDiagBulkAction,
  type ClientDiagCallClass,
  type ClientDiagCapability,
  type ClientDiagCapabilityOutcome,
  type ClientDiagCatalogueClass,
  type ClientDiagCeremonyFault,
  type ClientDiagCeremonyOutcome,
  type ClientDiagCeremonyStep,
  type ClientDiagChannelReasonClass,
  type ClientDiagClaimResult,
  type ClientDiagContractClass,
  type ClientDiagCspBlocked,
  type ClientDiagCspDirective,
  type ClientDiagCspInlineOrigin,
  type ClientDiagDegradeCause,
  type ClientDiagDeleteFate,
  type ClientDiagDiscoveryOutcome,
  type ClientDiagDriftClass,
  type ClientDiagDrillAbort,
  type ClientDiagDrillFact,
  type ClientDiagDropFact,
  type ClientDiagDropSurface,
  type ClientDiagErrorClass,
  type ClientDiagFaultClass,
  type ClientDiagFaultSource,
  type ClientDiagFeatureClass,
  type ClientDiagFeatureOutcome,
  type ClientDiagFieldClass,
  type ClientDiagFieldFamily,
  type ClientDiagFocusOutcome,
  type ClientDiagFormField,
  type ClientDiagGateBlockClass,
  type ClientDiagGovGate,
  type ClientDiagHandoffClass,
  type ClientDiagHttpClass,
  type ClientDiagIntentClass,
  type ClientDiagKind,
  type ClientDiagMaterialClass,
  type ClientDiagnosticRecord,
  type ClientDiagnosticsSection,
  type ClientDiagOnboardingOutcome,
  type ClientDiagOnboardingSecret,
  type ClientDiagOnboardingStep,
  type ClientDiagOwnerActionCode,
  type ClientDiagProbeOutcome,
  type ClientDiagProbeSurface,
  type ClientDiagReasonClass,
  type ClientDiagRecoveryCode,
  type ClientDiagRecoveryOp,
  type ClientDiagRejectOutcome,
  type ClientDiagRendererMode,
  type ClientDiagRollbackClass,
  type ClientDiagScreen,
  type ClientDiagSkewClass,
  type ClientDiagStorageArea,
  type ClientDiagStorageClass,
  type ClientDiagStorageOp,
  type ClientDiagStorageSurface,
  type ClientDiagSurface,
  type ClientDiagTransportClass,
  type ClientDiagWriteOutcome,
} from "./client-diag-vocab.ts";

// Set-membership allowlists (the engine re-validation authority), moved here from client-diag-vocab.ts on
// so the ONE applier that gates on them owns them: module-private, so no second list can be built
// against the vocabulary, and each Set is DERIVED (new Set(ARRAY)) from the one canonical tuple, so a member
// added to the vocabulary is admitted here by construction and the two cannot drift.
const CLIENT_DIAG_KIND_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_KINDS);
const CLIENT_DIAG_SCREEN_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_SCREENS);
const CLIENT_DIAG_HTTP_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_HTTP_CLASSES);
const CLIENT_DIAG_FAULT_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FAULT_CLASSES);
const CLIENT_DIAG_DRIFT_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DRIFT_CLASSES);
const CLIENT_DIAG_REASON_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_REASON_CLASSES);
const CLIENT_DIAG_APPLY_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_APPLY_CLASSES);
const CLIENT_DIAG_CAPABILITY_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CAPABILITIES);
const CLIENT_DIAG_SURFACE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_SURFACES);
const CLIENT_DIAG_CAPABILITY_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CAPABILITY_OUTCOMES);
const CLIENT_DIAG_BOOT_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_BOOT_CLASSES);
const CLIENT_DIAG_BUILD_CHECK_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_BUILD_CHECK_CLASSES);
const CLIENT_DIAG_ROLLBACK_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ROLLBACK_CLASSES);
const CLIENT_DIAG_GATE_BLOCK_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_GATE_BLOCK_CLASSES);
const CLIENT_DIAG_FIELD_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FIELD_CLASSES);
const CLIENT_DIAG_ANOMALY_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ANOMALIES);
const CLIENT_DIAG_ERROR_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ERROR_CLASSES);
const CLIENT_DIAG_FAULT_SOURCE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FAULT_SOURCES);
const CLIENT_DIAG_TRANSPORT_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_TRANSPORT_CLASSES);
const CLIENT_DIAG_CALL_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CALL_CLASSES);
const CLIENT_DIAG_ONBOARDING_STEP_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ONBOARDING_STEPS);
const CLIENT_DIAG_ONBOARDING_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ONBOARDING_OUTCOMES);
const CLIENT_DIAG_ONBOARDING_SECRET_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ONBOARDING_SECRETS);
const CLIENT_DIAG_CHANNEL_REASON_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CHANNEL_REASON_CLASSES);
const CLIENT_DIAG_DISCOVERY_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DISCOVERY_OUTCOMES);
const CLIENT_DIAG_CLAIM_RESULT_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CLAIM_RESULTS);
const CLIENT_DIAG_ADMIN_OP_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_ADMIN_OPS);
const CLIENT_DIAG_WRITE_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_WRITE_OUTCOMES);
const CLIENT_DIAG_RECOVERY_OP_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_RECOVERY_OPS);
const CLIENT_DIAG_RECOVERY_CODE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_RECOVERY_CODES);
const CLIENT_DIAG_INTENT_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_INTENT_CLASSES);
const CLIENT_DIAG_PROBE_SURFACE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_PROBE_SURFACES);
const CLIENT_DIAG_PROBE_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_PROBE_OUTCOMES);
const CLIENT_DIAG_FORM_FIELD_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FORM_FIELDS);
const CLIENT_DIAG_REJECT_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_REJECT_OUTCOMES);
const CLIENT_DIAG_CATALOGUE_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CATALOGUE_CLASSES);
const CLIENT_DIAG_FEATURE_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FEATURE_CLASSES);
const CLIENT_DIAG_FEATURE_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FEATURE_OUTCOMES);
const CLIENT_DIAG_GOV_GATE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_GOV_GATES);
const CLIENT_DIAG_SKEW_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_SKEW_CLASSES);
const CLIENT_DIAG_BULK_ACTION_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_BULK_ACTIONS);
const CLIENT_DIAG_MATERIAL_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_MATERIAL_CLASSES);
const CLIENT_DIAG_CONTRACT_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CONTRACT_CLASSES);
const CLIENT_DIAG_FIELD_FAMILY_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FIELD_FAMILIES);
const CLIENT_DIAG_DRILL_ABORT_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DRILL_ABORTS);
const CLIENT_DIAG_DRILL_FACT_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DRILL_FACTS);
const CLIENT_DIAG_OWNER_ACTION_CODE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_OWNER_ACTION_CODES);
const CLIENT_DIAG_CSP_DIRECTIVE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CSP_DIRECTIVES);
const CLIENT_DIAG_CSP_BLOCKED_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CSP_BLOCKED);
const CLIENT_DIAG_CSP_INLINE_ORIGIN_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CSP_INLINE_ORIGINS);
const CLIENT_DIAG_DELETE_FATE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DELETE_FATES);
const CLIENT_DIAG_DROP_SURFACE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DROP_SURFACES);
const CLIENT_DIAG_DROP_FACT_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DROP_FACTS);
const CLIENT_DIAG_HANDOFF_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_HANDOFF_CLASSES);
const CLIENT_DIAG_CEREMONY_STEP_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CEREMONY_STEPS);
const CLIENT_DIAG_CEREMONY_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CEREMONY_OUTCOMES);
const CLIENT_DIAG_CEREMONY_FAULT_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_CEREMONY_FAULTS);
const CLIENT_DIAG_STORAGE_AREA_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_STORAGE_AREAS);
const CLIENT_DIAG_STORAGE_OP_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_STORAGE_OPS);
const CLIENT_DIAG_STORAGE_CLASS_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_STORAGE_CLASSES);
const CLIENT_DIAG_STORAGE_SURFACE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_STORAGE_SURFACES);
const CLIENT_DIAG_RENDERER_MODE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_RENDERER_MODES);
const CLIENT_DIAG_DEGRADE_CAUSE_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_DEGRADE_CAUSES);
const CLIENT_DIAG_FOCUS_OUTCOME_SET: ReadonlySet<string> = new Set(CLIENT_DIAG_FOCUS_OUTCOMES);
// clampMs projects an untrusted numeric to a bounded non-negative integer performance.now offset; a
// NaN/negative/absent/huge value is unusable and collapses to undefined so the caller can drop the record.
function clampMs(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(CLIENT_DIAG_MS_MAX, Math.floor(v))) : undefined;
}

// clampCount projects an untrusted coalesce count to a bounded non-negative integer (cap COUNT_MAX); an
// absent/malformed value collapses to undefined so the record is dropped (a valid record always carries a
// finite count -- a repeat increments it).
function clampCount(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(CLIENT_DIAG_COUNT_MAX, Math.floor(v))) : undefined;
}

// clampAttempts projects the client-asserted engineAttempts denominator (the signal reasons over a
// failure RATIO, never a raw count). Value-free integer; absent when not supplied or malformed.
function clampAttempts(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(CLIENT_DIAG_COUNT_MAX, Math.floor(v))) : undefined;
}

// projectRecord re-validates one untrusted record by SET MEMBERSHIP and builds an allowlist projection, or
// returns null to DROP it. Any required field missing/invalid, OR any PRESENT recognised field whose value
// is not a set member, fails the record closed (a non-member value must never ride, so we never keep a record
// that carried one). Unknown/extra keys are simply never read (allowlist projection), so they cannot ride.
export function projectRecord(input: unknown): ClientDiagnosticRecord | null {
  if (input === null || typeof input !== "object") return null;
  const o = input as Record<string, unknown>;

  // Required closed-union string fields: kind + screen must be members.
  if (typeof o.kind !== "string" || !CLIENT_DIAG_KIND_SET.has(o.kind)) return null;
  if (typeof o.screen !== "string" || !CLIENT_DIAG_SCREEN_SET.has(o.screen)) return null;

  // Required numerics: count + firstMs + lastMs must be finite.
  const count = clampCount(o.count);
  const firstMs = clampMs(o.firstMs);
  const lastMs = clampMs(o.lastMs);
  if (count === undefined || firstMs === undefined || lastMs === undefined) return null;

  // Optional closed-union string fields: PRESENT-but-non-member fails the record closed (a smuggled value in
  // a recognised field must not admit the record). `undefined` (absent) is fine; anything else is validated.
  if (o.httpClass !== undefined && (typeof o.httpClass !== "string" || !CLIENT_DIAG_HTTP_CLASS_SET.has(o.httpClass))) return null;
  if (o.faultClass !== undefined && (typeof o.faultClass !== "string" || !CLIENT_DIAG_FAULT_CLASS_SET.has(o.faultClass))) return null;
  if (o.driftClass !== undefined && (typeof o.driftClass !== "string" || !CLIENT_DIAG_DRIFT_CLASS_SET.has(o.driftClass))) return null;
  if (o.reasonClass !== undefined && (typeof o.reasonClass !== "string" || !CLIENT_DIAG_REASON_CLASS_SET.has(o.reasonClass))) return null;
  if (o.applyClass !== undefined && (typeof o.applyClass !== "string" || !CLIENT_DIAG_APPLY_CLASS_SET.has(o.applyClass))) return null;
  if (o.capability !== undefined && (typeof o.capability !== "string" || !CLIENT_DIAG_CAPABILITY_SET.has(o.capability))) return null;
  if (o.surface !== undefined && (typeof o.surface !== "string" || !CLIENT_DIAG_SURFACE_SET.has(o.surface))) return null;
  if (o.capabilityOutcome !== undefined && (typeof o.capabilityOutcome !== "string" || !CLIENT_DIAG_CAPABILITY_OUTCOME_SET.has(o.capabilityOutcome))) return null;
  if (o.bootClass !== undefined && (typeof o.bootClass !== "string" || !CLIENT_DIAG_BOOT_CLASS_SET.has(o.bootClass))) return null;
  if (o.buildCheckClass !== undefined && (typeof o.buildCheckClass !== "string" || !CLIENT_DIAG_BUILD_CHECK_CLASS_SET.has(o.buildCheckClass))) return null;
  if (o.rollbackClass !== undefined && (typeof o.rollbackClass !== "string" || !CLIENT_DIAG_ROLLBACK_CLASS_SET.has(o.rollbackClass))) return null;
  if (o.gateBlockClass !== undefined && (typeof o.gateBlockClass !== "string" || !CLIENT_DIAG_GATE_BLOCK_CLASS_SET.has(o.gateBlockClass))) return null;
  if (o.fieldClass !== undefined && (typeof o.fieldClass !== "string" || !CLIENT_DIAG_FIELD_CLASS_SET.has(o.fieldClass))) return null;
  if (o.anomaly !== undefined && (typeof o.anomaly !== "string" || !CLIENT_DIAG_ANOMALY_SET.has(o.anomaly))) return null;
  if (o.errorClass !== undefined && (typeof o.errorClass !== "string" || !CLIENT_DIAG_ERROR_CLASS_SET.has(o.errorClass))) return null;
  if (o.faultSource !== undefined && (typeof o.faultSource !== "string" || !CLIENT_DIAG_FAULT_SOURCE_SET.has(o.faultSource))) return null;
  if (o.transportClass !== undefined && (typeof o.transportClass !== "string" || !CLIENT_DIAG_TRANSPORT_CLASS_SET.has(o.transportClass))) return null;
  if (o.callClass !== undefined && (typeof o.callClass !== "string" || !CLIENT_DIAG_CALL_CLASS_SET.has(o.callClass))) return null;
  if (o.obStep !== undefined && (typeof o.obStep !== "string" || !CLIENT_DIAG_ONBOARDING_STEP_SET.has(o.obStep))) return null;
  if (o.obOutcome !== undefined && (typeof o.obOutcome !== "string" || !CLIENT_DIAG_ONBOARDING_OUTCOME_SET.has(o.obOutcome))) return null;
  if (o.obSecret !== undefined && (typeof o.obSecret !== "string" || !CLIENT_DIAG_ONBOARDING_SECRET_SET.has(o.obSecret))) return null;
  if (o.channelReasonClass !== undefined && (typeof o.channelReasonClass !== "string" || !CLIENT_DIAG_CHANNEL_REASON_CLASS_SET.has(o.channelReasonClass))) return null;
  if (o.discoveryOutcome !== undefined && (typeof o.discoveryOutcome !== "string" || !CLIENT_DIAG_DISCOVERY_OUTCOME_SET.has(o.discoveryOutcome))) return null;
  if (o.claimResult !== undefined && (typeof o.claimResult !== "string" || !CLIENT_DIAG_CLAIM_RESULT_SET.has(o.claimResult))) return null;
  if (o.adminOp !== undefined && (typeof o.adminOp !== "string" || !CLIENT_DIAG_ADMIN_OP_SET.has(o.adminOp))) return null;
  if (o.writeOutcome !== undefined && (typeof o.writeOutcome !== "string" || !CLIENT_DIAG_WRITE_OUTCOME_SET.has(o.writeOutcome))) return null;
  if (o.recoveryOp !== undefined && (typeof o.recoveryOp !== "string" || !CLIENT_DIAG_RECOVERY_OP_SET.has(o.recoveryOp))) return null;
  if (o.recoveryCode !== undefined && (typeof o.recoveryCode !== "string" || !CLIENT_DIAG_RECOVERY_CODE_SET.has(o.recoveryCode))) return null;
  // The posture-round discriminators. Same rule, no exceptions: a present
  // field whose value is not a member fails the record CLOSED rather than being dropped, because a value that is
  // not a member of a frozen product vocabulary is, by construction, not a product constant.
  if (o.intentClass !== undefined && (typeof o.intentClass !== "string" || !CLIENT_DIAG_INTENT_CLASS_SET.has(o.intentClass))) return null;
  if (o.probeSurface !== undefined && (typeof o.probeSurface !== "string" || !CLIENT_DIAG_PROBE_SURFACE_SET.has(o.probeSurface))) return null;
  if (o.probeOutcome !== undefined && (typeof o.probeOutcome !== "string" || !CLIENT_DIAG_PROBE_OUTCOME_SET.has(o.probeOutcome))) return null;
  if (o.formField !== undefined && (typeof o.formField !== "string" || !CLIENT_DIAG_FORM_FIELD_SET.has(o.formField))) return null;
  if (o.rejectOutcome !== undefined && (typeof o.rejectOutcome !== "string" || !CLIENT_DIAG_REJECT_OUTCOME_SET.has(o.rejectOutcome))) return null;
  if (o.catalogueClass !== undefined && (typeof o.catalogueClass !== "string" || !CLIENT_DIAG_CATALOGUE_CLASS_SET.has(o.catalogueClass))) return null;
  if (o.featureClass !== undefined && (typeof o.featureClass !== "string" || !CLIENT_DIAG_FEATURE_CLASS_SET.has(o.featureClass))) return null;
  if (o.featureOutcome !== undefined && (typeof o.featureOutcome !== "string" || !CLIENT_DIAG_FEATURE_OUTCOME_SET.has(o.featureOutcome))) return null;
  if (o.govGate !== undefined && (typeof o.govGate !== "string" || !CLIENT_DIAG_GOV_GATE_SET.has(o.govGate))) return null;
  if (o.skewClass !== undefined && (typeof o.skewClass !== "string" || !CLIENT_DIAG_SKEW_CLASS_SET.has(o.skewClass))) return null;
  if (o.bulkAction !== undefined && (typeof o.bulkAction !== "string" || !CLIENT_DIAG_BULK_ACTION_SET.has(o.bulkAction))) return null;
  if (o.materialClass !== undefined && (typeof o.materialClass !== "string" || !CLIENT_DIAG_MATERIAL_CLASS_SET.has(o.materialClass))) return null;
  if (o.contractClass !== undefined && (typeof o.contractClass !== "string" || !CLIENT_DIAG_CONTRACT_CLASS_SET.has(o.contractClass))) return null;
  if (o.fieldFamily !== undefined && (typeof o.fieldFamily !== "string" || !CLIENT_DIAG_FIELD_FAMILY_SET.has(o.fieldFamily))) return null;
  if (o.drillAbort !== undefined && (typeof o.drillAbort !== "string" || !CLIENT_DIAG_DRILL_ABORT_SET.has(o.drillAbort))) return null;
  if (o.drillFact !== undefined && (typeof o.drillFact !== "string" || !CLIENT_DIAG_DRILL_FACT_SET.has(o.drillFact))) return null;
  // The POSTURE round, group 3. Validated by SET MEMBERSHIP like every field above:
  // a non-member fails the whole record CLOSED, never coerced to a nearest member.
  if (o.ownerActionCode !== undefined && (typeof o.ownerActionCode !== "string" || !CLIENT_DIAG_OWNER_ACTION_CODE_SET.has(o.ownerActionCode))) return null;
  if (o.cspDirective !== undefined && (typeof o.cspDirective !== "string" || !CLIENT_DIAG_CSP_DIRECTIVE_SET.has(o.cspDirective))) return null;
  if (o.cspBlocked !== undefined && (typeof o.cspBlocked !== "string" || !CLIENT_DIAG_CSP_BLOCKED_SET.has(o.cspBlocked))) return null;
  if (o.cspInlineOrigin !== undefined && (typeof o.cspInlineOrigin !== "string" || !CLIENT_DIAG_CSP_INLINE_ORIGIN_SET.has(o.cspInlineOrigin))) return null;
  if (o.deleteFate !== undefined && (typeof o.deleteFate !== "string" || !CLIENT_DIAG_DELETE_FATE_SET.has(o.deleteFate))) return null;
  if (o.dropSurface !== undefined && (typeof o.dropSurface !== "string" || !CLIENT_DIAG_DROP_SURFACE_SET.has(o.dropSurface))) return null;
  if (o.dropFact !== undefined && (typeof o.dropFact !== "string" || !CLIENT_DIAG_DROP_FACT_SET.has(o.dropFact))) return null;
  if (o.handoffClass !== undefined && (typeof o.handoffClass !== "string" || !CLIENT_DIAG_HANDOFF_CLASS_SET.has(o.handoffClass))) return null;
  if (o.ceremonyStep !== undefined && (typeof o.ceremonyStep !== "string" || !CLIENT_DIAG_CEREMONY_STEP_SET.has(o.ceremonyStep))) return null;
  if (o.ceremonyOutcome !== undefined && (typeof o.ceremonyOutcome !== "string" || !CLIENT_DIAG_CEREMONY_OUTCOME_SET.has(o.ceremonyOutcome))) return null;
  if (o.ceremonyFault !== undefined && (typeof o.ceremonyFault !== "string" || !CLIENT_DIAG_CEREMONY_FAULT_SET.has(o.ceremonyFault))) return null;
  if (o.storageArea !== undefined && (typeof o.storageArea !== "string" || !CLIENT_DIAG_STORAGE_AREA_SET.has(o.storageArea))) return null;
  if (o.storageOp !== undefined && (typeof o.storageOp !== "string" || !CLIENT_DIAG_STORAGE_OP_SET.has(o.storageOp))) return null;
  if (o.storageClass !== undefined && (typeof o.storageClass !== "string" || !CLIENT_DIAG_STORAGE_CLASS_SET.has(o.storageClass))) return null;
  if (o.storageSurface !== undefined && (typeof o.storageSurface !== "string" || !CLIENT_DIAG_STORAGE_SURFACE_SET.has(o.storageSurface))) return null;
  if (o.rendererMode !== undefined && (typeof o.rendererMode !== "string" || !CLIENT_DIAG_RENDERER_MODE_SET.has(o.rendererMode))) return null;
  if (o.degradeCause !== undefined && (typeof o.degradeCause !== "string" || !CLIENT_DIAG_DEGRADE_CAUSE_SET.has(o.degradeCause))) return null;
  if (o.focusOutcome !== undefined && (typeof o.focusOutcome !== "string" || !CLIENT_DIAG_FOCUS_OUTCOME_SET.has(o.focusOutcome))) return null;

  // Allowlist projection (NOT spread): each field is named explicitly, so an unknown/extra key on `o` (a
  // smuggled `note`/`url`/`message`/`email`) is structurally never copied into the output.
  const rec: ClientDiagnosticRecord = {
    kind: o.kind as ClientDiagKind,
    screen: o.screen as ClientDiagScreen,
    count,
    firstMs,
    lastMs,
  };
  if (typeof o.httpClass === "string") rec.httpClass = o.httpClass as ClientDiagHttpClass;
  if (typeof o.faultClass === "string") rec.faultClass = o.faultClass as ClientDiagFaultClass;
  if (typeof o.driftClass === "string") rec.driftClass = o.driftClass as ClientDiagDriftClass;
  if (typeof o.reasonClass === "string") rec.reasonClass = o.reasonClass as ClientDiagReasonClass;
  // applyClass is the WHOLE discriminator of an apply-outcome row: dropping it here while keeping the
  // row would land a row in the bundle that says an apply ended, and refuses to say how, which is worse than
  // no row at all. It is validated above, so a present-but-drifted value has already failed the record closed.
  if (typeof o.applyClass === "string") rec.applyClass = o.applyClass as ClientDiagApplyClass;
  // capability / surface / capabilityOutcome are the WHOLE discriminator of a capability-fault row.
  // Dropping any of them while keeping the row would land a row that says the browser would not do something,
  // and refuses to say what, on which ceremony, or whether the capability was even present. That is the row
  // the gap was refuted for: a "refused identity.key download" and an unrelated null-deref reduced to the same
  // three fields. Each is validated above, so a present-but-drifted value has already failed the record closed.
  if (typeof o.capability === "string") rec.capability = o.capability as ClientDiagCapability;
  if (typeof o.surface === "string") rec.surface = o.surface as ClientDiagSurface;
  if (typeof o.capabilityOutcome === "string") rec.capabilityOutcome = o.capabilityOutcome as ClientDiagCapabilityOutcome;
  // These discriminators. Each is the WHOLE point of the row that carries it, and
  // the same rule applies to every one of them: dropping the field while keeping the row would land a row in the
  // bundle that says something went wrong and refuses to say what, which reads as evidence and is not. A build
  // check with no class cannot say whether the origin served the wrong build or nothing at all; a blocked restore
  // gate with no class is the "awaiting approval" panel the operator already stared at; a wire anomaly with no
  // field class cannot be joined to anything. They are validated above, so a present-but-drifted value has
  // already failed the record closed.
  if (typeof o.bootClass === "string") rec.bootClass = o.bootClass as ClientDiagBootClass;
  if (typeof o.buildCheckClass === "string") rec.buildCheckClass = o.buildCheckClass as ClientDiagBuildCheckClass;
  if (typeof o.rollbackClass === "string") rec.rollbackClass = o.rollbackClass as ClientDiagRollbackClass;
  if (typeof o.gateBlockClass === "string") rec.gateBlockClass = o.gateBlockClass as ClientDiagGateBlockClass;
  if (typeof o.fieldClass === "string") rec.fieldClass = o.fieldClass as ClientDiagFieldClass;
  if (typeof o.anomaly === "string") rec.anomaly = o.anomaly as ClientDiagAnomaly;
  if (typeof o.errorClass === "string") rec.errorClass = o.errorClass as ClientDiagErrorClass;
  if (typeof o.faultSource === "string") rec.faultSource = o.faultSource as ClientDiagFaultSource;
  // These discriminators, projected under the same rule as every field above: each one
  // IS the row it rides on. Dropping the field while keeping the row would land a row in the bundle that says a
  // transport failed, or a read went quiet, or a wizard step ended, and refuses to say which or how. A
  // transport-fault with no class cannot tell a CORS block from an outage, which is the pair it exists for; a
  // read-degraded with no callClass is a 5xx on whatever screen the operator was standing on; a
  // discovery-connect with no outcome cannot tell an empty account from a scope gap. They are validated above,
  // so a present-but-drifted value has already failed the record closed.
  if (typeof o.transportClass === "string") rec.transportClass = o.transportClass as ClientDiagTransportClass;
  if (typeof o.callClass === "string") rec.callClass = o.callClass as ClientDiagCallClass;
  if (typeof o.obStep === "string") rec.obStep = o.obStep as ClientDiagOnboardingStep;
  if (typeof o.obOutcome === "string") rec.obOutcome = o.obOutcome as ClientDiagOnboardingOutcome;
  // obSecret and channelReasonClass are discriminators, projected under the same rule as every field
  // above: each IS the row it rides on. A poll-exhausted row with no obSecret cannot tell a HALF-KEYED engine from
  // an install that never took, which is the pair the field exists for; an update-channel-unverified row with no
  // channelReasonClass says the channel is not verified and refuses to say why, which is the six-week silent outage
  // this gap is about. Both are validated above, so a present-but-drifted value has already failed the record closed.
  if (typeof o.obSecret === "string") rec.obSecret = o.obSecret as ClientDiagOnboardingSecret;
  if (typeof o.channelReasonClass === "string") rec.channelReasonClass = o.channelReasonClass as ClientDiagChannelReasonClass;
  if (typeof o.discoveryOutcome === "string") rec.discoveryOutcome = o.discoveryOutcome as ClientDiagDiscoveryOutcome;
  if (typeof o.claimResult === "string") rec.claimResult = o.claimResult as ClientDiagClaimResult;
  // These discriminators, under the same rule. An admin-write with no adminOp
  // is a row that says a privileged write did not go through and will not say which one, on a screen that posts
  // four of them; with no writeOutcome it will not say whether the engine refused it, never saw it, or applied
  // it. A recovery-refusal with no code is the one thing a mid-disaster customer CAN read out, thrown away.
  if (typeof o.adminOp === "string") rec.adminOp = o.adminOp as ClientDiagAdminOp;
  if (typeof o.writeOutcome === "string") rec.writeOutcome = o.writeOutcome as ClientDiagWriteOutcome;
  if (typeof o.recoveryOp === "string") rec.recoveryOp = o.recoveryOp as ClientDiagRecoveryOp;
  if (typeof o.recoveryCode === "string") rec.recoveryCode = o.recoveryCode as ClientDiagRecoveryCode;
  // The posture-round discriminators. Each one IS the row it rides on, exactly as above: a probe-outcome with no
  // surface and no outcome is a row saying a test was run; an intent-dropped with no class says an option was
  // discarded and will not say which; a feature-probe with no outcome cannot tell BROKEN from UNBUILT, which is
  // the one thing it exists to say. Validated above, so a drifted value has already failed the record closed.
  if (typeof o.intentClass === "string") rec.intentClass = o.intentClass as ClientDiagIntentClass;
  if (typeof o.probeSurface === "string") rec.probeSurface = o.probeSurface as ClientDiagProbeSurface;
  if (typeof o.probeOutcome === "string") rec.probeOutcome = o.probeOutcome as ClientDiagProbeOutcome;
  if (typeof o.formField === "string") rec.formField = o.formField as ClientDiagFormField;
  if (typeof o.rejectOutcome === "string") rec.rejectOutcome = o.rejectOutcome as ClientDiagRejectOutcome;
  if (typeof o.catalogueClass === "string") rec.catalogueClass = o.catalogueClass as ClientDiagCatalogueClass;
  if (typeof o.featureClass === "string") rec.featureClass = o.featureClass as ClientDiagFeatureClass;
  if (typeof o.featureOutcome === "string") rec.featureOutcome = o.featureOutcome as ClientDiagFeatureOutcome;
  if (typeof o.govGate === "string") rec.govGate = o.govGate as ClientDiagGovGate;
  if (typeof o.skewClass === "string") rec.skewClass = o.skewClass as ClientDiagSkewClass;
  if (typeof o.bulkAction === "string") rec.bulkAction = o.bulkAction as ClientDiagBulkAction;
  if (typeof o.materialClass === "string") rec.materialClass = o.materialClass as ClientDiagMaterialClass;
  if (typeof o.contractClass === "string") rec.contractClass = o.contractClass as ClientDiagContractClass;
  if (typeof o.fieldFamily === "string") rec.fieldFamily = o.fieldFamily as ClientDiagFieldFamily;
  if (typeof o.drillAbort === "string") rec.drillAbort = o.drillAbort as ClientDiagDrillAbort;
  if (typeof o.drillFact === "string") rec.drillFact = o.drillFact as ClientDiagDrillFact;
  // The second allowlist projection: a field validated above and missing HERE is a discriminator that reaches the
  // pack as an empty column, so the row looks specific and is not.
  if (typeof o.ownerActionCode === "string") rec.ownerActionCode = o.ownerActionCode as ClientDiagOwnerActionCode;
  if (typeof o.cspDirective === "string") rec.cspDirective = o.cspDirective as ClientDiagCspDirective;
  if (typeof o.cspBlocked === "string") rec.cspBlocked = o.cspBlocked as ClientDiagCspBlocked;
  if (typeof o.cspInlineOrigin === "string") rec.cspInlineOrigin = o.cspInlineOrigin as ClientDiagCspInlineOrigin;
  if (typeof o.deleteFate === "string") rec.deleteFate = o.deleteFate as ClientDiagDeleteFate;
  if (typeof o.dropSurface === "string") rec.dropSurface = o.dropSurface as ClientDiagDropSurface;
  if (typeof o.dropFact === "string") rec.dropFact = o.dropFact as ClientDiagDropFact;
  if (typeof o.handoffClass === "string") rec.handoffClass = o.handoffClass as ClientDiagHandoffClass;
  if (typeof o.ceremonyStep === "string") rec.ceremonyStep = o.ceremonyStep as ClientDiagCeremonyStep;
  if (typeof o.ceremonyOutcome === "string") rec.ceremonyOutcome = o.ceremonyOutcome as ClientDiagCeremonyOutcome;
  if (typeof o.ceremonyFault === "string") rec.ceremonyFault = o.ceremonyFault as ClientDiagCeremonyFault;
  if (typeof o.storageArea === "string") rec.storageArea = o.storageArea as ClientDiagStorageArea;
  if (typeof o.storageOp === "string") rec.storageOp = o.storageOp as ClientDiagStorageOp;
  if (typeof o.storageClass === "string") rec.storageClass = o.storageClass as ClientDiagStorageClass;
  if (typeof o.storageSurface === "string") rec.storageSurface = o.storageSurface as ClientDiagStorageSurface;
  if (typeof o.rendererMode === "string") rec.rendererMode = o.rendererMode as ClientDiagRendererMode;
  if (typeof o.degradeCause === "string") rec.degradeCause = o.degradeCause as ClientDiagDegradeCause;
  // focusOutcome is the SECOND allowlist projection for the accessibility surface, and it is under the
  // same rule as every discriminator above: it IS the row it rides on. A focus-landing row with no outcome
  // says a navigation moved focus somewhere and refuses to say whether the control the operator activated
  // kept it, which is the only question the row exists to answer. Validated above, so a drifted value has
  // already failed the record closed.
  if (typeof o.focusOutcome === "string") rec.focusOutcome = o.focusOutcome as ClientDiagFocusOutcome;
  return rec;
}

// receivedAtSecond stamps the engine-side receipt time floored to SECOND precision. The client clock is
// not trusted, so the signature covers the engine's receipt instant, coarsened to a second so it is not a
// fingerprintable high-resolution timestamp.
function receivedAtSecond(): string {
  return new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// projectClientDiagnostics is the request-scoped receiver. Given the parsed POST body's `clientDiagnostics`
// value (or the whole body if it carries records directly), it returns the value-free section, or null when
// the body carried NO clientDiagnostics object at all (so the caller omits the section entirely -- the
// vendor-pull asymmetry). A PRESENT-but-empty ring yields a section with records:[] ("collected,
// nothing to report" is distinct from ABSENT = "not collected"). Enforces per-kind newest-wins cap 32, a
// global cap 128, and a per-kind uncapped true-count rollup for any kind whose rows were capped.
export function projectClientDiagnostics(input: unknown): ClientDiagnosticsSection | null {
  if (input === null || typeof input !== "object") return null;
  const raw = input as { records?: unknown; engineAttempts?: unknown; consoleBuild?: unknown };
  const rawRecords = Array.isArray(raw.records) ? raw.records : [];

  // Group valid records by kind, in input order (the console ships oldest -> newest ring order), tracking the
  // UNCAPPED true count per kind so a capped kind still registers as a number (D3).
  const byKind = new Map<ClientDiagKind, ClientDiagnosticRecord[]>();
  const trueByKind = new Map<ClientDiagKind, number>();
  for (const r of rawRecords) {
    const rec = projectRecord(r);
    if (rec === null) continue; // DROP: a non-member value / malformed record never rides
    trueByKind.set(rec.kind, (trueByKind.get(rec.kind) ?? 0) + 1);
    const bucket = byKind.get(rec.kind) ?? [];
    bucket.push(rec);
    byKind.set(rec.kind, bucket);
  }

  // Per-kind newest-wins cap: keep the LAST PER_KIND_ROW_CAP of each kind (newest, since input is oldest ->
  // newest). Record a rollup entry for any kind whose true count exceeded what is kept.
  const rollupByKind: Partial<Record<ClientDiagKind, number>> = {};
  let kept: ClientDiagnosticRecord[] = [];
  for (const [kind, bucket] of byKind) {
    const keepFrom = Math.max(0, bucket.length - CLIENT_DIAG_PER_KIND_ROW_CAP);
    const keptForKind = bucket.slice(keepFrom);
    kept = kept.concat(keptForKind);
    const trueCount = trueByKind.get(kind) ?? keptForKind.length;
    if (trueCount > keptForKind.length) rollupByKind[kind] = trueCount;
  }

  // Global cap: keep the newest GLOBAL_ROW_CAP by lastMs (monotonic), so a flood of one kind cannot crowd out
  // every other kind's newest rows. A rollup entry is stamped for any kind that lost rows to the global cap.
  if (kept.length > CLIENT_DIAG_GLOBAL_ROW_CAP) {
    const beforeByKind = new Map<ClientDiagKind, number>();
    for (const r of kept) beforeByKind.set(r.kind, (beforeByKind.get(r.kind) ?? 0) + 1);
    kept = kept.slice().sort((a, b) => b.lastMs - a.lastMs).slice(0, CLIENT_DIAG_GLOBAL_ROW_CAP);
    const afterByKind = new Map<ClientDiagKind, number>();
    for (const r of kept) afterByKind.set(r.kind, (afterByKind.get(r.kind) ?? 0) + 1);
    for (const [kind, before] of beforeByKind) {
      const after = afterByKind.get(kind) ?? 0;
      if (after < before) rollupByKind[kind] = Math.max(rollupByKind[kind] ?? 0, trueByKind.get(kind) ?? before);
    }
  }

  const section: ClientDiagnosticsSection = {
    source: "client-asserted",
    receivedAt: receivedAtSecond(),
    records: kept,
  };
  const engineAttempts = clampAttempts(raw.engineAttempts);
  if (engineAttempts !== undefined) section.engineAttempts = engineAttempts;
  // consoleBuild: admitted ONLY when it satisfies the shape gate, and dropped WHOLE otherwise. This is
  // the engine's own re-validation: the console applies the same regex, and the engine does not take its word
  // for it, exactly as it re-validates every closed member above. It is not truncated to fit, because a clamp
  // would bound the LENGTH of a smuggled value and not its content, and this field rides into a SIGNED bundle.
  if (typeof raw.consoleBuild === "string" && CONSOLE_BUILD_RE.test(raw.consoleBuild)) section.consoleBuild = raw.consoleBuild;
  if (Object.keys(rollupByKind).length > 0) section.rollupByKind = rollupByKind;
  return section;
}
