// The support pack's SECTION ROSTER, its health-vector summariser, and the licence allowlist projection.
//
// Kept separate from support.ts (the bundle ASSEMBLER, which gathers each section and lays out the
// bundle body): everything here is PURE and is about the pack's own SELF-DESCRIPTION -- which
// subsystems the pack promises to carry, how a partial gather is reported, and which licence fields
// may cross the no-custody boundary. None of it touches env, a DO stub or the network, so it is
// directly unit-testable, which is exactly what the health-vector contract needs (validate-support
// pins the produced section keys to the roster here).

import type { LicenceStatus } from "./licence.ts";

// SectionStatus is one bundle section's fetch OUTCOME at build time (INFRA bundle-degrades-silently-on-do-
// blip + platform-wide-outage): "ok" = the DO answered with data, "empty" = it answered but there was
// nothing to carry (honest absence, NOT a fault), "error" = the fetch threw or the DO was unreachable for
// THIS section (the section's data is missing because it could not be read, NOT because it is genuinely
// empty). Without this vector an empty section is ambiguous (no data vs a mid-outage read), and a snapshot
// taken while one subsystem was down would look identical to a healthy one. It replaces the need to ship
// raw Cloudflare runtime logs in the pack (INFRA no-runtime-logs-in-pack): the structured per-section
// outcome is the self-describing, redaction-safe equivalent -- a closed enum, never operator log text.
export type SectionStatus = "ok" | "empty" | "error";

// SUPPORT_SECTION_NAMES is the CLOSED roster of every subsystem the pack gathers through section() -- the
// explicit contract behind the sections health vector (INFRA no-runtime-logs-in-pack). The vector is the
// redaction-safe stand-in for raw Cloudflare runtime logs (which the pack cannot carry: operator log text is
// custody-unsafe), so it must be COMPLETE -- every expected subsystem always has an entry, even if a build path
// skipped one -- and EXPLICIT -- a labelled sectionsSummary a reader consults first. buildSupportBundle stamps any
// roster member missing from the produced map as "error" (couldn't-gather) so the vector can NEVER silently omit
// a subsystem, and validate-support pins the produced keys to this roster so a new fetch added without a
// section() wrapper (which would otherwise slip past unlogged) fails the gate. Order matches the gather order.
export const SUPPORT_SECTION_NAMES = [
  "downpipes",
  "preflight",
  "runs",
  "notify",
  "notifyConfig",
  "notifyHealth",
  "recovery",
  "audit",
  "auditFeed",
  "wrapKeyHealth",
  "configEvents",
  "replication",
  "controlPlaneExport",
  "ssoFailures",
  "canary",
  "alertCooldowns",
  "scheduler",
  "updates",
  "reconcile",
  "sealFaults",
  "licence",
  "ssoFailuresByKind",
  "authSignals",
  "authPosture",
  // lockoutPosture: whether the account has an Owner at all (GET /policy/lockout-preflight).
  "lockoutPosture",
  "beacon",
  "destResolution",
  "volumes",
  "siemPush",
  "otlpPush",
  "metricsFeed",
  "expiryRegistry",
  "ownerActionQueue",
  "retention",
  // Engine self-diagnostic sections: the scheduler DO's fault ledger (the errorId ring, the DO-side
  // ceremony/recovery classes, the Worker<->DO contract faults, the default destination's heartbeat, the
  // uncomputable-freshness downpipes), the per-downpipe pre-run seal-dispatch fault class, the /metrics
  // scrape surface's own health, the structural WebAuthn fault classes, and the recorders' own dropped writes.
  "schedDiag",
  "sealErrors",
  "metricsHealth",
  "webauthnFaults",
  "droppedWrites",
  // Per-downpipe source and destination fault evidence, the restore/drill/verify fault ring, and the
  // admin-side silent-fallback counters.
  "sourceFaults",
  "destFaults",
  "restoreFaults",
  "adminCounters",
  // Fault ledgers delivered into the pack: runtime wrap-key unwrap faults and when they started
  // (unwrapFaults), post-write binding-safety alarms (bindingAlarms), the self-update pipeline's failing
  // step and cause (updateFaults), the Worker-edge refusal trail (adminRefusals), the seal/verify/restore
  // core's fault locus (integrityFaults), the Worker's last-resort catches (dispatchFaults), the cron
  // plane's own health (cronHealth), the per-destination write-probe reason (destProbeFaults), the
  // destination's construction health and "unbuildable since" streak (destBuildHealth), and the
  // estate-sizing probe's outcomes (costSizing).
  "unwrapFaults",
  "bindingAlarms",
  "updateFaults",
  "adminRefusals",
  "integrityFaults",
  "dispatchFaults",
  "cronHealth",
  "destProbeFaults",
  "destBuildHealth",
  "costSizing",
  // Per-connection and per-certificate SSO/SAML health, and the RTO estimator's self-assessment.
  //
  //   - idpCertHealth:     the SAML signing certs the engine holds, including parseable-vs-total counts,
  //                        whether an expiry has ever been observed, and the curve in use.
  //   - ssoFailuresByConn: which connection is failing, by opaque ordinal (never the connId).
  //   - recoveryRto:       the RTO estimator's self-assessment, including how many samples it is based on
  //                        and why confidence degraded.
  "idpCertHealth",
  "ssoFailuresByConn",
  "recoveryRto",
  // Sections covering cases where the customer could lose data, or could not prove they have not.
  //
  //   - discoveryHealth:     the setup form's own honesty when discovering sources (GET /sources/discover
  //                          is fail-open per product): whether the account's resources were actually seen,
  //                          per-provider outcomes (denied/truncated/ok), and whether the engine account is
  //                          known at all.
  //   - auditExportAttempts: whether the customer can get their tamper-evident audit log OUT, with an
  //                          explicit record of failed export attempts.
  "discoveryHealth",
  "auditExportAttempts",
  // adminRouteErrors is the update / rollback / ramp / licence routes' outermost catch: the failing locus,
  // cause, and count of faults recorded at a stage where "nothing was changed" is not safe to assume (a
  // promote redeploys the engine, which can reset state the follow-up write needs).
  //
  // Related evidence rides inside existing sections rather than adding more top-level keys: the attach /
  // re-attach record inside discoveryHealth, the governance refusal reasons inside schedDiag, the
  // recovery-path refusals inside recovery, and the honest update outcomes inside updates.
  "adminRouteErrors",
] as const;

// summariseSections makes the sections health vector COMPLETE and EXPLICIT (INFRA no-runtime-logs-in-pack). It
// (a) stamps any SUPPORT_SECTION_NAMES member MISSING from the produced map as "error" (couldn't-gather), so the
// vector can never silently omit a subsystem -- a future fetch added without a section() wrapper, or a build path
// that skipped one -- and (b) returns the explicit ok/empty/error/expected header a reader consults FIRST in place
// of raw runtime logs. Mutates + summarises in one pass; pure over its input so both the all-present and the
// missing-member branches are directly unit-testable. Redaction-safe by construction (fixed names + four counts).
export function summariseSections(sections: Record<string, SectionStatus>): { expected: number; ok: number; empty: number; error: number } {
  for (const name of SUPPORT_SECTION_NAMES) if (!(name in sections)) sections[name] = "error";
  const count = (s: SectionStatus): number => Object.values(sections).filter((v) => v === s).length;
  return { expected: SUPPORT_SECTION_NAMES.length, ok: count("ok"), empty: count("empty"), error: count("error") };
}

// projectLicence allowlist-projects a LicenceStatus into the pack, mirroring how restoreProven.by is
// collapsed to a boolean: every field rides verbatim EXCEPT setBy, the verified Access e-mail of
// whichever owner activated the console licence (scheduler-do-account-config.ts / scheduler-do-dest-
// config.ts) -- that address is no-custody and must never leave the pack. activatedByKnown carries the
// same diagnostic (was activation attributed to an identity, or only the ADMIN_TOKEN break-glass path)
// without the address itself, and rides only when setBy actually did (readLicence attaches setBy only on
// the console-activated path). An explicit allowlist, not a spread, so a FUTURE LicenceStatus field must
// be a conscious addition here rather than riding straight through unredacted.
export function projectLicence(l: LicenceStatus | null): Record<string, unknown> | null {
  if (l === null) return null;
  return {
    tier: l.tier,
    valid: l.valid,
    ...(l.notAfter !== undefined ? { notAfter: l.notAfter } : {}),
    ...(l.reason !== undefined ? { reason: l.reason } : {}),
    ...(l.reasonCode !== undefined ? { reasonCode: l.reasonCode } : {}),
    ...(l.features !== undefined ? { features: l.features } : {}),
    ...(l.source !== undefined ? { source: l.source } : {}),
    ...(l.setAt !== undefined ? { setAt: l.setAt } : {}),
    ...(l.setBy !== undefined ? { activatedByKnown: l.setBy != null } : {}),
    ...(l.envTokenPresent !== undefined ? { envTokenPresent: l.envTokenPresent } : {}),
    ...(l.doReadFellBack !== undefined ? { doReadFellBack: l.doReadFellBack } : {}),
    ...(l.accountClaimMatchesEngine !== undefined ? { accountClaimMatchesEngine: l.accountClaimMatchesEngine } : {}),
  };
}
