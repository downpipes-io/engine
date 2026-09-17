// The support pack's SECTION ROSTER, its health-vector summariser, and the licence allowlist projection.
//
// Split out of support.ts (which is the bundle ASSEMBLER: it gathers each section and lays out the bundle
// body), which the section roster would otherwise push past the module line budget. The seam is real, not arbitrary:
// everything here is PURE and is about the pack's own SELF-DESCRIPTION -- which subsystems the pack promises
// to carry, how a partial gather is reported, and which licence fields may cross the no-custody boundary.
// None of it touches env, a DO stub or the network, so it is directly unit-testable, which is exactly what
// the health-vector contract needs (validate-support pins the produced section keys to the roster here).

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
  // lockoutPosture (defects 31/45): GET /policy/lockout-preflight, a DO route that existed and that NO gatherer
  // had ever fetched -- the same shape as recoveryRto above, and with a sharper consequence, because the
  // question it answers is whether the account has an Owner at all.
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
  // The ENGINE SELF-DIAGNOSTIC sections (support-sections-diag.ts): the scheduler DO's fault ledger (the
  // errorId ring, the DO-side ceremony/recovery classes, the Worker<->DO contract faults, the default
  // destination's heartbeat, the uncomputable-freshness downpipes), the per-downpipe pre-run seal-dispatch
  // fault class, the /metrics scrape surface's own health, the structural WebAuthn fault classes, and the
  // recorders' OWN dropped writes (the pack's under-count caveat).
  "schedDiag",
  "sealErrors",
  "metricsHealth",
  "webauthnFaults",
  "droppedWrites",
  // The per-downpipe SOURCE and DESTINATION fault evidence (the two ledgers that are
  // recorded at the fault site and would otherwise never reach the pack -- drainSourceFaultLedger() needs a
  // caller here to be read at all), the restore / drill / verify fault ring, and the admin-side
  // silent-fallback counters.
  "sourceFaults",
  "destFaults",
  "restoreFaults",
  "adminCounters",
  // Ten fault ledgers (support-sections-faults.ts) whose recorders fire on the
  // fault path. A gap is not closed until its evidence is in the
  // BUNDLE, so each of these is the delivery half of an existing recorder -- the runtime wrap-key unwrap
  // faults and WHEN they started (unwrapFaults), the post-write binding-safety alarms (bindingAlarms), the
  // self-update pipeline's failing step + cause + the live-but-unrecorded bookkeeping rows (updateFaults), the
  // Worker-edge refusal trail (adminRefusals), the seal/verify/restore core's fault locus (integrityFaults),
  // the Worker's last-resort catches (dispatchFaults), the cron plane's own health (cronHealth), the
  // per-destination write-probe reason (destProbeFaults), the destination's CONSTRUCTION health and the
  // "unbuildable since" streak (destBuildHealth), and the estate-sizing probe's outcomes (costSizing).
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
  // Each is the DELIVERY half of a recorder that fires on a real fault path -- a reminder that
  // a closed vocabulary, a live classifier and a DO route can all exist and still deliver nothing unless
  // something reads them.
  //
  //   - idpCertHealth     the SAML signing certs the engine actually holds. parseableCount < certCount
  //                       is a half-corrupt rollover paste that verifies on the good cert and says nothing
  //                       until the good one expires; expiryObserved:false is the state in which no expiry
  //                       warning can EVER fire; curves.p521 is the "every sign-in dies in a generic import
  //                       error" diagnosis. Every one of these ends in "nobody can sign in".
  //   - ssoFailuresByConn WHICH connection is failing, by OPAQUE ORDINAL (never the connId). The
  //                       aggregate said "12 SAML signature failures"; on a tenant with four SAML connections
  //                       that means re-checking all four.
  //   - recoveryRto       the RTO estimator's SELF-ASSESSMENT. GET /rto existed and NO gatherer read
  //                       it, so the estimator's every field landed in a route nothing fetched. rejectedSamples
  //                       answers "basedOnDrills says 2 but we ran 15 restore tests"; degradationCause splits
  //                       the confidence enum's erased cause into three different remedies.
  "idpCertHealth",
  "ssoFailuresByConn",
  "recoveryRto",
  // The DATA-LOSS sections. Each is a case where the customer loses data, or cannot prove they have not.
  //
  //   - discoveryHealth      the SETUP FORM'S OWN HONESTY. GET /sources/discover is fail-open per
  //                          product, so a token missing the R2 scope answers 200 with an EMPTY bucket list and
  //                          the customer builds their whole backup estate against a form that silently omitted
  //                          the resources they most needed to protect. "The form is empty" and "the account is
  //                          empty" were the same observation; lastOutcome.r2 = "denied" (or "truncated") is what
  //                          separates them, and engineAccountKnown:false is the state in which no source can
  //                          EVER be attached.
  //   - auditExportAttempts  the customer who cannot get their tamper-evident evidence OUT. Both export
  //                          paths were pass-throughs that recorded nothing on failure, so the pack showed an
  //                          intact chain with every event present and no hint that none of it could be produced.
  //                          The exported log is structurally incapable of recording its own failure to export.
  "discoveryHealth",
  "auditExportAttempts",
  // The AVAILABILITY section. adminRouteErrors is the update / rollback / ramp / licence
  // routes' OUTERMOST CATCH: each returned a fixed "nothing was changed" sentence and DISCARDED the
  // exception, so an update that always fails left no server-side trace of any kind -- not the locus, not
  // the cause, not even that it happened. And the sentence can be FALSE: the promote redeploys the engine,
  // which momentarily resets the very DO the follow-up write needs, so the throw can land AFTER the new
  // version is live. mutatingFaults is the count of faults recorded at a stage where that claim is not safe
  // to believe.
  //
  // OTHER evidence deliberately rides INSIDE existing sections rather than adding more
  // top-level keys, because it answers the same question the host section already asks: the attach /
  // re-attach record inside discoveryHealth (what the form could SEE, then whether the binding could be
  // WRITTEN), the governance refusal REASONS inside schedDiag, the recovery-path refusals inside recovery,
  // and the honest update outcomes inside updates.
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
