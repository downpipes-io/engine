import { b64urlEncode, utf8 } from "../crypto/bytes.ts";
import { recipientFingerprint, sealToRecipients } from "../crypto/capsule.ts";
import { aesGcmSeal, hkdfSha384 } from "../crypto/primitives.ts";
import { hybridSign } from "../crypto/sign.ts";
import { unwiredSecretSinks } from "../dest/restore-sink.ts";
import type { Env } from "../env.d.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { signerFingerprint } from "../format/writer.ts";
import { loadRecipientPublic, loadSigner } from "../keys-env.ts";
import { FREE_PLAN_SUBREQUEST_CEILING, LOW_SLICE_WALL_MS, resolveSliceScaleKnobs } from "../seal/budget.ts";
import type { ClientDiagnosticsSection } from "./client-diag-vocab.ts";
import { computeEstateRollup, type EstateRollup } from "./estate.ts";
import { type LicenceStatus, readLicence } from "./licence.ts";
import { runPreflight } from "./preflight.ts";
import { buildBandManifest } from "./support-band-manifest.ts";
import { doURL } from "../do-url.ts";
import { buildStatus } from "./status.ts";
import { projectLicence, type SectionStatus, summariseSections } from "./support-roster.ts";
import { fetchAuditExportAttempts, fetchAuditFeedState, fetchAuditStatus, fetchConfigEvents, fetchMetricsFeed } from "./support-sections-audit.ts";
import { fetchExportState, fetchRecoveryStatus } from "./support-sections-recovery.ts";
import { flushAdminAuthMethodUsage } from "./auth-method-usage.ts";
import { fetchAuthPosture, fetchAuthSignals, fetchIdpCertHealth, fetchLockoutPosture, fetchSsoFailures, fetchSsoFailuresByConn, fetchSsoFailuresByKind } from "./support-sections-auth.ts";
import { buildKeysHealth, danglingDestinationRef, fetchBeaconState, fetchConfigIntegrity, fetchDestinationIdSet, fetchDestResolution, fetchDiscoveryHealth, fetchExpiryRegistry, fetchLicenceActivationRefusals, fetchLicenceExpiryTracker, fetchOwnerActionQueue, fetchRosterIntegrity, fetchSourcesDetached, fetchWrapKeyHealth } from "./support-sections-config.ts";
import { capTruncationSubjectIndex, fetchAdminCounters, fetchDestFaults, fetchDroppedWrites, fetchMetricsHealth, fetchRateLimitHealth, fetchRestoreFaults, fetchSchedDiag, fetchSealErrors, fetchSourceFaults, fetchWebauthnFaults, freshnessUncomputableIndex } from "./support-sections-diag.ts";
import { fetchRtoEstimates, projectDownpipeRow, type SupportDownpipeRow, type SupportDownpipeState, selfIdentityDegradedCount, stateRefusalIndex } from "./support-sections-downpipes.ts";
import { fetchAdminRefusals, fetchAdminRouteErrors, fetchBindingAlarms, fetchCostSizing, fetchCronHealth, fetchDestBuildHealth, fetchDestProbeFaults, fetchDispatchFaults, fetchIntegrityFaults, fetchUnwrapFaults, fetchUpdateFaults } from "./support-sections-faults.ts";
import { fetchAlertCooldowns, fetchNotifyConfig, fetchNotifyHealth, fetchNotifyHistory } from "./support-sections-notify.ts";
import { fetchOtlpPush, fetchSiemPush } from "./support-sections-push.ts";
import { fetchDriveBudgetYield, fetchRunHistory, fetchSchedulerSignals, fetchStatusBaseline, fetchStatusDoOpts, fetchUpdateStatus } from "./support-sections-runs.ts";
import { fetchCanaryHealth, fetchReconcileInventory, fetchReplication, fetchRetentionState, fetchSealFaults, fetchWormPosture, sealKnobs } from "./support-sections-seal.ts";
import { clampNonNegInt, nowIso } from "./support-shared.ts";

// The section ROSTER + the health-vector summariser + the licence allowlist projection live in the pure
// support-roster.ts leaf (the pack's self-description; this module is the assembler). Re-exported so every
// existing importer -- and the validator, which pins the produced section keys to the roster -- is unchanged.
export { SUPPORT_SECTION_NAMES, summariseSections } from "./support-roster.ts";

// Secure support diagnostics. When a customer raises a ticket, the vendor needs
// evidence, and the product's no-custody rule forbids the two easy answers (a vendor-
// held Cloudflare token, or vendor dashboard access). Two mechanisms replace them:
//
//   1. The SUPPORT BUNDLE: a redaction-safe aggregation of what support actually needs
//      (engine version + provenance, presence-only status, the preflight report, per-
//      downpipe run-history rows with their coarse error vocabulary, notification
//      delivery outcomes, licence tier). It NEVER contains a key, a secret value, a
//      record name beyond the customer's own downpipe names, or customer data. It is
//      SIGNED by the engine's run signer so support can verify provenance, and when
//      VENDOR_SUPPORT_PUBLIC is configured it is SEALED to that key (the same hybrid
//      X25519+ML-KEM-1024 construction as archive recipients) so the bundle is
//      confidential through whatever ticket system carries it.
//
//   2. PLATFORM-ISSUED INGEST CREDENTIALS (client/secret): an Owner mints a time-boxed
//      credential per scope. The "diagnostics" scope lets vendor support PULL the same
//      bundle from GET /support/diagnostics during a ticket without any console or
//      Access seat; the "audit-feed" scope lets the customer's SIEM collector poll the
//      hash-chained audit events from GET /support/audit-feed. The secret's SHA-384
//      (never the secret) is stored, the comparison is constant-time, expiry is
//      enforced server-side, one credential is active per scope, the most recent 50 pulls
//      are recorded on the grant (visible to the customer; older entries roll over),
//      and revocation is immediate. A
//      credential grants EXACTLY its read-only feed: no admin route, no restore, no
//      configuration, no customer data.
//
// The section GATHERERS live in the support-sections-*.ts siblings (runs / notify / audit /
// auth / seal / config domains) and the ingest-credential subsystem in support-ingest.ts;
// this module keeps the shared types, the section roster, and the bundle assembly/signing.

const INFO_SUPPORT_BUNDLE_KEY = "downpipe/engine support-bundle-key v1";

type SupportDownpipe = SupportDownpipeState;


// ADDED_SOURCE_TYPES is the engine's ADVERTISED Cloudflare-wide (token-authenticated) source vocabulary (G311),
// mirroring the allow-list the DO enforces on POST /sources/discovery-sources (scheduler-do-account-config.ts)
// and the per-type booleans GET /sources/discovery advertises (router-discovery.ts). The console renders the
// whole Cloudflare-wide sources tier from that advertisement, so an OLDER engine that advertises none of them
// silently hides the tier -- and from the console side the skew is invisible ("docs show a Cloudflare-wide
// sources section but my console has none"). Projecting the vector lets support confirm "this engine build does
// not advertise the feature" rather than guessing at a console bug. Booleans/counts of capabilities only.
const ADDED_SOURCE_TYPES = ["cf-config", "workers", "stream", "images", "artifacts"] as const;

// SupportBundleContext is the REQUEST-scoped fact the bundle cannot derive from env or the DO (G267):
// accessPerimeter -- whether the read that is generating this pack traversed a Cloudflare Access application
// (the edge injects cf-access-jwt-assertion on every such request). Its presence means the hostname is
// Access-FRONTED, so the out-of-band /support/* pulls a minted collector credential is FOR, and the top-level
// /metrics scrape, are turned away at the EDGE before the engine ever sees the credential -- the "my
// Prometheus/SIEM collector credential never works" ticket. GET /support already computes it for the console's
// mint-time warning, but it never rode into the SEALED bundle, so support could not make the correlation
// remotely (a pull credential configured AND an Access perimeter fronting the host). A presence BOOLEAN only:
// never the Access team domain, the JWT, or the header value. Absent (honestly omitted) when the caller cannot
// supply it, so a pack built off-request never fabricates a false "no perimeter".
export interface SupportBundleContext {
  accessPerimeter?: boolean;
  // clientDiagnostics (Wave C, I1 REQUEST-SCOPED ONLY): the OPTIONAL console-asserted, value-free error-class
  // section. Supplied ONLY on the console-generate POST path (router-status.ts POST /support/bundle), already
  // re-validated + clamped by projectClientDiagnostics, and folded into ONLY this in-request bundle. It is NOT
  // gathered through section(), is NOT a SUPPORT_SECTION_NAMES roster member, and triggers NO DO write. When
  // absent (the vendor bearer-pull GET /support/diagnostics and every scheduled build) the section is
  // STRUCTURALLY omitted: there is no console POST body on those paths.
  //
  // It rides HERE, on the context object, rather than as its own positional parameter. Both this branch and the
  // clientdiag branch had changed the SAME third parameter of buildSupportBundle/signedSupportBundle/
  // sealedSupportBundle, so a naive merge resolution would have silently DROPPED one of the two evidence
  // channels: take one side and the browser evidence never reaches the bundle, take the other and the D5
  // section context goes. One object, both channels, no positional collision to resolve wrongly next time.
  clientDiagnostics?: ClientDiagnosticsSection | null;
}

// buildSupportBundle aggregates the redaction-safe diagnostic facts. Every field is
// either presence-only, a coarse enumerated outcome, or the customer's own labels.
export async function buildSupportBundle(env: Env, scheduler: DurableObjectStub, ctx: SupportBundleContext = {}): Promise<Record<string, unknown>> {
  const clientDiagnostics = ctx.clientDiagnostics;
  // G253: flush the auth-method-usage events this isolate's throttle is still holding, BEFORE the sections are
  // read. The router coalesces the recording of a credential path to one DO write per method per minute, so a
  // burst of break-glass traffic that stops inside its own window would otherwise sit in memory with no later
  // request to carry it out -- and this pack, built from that same isolate, would under-report the very usage it
  // exists to bound. Best-effort: it never throws and the build proceeds either way.
  await flushAdminAuthMethodUsage(scheduler);
  // The per-section fetch-status health vector: each data fetch runs through section(), which records its
  // OUTCOME and degrades a failed section to a safe fallback (honest absence) INSTEAD of throwing out of the
  // whole build. Before this, a DO blip on /downpipes or /history CRASHED the entire bundle (an unguarded
  // fetch), so a snapshot taken mid-outage produced nothing at all rather than a self-describing partial.
  const sections: Record<string, SectionStatus> = {};
  async function section<T>(name: string, fn: () => Promise<T>, fallback: T, isEmpty: (v: T) => boolean): Promise<T> {
    try {
      const v = await fn();
      sections[name] = isEmpty(v) ? "empty" : "ok";
      return v;
    } catch {
      sections[name] = "error";
      return fallback;
    }
  }

  // Presence-only status + the preflight report (both already redaction-safe). Every DO-backed section is
  // guarded so one section's fault degrades to a fallback + an "error" flag, never a crashed build.
  const downpipes = await section<Array<SupportDownpipe>>("downpipes", async () => (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as Array<SupportDownpipe>, [], (v) => v.length === 0);
  // destIdSet (Wave A4, G044/G268): the configured-destination roster, so a downpipe pinned to a since-removed
  // destination (which fails its run loudly but was never counted or attributed in the pack) is cross-checkable.
  // null on a roster read fault -> the per-downpipe danglingDestinationRef check and the count are SKIPPED (no
  // false positives against an unreadable roster; destResolution separately flags that read fault).
  const destIdSet = await fetchDestinationIdSet(scheduler);
  const danglingDestinationRefs = destIdSet ? downpipes.filter((d) => danglingDestinationRef(d.config as { destinationId?: unknown; destinationIds?: unknown }, destIdSet)).length : 0;
  // Pass the DO-owned status facts (break-glass disposal, expiry/cleanup, the live console-set destination) plus
  // the restorability count from the roster, so the pack's status lights up the same break-glass-disposal /
  // expiry / statusSource findings the console shows (Phase 2 item 1). restorabilityProven counts downpipes with
  // an offline-restorability proof, from the roster already fetched (no extra DO round trip); 0 is meaningful.
  const statusOpts = await fetchStatusDoOpts(scheduler);
  const restorabilityProven = downpipes.reduce((n, d) => (d?.restoreProven ? n + 1 : n), 0);
  const status = buildStatus(env, downpipes.length, { ...statusOpts, restorabilityProven });
  // SELF-OBSERVE the deploy identity at bundle build: the
  // engine-version-change audit marker was previously recorded ONLY when GET /admin/status ran
  // (router-status.ts posts the observation), so a bundle captured after a redeploy but before any
  // status poll -- exactly when a customer whose backups just broke reaches for the support pack --
  // could MISS the owner-#1 deploy keystone and downgrade a deploy-wipe to the neutral reading.
  // Post the SAME StatusObservation the status route posts, BEFORE fetchConfigEvents reads the
  // excerpt, so the marker exists in the chain the excerpt is about to read. Idempotent (diffStatus
  // records only on a CHANGE vs the stored snapshot; an unchanged identity appends nothing) and
  // best-effort (a DO hiccup degrades to the pre-fix behaviour, never fails the bundle).
  try {
    await scheduler.fetch(doURL("/audit-status"), {
      method: "POST",
      body: JSON.stringify({
        signerConfigured: status.signerConfigured,
        breakGlassConfigured: status.breakGlassConfigured,
        destConfigured: status.destConfigured,
        engineVersion: status.engineVersion,
        cfVersionId: status.cfVersionId,
      }),
      headers: { "content-type": "application/json" },
    });
  } catch {
    // Best-effort: the bundle still builds; the excerpt simply lacks a this-instant observation.
  }
  const preflight = await section<Awaited<ReturnType<typeof runPreflight>> | null>("preflight", () => runPreflight(env, scheduler), null, (v) => v === null);
  const runs = await section<Record<string, unknown[]>>("runs", () => fetchRunHistory(scheduler), {}, (v) => Object.keys(v).length === 0);
  // notify (G023/G342): ONE fetch of the DO's 1000-entry delivery ring now yields three views -- the recency
  // window the pack has always carried, the FAILURE-BIASED window (the most recent undelivered rows plus the
  // smart-retained ONSET row per channel kind), and the per-kind rollup over the whole ring.
  const notifyResult = await section<Awaited<ReturnType<typeof fetchNotifyHistory>>>(
    "notify",
    () => fetchNotifyHistory(scheduler),
    { entries: [], failures: [], byChannelKind: {} },
    (v) => v.entries.length === 0,
  );
  const notify = notifyResult.entries;
  const notifyConfig = await section("notifyConfig", () => fetchNotifyConfig(scheduler), { channelCount: 0, channelKinds: [] as string[], disabledChannelCount: 0, ruleCount: 0, danglingChannelRefs: 0, rules: [] as Array<{ events?: unknown; minSeverity?: string; scope?: string }> }, (v) => v.channelCount === 0 && v.ruleCount === 0);
  // notifyHealth / audit / auditFeed / wrapKeyHealth (phase3-cpr-notify): notify-pipeline drop counters, the
  // audit-chain verify verdict, the SIEM pull-credential recency, and the CONFIG_WRAP_KEY decrypt health -- each
  // guarded through section() like every other DO-backed fetch so a blip degrades to honest absence.
  const notifyHealth = await section<Record<string, unknown>>("notifyHealth", () => fetchNotifyHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const recovery = await section<Record<string, unknown>>("recovery", () => fetchRecoveryStatus(scheduler), {}, (v) => Object.keys(v).length === 0);
  const audit = await section<Record<string, unknown>>("audit", () => fetchAuditStatus(scheduler), {}, (v) => Object.keys(v).length === 0);
  const auditFeed = await section<Record<string, unknown>>("auditFeed", () => fetchAuditFeedState(scheduler), {}, (v) => Object.keys(v).length === 0);
  // metricsFeed (Wave A7 G262): the metrics-scope ingest-credential grant state (mirror of auditFeed), so a
  // Prometheus/Grafana/Datadog scraper that stopped collecting is diagnosable. isEmpty when the scope is not granted.
  const metricsFeed = await section<Record<string, unknown>>("metricsFeed", () => fetchMetricsFeed(scheduler), { configured: false }, (v) => v.configured !== true);
  // expiryRegistry (Wave A7 G260): the WHOLE credential-expiry registry (status carries only two counts). isEmpty
  // when no rows are tracked. The section-level fault -> "error" (a read fault is not an empty registry).
  const expiryRegistryResult = await section<{ rows: Array<Record<string, unknown>> }>("expiryRegistry", () => fetchExpiryRegistry(scheduler), { rows: [] }, (v) => v.rows.length === 0);
  // ownerActionQueue (Wave A6 G259/G265): the dual-control owner-action queue aggregate (pendingCount, oldest
  // proposal, kinds, expiredUndecided) so a stuck high-blast-radius change awaiting a second owner is visible
  // even after its propose event rolled off the audit excerpt. isEmpty when the queue is quiet.
  const ownerActionQueue = await section<Record<string, unknown>>("ownerActionQueue", () => fetchOwnerActionQueue(scheduler), {}, (v) => Object.keys(v).length === 0);
  const wrapKeyHealth = await section<Record<string, unknown>>("wrapKeyHealth", () => fetchWrapKeyHealth(env, scheduler), {}, (v) => Object.keys(v).length === 0);
  const configEventsResult = await section<{ events: unknown[]; fetched: boolean }>("configEvents", () => fetchConfigEvents(scheduler), { events: [], fetched: false }, (v) => v.events.length === 0);
  const configEvents = configEventsResult.events;
  // The fallback is NULL, not {}. A thrown /replication read must not degrade to the empty map:
  // projectReplication reads an empty map as "not one destination has ever reported" and marks EVERY
  // configured destination never-reported, on every downpipe -- a fact the read never established (what
  // it established is "I could not read the heartbeats"). Null says exactly that, and the projector
  // suppresses the never-reported claim on it. The engine already carries the same pattern two lines
  // below: fetchDestinationIdSet returns null on a read fault so the dangling check produces no false
  // positives against an unreadable roster.
  //
  // THE STATUS VECTOR MUST FAIL IN THE SAME DIRECTION AS THE DATA. fetchReplication SWALLOWS the fault (it
  // returns null rather than throwing, because the projector needs the null), so section()'s catch never runs
  // on that path alone; the fetch is re-wrapped here to re-raise the unreadable case, so the null still
  // reaches the projector (it IS the fallback) and the status honestly reads "error" -- the one line of
  // the pack a support engineer checks before trusting a section.
  const replication = await section<Record<string, Array<Record<string, unknown>>> | null>(
    "replication",
    async () => {
      const map = await fetchReplication(scheduler);
      if (map === null) throw new Error("replication heartbeats unreadable");
      return map;
    },
    null,
    (v) => v !== null && Object.keys(v).length === 0,
  );
  const controlPlaneExport = await section<Record<string, unknown>>("controlPlaneExport", () => fetchExportState(scheduler), {}, (v) => Object.keys(v).length === 0);
  const ssoFailures = await section<Record<string, { count: number; lastAt: string }>>("ssoFailures", () => fetchSsoFailures(scheduler), {}, (v) => Object.keys(v).length === 0);
  // canary / alertCooldowns (phase3-cpr-notify): the canary liveness + transition ring, and the per-downpipe
  // alert-cooldown state -- each guarded through section() like every other DO-backed fetch.
  const canary = await section<Record<string, unknown>>("canary", () => fetchCanaryHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const alertCooldowns = await section<Record<string, unknown>>("alertCooldowns", () => fetchAlertCooldowns(scheduler), {}, (v) => Object.keys(v).length === 0);
  const schedulerSignals = await section<Record<string, unknown>>("scheduler", () => fetchSchedulerSignals(scheduler), {}, (v) => Object.keys(v).length === 0);
  const updateStatus = await section<Record<string, unknown>>("updates", () => fetchUpdateStatus(env, scheduler), {}, (v) => Object.keys(v).length === 0);
  // reconcile (phase3-seal): the orphan-reconcile inventory + RUNLOG-health, guarded through section() like
  // every other DO-backed fetch so a reconcile-pass blip degrades to honest absence instead of crashing the build.
  const reconcile = await section<unknown[]>("reconcile", () => fetchReconcileInventory(scheduler), [], (v) => v.length === 0);
  // sealFaults (phase3-seal): the bounded seal-fault OBSERVE ring, guarded through section() like every other
  // DO-backed fetch so a fault-ring read blip degrades to honest absence instead of crashing the build.
  const sealFaults = await section<unknown[]>("sealFaults", () => fetchSealFaults(scheduler), [], (v) => v.length === 0);
  // retention (G071/G190): what the last prune pass skipped and WHY, and per downpipe whether it applied / was a
  // dry-run (enforce never set: the commonest "storage keeps growing" cause) / deferred / threw. isEmpty when
  // the pass has never run (honest absence); a read fault reads "error".
  const retention = await section<Record<string, unknown>>("retention", () => fetchRetentionState(scheduler), {}, (v) => Object.keys(v).length === 0);
  // The ENGINE SELF-DIAGNOSTIC sections (round-2 gap audit). Each is a DO-backed read guarded through section()
  // like every other, so a blip degrades to honest absence + an "error" flag rather than a crashed build, and
  // each is OMITTED from the bundle when clean (the healthy fleet's steady state is silence here).
  //   schedDiag      : the scheduler DO's fault ledger (G013 errorId ring / G014 + G039 ceremony + recovery
  //                    classes / G221 contract faults / G120 default-destination heartbeat / G076 freshness).
  //   sealErrors     : the per-downpipe PRE-RUN seal-dispatch fault class (G163) -- the throw that lands before
  //                    a run index exists, so it leaves NO run row and only an anonymous tick counter.
  //   metricsHealth  : the Prometheus /metrics scrape surface's own health (G049).
  //   webauthnFaults : the 14 structural WebAuthn defect classes, split by ceremony phase (G158).
  //   droppedWrites  : the recorders' OWN dropped writes (G100/G331/G104). READ THIS FIRST: any non-zero count
  //                    means every other counter in this pack is a LOWER BOUND, and says of which kind.
  const schedDiag = await section<Record<string, unknown>>("schedDiag", () => fetchSchedDiag(scheduler), {}, (v) => Object.keys(v).length === 0);
  const sealErrors = await section<Record<string, Record<string, unknown>>>("sealErrors", () => fetchSealErrors(scheduler), {}, (v) => Object.keys(v).length === 0);
  const metricsHealth = await section<Record<string, unknown>>("metricsHealth", () => fetchMetricsHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const webauthnFaults = await section<Record<string, unknown>>("webauthnFaults", () => fetchWebauthnFaults(scheduler), {}, (v) => Object.keys(v).length === 0);
  const droppedWrites = await section<Record<string, { count: number; lastAt?: string }>>("droppedWrites", () => fetchDroppedWrites(scheduler), {}, (v) => Object.keys(v).length === 0);
  //   sourceFaults   : per downpipe, WHY the crawl could not fully capture (the closed reason behind every
  //                    incompleteness sentinel, the tolerant-parse drops that void coverage behind a GREEN run,
  //                    the run-fatal transport class + crawl stage, the D1 snapshot verdict, the corrupt resume
  //                    tokens, the absorbed 429s, the security refusals).
  //   destFaults     : per downpipe, the closed identity of every FAILING destination op, plus the degradation
  //                    counters of a store that is quietly making a green run slow and expensive.
  //   restoreFaults  : the bounded restore / drill / blind-test / attest fault ring (phase + class + count).
  //   adminCounters  : the admin-side silent-fallback / silent-exclusion counters.
  const sourceFaults = await section<Record<string, unknown>>("sourceFaults", () => fetchSourceFaults(scheduler), {}, (v) => Object.keys(v).length === 0);
  const destFaults = await section<Record<string, unknown>>("destFaults", () => fetchDestFaults(scheduler), {}, (v) => Object.keys(v).length === 0);
  const restoreFaults = await section<unknown[]>("restoreFaults", () => fetchRestoreFaults(scheduler), [], (v) => v.length === 0);
  const adminCounters = await section<Record<string, { count: number; lastAt?: string }>>("adminCounters", () => fetchAdminCounters(scheduler), {}, (v) => Object.keys(v).length === 0);
  // ---- the ROUND-4 fault ledgers (support-sections-faults.ts) --------------------------------------------
  // Each is a DO-backed read guarded through section() like every other, so a blip degrades to honest absence
  // + an "error" flag rather than a crashed build, and each is OMITTED from the bundle when clean (the healthy
  // fleet's steady state here is silence). Every one of these is the DELIVERY half of a recorder that already
  // fires on the fault path: the evidence existed in the DO and nothing read it, which is the exact failure
  // this pass exists to end.
  const unwrapFaults = await section<Record<string, unknown>>("unwrapFaults", () => fetchUnwrapFaults(scheduler), {}, (v) => Object.keys(v).length === 0);
  const bindingAlarms = await section<unknown[]>("bindingAlarms", () => fetchBindingAlarms(scheduler), [], (v) => v.length === 0);
  const updateFaults = await section<unknown[]>("updateFaults", () => fetchUpdateFaults(scheduler), [], (v) => v.length === 0);
  const adminRefusals = await section<Record<string, { count: number; lastAt?: string }>>("adminRefusals", () => fetchAdminRefusals(scheduler), {}, (v) => Object.keys(v).length === 0);
  const integrityFaults = await section<Record<string, unknown>>("integrityFaults", () => fetchIntegrityFaults(scheduler), {}, (v) => Object.keys(v).length === 0);
  const dispatchFaults = await section<unknown[]>("dispatchFaults", () => fetchDispatchFaults(scheduler), [], (v) => v.length === 0);
  const cronHealth = await section<Record<string, unknown>>("cronHealth", () => fetchCronHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const destProbeFaults = await section<Record<string, unknown>>("destProbeFaults", () => fetchDestProbeFaults(scheduler), {}, (v) => Object.keys(v).length === 0);
  const destBuildHealth = await section<Record<string, unknown>>("destBuildHealth", () => fetchDestBuildHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const costSizing = await section<Record<string, unknown>>("costSizing", () => fetchCostSizing(scheduler), {}, (v) => Object.keys(v).length === 0);
  const licence = await section<LicenceStatus | null>("licence", () => readLicence(env, scheduler), null, (v) => v === null);
  // ssoFailuresByKind / authSignals / authPosture (phase3-idp-auth): the per-protocol SSO failure split, the
  // auth/RBAC defensive-branch counters, and the session-key/do-plaintext-secret posture probes -- each a DO
  // fetch guarded through section() like the rest. keys (P3) is env-derived key-material health (buildKeysHealth).
  const ssoFailuresByKind = await section<Record<string, Record<string, { count: number; lastAt: string }>>>("ssoFailuresByKind", () => fetchSsoFailuresByKind(scheduler), {}, (v) => Object.keys(v).length === 0);
  const authSignals = await section<Record<string, Record<string, unknown>>>("authSignals", () => fetchAuthSignals(scheduler), {}, (v) => Object.keys(v).length === 0);
  const authPosture = await section<Record<string, unknown>>("authPosture", () => fetchAuthPosture(scheduler), {}, (v) => Object.keys(v).length === 0);
  // lockoutPosture (defects 31 and 45, another pass): the DO's OWN lockout pre-flight, whose only caller
  // until now was the console's require-access wizard. It is the one surface built to answer "can this account
  // still get back in", and the pack read 73 DO routes and not that one -- so an account that has silently lost
  // its only Owner grant to a corrupt record sent a pack byte-identical to a healthy account's. It is guarded
  // through section() like the rest, so an engine too old to serve the route reads "error" rather than a clean
  // "empty" that would assert a healthy roster it never read.
  const lockoutPosture = await section<Record<string, unknown>>("lockoutPosture", () => fetchLockoutPosture(scheduler), {}, (v) => Object.keys(v).length === 0);
  // The ROUND-5 auth/IdP + recovery sections, each guarded through section() like the rest (so an unreadable
  // one reads "error", never a clean "empty"). ssoFailuresByConn is keyed by an OPAQUE ordinal, never a connId;
  // idpCertHealth is a deliberate AGGREGATE for the same reason. recoveryRto reads GET /rto, a DO route that
  // existed and that NO gatherer had ever fetched -- the estimator's whole output landed in a void.
  const ssoFailuresByConn = await section<Record<string, Record<string, { count: number; lastAt: string }>>>("ssoFailuresByConn", () => fetchSsoFailuresByConn(scheduler), {}, (v) => Object.keys(v).length === 0);
  const idpCertHealth = await section<Record<string, unknown>>("idpCertHealth", () => fetchIdpCertHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const recoveryRto = await section<Record<string, unknown>>("recoveryRto", () => fetchRtoEstimates(scheduler), {}, (v) => Object.keys(v).length === 0);
  // The ROUND-6 DATA-LOSS sections, guarded through section() like the rest. discoveryHealth (G008) is the
  // setup form's own honesty: a fail-open discovery answers 200 with an empty list whether the account holds
  // nothing, the token cannot see it, or the page cap cut it off, and the customer protects only what they were
  // shown. auditExportAttempts (G022) is the customer who cannot get their tamper-evident evidence out of the
  // account: both export paths were pass-throughs that recorded nothing when they failed.
  const discoveryHealth = await section<Record<string, unknown>>("discoveryHealth", () => fetchDiscoveryHealth(scheduler), {}, (v) => Object.keys(v).length === 0);
  const auditExportAttempts = await section<Record<string, unknown>>("auditExportAttempts", () => fetchAuditExportAttempts(scheduler), {}, (v) => Object.keys(v).length === 0);
  // adminRouteErrors (G183): the update / rollback / ramp / licence routes' outermost catches, which returned
  // a fixed "nothing was changed" and threw the exception away. Guarded through section() like the rest.
  const adminRouteErrors = await section<Record<string, unknown>>("adminRouteErrors", () => fetchAdminRouteErrors(scheduler), {}, (v) => Object.keys(v).length === 0);
  const keys = await buildKeysHealth(env);
  // beaconState / destResolution (phase3-lic-cfg-dest): the opt-in vendor-beacon last-POST outcome and the
  // EFFECTIVE resolved destination write settings -- each guarded through section() like the rest.
  const beaconState = await section<Record<string, unknown>>("beacon", () => fetchBeaconState(scheduler), {}, (v) => Object.keys(v).length === 0);
  const destResolution = await section<Record<string, unknown>>("destResolution", () => fetchDestResolution(env, scheduler), {}, (v) => Object.keys(v).length === 0);
  // siemPush / otlpPush (support-pack Wave A1): the SIEM audit-log push + OTLP metrics push delivery trails.
  // Each drain records a bounded trail on its scheduler-DO; the pack now carries the redaction-safe projection
  // (presence + transport + cursor lag + last attempts) so "our SIEM feed / OTLP metrics stopped" is
  // diagnosable. isEmpty when the drain is not configured and has no trail (honest absence).
  const siemPush = await section<Record<string, unknown>>("siemPush", () => fetchSiemPush(scheduler), { configured: false }, (v) => v.configured !== true && v.trail === undefined);
  const otlpPush = await section<Record<string, unknown>>("otlpPush", () => fetchOtlpPush(scheduler), { configured: false }, (v) => v.configured !== true && v.trail === undefined);
  // volumes (self-serve volume-based licensing): the estate usage rollup -- how much this engine is
  // actually protecting right now (see estate.ts), carried here as `volumes` (the identical object GET
  // /admin/licence carries as `estate`) so support sees usage without a separate query. computeEstateRollup
  // itself never throws (a fault resolves to null); the wrapper here RE-THROWS a null result so a genuine
  // compute fault reads sections.volumes "error" like every other DO-backed section, distinct from a fleet
  // that genuinely has zero downpipes yet, which isEmpty reads as "empty" (honest absence, not a fault).
  const volumes = await section<EstateRollup | null>(
    "volumes",
    async () => {
      const v = await computeEstateRollup(scheduler);
      if (v === null) throw new Error("estate rollup unavailable");
      return v;
    },
    null,
    (v) => v !== null && v.downpipes === 0,
  );
  // The default destination's live WORM / Object-Lock posture (Phase 2 item 3). Best-effort, time-boxed, fail-soft:
  // {} on any timeout/fault (it rides outside the section() roster, carrying its own honest absence), so a
  // live-probe hiccup never blocks or fails the bundle build.
  const wormPosture = await fetchWormPosture(env, scheduler);
  // driveBudgetYields / configIntegrity / licenceActivationRefusals / licenceExpiryTracker / sourcesDetached /
  // deployBaseline (phase3-lic-cfg-dest): additional diagnostic signals, each best-effort ({} on failure via
  // their own internal guard) and OMITTED from the pack when empty; projected below. They carry their own honest
  // absence, so they ride outside the section() health roster (unlike the core DO-backed fetches above).
  const driveBudgetYields = await fetchDriveBudgetYield(scheduler);
  const configIntegrity = await fetchConfigIntegrity(scheduler);
  const licenceActivationRefusals = await fetchLicenceActivationRefusals(scheduler);
  const licenceExpiryTracker = await fetchLicenceExpiryTracker(scheduler);
  const sourcesDetached = await fetchSourcesDetached(env, scheduler);
  const rosterIntegrity = await fetchRosterIntegrity(scheduler);
  const deployBaseline = await fetchStatusBaseline(scheduler);
  // rateLimitDoHealth (G104): the account-global CF API limiter's own health. It rides outside the section()
  // roster because it is a DIFFERENT Durable Object (not the scheduler) and carries its own honest absence:
  // {} when the optional binding is absent, which infra.rateLimitDoConfigured already reports.
  const rateLimitDoHealth = await fetchRateLimitHealth(env);
  // cfVersionId (two-engines-flapping-ledger): this running engine's immutable Cloudflare deploy id, from the
  // CF_VERSION_METADATA binding. `accountTag + cfVersionId` is the per-engine identity a diagnosis pairs to
  // disambiguate two engines flapping one licence-ledger row. Non-secret; omitted under env-fallback / local dev.
  const cfVm = env.CF_VERSION_METADATA;
  const cfVersionId = cfVm && typeof cfVm.id === "string" && cfVm.id !== "" ? cfVm.id : undefined;

  // infra scale/plan derivations (INFRA slice-knobs-misconfigured / cpu-ms-misconfigured-low; SCHED
  // free-plan-subrequest-cap). Resolve the scale knobs once, then derive the plan-tier + cpu cross-checks from
  // what IS runtime-readable -- the resolved budgets, the platform ceilings, and the observed per-tick subrequest
  // spend -- because the account PLAN itself cannot be queried by a Worker. All ints / booleans (no-custody).
  const scaleKnobs = resolveSliceScaleKnobs(env);
  const cpuMsRawStr = typeof env.CPU_MS === "string" ? env.CPU_MS.trim() : "";
  const cpuMsRaw = cpuMsRawStr !== "" ? Number(cpuMsRawStr) : Number.NaN;
  const cpuMs = Number.isFinite(cpuMsRaw) && cpuMsRaw > 0 ? Math.floor(cpuMsRaw) : undefined;
  // cpuMsInvalid (G317): the operator SET the CPU_MS mirror and it is not a positive number. Dropping it
  // silently made a TYPO indistinguishable from "never mirrored", so the sliceWallWithinCpuMs cross-check
  // (whether a slice can be CPU-KILLED before it checkpoints, an uncatchable death that wedges the run) simply
  // vanished with no explanation. A boolean only; the rejected raw value is never carried. This matches the
  // invalid-derivation pattern the scaleKnobs resolutions already use.
  const cpuMsInvalid = cpuMsRawStr !== "" && cpuMs === undefined;
  // maxObservedSubrequestSpend: the largest per-tick subrequest spend the DO's bounded outcome ring recorded (0
  // if it never recorded a tick). A recorded tick that SPENT more than the free-plan ceiling and still reported
  // an outcome PROVES the account is on a PAID plan -- a free plan would have been killed at the 50-cap before it
  // could record. Derived from the already-projected, already-clamped tick ring, never a fresh read.
  const observedTicks = Array.isArray(schedulerSignals.ticks) ? (schedulerSignals.ticks as Array<{ budgetSpent?: unknown }>) : [];
  const maxObservedSubrequestSpend = observedTicks.reduce((m, t) => Math.max(m, clampNonNegInt(t.budgetSpent)), 0);

  // sections completeness + summary (INFRA no-runtime-logs-in-pack): stamp any roster subsystem MISSING from the
  // produced map as "error" and build the explicit ok/empty/error/expected header. Today every section() runs
  // unconditionally, so the completeness fill is a forward-safety net; validate-support pins the produced keys to
  // SUPPORT_SECTION_NAMES so the roster and the gather cannot drift.
  const sectionsSummary = summariseSections(sections);

  // refusalIndex (G095/G210): the downpipeId -> state-refusal lookup, built from the scheduler section ALREADY
  // fetched above (no extra DO round trip); empty when that section faulted or nothing was refused.
  // selfIdentityDegradedFleet (G282): the fleet count of downpipes whose source config can no longer
  // re-identify itself, so a roster rebuild after a control-plane loss cannot reconstruct them.
  const refusalIndex = stateRefusalIndex(schedulerSignals);
  const selfIdentityDegradedFleet = selfIdentityDegradedCount(downpipes as unknown as SupportDownpipeRow[]);
  // freshnessIndex (G076): the downpipes whose staleness rule can NEVER arm, from the schedDiag section ALREADY
  // fetched above (no extra DO round trip). A downpipe in this index reads "Fresh" on the map and the overview
  // forever, even while its backups have stopped: the per-downpipe boolean below is what lets the bot fire the
  // staleness-uncomputable signal rather than trusting a green tile.
  const freshnessIndex = freshnessUncomputableIndex(schedDiag);
  // freshnessTruncation (G325 x G076): the OTHER half of the same join, and the half that was missing. The
  // fault map REFUSES a downpipe once full, so the index above can only ever mark the downpipes INSIDE the
  // cap; the one past it was absent from the map, carried no field, and its row asserted a working staleness
  // rule while `capTruncations` said only that some row had been dropped. The refusal now names its subject,
  // so the row can carry the third thing rather than the clean one.
  const freshnessTruncation = capTruncationSubjectIndex(schedDiag, "freshness-faults");
  // secretsRestorability (G208): a PURE, DERIVABLE standing posture, computed from the roster already fetched
  // by calling the restore path's OWN leaf (unwiredSecretSinks) on the same bound-secret list a restore would
  // build. Secrets Store bindings are READ-ONLY at runtime, so a secret whose operator never wired a write path
  // CANNOT be restored in-account -- and today that is discovered DURING the disaster, on the restore receipt,
  // when it is far too late to do anything about it. Because it is derived rather than recorded, it needs no
  // write, cannot be dropped by an unavailable DO, and cannot drift from the refusal it describes. COUNTS only:
  // a secret's NAME is a customer label and never rides.
  const boundSecretSinks = downpipes.flatMap((d) => {
    const src = d?.config?.source;
    if (src?.type !== "secrets" || !Array.isArray(src.secrets)) return [];
    // The restore path builds each secret's sink with a bindingVar and NO `put` (restore-sinks.ts), which is
    // exactly what makes it unrestorable; reconstructing the list the same way keeps this honest by construction.
    return src.secrets.map(() => ({ name: "", bindingVar: "SECRETS" }));
  });
  const secretsRestorability = unwiredSecretSinks(boundSecretSinks);

  return {
    kind: "downpipe-support-bundle",
    v: 2,
    generatedAt: nowIso(),
    engine: {
      version: ENGINE_VERSION,
      // accountTag is the engine's OWN Cloudflare account id (env.CF_ACCOUNT_ID) -- the operator's own
      // non-secret account label, already the vendor beacon's key and already surfaced per-source as
      // source.accountId. Surfacing it here lets support answer "is this engine reporting under the account
      // I expect?" (accounttag-mismatch) and disambiguate two engines flapping one licence ledger row
      // (per-engine identity = accountTag + cfVersionId). Presence-only; honestly omitted when unset.
      ...(env.CF_ACCOUNT_ID ? { accountTag: env.CF_ACCOUNT_ID } : {}),
      // cfVersionId (two-engines-flapping-ledger): the immutable Cloudflare deploy id of THIS engine, so
      // `accountTag + cfVersionId` together are the per-engine identity that disambiguates two engines flapping
      // one licence-ledger row (the ledger correlation itself is vendor-side / control-plane). Non-secret.
      ...(cfVersionId ? { cfVersionId } : {}),
      // deployBaseline (engine-version-change-baseline-suppressed / same-version-redeploy-double-blind): the
      // deploy identity observed when the status-snapshot baseline was (re-)established. A changed `at` across
      // two packs reveals a snapshot RESET (a wiped/first-poll control plane) a same-version redeploy would
      // otherwise hide; cfVersionId names the deploy. OMITTED before the first observation (best-effort {}).
      ...(Object.keys(deployBaseline).length > 0 ? { deployBaseline } : {}),
      ...(env.ARTEFACT_SHA384 ? { artefactSha384: env.ARTEFACT_SHA384 } : {}),
      ...(env.RELEASE_SIGNER_PIN ? { releaseSignerPin: env.RELEASE_SIGNER_PIN } : {}),
      // capabilities (G311): the engine's OWN advertised capability vector -- the same advertisement the console
      // renders the Cloudflare-wide sources tier from (GET /sources/discovery). An engine build that does not
      // advertise addedSources, or that offers none of the token-source types, silently HIDES the whole tier,
      // and from the console side that skew is indistinguishable from a console bug ("docs show a
      // Cloudflare-wide sources section but my console has none"). engine.version alone only makes the skew
      // loosely inferable; this states it. Booleans + a count of ADVERTISED capabilities -- no account, no
      // resource, no customer data.
      capabilities: {
        addedSourcesSupported: true,
        tokenSourceTypes: [...ADDED_SOURCE_TYPES],
        tokenSourceOfferedCount: ADDED_SOURCE_TYPES.length,
        workersSupported: true,
        streamSupported: true,
        imagesSupported: true,
        artifactsSupported: true,
      },
    },
    // accessPerimeter (G267): the read that generated this pack traversed a Cloudflare Access application, so
    // the hostname is Access-FRONTED. Cross-read it against auditFeed / metricsFeed: a pull credential that IS
    // configured behind an Access perimeter is turned away at the EDGE before the engine sees it, which is the
    // whole of the "my collector credential never works" ticket. A presence boolean; honestly OMITTED when the
    // caller could not supply it (never fabricated as false). See SupportBundleContext.
    ...(ctx.accessPerimeter !== undefined ? { accessPerimeter: ctx.accessPerimeter } : {}),
    status,
    preflight,
    // wormPosture (Phase 2 item 3): the default/primary destination's WORM / Object-Lock posture from a live
    // capability probe: configured/misconfigured + the valid policy's mode/days + the bucket's real enforcement
    // verdict (bucketEnforces true/false/"unknown"). Closed enums / booleans / integers only, never an
    // endpoint/bucket/credential. OMITTED entirely when the best-effort probe timed out or faulted.
    ...(Object.keys(wormPosture).length > 0 ? { wormPosture } : {}),
    // sealKnobs (Phase 3 seal-integrity): the resolved seal / verify-at-seal / scale tuning knobs in force
    // (ints + bools only). Lets support diagnose verify-at-seal-off / Tier-0-only-forced / an over-set slice
    // budget / a no-resume large-value posture from the bundle alone. Redaction-safe by construction.
    sealKnobs: sealKnobs(env),
    downpipes: downpipes.map((d) => projectDownpipeRow(d, { replication, destIdSet, sealErrors, freshnessIndex, freshnessTruncation, refusalIndex })),
    runs,
    notify,
    // notifyFailures (G023 + G342): the FAILURE-BIASED view of the same 1000-entry delivery ring. `recent` is
    // the most recent undelivered rows PLUS the smart-retained ONSET row per channel kind (the oldest
    // undelivered row still in the ring), and `byChannelKind` is the whole-ring rollup {failCount, lastFailAt,
    // lastDeliveredAt}. The 20-row recency window above is all recent successes by the time a customer says
    // "alerts stopped reaching PagerDuty three weeks ago", so the failing window was unrecoverable remotely.
    // OMITTED when nothing has ever failed to deliver. Same redaction as `notify` (closed codes only).
    ...(notifyResult.failures.length > 0 || Object.keys(notifyResult.byChannelKind).length > 0
      ? { notifyFailures: { recent: notifyResult.failures, byChannelKind: notifyResult.byChannelKind } }
      : {}),
    notifyConfig,
    // notifyHealth (NOTIF): the notify-pipeline drop counters (passes skipped / records dropped / emissions
    // rejected / feedback failures) + the pending-digest lifecycle (per-cadence depth/oldest/dueAt) so
    // "alerts silently stopped" and "a digest never flushed" are diagnosable. OMITTED when all-zero + empty.
    ...(Object.keys(notifyHealth).length > 0 ? { notifyHealth } : {}),
    // canary (NOTIF: canary-transition-only-pages-once): the canary's aggregate liveness + its bounded
    // transition ring, so a standing "paged once" death (which never re-pages) stays observable. OMITTED
    // when there is nothing to report (no status + no transitions). Closed enums / ints / clamped timestamps.
    ...(Object.keys(canary).length > 0 ? { canary } : {}),
    // alertCooldowns (NOTIF: cooldown-suppresses-renudge-1h): which downpipes are within a re-nudge cooldown
    // and since when (staleness/failure + replication streams), so "why didn't I get re-alerted" is
    // answerable. OMITTED when nothing is in cooldown. Downpipe id + closed state enum + epoch ms only.
    ...(Object.keys(alertCooldowns).length > 0 ? { alertCooldowns } : {}),
    recovery,
    // audit (CPR): the audit-chain VERIFY VERDICT -- intact vs the first brokenAt seq, rollover state
    // (so a legitimate retention rollover is never misread as tamper), the near-cap warning, and the
    // verify's own cost (duration/entries near the cap). Booleans / ints / clamped timestamps only.
    ...(Object.keys(audit).length > 0 ? { audit } : {}),
    // auditFeed (CPR): whether a SIEM PULL credential is wired + its last-pull recency (a lapse = the SIEM
    // stopped collecting). Non-PII: booleans / a pull count / clamped timestamps; the grantedBy email is dropped.
    ...(Object.keys(auditFeed).length > 0 ? { auditFeed } : {}),
    // metricsFeed (A7 G262): the metrics-scope ingest-credential grant state (configured/expired/pullCount/
    // grantedAt/expiresAt/lastPullAt). Omitted when the scope is not granted. Booleans + count + clamped times.
    ...(metricsFeed.configured === true ? { metricsFeed } : {}),
    // expiryRegistry (A7 G260): the full credential-expiry registry (up to 32 worst-state-first rows, each a
    // registry id + closed kind/lifecycle/state enums + hasTokenRef + usedAt). Omitted when nothing is tracked.
    ...(expiryRegistryResult.rows.length > 0 ? { expiryRegistry: expiryRegistryResult.rows } : {}),
    // danglingDestinationRefs (A4 G044/G268): the fleet count of downpipes pinned to a since-removed
    // destination (the destination twin of notifyConfig.danglingChannelRefs). Omitted when the roster read
    // faulted (undefined destIdSet) or none dangle. A count only; per-downpipe attribution rides in downpipes[].
    ...(danglingDestinationRefs > 0 ? { danglingDestinationRefs } : {}),
    // selfIdentityDegradedCount (G282): the fleet count of downpipes whose stored source config lacks the native
    // ids (kv namespaceId / r2 bucketName / d1 databaseId / a Secrets Store storeId) a roster rebuild needs, so
    // they cannot be reconstructed after a control-plane loss. Attribution rides in downpipes[]. A count only.
    ...(selfIdentityDegradedFleet > 0 ? { selfIdentityDegradedCount: selfIdentityDegradedFleet } : {}),
    // ownerActionQueue (A6 G259/G265): the dual-control queue aggregate (counts + oldest proposal + closed
    // kinds + expiredUndecided). Omitted when the queue is quiet. Counts + a timestamp + closed kinds only.
    ...(Object.keys(ownerActionQueue).length > 0 ? { ownerActionQueue } : {}),
    // wrapKeyHealth (CPR): whether the configured CONFIG_WRAP_KEY still decrypts the encrypted-at-rest dest
    // credentials (a rotated-wrong / removed key => a control-plane recovery restores an UNUSABLE credential).
    // A closed class + a count; the decrypted value is never surfaced.
    ...(Object.keys(wrapKeyHealth).length > 0 ? { wrapKeyHealth } : {}),
    // beacon (LICENCE corroboration): whether the opt-in vendor beacon is CONFIGURED (env presence -- ALL of
    // BEACON_URL + BEACON_INGEST_KEY + CF_ACCOUNT_ID, the same gate cron/beacon-emit.ts applies) and the last
    // POST outcome (lastOk/lastAt/lastStatus) when it has emitted. A beacon that is OFF (no vendor-side
    // corroboration of this engine's deploy/health) or configured-but-not-reaching-the-vendor is otherwise
    // invisible to a licence/entitlement diagnosis. Env booleans + a bool/timestamp/clamped-int only; the
    // BEACON_INGEST_KEY value is NEVER surfaced (only its presence via `configured`).
    beacon: {
      configured: Boolean(env.BEACON_URL && env.BEACON_INGEST_KEY && env.CF_ACCOUNT_ID),
      ...beaconState,
    },
    // destResolution (DEST write-path): the EFFECTIVE resolved write settings the engine computes at write
    // time but records nowhere -- the account-wide effective request rate + a rate-knob-typo flag, and per
    // destination the resolved addressing style, a dotted-bucket-under-vhost TLS risk, and the effective
    // storage class. Closed enums / a clamped int / bools / operator dest ids only; never the host/bucket name.
    destResolution,
    // siemPush / otlpPush (Wave A1): the audit-log push + metrics push delivery trails (presence, transport,
    // cursor lag, last attempts with coarse http status + reason class). Omitted when the drain is not
    // configured and has no trail; the trail is coarse-by-contract (never a URL, host, token or response body).
    ...(Object.keys(siemPush).length > 0 && (siemPush.configured === true || siemPush.trail !== undefined) ? { siemPush } : {}),
    ...(Object.keys(otlpPush).length > 0 && (otlpPush.configured === true || otlpPush.trail !== undefined) ? { otlpPush } : {}),
    // volumes (self-serve volume-based licensing, see estate.ts): the estate usage rollup, or null on a
    // genuine compute fault (sections.volumes then reads "error"; a healthy zero-downpipe fleet is a real
    // all-zero object, not null). Always present, mirroring the `licence` field's always-present contract.
    volumes,
    // driveBudgetYields (failover-probe-budget-exhaustion): the cumulative cron seal-loop budget-yield record --
    // how many ticks ran out of the shared per-invocation subrequest budget before dispatching every due
    // downpipe (carrying the tail to the next tick, which includes the per-downpipe failover-probe cost), when
    // it last happened, and how many were carried last time. A fleet too large for the per-tick budget silently
    // starves its tail otherwise. Count + timestamp + int only. OMITTED when the loop has never yielded ({}).
    ...(Object.keys(driveBudgetYields).length > 0 ? { driveBudgetYields } : {}),
    // controlPlaneExport (B4): how STALE the no-custody control-plane backup is, the config version the last
    // signed export to the destination covered + when. Complements `recovery` (the amnesia latch): together
    // they answer "the plane was wiped, and the freshest thing we can recover FROM is version N at time T."
    // Redaction-safe (int + timestamp); OMITTED entirely when the pointer is absent (best-effort {}).
    ...(Object.keys(controlPlaneExport).length > 0 ? { controlPlaneExport } : {}),
    // ssoFailures (D2): the bounded per-code SSO sign-in FAILURE aggregate, the pack's answer to "WHY can't my
    // users sign in via SSO". Each key is a CLOSED classifier code (issuer/audience/expired/clock-skew/signature/
    // key/replay/connection/malformed/other), each value a capped count + last-seen time. NEVER the raw reason
    // (which could embed an issuer/connId/error message). OMITTED entirely when empty (no recent failures).
    ...(Object.keys(ssoFailures).length > 0 ? { ssoFailures } : {}),
    // scheduler (RUNS-SCHEDULER + INFRA scheduler-liveness new-logging): the per-cron-tick OUTCOME ring (the
    // #1 "backups silently stopped" false-green detector -- a tick that reported green but dispatched 0 of N
    // due, overdrew its subrequest budget, crashed a pass, or missed ticks), the due-index parity snapshot,
    // and the runlog counter vs max history index. Counts / flags / clamped timestamps only (no-custody).
    // OMITTED when empty (the DO never recorded a tick yet); sections.scheduler carries the fetch status.
    ...(Object.keys(schedulerSignals).length > 0 ? { scheduler: schedulerSignals } : {}),
    // updates (UPDATES-LIFECYCLE new-logging): the safe-apply update state machine -- pending record (versions +
    // riskClass + promotedAt), last outcome + reason + canary verdict, the rollback-needed latch, the
    // anti-rollback high-water mark -- plus engineAccountMarked (the config-level gate the apply/settle/rollback
    // paths refuse on). Version strings are engine ids; the reason is an engine-authored class (bounded); no
    // token / no secret. Answers "my update/rollback failed" (previously presence-only, no reason/outcome).
    ...(Object.keys(updateStatus).length > 0 ? { updates: updateStatus } : {}),
    // reconcile (support-pack modes reconcile-orphans-invisible / runlog-corrupt-parse): the per-destination
    // orphan-reconcile inventory + RUNLOG-health the cron's report-only pass persists -- recoverable-but-
    // invisible orphan runs, never-referenced trees, the circuit-breaker abstain, and whether the
    // destination RUNLOG is present + signature-verified. OMITTED entirely when empty (the pass is opt-in via
    // ORPHAN_RECONCILE, so most bundles carry nothing). Redaction-safe: counts + booleans + dest labels.
    ...(reconcile.length > 0 ? { reconcile } : {}),
    // ssoFailuresByKind (P1): the same classified SSO failures split by connection PROTOCOL (oidc/oauth2/saml) ->
    // code -> {count,lastAt}. Redaction-safe by construction (closed enum keys at BOTH levels; never a connId).
    // OMITTED when empty (no failure carried a known kind).
    ...(Object.keys(ssoFailuresByKind).length > 0 ? { ssoFailuresByKind } : {}),
    // authSignals (P2/P3): the bounded auth/RBAC defensive-branch counters. The full closed vocabulary spans the
    // availability cluster (fail-closed rate-limit + limiter/break-glass DO-outage), SCIM 401/503/last-owner,
    // group -> role loss (dropped names, zero-match groups, subject rekey), verified-principal refusals
    // (emailless / unusable-subject / bind-blocked), CSRF-origin, SAML SP-initiated (relaystate-missing), OIDC
    // tenant-not-accepted, the private-key-jwt config refusal, the Cloudflare Access front-door denials
    // (aud/issuer/key/verify) and the session-revocation (email/idp epoch) enforcement. Closed event name ->
    // {count,lastAt}; never an ip/email/connId/subject/secret/reason. OMITTED when empty (no such event recorded).
    ...(Object.keys(authSignals).length > 0 ? { authSignals } : {}),
    // authPosture (P4): the session signing-key presence/age/adequate-length (session-signing-key-lost +
    // recovery-key-too-short), the count of confidential IdP connections missing their do-plaintext secret
    // (do-plaintext-secret-missing), and the alternative admin-credential-path counts (passkeys + enabled IdP
    // connections) for the token-fallback-lockout cross-check. Booleans/ints only, never a key or secret.
    ...(Object.keys(authPosture).length > 0 ? { authPosture } : {}),
    // lockoutPosture rides BESIDE authPosture, because the two answer the two halves of one question:
    // authPosture counts the admin sign-in PATHS that exist, and this says whether any of them still leads to
    // an OWNER. A count of one passkey credential is not evidence of a reachable Owner if the grant that makes
    // them one cannot be read.
    ...(Object.keys(lockoutPosture).length > 0 ? { lockoutPosture } : {}),
    // ssoFailuresByConn (G140): the SAME classified failures split by CONNECTION, keyed by an OPAQUE ordinal
    // (conn-1, conn-2, ...) minted DO-side. ssoFailures says "12 signature failures" and ssoFailuresByKind says
    // "they are all SAML"; on a tenant with four SAML connections neither says WHICH one is broken, so the
    // operator re-checks all four. The connId -- the operator's own slug -- is never carried anywhere.
    ...(Object.keys(ssoFailuresByConn).length > 0 ? { ssoFailuresByConn } : {}),
    // idpCertHealth (G053): the SAML signing certificates the engine actually holds. parseableCount < certCount
    // is the half-corrupt rollover paste (the engine verified on the good cert and said NOTHING, until the good
    // one expired); expiryObserved:false is the state in which no expiry warning can EVER fire; curves.p521 is
    // the "every sign-in dies in a generic import error" diagnosis; noUsableCertRefusals counts the outage. An
    // AGGREGATE, never keyed by connId. Counts, a closed curve-class map, booleans and one public expiry.
    ...(Object.keys(idpCertHealth).length > 0 ? { idpCertHealth } : {}),
    // keys (P3, SECURITY-SENSITIVE): key-material HEALTH - presence/parse booleans + FINGERPRINTS OF PUBLIC MATERIAL
    // ONLY (break-glass + vendor-support recipient fingerprints, the wrap-key KCV). Never a private half or secret.
    // Always present (a "no keys configured" pre-ceremony state is itself diagnostic). See buildKeysHealth.
    keys,
    // sealFaults (Phase 3 seal-integrity modes shard-list-truncated / shard-truncation-stalekeys /
    // lease-lost-abandon / orphan-root-worm-leak / signer-rotation-strands-runs): the bounded seal-fault
    // OBSERVE ring the per-downpipe seal DO records at each fault's detection point (a truncated-archive
    // refuse with its found/expected counts, an abandoned run's stale rows cleaned, a lost-lease abandon, an
    // orphan-root reclaim + WORM signal, a checkpoint-unwrap strand). OMITTED entirely when empty (the
    // healthy fleet's steady state). Redaction-safe: a closed kind + the customer's own ids + ints / a boolean.
    ...(sealFaults.length > 0 ? { sealFaults } : {}),
    // retention (G071/G190): the latest retention-prune pass -- the pass/destination skip codes, and per downpipe
    // the CLOSED outcome (applied / dry-run / no-op / deferred / error) with its deferral or error class and the
    // COMMITTED counts, plus replicationUnreadable (the coverage gate ran on no proof, so every replicated run
    // was held) and auditWriteFailures (a real deletion the chain never recorded). The pack's answer to "storage
    // keeps growing despite my retention policy", which until now left no evidence the vendor could read.
    ...(Object.keys(retention).length > 0 ? { retention } : {}),
    // configIntegrity (CONFIG-domain OBSERVE signals): snapshotFailures (config-snapshot-best-effort-gap -- a
    // config change that silently never got versioned), history (config-history-session-key-regen -- a config-
    // history chain that fails to verify, with signingKeyRotated distinguishing a rotated in-DO signing key
    // from genuine content tamper), and changeControlRefusals (change-number-required-refusal -- changes bounced
    // for want of a change number, read WITHOUT touching the CR ledger). Counts / timestamps / booleans / ids /
    // a closed action-kind label only. OMITTED entirely when every sub-signal is clean (best-effort {}).
    // configIntegrity.history additionally carries the G098 BODY-RETENTION scan: `listed` is how many config
    // versions the console offers as restorable, `readable` is how many you could ACTUALLY roll back to, and a
    // gap between them is a false assurance the operator discovers mid-incident. verifyFaulted says the chain
    // could not be CHECKED at all (its usual cause is exactly a body that is gone, since the verify hashes it).
    ...(Object.keys(configIntegrity).length > 0 ? { configIntegrity } : {}),
    // discoveryHealth (G008): the SETUP FORM'S OWN HONESTY. GET /sources/discover is fail-open per product, so
    // an empty listing means the account holds nothing, OR the token cannot see it, OR the page cap cut it off,
    // and all three answer an identical 200. The customer then protects only what they were shown. lastOutcome
    // names each product's real verdict ("denied" / "truncated" vs "empty"), degradedObservations says how much
    // to trust the console's "your account has no sources", and engineAccountKnown:false is the state in which
    // no source can EVER be attached. Closed enums + counts. OMITTED when discovery has never run.
    ...(Object.keys(discoveryHealth).length > 0 ? { discoveryHealth } : {}),
    // auditExportAttempts (G022): the customer who cannot get their tamper-evident evidence OUT of the account.
    // Both export paths are pass-throughs and recorded NOTHING on failure, so the pack showed an intact chain
    // with every event present and no hint that none of it could be produced -- and the exported log is
    // structurally incapable of recording its own failure to export. byChannel says whether an operator is
    // staring at a failed download or a SIEM is quietly missing days; a csv-only failure is a whole-log SCAN
    // size fault, not an outage. Counts + closed enums. OMITTED when no export has ever been attempted.
    ...(Object.keys(auditExportAttempts).length > 0 ? { auditExportAttempts } : {}),
    // adminRouteErrors (G183): WHERE the update / licence route threw, and HOW FAR it got. byRouteStage is the
    // locus ("update-apply|channel-fetch" is the signed channel; "|deploy-driver" is Cloudflare's API; the
    // licence path's "|persist" is the DO). mutatingFaults is the honesty check on the routes' own fixed
    // "nothing was changed" prose: a fault at deploy-driver or persist means something very possibly WAS
    // changed, and the customer was told otherwise. Closed enums and counts; no exception text ever persists.
    ...(Object.keys(adminRouteErrors).length > 0 ? { adminRouteErrors } : {}),
    // licenceActivationRefusals (failed-activation-no-trace): the cumulative count of console licence
    // activations refused by the verify-before-store gate (a token that did not verify), the last refusal time,
    // and the last CLOSED reason code, so "I pasted my licence but it still says community" is diagnosable
    // (typo vs expired vs future-tier vs tamper). A count + timestamp + closed code only, never the token.
    // OMITTED entirely when no activation has ever been refused (best-effort {}).
    ...(Object.keys(licenceActivationRefusals).length > 0 ? { licenceActivationRefusals } : {}),
    // licenceExpiryTracker (expiry-tracker-stale): the engine-OBSERVED `licence` expiry-registry row's tracked
    // notAfter + coarse state, surfaced ALONGSIDE licence.notAfter so a tracked row that has DRIFTED from the
    // live licence (a missed renewal, a stale row after a clear) is visible. The comparison is bot-side. A date
    // + closed state/source enums only, never the registry row's operator label. OMITTED when nothing tracked.
    ...(Object.keys(licenceExpiryTracker).length > 0 ? { licenceExpiryTracker } : {}),
    // sourcesDetached (sources-detached-binding-names-absent): WHICH source bindings are currently detached
    // (the count already rides in status.sourcesDetachedCount, but not the names), computed the SAME way the
    // one-click re-attach is (live env bindings vs the roster). Binding names are operator labels, the same
    // redaction class as source.binding in the config snapshot, and this is the confidential pack (not the
    // count-only /admin/status). Capped/sorted names + a count. OMITTED when nothing is detached (best-effort {}).
    ...(Object.keys(sourcesDetached).length > 0 ? { sourcesDetached } : {}),
    // rosterIntegrity (roster-hygiene): structural ghost rows the delete route can never remove (the
    // "permanent grey Unknown line on my map that I cannot delete" support case) plus never-ran
    // downpipes (what a standing Unknown edge is when the roster is sound). Ids/keys only, bounded,
    // the same redaction class as the config snapshot. OMITTED when the roster is clean and every
    // downpipe has run (best-effort {}).
    ...(Object.keys(rosterIntegrity).length > 0 ? { rosterIntegrity } : {}),
    // ---- the ENGINE SELF-DIAGNOSTIC block (round-2 gap audit) ----------------------------------------------
    // droppedWrites (G100/G331/G104): READ THIS BEFORE CONCLUDING "no events happened". The diagnostic writers
    // are best-effort by design (observing a fault must never break the path it observed), so a DO outage
    // silently DROPS the very evidence of itself. Each writer now tallies its own losses and folds them in on
    // the next write that lands, so any non-zero count here means this pack is INCOMPLETE by that many records
    // -- and names of which kind. The Worker edge and the scheduler DO share one record with disjoint,
    // additive vocabularies; the projection carries the UNION. OMITTED when nothing was ever lost.
    ...(Object.keys(droppedWrites).length > 0 ? { droppedWrites } : {}),
    // schedDiag (G013/G014/G039/G076/G120/G221): the scheduler DO's own fault ledger. recentErrors dereferences
    // the OPAQUE errorId a customer quotes from a console toast (stage + coarse reason class + a recurrence
    // count). ceremonyFaults carries the DO-side STRUCTURAL passkey/step-up/recovery classes the Worker edge
    // cannot see (a LIVE challenge evicted under a begin flood, an absent rp.id reported to every user as their
    // own bad request, a corrupt STORED COSE key, WHICH recovery limiter denied, a fail-CLOSED limiter refusing
    // a legitimate operator holding good codes). contractFaults counts every Worker<->DO coercion that used to
    // happen in silence (a `?? []` reconcile that CLEARS a real detached-source marker so an ongoing fault reads
    // as healed; a run completion discarded as unowned; a console screen 404ing after a mixed deploy) -- a climb
    // after an engine-version-change is the version-skew signal. defaultDestination is the ENV-DEFAULT
    // destination's reachability heartbeat, which for the common single-destination tenant was the one down
    // indicator that existed NOWHERE. freshnessFaults names the downpipes whose staleness rule can never arm.
    ...(Object.keys(schedDiag).length > 0 ? { schedDiag } : {}),
    // sealErrors (G163): per-downpipe PRE-RUN seal-dispatch faults. Attribution rides on downpipes[].lastSealError.
    ...(Object.keys(sealErrors).length > 0 ? { sealErrors } : {}),
    // metricsHealth (G049): the Prometheus /metrics scrape surface's own health -- the outcome histogram, the
    // shape-coercion fallbacks (a valid scrape rendering ZERO series while Prometheus's own `up` stays 1), and
    // the fail-CLOSED auth-check-unavailable refusals a DO hiccup reports to the operator as "unauthorised".
    // OMITTED until something has actually scraped, which is itself the answer to "is anything scraping us?".
    ...(Object.keys(metricsHealth).length > 0 ? { metricsHealth } : {}),
    // webauthnFaults (G158): the 14 structural WebAuthn defect classes split by ceremony PHASE. All 14 collapse
    // into one coarse bad_request on the wire (by design: the anti-enumeration posture is preserved), so "half
    // my fleet cannot enrol a key" and "this user's STORED key record is corrupt and they can never sign in
    // again" produced identical evidence: none. The phase is the diagnosis. OMITTED when the fleet is clean.
    ...(Object.keys(webauthnFaults).length > 0 ? { webauthnFaults } : {}),
    // sourceFaults (G015/G042/G068/G110/G144/G096/G170/G213/G327): per downpipe, WHY the crawl could not fully
    // capture. The seal already told you a surface was "_unavailable" in every run; this says whether that was
    // a 403 scope gap, a Cloudflare 5xx, a size ceiling, a page cap or a stuck render -- four different
    // tickets that produced identical packs. shapeAnomalies is the one to read on a HEALTHY-looking pipe: a
    // tolerant parser silently dropped items on a Cloudflare API shape change and the run still reported ok,
    // so coverage has been quietly voided for months. fatal names the run-fatal transport class AND the crawl
    // STAGE (a token that cannot even LIST is a different fix from one whose every item read fails).
    // snapshotConsistency is a DATA-INTEGRITY verdict that rides on runs which report OK: "re-anchored" means
    // the archive is a MIXED SNAPSHOT. OMITTED when the fleet's crawls are clean.
    ...(Object.keys(sourceFaults).length > 0 ? { sourceFaults } : {}),
    // destFaults (G135/G186): per downpipe, the closed IDENTITY of every failing destination op -- an expired
    // STS session vs a bucket-policy denial vs a signature mismatch vs an Object-Lock checksum complaint, all
    // of which used to collapse to "status 403". `arm: default-permanent` is the one to escalate on: the
    // classifier could NOT read the store's message and DEFAULTED to permanent, so a retryable fault may have
    // been given up on. `io` carries the degradation of a destination that is making a GREEN run slow and
    // expensive (the store's throttle pushback, the silently re-issued multipart steps, the black-holed
    // timeouts, and headNon200CollapsedToAbsent -- the dedup-defeating fault where a 403/5xx HEAD is read as
    // "absent", so the same segment re-uploads every night). OMITTED when the destinations behaved.
    ...(Object.keys(destFaults).length > 0 ? { destFaults } : {}),
    // restoreFaults (G070/G080): the bounded restore / drill / blind-test / attest fault ring. Read `phase`
    // FIRST: `verify` = NOTHING was written; `write` = other records landed and this one did not; `readback` =
    // the bytes ARE on the target and could not be PROVEN (offline-recoverable, NEVER data loss). Class
    // `too-large` is likewise offline-recoverable. `apply-crashed-lease-reclaimed` means an earlier apply died
    // mid-write holding a single-use approval. OMITTED when nothing has failed to restore.
    ...(restoreFaults.length > 0 ? { restoreFaults } : {}),
    // adminCounters (G080/G081/G082/G185/G186): READ THIS WITH droppedWrites. Any non-zero value means a
    // surface the pack ALREADY carries is quietly incomplete or was quietly degraded, and names which -- a
    // licence that silently flipped from the console-activated token to the deploy token, a point-in-time run
    // excluded for a corrupt timestamp (so "no run exists at T" may be wrong), a signed compliance report
    // built over an unreadable read, or an operator's WORM / assume-role destination policy silently
    // discarded. OMITTED when every counter is zero.
    ...(Object.keys(adminCounters).length > 0 ? { adminCounters } : {}),
    // ---- the ROUND-4 fault ledgers -------------------------------------------------------------------------
    // unwrapFaults (G028): WHEN the runtime CONFIG_WRAP_KEY unwrap started failing, and which of the four
    // causes. Read it BESIDE wrapKeyHealth: the probe says WHETHER the key opens right now; `firstAt` (never
    // overwritten by the applier) says SINCE WHEN it stopped -- the fact that separates "the operator rotated
    // the key last Tuesday" from "one stored record is damaged". A probe-time verdict structurally cannot
    // recover it. OMITTED when every read-for-use has opened cleanly.
    ...(Object.keys(unwrapFaults).length > 0 ? { unwrapFaults } : {}),
    // bindingAlarms (G099): the post-write binding-safety alarms -- a binding a plan ADDED that the read-back
    // could not find, a removal that survived, a lost-update race. This is the highest-impact failure mode (a deploy that
    // silently drops a source binding) with the operator's own binding labels attached, so support can say
    // WHICH binding to re-attach. The same redaction class as sourcesDetached. OMITTED when no alarm fired.
    ...(bindingAlarms.length > 0 ? { bindingAlarms } : {}),
    // updateFaults (G050/G054/G101/G159/G162): the self-update pipeline's failing STEP and closed cause, which
    // the 4.26 updates block could never carry. Four rows matter most: `rollbackFailed` (the engine is LIVE on
    // a bad version and its auto-rollback ALSO failed), the `bookkeeping` rows (the deploy went live and the
    // record of it was lost -- recordPhase says which half), `sources-dropped` (WHICH source bindings an
    // update dropped: previously a bare count on an HTTP response nobody kept), and the channel-verify split
    // (a truncated CDN object is no longer reported as "the signature did not verify under the pinned signer",
    // which sent operators on a key-pinning chase). OMITTED when no update has failed.
    ...(updateFaults.length > 0 ? { updateFaults } : {}),
    // adminRefusals (G245): the Worker-EDGE refusal trail (a "<surface>:<reason>" key over two closed sets).
    // The DR-hour headline is `restore-apply:gate-unavailable`: a restore refused "not approved" BECAUSE the
    // approval gate could not be READ is an ENGINE fault, and it was previously indistinguishable from a
    // genuinely missing approval -- "is my approval missing, or is your engine broken?" now has an answer.
    // Disjoint from schedDiag.schedAdminRefusals (what the DO refused); the pack carries both. OMITTED when
    // nothing was refused.
    ...(Object.keys(adminRefusals).length > 0 ? { adminRefusals } : {}),
    // integrityFaults (G011/G012/G056/G057/G087/G088/G089/G111): per downpipe, the seal / verify / restore
    // core's fault LOCUS. `failStages` splits the single "integrity check failed" reason 16 ways;
    // `classifiedBy` carries a keyword-fallback COUNT, which is an explicit caveat that the class you are
    // reading is lower-confidence; `fetchFaults` says WHY a RUNLOG read failed (a cold-storage transition is
    // no longer misfiled as a credential fault); `streamFaults` carries the CHUNK INDEX (chunk 0 = the object
    // was mangled from its first byte; chunk 4,000 of 4,001 = a truncated tail); and defaultedEmptyRecords is
    // the silent ZERO-BYTE SEAL -- a record with neither value nor stream that was hashed, sealed, signed and
    // reported GREEN, and whose emptiness the customer discovers months later, at restore. OMITTED when clean.
    ...(Object.keys(integrityFaults).length > 0 ? { integrityFaults } : {}),
    // dispatchFaults (G072): the Worker's four last-resort catches, which previously produced a 500 and
    // nothing else. The `fetch` surface is SELF-REFERENTIAL -- it covers /support/diagnostics itself, so a
    // support endpoint that 500s is recorded and surfaces in the NEXT successful pull. The `scim` surface is a
    // security event: an offboarding that silently did not happen. OMITTED when nothing threw.
    ...(dispatchFaults.length > 0 ? { dispatchFaults } : {}),
    // cronHealth (G084/G132/G205/G220/G234/G278): the cron plane's own health, which the pack previously
    // reduced to ONE anonymous scheduler.ticks.passErrors integer. `passes` attributes every failure to a
    // closed pass NAME and a closed error CLASS (consecutiveFailures > 0 is the chronic signal behind "no
    // alerts / no restore tests / no exports for days"); `tick` records the ring's HOLES (an invocation whose
    // DO preamble failed did nothing and recorded nothing) with gapDetected derived from the DO's OWN clock,
    // so a wedged edge clock can neither fabricate nor conceal a missed tick; `siem.cursor-reset` IS the
    // duplicate-delivery ticket and `siem.batch-cap-truncated` is audit-log LOSS. OMITTED when the cron is well.
    ...(Object.keys(cronHealth).length > 0 ? { cronHealth } : {}),
    // destProbeFaults (G133/G151): per destination, the CLOSED reason the failover write-probe refused it. "All
    // destinations unreachable" now names a cause per destination: an expired STS credential (rotate it), a
    // deleted bucket (recreate it) and a DNS fault (wait) are three different remedies that used to produce
    // identical evidence. OMITTED when every destination answered.
    ...(Object.keys(destProbeFaults).length > 0 ? { destProbeFaults } : {}),
    // destBuildHealth (G136/G137): the destination's CONSTRUCTION health. `failingSinceAt` is the start of the
    // current failing streak and is the one fact a coarse run error can never carry: "every backup has been
    // failing to even BUILD its destination since Tuesday, because DEST_ENDPOINT is gone". lastStsFailureClass
    // splits an AssumeRole refusal into a trust-policy denial (fix the policy) vs a rotated principal (rotate
    // the credential) vs a deleted role vs throttling. OMITTED until a destination has been built at all.
    ...(Object.keys(destBuildHealth).length > 0 ? { destBuildHealth } : {}),
    // costSizing (G296): the estate-sizing probe's outcome per source type. `measuredZero` is the load-bearing
    // member: a Cloudflare Analytics schema drift returns a 0 that is then presented to the customer as a
    // MEASURED size ("this source is empty"), which is a different fact from an honestly unavailable one --
    // and the two were the same evidence. OMITTED when nothing has been sized.
    ...(Object.keys(costSizing).length > 0 ? { costSizing } : {}),
    // recoveryRto (G318): the RTO estimator's own SELF-ASSESSMENT -- the estimate, and the two facts that make
    // it readable. rejectedSamples answers "basedOnDrills says 2 but we ran 15 restore tests" (the other 13
    // were filtered out of the throughput maths and NOTHING said so, while the pack showed recoverySamples.count
    // and basedOnDrills side by side and the discrepancy read as a bug). degradationCause splits the confidence
    // enum's ERASED cause into three different remedies: a fleet that ran 15 drills and has no usable sample
    // used to read IDENTICALLY to one that never drilled. The downpipe `name` and the free-text reason/caveat
    // are deliberately NOT projected. OMITTED when no downpipe has an estimate.
    ...(Object.keys(recoveryRto).length > 0 ? { recoveryRto } : {}),
    // secretsRestorability (G208): how many bound secrets have NO runtime write path and therefore CANNOT be
    // restored in-account. Secrets Store bindings are read-only at runtime, so today this is discovered DURING
    // the disaster, on the restore receipt. DERIVED at build time from the roster (no DO write, so it cannot be
    // dropped by an unavailable DO and cannot drift from the refusal it describes). Counts only, never a name.
    ...(secretsRestorability.bound > 0 ? { secretsRestorability } : {}),
    configEvents,
    // configEventsFetched (CPR): false means the audit excerpt could NOT be read (unavailable), so an EMPTY
    // configEvents array is not proof that nothing changed. true means the excerpt was read (empty = benign).
    configEventsFetched: configEventsResult.fetched,
    // licence is allowlist-projected (projectLicence, above) so setBy -- the licence-activating owner's
    // verified Access e-mail -- never rides raw, the same no-custody discipline as restoreProven.attributed.
    licence: projectLicence(licence),
    // sections (INFRA platform-wide-outage / bundle-degrades-silently-on-do-blip / no-runtime-logs-in-pack):
    // the per-section fetch-status health vector so a reader can tell an honestly-empty section from one that
    // could not be read at build time. A snapshot taken mid-outage is now self-describing (which subsystems
    // answered), and the closed-enum vector is the redaction-safe stand-in for raw runtime logs the pack cannot
    // carry. It is COMPLETE (every SUPPORT_SECTION_NAMES member is always present, missing ones stamped "error")
    // and EXPLICIT (sectionsSummary is the ok/empty/error/expected header a reader consults first -- the pack's
    // "which subsystems answered" answer in place of raw logs). Redaction-safe by construction (fixed section
    // names -> a 3-value enum + four counts).
    sections,
    sectionsSummary,
    // clientDiagnostics (Wave C, I1/I2/I4): the console-asserted, value-free error-class ring, present ONLY
    // when a console generate-POST supplied it (already re-validated + clamped by projectClientDiagnostics).
    // It rides INSIDE the sign+seal here, but is stamped `source: 'client-asserted'` (I4) so the signature
    // attests "the engine received this client blob at receivedAt", never "these events occurred"; the bot
    // weights it BELOW every engine-observed section. STRUCTURALLY omitted on the vendor-pull / scheduled
    // paths (no POST body -> the arg is absent). Its ABSENCE means "not collected", never "console healthy" (D9).
    ...(clientDiagnostics ? { clientDiagnostics } : {}),
    // infra (INFRA slice-knobs-misconfigured / cpu-ms-misconfigured-low; SCHED free-plan-subrequest-cap): the
    // RESOLVED per-slice subrequest + wall budgets (the effective per-invocation ceilings a run actually uses),
    // each with the platform ceiling and how it was derived (default/env/clamped/invalid). A misconfigured knob
    // (typo'd low, or over-set and clamped) is otherwise invisible and explains "large backups never finish a
    // slice". rateLimitDoConfigured is whether the OPTIONAL account-global CF API rate-limit DO binding is
    // present (absent = per-isolate limiting only, a source-throttle-under-fan-out risk). cpuMs is the operator
    // mirror of the deployed [limits] cpu_ms (the engine cannot read its own CPU limit), surfaced only to
    // cross-check against the resolved slice wall budget. All ints / booleans / closed enums (no custody).
    infra: {
      scaleKnobs,
      rateLimitDoConfigured: env.RATELIMIT_DO !== undefined,
      // rateLimitDoHealth (G104): presence was never the question. A limiter that has been FAILING OPEN (its
      // take() throws, so every caller is granted a free pass and NOTHING is throttled) reads byte-identically
      // to a healthy one -- which is exactly the "Cloudflare is 429-ing our crawls" ticket, where the engine's
      // own throttle had quietly stopped throttling. knobInvalid flags a CF_API_RATE_PER_SEC that is SET but
      // unparseable, silently falling back to the conservative default. OMITTED when the binding is absent
      // (rateLimitDoConfigured above already says so). Counts + a clamped timestamp + a boolean.
      ...(Object.keys(rateLimitDoHealth).length > 0 ? { rateLimitDoHealth } : {}),
      ...(cpuMs !== undefined ? { cpuMs } : {}),
      // cpuMsInvalid (G317): the CPU_MS mirror is SET but not a positive number (a typo), so the
      // sliceWallWithinCpuMs cross-check below is silently absent rather than merely un-mirrored.
      ...(cpuMsInvalid ? { cpuMsInvalid: true } : {}),
      // planTier (SCHED free-plan-subrequest-cap): the OBSERVE-side plan-tier indicator, since a Worker cannot
      // read its own account plan. freePlanSubrequestCeiling is Cloudflare's free-plan per-invocation subrequest
      // cap; budgetExceedsFreeCeiling is whether the RESOLVED slice budget is above it (a free account would be
      // KILLED at the cap before a slice could yield-and-checkpoint); maxObservedSubrequestSpend is the largest
      // spend any recorded tick survived; paidPlanProven is true when that survived spend exceeds the free
      // ceiling (only a PAID plan can spend past 50 and live) -- a positive, runtime-derived proof of tier. The
      // risk state a diagnoser reads is budgetExceedsFreeCeiling && !paidPlanProven ("possibly free-plan, and the
      // configured budget would die at the platform cap"). All ints / booleans (no-custody).
      planTier: {
        freePlanSubrequestCeiling: FREE_PLAN_SUBREQUEST_CEILING,
        budgetExceedsFreeCeiling: scaleKnobs.sliceSubrequests.resolved > FREE_PLAN_SUBREQUEST_CEILING,
        maxObservedSubrequestSpend,
        paidPlanProven: maxObservedSubrequestSpend > FREE_PLAN_SUBREQUEST_CEILING,
      },
      // cpu-ms cross-check (INFRA cpu-ms-misconfigured-low): lowSliceWallMs is the "unusually low" threshold and
      // sliceWallUnusuallyLow flags a resolved slice WALL budget below it (a typo'd-low SCALE_SLICE_WALL_MS makes
      // large runs crawl -- a handful of records per slice). When the operator mirrored the deployed [limits]
      // cpu_ms (cpuMs), sliceWallWithinCpuMs flags whether the resolved slice wall is comfortably INSIDE the CPU
      // limit (false = the invocation can be CPU-killed before it yields, and a CPU kill is uncatchable, so the
      // run wedges with no checkpoint). Ints / booleans (no-custody).
      lowSliceWallMs: LOW_SLICE_WALL_MS,
      sliceWallUnusuallyLow: scaleKnobs.sliceWallMs.resolved < LOW_SLICE_WALL_MS,
      ...(cpuMs !== undefined ? { sliceWallWithinCpuMs: scaleKnobs.sliceWallMs.resolved < cpuMs } : {}),
    },
  };
}

// signedSupportBundle canonicalises and signs the bundle with the engine's run signer,
// so support can verify it came from this engine and was not altered in transit.
export async function signedSupportBundle(env: Env, scheduler: DurableObjectStub, ctx: SupportBundleContext = {}): Promise<{ bundle: Record<string, unknown>; signature: string; signerFingerprint: string }> {
  const bundle = await buildSupportBundle(env, scheduler, ctx);
  if (!env.SIGNER_PRIVATE) {
    // No signer yet (pre-ceremony onboarding): the bundle is still useful, unsigned.
    return { bundle, signature: "", signerFingerprint: "" };
  }
  const signer = await loadSigner(env.SIGNER_PRIVATE);
  const bytes = canonicalJSON(bundle);
  const sig = await hybridSign(signer.edPrivate, signer.mldsaSecret, bytes);
  signer.mldsaSecret.fill(0);
  return {
    bundle,
    signature: b64urlEncode(sig),
    signerFingerprint: await signerFingerprint({ ed: signer.edPublic, mldsa: signer.mldsaPublic }),
  };
}

// sealedSupportBundle additionally seals the signed bundle to VENDOR_SUPPORT_PUBLIC: a
// fresh 32-byte key is wrapped to the vendor key with the archive's own hybrid capsule
// construction, and the bundle bytes ride AES-256-GCM under an HKDF of that key. Only
// vendor support (holding the matching identity) can open it; the envelope is
// versioned and self-describing for the vendor-side opener.
export async function sealedSupportBundle(env: Env, scheduler: DurableObjectStub, ctx: SupportBundleContext = {}): Promise<Record<string, unknown>> {
  const signed = await signedSupportBundle(env, scheduler, ctx);
  const vendorB64 = env.VENDOR_SUPPORT_PUBLIC;
  // The envelope `v` is the CONTENT-schema version and must track the body (which buildSupportBundle now emits
  // at v:2), a stale v:1 envelope around a v:2 body is a contract inconsistency (the consumer keys version off
  // the body, but the envelope should agree). This is distinct from the sealing-FORMAT version, which lives in
  // the aad / INFO domain-separators below ("...v1") and is unchanged.
  const bundleV = ((signed.bundle as { v?: number }).v ?? 2) as 1 | 2;
  if (!vendorB64) {
    // Signed-plain: the band manifest rides WITHOUT bodySha256, because the inner hybrid signature
    // already covers the whole body and there is no separate sealed body to bind to. Pre-ceremony
    // (no signer) emits no manifest at all: an unsigned manifest would be an unverifiable claim.
    // The signer is reloaded because signedSupportBundle zeroed its own copy's ML-DSA secret.
    const band = env.SIGNER_PRIVATE ? await buildBandManifest(signed, await loadSigner(env.SIGNER_PRIVATE), null) : null;
    return { kind: "downpipe-support-bundle-signed", v: bundleV, ...signed, ...(band ?? {}) };
  }
  const vendorPub = loadRecipientPublic(vendorB64);
  const k = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = canonicalJSON({ kind: "downpipe-support-bundle-signed", v: bundleV, ...signed });
  const aad = utf8("downpipe/engine support-bundle v1");
  const wraps = await sealToRecipients(k, [vendorPub], aad, () => crypto.getRandomValues(new Uint8Array(16)));
  const dek = await hkdfSha384(k, new Uint8Array(0), utf8(INFO_SUPPORT_BUNDLE_KEY), 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await aesGcmSeal(dek, iv, plaintext, aad);
  k.fill(0);
  // Sealed: bodySha256 hashes the SAME raw ciphertext bytes that are b64url-encoded into `ciphertext`
  // below, binding the cleartext manifest to this exact sealed body. The signer is reloaded because
  // signedSupportBundle zeroed its own copy's ML-DSA secret after signing the body.
  const band = env.SIGNER_PRIVATE ? await buildBandManifest(signed, await loadSigner(env.SIGNER_PRIVATE), ct) : null;
  return {
    kind: "downpipe-support-bundle-sealed",
    v: bundleV,
    generatedAt: nowIso(),
    recipientFingerprint: await recipientFingerprint(vendorPub.x25519, vendorPub.mlkemEk),
    capsule: wraps.map((w) => ({ fingerprint: w.fingerprint, kemCiphertext: b64urlEncode(w.kemCiphertext), sealed: b64urlEncode(w.sealed) })),
    iv: b64urlEncode(iv),
    ciphertext: b64urlEncode(ct),
    // The opener: decapsulate the capsule with the vendor identity (aad above), HKDF the
    // 32-byte key with INFO_SUPPORT_BUNDLE_KEY, AES-256-GCM-open ciphertext under iv+aad.
    openWith: "downpipe vendor support identity (X25519+ML-KEM-1024)",
    ...(band ?? {}),
  };
}
