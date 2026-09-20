// DOMAIN corpus scenarios: CPR (control-plane recovery / audit / keys), NOTIFY (alerting
// reliability), AUTH (IdP / SSO / auth posture) and LICENCE (entitlement) faults. Engine-exact
// vocabulary throughout: every DO payload copies the shapes test/validate-support.ts validates the
// REAL scheduler DO to produce; every enum value is a member of the engine's closed sets
// (src/admin/support.ts / licence.ts / auth-signals.ts / sso-failure-class.ts / notify types).
// Labels state what the bot's diagnose.ts precedence DOES by design: all of these signals are
// warning-only (they gate a clean HEALTHY + force escalation but never set the primary BACKUP
// class), so a scenario whose only evidence is one of them is INDETERMINATE + escalate ("warning
// rides under INDETERMINATE"), except where a real preflight/run consequence sets a primary
// (cpr.wrap-key-rotated -> POSTURE-ISSUE; notify.canary-dead-cooldown-suppressed -> DEST-THROTTLED-OR-DOWN).
//
// ## FINDINGS (all four FIXED in the 2026-07-02 fix round; labels below encode the POST-FIX behavior):
//
// FINDING-1 (cpr.export-stale-quiet-fleet) — FIXED 2026-07-02: `control-plane-export-stale` now treats
//   an old export as FRESH when the export pass skipped with the benign "unchanged" code OR the pass's
//   current configVersion equals the export's covered configVersion (the config has not moved since the
//   export). A quiet stable fleet reads clean HEALTHY; a genuinely-stale export (the config MOVED past
//   it) still fires — see cpr.export-pass-failing-and-stale.
//
// FINDING-2 (notify.canary-dead-cooldown-suppressed) — FIXED 2026-07-02: `alert-cooldown-stuck` no
//   longer fires on an ACTIVE cooldown (the suppression window working as designed). It fires only on a
//   GENUINELY stuck row: the window elapsed (at + cooldownMs + a 30-min reconcile grace < generatedAt)
//   while the row persists — the engine refreshes `at` on re-nudge and deletes the row on recovery, so
//   a long-elapsed surviving row means the reconciliation stopped. Genuine-stuck proof:
//   fixround.alert-cooldown-genuinely-stuck.
//
// FINDING-3 (signals.ts notify loop) — FIXED 2026-07-02: `notify-delivery-failed` now fires only when
//   the NEWEST dated state for a channelKind is a failure; a failure superseded by a newer
//   delivered:true on the same kind is a self-healed blip and stays quiet (benign proof:
//   fixround.notify-self-healed-blip). notify.sink-rebind-blocked still fires (its failure is newest).
//
// FINDING-4 (cpr.wrap-key-rotated) — FIXED 2026-07-02: probeDestination now stamps an additive closed
//   `overrideUnreadable: true` on the destination item when the console-set record could not be
//   read/decrypted, and the bot pairs it with wrap-key-unhealthy to route the POSTURE-ISSUE cause to
//   "the console-set destination record could not be read/decrypted (check CONFIG_WRAP_KEY)" instead of
//   the misleading "no destination is configured".

import { DEST_HOST, type Scenario, type World } from "./harness.ts";
import { loadSigner } from "../../src/keys-env.ts";
import { hybridSign } from "../../src/crypto/sign.ts";
import { canonicalJSON } from "../../src/format/canonjson.ts";
import { b64urlEncode, concat } from "../../src/crypto/bytes.ts";

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const iso = (t: number): string => new Date(t).toISOString();

type Dict = Record<string, unknown>;

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function bundleText(b: Dict): string {
  return JSON.stringify(b);
}
function expectInBundle(b: Dict, needle: string, what: string): string[] {
  return bundleText(b).includes(needle) ? [] : [`bundle does not carry ${what} (expected substring ${JSON.stringify(needle)})`];
}

function dp1(w: World): Dict {
  return (w.routes["/downpipes"] as Dict[])[0]!;
}
function runs(w: World): Dict[] {
  return ((w.routes["/history"] as Dict).byDownpipe as Record<string, Dict[]>)["dp1"]!;
}
/** Replace the latest run with a FAILED row carrying the engine's closed coarse error string. */
function failLatestRun(w: World, error: string): void {
  const now = Date.now();
  runs(w)[0] = {
    runId: "01RUNBAD",
    index: 8,
    startedAt: iso(now - 20 * MIN),
    status: "failed",
    error,
    causeDigest: "b2c3d4e5f6a1",
  };
  dp1(w).lastRunId = "01RUNBAD";
}

/** The healthy control-plane recovery-status body (mirrors harness healthyRoutes), for scenarios
 * that override ONE block of it while keeping the rest untouched. */
function healthyRecoveryStatus(now: number): Dict {
  return {
    recoveryRequired: false,
    configEmpty: false,
    resumeApplied: false,
    deploy: {
      engineVersion: "0.1.0",
      cfVersionId: "cfv-current-001",
      cfVersionIdAbsent: false,
      baselineEstablished: true,
      changesObserved: 0,
      firstSeenAt: iso(now - 30 * DAY),
      lastSeenAt: iso(now - 5 * MIN),
    },
    exportHealth: { at: iso(now - 20 * MIN), wroteAny: true, configVersion: 7, perDest: [{ id: "d-primary", ok: true }] },
  };
}

/** Serve an audit export whose RECENT WINDOW is the healthy two role-change events PLUS `extra`
 * (ascending seq from 13). The per-action keystone filter answers from `keystones` (empty
 * otherwise), exactly like the real DO's server-side action pushdown. */
function withAuditEvents(w: World, extra: Dict[], keystones: Record<string, Dict> = {}): void {
  const now = Date.now();
  const base: Dict[] = [
    { seq: 11, ts: iso(now - 2 * DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h10", hash: "sha384:h11" },
    { seq: 12, ts: iso(now - DAY), action: "role-change", outcome: "ok", prevHash: "sha384:h11", hash: "sha384:h12" },
    ...extra,
  ];
  const headSeq = base.reduce((m, e) => Math.max(m, e.seq as number), 0);
  const headHash = `sha384:h${headSeq}`;
  w.routes["/audit/export"] = (url: URL): Dict => {
    const action = url.searchParams.get("action");
    if (action !== null) {
      const k = keystones[action];
      return { events: k ? [k] : [], headSeq, headHash, exportedAt: iso(Date.now()) };
    }
    return { events: base, headSeq, headHash, exportedAt: iso(Date.now()) };
  };
}

// ---------------------------------------------------------------------------
// Licence-token fixtures: REAL vendor-style tokens (canonical-JSON claims hybrid-signed exactly as
// the vendor issuer signs them — see test/validate-licence.ts mintToken), verified by the REAL
// readLicence against a pin we install as env.LICENCE_SIGNER_PUBLIC. Never hand-shaped statuses.
const LIC = await (async () => {
  const vendor = await loadSigner(b64urlEncode(concat(rand(32), rand(32))));
  const pin = b64urlEncode(concat(vendor.edPublic, vendor.mldsaPublic));
  const mint = async (claims: unknown): Promise<string> => {
    const body = canonicalJSON(claims);
    const sig = await hybridSign(vendor.edPrivate, vendor.mldsaSecret, body);
    return `${b64urlEncode(body)}.${b64urlEncode(sig)}`;
  };
  const now = Date.now();
  const expiredNotAfter = iso(now - 21 * DAY);
  const soonNotAfter = iso(now + 7 * DAY);
  const longNotAfter = iso(now + 300 * DAY);
  // account matches the harness env CF_ACCOUNT_ID so accountClaimMatchesEngine reads true.
  const claims = (notAfter: string): Dict => ({ account: "acct-corpus-lab", tier: "enterprise", notAfter, features: ["dashboard", "priority-support"] });
  return {
    pin,
    expiredNotAfter,
    soonNotAfter,
    longNotAfter,
    expiredToken: await mint(claims(expiredNotAfter)),
    soonToken: await mint(claims(soonNotAfter)),
    longToken: await mint(claims(longNotAfter)),
  };
})();

export const DOMAIN_SCENARIOS: Scenario[] = [
  // ================================================================ CPR domain
  {
    id: "cpr.staged-pending-not-applied",
    title: "after last week's DO wipe support staged the signed export; the owner re-attached manually but never applied (or discarded) the staged snapshot",
    domain: "cpr",
    // Designed routing: recovery-staged-pending is a warning-only signal (it enriches
    // RECOVERY-REQUIRED but never sets a primary), so with the latch cleared it rides under
    // INDETERMINATE + escalate.
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["recovery-staged-pending"],
    expectAbsentSignals: ["recovery-required"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/control-plane/recovery-status"] = {
        ...healthyRecoveryStatus(now),
        // The staged generation found at the destination, not yet applied; resumeSkipped records
        // the no-authority resume declining to overwrite a non-empty plane (validate-support shape).
        staged: { version: "v42", stagedAt: iso(now - 2 * DAY), downpipes: 1, resumeApplied: false, resumeSkipped: 1 },
      };
    },
    capture: (b) => {
      const staged = ((b["recovery"] as Dict | undefined)?.["staged"] ?? null) as Dict | null;
      const fails: string[] = [];
      if (staged === null) fails.push("recovery.staged expected present, got null/absent");
      else {
        if (staged["resumeApplied"] !== false) fails.push(`recovery.staged.resumeApplied expected false, got ${String(staged["resumeApplied"])}`);
        if (staged["downpipes"] !== 1) fails.push(`recovery.staged.downpipes expected 1, got ${String(staged["downpipes"])}`);
      }
      return fails;
    },
  },
  {
    id: "cpr.export-pass-failing-and-stale",
    title: "the control-plane export credential lost write permission 9 days ago: every export pass since fails, so the recoverable plane is 9 days old",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["export-pass-degraded", "control-plane-export-stale"],
    expectAbsentSignals: ["wrap-key-unhealthy", "recovery-required"],
    mutate: (w) => {
      const now = Date.now();
      const rs = healthyRecoveryStatus(now);
      // The pass RAN this tick but its per-destination write FAILED (the export-pass-degraded shape
      // validate-support pins: perDest [{id, ok:false}], wroteAny false).
      rs.exportHealth = { at: iso(now - 20 * MIN), wroteAny: false, configVersion: 7, perDest: [{ id: "d-primary", ok: false }] };
      w.routes["/control-plane/recovery-status"] = rs;
      // The last export that LANDED covered config v6, 9 days ago (the stale plane a recovery would restore from).
      w.routes["/control-plane/export-state"] = { configVersion: 6, exportedAt: iso(now - 9 * DAY) };
    },
    capture: (b) => [
      ...expectInBundle(b, '"wroteAny":false', "the export pass's wroteAny=false outcome"),
      ...expectInBundle(b, '"ok":false', "the per-destination export write failure"),
      ...expectInBundle(b, '"configVersion":6', "the stale export-state pointer's covered config version"),
    ],
  },
  // FINDING-1 FIXED 2026-07-02: this fleet is HEALTHY — the config has not changed for 9 days, the
  // export pass skips with the benign "unchanged" code and the old export covers the CURRENT config
  // version, so control-plane-export-stale now stays quiet and the fleet auto-posts clean.
  {
    id: "cpr.export-stale-quiet-fleet",
    title: "a quiet fleet whose config has not changed in 9 days: the export pass skips 'unchanged' and the last export legitimately ages past 7 days",
    domain: "cpr",
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: [],
    expectAbsentSignals: ["control-plane-export-stale", "export-pass-degraded"],
    mutate: (w) => {
      const now = Date.now();
      const rs = healthyRecoveryStatus(now);
      // A recent pass that SKIPPED for the benign closed reason: nothing changed to export.
      rs.exportHealth = { at: iso(now - 20 * MIN), skipped: "unchanged", wroteAny: false, configVersion: 7, perDest: [] };
      w.routes["/control-plane/recovery-status"] = rs;
      // The last landed export covers the CURRENT config version — merely old, not out of date.
      w.routes["/control-plane/export-state"] = { configVersion: 7, exportedAt: iso(now - 9 * DAY) };
    },
    capture: (b) => [
      ...expectInBundle(b, '"skipped":"unchanged"', "the benign unchanged export-skip code"),
      ...expectInBundle(b, '"controlPlaneExport"', "the export-state pointer block"),
    ],
  },
  {
    id: "cpr.amnesia-probe-runlog-absent",
    title: "a bucket lifecycle rule expired _RECOVERY/RUNLOG: the amnesia self-check can no longer confirm scheduler-state integrity",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["control-plane-amnesia-probe-tripped"],
    expectAbsentSignals: ["recovery-required", "dest-auth-failed", "throttled"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/control-plane/recovery-status"] = {
        ...healthyRecoveryStatus(now),
        // The latch's own self-diagnosis: the destination answered but its RUNLOG is absent/unreadable
        // (AMNESIA_PROBE_CODES member "runlog-absent" — a recovery blind spot).
        amnesiaProbe: { probe: "runlog-absent", at: iso(now - 10 * MIN) },
      };
      // The RUNLOG object really is gone: the destination HEADs 404 (a normal absent state for the
      // real probe — present=false, still verified — so no dest fault is fabricated).
      w.net = [{ re: new RegExp(DEST_HOST.replace(/\./g, "\\.")), status: 404, body: "" }];
    },
    capture: (b) => [
      ...expectInBundle(b, '"amnesiaProbe"', "the amnesia-probe self-diagnosis block"),
      ...expectInBundle(b, '"runlog-absent"', "the runlog-absent probe class"),
    ],
  },
  {
    id: "cpr.audit-chain-broken",
    title: "a DO storage restore from an older snapshot broke the tamper-evident audit chain at seq 7",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["audit-chain-broken"],
    mutate: (w) => {
      const now = Date.now();
      // The audit-verify verdict shape validate-support pins, flipped to a genuine break (the
      // engine's verify is rollover-aware, so intact:false here is a real break, not a rollover).
      w.routes["/audit/verify"] = {
        intact: false,
        checkedThrough: 12,
        earliestSeq: 1,
        rolledOver: false,
        rolledOverCount: 0,
        brokenAt: 7,
        auditCount: 12,
        auditNearCap: false,
        verify: { at: iso(now - MIN), entriesChecked: 12, durationMs: 3, complete: true },
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"intact":false', "the failed audit-chain verify verdict"),
      ...expectInBundle(b, '"brokenAt":7', "the first broken seq"),
    ],
  },
  {
    id: "cpr.siem-feed-lapsed",
    title: "the SIEM collector VM was decommissioned: the audit-feed credential is live but nothing has pulled for 10 days",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["siem-feed-lapsed"],
    mutate: (w) => {
      const now = Date.now();
      // The audit-feed ingest grant (validate-support grant shape): unexpired, last pull 10 days ago.
      const grant = {
        clientId: "dpc_feed",
        secretSha384: "0".repeat(96),
        scope: "audit-feed",
        grantedAt: iso(now - 60 * DAY),
        grantedBy: "siem-admin@example.com",
        expiresAt: iso(now + 300 * DAY),
        pulls: [{ at: iso(now - 12 * DAY) }, { at: iso(now - 10 * DAY) }],
      };
      w.routes["/ingest-credential"] = (url: URL): Dict => ({ grant: url.searchParams.get("scope") === "audit-feed" ? grant : null });
    },
    capture: (b) => {
      const af = (b["auditFeed"] ?? {}) as Dict;
      const fails: string[] = [];
      if (af["configured"] !== true) fails.push(`auditFeed.configured expected true, got ${String(af["configured"])}`);
      if (af["expired"] !== false) fails.push(`auditFeed.expired expected false, got ${String(af["expired"])}`);
      if (typeof af["lastPullAt"] !== "string") fails.push("auditFeed.lastPullAt expected present (the lapse evidence)");
      if (bundleText(b).includes("siem-admin@example.com")) fails.push("the grantedBy email LEAKED into the pack (no-PII projection violated)");
      return fails;
    },
  },
  // FINDING-4 FIXED 2026-07-02: the destination probe now stamps `overrideUnreadable: true` when the
  // console-set record cannot be read/decrypted, and the bot routes the POSTURE-ISSUE cause to "the
  // console-set destination record could not be read/decrypted (check CONFIG_WRAP_KEY)" instead of
  // "no destination is configured" (asserted by the bot's fixround item-20 unit tests over this exact
  // shape). wrap-key-unhealthy still rides as the warning.
  {
    id: "cpr.wrap-key-rotated",
    title: "CONFIG_WRAP_KEY was rotated without re-wrapping: the stored destination credential no longer decrypts",
    domain: "cpr",
    trueClass: "POSTURE-ISSUE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["wrap-key-unhealthy", "posture-failed"],
    expectAbsentSignals: ["key-material-unhealthy", "dest-auth-failed"],
    mutate: (w) => {
      // A well-formed 32-byte AES key that is simply the WRONG one (rotated after the wrap): the
      // real fetchWrapKeyHealth unwrap then fails -> class "wrong-key" (never "malformed-key").
      w.env["CONFIG_WRAP_KEY"] = b64urlEncode(rand(32));
    },
    capture: (b) => {
      const fails: string[] = [];
      const wk = (b["wrapKeyHealth"] ?? {}) as Dict;
      if (wk["class"] !== "wrong-key") fails.push(`wrapKeyHealth.class expected wrong-key, got ${String(wk["class"])}`);
      const items = ((b["preflight"] as Dict | null)?.["items"] ?? []) as Dict[];
      const dest = items.find((i) => i["id"] === "destination");
      if (dest?.["status"] !== "unconfigured") fails.push(`preflight destination expected unconfigured (the override became unreadable), got ${String(dest?.["status"])}`);
      // The corrected-routing keystone (item 20): the probe must RECORD that the console record was unreadable.
      if (dest?.["overrideUnreadable"] !== true) fails.push(`preflight destination overrideUnreadable expected true, got ${String(dest?.["overrideUnreadable"])}`);
      return fails;
    },
  },
  {
    id: "cpr.deploy-identity-changed-benign",
    title: "a routine engine update 4 hours ago (bindings survived); the customer asks whether the update broke anything",
    domain: "cpr",
    // FIXED 2026-07-02 (F-HV2): deploy-identity-changed is now a correlator, so a redeploy whose
    // bindings all VERIFIED present and whose runs are green stays quiet and the fleet reads clean
    // HEALTHY. roster-dropped-across-version-change still fires (a version-change keystone with no
    // sources-detached after it) but it only routes a primary inside the bindings-probe-failed branch
    // and is deliberately NOT in the HEALTHY gate — the owner-#1 chain is unchanged.
    trueClass: "HEALTHY",
    isFault: false,
    expectEscalate: false,
    expectSignals: ["roster-dropped-across-version-change"],
    expectAbsentSignals: ["deploy-identity-changed", "bindings-probe-failed", "user-removed-binding", "vendor-deploy-corroborated"],
    mutate: (w) => {
      const now = Date.now();
      const rs = healthyRecoveryStatus(now);
      // The deterministic per-tick deploy-identity marker observed ONE recent change.
      rs.deploy = {
        engineVersion: "0.1.0",
        cfVersionId: "cfv-current-001",
        cfVersionIdAbsent: false,
        baselineEstablished: true,
        changesObserved: 1,
        firstSeenAt: iso(now - 30 * DAY),
        lastSeenAt: iso(now - 5 * MIN),
        lastChangeAt: iso(now - 4 * HOUR),
      };
      w.routes["/control-plane/recovery-status"] = rs;
      // The matching audit keystone: an engine-version-change with NO sources-detached after it.
      withAuditEvents(w, [
        { seq: 13, ts: iso(now - 4 * HOUR), action: "engine-version-change", outcome: "ok", target: { detail: "0.1.0" }, prevHash: "sha384:h12", hash: "sha384:h13" },
      ]);
    },
    capture: (b) => [
      ...expectInBundle(b, '"changesObserved":1', "the deploy-identity change count"),
      ...expectInBundle(b, '"lastChangeAt"', "the recent deploy-change timestamp"),
      ...expectInBundle(b, "engine-version-change", "the retained engine-version-change keystone"),
    ],
  },
  {
    id: "cpr.cor-registry-corrupt",
    title: "vendor intake cannot tie the bundle to a customer-of-record: the CoR registry read corrupt (control-plane cor-health)",
    domain: "cpr",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["cor-registry-unhealthy"],
    expectAbsentSignals: ["engine-flapping-two-versions"],
    // Out-of-band corroboration (the cor-health read-client's CorHealth shape): the registry is
    // minted but its integrity read is corrupt — the bundle itself is healthy.
    corroboration: {
      corHealth: {
        registry: "minted",
        integrity: "corrupt",
        corruptReads: 2,
        environment: { expected: "production", bound: "production", matches: true },
        baseline: { established: true },
        checkedAt: iso(Date.now()),
      },
    },
    mutate: () => {},
    capture: (b) => expectInBundle(b, '"accountTag"', "the engine account tag the CoR correlation keys on"),
  },

  // ============================================================== NOTIFY domain
  {
    id: "notify.delivery-failed-webhook-5xx",
    title: "the ops webhook endpoint was migrated and now answers 500: even success notifications fail to deliver",
    domain: "notify",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["notify-delivery-failed"],
    expectAbsentSignals: ["notify-sink-rebind-exposed", "no-notify-channels", "notify-rule-misconfigured"],
    mutate: (w) => {
      const now = Date.now();
      // The flat NotifyHistoryEntry shape the DO serves (validate-support): the newest delivery
      // FAILED with the closed http-5xx code; the older one had delivered fine.
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - 40 * MIN), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: false, deliveryCode: "http-5xx" },
        { seq: 2, ts: iso(now - 2 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
      ];
    },
    capture: (b) => [
      ...expectInBundle(b, '"delivered":false', "the failed delivery outcome"),
      ...expectInBundle(b, '"deliveryCode":"http-5xx"', "the closed delivery-failure code"),
    ],
  },
  {
    id: "notify.no-channels-configured",
    title: "the operator deleted the webhook channel during a vendor migration and never re-created one: alerting is off",
    domain: "notify",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["no-notify-channels"],
    expectAbsentSignals: ["notify-rule-misconfigured", "notify-delivery-failed"],
    mutate: (w) => {
      w.routes["/notify/channels"] = [];
      w.routes["/notify/rules"] = [];
    },
    capture: (b) => {
      const nc = (b["notifyConfig"] ?? {}) as Dict;
      return nc["channelCount"] === 0 ? [] : [`notifyConfig.channelCount expected 0, got ${String(nc["channelCount"])}`];
    },
  },
  {
    id: "notify.rule-references-deleted-channel",
    title: "a notification channel was deleted but the global routing rule still references it: that route's alerts silently drop",
    domain: "notify",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["notify-rule-misconfigured"],
    expectAbsentSignals: ["no-notify-channels", "notify-delivery-failed"],
    mutate: (w) => {
      // The live channel remains; the rule carries a DANGLING second channel id (a server-minted
      // ULID for a channel that no longer exists) — the validate-support dangling-ref shape.
      w.routes["/notify/rules"] = [{ events: "all", minSeverity: "warn", scope: { kind: "global" }, channelIds: ["ch-live", "ch-deleted"] }];
    },
    capture: (b) => expectInBundle(b, '"danglingChannelRefs":1', "the dangling rule->channel reference count"),
  },
  {
    id: "notify.sink-rebind-blocked",
    title: "a webhook at an internal-tools hostname resolved to a private IP at send time: the send-time screen blocked it and the alert never went out",
    domain: "notify",
    // Designed routing: the sinkScreen=hostname + internal-sink-blocked pairing fires the rebind
    // signal, and the same row's delivered:false fires notify-delivery-failed — both warning-only.
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["notify-sink-rebind-exposed", "notify-delivery-failed"],
    expectAbsentSignals: ["no-notify-channels"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: false, deliveryCode: "internal-sink-blocked", sinkScreen: "hostname" },
        { seq: 2, ts: iso(now - 3 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true, sinkScreen: "hostname" },
      ];
    },
    capture: (b) => [
      ...expectInBundle(b, '"sinkScreen":"hostname"', "the residual rebind-exposed sink-screen verdict"),
      ...expectInBundle(b, '"deliveryCode":"internal-sink-blocked"', "the internal-sink send-time block code"),
    ],
  },
  // FINDING-2 FIXED 2026-07-02: the 30-minute-old ACTIVE cooldown is the suppression window WORKING
  // (the first alert delivered) — alert-cooldown-stuck no longer fires on it and is now the scenario's
  // benign-active proof. The genuinely-stuck twin is fixround.alert-cooldown-genuinely-stuck.
  {
    id: "notify.canary-dead-cooldown-suppressed",
    title: "the destination has been down for 2 hours: the canary flipped dead (paged once), the failure alert delivered, and re-alerts sit in the 1h cooldown",
    domain: "notify",
    // One fault (the destination outage) with its full alerting story: the failed run's transient
    // SlowDown reject sets the DEST-THROTTLED-OR-DOWN primary (conf 0.85 < 0.90 bar -> escalates),
    // and the canary warning rides alongside (the active cooldown is by-design quiet).
    trueClass: "DEST-THROTTLED-OR-DOWN",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["throttled", "canary-standing-death"],
    expectAbsentSignals: ["alert-cooldown-stuck", "dest-auth-failed", "notify-delivery-failed", "no-notify-channels"],
    mutate: (w) => {
      const now = Date.now();
      failLatestRun(w, "destination rejected the write (SlowDown)");
      // The canary's standing death (validate-support transition-ring shape; to:"dead" is closed).
      w.routes["/canary/transitions"] = {
        enabled: true,
        status: "dead",
        deadDestinations: 1,
        transitionCount: 1,
        transitions: [{ at: iso(now - 2 * HOUR), destinationId: "d-primary", to: "dead", runSeq: 8 }],
      };
      // The one delivered critical alert, now inside its re-nudge cooldown window.
      w.routes["/notify/history"] = [
        { seq: 3, ts: iso(now - 30 * MIN), event: "backup-failure", severity: "critical", downpipeId: "dp1", channelKind: "webhook", delivered: true },
        { seq: 2, ts: iso(now - 3 * HOUR), event: "backup-success", severity: "info", downpipeId: "dp1", channelKind: "webhook", delivered: true },
      ];
      w.routes["/notify/cooldowns"] = { cooldownMs: 3_600_000, alert: [{ downpipeId: "dp1", state: "failed", at: now - 30 * MIN }], replication: [] };
    },
    capture: (b) => [
      ...expectInBundle(b, '"deadDestinations":1', "the standing canary death count"),
      ...expectInBundle(b, '"state":"failed"', "the active alert-cooldown row"),
      ...expectInBundle(b, "destination rejected the write (SlowDown)", "the failed run's transient dest reject"),
    ],
  },

  // ================================================================ AUTH domain
  {
    id: "auth.idp-saml-connection-deleted",
    title: "an owner deleted the corporate SAML connection during an IdP migration; staff SSO sign-in then broke",
    domain: "auth",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["idp-connection-disrupted"],
    expectAbsentSignals: ["idp-management-denied", "bindings-probe-failed"],
    mutate: (w) => {
      const now = Date.now();
      // The idp-connection-change event with its structured idpconnection target (validate-support
      // shape): a SUCCESSFUL DELETE of a saml connection — the disruptive-op class. The connId is an
      // operator slug the excerpt must NEVER carry.
      withAuditEvents(w, [
        { seq: 13, ts: iso(now - 3 * DAY), action: "idp-connection-change", outcome: "success", prevHash: "sha384:h12", hash: "sha384:h13", target: { kind: "idpconnection", connId: "corp-saml-prod", connKind: "saml", op: "delete" } },
      ]);
    },
    capture: (b) => {
      const fails = [
        ...expectInBundle(b, '"connKind":"saml"', "the disrupted connection's protocol kind"),
        ...expectInBundle(b, '"op":"delete"', "the disruptive op"),
      ];
      if (bundleText(b).includes("corp-saml-prod")) fails.push("the operator connId LEAKED into the excerpt (redaction violated)");
      return fails;
    },
  },
  {
    id: "auth.idp-management-denied",
    title: "a helpdesk operator without owner rights tried to re-test the OIDC connection and was blocked (no config changed)",
    domain: "auth",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["idp-management-denied"],
    // A DENIED attempt changes nothing, so the disruptive-change signal must NOT fire.
    expectAbsentSignals: ["idp-connection-disrupted"],
    mutate: (w) => {
      const now = Date.now();
      withAuditEvents(w, [
        { seq: 13, ts: iso(now - 6 * HOUR), action: "idp-connection-change", outcome: "denied", prevHash: "sha384:h12", hash: "sha384:h13", target: { kind: "idpconnection", connId: "corp-oidc-prod", connKind: "oidc", op: "test" } },
      ]);
    },
    capture: (b) => [
      ...expectInBundle(b, '"outcome":"denied"', "the denied management-attempt outcome"),
      ...expectInBundle(b, '"op":"test"', "the attempted op"),
    ],
  },
  {
    id: "auth.sso-saml-signature-failing",
    title: "the IdP rotated its SAML signing certificate this morning: every staff sign-in since fails the signature check",
    domain: "auth",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    // The per-code aggregate and its per-protocol split both record the same failures (the engine
    // maintains both), so one fault fires both signals: dominant code "signature", dominant kind "saml".
    expectSignals: ["sso-signin-failing", "sign-in-failing-by-protocol"],
    expectAbsentSignals: ["auth-defensive-branch-firing", "idp-connection-disrupted"],
    mutate: (w) => {
      const now = Date.now();
      w.routes["/sso-failures"] = { signature: { count: 14, lastAt: iso(now - 25 * MIN) } };
      w.routes["/sso-failures-by-kind"] = { saml: { signature: { count: 14, lastAt: iso(now - 25 * MIN) } } };
    },
    capture: (b) => {
      const sso = (b["ssoFailures"] ?? {}) as Dict;
      const byKind = (b["ssoFailuresByKind"] ?? {}) as Dict;
      const fails: string[] = [];
      if ((sso["signature"] as Dict | undefined)?.["count"] !== 14) fails.push("ssoFailures.signature.count expected 14");
      if (((byKind["saml"] as Dict | undefined)?.["signature"] as Dict | undefined)?.["count"] !== 14) fails.push("ssoFailuresByKind.saml.signature.count expected 14");
      return fails;
    },
  },
  {
    id: "auth.ratelimit-lockout-shared-nat",
    title: "a whole office behind one NAT egress IP tripped the per-IP sign-in rate limit: staff are locked out until the window passes",
    domain: "auth",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["auth-defensive-branch-firing"],
    expectAbsentSignals: ["sso-signin-failing", "no-admin-credential-path"],
    mutate: (w) => {
      const now = Date.now();
      // The bounded auth-signal aggregate keyed by the CLOSED AUTH_SIGNAL_NAMES member.
      w.routes["/auth-signals"] = { "auth-ratelimited": { count: 37, lastAt: iso(now - 20 * MIN) } };
    },
    capture: (b) => {
      const a = ((b["authSignals"] ?? {}) as Dict)["auth-ratelimited"] as Dict | undefined;
      return a?.["count"] === 37 ? [] : [`authSignals.auth-ratelimited.count expected 37, got ${String(a?.["count"])}`];
    },
  },
  {
    id: "auth.session-signing-key-lost",
    title: "an auth-DO storage reset lost the session signing key: sessions cannot be signed and recovery-code sign-in is broken",
    domain: "auth",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["session-signing-key-missing-or-aged"],
    expectAbsentSignals: ["no-admin-credential-path", "posture-failed"],
    mutate: (w) => {
      // The auth-posture probe reports the key ABSENT; the alternative credential paths remain.
      w.routes["/auth-posture"] = {
        sessionSigningKey: { present: false },
        doPlaintextSecretsMissing: 0,
        adminCredentialPaths: { passkeyCredentials: 1, enabledIdpConnections: 1 },
      };
    },
    capture: (b) => {
      const sk = ((b["authPosture"] ?? {}) as Dict)["sessionSigningKey"] as Dict | undefined;
      return sk?.["present"] === false ? [] : [`authPosture.sessionSigningKey.present expected false, got ${String(sk?.["present"])}`];
    },
  },
  {
    id: "auth.admin-lockout-no-credential-path",
    title: "the owner disabled the bare-token fallback after enrolling a passkey, then deleted that passkey: every admin sign-in path is now closed",
    domain: "auth",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["no-admin-credential-path"],
    expectAbsentSignals: ["session-signing-key-missing-or-aged", "auth-defensive-branch-firing"],
    mutate: (w) => {
      // status.tokenFallbackDisabled reads env ADMIN_TOKEN_DISABLED (envFlagEnabled: "true").
      w.env["ADMIN_TOKEN_DISABLED"] = "true";
      // Zero passkeys + zero enabled IdP connections; no CF_ACCESS_* env, so the access-zero-trust
      // probe stays "unconfigured" (required:false — not a posture fault, but not a sign-in path).
      w.routes["/auth-posture"] = {
        sessionSigningKey: { present: true, ageMs: 3 * DAY, adequateLength: true },
        doPlaintextSecretsMissing: 0,
        adminCredentialPaths: { passkeyCredentials: 0, enabledIdpConnections: 0 },
      };
    },
    capture: (b) => [
      ...expectInBundle(b, '"tokenFallbackDisabled":true', "the disabled bare-token fallback flag"),
      ...expectInBundle(b, '"passkeyCredentials":0', "the zero-passkey credential-path count"),
      ...expectInBundle(b, '"enabledIdpConnections":0', "the zero-IdP credential-path count"),
    ],
  },

  // ============================================================= LICENCE domain
  {
    id: "lic.expired-three-weeks",
    title: "the enterprise licence lapsed three weeks ago and nobody renewed: the engine fails open to community",
    domain: "lic",
    // Designed routing: licence-expired AND licence-invalid both fire (an expired token verifies
    // then resolves valid:false with the closed reasonCode "expired") — warning-only, so INDETERMINATE.
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["licence-expired", "licence-invalid"],
    expectAbsentSignals: ["licence-expiring-soon", "licence-activation-failed"],
    mutate: (w) => {
      // A REAL vendor-signed token whose notAfter is past: the real readLicence verifies the
      // signature then fails open to community with reasonCode "expired".
      w.env["LICENCE_TOKEN"] = LIC.expiredToken;
      w.env["LICENCE_SIGNER_PUBLIC"] = LIC.pin;
    },
    capture: (b) => {
      const lic = (b["licence"] ?? {}) as Dict;
      const fails: string[] = [];
      if (lic["valid"] !== false) fails.push(`licence.valid expected false, got ${String(lic["valid"])}`);
      if (lic["reasonCode"] !== "expired") fails.push(`licence.reasonCode expected expired, got ${String(lic["reasonCode"])}`);
      if (lic["notAfter"] !== LIC.expiredNotAfter) fails.push(`licence.notAfter expected the lapsed expiry ${LIC.expiredNotAfter}, got ${String(lic["notAfter"])}`);
      return fails;
    },
  },
  {
    id: "lic.expiring-in-seven-days",
    title: "the enterprise licence is valid but expires in 7 days: a renewal heads-up, nothing broken yet",
    domain: "lic",
    // A valid-but-expiring licence is not a fault; the bot deliberately gates HEALTHY + escalates
    // for the renewal heads-up (warning-only -> INDETERMINATE).
    trueClass: "INDETERMINATE",
    isFault: false,
    expectEscalate: true,
    expectSignals: ["licence-expiring-soon"],
    expectAbsentSignals: ["licence-expired", "licence-invalid", "licence-expiry-stale"],
    mutate: (w) => {
      w.env["LICENCE_TOKEN"] = LIC.soonToken;
      w.env["LICENCE_SIGNER_PUBLIC"] = LIC.pin;
    },
    capture: (b) => {
      const lic = (b["licence"] ?? {}) as Dict;
      const fails: string[] = [];
      if (lic["valid"] !== true) fails.push(`licence.valid expected true, got ${String(lic["valid"])}`);
      if (lic["tier"] !== "enterprise") fails.push(`licence.tier expected enterprise, got ${String(lic["tier"])}`);
      if (lic["notAfter"] !== LIC.soonNotAfter) fails.push(`licence.notAfter expected ${LIC.soonNotAfter}, got ${String(lic["notAfter"])}`);
      return fails;
    },
  },
  {
    id: "lic.activation-refused-expired-token",
    title: "the customer keeps pasting last year's licence into the console: the verify-before-store gate refuses it and the engine stays community",
    domain: "lic",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["licence-activation-failed"],
    // The refusal left NO active licence, so the live licence block stays the benign community
    // no-token state (licence-invalid must NOT fire on it).
    expectAbsentSignals: ["licence-invalid", "licence-expired"],
    mutate: (w) => {
      const now = Date.now();
      // The refusal tally shape validate-support pins ("expired" is a LICENCE_REFUSAL_CODE_SET member).
      w.routes["/licence-activation-refusal"] = { count: 4, lastAt: now - 2 * HOUR, lastReasonCode: "expired" };
    },
    capture: (b) => {
      const lar = (b["licenceActivationRefusals"] ?? {}) as Dict;
      const fails: string[] = [];
      if (lar["count"] !== 4) fails.push(`licenceActivationRefusals.count expected 4, got ${String(lar["count"])}`);
      if (lar["lastReasonCode"] !== "expired") fails.push(`licenceActivationRefusals.lastReasonCode expected expired, got ${String(lar["lastReasonCode"])}`);
      return fails;
    },
  },
  {
    id: "lic.expiry-tracker-missed-renewal",
    title: "the licence was renewed but the engine's expiry-registry row still tracks the OLD expiry: the tracker missed the renewal",
    domain: "lic",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["licence-expiry-stale"],
    expectAbsentSignals: ["licence-expired", "licence-expiring-soon", "licence-invalid"],
    mutate: (w) => {
      const now = Date.now();
      // The LIVE licence: a renewed, valid token good for ~300 days.
      w.env["LICENCE_TOKEN"] = LIC.longToken;
      w.env["LICENCE_SIGNER_PUBLIC"] = LIC.pin;
      // The OBSERVED expiry-registry row still carries the PRE-renewal expiry (30 days out):
      // trackedNotAfter differs from licence.notAfter -> the bot-side drift comparison fires.
      w.routes["/expiry"] = [
        { id: "lic-observed", label: "my licence", kind: "licence", expiresAt: iso(now + 30 * DAY), state: "approaching", source: "observed" },
      ];
    },
    capture: (b) => {
      const lic = (b["licence"] ?? {}) as Dict;
      const trk = (b["licenceExpiryTracker"] ?? {}) as Dict;
      const fails: string[] = [];
      if (typeof trk["trackedNotAfter"] !== "string") fails.push("licenceExpiryTracker.trackedNotAfter expected present");
      if (trk["source"] !== "observed") fails.push(`licenceExpiryTracker.source expected observed, got ${String(trk["source"])}`);
      if (lic["notAfter"] === trk["trackedNotAfter"]) fails.push("tracked expiry row expected to DIFFER from the live licence.notAfter (the drift evidence)");
      if (bundleText(b).includes("my licence")) fails.push("the registry row's operator label LEAKED into the pack");
      return fails;
    },
  },
  {
    id: "lic.beacon-configured-but-rejected",
    title: "the opt-in vendor beacon is on, but the vendor ingest has answered 503 since Tuesday: no vendor-side corroboration despite the opt-in",
    domain: "lic",
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["beacon-silent"],
    expectAbsentSignals: ["engine-flapping-two-versions"],
    mutate: (w) => {
      const now = Date.now();
      // The beacon env gate (BEACON_URL + BEACON_INGEST_KEY + CF_ACCOUNT_ID) -> configured:true;
      // the DO's last-POST record says the vendor rejected it (the beacon-post-lost shape).
      w.env["BEACON_URL"] = "https://beacon.vendor.example/ingest";
      w.env["BEACON_INGEST_KEY"] = "corpus-beacon-ingest-key";
      w.routes["/beacon-state"] = { at: now - 45 * MIN, ok: false, status: 503 };
    },
    capture: (b) => {
      const beacon = (b["beacon"] ?? {}) as Dict;
      const fails: string[] = [];
      if (beacon["configured"] !== true) fails.push(`beacon.configured expected true, got ${String(beacon["configured"])}`);
      if (beacon["lastOk"] !== false) fails.push(`beacon.lastOk expected false, got ${String(beacon["lastOk"])}`);
      if (beacon["lastStatus"] !== 503) fails.push(`beacon.lastStatus expected 503, got ${String(beacon["lastStatus"])}`);
      if (bundleText(b).includes("corpus-beacon-ingest-key")) fails.push("the BEACON_INGEST_KEY value LEAKED into the pack");
      return fails;
    },
  },
  {
    id: "lic.engine-flapping-two-versions",
    title: "the vendor deploy ledger shows this account reporting under two distinct engine deploy ids in one window: two engines contending one ledger row",
    domain: "lic",
    // CORROBORATION-driven by design: a single self-signed bundle cannot self-prove flapping (a
    // normal redeploy also changes cfVersionId), so the bundle stays untouched and the ledger
    // verdict arrives out-of-band; the signal pairs it with the bundle's cfVersionId identity.
    trueClass: "INDETERMINATE",
    isFault: true,
    expectEscalate: true,
    expectSignals: ["engine-flapping-two-versions"],
    expectAbsentSignals: ["deploy-identity-changed", "beacon-silent"],
    corroboration: { engineVersionFlappingForAccount: true },
    mutate: () => {},
    capture: (b) => {
      const eng = (b["engine"] ?? {}) as Dict;
      return typeof eng["cfVersionId"] === "string" && (eng["cfVersionId"] as string) !== ""
        ? []
        : ["engine.cfVersionId expected present (the per-engine identity the ledger correlates)"];
    },
  },
];
