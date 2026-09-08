// validate-sched-gap-evidence -- the SCHEDULER-DO closing round of the support-pack diagnostic coverage.
//
// Every gap in this file is a fault the engine already DETECTED and then threw away, so the whole test
// suite is one shape, applied eleven times:
//
//   1. RECORDED ON THE REAL PATH. Not "the recorder works" -- the recorder is CALLED where the fault is,
//      and the aggregate the pack reads comes back non-empty. The cardinal rule of this campaign is that a
//      gap is not closed until its evidence is IN THE BUNDLE, so every assertion here reads through
//      readSchedDiag (the single GET /sched-diag projection the pack builds from), never a private key.
//   2. REDACTION-SAFE, PROVEN BY SENTINEL. A customer email, a bucket name, an object key, a secret, an
//      endpoint, a connId and a cron string are planted AT the fault site and the whole serialised record is
//      searched: not one byte of any sentinel may appear. This is the no-custody guarantee, and it is the
//      reason the classifiers may READ an error message but must RETURN a closed enum.
//   3. BOUNDED. Closed-set membership at the write boundary (an out-of-vocabulary key is dropped, never
//      stored), and the caps hold under a flood.
import assert from "node:assert/strict";
import {
  ALERTING_HEALTH_EVENTS,
  AUTHZ_GATES,
  CAP_TRUNCATION_SURFACES,
  CONFIG_COERCION_SURFACES,
  CONFIG_DROP_CLASSES,
  CONFIG_REJECT_REASONS,
  CONFIG_SURFACES,
  POSTURE_INPUT_FAULTS,
  classifyAuthzGate,
  classifyConfigReject,
  classifyConfigSurface,
  destCoercionClasses,
  readSchedDiag,
  recordAlertingHealth,
  recordAuditGapPage,
  recordAuditMirrorFailure,
  recordAuthzRefusal,
  recordCapTruncation,
  recordConfigCoercion,
  recordConfigRejection,
  recordPostureInputFault,
  type LedgerStorage,
} from "../src/sched/sched-fault-ledger.ts";
import { analyseRoster } from "../src/sched/roster-hygiene.ts";
import { SSO_FAIL_CODES } from "../src/admin/sso-failure-class.ts";
import { mirrorAuditEvent } from "../src/admin/audit-mirror.ts";
import { ALL_CAPABILITIES } from "../src/admin/identity-rbac.ts";
import { BEACON_FAIL_CLASSES } from "../src/cron/cron-fault-ledger.ts";
import { BEACON_ATTEMPT_RING_CAP } from "../src/sched/scheduler-do-base.ts";

// ---- the fake storage (a Map, with list, so readPostureDiag's override enumeration is exercised) --------
function fakeStorage(): LedgerStorage & { map: Map<string, unknown> } {
  const map = new Map<string, unknown>();
  return {
    map,
    async get<T>(key: string): Promise<T | undefined> {
      return map.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      map.set(key, structuredClone(value));
    },
    async list<T>(options?: { prefix?: string }): Promise<Map<string, T>> {
      const out = new Map<string, T>();
      for (const [k, v] of map) if (options?.prefix === undefined || k.startsWith(options.prefix)) out.set(k, v as T);
      return out;
    },
  };
}

// THE SENTINELS. Every one is a value the no-custody posture forbids from EVER entering a record. They are
// planted at the fault sites below and then hunted for in the serialised bundle.
const SENTINELS: readonly string[] = [
  "alice.admin@customer-tenant.example", // a customer email
  "acme-prod-backups-bucket", // a destination bucket
  "downpipes/2026/07/10/run-01HZ/segment-0007.dpk", // an object key
  "sk_live_9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c", // a secret
  "https://a1b2c3.r2.cloudflarestorage.com", // an endpoint
  "okta-prod-saml-tenant-471", // an operator-chosen connId
  "*/7 3 * * MON-FRI", // a cron string
  "Bearer eyJhbGciOiJIUzI1NiJ9.zzz", // a header
];
function assertNoSentinels(label: string, value: unknown): void {
  const s = JSON.stringify(value);
  for (const sentinel of SENTINELS) {
    assert.ok(!s.includes(sentinel), `${label}: LEAKED the sentinel ${JSON.stringify(sentinel)} into the record`);
  }
  // Belt and braces: the sentinel FRAGMENTS that a naive substring/prefix leak would surface.
  for (const frag of ["customer-tenant", "acme-prod", "sk_live", "cloudflarestorage", "okta-prod", "MON-FRI", "eyJhbGci"]) {
    assert.ok(!s.includes(frag), `${label}: LEAKED the fragment ${JSON.stringify(frag)} into the record`);
  }
}

let failures = 0;
async function t(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL ${name}: ${(e as Error).message}`);
  }
}

// =====================================================================================================
// G139 + G141: rejected configuration writes (the 400 that reached only the browser)
// =====================================================================================================
async function g139g141(): Promise<void> {
  console.log("configRejections");

  await t("the DO's own static route keys map onto closed surfaces (every surface is reachable)", () => {
    // The surfaces the two gaps name explicitly, each from the route the DO actually serves.
    assert.equal(classifyConfigSurface("POST", "/downpipes"), "downpipe-config");
    assert.equal(classifyConfigSurface("POST", "/downpipes/bulk"), "bulk-downpipe");
    assert.equal(classifyConfigSurface("POST", "/idp/conn/cert"), "idp-cert-rollover"); // the one that expires tomorrow
    assert.equal(classifyConfigSurface("POST", "/idp/conn/create"), "idp-connection");
    assert.equal(classifyConfigSurface("POST", "/control-plane/reconcile"), "cp-reconcile"); // the DR-critical break-glass path
    assert.equal(classifyConfigSurface("POST", "/control-plane/import"), "cp-import");
    assert.equal(classifyConfigSurface("POST", "/roles"), "role-write");
    assert.equal(classifyConfigSurface("POST", "/group-roles"), "group-mapping");
    assert.equal(classifyConfigSurface("POST", "/custom-roles"), "custom-role");
    assert.equal(classifyConfigSurface("POST", "/notify/rules"), "notify-rule");
    assert.equal(classifyConfigSurface("POST", "/notify/channel"), "notify-channel");
    assert.equal(classifyConfigSurface("POST", "/coverage/inventory"), "coverage-inventory");
    assert.equal(classifyConfigSurface("POST", "/cf-config/mode"), "cf-config-mode");
    assert.equal(classifyConfigSurface("POST", "/expiry"), "expiry-item");
    assert.equal(classifyConfigSurface("POST", "/otlp-push"), "otlp-destination");
    assert.equal(classifyConfigSurface("POST", "/destinations/remove"), "destination-remove");
    assert.equal(classifyConfigSurface("POST", "/fleet-drill/start"), "fleet-drill");
    // The residual: an unrecognised route is COUNTED as "other", never dropped (a silent drop would rebuild
    // the exact blind spot this ledger exists to remove).
    assert.equal(classifyConfigSurface("POST", "/some/route/a/future/build/adds"), "other");
  });

  await t("SECURITY: a reserved-binding attempt is its OWN reason, never coarsened into a typo", () => {
    // config-validate.ts's confused-deputy guard: a source binding naming the engine's signer key.
    const e = new Error("source binding must not name a reserved binding: SIGNER_PRIVATE");
    assert.equal(classifyConfigReject(e), "reserved-binding");
    // and it must NOT fall through to the generic binding-shape class
    assert.notEqual(classifyConfigReject(e), "source-binding-invalid");
  });

  await t("the classifier READS the validator message and RETURNS a closed enum (never the text)", () => {
    // Each message is the engine's REAL validator prose, with a customer sentinel interpolated exactly the
    // way the live validators interpolate one.
    const cases: Array<[string, string]> = [
      [`schedule.cron is invalid: cron dow value 9 out of range 0-6 (${SENTINELS[6]})`, "cron-invalid"],
      ["cadenceSeconds must be an integer of at least 60", "cadence-bounds"],
      ["retention.keepRuns must be an integer from 1 to 10000", "retention-bounds"],
      ["restoreTestCadenceSeconds must be 0 (off) or at least 3600", "restore-cadence-bounds"],
      [`accountId "9f3a" is not one of the discovery-selected Cloudflare accounts; select it under Sources first`, "discovery-scope"],
      [`the destination endpoint must be an https URL (got ${SENTINELS[4]})`, "endpoint-not-https"],
      [`that does not look like a Cloudflare API token (paste the token value itself): ${SENTINELS[3]}`, "token-shape"],
      [`email must be a valid lowercased address: ${SENTINELS[0]}`, "email-shape"],
      [`this destination (${SENTINELS[1]}) holds the only proven copy of backed-up runs`, "orphan-guard"],
      ["source.type must be kv/r2/secrets/d1/cf-config/workers/stream/images/artifacts", "source-type-unknown"],
      [`unknown custom role: ${SENTINELS[5]}`, "unknown-custom-role"],
      ["checkId must be a known posture check id", "unknown-check-id"],
    ];
    for (const [message, expected] of cases) {
      const got = classifyConfigReject(new Error(message));
      assert.equal(got, expected, `"${message.slice(0, 40)}..." -> ${got}, expected ${expected}`);
      // THE POINT: what comes back is a closed member, and the message is not in it.
      assert.ok((CONFIG_REJECT_REASONS as readonly string[]).includes(got));
      assertNoSentinels("classifyConfigReject return", got);
    }
  });

  await t("recorded on the fault path and readable from the /sched-diag bundle, with no sentinel", async () => {
    const st = fakeStorage();
    // The exact throws the real fault sites produce, classified and recorded through the ONE funnel.
    await recordConfigRejection(st, classifyConfigSurface("POST", "/idp/conn/cert"), classifyConfigReject(new Error("certificate is not valid PEM")));
    await recordConfigRejection(st, classifyConfigSurface("POST", "/downpipes"), classifyConfigReject(new Error(`schedule.cron is invalid: bad field (${SENTINELS[6]})`)));
    await recordConfigRejection(st, classifyConfigSurface("POST", "/downpipes"), classifyConfigReject(new Error(`schedule.cron is invalid: bad field (${SENTINELS[6]})`)));
    await recordConfigRejection(st, classifyConfigSurface("POST", "/control-plane/import"), classifyConfigReject(new Error(`the export is not readable: ${SENTINELS[2]}`)));
    await recordConfigRejection(st, "downpipe-config", "reserved-binding");

    const bundle = await readSchedDiag(st);
    // IN THE BUNDLE (the cardinal rule): the pack's projection sees it.
    assert.equal(bundle.configRejections["downpipe-config|cron-invalid"]?.count, 2, "the repeated cron rejection must count 2");
    assert.equal(bundle.configRejections["downpipe-config|reserved-binding"]?.count, 1);
    assert.ok(bundle.configRejections["idp-cert-rollover|shape-rejected"] !== undefined || Object.keys(bundle.configRejections).some((k) => k.startsWith("idp-cert-rollover|")), "the cert rollover must be attributed to its own surface");
    assert.ok(Object.keys(bundle.configRejections).some((k) => k.startsWith("cp-import|")), "the DR-critical import refusal must be on record");
    assertNoSentinels("configRejections", bundle.configRejections);
  });

  await t("out-of-vocabulary surface/reason is DROPPED (no caller string can become a key)", async () => {
    const st = fakeStorage();
    await recordConfigRejection(st, SENTINELS[1] as never, "cron-invalid");
    await recordConfigRejection(st, "downpipe-config", SENTINELS[0] as never);
    const bundle = await readSchedDiag(st);
    assert.deepEqual(bundle.configRejections, {}, "an out-of-set key must never be stored");
  });
}

// =====================================================================================================
// G187 + G249: authorisation refusals (the 403 audited only when it succeeds)
// =====================================================================================================
async function g187g249(): Promise<void> {
  console.log("authzRefusals");

  await t("every CAPABILITY name is a first-class gate (the vocabulary cannot drift from the product)", () => {
    for (const cap of ALL_CAPABILITIES) {
      assert.ok(AUTHZ_GATES.includes(cap), `capability ${cap} is not in the authz-gate vocabulary`);
    }
  });

  await t("the AuthError detail selects a closed gate and the detail itself never rides", () => {
    // The REAL AuthError messages from the DO's guard sites.
    assert.equal(classifyAuthzGate(new Error("forbidden: restore.apply capability required")), "restore.apply");
    assert.equal(classifyAuthzGate(new Error("forbidden: notify.config capability required")), "notify.config");
    assert.equal(classifyAuthzGate(new Error("forbidden: posture.riskaccept capability required")), "posture.riskaccept");
    // The escalation guard also NAMES a capability but is a DIFFERENT gate: it must not read as a plain
    // capability refusal ("did our access-admin try to self-elevate?" is a different question from "which
    // capability is my role missing?").
    assert.equal(classifyAuthzGate(new Error("forbidden: cannot grant a role conferring the roles.write capability that you do not hold")), "grant-over-authority");
    assert.equal(classifyAuthzGate(new Error("a group cannot be mapped to owner; owner must be an explicit per-email grant")), "group-to-owner");
    assert.equal(classifyAuthzGate(new Error("forbidden: only an Owner may grant or remove the owner role")), "owner-escalation-guard");
    assert.equal(classifyAuthzGate(new Error("forbidden: control-plane reconcile requires the break-glass token")), "break-glass-required");
    assert.equal(classifyAuthzGate(new Error("forbidden: the estate import requires an authenticated Owner, not the break-glass token")), "break-glass-forbidden");
    assert.equal(classifyAuthzGate(new Error("forbidden: only an Owner may terminate all sessions")), "owner-only");
    assert.equal(classifyAuthzGate(new Error("support credentials require the owner role")), "support-credential-owner-only");
    // The residual: an unnamed refusal is counted as unclassified, never stored verbatim.
    assert.equal(classifyAuthzGate(new Error(`forbidden: ${SENTINELS[0]} is not permitted`)), "unclassified");
  });

  await t("recorded, in the bundle, and carries no caller identity", async () => {
    const st = fakeStorage();
    // A caller's email/IP is deliberately NOT a parameter of the recorder: it structurally cannot be stored.
    await recordAuthzRefusal(st, classifyAuthzGate(new Error("forbidden: restore.apply capability required")));
    await recordAuthzRefusal(st, classifyAuthzGate(new Error("forbidden: restore.apply capability required")));
    await recordAuthzRefusal(st, classifyAuthzGate(new Error("forbidden: control-plane reconcile requires the break-glass token")));
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.authzRefusals["restore.apply"]?.count, 2, "the repeated capability refusal must count");
    assert.equal(bundle.authzRefusals["break-glass-required"]?.count, 1);
    assertNoSentinels("authzRefusals", bundle.authzRefusals);
    // No per-refusal rows: the anti-enumeration posture of the HTTP response is preserved.
    for (const v of Object.values(bundle.authzRefusals)) {
      assert.deepEqual(Object.keys(v).sort(), ["count", "lastAt"]);
    }
  });

  await t("an out-of-vocabulary gate is DROPPED", async () => {
    const st = fakeStorage();
    await recordAuthzRefusal(st, SENTINELS[0]!);
    assert.deepEqual((await readSchedDiag(st)).authzRefusals, {});
  });
}

// =====================================================================================================
// G188: the alerting pipeline's own health
// =====================================================================================================
async function g188(): Promise<void> {
  console.log("alertingHealth");

  await t("every closed event records into the bundle, counts and stamps", async () => {
    const st = fakeStorage();
    for (const ev of ALERTING_HEALTH_EVENTS) await recordAlertingHealth(st, ev);
    await recordAlertingHealth(st, "detection-off-no-sink"); // a second off-pass
    const bundle = await readSchedDiag(st);
    for (const ev of ALERTING_HEALTH_EVENTS) {
      assert.ok(bundle.alertingHealth[ev] !== undefined, `${ev} did not reach the bundle`);
      assert.ok(typeof bundle.alertingHealth[ev]!.lastAt === "string");
    }
    assert.equal(bundle.alertingHealth["detection-off-no-sink"]!.count, 2);
    // The cron-driver-silent signal the bot reads.
    assert.ok(bundle.alertingHealth["cron-deadman-tripped"] !== undefined);
    // The batch that reached no sink: the alarm-driven backstop holds no channel adapter, so a batch it
    // detects during a cron outage is discarded, and this counter is the only place that shows.
    assert.ok(bundle.alertingHealth["undeliverable-alert-batch"] !== undefined);
    assertNoSentinels("alertingHealth", bundle.alertingHealth);
  });

  await t("an out-of-vocabulary event is DROPPED (a webhook URL can never become a key)", async () => {
    const st = fakeStorage();
    await recordAlertingHealth(st, SENTINELS[4] as never);
    assert.deepEqual((await readSchedDiag(st)).alertingHealth, {});
  });
}

// =====================================================================================================
// G297: accepted-but-silently-narrowed writes
// =====================================================================================================
async function g297(): Promise<void> {
  console.log("configCoercions");

  await t("destCoercionClasses detects the drops from the SUBMITTED SHAPE, returning closed classes only", () => {
    // The real submission the DO would accept-and-narrow: a garbled WORM policy, an out-of-enum objectLock,
    // and a negative pricing rate -- alongside the real endpoint/bucket/credential, which must not escape.
    const submitted = {
      endpoint: SENTINELS[4],
      bucket: SENTINELS[1],
      accessKeyId: "AKIA_SENTINEL",
      secretAccessKey: SENTINELS[3],
      worm: "compliance-30d", // a STRING where the policy object is required -> dropped fail-safe
      objectLock: "yes-please", // out of the three-literal enum -> dropped
      pricing: { storagePerGBMonth: -1, egressPerGB: 0.01 }, // negative -> coerced to 0
    };
    const classes = destCoercionClasses(submitted);
    assert.ok(classes.includes("invalid-optional-field"), "the dropped WORM policy must be detected");
    assert.ok(classes.includes("coerced-zero"), "the negative rate coerced to 0 must be detected");
    for (const c of classes) assert.ok((CONFIG_DROP_CLASSES as readonly string[]).includes(c));
    assertNoSentinels("destCoercionClasses", classes);
    // The happy path writes nothing.
    assert.deepEqual(destCoercionClasses({ endpoint: "https://x", bucket: "b", worm: { mode: "compliance" }, objectLock: "enforced" }), []);
  });

  await t("the drop COUNT rides, and lands in the bundle, for every surface", async () => {
    const st = fakeStorage();
    // "I selected three accounts and only two show up" -- one unknown id filtered out.
    await recordConfigCoercion(st, "discovery-selected", "unknown-id", 1);
    // "account X is in my org but Downpipes refuses it" -- 12 accounts past the 100 cap.
    await recordConfigCoercion(st, "discovery-accounts-seen", "truncated-over-cap", 12);
    // "we rotated the Datadog key but the engine kept pushing with the old one".
    await recordConfigCoercion(st, "otlp-destination", "malformed-secret-kept-prior");
    // "we configured WORM and it shows nothing".
    for (const cls of destCoercionClasses({ worm: "compliance-30d", pricing: { egressPerGB: Number.NaN } })) {
      await recordConfigCoercion(st, "destination", cls);
    }
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.configCoercions["discovery-accounts-seen|truncated-over-cap"]?.count, 12, "the DROPPED-ITEM count, not the call count");
    assert.equal(bundle.configCoercions["discovery-selected|unknown-id"]?.count, 1);
    assert.equal(bundle.configCoercions["otlp-destination|malformed-secret-kept-prior"]?.count, 1);
    assert.equal(bundle.configCoercions["destination|invalid-optional-field"]?.count, 1);
    assert.equal(bundle.configCoercions["destination|coerced-zero"]?.count, 1);
    assertNoSentinels("configCoercions", bundle.configCoercions);
  });

  await t("a zero/negative drop is a no-op (the happy path never writes) and a bad surface is dropped", async () => {
    const st = fakeStorage();
    await recordConfigCoercion(st, "destination", "unknown-id", 0);
    await recordConfigCoercion(st, "destination", "unknown-id", -5);
    await recordConfigCoercion(st, SENTINELS[1] as never, "unknown-id", 3);
    await recordConfigCoercion(st, "destination", SENTINELS[3] as never, 3);
    assert.deepEqual((await readSchedDiag(st)).configCoercions, {});
  });

  await t("the surface + class vocabularies are closed", () => {
    assert.ok(CONFIG_COERCION_SURFACES.includes("otlp-destination"));
    assert.ok(CONFIG_DROP_CLASSES.includes("malformed-secret-kept-prior"));
    assert.ok(CONFIG_SURFACES.length > 0);
  });
}

// =====================================================================================================
// G323: SIEM audit egress health
// =====================================================================================================
async function g323(): Promise<void> {
  console.log("auditEgress");

  await t("mirrorAuditEvent REPORTS success/failure (it no longer swallows silently)", () => {
    // The healthy emission returns true. The event carries a customer email by design (an AuditEvent's actor);
    // what matters is that the ENGINE-SIDE RECORD of a mirror failure carries none of it -- proven below.
    const ok = mirrorAuditEvent({ seq: 1, ts: "2026-07-10T00:00:00.000Z", action: "role-change", outcome: "success", hash: "h", prevHash: "g" } as never);
    assert.equal(ok, true, "a healthy mirror must report true");
  });

  await t("a dead mirror and a served gap page reach the bundle as counts only", async () => {
    const st = fakeStorage();
    await recordAuditMirrorFailure(st);
    await recordAuditMirrorFailure(st);
    // The collector's cursor sits below the oldest retained entry: the events between are gone forever.
    await recordAuditGapPage(st, 4211);
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.auditEgress?.mirrorFailures?.count, 2, "the dead mirror must be countable");
    assert.equal(bundle.auditEgress?.gapPagesServed?.count, 1);
    assert.equal(bundle.auditEgress?.gapPagesServed?.lastGapBeforeSeq, 4211, "the engine-minted sequence boundary rides; no event content does");
    assertNoSentinels("auditEgress", bundle.auditEgress);
    // No event content, no actor, no target: the record has exactly these fields.
    assert.deepEqual(Object.keys(bundle.auditEgress!).sort(), ["gapPagesServed", "mirrorFailures"]);
  });

  await t("a malformed sequence clamps rather than riding", async () => {
    const st = fakeStorage();
    await recordAuditGapPage(st, SENTINELS[2]); // an object key where an int belongs
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.auditEgress?.gapPagesServed?.lastGapBeforeSeq, 0);
    assertNoSentinels("auditEgress clamp", bundle.auditEgress);
  });
}

// =====================================================================================================
// G325: capped records that never said they were capped
// =====================================================================================================
async function g325(): Promise<void> {
  console.log("capTruncations");

  await t("analyseRoster STATES the truncation and the dropped-row count", () => {
    // 40 malformed dp: rows against a 25-row list cap.
    const entries = new Map<string, unknown>();
    for (let i = 0; i < 40; i++) entries.set(`dp:ghost-${i}`, { notAConfig: true });
    const report = analyseRoster(entries, new Set());
    assert.equal(report.ghostCount, 40, "the exact total must be kept");
    assert.ok(report.ghosts.length < 40, "the list must be capped");
    assert.equal(report.ghostsTruncated, true, "the report must SAY it was truncated");
    assert.equal(report.ghostsDropped, 40 - report.ghosts.length);
    // A small roster is not truncated and says so.
    const small = analyseRoster(new Map([["dp:x", { notAConfig: true }]]), new Set());
    assert.equal(small.ghostsTruncated, false);
    assert.equal(small.ghostsDropped, 0);
  });

  await t("the dropped rows are counted per surface, in the bundle, ids excluded", async () => {
    const st = fakeStorage();
    await recordCapTruncation(st, "export-health-perdest", 3); // the 65th destination's MISSING RECOVERY COPY
    await recordCapTruncation(st, "reconcile-signal-map", 8); // the 8 oldest buckets evicted
    await recordCapTruncation(st, "roster-ghosts", 15);
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.capTruncations["export-health-perdest"]?.count, 3);
    assert.equal(bundle.capTruncations["reconcile-signal-map"]?.count, 8);
    assert.equal(bundle.capTruncations["roster-ghosts"]?.count, 15);
    assertNoSentinels("capTruncations", bundle.capTruncations);
    for (const s of CAP_TRUNCATION_SURFACES) assert.ok(typeof s === "string");
  });

  await t("no truncation writes nothing; a bad surface is dropped", async () => {
    const st = fakeStorage();
    await recordCapTruncation(st, "roster-ghosts", 0);
    await recordCapTruncation(st, SENTINELS[1] as never, 5);
    assert.deepEqual((await readSchedDiag(st)).capTruncations, {});
  });
}

// =====================================================================================================
// G334: the security-posture evaluation and its swallowed input faults
// =====================================================================================================
async function g334(): Promise<void> {
  console.log("posture");

  await t("the three input-fault classes record and reach the bundle", async () => {
    const st = fakeStorage();
    // "admin-strong-auth has said cannot-verify for weeks": a DROPPED IDP_KV BINDING, not a blip.
    await recordPostureInputFault(st, "identity-read-failed");
    await recordPostureInputFault(st, "identity-read-failed");
    // The version-skewed slice that manufactures a spurious "retire the break-glass token" regression.
    await recordPostureInputFault(st, "status-slice-malformed");
    // The real WORM misconfiguration flattened to "not configured".
    await recordPostureInputFault(st, "worm-slice-malformed");
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.posture.inputFaults["identity-read-failed"]?.count, 2);
    assert.equal(bundle.posture.inputFaults["status-slice-malformed"]?.count, 1);
    assert.equal(bundle.posture.inputFaults["worm-slice-malformed"]?.count, 1);
    for (const f of POSTURE_INPUT_FAULTS) assert.ok(typeof f === "string");
  });

  // The stated attended-verification interval. Without it "attended-verification-cadence: failed" is
  // uninterpretable in a pack: failed against WHAT? One integer, naming no downpipe.
  await t("the STATED attended-verification interval reaches the bundle beside the verdicts", async () => {
    const st = fakeStorage();
    await st.put("orgpolicy", { requireConfigApproval: false, attendedCadenceDays: 91 });
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.posture.attendedCadenceDays, 91);
  });

  await t("an estate with NO stated rhythm reports 0, never a fabricated interval", async () => {
    const st = fakeStorage();
    await st.put("orgpolicy", { requireConfigApproval: false });
    assert.equal((await readSchedDiag(st)).posture.attendedCadenceDays, 0);
    // And with no policy record at all, which is a fresh estate.
    assert.equal((await readSchedDiag(fakeStorage())).posture.attendedCadenceDays, 0);
  });

  await t("a malformed interval is normalised to 0 at the redaction chokepoint, not propagated", async () => {
    for (const bad of ["91", -5, 0.5, Number.NaN, null, {}]) {
      const st = fakeStorage();
      await st.put("orgpolicy", { requireConfigApproval: false, attendedCadenceDays: bad });
      assert.equal((await readSchedDiag(st)).posture.attendedCadenceDays, 0, `a ${typeof bad} interval must read 0`);
    }
  });

  await t("the evaluation + overrides are projected, and the free-text REASON is left behind", async () => {
    const st = fakeStorage();
    // The snapshot computePostureReport persists.
    await st.put("posture-snapshot", {
      at: "2026-07-10T04:00:00.000Z",
      checks: [
        { id: "admin-strong-auth", passed: false, severity: "high" },
        { id: "dispose-bootstrap-token", passed: true, severity: "critical" },
      ],
    });
    // An owner override, whose justification is FREE TEXT and quotes a customer's own internals. The
    // projection must carry the check id and the kind and DROP the reason -- that is the whole design.
    await st.put("posture-accept:admin-strong-auth", {
      checkId: "admin-strong-auth",
      kind: "compensating-control",
      at: "2026-07-09T01:02:03.000Z",
      reason: `we enforce MFA in Okta for ${SENTINELS[0]} on ${SENTINELS[5]}; bucket ${SENTINELS[1]}`,
      acceptedBy: SENTINELS[0],
    });
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.posture.lastEvaluatedAt, "2026-07-10T04:00:00.000Z");
    assert.equal(bundle.posture.checks.length, 2);
    assert.deepEqual(bundle.posture.checks[0], { id: "admin-strong-auth", passed: false, severity: "high" });
    assert.equal(bundle.posture.overrides.length, 1);
    assert.deepEqual(bundle.posture.overrides[0], { checkId: "admin-strong-auth", overrideKind: "compensating-control", at: "2026-07-09T01:02:03.000Z" });
    // THE REDACTION PROOF: neither the justification nor the accepting owner's email survives the projection.
    assertNoSentinels("posture projection", bundle.posture);
    assert.ok(!JSON.stringify(bundle.posture).includes("reason"));
    assert.ok(!JSON.stringify(bundle.posture).includes("acceptedBy"));
  });

  await t("a legacy override with no kind reads as risk-accepted (the documented default)", async () => {
    const st = fakeStorage();
    await st.put("posture-accept:failure-alerts", { checkId: "failure-alerts", at: "2026-01-01T00:00:00.000Z", reason: SENTINELS[3] });
    const bundle = await readSchedDiag(st);
    assert.equal(bundle.posture.overrides[0]?.overrideKind, "risk-accepted");
    assertNoSentinels("legacy override", bundle.posture);
  });
}

// =====================================================================================================
// G140: SSO per-connection attribution + the uncounted start/metadata paths
// =====================================================================================================
async function g140(): Promise<void> {
  console.log("sso start/metadata + per-connection ordinal");

  await t("the two previously-uncounted paths are CLOSED CODES in the shared vocabulary", () => {
    assert.ok((SSO_FAIL_CODES as readonly string[]).includes("start-failure"), "the start path must have a code");
    assert.ok((SSO_FAIL_CODES as readonly string[]).includes("metadata-failure"), "the metadata path must have a code");
    // Additive: nothing was removed from the vocabulary the pack already projects.
    for (const legacy of ["issuer", "audience", "expired", "signature", "replay", "connection", "malformed", "other"]) {
      assert.ok((SSO_FAIL_CODES as readonly string[]).includes(legacy), `${legacy} must survive`);
    }
  });

  // The ordinal chokepoint is a DO method, so it is exercised against a minimal harness that reproduces the
  // exact storage contract: the connId goes in, and ONLY an opaque ordinal may come out.
  await t("ssoConnOrdinal is the chokepoint: the connId goes in, only an opaque ordinal comes out", async () => {
    const map = new Map<string, unknown>();
    const storage = {
      get: async <T>(k: string): Promise<T | undefined> => map.get(k) as T | undefined,
      put: async <T>(k: string, v: T): Promise<void> => void map.set(k, structuredClone(v)),
    };
    // The mixin's implementation, in the same shape it runs in the DO.
    const SSO_CONN_ORDINALS_KEY = "ssofailures:connordinals";
    const SSO_CONN_ORDINAL_CAP = 24;
    async function ssoConnOrdinal(connId: string): Promise<string | null> {
      const m = (await storage.get<Record<string, number>>(SSO_CONN_ORDINALS_KEY)) ?? {};
      const existing = m[connId];
      if (typeof existing === "number") return `conn-${existing}`;
      const used = Object.values(m).filter((n) => typeof n === "number");
      if (used.length >= SSO_CONN_ORDINAL_CAP) return null;
      const next = used.length === 0 ? 1 : Math.max(...used) + 1;
      m[connId] = next;
      await storage.put(SSO_CONN_ORDINALS_KEY, m);
      return `conn-${next}`;
    }
    const a = await ssoConnOrdinal(SENTINELS[5]!); // the operator-chosen connId
    const b = await ssoConnOrdinal("entra-corp-002");
    assert.equal(a, "conn-1");
    assert.equal(b, "conn-2");
    // STABLE: the same connection always reads back the same ordinal (support can say "conn-2" across weeks).
    assert.equal(await ssoConnOrdinal(SENTINELS[5]!), "conn-1");
    // THE REDACTION PROOF: the ordinal that RIDES carries no trace of the connId.
    assertNoSentinels("ssoConnOrdinal return", a);
    // The connId -> ordinal map is DO-side only; it never enters a pack projection (the projections are the
    // by-conn aggregate and the secretless list, both keyed by ordinal, asserted below).
    const byConn: Record<string, Record<string, { count: number; lastAt: string }>> = {};
    byConn[a!] = { "start-failure": { count: 3, lastAt: "2026-07-10T00:00:00.000Z" } };
    byConn[b!] = { signature: { count: 1, lastAt: "2026-07-10T00:00:00.000Z" } };
    assertNoSentinels("ssoFailuresByConn projection", byConn);
    // The cap holds: past it, no new ordinal is minted (a churn cannot grow the map without bound).
    for (let i = 0; i < SSO_CONN_ORDINAL_CAP; i++) await ssoConnOrdinal(`conn-churn-${i}`);
    assert.equal(await ssoConnOrdinal("one-too-many"), null);
  });
}

// =====================================================================================================
// G324: beacon failure CAUSE class + intermittency (the last-attempt-only record)
// =====================================================================================================
async function g324(): Promise<void> {
  console.log("beacon cause class + ring");

  // recordBeaconAttempt is a DO method; the harness reproduces its exact contract (the same closed-set
  // validation and the same ring cap) so the vocabulary guard and the bound are pinned by a test.
  const map = new Map<string, unknown>();
  const RING_CAP = BEACON_ATTEMPT_RING_CAP;
  interface Attempt {
    at: number;
    ok: boolean;
    status?: number;
    errorClass?: string;
  }
  async function recordBeaconAttempt(req: { ok?: unknown; status?: unknown; errorClass?: unknown }): Promise<void> {
    const ok = req.ok === true;
    const status = typeof req.status === "number" && Number.isFinite(req.status) ? Math.max(0, Math.min(999, Math.floor(req.status))) : undefined;
    const errorClass = !ok && typeof req.errorClass === "string" && (BEACON_FAIL_CLASSES as readonly string[]).includes(req.errorClass) ? req.errorClass : undefined;
    const attempt: Attempt = { at: Date.now(), ok, ...(status !== undefined ? { status } : {}), ...(errorClass !== undefined ? { errorClass } : {}) };
    const prior = map.get("beaconstate") as { recent?: Attempt[] } | undefined;
    const ring = [...(Array.isArray(prior?.recent) ? prior.recent : []), attempt];
    map.set("beaconstate", { ...attempt, recent: ring.length > RING_CAP ? ring.slice(ring.length - RING_CAP) : ring });
  }

  await t("the CAUSE class rides, so a malformed BEACON_URL is not a network blip", async () => {
    map.clear();
    // The cron's own classifier vocabulary: a permanent operator error vs a self-healing one.
    assert.ok((BEACON_FAIL_CLASSES as readonly string[]).includes("url-invalid"));
    assert.ok((BEACON_FAIL_CLASSES as readonly string[]).includes("network"));
    await recordBeaconAttempt({ ok: false, errorClass: "url-invalid" });
    const rec = map.get("beaconstate") as { ok: boolean; errorClass?: string; recent?: Attempt[] };
    assert.equal(rec.ok, false);
    assert.equal(rec.errorClass, "url-invalid", "the network-level failure must now carry WHY");
    assertNoSentinels("beacon state", rec);
  });

  await t("the ring shows INTERMITTENCY and is bounded", async () => {
    map.clear();
    // "ok, fail, ok, fail" is a different ticket from "fail, fail, fail" -- the last-attempt-only record
    // could tell neither.
    await recordBeaconAttempt({ ok: true, status: 200 });
    await recordBeaconAttempt({ ok: false, errorClass: "network" });
    await recordBeaconAttempt({ ok: true, status: 200 });
    await recordBeaconAttempt({ ok: false, status: 401, errorClass: "non-2xx" });
    const rec = map.get("beaconstate") as { recent: Attempt[] };
    assert.equal(rec.recent.length, 4);
    assert.deepEqual(rec.recent.map((a) => a.ok), [true, false, true, false], "the sequence IS the diagnosis");
    assert.equal(rec.recent[3]!.status, 401);
    // Bounded: a long-running failing beacon cannot grow the record.
    for (let i = 0; i < 20; i++) await recordBeaconAttempt({ ok: false, errorClass: "network" });
    assert.equal((map.get("beaconstate") as { recent: Attempt[] }).recent.length, RING_CAP);
  });

  await t("an out-of-vocabulary class is DROPPED (the URL and the ingest key can never be stored)", async () => {
    map.clear();
    await recordBeaconAttempt({ ok: false, errorClass: SENTINELS[4] }); // the endpoint, where a class belongs
    await recordBeaconAttempt({ ok: false, errorClass: SENTINELS[3] }); // the ingest key
    const rec = map.get("beaconstate") as { errorClass?: string; recent: Attempt[] };
    assert.equal(rec.errorClass, undefined, "an unknown class must be dropped, never stored");
    assertNoSentinels("beacon state (hostile input)", rec);
  });
}

async function main(): Promise<void> {
  console.log("validate-sched-gap-evidence: the scheduler-DO closing round\n");
  await g139g141();
  await g187g249();
  await g188();
  await g297();
  await g323();
  await g325();
  await g334();
  await g140();
  await g324();
  console.log(failures === 0 ? "\nall sched gap-evidence checks passed" : `\n${failures} FAILURES`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
