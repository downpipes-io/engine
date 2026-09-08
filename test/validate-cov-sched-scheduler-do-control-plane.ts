// validate-cov-sched-scheduler-do-control-plane: a focused branch-coverage proof for the SchedulerDO
// control-plane RECOVERY mixin (src/sched/scheduler-do-control-plane.ts), the layer that builds the
// no-custody signed-export SLICE, latches the silence-killing recovery-required flag, and rebuilds the DO
// from a verified export (the break-glass reconcile + the safe auto-heal resume/authority split).
//
// It drives the REAL DO methods through the shared in-memory harness (no network, no signer needed: the DO
// never touches a key or a bucket, the Worker does). Every assertion checks a real stored/returned/audited
// outcome. The aim is to exercise the optional-field projection branches, the empty/absent fallbacks, the
// role/owner/caller gates, the validation rejections and the idempotency edges that the happy-path suites
// leave uncovered. Australian English; no timestamp or random-dependent assertions.
//
// Run: node test/validate-cov-sched-scheduler-do-control-plane.ts

import { makeScheduler, makeConfig } from "./validate-scheduler-shared.ts";
import { wrapConfigSecret } from "../src/admin/config-secret.ts";
import { roleSubjectKey, rolePendingKey } from "../src/admin/identity.ts";
import { GROUP_ROLE_PREFIX, CUSTOM_ROLE_PREFIX, DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { CONFIG_HISTORY_PREFIX } from "../src/admin/config-history.ts";
import type { ControlPlaneExport, ExportedDestination, ExportedSecret, StagedControlPlane } from "../src/admin/control-plane.ts";
import type { StoredDestination, DestinationCollection } from "../src/sched/scheduler-do-base.ts";

// The ControlPlaneMixin (src/sched/scheduler-do-control-plane.ts) adds these methods to the SchedulerDO at
// runtime, but the composed SchedulerDO *type* does not surface them, so the test reaches them through this
// precise structural view. The signatures mirror the mixin exactly (no widening, no `any`).
interface ControlPlaneMethods {
  exportSecretFor(secret: string | { v: 1; iv: string; ct: string }): ExportedSecret;
  reconciledDestination(d: ExportedDestination): StoredDestination;
  applyResumeDownpipes(exp: ControlPlaneExport, tolerant: boolean): Promise<number>;
  applyResumeDestinations(exp: ControlPlaneExport): Promise<number>;
  clearControlPlaneStaged(): Promise<void>;
}
// cp views a SchedulerDO stub through the mixin's runtime methods declared above. The stub is taken as
// `unknown` so the single assertion needs no double-cast and introduces no `any`.
const cp = (s: unknown): ControlPlaneMethods => s as ControlPlaneMethods;

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A forwarded-caller shape, structurally compatible with the mixin's CallerLike.
type Caller = { method: "token" | "access"; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null };
const tokenWithIp: Caller = { method: "token", email: null, subject: null, groups: [], sourceIp: "203.0.113.7" };
const tokenNoIp: Caller = { method: "token", email: null, subject: null, groups: [] };
const accessCaller: Caller = { method: "access", email: "x@y.example", subject: "subj-x", groups: [] };

const has = (o: unknown, k: string): boolean => typeof o === "object" && o !== null && Object.prototype.hasOwnProperty.call(o, k);
const findDest = (exp: ControlPlaneExport, id: string): ExportedDestination => exp.destinations.find((d) => d.id === id)!;
async function caught(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

async function main(): Promise<void> {
  const wrapKey = crypto.getRandomValues(new Uint8Array(32));
  const wrappedFull = await wrapConfigSecret(wrapKey, "full-principal-secret");
  const wrappedNoDur = await wrapConfigSecret(wrapKey, "nodur-principal-secret");
  const wrappedW = await wrapConfigSecret(wrapKey, "wrap-only-secret");

  // The four destination fixtures span every optional-field branch in the projection + reconcile.
  const destFull: StoredDestination = {
    id: "dest-full", label: "Full", endpoint: "https://s3.example.com", bucket: "b-full", region: "us-east-1",
    accessKeyId: "AKIAFULL", secretAccessKey: wrappedFull, setAt: 1_700_000_000_000, setBy: "owner@x.example",
    verifiedAt: 1_700_000_000_001, deleteProbe: "ok",
    worm: { mode: "compliance", retentionDays: 7 }, objectLock: "enforced",
    assumeRole: { roleArn: "arn:aws:iam::123456789012:role/Backup", externalId: "ext-secret", durationSeconds: 3600 },
    addressing: "path", storageClass: "STANDARD_IA",
    pricing: { storagePerGBMonth: 0.02, classAPerMillion: 4.5, classBPerMillion: 0.36, egressPerGB: 0, currency: "USD", source: "operator" },
  };
  const destPlain: StoredDestination = {
    id: "dest-plain", label: "Plain", endpoint: "https://s3.example.com", bucket: "b-plain", region: "auto",
    accessKeyId: "AKIAPLAIN", secretAccessKey: "plaintext-secret-at-rest", setAt: 1_700_000_000_000, setBy: null,
    verifiedAt: 1_700_000_000_001, deleteProbe: "denied",
  };
  const destNoDur: StoredDestination = {
    id: "dest-nodur", label: "NoDur", endpoint: "https://s3.example.com", bucket: "b-nodur", region: "us-west-2",
    accessKeyId: "AKIANODUR", secretAccessKey: wrappedNoDur, setAt: 1_700_000_000_000, setBy: "owner@x.example",
    verifiedAt: 1_700_000_000_001, deleteProbe: "ok",
    assumeRole: { roleArn: "arn:aws:iam::123456789012:role/NoDur" },
  };
  const destWrapOnly: StoredDestination = {
    id: "dest-wrap", label: "Wrap", endpoint: "https://s3.example.com", bucket: "b-wrap", region: "auto",
    accessKeyId: "AKIAWRAP", secretAccessKey: wrappedW, setAt: 1_700_000_000_000, setBy: null,
    verifiedAt: 1_700_000_000_001, deleteProbe: "ok",
  };

  // ---- (1) exportSecretFor: wrapped envelope vs reestablish marker -------------------------------
  const sched0 = makeScheduler();
  const secWrapped = cp(sched0.stub).exportSecretFor(wrappedFull);
  const secReest = cp(sched0.stub).exportSecretFor("plaintext-secret-at-rest");
  ok("exportSecretFor: a WrappedSecret rides as a wrapped envelope", has(secWrapped, "wrapped") && !has(secWrapped, "reestablish"));
  ok("exportSecretFor: a plaintext-at-rest secret is OMITTED + reestablish", has(secReest, "reestablish") && !has(secReest, "wrapped"));

  // ---- (2) buildControlPlaneExport over a RICH plane (every TRUE projection branch) --------------
  const full = makeScheduler();
  await full.stub.addDownpipe(makeConfig("dp-cp"));
  const fullColl: DestinationCollection = { list: [destFull, destPlain, destNoDur], defaultId: "dest-full" };
  await full.stub.saveDestinations(fullColl);
  // Seed the RBAC tables directly: a bound grant with NO extras, a bound grant WITH expiry + customRole,
  // and two pending invites (one bare, one with expiry + customRole) -> covers both spread branches twice.
  await full.storage.put(roleSubjectKey("subj-a"), { subject: "subj-a", email: "a@x.example", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
  await full.storage.put(roleSubjectKey("subj-b"), { subject: "subj-b", email: "b@x.example", role: "viewer", grantedBy: "a@x.example", grantedAt: "2026-01-02T00:00:00.000Z", expiresAt: "2030-01-01T00:00:00.000Z", customRole: "auditor" });
  await full.storage.put(rolePendingKey("p1@x.example"), { email: "p1@x.example", role: "operator", grantedBy: "a@x.example", grantedAt: "2026-01-03T00:00:00.000Z" });
  await full.storage.put(rolePendingKey("p2@x.example"), { email: "p2@x.example", role: "viewer", grantedBy: "a@x.example", grantedAt: "2026-01-04T00:00:00.000Z", expiresAt: "2030-01-01T00:00:00.000Z", customRole: "auditor" });
  await full.storage.put(`${GROUP_ROLE_PREFIX}engineers`, { group: "engineers", role: "operator", grantedBy: "a@x.example", grantedAt: "2026-01-05T00:00:00.000Z" });
  await full.storage.put(`${CUSTOM_ROLE_PREFIX}auditor`, { name: "auditor", label: "Auditor", capabilities: ["audit.read"], surface: {}, presentation: "full", landing: "/audit", createdBy: "a@x.example", createdAt: "2026-01-06T00:00:00.000Z" });
  await full.storage.put(DISCOVERY_KEY, { token: "cfat_secret_discovery_token_value", setAt: 5, setBy: "owner@x.example", accountsSeen: [{ id: "acct-1", name: "Acct One" }], selected: ["acct-1"], engineAccountId: "acct-1" });
  await full.storage.put(`${CONFIG_HISTORY_PREFIX}0000000007`, { id: 7, contentHash: "sha384:rich-head-hash" });
  await full.stub.writeOrgPolicy({ requireConfigApproval: true, requireChangeNumber: true, breakGlassTokenRetired: true });

  const fullExport = await full.stub.buildControlPlaneExport();
  ok("export: the downpipe config is carried", fullExport.downpipes.some((c) => (c as { id: string }).id === "dp-cp"));
  ok("export: three destinations are projected", fullExport.destinations.length === 3);
  const eFull = findDest(fullExport, "dest-full");
  ok("project: a wrapped dest secret rides as a wrapped envelope", has(eFull.secret, "wrapped"));
  ok("project: worm/objectLock/addressing/storageClass/pricing all carried", eFull.worm !== undefined && eFull.objectLock === "enforced" && eFull.addressing === "path" && eFull.storageClass === "STANDARD_IA" && eFull.pricing !== undefined);
  ok("project: assumeRole carries roleArn + durationSeconds + externalIdReestablish, drops externalId", eFull.assumeRole?.roleArn === "arn:aws:iam::123456789012:role/Backup" && eFull.assumeRole?.durationSeconds === 3600 && eFull.assumeRole?.externalIdReestablish === true && !has(eFull.assumeRole, "externalId"));
  const ePlain = findDest(fullExport, "dest-plain");
  ok("project: a plaintext-at-rest secret is omitted + reestablish", has(ePlain.secret, "reestablish"));
  ok("project: a bare destination omits every optional field", ePlain.worm === undefined && ePlain.objectLock === undefined && ePlain.assumeRole === undefined && ePlain.addressing === undefined && ePlain.storageClass === undefined && ePlain.pricing === undefined);
  const eNoDur = findDest(fullExport, "dest-nodur");
  ok("project: an assumeRole without durationSeconds omits it", eNoDur.assumeRole?.roleArn === "arn:aws:iam::123456789012:role/NoDur" && eNoDur.assumeRole?.durationSeconds === undefined);
  ok("export: defaultDestinationId is carried when there are destinations", fullExport.defaultDestinationId === "dest-full");

  const boundA = fullExport.roles.find((r) => r.subject === "subj-a")!;
  const boundB = fullExport.roles.find((r) => r.subject === "subj-b")!;
  const pend1 = fullExport.roles.find((r) => r.subject === "" && r.email === "p1@x.example")!;
  const pend2 = fullExport.roles.find((r) => r.subject === "" && r.email === "p2@x.example")!;
  ok("export: a bare bound grant omits expiresAt + customRole", boundA !== undefined && boundA.expiresAt === undefined && boundA.customRole === undefined);
  ok("export: a bound grant with extras carries expiresAt + customRole", boundB?.expiresAt === "2030-01-01T00:00:00.000Z" && boundB?.customRole === "auditor");
  ok("export: a bare pending invite (subject '') omits the extras", pend1 !== undefined && pend1.expiresAt === undefined && pend1.customRole === undefined);
  ok("export: a pending invite with extras carries them", pend2?.expiresAt === "2030-01-01T00:00:00.000Z" && pend2?.customRole === "auditor");
  ok("export: group roles + custom roles are carried", fullExport.groupRoles.length === 1 && fullExport.customRoles.length === 1);
  ok("export: discovery is carried no-custody (tokenReestablish, no token, engineAccountId)", fullExport.discovery !== null && fullExport.discovery.tokenReestablish === true && fullExport.discovery.engineAccountId === "acct-1" && !has(fullExport.discovery, "token"));
  ok("export: configVersion + configContentHash come from the head version", fullExport.configVersion === 7 && fullExport.configContentHash === "sha384:rich-head-hash");
  ok("export: engineAccountId comes from discovery", fullExport.engineAccountId === "acct-1");
  ok("export: orgPolicy carries requireConfigApproval + requireChangeNumber + breakGlassTokenRetired", fullExport.orgPolicy.requireConfigApproval === true && fullExport.orgPolicy.requireChangeNumber === true && fullExport.orgPolicy.breakGlassTokenRetired === true);
  ok("export: reestablish lists destination-credentials + discovery-token + the always-required categories", fullExport.reestablish.includes("destination-credentials") && fullExport.reestablish.includes("discovery-token") && fullExport.reestablish.includes("idp-secrets") && fullExport.reestablish.includes("session-keys"));

  // ---- (3) buildControlPlaneExport over an EMPTY plane (every FALSE/absent fallback) -------------
  const empty = makeScheduler();
  const emptyExport = await empty.stub.buildControlPlaneExport();
  ok("export(empty): discovery is null", emptyExport.discovery === null);
  ok("export(empty): no destinations => defaultDestinationId null", emptyExport.destinations.length === 0 && emptyExport.defaultDestinationId === null);
  ok("export(empty): no head version => configVersion 0 + genesis hash", emptyExport.configVersion === 0 && emptyExport.configContentHash.startsWith("sha384:"));
  ok("export(empty): engineAccountId null when no discovery", emptyExport.engineAccountId === null);
  ok("export(empty): orgPolicy default (no approval, no optional flags)", emptyExport.orgPolicy.requireConfigApproval === false && emptyExport.orgPolicy.requireChangeNumber === undefined && emptyExport.orgPolicy.breakGlassTokenRetired === undefined);
  ok("export(empty): reestablish omits destination-credentials + discovery-token", !emptyExport.reestablish.includes("destination-credentials") && !emptyExport.reestablish.includes("discovery-token"));
  ok("export(empty): roles empty", emptyExport.roles.length === 0);

  // ---- (4) the reestablish-needed predicate edges (left-true / both-false) -----------------------
  const reestFirst = makeScheduler();
  await reestFirst.stub.saveDestinations({ list: [destPlain], defaultId: "dest-plain" });
  const reestExport = await reestFirst.stub.buildControlPlaneExport();
  ok("predicate: a reestablish destination triggers destination-credentials", reestExport.reestablish.includes("destination-credentials"));
  const wrapOnly = makeScheduler();
  await wrapOnly.stub.saveDestinations({ list: [destWrapOnly], defaultId: "dest-wrap" });
  const wrapExport = await wrapOnly.stub.buildControlPlaneExport();
  ok("predicate: a fully-wrapped no-assumeRole destination does NOT trigger destination-credentials", !wrapExport.reestablish.includes("destination-credentials") && wrapExport.defaultDestinationId === "dest-wrap");

  // ---- (5) reconciledDestination: rebuild a StoredDestination from each exported variant ----------
  const rd = makeScheduler();
  const rdFull = cp(rd.stub).reconciledDestination(eFull);
  ok("reconciledDest(full): wrapped secret restored as an envelope, all optional fields restored", typeof rdFull.secretAccessKey === "object" && (rdFull.secretAccessKey as { v?: number }).v === 1 && rdFull.worm !== undefined && rdFull.objectLock === "enforced" && rdFull.assumeRole?.durationSeconds === 3600 && rdFull.addressing === "path" && rdFull.storageClass === "STANDARD_IA" && rdFull.pricing !== undefined);
  const rdPlain = cp(rd.stub).reconciledDestination(ePlain);
  ok("reconciledDest(plain): omitted secret becomes '' (loud-fail), no optional fields", rdPlain.secretAccessKey === "" && rdPlain.worm === undefined && rdPlain.objectLock === undefined && rdPlain.assumeRole === undefined && rdPlain.addressing === undefined && rdPlain.storageClass === undefined && rdPlain.pricing === undefined);
  const rdNoDur = cp(rd.stub).reconciledDestination(eNoDur);
  ok("reconciledDest(nodur): assumeRole restored without durationSeconds", rdNoDur.assumeRole?.roleArn === "arn:aws:iam::123456789012:role/NoDur" && rdNoDur.assumeRole?.durationSeconds === undefined);

  // ---- (6) the export-state change-gate pointer + the engine-driven audit row --------------------
  const es = makeScheduler();
  ok("export-state: absent reads null", (await es.stub.getControlPlaneExportState()) === null);
  await es.stub.setControlPlaneExportState({ configVersion: 7, configContentHash: "sha384:h", exportedAt: "2026-01-01T00:00:00.000Z" });
  const esGot = await es.stub.getControlPlaneExportState();
  ok("export-state: round-trips the recorded pointer", esGot !== null && esGot.configVersion === 7 && esGot.configContentHash === "sha384:h");
  await es.stub.recordControlPlaneExported(7);
  const esAudit = await es.stub.listAuditEntries();
  ok("export-state: recordControlPlaneExported appends a who-less control-plane-exported audit", esAudit.some((e) => e.action === "control-plane-exported" && e.outcome === "success" && e.actorMethod === "engine"));

  // ---- (7) the silence-killer latch: set (loud first transition), idempotent, clear -------------
  const latch = makeScheduler();
  const def = await latch.stub.getControlPlaneRecoveryRequired();
  ok("latch: default is not-required with a null reason", def.required === false && def.reason === null);
  await latch.stub.setControlPlaneRecoveryRequired("config empty but the bucket has runs");
  const set1 = await latch.stub.getControlPlaneRecoveryRequired();
  ok("latch: set latches required + records the reason", set1.required === true && set1.reason === "config empty but the bucket has runs");
  const empties1 = (await latch.stub.listAuditEntries()).filter((e) => e.action === "control-plane-empty").length;
  await latch.stub.setControlPlaneRecoveryRequired("a second detection");
  const empties2 = (await latch.stub.listAuditEntries()).filter((e) => e.action === "control-plane-empty").length;
  ok("latch: the critical control-plane-empty audit fires ONCE (idempotent on re-set)", empties1 === 1 && empties2 === 1);
  await latch.stub.clearControlPlaneRecoveryRequired();
  ok("latch: clear releases the latch", (await latch.stub.getControlPlaneRecoveryRequired()).required === false);

  // ---- (8) controlPlaneIsEmpty across the three states ------------------------------------------
  ok("empty: a brand-new plane is empty", (await makeScheduler().stub.controlPlaneIsEmpty()) === true);
  const withDp = makeScheduler();
  await withDp.stub.addDownpipe(makeConfig("dp-x"));
  ok("empty: a plane with a downpipe is NOT empty", (await withDp.stub.controlPlaneIsEmpty()) === false);
  const withDest = makeScheduler();
  await withDest.stub.saveDestinations({ list: [destWrapOnly], defaultId: "dest-wrap" });
  ok("empty: a plane with only a destination is NOT empty", (await withDest.stub.controlPlaneIsEmpty()) === false);

  // ---- (9) applyResumeDownpipes: tolerant skip vs strict throw ----------------------------------
  const dpTol = makeScheduler();
  const badConfig = { ...makeConfig("dp-bad"), id: "" }; // an empty id fails validateConfig
  const tolCount = await cp(dpTol.stub).applyResumeDownpipes({ downpipes: [makeConfig("dp-good"), badConfig] } as unknown as ControlPlaneExport, true);
  ok("resume-dp(tolerant): a malformed config is skipped, the good one applies", tolCount === 1 && (await dpTol.stub.listDownpipes()).some((s) => s.config.id === "dp-good"));
  const dpStrict = makeScheduler();
  ok("resume-dp(strict): a malformed config throws", await caught(() => cp(dpStrict.stub).applyResumeDownpipes({ downpipes: [badConfig] } as unknown as ControlPlaneExport, false)));

  // ---- (10) applyResumeDestinations: default-id fallback to list[0], then to '' on empty ---------
  const adNoMatch = makeScheduler();
  const nNoMatch = await cp(adNoMatch.stub).applyResumeDestinations({ destinations: [ePlain], defaultDestinationId: "not-a-real-id" } as unknown as ControlPlaneExport);
  ok("resume-dest: an unmatched defaultId falls back to the first entry", nNoMatch === 1 && (await adNoMatch.stub.loadDestinations()).defaultId === "dest-plain");
  const adEmpty = makeScheduler();
  const nEmpty = await cp(adEmpty.stub).applyResumeDestinations({ destinations: [], defaultDestinationId: "x" } as unknown as ControlPlaneExport);
  ok("resume-dest: an empty list yields a count of 0 and an empty defaultId", nEmpty === 0 && (await adEmpty.stub.loadDestinations()).defaultId === "");

  // ---- (11) reconcileControlPlane: caller gates + empty/authority gates + full rebuild ------------
  const rc = makeScheduler();
  ok("reconcile: a null caller is refused", await caught(() => rc.stub.reconcileControlPlane(fullExport, null)));
  ok("reconcile: a non-token (Access) caller is refused", await caught(() => rc.stub.reconcileControlPlane(fullExport, accessCaller)));
  const recon = await rc.stub.reconcileControlPlane(fullExport, tokenWithIp);
  ok("reconcile: the break-glass rebuild returns the restored counts", recon.ok === true && recon.downpipes === 1 && recon.destinations === 3 && recon.roles >= 1);
  ok("reconcile: it bridges from the export's prior audit head", recon.bridgedFrom.headHash === fullExport.priorAuditHead.headHash);
  ok("reconcile: the downpipe reappears", (await rc.stub.listDownpipes()).some((s) => s.config.id === "dp-cp"));
  ok("reconcile: the wrapped destination secret is restored as an envelope", typeof (await rc.stub.getDestConfigById("dest-full"))?.secretAccessKey === "object");
  ok("reconcile: bootstrapConsumed is re-armed", (await rc.stub.getBootstrapConsumed()) === true);
  ok("reconcile: the recovery latch is cleared", (await rc.stub.getControlPlaneRecoveryRequired()).required === false);
  ok("reconcile: the RBAC authority is restored (role table not empty)", (await rc.stub.roleTableIsEmpty()) === false);
  const rcAudit = await rc.stub.listAuditEntries();
  ok("reconcile: a control-plane-reconciled BRIDGE event is written with the caller's source ip", rcAudit.some((e) => e.action === "control-plane-reconciled" && e.outcome === "success" && e.sourceIp === "203.0.113.7"));
  ok("reconcile: a non-empty plane is refused (no force overwrite)", await caught(() => rc.stub.reconcileControlPlane(fullExport, tokenWithIp)));

  // ---- (12) reconcile of the EMPTY export (no-discovery + no-optional-orgPolicy arm) -------------
  const rcEmpty = makeScheduler();
  const reconE = await rcEmpty.stub.reconcileControlPlane(emptyExport, tokenNoIp);
  ok("reconcile(empty export): applies nothing, still ok, bridge written with null source ip", reconE.ok === true && reconE.downpipes === 0 && reconE.destinations === 0 && reconE.roles === 0);
  ok("reconcile(empty export): no discovery restored (the discovery key stays absent)", (await rcEmpty.storage.get(DISCOVERY_KEY)) === undefined);
  const rcEAudit = await rcEmpty.stub.listAuditEntries();
  ok("reconcile(empty export): the bridge event carries a null source ip", rcEAudit.some((e) => e.action === "control-plane-reconciled" && e.sourceIp === null));

  // ---- (13) the staged-record store: stage / refused / clear -------------------------------------
  const staged: StagedControlPlane = { export: fullExport, signature: "verified-by-the-worker-not-the-do", sourceKey: "_RECOVERY/CONTROL-PLANE/000000000007-x.json", version: 7, stagedAt: "2026-01-01T00:00:00.000Z", resumeApplied: false };
  const rec = makeScheduler();
  ok("staged: absent reads null", (await rec.stub.getControlPlaneRecoveryRecord()) === null);
  await rec.stub.stageControlPlaneRecovery(staged);
  const recGot = await rec.stub.getControlPlaneRecoveryRecord();
  ok("staged: a staged export round-trips", recGot !== null && recGot.staged !== undefined && recGot.staged.version === 7);
  await rec.stub.recordControlPlaneRecoveryRefused("the auto-heal found nothing safe to apply");
  const recRef = await rec.stub.getControlPlaneRecoveryRecord();
  ok("staged: a refusal replaces the staged export", recRef !== null && recRef.staged === undefined && recRef.refused?.reason === "the auto-heal found nothing safe to apply");
  await cp(rec.stub).clearControlPlaneStaged();
  ok("staged: clear drops the record", (await rec.stub.getControlPlaneRecoveryRecord()) === null);

  // ---- (14) applyControlPlaneResumeSlice: the three refusals + the no-authority happy path -------
  const rsNoLatch = makeScheduler();
  const rsNL = await rsNoLatch.stub.applyControlPlaneResumeSlice();
  ok("resume-slice: refused when no recovery latch is set", rsNL.ok === false && rsNL.reason.includes("no recovery"));
  const rsNoStaged = makeScheduler();
  await rsNoStaged.stub.setControlPlaneRecoveryRequired("amnesia");
  const rsNS = await rsNoStaged.stub.applyControlPlaneResumeSlice();
  ok("resume-slice: refused when latched but nothing is staged", rsNS.ok === false && rsNS.reason.includes("no staged"));
  const rsRefused = makeScheduler();
  await rsRefused.stub.setControlPlaneRecoveryRequired("amnesia");
  await rsRefused.stub.recordControlPlaneRecoveryRefused("stepped back to manual");
  const rsR = await rsRefused.stub.applyControlPlaneResumeSlice();
  ok("resume-slice: refused when the record holds a refusal (no staged export)", rsR.ok === false && rsR.reason.includes("no staged"));

  const ah = makeScheduler();
  await ah.stub.setControlPlaneRecoveryRequired("amnesia detected");
  await ah.stub.stageControlPlaneRecovery(staged);
  const resumed = await ah.stub.applyControlPlaneResumeSlice();
  ok("resume-slice: applies the no-authority slice (backups resume)", resumed.ok === true && (resumed as { downpipes: number }).downpipes === 1);
  ok("resume-slice INVARIANT: no RBAC restored, latch still set", (await ah.stub.roleTableIsEmpty()) === true && (await ah.stub.getControlPlaneRecoveryRequired()).required === true);
  ok("resume-slice: a control-plane-resumed audit is written", (await ah.stub.listAuditEntries()).some((e) => e.action === "control-plane-resumed" && e.outcome === "success"));
  const resumed2 = await ah.stub.applyControlPlaneResumeSlice();
  ok("resume-slice: idempotent (a re-run is still ok, still no authority)", resumed2.ok === true && (await ah.stub.roleTableIsEmpty()) === true);

  // ---- (15) applyControlPlaneAuthoritySlice: caller/latch/staged/clobber gates + happy path ------
  ok("authority: a null caller is refused", await caught(() => ah.stub.applyControlPlaneAuthoritySlice(null)));
  ok("authority: a non-token (Access) caller is refused", await caught(() => ah.stub.applyControlPlaneAuthoritySlice(accessCaller)));
  const asNoLatch = makeScheduler();
  ok("authority: refused when no recovery latch is set", await caught(() => asNoLatch.stub.applyControlPlaneAuthoritySlice(tokenNoIp)));
  const asNoStaged = makeScheduler();
  await asNoStaged.stub.setControlPlaneRecoveryRequired("amnesia");
  ok("authority: refused when latched but nothing is staged", await caught(() => asNoStaged.stub.applyControlPlaneAuthoritySlice(tokenNoIp)));
  const asRefused = makeScheduler();
  await asRefused.stub.setControlPlaneRecoveryRequired("amnesia");
  await asRefused.stub.recordControlPlaneRecoveryRefused("manual");
  ok("authority: refused when the record holds a refusal", await caught(() => asRefused.stub.applyControlPlaneAuthoritySlice(tokenNoIp)));
  const asClobber = makeScheduler();
  await asClobber.stub.setControlPlaneRecoveryRequired("amnesia");
  await asClobber.stub.stageControlPlaneRecovery(staged);
  await asClobber.storage.put(roleSubjectKey("subj-live"), { subject: "subj-live", email: "live@x.example", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
  ok("authority: refused when the role table is NON-empty (never clobbers live authority)", await caught(() => asClobber.stub.applyControlPlaneAuthoritySlice(tokenNoIp)));

  // The break-glass confirm on the resumed (latched, staged, empty-role-table) plane succeeds.
  const authority = await ah.stub.applyControlPlaneAuthoritySlice(tokenNoIp);
  ok("authority: the break-glass restores RBAC", authority.ok === true && authority.roles >= 1 && authority.bridgedFrom.headHash === fullExport.priorAuditHead.headHash);
  ok("authority: the latch is cleared + bootstrap re-armed", (await ah.stub.getControlPlaneRecoveryRequired()).required === false && (await ah.stub.getBootstrapConsumed()) === true);
  ok("authority: the staged record is consumed", (await ah.stub.getControlPlaneRecoveryRecord()) === null);
  ok("authority: a control-plane-reconciled BRIDGE event is written with a null source ip", (await ah.stub.listAuditEntries()).some((e) => e.action === "control-plane-reconciled" && e.sourceIp === null));

  // ---- (16) acknowledgeControlPlaneRecovery: the narrow latch-clear for a plane that has organically
  // un-emptied -- clears ONLY the latch when the plane has organically un-emptied
  // (role table non-empty) under an active latch, and never when there is no owner on record to ask.
  ok("acknowledge: a null caller is refused", await caught(() => rc.stub.acknowledgeControlPlaneRecovery(null)));
  ok("acknowledge: the bare break-glass token is refused (an owner already exists to ask)", await caught(() => rc.stub.acknowledgeControlPlaneRecovery(tokenNoIp)));
  const ackNoLatch = makeScheduler();
  await ackNoLatch.storage.put(roleSubjectKey("subj-ack"), { subject: "subj-ack", email: "ack@x.example", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
  ok("acknowledge: refused when no recovery is in effect (nothing to acknowledge)", await caught(() => ackNoLatch.stub.acknowledgeControlPlaneRecovery(accessCaller)));
  const ackEmptyRoles = makeScheduler();
  await ackEmptyRoles.stub.setControlPlaneRecoveryRequired("amnesia");
  ok(
    "acknowledge: refused over an EMPTY role table (never trades the visible latch for a silent deadlock)",
    await caught(() => ackEmptyRoles.stub.acknowledgeControlPlaneRecovery(accessCaller)),
  );
  ok("acknowledge: the empty-role-table refusal leaves the latch untouched (still set)", (await ackEmptyRoles.stub.getControlPlaneRecoveryRequired()).required === true);
  const ackHappy = makeScheduler();
  await ackHappy.storage.put(roleSubjectKey("subj-ack2"), { subject: "subj-ack2", email: "ack2@x.example", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
  await ackHappy.stub.setControlPlaneRecoveryRequired("organic resume: break-glass activity kept the plane alive under the latch");
  const bootstrapBefore = await ackHappy.stub.getBootstrapConsumed();
  const ack = await ackHappy.stub.acknowledgeControlPlaneRecovery(accessCaller);
  ok("acknowledge: returns ok/acknowledged", ack.ok === true && ack.acknowledged === true);
  ok("acknowledge: clears the latch", (await ackHappy.stub.getControlPlaneRecoveryRequired()).required === false);
  ok("acknowledge: NEVER touches bootstrapConsumed (never re-arms it)", (await ackHappy.stub.getBootstrapConsumed()) === bootstrapBefore);
  ok("acknowledge: no downpipe/destination is imported (it grants no config, only clears the flag)", (await ackHappy.stub.listDownpipes()).length === 0);
  const ackAudit = await ackHappy.stub.listAuditEntries();
  ok(
    "acknowledge: writes a DISTINCT control-plane-recovery-acknowledged audit event (never control-plane-reconciled)",
    ackAudit.some((e) => e.action === "control-plane-recovery-acknowledged" && e.outcome === "success") && !ackAudit.some((e) => e.action === "control-plane-reconciled"),
  );
  ok("acknowledge: idempotent refusal -- a second call with nothing latched is refused, not silently ok", await caught(() => ackHappy.stub.acknowledgeControlPlaneRecovery(accessCaller)));

  // ---- (17) armAuthorityOrgPolicy: the retire latch is the DO's OWN authority, never the import's -------
  // regression: a reconcile/apply-staged driven by an export captured BEFORE the Owner retired the
  // break-glass token must never un-retire it -- only the owner-gated setBreakGlassTokenRetired may flip
  // this latch. Prove the DO's CURRENT value survives a reconcile whose export disagrees, both directions.
  const retTrue = makeScheduler();
  await retTrue.stub.writeOrgPolicy({ breakGlassTokenRetired: true }); // the DO's own state: retired
  const exportSaysFalse: ControlPlaneExport = { ...fullExport, orgPolicy: { ...fullExport.orgPolicy, breakGlassTokenRetired: false } };
  await retTrue.stub.reconcileControlPlane(exportSaysFalse, tokenWithIp);
  ok("armAuthorityOrgPolicy: a currently-retired DO stays retired even when the import claims false", (await retTrue.stub.getBreakGlassTokenRetired()) === true);
  const retFalse = makeScheduler();
  // the DO's own state is the untouched default (not retired); fullExport.orgPolicy.breakGlassTokenRetired
  // is true (seeded in step (2)) -- the import must not retire it either: only the DO's own prior state rides.
  await retFalse.stub.reconcileControlPlane(fullExport, tokenNoIp);
  ok("armAuthorityOrgPolicy: a not-yet-retired DO is unaffected by an import claiming true", (await retFalse.stub.getBreakGlassTokenRetired()) === false);

  console.log(failures === 0 ? "\nCONTROL-PLANE COVERAGE VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
