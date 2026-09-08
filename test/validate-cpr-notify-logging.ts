// Prove the Phase-3 CPR + NOTIFICATIONS "needs-new-logging" signals: the durable, closed-vocabulary
// diagnostic records the engine now writes so the support pack can diagnose audit / control-plane /
// recovery + notification-delivery failures. Server-side, in-memory doubles only. Run:
//   node test/validate-cpr-notify-logging.ts
//
// INVARIANTS asserted throughout: every new signal is a CLOSED enum / int / flag / clamped timestamp
// (no raw operator text, no PII, no secret). Sealed-archive bytes + the signing format are untouched.

import { makeScheduler, makeConfig, stubFetch } from "./validate-scheduler-shared.ts";
import type { ControlPlaneExport, StagedControlPlane } from "../src/admin/control-plane.ts";
import { controlPlaneDestCredFingerprint } from "../src/admin/control-plane.ts";
import { auditKey } from "../src/admin/audit.ts";
import { AUDIT_ROLLOVER_KEY, ALERT_COOLDOWN_PREFIX, REPL_ALERT_COOLDOWN_PREFIX } from "../src/sched/scheduler-do-base.ts";
import { classifyHttpDeliveryStatus, sanitiseEmailPlatformCode, screenSinkHost, DELIVERY_FAIL_CODES, SINK_SCREEN_VERDICTS } from "../src/notify.ts";
import { deliver as deliverWebhook } from "../src/notify/channels/webhook.ts";
import { deliver as deliverEmailChannel } from "../src/notify/channels/email.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify.ts";
import type { Env } from "../src/env.d.ts";

type AuditDraftLike = Parameters<ReturnType<typeof makeScheduler>["stub"]["appendAudit"]>[0];
const engineDraft: AuditDraftLike = { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "role-change", outcome: "success", target: { kind: "access-policy" } };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- audit / control-plane / recovery -------------------------------------------------------------
async function controlPlaneAmnesiaProbe(): Promise<void> {
  console.log("\n# CPR: amnesia-probe (the recovery latch's own blind spots)");
  const A = makeScheduler();
  // No probe recorded yet.
  ok("amnesia-probe: absent before any detection attempt", (await A.stub.getControlPlaneAmnesiaProbe()) === null);
  // Each closed class round-trips.
  for (const cls of ["not-empty", "runs-present", "runlog-absent", "probe-error", "no-resolvable-dest"] as const) {
    await A.stub.recordControlPlaneAmnesiaProbe(cls);
    const rec = await A.stub.getControlPlaneAmnesiaProbe();
    ok(`amnesia-probe: class '${cls}' round-trips with a timestamp`, rec?.probe === cls && typeof rec?.at === "string");
  }
  // The recovery-status route surfaces the probe (the pack reads it here).
  await A.stub.recordControlPlaneAmnesiaProbe("no-resolvable-dest");
  const st = (await (await stubFetch(A.stub, "GET", "/control-plane/recovery-status")).json()) as { amnesiaProbe?: { probe?: string } };
  ok("amnesia-probe: surfaced on /control-plane/recovery-status", st.amnesiaProbe?.probe === "no-resolvable-dest");
  // Defence in depth: an out-of-vocabulary probe class is REFUSED by the route (never propagated).
  const bad = await stubFetch(A.stub, "POST", "/control-plane/amnesia-probe", { probe: "id=secret-123" });
  ok("amnesia-probe: an unknown probe class is refused (400)", bad.status === 400);
}

async function controlPlaneDeployObservation(): Promise<void> {
  console.log("\n# CPR: deterministic per-tick deploy-identity observation");
  const A = makeScheduler();
  ok("deploy-obs: absent before any tick", (await A.stub.getControlPlaneDeployObservation()) === null);
  // First observation = BASELINE (records no change; the first tick is never a deploy).
  const first = await A.stub.recordControlPlaneDeployObservation({ engineVersion: "1.0.0", cfVersionId: "cf-aaa" });
  ok("deploy-obs: first observation is the baseline (no change)", first.baseline === true && first.changed === false);
  const o1 = await A.stub.getControlPlaneDeployObservation();
  ok("deploy-obs: baseline established, changesObserved=0", o1?.baselineEstablished === true && o1?.changesObserved === 0 && o1?.cfVersionIdAbsent === false);
  // Same identity again = NO change.
  const same = await A.stub.recordControlPlaneDeployObservation({ engineVersion: "1.0.0", cfVersionId: "cf-aaa" });
  ok("deploy-obs: unchanged identity records no change", same.changed === false);
  // A NEW cf deploy id (same software) = a redeploy (change) -- the owner-#1 signal.
  const redeploy = await A.stub.recordControlPlaneDeployObservation({ engineVersion: "1.0.0", cfVersionId: "cf-bbb" });
  const o2 = await A.stub.getControlPlaneDeployObservation();
  ok("deploy-obs: a same-software redeploy (new cf id) is a CHANGE", redeploy.changed === true && o2?.changesObserved === 1 && typeof o2?.lastChangeAt === "string");
  // cfVersionId ABSENT (env-fallback/local) is flagged; a software-version change is still observed.
  const B = makeScheduler();
  await B.stub.recordControlPlaneDeployObservation({ engineVersion: "1.0.0" });
  const softChange = await B.stub.recordControlPlaneDeployObservation({ engineVersion: "1.0.1" });
  const ob = await B.stub.getControlPlaneDeployObservation();
  ok("deploy-obs: cfVersionIdAbsent flagged when no cf id, engine-version change still seen", ob?.cfVersionIdAbsent === true && softChange.changed === true);
  // Surfaced on recovery-status.
  const st = (await (await stubFetch(A.stub, "GET", "/control-plane/recovery-status")).json()) as { deploy?: { changesObserved?: number } };
  ok("deploy-obs: surfaced on /control-plane/recovery-status", (st.deploy?.changesObserved ?? -1) >= 1);
}

async function controlPlaneExportHealth(): Promise<void> {
  console.log("\n# CPR: export-pass health (skip reason + per-dest write outcome)");
  const A = makeScheduler();
  ok("export-health: absent before any export pass", (await A.stub.getControlPlaneExportHealth()) === null);
  await A.stub.recordControlPlaneExportHealth({ at: new Date().toISOString(), skipped: "budget-yield", wroteAny: false, perDest: [] });
  const skipped = await A.stub.getControlPlaneExportHealth();
  ok("export-health: budget-yield skip recorded (stale generation explained)", skipped?.skipped === "budget-yield" && skipped?.wroteAny === false);
  await A.stub.recordControlPlaneExportHealth({ at: new Date().toISOString(), wroteAny: true, configVersion: 7, perDest: [{ id: "d1", ok: true }, { id: "d2", ok: false }] });
  const wrote = await A.stub.getControlPlaneExportHealth();
  ok("export-health: per-destination write outcome recorded (one dest rejected the artefact)", wrote?.perDest?.length === 2 && wrote.perDest.some((d) => d.id === "d2" && d.ok === false));
  // The per-dest array is bounded (defence in depth against an oversized caller).
  await A.stub.recordControlPlaneExportHealth({ at: new Date().toISOString(), wroteAny: true, perDest: Array.from({ length: 200 }, (_, i) => ({ id: `d${i}`, ok: true })) });
  const bounded = await A.stub.getControlPlaneExportHealth();
  ok("export-health: per-dest array is clamped to <=64", (bounded?.perDest?.length ?? 999) <= 64);
}

async function controlPlaneCredGate(): Promise<void> {
  console.log("\n# CPR: export change-gate keyed on the dest-credential fingerprint");
  const A = makeScheduler();
  const exp = (await A.stub.buildControlPlaneExport()) as ControlPlaneExport;
  const fp1 = await controlPlaneDestCredFingerprint(exp);
  ok("cred-gate: fingerprint is a sha384 hex", /^sha384:[0-9a-f]{96}$/.test(fp1));
  // A rotated credential (a new wrapped envelope) changes the fingerprint; unchanged material is stable.
  const exp2: ControlPlaneExport = JSON.parse(JSON.stringify(exp));
  exp2.destinations = [{ id: "d1", label: "d", endpoint: "https://s3.example.com", bucket: "b", region: "auto", accessKeyId: "AK", secret: { wrapped: { v: 1, iv: "aaa", ct: "bbb" } }, setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }];
  const fpA = await controlPlaneDestCredFingerprint(exp2);
  const exp3: ControlPlaneExport = JSON.parse(JSON.stringify(exp2));
  (exp3.destinations[0]!.secret as { wrapped: { ct: string } }).wrapped.ct = "ROTATED-ct";
  const fpB = await controlPlaneDestCredFingerprint(exp3);
  ok("cred-gate: a rotated credential changes the fingerprint (export re-fires)", fpA !== fpB);
  ok("cred-gate: identical material yields a stable fingerprint", (await controlPlaneDestCredFingerprint(exp2)) === fpA);
  // The fingerprint carries no plaintext (only the wrapped/omitted envelope material).
  ok("cred-gate: fingerprint input carries no plaintext secret", !fpA.includes("secret"));
}

async function controlPlaneRefusalCode(): Promise<void> {
  console.log("\n# CPR: auto-heal refusal CODE (redaction-safe classifier)");
  const A = makeScheduler();
  await A.stub.recordControlPlaneRecoveryRefused("the latest recovery export failed signature verification", "signature");
  const rec = await A.stub.getControlPlaneRecoveryRecord();
  ok("refusal-code: closed code stored alongside the free-text reason", rec?.refused?.code === "signature" && typeof rec?.refused?.reason === "string");
  // The DO route surfaces the closed refusedCode top-level; the support pack projects the free-text
  // `refused` object down to a bare boolean (asserted in the support-bundle projection test below).
  const st = (await (await stubFetch(A.stub, "GET", "/control-plane/recovery-status")).json()) as { refused?: unknown; refusedCode?: string };
  ok("refusal-code: recovery-status surfaces the closed refusedCode", st.refusedCode === "signature" && st.refused != null);
}

async function controlPlaneResumeSkip(): Promise<void> {
  console.log("\n# CPR: resume applied-vs-expected skip + applied generation");
  // Build a valid export with one downpipe, then inject a MALFORMED downpipe so the tolerant resume skips it.
  const Src = makeScheduler();
  await Src.stub.addDownpipe(makeConfig("good-dp"));
  const exp = (await Src.stub.buildControlPlaneExport()) as ControlPlaneExport;
  exp.configVersion = 42;
  (exp.downpipes as unknown[]).push({ id: "bad id with spaces", name: "x", enabled: true }); // fails validateConfig -> skipped
  // Resume into a fresh, wiped DO with the amnesia latch set.
  const Dst = makeScheduler();
  await Dst.stub.setControlPlaneRecoveryRequired("amnesia: bucket has runs but the plane is empty");
  const staged: StagedControlPlane = { export: exp, signature: "sig", sourceKey: "_RECOVERY/CONTROL-PLANE/x.json", version: exp.configVersion, stagedAt: new Date().toISOString(), resumeApplied: false };
  await Dst.stub.stageControlPlaneRecovery(staged);
  const res = await Dst.stub.applyControlPlaneResumeSlice();
  ok("resume-skip: resume applied the valid downpipe and skipped the malformed one", res.ok === true && res.downpipes === 1 && res.downpipesExpected === 2 && res.resumeSkipped === 1);
  ok("resume-skip: the APPLIED GENERATION is recorded (stale-rollback visible)", res.ok === true && res.appliedVersion === 42);
  // The staged record carries the resume diagnostics forward for the pack.
  const st = (await (await stubFetch(Dst.stub, "GET", "/control-plane/recovery-status")).json()) as { staged?: { resumeSkipped?: number; appliedVersion?: number } };
  ok("resume-skip: recovery-status surfaces resumeSkipped + appliedVersion", st.staged?.resumeSkipped === 1 && st.staged?.appliedVersion === 42);
}

async function auditVerifyVerdict(): Promise<void> {
  console.log("\n# CPR: audit-chain verify verdict + rollover-hardening + verify cost");
  const A = makeScheduler();
  for (let i = 0; i < 4; i++) await A.stub.appendAudit(engineDraft);
  const v0 = await A.stub.verifyAudit();
  ok("audit-verify: a healthy chain verifies intact", v0.intact === true && v0.rolledOver === false);
  ok("audit-verify: records the verify COST (entriesChecked + durationMs) for the near-cap signal", v0.verify.entriesChecked === 4 && v0.verify.complete === true && v0.verify.durationMs >= 0);
  ok("audit-verify: surfaces the live count + near-cap flag", v0.auditCount === 4 && v0.auditNearCap === false);
  // ROLLOVER-HARDENING (rollover-state-lost-false-tamper): drop genesis (seq 1) AND the rollover record, so
  // the chain legitimately begins above seq 1 with NO record. The OLD code would expect genesis and report a
  // spurious break; the hardened code DERIVES the rollover from the earliest retained seq and stays intact.
  await A.storage.delete(auditKey(1));
  await A.storage.delete(AUDIT_ROLLOVER_KEY);
  const v1 = await A.stub.verifyAudit();
  ok("audit-verify: a LOST rollover record does not read as tamper (derived from earliest retained seq)", v1.intact === true && v1.rolledOver === true && v1.earliestSeq === 2 && v1.rolledOverCount === 1 && v1.brokenAt === undefined);
  // The pack projection surfaces the verdict via GET /audit/verify.
  const av = (await (await stubFetch(A.stub, "GET", "/audit/verify")).json()) as { intact?: boolean; rolledOver?: boolean; verify?: { entriesChecked?: number } };
  ok("audit-verify: the verdict is served on GET /audit/verify (the pack's source)", av.intact === true && av.rolledOver === true && typeof av.verify?.entriesChecked === "number");
}

// ---- notifications: per-channel delivery WHY + pipeline drop counters -----------------------------
const validEmission: NotifyEmission = { event: "backup-failure", severity: "critical", downpipeId: null, downpipeName: "acct", detail: "a backup failed", at: "2026-07-01T00:00:00.000Z" };

async function notifyDeliveryCode(): Promise<void> {
  console.log("\n# NOTIF: per-channel delivery WHY (closed code, never the raw response)");
  // The HTTP-status classifier maps a non-2xx to the closed vocabulary.
  ok("delivery-code: an opaque redirect (status 0) classifies as http-redirect", classifyHttpDeliveryStatus(0) === "http-redirect" && classifyHttpDeliveryStatus(302) === "http-redirect");
  ok("delivery-code: an OTHER 4xx / 5xx / other status classify distinctly", classifyHttpDeliveryStatus(404) === "http-4xx" && classifyHttpDeliveryStatus(503) === "http-5xx" && classifyHttpDeliveryStatus(101) === "http-other");
  // Granular failure codes: 401/403/429/400 no longer collapse into the
  // blanket http-4xx bucket, so an operator can tell "fix your credential" from "you're throttled" from
  // "you sent a malformed request" from any other 4xx.
  ok("delivery-code: 401 and 403 BOTH classify as http-auth (a broken credential/permission)", classifyHttpDeliveryStatus(401) === "http-auth" && classifyHttpDeliveryStatus(403) === "http-auth");
  ok("delivery-code: 429 classifies as http-rate-limited (back off, not a broken credential)", classifyHttpDeliveryStatus(429) === "http-rate-limited");
  ok("delivery-code: 400 classifies as http-bad-request (a malformed request, distinct from auth/throttling)", classifyHttpDeliveryStatus(400) === "http-bad-request");
  ok("delivery-code: a 4xx outside {400,401,403,429} still falls to the residual http-4xx", classifyHttpDeliveryStatus(404) === "http-4xx" && classifyHttpDeliveryStatus(405) === "http-4xx" && classifyHttpDeliveryStatus(422) === "http-4xx");
  ok("delivery-code: the new granular codes are all in the closed allow-list", ["http-auth", "http-rate-limited", "http-bad-request"].every((c) => DELIVERY_FAIL_CODES.has(c)));
  // SSRF default-deny at send time yields a CLOSED internal-sink-blocked code (no fetch happens).
  const internalChannel: NotifyChannel = { id: "c1", kind: "webhook", name: "internal", url: "http://127.0.0.1:9000/hook", enabled: true, createdAt: "2026-07-01T00:00:00.000Z" };
  const wr = await deliverWebhook(internalChannel, validEmission);
  ok("delivery-code: an SSRF-screened internal sink surfaces internal-sink-blocked", wr.ok === false && wr.code === "internal-sink-blocked");
  // The email platform code is SHAPE-GATED (E_UPPER_SNAKE only; free text dropped).
  ok("delivery-code: a valid platform code passes the shape gate", sanitiseEmailPlatformCode("E_SENDER_DOMAIN_NOT_AVAILABLE") === "E_SENDER_DOMAIN_NOT_AVAILABLE");
  ok("delivery-code: free text / an injection is DROPPED by the shape gate", sanitiseEmailPlatformCode("id=secret; DROP TABLE") === undefined && sanitiseEmailPlatformCode("hello world") === undefined);
  // The email adapter maps an unconfigured binding to a closed code, and a platform rejection to
  // email-platform-rejected + the shape-gated platform code (split from the engine-side formatting faults,
  // which have opposite owners from the platform's own refusal; see
  // test/validate-root-notify-evidence.ts).
  const emailChannel: NotifyChannel = { id: "c2", kind: "email", name: "oncall", toAddresses: ["ops@example.com"], enabled: true, createdAt: "2026-07-01T00:00:00.000Z" };
  const noBinding = await deliverEmailChannel({ EMAIL_FROM: "alerts@example.com" } as unknown as Env, emailChannel, validEmission);
  ok("delivery-code: email with no send_email binding => email-not-configured", noBinding.ok === false && noBinding.code === "email-not-configured");
  const rejectingEnv = { EMAIL_FROM: "alerts@example.com", EMAIL: { send: async () => { throw Object.assign(new Error("rejected"), { code: "E_SENDER_NOT_VERIFIED" }); } } } as unknown as Env;
  const rejected = await deliverEmailChannel(rejectingEnv, emailChannel, validEmission);
  ok("delivery-code: a platform rejection => email-platform-rejected + the shape-gated platform code", rejected.ok === false && rejected.code === "email-platform-rejected" && rejected.platformCode === "E_SENDER_NOT_VERIFIED");
  ok("delivery-code: every emitted code is in the closed allow-list", [wr.code, noBinding.code, rejected.code].every((c) => c !== undefined && DELIVERY_FAIL_CODES.has(c)));
}

async function notifySinkScreen(): Promise<void> {
  console.log("\n# NOTIF: send-time sink-screen verdict (dns-rebinding-gap, OBSERVE not IP-pin)");
  // The PURE classifier splits a literal internal address/name (blocked), a literal PUBLIC IP (fully
  // screened -- a literal cannot be DNS-rebound), a DNS NAME (the residual rebind-exposed class the literal
  // screen cannot see through), and an unparseable url. This is the OBSERVE side of the gap: it names what
  // the literal screen can and cannot see, WITHOUT adding true resolve-then-pin behaviour.
  ok("sink-screen: a literal loopback / RFC1918 IP is internal-literal", screenSinkHost("http://127.0.0.1/hook") === "internal-literal" && screenSinkHost("https://10.1.2.3/x") === "internal-literal");
  ok("sink-screen: an internal NAME (localhost / *.localhost) is internal-literal", screenSinkHost("http://localhost/hook") === "internal-literal" && screenSinkHost("https://svc.localhost/x") === "internal-literal");
  ok("sink-screen: a literal PUBLIC IPv4/IPv6 is public-literal (un-rebindable)", screenSinkHost("https://203.0.113.5/hook") === "public-literal" && screenSinkHost("https://[2001:db8::1]/x") === "public-literal");
  ok("sink-screen: a DNS NAME is the residual rebind-exposed `hostname` class", screenSinkHost("https://sink.example.com/hook") === "hostname");
  ok("sink-screen: an unparseable url is url-invalid", screenSinkHost("not a url") === "url-invalid");
  ok("sink-screen: every verdict is in the closed allow-list", (["internal-literal", "public-literal", "hostname", "url-invalid"] as const).every((v) => SINK_SCREEN_VERDICTS.has(v)));
  // The webhook adapter surfaces the verdict on the delivery result. A blocked internal sink carries the
  // verdict ALONGSIDE internal-sink-blocked; a hostname sink surfaces `hostname` regardless of the outcome.
  const internalChannel: NotifyChannel = { id: "c1", kind: "webhook", name: "internal", url: "http://127.0.0.1:9000/hook", enabled: true, createdAt: "2026-07-01T00:00:00.000Z" };
  const blocked = await deliverWebhook(internalChannel, validEmission);
  ok("sink-screen: a blocked internal sink carries the verdict alongside internal-sink-blocked", blocked.ok === false && blocked.code === "internal-sink-blocked" && blocked.sinkScreen === "internal-literal");
  const nameChannel: NotifyChannel = { id: "c2", kind: "webhook", name: "sink", url: "https://sink.invalid.example/hook", enabled: true, createdAt: "2026-07-01T00:00:00.000Z" };
  const nameRes = await deliverWebhook(nameChannel, validEmission);
  ok("sink-screen: a hostname sink surfaces sinkScreen=hostname regardless of delivery outcome", nameRes.sinkScreen === "hostname");
}

async function notifyHistoryCode(): Promise<void> {
  console.log("\n# NOTIF: the delivery code rides onto the history entry (the pack's source)");
  const A = makeScheduler();
  const res = await A.stub.recordNotify({ emission: validEmission, records: [{ channelId: "c1", channelKind: "webhook", delivered: false, code: "http-5xx" }, { channelId: "c2", channelKind: "email", delivered: false, code: "email-rejected", platformCode: "E_SENDER_NOT_VERIFIED" }] });
  ok("history-code: both delivery records were recorded", res.recorded === 2 && res.skipped === 0);
  const hist = await A.stub.listNotifyHistory();
  const wh = hist.find((h) => h.channelId === "c1");
  const em = hist.find((h) => h.channelId === "c2");
  ok("history-code: the failed webhook carries deliveryCode=http-5xx", wh?.delivered === false && (wh as { deliveryCode?: string }).deliveryCode === "http-5xx");
  ok("history-code: the failed email carries the platform code", em !== undefined && (em as { platformCode?: string }).platformCode === "E_SENDER_NOT_VERIFIED");
  // An out-of-vocabulary code is DROPPED (defence in depth on the redaction).
  await A.stub.recordNotify({ emission: validEmission, records: [{ channelId: "c3", channelKind: "webhook", delivered: false, code: "id=secret-leak" }] });
  const h3 = (await A.stub.listNotifyHistory()).find((h) => h.channelId === "c3");
  ok("history-code: an unknown delivery code is dropped, never propagated", h3 !== undefined && (h3 as { deliveryCode?: string }).deliveryCode === undefined);
  // A delivered:true row carries NO failure code (the code is only a WHY-it-failed signal).
  await A.stub.recordNotify({ emission: validEmission, records: [{ channelId: "c4", channelKind: "slack", delivered: true, code: "http-5xx" }] });
  const h4 = (await A.stub.listNotifyHistory()).find((h) => h.channelId === "c4");
  ok("history-code: a delivered row carries no failure code", h4 !== undefined && (h4 as { deliveryCode?: string }).deliveryCode === undefined);
  // The sinkScreen verdict (NOTIF: dns-rebinding-gap) rides on SUCCESS and failure alike (a delivered hostname
  // sink is the rebind-exposed one), validated against the closed allow-list; an out-of-vocab verdict is dropped.
  await A.stub.recordNotify({ emission: validEmission, records: [
    { channelId: "c5", channelKind: "webhook", delivered: true, sinkScreen: "hostname" },
    { channelId: "c6", channelKind: "webhook", delivered: false, code: "http-5xx", sinkScreen: "internal-literal" },
    { channelId: "c7", channelKind: "webhook", delivered: true, sinkScreen: "id=secret-leak" },
  ] });
  const hist2 = await A.stub.listNotifyHistory();
  const h5 = hist2.find((h) => h.channelId === "c5");
  const h6 = hist2.find((h) => h.channelId === "c6");
  const h7 = hist2.find((h) => h.channelId === "c7");
  ok("history-sink: a DELIVERED hostname sink carries sinkScreen=hostname on the history entry", h5?.delivered === true && (h5 as { sinkScreen?: string }).sinkScreen === "hostname");
  ok("history-sink: a failed internal sink carries sinkScreen alongside the delivery code", h6 !== undefined && (h6 as { sinkScreen?: string }).sinkScreen === "internal-literal" && (h6 as { deliveryCode?: string }).deliveryCode === "http-5xx");
  ok("history-sink: an out-of-vocabulary sinkScreen is dropped, never propagated", h7 !== undefined && (h7 as { sinkScreen?: string }).sinkScreen === undefined);
}

async function notifyHealthCounters(): Promise<void> {
  console.log("\n# NOTIF: pipeline drop counters (silent alert loss becomes visible)");
  const A = makeScheduler();
  ok("notify-health: absent before any drop", (await A.stub.getNotifyHealth()) === null);
  // A malformed emission (an unknown event) is a parse-reject.
  await A.stub.recordNotify({ emission: { event: "not-an-event", severity: "critical", downpipeId: null, detail: "x", at: "2026-07-01T00:00:00.000Z" }, records: [] });
  // An OVERLONG free-text detail is also a parse-reject (NOTIF: freetext-detail-overlong-rejected).
  await A.stub.resolveNotify({ emission: { event: "backup-failure", severity: "critical", downpipeId: null, detail: "x".repeat(600), at: "2026-07-01T00:00:00.000Z" } });
  // A malformed per-channel record is a record-skip.
  await A.stub.recordNotify({ emission: validEmission, records: [{ nonsense: true }, { channelId: "", channelKind: "webhook", delivered: false }] });
  // The Worker's health-bump route bumps passSkips (a skipped pass) and feedbackFails (a stuck cooldown).
  await stubFetch(A.stub, "POST", "/notify/health-bump", { field: "passSkips" });
  await stubFetch(A.stub, "POST", "/notify/health-bump", { field: "feedbackFails" });
  const badBump = await stubFetch(A.stub, "POST", "/notify/health-bump", { field: "id=secret" });
  ok("notify-health: an unknown health field is refused (400)", badBump.status === 400);
  const h = await A.stub.getNotifyHealth();
  ok("notify-health: parseRejects counts malformed + overlong emissions", (h?.parseRejects ?? 0) === 2);
  ok("notify-health: recordSkips counts dropped per-channel records", (h?.recordSkips ?? 0) === 2);
  ok("notify-health: passSkips + feedbackFails count skipped passes + stuck-cooldown feedback failures", (h?.passSkips ?? 0) === 1 && (h?.feedbackFails ?? 0) === 1 && typeof h?.lastAt === "string");
  // The counter record is served on GET /notify/health (the pack's source).
  const nh = (await (await stubFetch(A.stub, "GET", "/notify/health")).json()) as { parseRejects?: number };
  ok("notify-health: served on GET /notify/health", nh.parseRejects === 2);
}

async function notifyDigestPending(): Promise<void> {
  console.log("\n# NOTIF: pending-digest queue depth + oldest deferred entry");
  const A = makeScheduler();
  const ch: NotifyChannel = { id: "cd", kind: "email", name: "digest", toAddresses: ["a@example.com"], enabled: true, createdAt: "2026-07-01T00:00:00.000Z" };
  const em: NotifyEmission = { event: "backup-success", severity: "info", downpipeId: null, downpipeName: "x", detail: "ok", at: "2026-07-01T00:00:00.000Z" };
  ok("digest-pending: empty when nothing is deferred", (await A.stub.digestPending()).count === 0 && (await A.stub.digestPending()).oldestAt === null);
  await A.stub.appendDigestEntry({ ...em, at: "2026-07-01T02:00:00.000Z" }, ch, "daily");
  await A.stub.appendDigestEntry({ ...em, at: "2026-07-01T01:00:00.000Z" }, ch, "daily");
  const dp = await A.stub.digestPending();
  ok("digest-pending: reports queue depth + the oldest deferred entry (a never-flushing digest is visible)", dp.count === 2 && dp.oldestAt === "2026-07-01T01:00:00.000Z");
  // The PER-CADENCE window state (digest-defers-success-up-to-a-week): a weekly deferral joins the two daily
  // ones, so byPeriod names WHICH cadence holds how many, its oldest deferred instant, and the computed DUE-AT
  // (oldest + that period's fixed window: daily 24h, weekly 7d). A stuck cadence is then attributable + dated.
  await A.stub.appendDigestEntry({ ...em, at: "2026-07-01T03:00:00.000Z" }, ch, "weekly");
  const dp2 = await A.stub.digestPending();
  ok("digest-pending: byPeriod reports the per-cadence queue depth", dp2.byPeriod.daily?.count === 2 && dp2.byPeriod.weekly?.count === 1);
  ok("digest-pending: byPeriod reports the oldest deferred instant per cadence", dp2.byPeriod.daily?.oldestAt === "2026-07-01T01:00:00.000Z" && dp2.byPeriod.weekly?.oldestAt === "2026-07-01T03:00:00.000Z");
  ok("digest-pending: byPeriod reports the computed dueAt window (oldest + the fixed period window)", dp2.byPeriod.daily?.dueAt === "2026-07-02T01:00:00.000Z" && dp2.byPeriod.weekly?.dueAt === "2026-07-08T03:00:00.000Z");
  // Surfaced on the route (the pack's source).
  const route = (await (await stubFetch(A.stub, "GET", "/notify/digest-pending")).json()) as { byPeriod?: { daily?: { count?: number } } };
  ok("digest-pending: byPeriod served on GET /notify/digest-pending (the pack's source)", route.byPeriod?.daily?.count === 2);
}

async function canaryTransitionRing(): Promise<void> {
  console.log("\n# NOTIF: canary transition ring (canary-transition-only-pages-once)");
  const A = makeScheduler();
  ok("canary-ring: empty before any flight", (await A.stub.getCanaryTransitions()).transitions.length === 0);
  // Flight 1: the default destination falls DEAD -> a dead transition is recorded (prev pending != dead).
  const dead = await A.stub.canaryComplete({ run: { runSeq: 1, dests: [{ runId: "cr1", runSeq: 1, destinationId: null, cleanupRunId: null }] }, results: [{ status: "dead", destinationId: null, durationMs: 5, aspects: [], byteDelta: 3, deadReason: "a byte strayed" }] });
  ok("canary-ring: canaryComplete reports the dead threshold crossing", dead.transitions.length === 1 && dead.transitions[0]?.transitioned === "dead");
  const afterDead = await A.stub.getCanaryTransitions();
  ok("canary-ring: the ring durably records the dead crossing (WHEN + to-state + flight number)", afterDead.transitions.length === 1 && afterDead.transitions[0]?.to === "dead" && afterDead.transitions[0]?.runSeq === 1 && typeof afterDead.transitions[0]?.at === "string");
  ok("canary-ring: the aggregate status + dead-destination count reflect the standing death", afterDead.status === "dead" && afterDead.deadDestinations === 1);
  // Flight 2: it RECOVERS -> a recovered transition is appended (newest-last; both crossings retained).
  await A.stub.canaryComplete({ run: { runSeq: 2, dests: [{ runId: "cr2", runSeq: 2, destinationId: null, cleanupRunId: "cr1" }] }, results: [{ status: "alive", destinationId: null, durationMs: 5, aspects: [], byteDelta: 0, deadReason: null }] });
  const afterRecover = await A.stub.getCanaryTransitions();
  ok("canary-ring: the recovered crossing is appended newest-last (both crossings retained)", afterRecover.transitions.length === 2 && afterRecover.transitions[1]?.to === "recovered" && afterRecover.deadDestinations === 0);
  // A steady flight (no crossing) does NOT grow the ring (the "pages once, not every tick" behaviour this
  // signal makes observable: the durable record does not gain a spurious entry on a non-transition tick).
  await A.stub.canaryComplete({ run: { runSeq: 3, dests: [{ runId: "cr3", runSeq: 3, destinationId: null, cleanupRunId: "cr2" }] }, results: [{ status: "alive", destinationId: null, durationMs: 5, aspects: [], byteDelta: 0, deadReason: null }] });
  ok("canary-ring: a steady flight adds no transition (only pages once, the exact fault this makes observable)", (await A.stub.getCanaryTransitions()).transitions.length === 2);
  // Surfaced on the route (the pack's source).
  const rt = (await (await stubFetch(A.stub, "GET", "/canary/transitions")).json()) as { transitions?: Array<{ to?: string }>; status?: string };
  ok("canary-ring: surfaced on GET /canary/transitions (the pack's source)", (rt.transitions?.length ?? 0) === 2 && rt.status === "alive");
}

async function alertCooldownState(): Promise<void> {
  console.log("\n# NOTIF: per-downpipe alert-cooldown state (cooldown-suppresses-renudge-1h)");
  const A = makeScheduler();
  ok("cooldowns: empty before any alert", (await A.stub.listAlertCooldowns()).alert.length === 0);
  // Seed the EXACT records the reconcile detector writes ({ state, at } epoch ms) for both streams; the read
  // side is what the pack surfaces so "why didn't I get re-alerted about a still-broken pipe" is answerable.
  await A.storage.put(`${ALERT_COOLDOWN_PREFIX}dp1`, { state: "failed", at: 1_700_000_000_000 });
  await A.storage.put(`${ALERT_COOLDOWN_PREFIX}dp2`, { state: "stale", at: 1_700_000_100_000 });
  await A.storage.put(`${REPL_ALERT_COOLDOWN_PREFIX}dp1`, { state: "replication-degraded", at: 1_700_000_200_000 });
  const cd = await A.stub.listAlertCooldowns();
  ok("cooldowns: the staleness/failure stream surfaces per-downpipe state + time", cd.alert.length === 2 && cd.alert.some((r) => r.downpipeId === "dp1" && r.state === "failed" && r.at === 1_700_000_000_000) && cd.alert.some((r) => r.downpipeId === "dp2" && r.state === "stale"));
  ok("cooldowns: the replication stream surfaces its own cooldown state", cd.replication.length === 1 && cd.replication[0]?.downpipeId === "dp1" && cd.replication[0]?.state === "replication-degraded");
  ok("cooldowns: the cooldown window (cooldownMs) rides so 'suppressed until at + cooldownMs' is computable", cd.cooldownMs === 60 * 60 * 1000);
  // Surfaced on the route (the pack's source).
  const rt = (await (await stubFetch(A.stub, "GET", "/notify/cooldowns")).json()) as { alert?: unknown[]; cooldownMs?: number };
  ok("cooldowns: surfaced on GET /notify/cooldowns (the pack's source)", Array.isArray(rt.alert) && rt.alert.length === 2 && rt.cooldownMs === 60 * 60 * 1000);
}

async function main(): Promise<void> {
  await controlPlaneAmnesiaProbe();
  await controlPlaneDeployObservation();
  await controlPlaneExportHealth();
  await controlPlaneCredGate();
  await controlPlaneRefusalCode();
  await controlPlaneResumeSkip();
  await auditVerifyVerdict();
  await notifyDeliveryCode();
  await notifySinkScreen();
  await notifyHistoryCode();
  await notifyHealthCounters();
  await notifyDigestPending();
  await canaryTransitionRing();
  await alertCooldownState();

  console.log(failures === 0 ? "\nCPR + NOTIFY LOGGING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
