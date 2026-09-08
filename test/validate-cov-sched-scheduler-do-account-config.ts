// validate-cov-sched-scheduler-do-account-config: branch-coverage proof for the AccountConfigMixin
// (src/sched/scheduler-do-account-config.ts), the console-set account-config subsystems extracted from
// the SchedulerDO god module: the account-discovery read-only API token + selected accounts, the
// added token-source set, the assurance licence record, and the safe-apply update-lifecycle bookkeeping.
//
// It drives the REAL Durable Object through its internal fetch routes (s.stub.fetch with an x-downpipe-caller
// header, the same router-bypass defence-in-depth pattern validate-sources-enable.ts uses), so every
// assertion checks a real outcome: an HTTP status, a returned body field, or a recorded audit event. The
// owner gate is re-resolved for real inside each method (roleForCaller), so the owner / non-owner / token
// break-glass paths are exercised genuinely. A token caller (method:"token", email:null) is used to reach
// the null-email / null-sourceIp audit arms, which a JWT-authenticated router caller can never synthesise;
// a bootstrapped Access owner (with a sourceIp) reaches the email-present / sourceIp-present arms.
//
// Run: node test/validate-cov-sched-scheduler-do-account-config.ts

import { makeScheduler } from "./validate-rbac-harness.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { SELECTABLE_TOKEN_SOURCE_TYPES } from "../src/sched/config-validate.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
const sorted = (xs: string[] | undefined): string => JSON.stringify((xs ?? []).slice().sort());

interface AuditEvt {
  actorEmail: string | null;
  actorMethod: string;
  sourceIp: string | null;
  action: string;
  outcome: string;
}

async function main(): Promise<void> {
  const s = makeScheduler();

  // ---- identities -----------------------------------------------------------------------------
  const OWNER_EMAIL = "owner@cov.example";
  const OWNER_SUBJECT = "covsubj-owner";
  const OWNER_IP = "203.0.113.9";
  // A bootstrapped Access Owner carrying a sourceIp: reaches the email-present / sourceIp-present arms.
  const ownerAccess: Caller = { method: "access", email: OWNER_EMAIL, subject: OWNER_SUBJECT, role: "owner", groups: [], sourceIp: OWNER_IP };
  // The bare-token break-glass: resolves to owner WITHOUT the role table, email null, no sourceIp: reaches
  // the null-email / "token" method / null-sourceIp arms.
  const tokenOwner: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
  // A genuine non-owner (a distinct subject with no grant): reaches every forbidden arm.
  const viewer: Caller = { method: "access", email: "viewer@cov.example", subject: "covsubj-viewer", role: "viewer", groups: [] };

  const doGet = (path: string, caller?: Caller): Promise<Response> =>
    s.stub.fetch(`https://scheduler.internal${path}`, { method: "GET", headers: caller ? { "x-downpipe-caller": encodeCaller(caller) } : {} });
  const doPost = (path: string, caller: Caller | null, body: unknown): Promise<Response> =>
    s.stub.fetch(`https://scheduler.internal${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(caller ? { "x-downpipe-caller": encodeCaller(caller) } : {}) },
      body: JSON.stringify(body),
    });
  const jget = async (r: Response): Promise<Record<string, unknown>> => (await r.json()) as Record<string, unknown>;

  // Bootstrap the first authenticated caller as Owner (keyed on the stable subject), so ownerAccess
  // resolves to owner through the real role table while viewer (a distinct subject) stays viewer.
  const boot = await jget(await doGet(`/whoami?email=${encodeURIComponent(OWNER_EMAIL)}&subject=${encodeURIComponent(OWNER_SUBJECT)}&method=access`));
  ok("bootstrap: the first Access caller becomes Owner", boot.role === "owner");

  // ============================================================================================
  // UPDATE LIFECYCLE (getUpdateRecord / setUpdatePending / setUpdateSettled / claimUpdateAlert /
  // claimRollbackNeeded). No caller is read by these routes. Two passes: the first with no
  // lastAlertedVersion (the `: {}` arms), the second after one is recorded (the present arms).
  // ============================================================================================

  // U1: absent record reads the default.
  const u1 = await jget(await doGet("/update-status"));
  ok("getUpdateRecord: absent reads {pending:null,last:null}", u1.pending === null && u1.last === null);

  // U2: a blank version never claims an update alert (non-string -> "" -> early false).
  const u2 = await jget(await doPost("/update-alert-claim", null, {}));
  ok("claimUpdateAlert: blank version -> shouldAlert false", u2.shouldAlert === false);

  // U3: a blank version never claims a rollback (non-string recommended/to/verdict -> early false).
  const u3 = await jget(await doPost("/update-rollback-needed-claim", null, {}));
  ok("claimRollbackNeeded: blank version -> shouldAlert false", u3.shouldAlert === false);

  // U4: first pending, no prior lastAlertedVersion -> the absent `: {}` arm.
  const u4 = await jget(await doPost("/update-pending", null, { fromVersion: "v1", toVersion: "v2", recommendedVersion: "v2", promotedAt: 1, promotedBy: "o" }));
  ok("setUpdatePending: stores pending (absent lastAlertedVersion arm)", (u4.pending as { toVersion?: string } | null)?.toVersion === "v2" && u4.lastAlertedVersion === undefined);

  // U5: pending present, no prior rollback flag, no lastAlertedVersion -> first claim alerts.
  const u5 = await jget(await doPost("/update-rollback-needed-claim", null, { recommendedVersion: "r1", toVersion: "t1", canaryVerdict: "failing" }));
  ok("claimRollbackNeeded: first observation while pending -> shouldAlert true", u5.shouldAlert === true);

  // U6: the SAME recommended version is deduped (already observed) -> no second page.
  const u6 = await jget(await doPost("/update-rollback-needed-claim", null, { recommendedVersion: "r1", toVersion: "t1", canaryVerdict: "failing" }));
  ok("claimRollbackNeeded: same version again -> shouldAlert false (deduped)", u6.shouldAlert === false);

  // U7: settle with no lastAlertedVersion -> the absent `: {}` arm; resolves pending + clears the flag.
  const u7 = await jget(await doPost("/update-settled", null, { outcome: "kept", at: 1, by: "o" }));
  ok("setUpdateSettled: settles (absent lastAlertedVersion arm)", (u7.last as { outcome?: string } | null)?.outcome === "kept" && u7.pending === null);

  // U8: a rollback claim with a real version but NO pending -> the !pending early false.
  const u8 = await jget(await doPost("/update-rollback-needed-claim", null, { recommendedVersion: "r9" }));
  ok("claimRollbackNeeded: no pending -> shouldAlert false", u8.shouldAlert === false);

  // U9: a genuinely new version (no rollback flag present) records + alerts.
  const u9 = await jget(await doPost("/update-alert-claim", null, { recommendedVersion: "r2" }));
  ok("claimUpdateAlert: new version -> shouldAlert true (rollbackNeeded absent arm)", u9.shouldAlert === true);

  // U10: the same version is deduped.
  const u10 = await jget(await doPost("/update-alert-claim", null, { recommendedVersion: "r2" }));
  ok("claimUpdateAlert: same version again -> shouldAlert false", u10.shouldAlert === false);

  // U11: pending with a lastAlertedVersion present -> the present arm carries it through.
  const u11 = await jget(await doPost("/update-pending", null, { fromVersion: "v2", toVersion: "v3", recommendedVersion: "r2", promotedAt: 1, promotedBy: "o" }));
  ok("setUpdatePending: carries lastAlertedVersion (present arm)", (u11.pending as { toVersion?: string } | null)?.toVersion === "v3" && u11.lastAlertedVersion === "r2");

  // U12: rollback claim while a lastAlertedVersion is present -> the present arm; records the flag.
  const u12 = await jget(await doPost("/update-rollback-needed-claim", null, { recommendedVersion: "r3", toVersion: "t3", canaryVerdict: "ill" }));
  ok("claimRollbackNeeded: alerts with lastAlertedVersion present arm", u12.shouldAlert === true);

  // U13: a new alert version with a rollback flag PRESENT -> the rollbackNeeded present arm.
  const u13 = await jget(await doPost("/update-alert-claim", null, { recommendedVersion: "r4" }));
  ok("claimUpdateAlert: new version carries the rollback flag (present arm)", u13.shouldAlert === true);

  // U14: settle with a lastAlertedVersion present -> the present arm.
  const u14 = await jget(await doPost("/update-settled", null, { outcome: "rolled-back", at: 1, by: "o" }));
  ok("setUpdateSettled: carries lastAlertedVersion (present arm)", (u14.last as { outcome?: string } | null)?.outcome === "rolled-back" && u14.lastAlertedVersion === "r4");

  // ============================================================================================
  // The anti-rollback high-water mark + the freshness watermark, persisted, monotonic, sticky.
  // ============================================================================================
  // R8: the FIRST "applied" settle adopts the settled semver as the high-water mark (semverMax no-current arm).
  const h1 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.5.0", fromVersion: "vA", toVersion: "vB", at: 1, by: "o" }));
  ok("first applied settle sets the high-water mark", h1.settledHighWaterMark === "0.5.0");
  // R8: a LOWER applied settle never lowers it (semverMax keep-current arm, cmp = -1).
  const h2 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.4.0", at: 1, by: "o" }));
  ok("a lower applied settle does NOT lower the mark (monotonic)", h2.settledHighWaterMark === "0.5.0");
  // R8: a HIGHER applied settle advances it (semverMax adopt-candidate arm, cmp = 1).
  const h3 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.6.0", at: 1, by: "o" }));
  ok("a higher applied settle advances the mark", h3.settledHighWaterMark === "0.6.0");
  // R8: an UNCOMPARABLE applied version keeps the existing mark (semverMax cmp = null fail-safe arm).
  const h4 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "garbage", at: 1, by: "o" }));
  ok("applied settle with an uncomparable version keeps the existing mark", h4.settledHighWaterMark === "0.6.0");
  // R8: an "applied" settle with NO recommendedVersion leaves the mark unchanged (settledVersion === "" arm).
  const h5 = await jget(await doPost("/update-settled", null, { outcome: "applied", at: 1, by: "o" }));
  ok("applied settle with no recommendedVersion -> mark unchanged", h5.settledHighWaterMark === "0.6.0");
  // R8: a non-applied (rolled-back) settle never advances the mark.
  const h6 = await jget(await doPost("/update-settled", null, { outcome: "rolled-back", recommendedVersion: "0.7.0", at: 1, by: "o" }));
  ok("a rolled-back settle does NOT advance the mark (only applied does)", h6.settledHighWaterMark === "0.6.0");
  // R8 STICKY: a cron update-alert claim (returns {shouldAlert}) must CARRY the mark forward, read it back.
  await doPost("/update-alert-claim", null, { recommendedVersion: "9.9.9" });
  const h7 = await jget(await doGet("/update-status"));
  ok("update-alert claim preserves the high-water mark (sticky)", h7.settledHighWaterMark === "0.6.0");
  // R9: a promote carrying a channel freshness claim ADVANCES the persisted watermark (present advance arms),
  // and carries the high-water mark forward too (stickyUpdateFields present arm).
  const f1 = await jget(await doPost("/update-pending", null, { fromVersion: "vB", toVersion: "vC", recommendedVersion: "0.6.0", promotedAt: 1, promotedBy: "o", channelSeq: 12, channelIssuedAt: "2026-06-20T00:00:00Z" }));
  ok("setUpdatePending advances the freshness watermark from the channel claim", f1.lastChannelSeq === 12 && f1.lastChannelIssuedAt === "2026-06-20T00:00:00Z");
  ok("the freshness advance carried the high-water mark forward (sticky)", f1.settledHighWaterMark === "0.6.0");
  // R9 STICKY: a rollback-needed claim while pending (returns {shouldAlert}) preserves BOTH; read it back.
  await doPost("/update-rollback-needed-claim", null, { recommendedVersion: "0.6.0", toVersion: "vC", canaryVerdict: "ailing" });
  const f2 = await jget(await doGet("/update-status"));
  ok("rollback-needed claim preserves the freshness watermark + the high-water mark", f2.lastChannelSeq === 12 && f2.settledHighWaterMark === "0.6.0");

  // ============================================================================================
  // MULTI-COMPONENT updates: per-component settle routing (lastConsole vs last), the floors map +
  // its legacy-scalar mirror + the read-time migration, the queued-console abort, the history ring,
  // and the R9 advance a settle can carry (a console-only apply records no engine pending).
  // ============================================================================================
  // MC1: a CONSOLE applied settle lands in lastConsole + floors.console; the ENGINE's last + floor
  // and the legacy scalar mirror are untouched (a console outcome must never clobber the engine's).
  const engineLastBefore = JSON.stringify(f2.last);
  const mc1 = await jget(await doPost("/update-settled", null, { outcome: "applied", component: "console", recommendedVersion: "0.3.0", fromVersion: "cv-1", toVersion: "cv-2", at: 2, by: "o" }));
  ok("a console applied settle lands in lastConsole (component recorded)", (mc1.lastConsole as { outcome?: string; component?: string } | null)?.outcome === "applied" && (mc1.lastConsole as { component?: string } | null)?.component === "console");
  ok("the ENGINE's last outcome is untouched by a console settle", JSON.stringify(mc1.last) === engineLastBefore);
  ok("floors: console adopted, engine + the legacy scalar mirror unchanged", (mc1.floors as { engine?: string; console?: string }).console === "0.3.0" && (mc1.floors as { engine?: string }).engine === "0.6.0" && mc1.settledHighWaterMark === "0.6.0");
  ok("the history ring appended the console entry", Array.isArray(mc1.history) && (mc1.history as Array<{ component?: string }>).some((h) => h.component === "console"));
  // MC2: a console ROLLED-BACK settle never advances floors.console.
  const mc2 = await jget(await doPost("/update-settled", null, { outcome: "rolled-back", component: "console", recommendedVersion: "0.9.9", fromVersion: "cv-1", toVersion: "cv-2", at: 3, by: "o" }));
  ok("a console rolled-back settle does not advance floors.console", (mc2.floors as { console?: string }).console === "0.3.0" && (mc2.lastConsole as { outcome?: string } | null)?.outcome === "rolled-back");
  // MC3: an ENGINE settle that is NOT applied ABORTS a queued console intent with an honest record.
  await doPost("/update-pending", null, { fromVersion: "vC", toVersion: "vD", recommendedVersion: "0.8.0", promotedAt: 4, promotedBy: "o", consoleQueued: { version: "0.8.0", riskClass: "routine", queuedAt: 4 } });
  const mc3 = await jget(await doPost("/update-settled", null, { outcome: "rolled-back", recommendedVersion: "0.8.0", fromVersion: "vC", toVersion: "vD", at: 5, by: "o" }));
  ok("a non-applied engine settle aborts the queued console (honest refused record)", (mc3.lastConsole as { outcome?: string; reason?: string } | null)?.outcome === "refused" && /did not settle as applied/.test(String((mc3.lastConsole as { reason?: string } | null)?.reason)));
  ok("the abort rode into the history ring alongside the engine outcome", Array.isArray(mc3.history) && (mc3.history as Array<{ component?: string; outcome?: string }>).some((h) => h.component === "console" && h.outcome === "refused"));
  // MC4: an ENGINE settle that IS applied leaves the queue to the router's console continuation (the
  // pending is consumed; lastConsole is NOT overwritten by the DO).
  await doPost("/update-pending", null, { fromVersion: "vD", toVersion: "vE", recommendedVersion: "0.8.1", promotedAt: 6, promotedBy: "o", consoleQueued: { version: "0.8.1", riskClass: "routine", queuedAt: 6 } });
  const mc4 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.8.1", fromVersion: "vD", toVersion: "vE", at: 7, by: "o" }));
  ok("an applied engine settle consumes the pending without fabricating a console outcome", mc4.pending === null && (mc4.lastConsole as { outcome?: string } | null)?.outcome === "refused");
  // MC5: a CONSOLE settle while an engine pending still carries a queue STRIPS the consumed queue.
  await doPost("/update-pending", null, { fromVersion: "vE", toVersion: "vF", recommendedVersion: "0.8.2", promotedAt: 8, promotedBy: "o", consoleQueued: { version: "0.8.2", riskClass: "routine", queuedAt: 8 } });
  const mc5 = await jget(await doPost("/update-settled", null, { outcome: "applied", component: "console", recommendedVersion: "0.8.2", fromVersion: "cv-2", toVersion: "cv-3", at: 9, by: "o" }));
  ok("a console settle preserves the engine pending but strips the consumed queue", (mc5.pending as { toVersion?: string; consoleQueued?: unknown } | null)?.toVersion === "vF" && (mc5.pending as { consoleQueued?: unknown } | null)?.consoleQueued === null);
  await doPost("/update-settled", null, { outcome: "expired", at: 10, by: null }); // clear the pending for the cases below
  // MC6 [R9]: a settle carrying the channel freshness claim advances the watermark (the console-only
  // apply's accepting act -- it records no engine pending, so the settle is where the claim lands).
  const mc6 = await jget(await doPost("/update-settled", null, { outcome: "applied", component: "console", recommendedVersion: "0.8.3", fromVersion: "cv-3", toVersion: "cv-4", at: 11, by: "o", channelSeq: 15, channelIssuedAt: "2026-07-01T00:00:00Z" }));
  ok("a settle carrying the channel claim advances the freshness watermark", mc6.lastChannelSeq === 15 && mc6.lastChannelIssuedAt === "2026-07-01T00:00:00Z");
  // MC7: the history ring is BOUNDED (newest kept, capped at 20).
  for (let i = 0; i < 22; i++) {
    await doPost("/update-settled", null, { outcome: "rolled-back", component: "console", recommendedVersion: `0.0.${i}`, at: 100 + i, by: "o" });
  }
  const mc7 = await jget(await doGet("/update-status"));
  ok("the history ring caps at 20 entries, newest kept", Array.isArray(mc7.history) && (mc7.history as unknown[]).length === 20 && (mc7.history as Array<{ at?: number }>)[19]?.at === 121);
  // MC8: READ-TIME MIGRATION -- a legacy record carrying only the settledHighWaterMark scalar (no floors
  // map) reads as floors = { engine: scalar }, the migrateCanaryState precedent.
  await s.storage.put("updateLifecycle", { pending: null, last: null, settledHighWaterMark: "1.2.3" });
  const mc8 = await jget(await doGet("/update-status"));
  ok("a legacy scalar-only record migrates on read as floors.engine", (mc8.floors as { engine?: string } | undefined)?.engine === "1.2.3" && mc8.settledHighWaterMark === "1.2.3");
  // ... and the migrated floors persist through the next write (sticky), with the scalar still mirrored.
  const mc9 = await jget(await doPost("/update-settled", null, { outcome: "applied", component: "console", recommendedVersion: "0.1.0", at: 200, by: "o" }));
  ok("the migrated engine floor persists through a console write (sticky + mirrored)", (mc9.floors as { engine?: string; console?: string }).engine === "1.2.3" && (mc9.floors as { console?: string }).console === "0.1.0" && mc9.settledHighWaterMark === "1.2.3");

  // ============================================================================================
  // 0.1.5 UX design §3: confirmUpdateSettled, the hourly canary's background confirmation of a KEEP
  // decided via the self-check (confirmationPending:true). Bookkeeping only: never touches floors,
  // history or the freshness watermark, and needs no caller/token.
  // ============================================================================================
  // CU1: an engine KEEP decided via the self-check carries confirmationPending:true.
  const cu1 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.9.0", fromVersion: "cu-prior", toVersion: "cu-now", at: 300, by: "o", confirmationPending: true }));
  ok("a self-check keep persists confirmationPending:true", (cu1.last as { confirmationPending?: boolean } | null)?.confirmationPending === true);
  const cu1FloorsBefore = JSON.stringify(cu1.floors);
  const cu1HistoryLenBefore = Array.isArray(cu1.history) ? (cu1.history as unknown[]).length : -1;
  // CU2: a MISMATCHED recommendedVersion (a different version now confirmed alive) -> clean no-op, the
  // flag stays untouched.
  const cu2 = await jget(await doPost("/update-confirm", null, { recommendedVersion: "9.9.9" }));
  ok("confirmUpdateSettled: mismatched recommendedVersion -> cleared:false", cu2.cleared === false);
  const afterCu2 = await jget(await doGet("/update-status"));
  ok("a mismatched confirm leaves confirmationPending untouched (still true)", (afterCu2.last as { confirmationPending?: boolean } | null)?.confirmationPending === true);
  // CU3: a blank/missing recommendedVersion -> clean no-op (never a wildcard clear).
  const cu3 = await jget(await doPost("/update-confirm", null, {}));
  ok("confirmUpdateSettled: blank recommendedVersion -> cleared:false", cu3.cleared === false);
  // CU4: the MATCHING recommendedVersion clears the flag, and touches NOTHING else (floors/history sticky,
  // unchanged -- this is bookkeeping on an already-trusted outcome, never a new settle).
  const cu4 = await jget(await doPost("/update-confirm", null, { recommendedVersion: "0.9.0" }));
  ok("confirmUpdateSettled: matching recommendedVersion -> cleared:true", cu4.cleared === true);
  const afterCu4 = await jget(await doGet("/update-status"));
  const lastAfterCu4 = afterCu4.last as { outcome?: string; recommendedVersion?: string; confirmationPending?: boolean } | null;
  ok("the flag reads false after a genuine confirm (not merely absent)", lastAfterCu4?.confirmationPending === false);
  ok("the rest of the last record is untouched by the confirm", lastAfterCu4?.outcome === "applied" && lastAfterCu4?.recommendedVersion === "0.9.0");
  ok("confirmUpdateSettled never touches floors (bookkeeping only, not a new settle)", JSON.stringify(afterCu4.floors) === cu1FloorsBefore);
  ok("confirmUpdateSettled never appends to history (not a new settle event)", Array.isArray(afterCu4.history) && (afterCu4.history as unknown[]).length === cu1HistoryLenBefore);
  // CU5: a REDUNDANT confirm (already cleared) -> clean no-op (confirmationPending is no longer === true).
  const cu5 = await jget(await doPost("/update-confirm", null, { recommendedVersion: "0.9.0" }));
  ok("a redundant confirm after clearing -> cleared:false (idempotent)", cu5.cleared === false);
  // CU6: a settle whose outcome is NOT applied (e.g. rolled-back) never confirms, even naming its version.
  await doPost("/update-settled", null, { outcome: "rolled-back", recommendedVersion: "0.9.5", fromVersion: "cu-a", toVersion: "cu-b", at: 301, by: "o" });
  const cu6 = await jget(await doPost("/update-confirm", null, { recommendedVersion: "0.9.5" }));
  ok("a rolled-back outcome is never confirmable (cleared:false)", cu6.cleared === false);

  // ============================================================================================
  // DP-0 update provenance: artefactSha384 (the signed channel digest the apply verified) rides
  // the pending record, the settled record, the console's own settled record and the history
  // ring; a digest-less write stays digest-less (the legacy shape, byte-compatible).
  // ============================================================================================
  const DIGEST_A = "a".repeat(96);
  const DIGEST_B = "b".repeat(96);
  // AS1: a promote carrying the digest persists it on the pending record.
  const as1 = await jget(await doPost("/update-pending", null, { fromVersion: "vP", toVersion: "vQ", recommendedVersion: "0.9.6", promotedAt: 400, promotedBy: "o", artefactSha384: DIGEST_A }));
  ok("setUpdatePending persists artefactSha384 (present arm)", (as1.pending as { artefactSha384?: string } | null)?.artefactSha384 === DIGEST_A);
  // AS2: the settle carrying the digest lands it on the engine's last record AND in the history ring.
  const as2 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.9.6", fromVersion: "vP", toVersion: "vQ", at: 401, by: "o", artefactSha384: DIGEST_A }));
  ok("setUpdateSettled persists artefactSha384 on last (present arm)", (as2.last as { artefactSha384?: string } | null)?.artefactSha384 === DIGEST_A);
  ok("the settled digest rode into the history ring", Array.isArray(as2.history) && (as2.history as Array<{ artefactSha384?: string }>).some((h) => h.artefactSha384 === DIGEST_A));
  // AS3: a console settle carries its OWN bundle digest into lastConsole (never the engine's).
  const as3 = await jget(await doPost("/update-settled", null, { outcome: "applied", component: "console", recommendedVersion: "0.9.7", fromVersion: "cv-9", toVersion: "cv-10", at: 402, by: "o", artefactSha384: DIGEST_B }));
  ok("a console settle persists its own artefactSha384 on lastConsole", (as3.lastConsole as { artefactSha384?: string } | null)?.artefactSha384 === DIGEST_B);
  ok("the engine's last keeps ITS digest across a console settle", (as3.last as { artefactSha384?: string } | null)?.artefactSha384 === DIGEST_A);
  // AS4: absent stays absent -- a digest-less settle writes a record without the field.
  const as4 = await jget(await doPost("/update-settled", null, { outcome: "applied", recommendedVersion: "0.9.8", fromVersion: "vQ", toVersion: "vR", at: 403, by: "o" }));
  ok("a digest-less settle stays digest-less (absent arm)", (as4.last as { artefactSha384?: string } | null)?.artefactSha384 === undefined);

  // ============================================================================================
  // ACCOUNT DISCOVERY (getDiscoveryConfig / getDiscoveryStatus / setDiscoveryToken).
  // ============================================================================================
  const VALID_CF = "cfat-discovery-token-abcdef"; // matches /^[A-Za-z0-9_.-]{20,300}$/

  // D1/D2: absent config + absent status.
  const d1 = await jget(await doGet("/sources/discovery-config"));
  ok("getDiscoveryConfig: absent -> null", d1.config === null);
  const d2 = await jget(await doGet("/sources/discovery-status"));
  ok("getDiscoveryStatus: absent -> {present:false}", d2.present === false);

  // D3: a non-owner is refused (the clear path routes straight to setDiscoveryToken; the owner gate
  // throws before the token===null branch).
  ok("setDiscoveryToken: non-owner refused (403)", (await doPost("/sources/discovery-token", viewer, { token: null })).status === 403);

  // D4: a non-string token -> "" -> fails the shape check (400).
  ok("setDiscoveryToken: non-string token -> 400", (await doPost("/sources/discovery-token", ownerAccess, { token: 12345 })).status === 400);

  // D5: a too-short string token fails the shape check (400).
  ok("setDiscoveryToken: malformed string token -> 400", (await doPost("/sources/discovery-token", ownerAccess, { token: "short" })).status === 400);

  // D6: a valid token but a NON-ARRAY accountsSeen -> no accounts -> 400.
  ok("setDiscoveryToken: valid token, non-array accountsSeen -> 400", (await doPost("/sources/discovery-token", ownerAccess, { token: VALID_CF, accountsSeen: "notarray" })).status === 400);

  // D7: a valid token but every account entry is invalid (non-string id / empty id / no id) -> 400.
  const d7 = await doPost("/sources/discovery-token", ownerAccess, { token: VALID_CF, accountsSeen: [{ id: 123 }, { id: "" }, { name: "x" }] });
  ok("setDiscoveryToken: all-invalid account entries -> 400", d7.status === 400);

  // D8: success, ONE account, as the Access owner (email + sourceIp). Single -> auto-select + engine account.
  const d8 = await doPost("/sources/discovery-token", ownerAccess, { token: VALID_CF, accountsSeen: [{ id: "acct-1", name: "Acct One" }] });
  ok("setDiscoveryToken: single account succeeds (200)", d8.status === 200);
  const d8b = await jget(d8);
  ok("setDiscoveryToken: single -> auto-selected + engine account", sorted(d8b.selected as string[]) === sorted(["acct-1"]) && d8b.engineAccountId === "acct-1");
  ok("setDiscoveryToken: setBy is the owner email (email-present arm)", d8b.setBy === OWNER_EMAIL);
  ok("getDiscoveryStatus: enabledSources defaults to [] (absent `?? []` arm)", sorted(d8b.enabledSources as string[]) === sorted([]));

  // getDiscoveryConfig present arm (internal route returns the stored config).
  const dcfg = await jget(await doGet("/sources/discovery-config"));
  ok("getDiscoveryConfig: present -> stored config", (dcfg.config as { selected?: string[] } | null)?.selected?.[0] === "acct-1");

  // D9: success, MULTIPLE accounts, as the token break-glass (null email). Name fallback to id; not-single
  // -> empty selection + null engine account; setBy null.
  const d9 = await doPost("/sources/discovery-token", tokenOwner, { token: VALID_CF, accountsSeen: [{ id: "a1", name: "A1" }, { id: "a2" }, { id: "a3", name: "" }] });
  ok("setDiscoveryToken: multi-account succeeds (200)", d9.status === 200);
  const d9b = await jget(d9);
  ok("setDiscoveryToken: multi -> no auto-select, null engine account", (d9b.selected as string[]).length === 0 && d9b.engineAccountId === null);
  ok("setDiscoveryToken: setBy null for the token caller (null-email arm)", d9b.setBy === null);
  const d9names = (d9b.accountsSeen as Array<{ id: string; name: string }>).map((a) => a.name);
  ok("setDiscoveryToken: name falls back to id when absent/empty", sorted(d9names) === sorted(["A1", "a2", "a3"]));

  // ============================================================================================
  // ADDED TOKEN-SOURCE SET (setEnabledSources) + getDiscoveryStatus enabledSources-present arm.
  // ============================================================================================
  // S1: non-owner refused.
  ok("setEnabledSources: non-owner refused (403)", (await doPost("/sources/enable", viewer, { sources: ["workers"] })).status === 403);

  // S2: owner SET, deduped. A type outside the closed set is REFUSED (POSTCONDITION) rather than
  // filtered out with a 200: this used to submit "bogus" alongside two legal types and assert a success that
  // quietly dropped it, which is the "I added it and it never appeared" shape.
  const s2bad = await doPost("/sources/enable", ownerAccess, { sources: ["workers", "stream", "bogus", "workers"] });
  ok("setEnabledSources: an unknown type is refused 400, not dropped with a success", s2bad.status === 400);
  // ASSERT THE EXACT MESSAGE, not the status. A mutant that keeps the 400 and guts only the wording
  // survived an earlier draft of this assertion, which only asked whether the message CONTAINED the
  // offending value: the template around the gutted phrase still carried it. The choices are derived from
  // the engine's own exported list rather than restated, so a sixth source type needs no edit here.
  const s2badWant = `not a source type this engine can add: bogus. Choose from ${SELECTABLE_TOKEN_SOURCE_TYPES.join(", ")}`;
  const s2badMsg = String((await jget(s2bad)).error ?? "");
  ok("setEnabledSources: the refusal carries the EXACT message, naming the value and the choices", s2badMsg === s2badWant);
  ok("setEnabledSources: the refused write stored nothing", ((await jget(await doGet("/sources/discovery-status"))).enabledSources as string[] | undefined ?? []).length === 0);
  const s2 = await doPost("/sources/enable", ownerAccess, { sources: ["workers", "stream", "workers"] });
  ok("setEnabledSources: owner SET deduped (200)", s2.status === 200);
  ok("setEnabledSources: reflects {stream,workers}", sorted(((await jget(s2)).enabledSources as string[])) === sorted(["stream", "workers"]));

  // S3: getDiscoveryStatus now carries enabledSources (the present `?? []` arm).
  const s3 = await jget(await doGet("/sources/discovery-status"));
  ok("getDiscoveryStatus: enabledSources present arm", sorted(s3.enabledSources as string[]) === sorted(["stream", "workers"]));

  // S4: non-array sources clears the set, as the token caller (null-email audit arm).
  const s4 = await doPost("/sources/enable", tokenOwner, { sources: "notarray" });
  ok("setEnabledSources: non-array sources -> empty set (200)", s4.status === 200 && ((await jget(s4)).enabledSources as string[]).length === 0);

  // ============================================================================================
  // ACCOUNT SELECTION (setDiscoveryAccounts). The config now lists a1/a2/a3 (from D9).
  // ============================================================================================
  // A1: non-owner refused (the gated route applies inline with the gate off, so the method's own
  // owner re-check throws -> 403).
  ok("setDiscoveryAccounts: non-owner refused (403)", (await doPost("/sources/discovery-accounts", viewer, { selected: ["a1"] })).status === 403);

  // A3: owner success, known-id filter + dedupe + a known engine account.
  const a3 = await doPost("/sources/discovery-accounts", ownerAccess, { selected: ["a1", "a2", "bogus", "a1"], engineAccountId: "a2" });
  ok("setDiscoveryAccounts: success (200)", a3.status === 200);
  const a3b = await jget(a3);
  ok("setDiscoveryAccounts: keeps known + dedup, drops unknown", sorted(a3b.selected as string[]) === sorted(["a1", "a2"]));
  ok("setDiscoveryAccounts: known engineAccountId is kept", a3b.engineAccountId === "a2");

  // A4: every selected id unknown -> empty selection -> 400.
  ok("setDiscoveryAccounts: all-unknown selection -> 400", (await doPost("/sources/discovery-accounts", ownerAccess, { selected: ["zzz", "yyy"] })).status === 400);

  // A5: non-array selected -> empty selection -> 400 (the non-array `: []` arm).
  ok("setDiscoveryAccounts: non-array selected -> 400", (await doPost("/sources/discovery-accounts", ownerAccess, { selected: "notarray" })).status === 400);

  // A6: a known selection but an UNKNOWN (string) engineAccountId -> null (the `&&` right-false arm),
  // as the token caller (null-email audit arm).
  const a6 = await jget(await doPost("/sources/discovery-accounts", tokenOwner, { selected: ["a1"], engineAccountId: "not-a-known-id" }));
  ok("setDiscoveryAccounts: unknown engineAccountId -> null", a6.engineAccountId === null && sorted(a6.selected as string[]) === sorted(["a1"]));

  // A7: a NON-STRING engineAccountId -> null (the `&&` left-false short-circuit).
  const a7 = await jget(await doPost("/sources/discovery-accounts", ownerAccess, { selected: ["a2"], engineAccountId: 999 }));
  ok("setDiscoveryAccounts: non-string engineAccountId -> null", a7.engineAccountId === null && sorted(a7.selected as string[]) === sorted(["a2"]));

  // ============================================================================================
  // DISCOVERY TOKEN CLEAR (token:null) -> direct setDiscoveryToken clear path.
  // ============================================================================================
  // C1: owner clear (email-present clear-audit arm).
  const c1 = await doPost("/sources/discovery-token", ownerAccess, { token: null });
  ok("setDiscoveryToken: owner clear -> {present:false}", c1.status === 200 && (await jget(c1)).present === false);
  // C2: token-caller clear (null-email clear-audit arm); idempotent.
  const c2 = await doPost("/sources/discovery-token", tokenOwner, { token: null });
  ok("setDiscoveryToken: token-caller clear -> {present:false}", c2.status === 200 && (await jget(c2)).present === false);

  // N: with NO config, both selection and enable are clean 400s (the no-config `if (!c) throw` arms).
  await s.storage.delete(DISCOVERY_KEY);
  ok("setDiscoveryAccounts: no config -> 400", (await doPost("/sources/discovery-accounts", ownerAccess, { selected: ["a1"] })).status === 400);
  ok("setEnabledSources: no config -> 400", (await doPost("/sources/enable", ownerAccess, { sources: ["workers"] })).status === 400);

  // ============================================================================================
  // ASSURANCE LICENCE (getLicenceRecord / setLicenceToken).
  // ============================================================================================
  const VALID_LICENCE = "a".repeat(20) + "." + "b".repeat(20); // 41 chars, two base64url segments
  const VALID_LICENCE2 = "c".repeat(25) + "." + "d".repeat(15);

  // L1: absent record.
  ok("getLicenceRecord: absent -> {token:null}", (await jget(await doGet("/licence-token"))).token === null);

  // L2: non-owner refused (clear path).
  ok("setLicenceToken: non-owner refused (403)", (await doPost("/licence-token", viewer, { token: null })).status === 403);

  // L3: non-string token -> "" -> length<32 -> 400.
  ok("setLicenceToken: non-string token -> 400", (await doPost("/licence-token", ownerAccess, { token: 12345 })).status === 400);
  // L4: a too-short token -> the length<32 operand.
  ok("setLicenceToken: too-short token -> 400", (await doPost("/licence-token", ownerAccess, { token: "abc" })).status === 400);
  // L5: a long-enough but wrong-shape token (no dot) -> the regex operand.
  ok("setLicenceToken: wrong-shape token -> 400", (await doPost("/licence-token", ownerAccess, { token: "a".repeat(40) })).status === 400);
  // L6: an over-long token -> the length>20000 operand.
  ok("setLicenceToken: over-long token -> 400", (await doPost("/licence-token", ownerAccess, { token: "a".repeat(20001) })).status === 400);

  // L7: owner success (email-present arms).
  const l7 = await doPost("/licence-token", ownerAccess, { token: VALID_LICENCE });
  const l7b = await jget(l7);
  ok("setLicenceToken: owner activate -> {present:true}", l7.status === 200 && l7b.present === true);
  ok("setLicenceToken: setBy is the owner email", l7b.setBy === OWNER_EMAIL);

  // L8: present record carries the token on the internal read.
  ok("getLicenceRecord: present -> stored token", (await jget(await doGet("/licence-token"))).token === VALID_LICENCE);

  // L9: token-caller success (null-email arms).
  const l9 = await jget(await doPost("/licence-token", tokenOwner, { token: VALID_LICENCE2 }));
  ok("setLicenceToken: token-caller activate -> setBy null", l9.present === true && l9.setBy === null);

  // L10/L11: clear, owner then token-caller (both clear-audit arm sides).
  ok("setLicenceToken: owner clear -> {present:false}", (await jget(await doPost("/licence-token", ownerAccess, { token: null }))).present === false);
  ok("setLicenceToken: token-caller clear -> {present:false}", (await jget(await doPost("/licence-token", tokenOwner, { token: null }))).present === false);

  // ============================================================================================
  // ENGINE-ACCOUNT VERIFICATION: getVerifiedEngineAccount
  // / recordVerifiedEngineAccount, reached via GET/POST /sources/engine-account-verified. Unlike every
  // other mixin method exercised above, this one is NOT owner-gated (it is the engine recording a fact it
  // just proved to itself against the live Cloudflare API, never an operator handing it a credential or a
  // choice), so it is driven with NO caller at all to prove that directly.
  // ============================================================================================
  // Parameterised over a scheduler's own stub (unlike doGet/doPost above, which are closed over `s`),
  // since the "never overwritten" proof below needs genuinely fresh DOs, not the one already exercised.
  const doGetOn = (stub: { fetch: DurableObjectStub["fetch"] }, path: string): Promise<Response> =>
    stub.fetch(`https://scheduler.internal${path}`, { method: "GET" });
  const doPostOn = (stub: { fetch: DurableObjectStub["fetch"] }, path: string, body: unknown): Promise<Response> =>
    stub.fetch(`https://scheduler.internal${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  const vs2 = makeScheduler(); // a fresh DO: the "never overwritten" proof needs a genuinely empty start

  // V1: absent before anything is recorded.
  ok("getVerifiedEngineAccount: absent on a fresh DO -> null", (await jget(await doGetOn(vs2.stub, "/sources/engine-account-verified"))) === null);

  // V2: a malformed/blank accountId is dropped silently, nothing stored, no caller required.
  const v2 = await jget(await doPostOn(vs2.stub, "/sources/engine-account-verified", { accountId: "   " }));
  ok("recordVerifiedEngineAccount: blank accountId -> {accountId:null}, nothing stored", v2.accountId === null);
  ok("getVerifiedEngineAccount: still absent after a blank attempt", (await jget(await doGetOn(vs2.stub, "/sources/engine-account-verified"))) === null);

  // V3: NO CALLER AT ALL succeeds (the point of this being unlike setDiscoveryToken/setDiscoveryAccounts
  // above, both of which 403 a non-owner). "via" defaults to "attach" when omitted or not "update-apply".
  const v3 = await jget(await doPostOn(vs2.stub, "/sources/engine-account-verified", { accountId: "acct-verified-1" }));
  ok("recordVerifiedEngineAccount: no caller, no via -> succeeds and defaults via to attach", v3.accountId === "acct-verified-1");
  const v3b = await jget(await doGetOn(vs2.stub, "/sources/engine-account-verified"));
  ok("getVerifiedEngineAccount: reads back the stored record", v3b.accountId === "acct-verified-1" && v3b.via === "attach" && typeof v3b.verifiedAt === "number");

  // V4: NEVER OVERWRITTEN once set -- the account a running Worker script lives in cannot change under
  // it, so a second call (an ordinary later attach or apply) is an idempotent no-op, not a fresh write.
  const v4 = await jget(await doPostOn(vs2.stub, "/sources/engine-account-verified", { accountId: "acct-different-2", via: "update-apply" }));
  ok("recordVerifiedEngineAccount: a second, different accountId does NOT overwrite the first", v4.accountId === "acct-verified-1");
  const v4b = await jget(await doGetOn(vs2.stub, "/sources/engine-account-verified"));
  ok("getVerifiedEngineAccount: still the first record after the second call", v4b.accountId === "acct-verified-1" && v4b.via === "attach");

  // V5: a fresh DO's first call with via:"update-apply" is honoured (proves the parameter is read, not
  // just defaulted every time -- V3 above proved the default, this proves the explicit value).
  const vs3 = makeScheduler();
  const v5 = await jget(await doPostOn(vs3.stub, "/sources/engine-account-verified", { accountId: "acct-via-apply", via: "update-apply" }));
  ok("recordVerifiedEngineAccount: via:update-apply is honoured on first write", v5.accountId === "acct-via-apply");
  const v5b = await jget(await doGetOn(vs3.stub, "/sources/engine-account-verified"));
  ok("getVerifiedEngineAccount: via reads back as update-apply", v5b.via === "update-apply");

  // One call against the ORIGINAL `s` DO too, so the audit-effects block below (which reads `s`'s own
  // log) can assert the recorded row.
  await doPost("/sources/engine-account-verified", null, { accountId: "acct-on-primary-do" });

  // ============================================================================================
  // AUDIT EFFECTS: the caller-attribution arms ties to a real recorded event. The Access owner
  // stamps email + "access" + sourceIp; the token break-glass stamps null + "token" + null.
  // ============================================================================================
  const log = await jget(await doGet("/audit?limit=2000"));
  const events = (log.events as AuditEvt[]) ?? [];
  const has = (action: string, email: string | null, method: string, ip: string | null): boolean =>
    events.some((e) => e.action === action && e.actorEmail === email && e.actorMethod === method && e.sourceIp === ip && e.outcome === "success");

  ok("audit: discovery-token-set by Access owner (email/access/ip)", has("discovery-token-set", OWNER_EMAIL, "access", OWNER_IP));
  ok("audit: discovery-token-set by token caller (null/token/null)", has("discovery-token-set", null, "token", null));
  ok("audit: discovery-token-cleared by Access owner", has("discovery-token-cleared", OWNER_EMAIL, "access", OWNER_IP));
  ok("audit: discovery-token-cleared by token caller", has("discovery-token-cleared", null, "token", null));
  ok("audit: discovery-accounts-set by Access owner", has("discovery-accounts-set", OWNER_EMAIL, "access", OWNER_IP));
  ok("audit: discovery-accounts-set by token caller", has("discovery-accounts-set", null, "token", null));
  ok("audit: discovery-sources-set by Access owner", has("discovery-sources-set", OWNER_EMAIL, "access", OWNER_IP));
  ok("audit: discovery-sources-set by token caller", has("discovery-sources-set", null, "token", null));
  ok("audit: licence-activated by Access owner", has("licence-activated", OWNER_EMAIL, "access", OWNER_IP));
  ok("audit: licence-activated by token caller", has("licence-activated", null, "token", null));
  ok("audit: licence-cleared by Access owner", has("licence-cleared", OWNER_EMAIL, "access", OWNER_IP));
  ok("audit: licence-cleared by token caller", has("licence-cleared", null, "token", null));
  // engine-account-verified: recorded with NO caller at all (null/engine/null), unlike every other row
  // above -- proof this is the engine recording a fact about itself, never an attributed operator action.
  // actorMethod "engine" (not "access"): an "access" row must never hard-code sourceIp:null, since "access"
  // means an authenticated human who always has a real address.
  ok("audit: engine-account-verified with no caller (null/engine/null)", has("engine-account-verified", null, "engine", null));

  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
