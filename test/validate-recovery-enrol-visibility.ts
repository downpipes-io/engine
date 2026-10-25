// validate-recovery-enrol-visibility: a passkey enrolled from a session that a recovery code minted is named in the
// audit chain, in the alert, in an email to every other Owner, and in the support pack.
//
// THE GAP. A recovery code is single use, but the session it signs in can enrol a passkey, and that passkey is a
// standing credential. The enrolment arrived indistinguishable from an ordinary passkey session: one generic
// credential-change alert, no audit row, nothing in the pack.
//
// WHAT THIS FILE CHECKS, against a real Durable Object through the production router:
//   A. a passkey enrolled from an ordinary passkey session writes no recovery row, raises the generic alert and
//      emails nobody (negative control);
//   B. a passkey enrolled from a recovery-code session writes one passkey-recovery-enrol row naming the member;
//   C. its alert says the passkey was enrolled from a session signed in with a recovery code;
//   D. every other Owner is emailed, the enrolling member and a non-Owner are not;
//   E. the support pack's audit excerpt lists the recovery-code sign-in and the enrolment, and not a failed attempt;
//   F. with no invite sender configured, the enrolment still succeeds and is audited and alerted;
//   G. when the mail binding rejects the send, the enrolment still succeeds and the failure is counted;
//   H. with one Owner address the engine cannot mail and one it can, the trace says partial, with counts and no address.
// Every outcome of the Owner email (sent, partial, skipped, failed) leaves a passkey-recovery-enrol-notice audit row,
// a sentence in the alert, and a line in the support pack.
//
// Run: node test/validate-recovery-enrol-visibility.ts

import type { AuditEvent } from "../src/admin/audit.ts";
import { fetchConfigEvents } from "../src/admin/support-sections-audit.ts";
import { noticeAuditOutcome, RECOVERY_ENROL_SUBJECT } from "../src/admin/router-notify.ts";
import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import {
  ADMIN_TOKEN,
  buildAttestation,
  challengeFor,
  enrolBootstrapOwner,
  extractSessionCookie,
  grantRoleViaToken,
  loginBegin,
  loginFinish,
  makeAuthenticator,
  makeScheduler,
  ORIGIN,
  post,
  registerBegin,
  registerFinish,
  signAssertion,
  type Authenticator,
} from "./validate-passkey-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const OWNER1 = "owner-one-rev@acme.example";
const OWNER2 = "owner-two-rev@acme.example";
const VIEWER = "viewer-rev@acme.example";

type Emission = { event?: string; detail?: string };
type Sent = { to?: string; subject?: string; text?: string };

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 120));

async function main(): Promise<void> {
  const base = makeScheduler();
  const inner = base.env.SCHEDULER.get(base.env.SCHEDULER.idFromName("x"));
  const resolves: Emission[] = [];
  const signals: string[] = [];
  const wrapped = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/auth-signal") && typeof init?.body === "string") {
        try {
          signals.push(String((JSON.parse(init.body) as { name?: unknown }).name));
        } catch {
          // not a signal body this file can read; nothing recorded
        }
      }
      if (url.endsWith("/notify/resolve") && typeof init?.body === "string") {
        try {
          resolves.push(((JSON.parse(init.body) as { emission?: Emission }).emission ?? {}) as Emission);
        } catch {
          // not a resolve body this file can read; nothing recorded
        }
      }
      return inner.fetch(input, init);
    },
  } as unknown as DurableObjectStub;
  const sent: Sent[] = [];
  const scheduler = { idFromName: () => ({}), get: () => wrapped };
  const env = {
    ...base.env,
    SCHEDULER: scheduler,
    EMAIL: { send: async (m: Sent): Promise<void> => { sent.push(m); } },
    INVITE_EMAIL_FROM: "notices@acme.example",
  } as unknown as Env;
  const brokenMailEnv = { ...env, EMAIL: { send: async (): Promise<void> => { throw new Error("rejected"); } } } as unknown as Env;
  const noMailEnv = { ...env, EMAIL: undefined, INVITE_EMAIL_FROM: undefined } as unknown as Env;

  const audit = async (): Promise<Array<AuditEvent & { outcome?: string }>> => {
    const r = await handleAdmin(new Request("https://engine.example/admin/audit?limit=1000", { headers: { authorization: `Bearer ${ADMIN_TOKEN}`, origin: ORIGIN } }), env);
    return ((await r.json()) as { events?: Array<AuditEvent & { outcome?: string }> }).events ?? [];
  };
  const recoveryRows = async (): Promise<AuditEvent[]> => (await audit()).filter((e) => e.action === ("passkey-recovery-enrol" as AuditEvent["action"]));
  type NoticeTarget = { kind?: string; notice?: { state?: string; reason?: string; owners?: number; sent?: number; skipped?: number; failed?: number } };
  const noticeRows = async (): Promise<Array<AuditEvent & { target?: NoticeTarget }>> => ((await audit()).filter((e) => e.action === ("passkey-recovery-enrol-notice" as AuditEvent["action"])) as Array<AuditEvent & { target?: NoticeTarget }>).sort((a, b) => a.seq - b.seq);
  const lastNotice = async (): Promise<NonNullable<NoticeTarget["notice"]> | undefined> => (await noticeRows()).at(-1)?.target?.notice;
  const lastPackNotice = async (): Promise<Record<string, unknown> | undefined> => ((await fetchConfigEvents(inner)).events as Array<Record<string, unknown>>).filter((e) => e.action === "passkey-recovery-enrol-notice").at(-1);
  const notices = (): Sent[] => sent.filter((m) => m.subject === RECOVERY_ENROL_SUBJECT);
  const credAlerts = (from: number): Emission[] => resolves.slice(from).filter((e) => e.event === "auth-credential-change" && typeof e.detail === "string" && e.detail.includes("passkey"));
  const assertWith = async (auth: Authenticator, challenge: string): ReturnType<typeof signAssertion> => {
    const asr = await signAssertion(auth, challenge);
    auth.signCount += 1;
    return asr;
  };

  // ---- setup: two Owners and a viewer ------------------------------------------------------------------
  const key1 = await makeAuthenticator("ES256");
  const boot = await enrolBootstrapOwner(env, key1, OWNER1);
  const codes = (boot.json.recoveryCodes as string[] | undefined) ?? [];
  ok("setup: the first Owner enrols and holds recovery codes", boot.json.ok === true && codes.length === 10);
  const key2 = await makeAuthenticator("ES256");
  const inv2 = await grantRoleViaToken(env, OWNER2, "owner");
  const b2 = await registerBegin(env, OWNER2, { inviteToken: inv2 });
  const f2 = await registerFinish(env, OWNER2, await buildAttestation(key2, challengeFor(b2)), { inviteToken: inv2 });
  ok("setup: a second Owner enrols through an invite", f2.json.ok === true);
  const keyV = await makeAuthenticator("ES256");
  const invV = await grantRoleViaToken(env, VIEWER, "viewer");
  const bV = await registerBegin(env, VIEWER, { inviteToken: invV });
  const fV = await registerFinish(env, VIEWER, await buildAttestation(keyV, challengeFor(bV)), { inviteToken: invV });
  ok("setup: a viewer enrols through an invite", fV.json.ok === true);
  sent.length = 0;

  // ---- A. an ordinary passkey session: nothing recovery-shaped -------------------------------------------
  console.log("\nA. self-add from an ordinary passkey session (negative control)");
  const lb = await loginBegin(env, OWNER1);
  const lf = await loginFinish(env, lb.json.challengeId as string, await assertWith(key1, challengeFor(lb)));
  const normal = extractSessionCookie(lf.setCookie);
  ok("A0: a passkey login mints a session", lf.json.ok === true && normal !== null);
  const alertsA = resolves.length;
  const keyA = await makeAuthenticator("ES256");
  const bA = await registerBegin(env, OWNER1, { cookie: normal!, origin: ORIGIN });
  const fA = await registerFinish(env, OWNER1, await buildAttestation(keyA, challengeFor(bA)), { cookie: normal!, origin: ORIGIN });
  await settle();
  ok("A1: the ordinary session enrols a passkey (self-add)", fA.json.ok === true && fA.json.enrolmentPath === "self-add");
  ok("A2: the response carries no recovery-session marker", !("recoveredSession" in fA.json));
  ok("A3: no passkey-recovery-enrol row is written", (await recoveryRows()).length === 0);
  const aAlerts = credAlerts(alertsA);
  ok("A4: the generic credential alert is raised once", aAlerts.length === 1 && aAlerts[0]!.detail === `A new passkey credential was enrolled for ${OWNER1}.`);
  ok("A5: the alert does not mention a recovery code", aAlerts.every((e) => !/recovery/i.test(e.detail ?? "")));
  ok("A6: no Owner is emailed", notices().length === 0);
  ok("A7: no notice row is written", (await noticeRows()).length === 0);
  ok("A8: the alert carries no Owner-email sentence", aAlerts.every((e) => !/Owners? (were|was) (not )?emailed/i.test(e.detail ?? "")));

  // ---- B-E. a recovery-code session -----------------------------------------------------------------------
  console.log("\nB. self-add from a recovery-code session");
  const rec = await post(env, "/admin/auth/recovery", { email: OWNER1, code: codes[0]! });
  const recCookie = extractSessionCookie(rec.setCookie);
  ok("B0: a recovery code signs in", rec.status === 200 && rec.json.ok === true && recCookie !== null);
  const alertsB = resolves.length;
  const keyB = await makeAuthenticator("ES256");
  const bB = await registerBegin(env, OWNER1, { cookie: recCookie!, origin: ORIGIN });
  const fB = await registerFinish(env, OWNER1, await buildAttestation(keyB, challengeFor(bB)), { cookie: recCookie!, origin: ORIGIN });
  await settle();
  ok("B1: the recovery session enrols a passkey (self-add)", fB.json.ok === true && fB.json.enrolmentPath === "self-add");
  const rows = (await recoveryRows()) as Array<AuditEvent & { target?: { kind?: string; email?: string; role?: string } }>;
  ok("B2: exactly one passkey-recovery-enrol row is written", rows.length === 1);
  const row = rows[0];
  ok("B3: the row names the member as actor and target, with the role", row !== undefined && row.actorEmail === OWNER1 && row.outcome === "success" && row.target?.kind === "role" && row.target.email === OWNER1 && row.target.role === "owner");

  console.log("\nC. the alert");
  const bAlerts = credAlerts(alertsB);
  ok("C1: one credential alert is raised", bAlerts.length === 1);
  ok("C2: it says the passkey was enrolled from a session signed in with a recovery code", /session signed in with a recovery code/.test(bAlerts[0]?.detail ?? ""));
  ok("C3: it names the member and carries no code or credential value", (bAlerts[0]?.detail ?? "").includes(OWNER1) && !codes.some((c) => (bAlerts[0]?.detail ?? "").includes(c)));

  console.log("\nD. the other Owners");
  const mails = notices();
  ok("D1: exactly one notice is sent", mails.length === 1);
  ok("D2: it goes to the other Owner", mails[0]?.to === OWNER2);
  ok("D3: the enrolling member and the viewer are not emailed", mails.every((m) => m.to !== OWNER1 && m.to !== VIEWER));
  ok("D4: the notice names the member and the recovery code", (mails[0]?.text ?? "").includes(OWNER1) && /recovery code/.test(mails[0]?.text ?? ""));

  const sentNotice = await lastNotice();
  ok("D5: a notice row records state sent, one Owner, one sent", sentNotice?.state === "sent" && sentNotice.owners === 1 && sentNotice.sent === 1 && sentNotice.skipped === 0 && sentNotice.failed === 0);
  ok("D6: the sent trace carries no address", (await noticeRows())[0] !== undefined && !JSON.stringify((await noticeRows())[0]?.target ?? {}).includes(OWNER2));
  ok("D7: the alert says the other Owners were emailed", /The other Owners were emailed\./.test(bAlerts[0]?.detail ?? ""));
  const packSent = await lastPackNotice();
  ok("D8: the support pack shows the sent trace beside the enrolment", packSent?.noticeState === "sent" && packSent.noticeSent === 1 && packSent.noticeOwners === 1);

  console.log("\nE. the support pack");
  const failedTry = await post(env, "/admin/auth/recovery", { email: OWNER1, code: "wrong-code-0000" });
  ok("E0: a wrong recovery code is refused", failedTry.json.ok !== true);
  const pack = await fetchConfigEvents(inner);
  const actions = (pack.events as Array<{ action: string; seq: number }>).map((e) => e.action);
  ok("E1: the excerpt lists the passkey-recovery-enrol row", actions.includes("passkey-recovery-enrol"));
  ok("E2: the excerpt lists the recovery-code sign-in", actions.includes("recovery-code-used"));
  const all = await audit();
  const failedRows = all.filter((e) => e.action === "recovery-code-used" && e.outcome !== "success").length;
  ok("E3: the chain holds a failed recovery-code row that the excerpt leaves out", failedRows > 0 && actions.filter((a) => a === "recovery-code-used").length === all.filter((e) => e.action === "recovery-code-used" && e.outcome === "success").length);
  const enrolSeq = (pack.events as Array<{ action: string; seq: number }>).find((e) => e.action === "passkey-recovery-enrol")?.seq ?? -1;
  const useSeq = (pack.events as Array<{ action: string; seq: number }>).find((e) => e.action === "recovery-code-used")?.seq ?? -1;
  ok("E4: the sign-in sits before the enrolment in the excerpt", useSeq > 0 && enrolSeq > useSeq);

  // ---- F. no invite sender -----------------------------------------------------------------------------------
  console.log("\nF. recovery-session enrolment with no invite sender");
  const rec2 = await post(noMailEnv, "/admin/auth/recovery", { email: OWNER1, code: codes[1]! });
  const cookie2 = extractSessionCookie(rec2.setCookie);
  sent.length = 0;
  const alertsF = resolves.length;
  const bF = await registerBegin(noMailEnv, OWNER1, { cookie: cookie2!, origin: ORIGIN });
  const fF = await registerFinish(noMailEnv, OWNER1, await buildAttestation(await makeAuthenticator("ES256"), challengeFor(bF)), { cookie: cookie2!, origin: ORIGIN });
  await settle();
  ok("F1: the enrolment still succeeds", fF.json.ok === true);
  ok("F2: it is still audited (a second row)", (await recoveryRows()).length === 2);
  ok("F3: it is still alerted with the recovery wording", credAlerts(alertsF).some((e) => /recovery code/.test(e.detail ?? "")));
  ok("F4: no email is attempted", sent.length === 0);
  const skippedNotice = await lastNotice();
  ok("F5: a notice row records state skipped with reason mail-not-configured", skippedNotice?.state === "skipped" && skippedNotice.reason === "mail-not-configured" && skippedNotice.sent === 0);
  ok("F6: the alert says plainly that the other Owners were not emailed", credAlerts(alertsF).some((e) => (e.detail ?? "").includes("Other Owners were not emailed: invite email is not configured.")));
  const packSkipped = await lastPackNotice();
  ok("F7: the support pack shows the skipped trace and its reason", packSkipped?.noticeState === "skipped" && packSkipped.noticeReason === "mail-not-configured");

  // ---- G. a rejected send ------------------------------------------------------------------------------------
  console.log("\nG. recovery-session enrolment when the mail binding rejects the send");
  const rec3 = await post(brokenMailEnv, "/admin/auth/recovery", { email: OWNER1, code: codes[2]! });
  const cookie3 = extractSessionCookie(rec3.setCookie);
  const bG = await registerBegin(brokenMailEnv, OWNER1, { cookie: cookie3!, origin: ORIGIN });
  const fG = await registerFinish(brokenMailEnv, OWNER1, await buildAttestation(await makeAuthenticator("ES256"), challengeFor(bG)), { cookie: cookie3!, origin: ORIGIN });
  await settle();
  ok("G1: the enrolment still succeeds and is audited", fG.json.ok === true && (await recoveryRows()).length === 3);
  ok("G2: the failed notice is counted as a closed auth signal", signals.includes("recovery-enrol-notice-failed"));
  ok("G3: no failure is counted while the send works (A to F)", signals.filter((n) => n === "recovery-enrol-notice-failed").length === 1);
  const failedNotice = await lastNotice();
  ok("G4: a notice row records state failed with one failed send", failedNotice?.state === "failed" && failedNotice.failed === 1 && failedNotice.sent === 0);
  ok("G5: its audit outcome is failed", (await noticeRows()).at(-1)?.outcome === "failed");
  ok("G6: the support pack shows the failed trace", (await lastPackNotice())?.noticeState === "failed");

  // ---- H. one Owner address the engine cannot mail, one it can ----------------------------------------------
  console.log("\nH. a second Owner whose address cannot receive engine email");
  const BAD_OWNER = "owner-three-rev@bad.workers.dev";
  const keyBad = await makeAuthenticator("ES256");
  const invBad = await grantRoleViaToken(env, BAD_OWNER, "owner");
  const bBad = await registerBegin(env, BAD_OWNER, { inviteToken: invBad });
  const fBad = await registerFinish(env, BAD_OWNER, await buildAttestation(keyBad, challengeFor(bBad)), { inviteToken: invBad });
  ok("H0: setup: the third Owner enrols", fBad.json.ok === true);
  sent.length = 0;
  const alertsH = resolves.length;
  const rec4 = await post(env, "/admin/auth/recovery", { email: OWNER1, code: codes[3]! });
  const cookie4 = extractSessionCookie(rec4.setCookie);
  const bH = await registerBegin(env, OWNER1, { cookie: cookie4!, origin: ORIGIN });
  await registerFinish(env, OWNER1, await buildAttestation(await makeAuthenticator("ES256"), challengeFor(bH)), { cookie: cookie4!, origin: ORIGIN });
  await settle();
  const partial = await lastNotice();
  ok("H1: a notice row records state partial: two Owners, one sent, one skipped", partial?.state === "partial" && partial.owners === 2 && partial.sent === 1 && partial.skipped === 1 && partial.failed === 0);
  ok("H2: the valid Owner was emailed and the unusable address was not attempted", notices().length === 1 && notices()[0]?.to === OWNER2);
  ok("H3: the row lists no address", (await noticeRows()).at(-1) !== undefined && !JSON.stringify((await noticeRows()).at(-1)?.target ?? {}).includes("workers.dev"));
  ok("H4: the alert says one of two other Owners was emailed", credAlerts(alertsH).some((e) => (e.detail ?? "").includes("Emailed 1 of 2 other Owners")));
  const packPartial = await lastPackNotice();
  ok("H5: the support pack shows the partial trace with its counts", packPartial?.noticeState === "partial" && packPartial.noticeSent === 1 && packPartial.noticeSkipped === 1 && packPartial.noticeOwners === 2);
  const noticeBase = { owners: 0, sent: 0, skipped: 0, failed: 0 };
  ok("I1: a single-Owner estate (no other Owner to email) is a success row, not a failed one", noticeAuditOutcome({ ...noticeBase, state: "skipped", reason: "no-other-owner" }) === "success" && noticeAuditOutcome({ ...noticeBase, state: "skipped", reason: "mail-not-configured" }) === "failed" && noticeAuditOutcome({ ...noticeBase, state: "sent", owners: 1, sent: 1 }) === "success");

  console.log(failures === 0 ? "\nRECOVERY ENROLMENT VISIBILITY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exit(1);
}

void main();
