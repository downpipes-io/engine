// router-notify.ts -- the engine's outbound ALERT-ROUTING helpers: the two-phase (resolve channels in the
// DO, deliver via the channel adapters here where env lives, post the redaction-safe outcomes back for
// history) routers for a recovery-code alert, an auth-affecting change, a dual-control disarm, and a
// posture regression. All are fully fail-open.
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { type DeliveryRecord, deliverEmission, type NotifyChannel, type NotifyEmission, type NotifyEvent, type Severity, severityOf } from "../notify.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import type { AdminCounterName } from "./diag-records.ts";
import type { PostureRegression } from "./posture.ts";
import { type AlertClass, alertEmissionCounter, alertEmissionCounterAdmitted, type AlertEmissionStage } from "./posture-counters.ts";
import { doURL } from "../do-url.ts";

// nowStamp is the millisecond-precision ISO timestamp the notify emissions carry.
function nowStamp(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

// routeEmission runs the shared two-phase notify transport: resolve the matching channels in the DO,
// deliver via the channel adapters here (where env lives), and post the per-channel outcomes back so the
// DO appends the redaction-safe history. It is fully fail-open: deliverEmission never throws, and the record
// post and the failure counters swallow their own faults rather than being dropped out of the promise chain,
// so awaiting them cannot escape into the caller's path. label names the alert in the non-critical
// record-failure log line.
//
// G274: EVERY stage below can silently swallow a SECURITY alert. The resolve round trip can throw or answer
// unusably; the resolved channel set can be EMPTY (nobody wired a rule for this event, so the takeover
// notification is dropped and nothing says so); every channel's delivery can fail; and the post-delivery
// history write WAS a VOID-ed promise, so an alert that WAS delivered could leave no row in the notify history
// the pack carries. The result: for the disarm, the owner-added and the recovery-code-spent alerts -- the exact
// alerts a customer relies on to learn they are being taken over -- the pack was EMPTIEST when it mattered most.
//
// noteEmissionFailure counts the CLASS x STAGE. The stage is in the KEY, not a payload field, because
// "nobody was told because no channel matched" (wire a rule) and "...because delivery failed" (the webhook is
// dead) are opposite fixes, and a single alertEmissionFailures counter would have made them the same row.
//
// NOISE: only the routeXxxAlert wrappers below reach this counter, and they fire only on SECURITY events. An
// OPERATIONAL notification (backup-success, canary-recovered, update-available) goes through routeNotification
// and never touches it, so a customer who has deliberately wired no channel for one can never trip a fault.
//
// NO-CUSTODY: a closed counter name. Never the channel, the webhook URL, the recipient or the alert detail.
// The class is an ARGUMENT, not a lookup on emission.event (G274). See the note over ALERT_CLASSES: the notify
// events are a routing vocabulary, and three of them are shared by unrelated alerts, so deriving the class from
// the event coalesced "an attacker added an owner" with "the destination was repointed" into one count.
// AlertClass is a closed union, so a call site cannot invent a name.
//
// IT RETURNS ITS WRITE INSTEAD OF DROPPING IT. A bare `void bumpAdminCounter(...)` would leave the counter
// outside routeEmission's promise chain at the moment it fires, so every call site of every routeXxxAlert
// wrapper would hold a promise that resolved BEFORE the only durable record of the dropped alert had been
// written, and handing that promise to the runtime's waitUntil could not cover a write that was never in it.
// Returning the promise is what makes the keep-alive at the call site mean anything. bumpAdminCounters
// swallows its own faults, so awaiting this can never throw into an alert path that is contracted to be
// fail-open.
function noteEmissionFailure(scheduler: DurableObjectStub, cls: AlertClass, stage: AlertEmissionStage): Promise<void> {
  return bumpAdminCounter(scheduler, alertEmissionCounter(cls, stage) as AdminCounterName);
}

async function routeEmission(env: Env, scheduler: DurableObjectStub, emission: NotifyEmission, cls: AlertClass, label: string): Promise<void> {
  let now: NotifyChannel[];
  let rejected = false;
  try {
    const resolveResp = await scheduler.fetch(doURL("/notify/resolve"), {
      method: "POST",
      body: JSON.stringify({ emission }),
      headers: { "content-type": "application/json" },
    });
    // R4: READ THE VERDICT, NOT JUST THE CHANNEL LIST. resolveNotify answers {now:[], digestedCount:0,
    // emission:null} when parseEmission REJECTS the emission -- BEFORE a single rule or channel is consulted --
    // and this code read only `now`, so a rejection was filed as "no-channel". Those are opposite remedies: a
    // customer with a live channel AND a matching rule got the row that says "wire a rule", and no rule change
    // could ever have helped, because the alert never reached rule matching at all. The discriminator was sitting
    // in the response and was being discarded.
    const parsed = (await resolveResp.json()) as { now?: NotifyChannel[]; emission?: NotifyEmission | null };
    if (!Array.isArray(parsed.now)) throw new Error("resolve answered no channel list");
    now = parsed.now;
    rejected = parsed.emission === null;
  } catch (e) {
    // The alert died BEFORE any channel was chosen. It is fully fail-open (the caller's operation already
    // succeeded and must not be undone by an alerting fault), which is exactly why this needed a counter: the
    // throw was swallowed by the caller's guard and the alert simply never happened.
    await noteEmissionFailure(scheduler, cls, "resolve");
    log("error", `${label} resolve failed (non-critical): ${(e as Error).message}`);
    return;
  }
  if (rejected) {
    // The DO REFUSED the emission at the input boundary (an over-long composed detail is the only shape that can
    // do it; see ALERT_EMISSION_COUNTER_NAMES, which names both producers). No rule was consulted and no rule
    // change can fix it, so this must never read as no-channel. Where the vocabulary admits the sharp name it is
    // used; where it does not -- because that class cannot compose a rejectable detail -- the fault still falls to
    // `resolve`, which is true of it ("the alert died before any channel was chosen"), rather than being dropped.
    await noteEmissionFailure(scheduler, cls, alertEmissionCounterAdmitted(cls, "rejected") ? "rejected" : "resolve");
    log("error", `${label} emission refused by the notify input boundary (non-critical)`);
    return;
  }
  if (now.length === 0) {
    await noteEmissionFailure(scheduler, cls, "no-channel");
    return;
  }
  const records: DeliveryRecord[] = await deliverEmission(env, emission, now);
  // deliverEmission never throws; a per-channel failure comes back as a record with ok:false. EVERY channel
  // failing means the alert was addressed and arrived nowhere, which is the same posture outcome as no channel
  // at all and a different cause. A PARTIAL failure is not counted here: the alert reached a human.
  if (records.length > 0 && records.every((r) => r.delivered !== true)) await noteEmissionFailure(scheduler, cls, "deliver");
  // THE RECORD STAGE MUST READ THE BODY, NOT THE STATUS (G274, R4). The R3 fix read `resp.ok` -- and the DO's
  // route is `case "POST /notify/record": return this.json(await this.recordNotify(...))`, and json() sets NO
  // status. recordNotify NEVER THROWS on a malformed set by design: it drops the rows and answers
  // {recorded:0, skipped:N} with an HTTP 200. So `!resp.ok` could not fire on a drop, and the stage's own
  // HEADLINE STATE -- "the alert WAS delivered and the DO dropped the history row as malformed", the one this
  // counter exists for -- stayed at ZERO. The drop is reported only in the BODY, and the body was never read.
  //
  // Now: a non-2xx, a throw, AND a 200 that recorded nothing (or skipped a row) all count. `recorded === 0` with
  // records to write is the drop; `skipped > 0` is a partial drop, which is the same fact for the rows that fell.
  await scheduler.fetch(doURL("/notify/record"), {
    method: "POST",
    body: JSON.stringify({ emission, records }),
    headers: { "content-type": "application/json" },
  }).then(async (resp) => {
    if (!resp.ok) {
      await noteEmissionFailure(scheduler, cls, "record");
      log("error", `${label} history record refused (non-critical): the DO answered ${resp.status}`);
      return;
    }
    const body = (await resp.json().catch(() => null)) as { recorded?: unknown; skipped?: unknown } | null;
    const recorded = typeof body?.recorded === "number" ? body.recorded : -1;
    const skipped = typeof body?.skipped === "number" ? body.skipped : 0;
    // A body the engine cannot read at all (recorded === -1) is itself a lost history write: count it rather
    // than assume the rows landed.
    if (recorded < records.length || skipped > 0) {
      await noteEmissionFailure(scheduler, cls, "record");
      log("error", `${label} history rows were dropped by the DO (non-critical): recorded ${recorded} of ${records.length}`);
    }
  }).catch(async (e: unknown) => {
    // The alert may well have been DELIVERED and the pack's notify history has no row for it, so "was our
    // critical alert delivered?" is unanswerable from the bundle in exactly the case that matters.
    await noteEmissionFailure(scheduler, cls, "record");
    log("error", `${label} history record failed (non-critical): ${(e as Error).message}`);
  });
}

// routePostureRegressions routes the detected posture regressions through the two-phase notify path
// (mirroring routeNotification in index.ts): for each regression, resolve the matching channels in the
// DO, deliver via the channel adapters (the router holds env), and post the per-channel outcomes back so
// the DO appends the redaction-safe history. It is fully fail-open: deliverEmission never throws, and any
// error is swallowed by the caller's guard. The event is posture-regression; the severity is critical for
// a critical-check regression and warning otherwise.
export async function routePostureRegressions(env: Env, scheduler: DurableObjectStub, regressions: PostureRegression[]): Promise<void> {
  const at = nowStamp();
  for (const reg of regressions) {
    const event: NotifyEvent = "posture-regression";
    const severity: Severity = reg.severity === "critical" ? "critical" : "warning";
    const emission: NotifyEmission = {
      event,
      severity,
      downpipeId: null,
      downpipeName: null,
      detail: `Posture regression: ${reg.title} now failing`,
      at,
    };
    await routeEmission(env, scheduler, emission, "posture-regression", "posture-regression");
  }
}


// routeRecoveryAlert routes a recovery-code alert (recovery-code-used on a successful break-glass sign-in,
// recovery-code-abuse on repeated/failed attempts) through the SAME two-phase notify path the posture
// regressions use: resolve the matching channels in the DO, deliver via the channel adapters (the router
// holds env), and post the per-channel outcomes back for the redaction-safe history. It is fully fail-open
// (deliverEmission never throws; the caller swallows any error), so a delivery hiccup never affects the
// recovery response. The detail is redaction-safe: it names the email on a successful USE (the actor's own
// identity, the same class as a role-change notification) and stays generic on ABUSE (no email, since a
// failed attempt's "email" is an unverified guess we must not echo as if it were a real account).
export async function routeRecoveryAlert(
  env: Env,
  scheduler: DurableObjectStub,
  event: "recovery-code-used" | "recovery-code-abuse",
  email: string | null,
): Promise<void> {
  const at = nowStamp();
  const severity: Severity = event === "recovery-code-abuse" ? "critical" : "warning";
  const detail =
    event === "recovery-code-used"
      ? `Recovery code used for admin sign-in${email ? ` by ${email}` : ""}; prompt a fresh passkey enrolment.`
      : "Repeated or rate-limited recovery-code attempts detected; a high-value admin credential may be under attack.";
  const emission: NotifyEmission = { event, severity, downpipeId: null, downpipeName: null, detail, at };
  // R4: THE CLASS IS THE EVENT, and one class over both events was the coalescence this gap exists to remove --
  // reintroduced inside the very route that was meant to fix it. A recovery code that WORKED means somebody is
  // signed in as an admin right now; rate-limited attempts mean somebody is being kept OUT. They are opposite
  // facts with different notify rules (the customer's rules key on the event, so the "wire a rule" remedy
  // differs), and one counter summed them into one row. The old name asserted a fact the code never established
  // as well: a lawful owner break-glass with no channel wired was filed as "recovery-abuse".
  await routeEmission(env, scheduler, emission, event === "recovery-code-used" ? "recovery-code-used" : "recovery-code-abuse", "recovery-code alert");
}


// routeSignInContextAlert fires the R6 unusual-location notify (sign-in-new-context, V6.3.5): a
// successful sign-in's coarse network context was materially NEW for that operator (the DO's opt-in,
// bounded, no-raw-IP check decided; the router only delivers). Same two-phase path + FAIL-OPEN discipline
// as the recovery-code alert, fired AFTER the sign-in response is already determined so a notify hiccup
// can never affect a sign-in. The detail is DELIBERATELY generic: per the event's redaction contract it
// carries NO IP, prefix, email, subject or location, only the "was this you?" prompt and where to act.
export async function routeSignInContextAlert(env: Env, scheduler: DurableObjectStub): Promise<void> {
  const at = nowStamp();
  const emission: NotifyEmission = {
    event: "sign-in-new-context",
    severity: "warning",
    downpipeId: null,
    downpipeName: null,
    detail: "A successful sign-in came from a network not seen recently for that operator. If this was not you, sign out other sessions under Access and security and review passkeys and IdP access.",
    at,
  };
  await routeEmission(env, scheduler, emission, "sign-in-context", "sign-in-context alert");
}

// routeAuthChangeAlert fires a real-time notification on an AUTHENTICATION-AFFECTING change - a role
// grant/revoke (offboarding), and any other "your access changed" signal a user needs to spot an unexpected
// or takeover change (ASVS V6.3.7). The change itself is already committed + AUDITED in the DO; the audit is
// the tamper-evident record, but a NOTIFICATION is what reaches a human promptly. It routes through the SAME
// two-phase notify path the recovery-code + dual-control-disarm alerts use, and is fully FAIL-OPEN (an
// alerting hiccup never affects the operation). The detail is redaction-safe: it names WHO made the change
// and WHAT class of change, never a secret, key, credential value or fingerprint. The event MUST be one the
// DO's isNotifyEventLocal admits (e.g. "role-change"); resolve returns no channels for an unknown one.
export async function routeAuthChangeAlert(env: Env, scheduler: DurableObjectStub, event: NotifyEvent, cls: AlertClass, detail: string): Promise<void> {
  try {
    const at = nowStamp();
    const emission: NotifyEmission = { event, severity: severityOf(event), downpipeId: null, downpipeName: null, detail, at };
    await routeEmission(env, scheduler, emission, cls, "auth-change alert");
  } catch (e) {
    log("error", `auth-change alert failed (non-critical): ${(e as Error).message}`);
  }
}

// doRefusedTheChange answers the question `resp.ok` CANNOT: did the durable object itself refuse this change?
// It belongs beside routeAuthChangeAlert because it is the test that decides whether that alert has anything
// to announce, and because a router spoke that guards an alert on a DO response needs it before it needs
// anything else in this file.
//
// A ROUTE THAT ROUTES ITS REFUSALS THROUGH THE BODY CANNOT READ THEM OFF THE STATUS. The four IdP
// connection-management DO methods (scheduler-do-idp.ts idpConnCreate, idpConnDelete, idpConnSetEnabled,
// idpConnSamlCertUpdate) return { ok:false, reason } on a refusal, and ownerActionJson (scheduler-do.ts:773)
// wraps that in a plain 200 -- so `resp.ok` is TRUE for a change that was refused and wrote nothing anywhere.
// Guarding the alert on the transport result therefore raised "an IdP connection add was requested (changes
// who can sign in)" for an add the DO had just rejected. That invites an operator to investigate a change that
// never happened, and worse, it makes an alert stream firing on refusals indistinguishable from one firing on
// successes, on the surface that decides who can sign in. The four sibling alert sites that read a DO body
// already state this rule in place -- router-rbac.ts:144 ("a no-op delete of an absent member returns
// { deleted:false } and is not a change worth alerting on") and router-account-session.ts:116 and :152 ("a
// revoke that found nothing ... is not a credential change and must not raise one") -- and routeAuthChangeAlert
// above opens "The change itself is already committed + AUDITED in the DO". The destination sites in
// router-destinations.ts are exempt for a real reason rather than by oversight: removeDest and setDefaultDest
// THROW on refusal ("no such destination"), which the DO's catch maps to a 400, so `resp.ok` is already false.
//
// IT IS A REFUSAL TEST AND NOT A SUCCESS TEST, and that is the whole of the difference. A dual-control-armed
// engine answers 202 { ownerActionQueued, id, actionHash, status } with NO `ok` field at all: the change has
// not run, it is waiting for a second owner, and that alert MUST survive. It is the ONLY alert such a change
// ever gets, because the approve path (router.ts:664) fires an alert for dual-control-disable and for nothing
// else -- so a guard written as `body.ok === true` would silently delete the notification that a second owner
// has an IdP change waiting. "was requested" is the true word for a queued change, which is why the wording at
// those sites is left exactly as it was; only the condition moved.
//
// FAIL-OPEN: an unreadable or non-JSON body keeps the alert rather than losing it. The peek is on a CLONE, so
// the caller's own Response is returned untouched and unread.
export async function doRefusedTheChange(resp: Response): Promise<boolean> {
  try {
    return ((await resp.clone().json()) as { ok?: unknown }).ok === false;
  } catch {
    return false;
  }
}

// doDeletedNothing is the SECOND question a delete's response has to answer, and it is not the one above.
// A REFUSAL AND A NO-OP ARE DIFFERENT ANSWERS AND ONLY ONE OF THEM IS AN `ok:false`. A delete of a
// valid-shaped but ABSENT connection passes every gate and every validator, so scheduler-do-idp.ts
// idpConnDelete rightly answers `ok:true` -- and it removed nothing, it wrote no audit row (the append is
// guarded on the same `existed`), and it is therefore not a change worth announcing. doRefusedTheChange
// cannot see that state, because there is no refusal to see: the router was not ignoring a verdict, the DO
// was not reporting one. So the repair is a FIELD on the DO's response (`deleted`) and this is the test that
// reads it, which is why the two helpers sit side by side rather than being folded into one -- they answer
// "was it refused?" and "did it change anything?", and a caller that conflates them loses one of the two.
//
// IT IS A NO-OP TEST AND NOT A SUCCESS TEST, for exactly the reason stated above: only an EXPLICIT
// `deleted:false` suppresses. A 202 `{ ownerActionQueued }` under dual control carries no `deleted` field at
// all, and its propose-time alert is the ONLY alert that change will ever get, so a test written as
// `deleted === true` would silently delete the notification that a second owner has an IdP removal waiting.
// Every body that does not say "I deleted nothing" keeps its alert.
//
// The spelling is the house's, not a new one: router-rbac.ts:144 reads `{ deleted:true }` off the roles
// delete for this same question ("a no-op delete of an absent member returns { deleted:false } and is not a
// change worth alerting on"), and router-account-session.ts:116 reads the identical field off the passkey
// credential revoke. FAIL-OPEN and CLONE-based like its sibling above: an unreadable body keeps the alert,
// and the caller's own Response is returned untouched and unread.
export async function doDeletedNothing(resp: Response): Promise<boolean> {
  try {
    return ((await resp.clone().json()) as { deleted?: unknown }).deleted === false;
  } catch {
    return false;
  }
}

// routeDualControlDisarmAlert fires the real-time DISARM ALERT when the dual-control off switch is turned OFF
// (requireConfigApproval true -> false). A disarm drops the second-owner-approval guarantee over every
// high-blast-radius config + owner operation, so a human must know PROMPTLY (whether the disarm was an
// immediate owner toggle, a break-glass escape, or a second-owner-approved disarm). It routes through the SAME
// two-phase notify path the recovery-code + posture alerts use (resolve the channels in the DO, deliver via
// the channel adapters here where env lives, post the redaction-safe outcomes back for history). It is fully
// FAIL-OPEN: deliverEmission never throws and the whole thing is wrapped, so an alerting hiccup never affects
// the disarm response (the disarm itself already succeeded + was audited in the DO). The detail is
// redaction-safe: it names WHO disarmed it (the actor email, the same class as a role-change notification) and
// the path (break-glass vs an approved second-owner disarm vs a direct owner toggle); never a secret.
export async function routeDualControlDisarmAlert(env: Env, scheduler: DurableObjectStub, actorEmail: string | null, via: string): Promise<void> {
  try {
    const at = nowStamp();
    const detail = `Dual control was turned OFF (${via})${actorEmail ? ` by ${actorEmail}` : ""}; high-blast-radius config and owner operations no longer require a second owner's approval until it is turned back on.`;
    const emission: NotifyEmission = { event: "dual-control-disabled", severity: severityOf("dual-control-disabled"), downpipeId: null, downpipeName: null, detail, at };
    await routeEmission(env, scheduler, emission, "dual-control-disarm", "dual-control disarm alert");
  } catch (e) {
    log("error", `dual-control disarm alert skipped (non-critical): ${(e as Error).message}`);
  }
}
