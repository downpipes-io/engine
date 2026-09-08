// The CHECKED best-effort writer for the ADMIN diagnostic counters.
//
// These are the engine's SILENT SUBSTITUTIONS and SILENT EXCLUSIONS: a crashed apply's reservation lease
// reclaimed as a pure read-time projection (so the retry's overwrite erases the only trace an apply died
// mid-write); a console-activated licence quietly resolving from the DEPLOY token during a DO storage
// incident; a run row with a corrupt timestamp dropped from a point-in-time window, so a successful run that
// COVERS the requested instant is reported as "no run exists". Each reports success while telling the reader
// less than the truth, which is the worst failure mode a remote-diagnosis pack can have.
//
// They are RATES, not events, so they share ONE bounded {closed name -> count, lastAt} aggregate
// (ADMIN_COUNTER_NAMES in admin/diag-records.ts). A non-zero counter is the signal that says "the surface you
// are reading is not telling you everything".
//
// NO-CUSTODY: the only thing that crosses the wire is a {closed name: int count} tally. applyAdminCounters is
// the redaction chokepoint on the DO side (an out-of-vocabulary name is dropped, every count clamped), so no
// id, message, token or value can enter the record from either side.

import { classifyRunIdMalformation } from "../format/ulid.ts";
import { classifyTestFailure, type TestDeleteProbe, type TestObjectLock, type TestReasonClass, type TestStatusClass, type TestSurface, testStatusClass } from "../sched/sched-fault-ledger.ts";
import type { WormUnknownReason } from "../dest/types.ts";
import { emailPlatformCodeOf } from "../notify/types.ts";
import type { AdminCounterName, AdminRouteError, ExportAttempt, RecoveryRefusal } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import type { AttachObservation, DiscoveryObservation, DiscoveryTokenSetFailClass, DiscoveryTokenSetOutcome } from "./discovery-health.ts";

import { doURL } from "../do-url.ts";

/**
 * bumpAdminCounters records a {closed name: count} tally on the DO's bounded aggregate, CHECKED: a dropped
 * write is counted in droppedWrites (kind "admin-counter") instead of vanishing. It NEVER throws and never
 * alters the caller's path (the response is already decided); a no-op for an empty tally.
 *
 * @param scheduler - the scheduler DO stub.
 * @param bumps - the {closed name: positive int} tally.
 */
export async function bumpAdminCounters(scheduler: DurableObjectStub, bumps: Partial<Record<AdminCounterName, number>>): Promise<void> {
  const entries = Object.entries(bumps).filter(([, n]) => typeof n === "number" && n > 0);
  if (entries.length === 0) return;
  try {
    await recordDiagWrite(scheduler, "admin-counter", () =>
      scheduler.fetch(doURL("/diag/admin-counters"), {
        method: "POST",
        body: JSON.stringify({ bumps: Object.fromEntries(entries) }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: observing a silent fallback must never break the path that took it */
  }
}

/**
 * bumpAdminCounter is the single-name convenience form.
 *
 * @param scheduler - the scheduler DO stub.
 * @param name - the closed counter name.
 * @param n - how many (defaults to 1).
 */
export async function bumpAdminCounter(scheduler: DurableObjectStub, name: AdminCounterName, n = 1): Promise<void> {
  await bumpAdminCounters(scheduler, { [name]: n } as Partial<Record<AdminCounterName, number>>);
}

// The closed kind -> counter-name map for a REJECTED runId. Kept here (beside the other counter writers)
// rather than at the four route sites, so the vocabulary is applied in exactly one place.
const INVALID_RUNID_COUNTERS: Readonly<Record<string, AdminCounterName>> = {
  length: "invalid-runid-length",
  charset: "invalid-runid-charset",
  overflow: "invalid-runid-overflow",
};

/**
 * noteInvalidRunId counts ONE restore/verify runId rejection under its closed malformation kind (G321). The
 * endpoints answer a flat 400 and persist nothing today, so "our integration script keeps getting invalid
 * runId" is unanswerable from the pack: support cannot see whether the ids arrive truncated, case-mangled or
 * out of range, which are three different fixes on the customer's side.
 *
 * REDACTION: the candidate is classified to an ENUM here and DISCARDED. It is the one value that must never be
 * recorded -- an unauthenticated-shaped input a caller can fill with anything (a token, an email, a traversal
 * payload) -- so it never crosses the wire and never enters the record. A well-formed id records nothing.
 *
 * Never throws and never alters the caller's path (the 400 is already decided).
 *
 * @param scheduler - the scheduler DO stub.
 * @param candidate - the rejected runId, read only to select a closed kind.
 */
export async function noteInvalidRunId(scheduler: DurableObjectStub, candidate: unknown): Promise<void> {
  try {
    const kind = classifyRunIdMalformation(candidate);
    if (kind === null) return; // a valid ULID: nothing was rejected, nothing is recorded
    await bumpAdminCounter(scheduler, INVALID_RUNID_COUNTERS[kind]!);
  } catch {
    /* best-effort: observing a refusal must never break the refusal */
  }
}

/**
 * recordTestOutcome files ONE setup-surface WIRING-CHECK outcome: the result of a Test / Verify button.
 *
 * WHY. Every one of these buttons computes a rich, precise answer -- a push endpoint's 401, a Slack webhook's
 * delivery code, an IdP's cert error, a destination probe's delete-denied -- and then throws it away with the
 * HTTP response. The pack's only test artefact is a notify-history row carrying `delivered:false` and no
 * reason. So "the push test failed with a 401 yesterday but works when support asks us to retry" is a customer
 * report the engine cannot corroborate or refute, and support's only move is to ask them to press it again.
 *
 * REDACTION: the caller CLASSIFIES the failure (classifyTestFailure reads the text only to select a closed
 * member and discards it) and passes closed enums. No URL, webhook address, recipient, endpoint, bucket,
 * issuer or provider text crosses the wire; recordTestOutcome DO-side re-gates every field.
 *
 * Never throws and never alters the test's own response.
 *
 * @param scheduler - the scheduler DO stub.
 * @param entry - the classified outcome.
 */
export async function recordTestOutcome(
  scheduler: DurableObjectStub,
  entry: {
    surface: TestSurface;
    ok: boolean;
    reasonClass?: TestReasonClass;
    statusClass?: TestStatusClass;
    deleteProbe?: TestDeleteProbe;
    deleteStatusClass?: TestStatusClass;
    objectLock?: TestObjectLock;
    objectLockUnknownReason?: WormUnknownReason;
    defaultRetention?: boolean;
    platformCode?: string;
    // The notify-channel surface's closed DeliveryFailCode. THIS TYPE IS A WIRE CONTRACT, and it is the
    // sibling site the fix nearly died on: the field is serialised straight into the DO body below, so a member
    // that is not declared here is silently dropped in the hop and the recorder never sees it.
    deliveryCode?: string;
  },
): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "test-outcome", () =>
      scheduler.fetch(doURL("/diag/test-outcome"), {
        method: "POST",
        body: JSON.stringify(entry),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: recording a wiring check must never break the wiring check */
  }
}

/**
 * noteTestOutcome is the convenience form the five Test routes call: it takes the RAW result they already have
 * ({ ok, reason?, status? }) and classifies it here, in ONE place, so the vocabulary is applied identically on
 * every surface and no route can accidentally pass a message through.
 *
 * G246: `deleteProbe` and `objectLock` are the destination probe's OWN closed verdicts, passed through
 * unchanged (they are already enum members, so there is nothing to classify and nothing to read). They are the
 * discriminator that stops a destination whose retention SILENTLY DOES NOT WORK -- writes accepted, deletes
 * refused, archive growing for ever -- from producing a row byte-identical to a healthy destination's. A denied
 * delete is NOT a failed test (backups work), so it does not and must not flip `ok`.
 *
 * @param scheduler - the scheduler DO stub.
 * @param surface - the closed surface.
 * @param result - the test's own outcome; `reason` is READ only to select a closed class and is never stored.
 */
export async function noteTestOutcome(
  scheduler: DurableObjectStub,
  surface: TestSurface,
  result: {
    ok: boolean;
    reason?: unknown;
    status?: unknown;
    deleteProbe?: TestDeleteProbe;
    deleteStatusClass?: TestStatusClass;
    objectLock?: TestObjectLock;
    objectLockUnknownReason?: WormUnknownReason;
    defaultRetention?: boolean;
    // Email + notify-channel surfaces: the platform's RAW rejection code, read ONLY to select a bounded
    // token. It is classified HERE through emailPlatformCodeOf and the raw value never
    // leaves this function, so the caller may hand over whatever the Email Service returned.
    platformCode?: unknown;
    // Notify-channel surface: the channel adapter's OWN closed DeliveryFailCode. It is ALREADY an enum
    // member, so there is nothing to classify and nothing to read: it is passed through and re-gated against
    // DELIVERY_FAIL_CODES by the recorder. It must NOT go through `reason`, which is where six rounds of this
    // gap died: classifyTestFailure's text arm coarsens http-bad-request, http-gone, http-4xx and
    // email-platform-rejected all to "rejected", so the discriminator the channel layer had already computed was
    // being destroyed one function call after it was made.
    deliveryCode?: unknown;
  },
): Promise<void> {
  const statusClass = testStatusClass(result.status);
  // The ONE thing "our test email never arrives" turns on. sendEmail already computes the platform code
  // (E_SENDER_DOMAIN_NOT_AVAILABLE = the sending domain is not onboarded, E_SENDER_NOT_VERIFIED = the sender
  // is not verified, E_RATE_LIMITED = a platform throttle: three different remedies), and the route dropped it,
  // so all three landed in the pack as {"ok":false,"reasonClass":"other"}. emailPlatformCodeOf gates it to the
  // documented E_UPPER_SNAKE shape (E_OTHER when the platform sent something else), never a message.
  // The notify-channel Test button on a kind:"email" channel reaches the same Email Service through the same
  // adapter, so the same bounded token rides on the same terms. Never on push / idp / dest-verify (no producer).
  const platformCode = surface === "email" || surface === "notify-channel" ? emailPlatformCodeOf(result.platformCode) : undefined;
  await recordTestOutcome(scheduler, {
    surface,
    ok: result.ok === true,
    ...(result.ok === true ? {} : { reasonClass: classifyTestFailure(result.reason, result.status) }),
    ...(statusClass !== undefined ? { statusClass } : {}),
    ...(result.deleteProbe !== undefined ? { deleteProbe: result.deleteProbe } : {}),
    // The CLEANUP DELETE's own status class. The probe's delete verdict used to be inferred from the bare
    // fact of a throw, so a 503, a 429 and a dropped socket all read "denied" -- a permission fact none of them
    // established. deleteProbe now names what was measured and this carries the status behind it.
    ...(result.deleteStatusClass !== undefined ? { deleteStatusClass: result.deleteStatusClass } : {}),
    ...(result.objectLock !== undefined ? { objectLock: result.objectLock } : {}),
    // The object-lock probe's OWN closed unknown-reason, and whether a locked bucket carries a default
    // retention rule. Without the first, "denied" (a short IAM allow-list) and "not-implemented" (a store with no
    // Object-Lock API) were the same row with opposite remedies; without the second, "enforced" stood in for
    // "locked". The DO recorder re-gates both against their closed sets and admits them only where they mean
    // something.
    ...(result.objectLockUnknownReason !== undefined ? { objectLockUnknownReason: result.objectLockUnknownReason } : {}),
    ...(result.defaultRetention !== undefined ? { defaultRetention: result.defaultRetention } : {}),
    ...(platformCode !== undefined ? { platformCode } : {}),
    ...(surface === "notify-channel" && typeof result.deliveryCode === "string" ? { deliveryCode: result.deliveryCode } : {}),
  });
}

/**
 * recordDiscoveryHealth reports ONE source-discovery outcome to the DO's bounded discovery aggregate,
 * CHECKED: a dropped write is counted in droppedWrites (kind "discovery-health") instead of vanishing. It
 * NEVER throws and never alters the discover response (which is already decided).
 *
 * The observation is built by the caller from CLASSIFIED verdicts only (closed enums, counts, booleans), so no
 * account, bucket, namespace, database, secret name, zone or token is representable on the wire; applyDiscoveryHealth
 * re-gates the whole shape DO-side.
 *
 * @param scheduler - the scheduler DO stub.
 * @param obs - the classified observation.
 */
export async function recordDiscoveryHealth(scheduler: DurableObjectStub, obs: DiscoveryObservation): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "discovery-health", () =>
      scheduler.fetch(doURL("/diag/discovery-health"), {
        method: "POST",
        body: JSON.stringify(obs),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: observing the setup form's health must never break the setup form */
  }
}

/**
 * recordDiscoveryTokenSet records the verdict of ONE pasted discovery-token verification, at the ONE
 * place in the system that knows it: the route that made the Cloudflare call and read the status.
 *
 * The console cannot do this. POST /sources/discovery-token answers a flat 400 for a typo'd token, a scope-less
 * token, an expired token, a Cloudflare outage and a verify that never returned, so the browser's row collapsed
 * to a single `refused` and all five COALESCED into it -- while the gap's own ticket asks support to tell a
 * scope gap from an invalid token, whose remedies are opposites.
 *
 * `outcome` and `failClass` are closed members chosen by the classifier; `accountsSeen` is a count.
 * applyDiscoveryTokenSet re-gates all three DO-side, so no token, account id or Cloudflare sentence is
 * representable on the wire.
 *
 * @param scheduler - the scheduler DO stub.
 * @param obs - the classified token-set verdict.
 */
export async function recordDiscoveryTokenSet(scheduler: DurableObjectStub, obs: { outcome: DiscoveryTokenSetOutcome; failClass?: DiscoveryTokenSetFailClass; accountsSeen: number }): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "discovery-health", () =>
      scheduler.fetch(doURL("/diag/discovery-token-set"), {
        method: "POST",
        body: JSON.stringify(obs),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: observing a refused token must never change how it was refused */
  }
}

/**
 * recordExportAttempt reports ONE audit-log export attempt to the DO's bounded aggregate, CHECKED: a
 * dropped write is counted in droppedWrites (kind "audit-export-attempt") instead of vanishing. It NEVER throws
 * and never alters the caller's response (the export, or the error, has already been decided).
 *
 * Both channels post through here: the operator's console download (router-rbac.ts) and the collector's feed
 * pull (support-ingest.ts). The attempt carries three closed enums and one boolean -- never the filter the
 * caller supplied, never a cursor, never a byte of the log.
 *
 * @param scheduler - the scheduler DO stub.
 * @param att - the classified attempt.
 */
export async function recordExportAttempt(scheduler: DurableObjectStub, att: ExportAttempt): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "audit-export-attempt", () =>
      scheduler.fetch(doURL("/diag/export-attempt"), {
        method: "POST",
        body: JSON.stringify(att),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: recording that an export failed must never break the path that failed it */
  }
}

/**
 * recordAttachHealth reports ONE attach / re-attach attempt to the DO's bounded aggregate, CHECKED: a
 * dropped write is counted in droppedWrites (kind "attach-health") instead of vanishing. It NEVER throws and
 * never alters the caller's response (the attach, or the refusal, is already decided).
 *
 * Both writes post through here: POST /sources/attach (a NEW source) and POST /sources/reattach-missing (the
 * HEAL after a deploy dropped the bindings -- the owner's stated #1 fear). A SUCCESS is posted too: it is what
 * clears a failing streak, and "the heal worked on the third try" is a different story from "it never worked".
 *
 * The observation carries a closed op, a closed fault class and counts. The deploy token, the account id, the
 * script name, the Cloudflare message and the binding names are never passed; applyAttachHealth re-gates the
 * whole shape DO-side.
 *
 * @param scheduler - the scheduler DO stub.
 * @param obs - the classified observation.
 */
export async function recordAttachHealth(scheduler: DurableObjectStub, obs: AttachObservation): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "attach-health", () =>
      scheduler.fetch(doURL("/diag/attach-health"), {
        method: "POST",
        body: JSON.stringify(obs),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: recording that a re-attach failed must never break the re-attach path */
  }
}

/**
 * recordAdminRouteError reports ONE admin-route outer-catch fault to the DO's bounded aggregate,
 * CHECKED: a dropped write is counted in droppedWrites (kind "admin-route-error") instead of vanishing.
 *
 * These are the catches that return a FIXED sentence ("nothing was changed") and discard the exception. The
 * sentence is sometimes FALSE -- the throw can land AFTER the deploy -- and the exception then vanishes with
 * the browser tab, leaving nothing server-side to say whether the DO, the channel fetch or Cloudflare's API
 * was at fault. `stage` is set at the LAST CHECKPOINT PASSED, so the "nothing was changed" claim becomes
 * checkable: a fault at stage `deploy-driver` or later means something very possibly WAS changed.
 *
 * @param scheduler - the scheduler DO stub.
 * @param err - the classified {route, stage} (closed enums only; the exception text never travels).
 */
export async function recordAdminRouteError(scheduler: DurableObjectStub, err: AdminRouteError): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "admin-route-error", () =>
      scheduler.fetch(doURL("/diag/admin-route-error"), {
        method: "POST",
        body: JSON.stringify(err),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: the route's 400 is already decided */
  }
}

/**
 * recordRecoveryRefusal reports ONE control-plane import / recovery / export-download refusal to the
 * DO's bounded aggregate, CHECKED: a dropped write is counted in droppedWrites (kind "recovery-refusal").
 *
 * This is the DISASTER-RECOVERY path: the customer is rebuilding a wiped estate and the support pack may be
 * the only artefact left. Every refusal on it lived in the operator's browser alone, so "estate import says
 * the signature is invalid but the kit is correct" arrived with no evidence at all -- and, critically, a
 * THROWN crypto fault (a corrupt kit key, an unimportable verifier) was indistinguishable from a genuine
 * signature MISMATCH (tamper), which are opposite diagnoses.
 *
 * @param scheduler - the scheduler DO stub.
 * @param refusal - the classified {surface, cls} (closed enums only; no signature material, no export bytes).
 */
export async function recordRecoveryRefusal(scheduler: DurableObjectStub, refusal: RecoveryRefusal): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "recovery-refusal", () =>
      scheduler.fetch(doURL("/diag/recovery-refusal"), {
        method: "POST",
        body: JSON.stringify(refusal),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: recording a refusal must never break the recovery path that refused */
  }
}
