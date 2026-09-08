// router-posture.ts -- the security-centre / posture computation + the contract-section-6 reports: the
// env-derived presence slice, the live WORM capability probe, the destination write-probe,
// computePosture-via-DO (which also routes any regression), and the report assembly/sign/PDF path.

import { ab } from "../crypto/bytes.ts";
import { buildDestination, fetchDestConfig, parseWormPolicy, type RuntimeDestConfig } from "../dest/factory.ts";
import { destStatusOf, WORM_UNKNOWN_REASONS, type WormUnknownReason } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { loadSigner } from "../keys-env.ts";
import { log } from "../log.ts";
import { drainReportRenderFaults, renderReportPDF } from "../pdf.ts";
import { type TestDeleteProbe, type TestStatusClass, testStatusClass } from "../sched/sched-fault-ledger.ts";
import type { AuditEvent } from "./audit-types.ts";
import { beaconConfigured } from "../cron/beacon-config.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import { FRAMEWORKS, getFramework, isFrameworkId } from "./frameworks.ts";
import type { Caller } from "./identity.ts";
import type { PostureRegression, PostureReport, PostureWormInput } from "./posture.ts";
import {
  buildChangeRequestsReport,
  buildEvidencePackReport,
  buildImmutabilityReport,
  buildPostureReport,
  isReportKind,
  makeReport,
  type Report,
  type ReportKind,
  type ReportPeriod,
  type RestoreTestsData,
  type SlaComplianceData,
  signReport,
} from "./reports.ts";
import { jsonResponse } from "./router-core.ts";
import { doURL } from "../do-url.ts";
import { routePostureRegressions } from "./router-notify.ts";
import { buildStatus, resolveDestKind } from "./status.ts";



const WORM_UNKNOWN_REASON_SET: ReadonlySet<string> = new Set(WORM_UNKNOWN_REASONS);

// probeDestination proves a destination LIVE: reachability + read auth via exists() on the RUNLOG
// key (absence is a normal first-run state), then a REAL write probe (a tiny object under the
// _RECOVERY/ prefix), then a best-effort delete of the probe. A delete refusal is recorded as the
// honest "denied" posture rather than a failure: an object-locked/immutable archive bucket is a
// deliberate hardening (backups work; retention pruning will not). With an override the probe
// targets the SUBMITTED configuration (the pre-store verification); without one it targets the
// deploy-time env destination. The error reason is sanitised of URL-shaped values exactly like
// preflight evidence (NC-5): the operator's own submitted strings may echo, but a stored endpoint
// never leaves through an error string.
export async function probeDestination(
  env: Env,
  override?: RuntimeDestConfig,
): Promise<
  | { ok: true; deleteProbe: TestDeleteProbe; deleteStatusClass?: TestStatusClass; objectLock: "enforced" | "not-enforced" | "unknown"; objectLockUnknownReason?: WormUnknownReason; credentialExpiry?: { kind: "sas"; expiresAtMs: number | null }; defaultRetention?: boolean; ms: number }
  | { ok: false; reason: string }
> {
  const started = Date.now();
  // The bucket this probe targets, for an ACTIONABLE auth-denied reason. Operator-facing only
  // (the verify/POST handlers return it, never log it), so naming the operator's own bucket is
  // safe; the endpoint URL stays sanitised below (NC-5).
  const bucket = override?.bucket ?? (typeof env.DEST_BUCKET === "string" && env.DEST_BUCKET !== "" ? env.DEST_BUCKET : undefined);
  try {
    const dest = await buildDestination(env, undefined, override ?? null);
    await dest.exists("_RECOVERY/RUNLOG");
    const probeKey = "_RECOVERY/.write-probe";
    await dest.put(probeKey, new TextEncoder().encode(`downpipes destination write probe ${new Date().toISOString()}`));
    // G246 (R5): CLASSIFY THE DELETE FAILURE, DO NOT INFER IT FROM THE FACT OF A THROW.
    //
    // This used to be a bare `catch { deleteProbe = "denied" }`, and dest.delete throws on ANY unusable status
    // as well as on a transport fault. So a 503 SlowDown, a 500, a 429 throttle and a dropped socket all landed
    // as "denied" -- a PERMISSION fact the probe had not established -- and filed a durable pack row telling
    // support this customer's retention is permanently broken and their IAM allow-list (which is correct) needs
    // fixing. In the other direction it made a genuine least-privilege denial waveable-away as a blip. Both
    // directions are wrong, from one row.
    //
    // del() already had the status on the response and now throws it TAGGED (DestStatusError), so the verdict
    // says what was MEASURED: 401/403 is the denial, 429/5xx is the store being busy, no status at all is the
    // transport, and anything else is the honest residual. deleteStatusClass rides the class itself.
    let deleteProbe: TestDeleteProbe = "ok";
    let deleteStatusClass: TestStatusClass | undefined;
    try {
      await dest.delete(probeKey);
    } catch (e) {
      const status = destStatusOf(e);
      deleteStatusClass = testStatusClass(status);
      deleteProbe = classifyDeleteFailure(status);
    }
    // objectLock is the LIVE WORM capability verdict, read at store time so a configured WORM policy
    // is only ever claimed against what the bucket actually ENFORCES (a policy on a bucket that was not
    // created with Object-Lock has every write REFUSED by the store, not silently stripped, so that
    // destination holds nothing at all). The same feature-detect + safe-degrade mapping the immutability
    // posture uses (gatherWormSlice): any fault reads "unknown" (cannot-confirm), never a false "enforced".
    // It NEVER fails the probe: the write/delete result above is what decides ok.
    let objectLock: "enforced" | "not-enforced" | "unknown" = "unknown";
    // G246 (R4): THE DISCRIMINATOR WAS ALREADY COMPUTED HERE AND WAS BEING THROWN AWAY, which is the same defect
    // the delete-denied fix repaired one layer up.
    //
    //   objectLockUnknownReason  objectLockStatus already returns a CLOSED WormUnknownReason (WORM_UNKNOWN_REASONS)
    //                            saying WHY it could not confirm, and this probe read only status.enabled and
    //                            discarded it. Without it, "denied" (the least-privilege key that may PutObject but
    //                            not GetBucketObjectLockConfiguration -- and, by the same allow-list, not
    //                            DeleteObject) and "not-implemented" (a store with NO Object-Lock API, where a
    //                            refused delete is the customer's own deny-delete policy) produced a byte-identical
    //                            row, and they are the two intents this gap exists to separate. One is a one-line
    //                            IAM fix; the other is nothing to fix.
    //
    //   defaultRetention         ObjectLockEnabled does NOT mean anything is retained: the bucket can have lock on
    //                            with no default rule (dest/types.ts). "enforced" was standing in for "locked", so
    //                            carry the presence of an actual default retention rule as a boolean.
    //
    // Both are closed: a member of a closed vocabulary and a boolean. The bucket's retention DAYS and mode are the
    // customer's configuration and stay where they are.
    let objectLockUnknownReason: WormUnknownReason | undefined;
    let defaultRetention: boolean | undefined;
    try {
      if (typeof dest.objectLockStatus === "function") {
        const status = await dest.objectLockStatus();
        objectLock = status.enabled === true ? "enforced" : status.enabled === false ? "not-enforced" : "unknown";
        if (status.enabled === "unknown" && typeof status.unknownReason === "string" && WORM_UNKNOWN_REASON_SET.has(status.unknownReason)) {
          objectLockUnknownReason = status.unknownReason;
        }
        if (status.enabled === true) defaultRetention = status.defaultMode !== undefined;
      }
    } catch {
      objectLock = "unknown";
      // The probe itself threw, so the store never answered: this is the transport residual, not a store fact.
      objectLockUnknownReason = "network";
    }

    // THE CREDENTIAL THAT DIES ON ITS OWN. Every other destination credential here is valid until somebody
    // rotates it; an Azure SAS carries its own expiry and stops working on a date nobody is reminded of.
    //
    // AzureBlobDestination.sasExpiry() has existed, has three tests, and carries a
    // doc comment saying it is "for a surface that warns before the day comes", but had no production caller,
    // so the warning surface its own comment describes did not exist. A capability with a test and
    // no caller reads exactly like a shipped feature.
    //
    // THE NULL IS NOT "SAFE", and the method's own header says so: a SAS whose token carries no `se`
    // parameter reports expiresAtMs null, which means the expiry is NOT VISIBLE to us, not that the token
    // never expires. It is carried through as null rather than collapsed into an absent field, so a reader
    // can tell "no expiry reading" from "not a SAS at all". Those are different facts and only one of them
    // means no warning is owed.
    let credentialExpiry: { kind: "sas"; expiresAtMs: number | null } | undefined;
    try {
      if (typeof dest.sasExpiry === "function") {
        const reading = dest.sasExpiry();
        if (reading !== null) credentialExpiry = { kind: "sas", expiresAtMs: reading.expiresAtMs };
      }
    } catch {
      // A throw here says nothing about the credential, only that this reading could not be taken, so the
      // field stays ABSENT rather than being reported as an unknown expiry. Absent means "not a SAS or not
      // readable"; null inside the field means "a SAS whose expiry we cannot see". Collapsing the two
      // would invent a fact.
      credentialExpiry = undefined;
    }
    return {
      ok: true,
      deleteProbe,
      ...(deleteStatusClass !== undefined ? { deleteStatusClass } : {}),
      objectLock,
      ...(objectLockUnknownReason !== undefined ? { objectLockUnknownReason } : {}),
      ...(credentialExpiry !== undefined ? { credentialExpiry } : {}),
      ...(defaultRetention !== undefined ? { defaultRetention } : {}),
      ms: Date.now() - started,
    };
  } catch (e) {
    return classifyProbeError((e as Error).message, bucket);
  }
}

// classifyDeleteFailure maps the STATUS the store answered the cleanup DELETE with (or its absence, which is the
// transport case) onto the closed delete-probe verdict. Pure and total: it reads an integer, never a message.
//
// 401/403 is the ONLY pair that establishes a permission fact. 429 and 5xx are the store refusing for volume or
// erroring, which says nothing about the credential and nothing about retention. An absent status means the
// request never reached one, which is a socket, not a policy. Everything else is the residual, and is not guessed.
function classifyDeleteFailure(status: number | undefined): TestDeleteProbe {
  if (status === undefined) return "transient"; // no status was ever seen: a transport fault, not a denial
  if (status === 401 || status === 403) return "denied";
  if (status === 429 || (status >= 500 && status <= 599)) return "transient";
  return "other";
}

// classifyProbeError maps a probe exception message into an ACTIONABLE operator reason. It covers the three
// recurring causes (an authorised-elsewhere 401/403, a region-mismatch redirect, and the generic sanitised
// fallback), keeping probeDestination itself under the function-length ceiling.
function classifyProbeError(raw: string, bucket: string | undefined): { ok: false; reason: string } {
  // A 401/403 on the credentialed probe means the endpoint was reachable and the request was
  // signed, but the key is not authorised HERE. The overwhelmingly common cause is an R2 API
  // token scoped to a DIFFERENT bucket than this destination's (a single-bucket token 403s every
  // other bucket, easy to hit in a multi-bucket / 3-2-1 setup), a read-only token, or an
  // endpoint account id that does not match the bucket. Name the bucket and the cause so the
  // operator stops chasing the credential VALUE (which is valid).
  const status = raw.match(/status (\d{3})/);
  if (status && (status[1] === "403" || status[1] === "401")) {
    const where = bucket ? ` to bucket "${bucket}"` : "";
    return {
      ok: false,
      reason: `the destination denied the write${where} (HTTP ${status[1]}). The endpoint was reachable and the request was signed, so the access key is valid but is not authorised here. Most likely the R2 API token is scoped to a different bucket, for a multi-bucket / 3-2-1 setup use an account-wide "Object Read & Write" token, not a single-bucket one, or the token is read-only, or the endpoint's account id does not match the bucket's account. On AWS S3 a 403 can also mean the bucket's default encryption (SSE-KMS) denies this principal access to the KMS key; downpipes already encrypts every archive before it leaves your account, so SSE-S3 is the simpler bucket default.`,
    };
  }
  // A redirect on a credentialed request (the dest layer turns a 3xx into "unexpected redirect" rather
  // than following it, V15.3.2) almost always means the SIGNED REGION does not match the bucket's
  // region: S3 answers a mis-regioned request with a 301 PermanentRedirect. Name that cause so the
  // operator fixes the region rather than chasing the (valid) credentials.
  if (/unexpected redirect|status 301/i.test(raw)) {
    return { ok: false, reason: "the destination redirected the request, which usually means the region is wrong for this bucket. Set the region to the bucket's actual region (for Cloudflare R2 use \"auto\"), then verify again." };
  }
  return { ok: false, reason: raw.replace(/https?:\/\/[^\s"')]+/gi, "<endpoint>").slice(0, 200) };
}


// REPORT_DEFAULT_WINDOW_SECONDS is the default period the time-bounded reports cover when the caller
// supplies no explicit from/to: the last 90 days. It is a sensible compliance window (a quarter), and
// the caller can override it with ?from=<epochSeconds>&to=<epochSeconds>. The point-in-time reports
// (posture, immutability) ignore the period (it stays null).
export const REPORT_DEFAULT_WINDOW_SECONDS = 90 * 24 * 60 * 60;


// statusSliceForPosture builds the env-derived presence slice computePosture needs (the part the DO
// cannot read, since the DO holds no env). It reuses buildStatus (the single presence projection) so the
// posture and the onboarding status agree on what "configured" means, then narrows it to the four fields
// posture reads. The downpipe count is irrelevant to the slice, so 0 is passed (buildStatus does not use
// it for these fields). It carries only booleans; no secret.
export function statusSliceForPosture(env: Env): { destConfigured: boolean; breakGlassConfigured: boolean; operationalConfigured: { public: boolean; private: boolean }; tokenFallbackDisabled: boolean; adminTokenPresent: boolean } {
  const s = buildStatus(env, 0);
  return {
    destConfigured: s.destConfigured,
    breakGlassConfigured: s.breakGlassConfigured,
    operationalConfigured: { public: s.operationalConfigured.public, private: s.operationalConfigured.private },
    tokenFallbackDisabled: s.tokenFallbackDisabled,
    // adminTokenPresent is env-derived (the presence of ADMIN_TOKEN), forwarded so the DO can compute the
    // dispose-bootstrap-token finding (the DO supplies the bootstrapConsumed/breakGlassTokenRetired latches
    // from its own storage). No secret crosses; only the presence boolean.
    adminTokenPresent: s.adminTokenConfigured,
  };
}


// computePostureViaDO drives the posture computation (contract section 7): it forwards the env presence
// slice + the caller's auth posture + the beacon flag to the DO's POST /posture (which adds the state it
// owns, runs the pure computePosture, snapshots and detects regressions), then ROUTES any regression the
// DO returned as a posture-regression notification (fail-open, fire-and-forget) and returns the report.
// beaconEnabled reflects the OPT-IN no-custody vendor beacon (cron/beacon-emit.ts): false by default (no
// phone-home), true ONLY when the operator has set all three of BEACON_URL, BEACON_INGEST_KEY and
// CF_ACCOUNT_ID. It is now the EMITTER'S OWN PREDICATE (cron/beacon-config.ts beaconConfigured) rather than
// a second copy of it. The copy read two of the three vars, so an estate with the beacon vars set and no
// CF_ACCOUNT_ID was told on the posture screen that the engine reports usage to the vendor while the
// emitter returned without sending anything. See beacon-config.ts for why the emitter's condition is the
// one that was mirrored. So the posture
// honestly states whether the (content-free, aggregate-only) beacon is off or on. The whole call is
// best-effort on the notify side: a routing hiccup degrades to "no regression notice this read".
// gatherWormSlice builds the WORM observable state for the immutability posture check (the part the DO
// cannot read, since it needs env + a live destination probe). It combines:
//   - the CONFIG verdict: a WORM policy is configured/misconfigured from the env DEST_WORM_* knobs OR the
//     console-set default destination's own per-destination policy (a console policy wins, mirroring the
//     destination-config precedence); a partial/invalid policy is configured-but-misconfigured (fail-safe).
//   - the live CAPABILITY PROBE: objectLockStatus() on the DEFAULT destination, so the check can report
//     REAL enforcement (the bucket actually has Object-Lock) rather than inferring it from delete behaviour.
// It is fully best-effort: ANY fault (no destination, an unreadable DO config, a probe transport error)
// degrades to the safe reading (no probe verdict, or "unknown"), and the function returns undefined only
// when it cannot even read the env policy shape, in which case the check reports the honest not-configured
// state. It performs ONE extra destination read (the probe) per posture computation, no archive bytes.
export async function gatherWormSlice(env: Env, scheduler: DurableObjectStub): Promise<PostureWormInput | undefined> {
  // CONFIG from env (the single fail-safe interpreter). configured/misconfigured/policy.
  const envParse = parseWormPolicy(env);
  // Resolve the default destination's console-set config (if any) so we can (a) honour a per-destination
  // WORM policy and (b) probe the bucket. A read fault here is non-fatal: we still report the env config and
  // skip the probe.
  let override: RuntimeDestConfig | null = null;
  try {
    override = await fetchDestConfig(scheduler, undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
  } catch {
    override = null;
  }
  // The effective configured policy: a console-set per-destination policy wins over env; else the env policy.
  const consoleWorm = override?.worm;
  let configured = envParse.configured;
  let misconfigured = envParse.configured ? envParse.misconfigured : false;
  let mode: "governance" | "compliance" | undefined = envParse.configured && !envParse.misconfigured ? envParse.policy.mode : undefined;
  let retentionDays: number | undefined = envParse.configured && !envParse.misconfigured ? envParse.policy.retentionDays : undefined;
  if (consoleWorm !== undefined) {
    // A console-set policy is INTENDED; validate it the same way the factory does. Invalid => misconfigured.
    configured = true;
    if (typeof consoleWorm.mode === "string" && (consoleWorm.mode === "governance" || consoleWorm.mode === "compliance") && Number.isInteger(consoleWorm.retentionDays) && consoleWorm.retentionDays > 0) {
      misconfigured = false;
      mode = consoleWorm.mode;
      retentionDays = consoleWorm.retentionDays;
    } else {
      misconfigured = true;
      mode = undefined;
      retentionDays = undefined;
    }
  }
  const probe = await probeWormCapability(env, override);
  // The STORE behind the default destination, derived through the SAME selection status.ts reports from,
  // because the immutability check's remedy depends on it: Azure enables version-level immutability on the
  // container, Google Cloud creates the bucket with per-object retention, Amazon S3 creates it with
  // Object-Lock, and R2 has no mechanism at all (dest/worm-remedy.ts). Honestly absent when no destination
  // is selected or the selection is ambiguous, in which case the check keeps the generic S3 wording.
  const provider = resolveDestKind(env, override !== null, override?.endpoint).destKind;
  return {
    configured,
    misconfigured,
    ...(provider !== null ? { provider } : {}),
    ...(mode !== undefined ? { mode } : {}),
    ...(retentionDays !== undefined ? { retentionDays } : {}),
    ...(probe.bucketEnforces !== undefined ? { bucketEnforces: probe.bucketEnforces } : {}),
    ...(probe.probeMode !== undefined ? { probeMode: probe.probeMode } : {}),
    ...(probe.probeDays !== undefined ? { probeDays: probe.probeDays } : {}),
    ...(probe.defaultRetention !== undefined ? { defaultRetention: probe.defaultRetention } : {}),
  };
}

// probeWormCapability does the live, best-effort Object-Lock capability read on the default destination so
// gatherWormSlice can report REAL enforcement rather than inferring it. We only build a destination when there
// is something to build (a console override or env destination config); buildDestination throws on a
// misconfigured env, so guard the whole thing. objectLockStatus is optional on the interface, so feature-
// detect it. Any fault leaves the verdict unset (the check treats an absent probe as cannot-confirm, never as
// enforcing).
//
// defaultRetention rides alongside the verdict for the same reason probeDestination above carries it, and it
// is derived identically (status.defaultMode !== undefined, set ONLY when the bucket reads enabled): a
// lock-ENABLED bucket retains nothing by itself, so "enforced" cannot stand in for "locked". The
// immutability REPORT reads it, because its strongest sentence -- a compromised delete-credential cannot
// hard-delete an archive within its retention window -- is true on this bucket only while something applies
// a retention window, which is either the header the engine writes under a valid policy or this rule. When
// the bucket does not read enabled the field is honestly absent, which is cannot-confirm, not false.
async function probeWormCapability(env: Env, override: RuntimeDestConfig | null): Promise<{ bucketEnforces?: boolean | "unknown"; probeMode?: "governance" | "compliance"; probeDays?: number; defaultRetention?: boolean }> {
  try {
    const dest = await buildDestination(env, undefined, override);
    if (typeof dest.objectLockStatus === "function") {
      const status = await dest.objectLockStatus();
      const out: { bucketEnforces?: boolean | "unknown"; probeMode?: "governance" | "compliance"; probeDays?: number; defaultRetention?: boolean } = { bucketEnforces: status.enabled };
      if (status.defaultMode !== undefined) out.probeMode = status.defaultMode;
      if (status.defaultDays !== undefined) out.probeDays = status.defaultDays;
      if (status.enabled === true) out.defaultRetention = status.defaultMode !== undefined;
      return out;
    }
  } catch {
    // fall through to the cannot-confirm reading
  }
  return {};
}


// keepAlive, when supplied, is the request's own ctx.waitUntil. See the regression-routing block below for
// why this parameter exists at all: without it the posture-regression alert was the one alert in the engine
// that the fireInBackground repair could not reach, because this caller threw the helper's promise away.
export async function computePostureViaDO(env: Env, scheduler: DurableObjectStub, caller: Caller | null, keepAlive?: (task: Promise<unknown>) => void): Promise<PostureReport> {
  // Gather the WORM observable state (env policy + live capability probe of the default destination) in the
  // router, where env and the destination I/O live; the DO has neither. It is best-effort: a probe fault
  // degrades to "unknown" (the safe cannot-confirm reading), never a failed posture read.
  const worm = await gatherWormSlice(env, scheduler);
  const resp = await scheduler.fetch(doURL("/posture"), {
    method: "POST",
    // callerEmail scopes the recovery-codes-low finding to the caller's OWN set (the DO never exposes another
    // user's count). It is the verified caller email (null for the bare-token break-glass or the SCHEDULED
    // evaluation, neither of which has a per-email recovery set, so the low finding is simply not raised).
    // The caller's auth METHOD is deliberately not forwarded: every check is computed from account-level
    // facts, so the report is identical for every reader and for the scheduled (caller-less) evaluation.
    // liveVersionId (DP-D) is the running isolate's version_metadata id, the router's env-derived half of
    // the update-version-drift check (the DO owns the expectation from the update lifecycle record).
    body: JSON.stringify({ status: statusSliceForPosture(env), beaconEnabled: beaconConfigured(env), configWrapKeyConfigured: loadConfigWrapKey(env.CONFIG_WRAP_KEY) !== undefined, ...(caller !== null && caller.email !== null ? { callerEmail: caller.email } : {}), ...(worm !== undefined ? { worm } : {}), ...(typeof env.CF_VERSION_METADATA?.id === "string" && env.CF_VERSION_METADATA.id !== "" ? { liveVersionId: env.CF_VERSION_METADATA.id } : {}) }),
    headers: { "content-type": "application/json" },
  });
  const { report, regressions } = (await resp.json()) as { report: PostureReport; regressions: PostureRegression[] };
  // Route each detected regression as a posture-regression notification. Fire-and-forget within a guard:
  // a delivery hiccup must never fail the posture read. The severity is critical for a critical-check
  // regression, otherwise warning (the contract's posture-regression mapping); the detail names the check
  // title only (redaction-safe). This is the ONLY place a posture-regression leaves the account.
  //
  // THE PROMISE IS KEPT INSTEAD OF DROPPED, and this is the one alert the fireInBackground repair could not
  // reach. routeEmission was fixed to RETURN its two writes (the alert-emit counter and the /notify/record
  // post that IS the notify-history row) rather than firing them with a bare void, so that a call site
  // handing the returned promise to a keep-alive really covers the durable record. Every other routeXxxAlert
  // call site does hand it over. This one did `void routePostureRegressions(...)`, so there was nothing for
  // the repair to give the writes to.
  //
  // A bare `void` here can abandon the emission at its FIRST await (the channel resolve), so the resolve
  // is issued but the webhook delivery never happens: nobody is told at all. A posture regression is a
  // previously-passing security control that has started failing, so the alert that goes missing is the one
  // that says the account's protection has degraded.
  //
  // keepAlive is the request's own ctx.waitUntil where the caller has one (GET /admin/posture). Where it does
  // not, the routing is AWAITED rather than dropped, which is correct for both remaining entry points: the
  // signed-report build is already inside an awaited handler, and the scheduled pass is inside the cron drive
  // that index.ts hands to ctx.waitUntil. Fail-open is unchanged: the .catch is still there, deliverEmission
  // never throws, and the counter writes swallow their own faults, so neither shape can fail a posture read.
  if (Array.isArray(regressions) && regressions.length > 0) {
    const routed = routePostureRegressions(env, scheduler, regressions).catch((e: unknown) => {
      log("error", `posture-regression routing skipped (non-critical): ${(e as Error).message}`);
    });
    if (keepAlive) keepAlive(routed);
    else await routed;
  }
  return report;
}


// reportPeriodFromQuery derives the period from ?from=&to= (epoch seconds), defaulting to the last
// REPORT_DEFAULT_WINDOW_SECONDS for the time-bounded reports. Returns null for the point-in-time kinds
// (posture, immutability), which ignore the period. An out-of-range/garbled from/to falls back to the
// default window so a malformed query still returns a sensible report rather than 400ing a read.
export function reportPeriodFromQuery(kind: ReportKind, params: URLSearchParams, now: number): ReportPeriod {
  if (kind === "posture" || kind === "immutability") return null;
  const nowSec = Math.floor(now / 1000);
  const parseSec = (raw: string | null): number | null => {
    if (raw === null) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
  };
  const from = parseSec(params.get("from"));
  const to = parseSec(params.get("to"));
  const toSeconds = to ?? nowSec;
  const fromSeconds = from ?? toSeconds - REPORT_DEFAULT_WINDOW_SECONDS;
  return fromSeconds <= toSeconds ? { fromSeconds, toSeconds } : { fromSeconds: toSeconds, toSeconds: fromSeconds };
}


// signReportFailOpen signs a report with the engine signer, fail-open: if no signer is configured, or
// loading/signing throws, the UNSIGNED report is returned (a missing signer must never 500 a read; the
// report data is valuable even unsigned, and the console surfaces the signature-verified state honestly).
// The signer is loaded per-call (the router is stateless); a report read is infrequent enough that this is
// not a hot path, and it keeps the router from holding the signer across requests.
export async function signReportFailOpen(env: Env, report: Report): Promise<Report> {
  if (!env.SIGNER_PRIVATE) return report;
  try {
    const signer = await loadSigner(env.SIGNER_PRIVATE);
    return await signReport(report, signer);
  } catch (e) {
    log("error", `report signing skipped (non-critical, unsigned report returned): ${(e as Error).message}`);
    return report;
  }
}


// handleReport assembles, signs and returns one report (contract section 6). It validates the :kind,
// gathers the per-kind data (restore-tests/sla-compliance read DO-owned data; posture computes via the DO;
// immutability reads the env presence slice), signs the report fail-open, and returns JSON or, with
// ?format=pdf, a rendered PDF (renderReportPDF, dependency-free). An unknown :kind is a 404. The period
// for the time-bounded kinds is taken from ?from=&to= (epoch seconds), defaulting to the last 90 days.
// NO-CUSTODY: every body is a redaction-safe projection; the PDF renders only the report's own fields.
export async function handleReport(env: Env, scheduler: DurableObjectStub, caller: Caller, kindRaw: string, params: URLSearchParams): Promise<Response> {
  if (!isReportKind(kindRaw)) return new Response(JSON.stringify({ error: "unknown report kind" }), { status: 404, headers: { "content-type": "application/json" } });
  const kind: ReportKind = kindRaw;
  const now = Date.now();
  // evidence-pack selects a framework via ?framework= (a framework id, or "all" for every framework, the
  // default). An unknown framework is a 404, mirroring the unknown-kind guard, so a typo never silently
  // yields an empty pack.
  const framework = params.get("framework") ?? "all";
  if (kind === "evidence-pack" && framework !== "all" && !isFrameworkId(framework)) {
    return new Response(JSON.stringify({ error: "unknown framework" }), { status: 404, headers: { "content-type": "application/json" } });
  }
  const period = reportPeriodFromQuery(kind, params, now);
  const report = await buildReportBody(env, scheduler, caller, kind, period, now, framework);
  const signed = await signReportFailOpen(env, report);
  if (params.get("format") === "pdf") {
    // G225: the render is GUARDED and its health is RECORDED. Before this, a single non-numeric
    // lastRestoreTestAt threw a RangeError deep inside PDF assembly, so the customer's compliance-report
    // DOWNLOAD 500'd -- the report an auditor was waiting for could not be produced at all, and nothing
    // anywhere said why. The renderer now coerces an unrenderable timestamp to "unknown" and COUNTS it (a
    // degraded cell must not become a new silent fallback), and a render that throws for any other reason is
    // counted too, so a 500 on this route is no longer evidence-free. Both counters ride the pack's existing
    // adminCounters aggregate; the offending value is never retained.
    let pdf: Uint8Array;
    try {
      pdf = renderReportPDF(signed);
    } catch {
      await bumpAdminCounter(scheduler, "report-pdf-render-failed");
      return new Response(JSON.stringify({ error: "report could not be rendered" }), { status: 500, headers: { "content-type": "application/json" } });
    }
    const renderFaults = drainReportRenderFaults();
    if (renderFaults.unparseableTimestamps > 0) await bumpAdminCounter(scheduler, "report-pdf-unparseable-ts", renderFaults.unparseableTimestamps);
    // ab() narrows the fresh ArrayBuffer-backed Uint8Array to the generic Response's BodyInit expects at
    // the fetch boundary (the same coercion the codebase uses at Web Crypto/fetch boundaries). The
    // content-disposition is inline so the console can preview it; the filename names the kind (and the
    // framework for an evidence pack).
    const filename = kind === "evidence-pack" ? `downpipe-evidence-pack-${framework}.pdf` : `downpipe-${kind}-report.pdf`;
    return new Response(ab(pdf), {
      headers: {
        "content-type": "application/pdf",
        "content-disposition": `inline; filename="${filename}"`,
      },
    });
  }
  return jsonResponse(signed);
}


// buildReportBody gathers the unsigned Report for a kind. Split out so handleReport stays small. The DO
// supplies the data it owns (restore-tests/sla-compliance); posture reuses computePostureViaDO (the single
// posture computation path, which also fires any regression notification); immutability reads the env
// presence slice. The period (null for the point-in-time kinds) is forwarded to the DO for the bounded ones.
export async function buildReportBody(env: Env, scheduler: DurableObjectStub, caller: Caller, kind: ReportKind, period: ReportPeriod, now: number, framework?: string): Promise<Report> {
  if (kind === "posture") {
    const posture: PostureReport = await computePostureViaDO(env, scheduler, caller);
    return makeReport("posture", buildPostureReport(posture), null, now);
  }
  if (kind === "evidence-pack") {
    // The customer-specific signed compliance pack: compute the live posture (the same single path the
    // posture report uses, which also fires any regression), then re-project it through one framework's
    // control mapping, or every framework for the "all" pack. Validated in handleReport, so framework is
    // "all" or a known id here.
    const posture: PostureReport = await computePostureViaDO(env, scheduler, caller);
    const target = framework ?? "all";
    const fws = target === "all" ? FRAMEWORKS : [getFramework(target)].filter((f): f is NonNullable<typeof f> => f !== undefined);
    return makeReport("evidence-pack", buildEvidencePackReport(fws, posture, target), null, now);
  }
  if (kind === "immutability") {
    const s = buildStatus(env, 0);
    // Gather the REAL WORM signal (config + live capability probe) so the report states store-enforced
    // immutability honestly rather than always falling back to tamper-evidence. Best-effort: a probe fault
    // leaves the signal "unknown"/absent and the report degrades gracefully. PostureWormInput is
    // structurally the WormForReport the generator reads.
    const worm = await gatherWormSlice(env, scheduler);
    const data = buildImmutabilityReport(
      {
        destConfigured: s.destConfigured,
        destKind: s.destKind,
        breakGlassConfigured: s.breakGlassConfigured,
        operationalConfigured: { public: s.operationalConfigured.public, private: s.operationalConfigured.private },
      },
      worm,
    );
    return makeReport("immutability", data, null, now);
  }
  if (kind === "restore-tests") {
    const resp = await scheduler.fetch(doURL("/reports/restore-tests-data"), {
      method: "POST",
      body: JSON.stringify({ period }),
      headers: { "content-type": "application/json" },
    });
    await assertReportData(env, scheduler, resp);
    const data = (await resp.json()) as RestoreTestsData;
    return makeReport("restore-tests", data, period, now);
  }
  if (kind === "change-requests") {
    // The CR ledger for the OWNER-OPT-IN "Require Change Number" policy: the DO returns the change-recorded
    // events; the pure builder period-filters + projects them to the redaction-safe rows. Time-bounded (default
    // window), like restore-tests/sla-compliance.
    const resp = await scheduler.fetch(doURL("/reports/change-requests-data"), {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "content-type": "application/json" },
    });
    await assertReportData(env, scheduler, resp);
    const body = (await resp.json()) as { events: AuditEvent[] };
    const data = buildChangeRequestsReport(body.events ?? [], period);
    // G082: this report is SIGNED, so a row the projector quietly dropped becomes a signed statement that the
    // change was never recorded -- the auditor's worst outcome. The builder already carries the exclusion
    // counts ON THE REPORT (excludedUnparseableTs / excludedShape), which is what the auditor reading THAT
    // report sees; these counters are the same fact in the PACK, which is what support reads months later when
    // the customer says the report is missing a change they know they made. Bumped only when a row was
    // actually excluded (a report that dropped nothing records nothing), and by the COUNT dropped. A row that
    // simply falls outside the requested window is ordinary period filtering and is never counted.
    if ((data.excludedUnparseableTs ?? 0) > 0) await bumpAdminCounter(scheduler, "report-row-excluded-unparseable-ts", data.excludedUnparseableTs);
    if ((data.excludedShape ?? 0) > 0) await bumpAdminCounter(scheduler, "report-row-excluded-shape", data.excludedShape);
    return makeReport("change-requests", data, period, now);
  }
  // sla-compliance
  const resp = await scheduler.fetch(doURL("/reports/sla-data"), {
    method: "POST",
    body: JSON.stringify({ period }),
    headers: { "content-type": "application/json" },
  });
  await assertReportData(env, scheduler, resp);
  const data = (await resp.json()) as SlaComplianceData;
  return makeReport("sla-compliance", data, period, now);
}

// assertReportData is the G082 guard on the three report-data DO reads. Each one used to cast resp.json()
// straight into the report body with NO ok check, so a DO that answered 500 (a storage incident, a contract
// drift) had its ERROR BODY cast to the report's data shape, filled with undefined -- and the engine then
// SIGNED it. A signed compliance report showing "no restore tests" / "no changes recorded" is materially
// worse than no report: it is a confident false statement, and the customer's auditor reads it as fact.
//
// It now fails LOUDLY (the route's caller turns the throw into a 5xx, so the console shows an error rather
// than an empty report) and the failure is COUNTED durably, so a report read that is intermittently faulting
// is visible in the pack even when the retry succeeded. Best-effort counter; never a message or a body.
//
async function assertReportData(_env: Env, scheduler: DurableObjectStub, resp: Response): Promise<void> {
  if (resp.ok) return;
  await bumpAdminCounter(scheduler, "report-data-read-unavailable");
  throw new Error("report data unavailable");
}
