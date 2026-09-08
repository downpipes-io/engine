// The engine-bound HealthGate for the safe-apply settle phase (update-apply.ts). It MUST be invoked
// inside a request to the NOW-LIVE (post-promote) version, so flyNow()/selfCheck() exercise the NEW
// code, that is the whole point of the two-phase design: phase 1 (apply) promotes on the old version,
// then the console calls phase 2 (settle) over its service binding, which hits the just-promoted new
// version, so the canary flight here genuinely tests the new build before it is trusted.

import { runCanaryCycle } from "../canary/cycle.ts";
import type { CanaryLiveness, CanaryView } from "../canary/types.ts";
import { destBuildFaultOf } from "../dest/build-health.ts";
import { buildDestination, fetchDestConfig, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import { type AdminCounterName, unwrapFaultCauseOf } from "./diag-records.ts";
import { selfCheckDegradationCounter } from "./posture-counters.ts";
import { runPreflight } from "./preflight.ts";
import { doURL } from "../do-url.ts";
import type { HealthGate, StepLog } from "./update-apply.ts";

// CRITICAL_PREFLIGHT_CHECK_IDS is the narrow allowlist selfCheck gates on (design UPDATE-UX-015 §3): a
// self-check failure must mean the NEW BUILD is broken, never that the install has chores. "durable-objects"
// is the one item that qualifies -- the live round-trip through the scheduler DO that proves the just-
// promoted code can bind and reach its own control plane AT ALL (the brick class: if this fails, nothing on
// the engine works, full stop). Every other preflight item (destination reachability, source bindings/
// liveness, the signer/recipient keys, Access, email, sliced-runs, licence, the API discovery token, ...) is
// an INSTALL CHORE: it reflects THIS customer's configuration or environment, never whether the new binary
// itself works, and gating on it is exactly the bug this design fixes (a chronically-unconfigured install,
// e.g. the demo's long-detached sources, would otherwise roll back a perfectly healthy release forever). A
// critical id absent from the report at all is treated the same as failed (fail-closed: see selfCheck below).
export const CRITICAL_PREFLIGHT_CHECK_IDS: ReadonlySet<string> = new Set(["durable-objects"]);

// SETTLE_PROBE_SCHEDULE is the bounded retry schedule probeSettleVerdict (below) applies when a canary
// flight right after a promote comes back NEITHER alive NOR dead: the code swap that settle runs on has
// JUST reset every Durable Object, so a flight in that window can fail transiently (pending/ailing)
// without saying anything about the new build. Two flight retries + one self-check retry, ~3s total
// sleep -- enough to clear the post-swap window, small enough that the settle request stays interactive.
// A DEAD verdict (a byte strayed) is NEVER retried: that is data evidence, not a transient. Named at
// module scope, exported and read at CALL time (the SETTLE_TTL_MS precedent: visible to tests and
// adjustable in one place -- the route-level validators zero it so the suite does not sleep for real;
// the probe's own retry vectors inject a recording sleep instead).
export const SETTLE_PROBE_SCHEDULE: { backoffMs: number[]; selfCheckBackoffMs: number } = {
  backoffMs: [1000, 1500],
  selfCheckBackoffMs: 500,
};

// SettleProbe is probeSettleVerdict's result: the final canary verdict (after bounded retries), the
// self-check outcome (consulted + retried only when the verdict stayed pending/ailing), and one step per
// attempt so the operator sees the probe reason in real terms in the settle response.
export interface SettleProbe {
  verdict: CanaryLiveness;
  selfCheckOk: boolean;
  attempts: StepLog[];
}

// probeSettleVerdict is the POST-SWAP-TOLERANT verdict read the settle path uses: an isolate swap right
// after promote resets every Durable Object, so an immediate canary flight in that window can come back
// not-alive with no bearing on the new build's health, and rolling back on it would revert a perfectly
// healthy update.
// The rules, in order:
//   * a flight that returns ALIVE decides immediately (keep);
//   * a flight that returns DEAD decides immediately (rollback) and is NEVER retried -- a strayed byte
//     is data evidence, not a transient;
//   * PENDING/AILING is retried on the bounded backoff schedule above (a flight that cannot COMPLETE in
//     the post-swap window is not evidence of regression), and if it never resolves, the SELF-CHECK
//     (boots + answers + reports the expected version + preflight) is consulted, itself retried once.
// A thrown flight reads as "ailing" (could not prove healthy) and a thrown self-check as false, exactly
// as the settle flow already treated them. Every attempt is logged as a step. `sleep` is injectable so
// the validator drives the schedule with no real waiting; the route uses the real timer.
export async function probeSettleVerdict(
  gate: HealthGate,
  opts: { backoffMs?: readonly number[]; selfCheckBackoffMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<SettleProbe> {
  const backoffs = opts.backoffMs ?? SETTLE_PROBE_SCHEDULE.backoffMs;
  const selfCheckBackoff = opts.selfCheckBackoffMs ?? SETTLE_PROBE_SCHEDULE.selfCheckBackoffMs;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const attempts: StepLog[] = [];
  const fly = async (label: string): Promise<CanaryLiveness> => {
    try {
      // G275: prefer the gate that can say whether the flight MEASURED anything. An unmeasured flight reports
      // "pending" like a slow one, so without this the settle trace coalesced "your engine could not reach its
      // destination at all" with "the flight has not finished yet" -- opposite remedies, one row. The verdict
      // returned is unchanged; only the recorded detail distinguishes them. The detail is an ENGINE-AUTHORED
      // sentence (never a platform message) and the projector reduces it to a closed class.
      if (typeof gate.flyNowMeasured === "function") {
        const f = await gate.flyNowMeasured();
        attempts.push({ step: label, ok: f.status === "alive", detail: f.measured ? f.status : "the canary flight measured nothing: it resolved no destination, so no probe was attempted" });
        return f.status;
      }
      const v = await gate.flyNow();
      attempts.push({ step: label, ok: v === "alive", detail: v });
      return v;
    } catch (e) {
      attempts.push({ step: label, ok: false, detail: `the canary flight errored: ${e instanceof Error ? e.message : String(e)}` });
      return "ailing";
    }
  };
  let verdict = await fly("canary-flight");
  for (let i = 0; i < backoffs.length && verdict !== "alive" && verdict !== "dead"; i++) {
    await sleep(backoffs[i]!);
    verdict = await fly(`canary-flight-retry-${i + 1}`);
  }
  let selfCheckOk = false;
  if (verdict !== "alive" && verdict !== "dead") {
    const check = async (label: string): Promise<boolean> => {
      let v = false;
      try {
        v = await gate.selfCheck();
      } catch {
        v = false;
      }
      attempts.push({ step: label, ok: v, detail: v ? "the new version boots, answers and reports the expected version" : "the new version did not pass its self-check" });
      return v;
    };
    selfCheckOk = await check("self-check");
    if (!selfCheckOk) {
      await sleep(selfCheckBackoff);
      selfCheckOk = await check("self-check-retry-1");
    }
  }
  return { verdict, selfCheckOk, attempts };
}

// makeHealthGate builds the gate for one settle. recommendedVersion is the version the channel said to
// deploy; selfCheck() confirms the live (new) code self-identifies as exactly that.
export function makeHealthGate(env: Env, scheduler: DurableObjectStub, recommendedVersion: string): HealthGate {
  // flight() is the ONE canary flight both flyNow() and flyNowMeasured() report, so the two can never
  // disagree about what happened.
  //
  // G275: "NOTHING COULD BE MEASURED" IS NOT "PENDING". A settle whose canary could not resolve a destination
  // at all -- the config plane unreachable, the stored destination unreadable -- returns "pending" from
  // runCanaryCycle, which is byte-identical to a flight that RAN and simply had not resolved inside the
  // post-swap window (the legitimate, common, wait-and-retry state). The two send an operator in opposite
  // directions, and the pack could not tell them apart.
  //
  // The discriminator is read STRUCTURALLY off the cycle's own aspect log, not off a message: runCanaryCycle
  // records an aspect for every stage it attempts, and resolveDestination (canary/cycle.ts) is the ONLY exit
  // that records no attempt at all -- it adds a single write-probe/"skip" and returns pending. Every other
  // exit, including every fault exit, has already recorded a pass/fail/note. So "no aspect was anything but a
  // skip" IS the fact "this flight attempted no measurement", established rather than inferred. It cannot fire
  // on a healthy flight, which always reaches at least the write probe.
  //
  // The VERDICT IS UNCHANGED (this is a logging change, not a control change): an unmeasured flight still
  // reports its "pending" and decideKeep still keeps. Only the evidence improves.
  //
  // NO-CUSTODY: a closed counter name and a boolean. The destination, the endpoint, the run id and the
  // cycle's own detail strings stay where they are.
  const flight = async (): Promise<{ status: CanaryLiveness; measured: boolean }> => {
    let destinationId: string | null = null;
    try {
      const resp = await scheduler.fetch(doURL("/canary"), { method: "GET" });
      const view = (await resp.json()) as CanaryView;
      destinationId = view.allDestinations?.find((d) => d.isDefault)?.id ?? null;
    } catch {
      destinationId = null; // null = the account/env default; runCanaryCycle resolves it
    }
    const run = { runId: `update-gate-${crypto.randomUUID()}`, runSeq: 0, destinationId, cleanupRunId: null };
    // runCanaryCycle never throws and touches only the isolated _CANARY/ cell; its status IS the verdict.
    const result = await runCanaryCycle(env, scheduler, run);
    const measured = result.aspects.some((a) => a.outcome !== "skip");
    if (!measured) void bumpAdminCounter(scheduler, "update-degraded-canary-unmeasured");
    return { status: result.status, measured };
  };
  return {
    // baseline: the canary's aggregate liveness BEFORE this apply (the hourly cron keeps it current; no
    // extra flight). Used to detect a regression (alive -> not-alive after the new version).
    async baseline(): Promise<CanaryLiveness> {
      try {
        const resp = await scheduler.fetch(doURL("/canary"), { method: "GET" });
        const view = (await resp.json()) as CanaryView;
        return view.status ?? "pending";
      } catch {
        // G332: THE SILENTLY DISARMED REGRESSION GUARD. The baseline is what decideKeep compares the post-
        // deploy verdict against: an alive->not-alive transition is a REGRESSION and rolls back. A DO blip here
        // coerces the baseline to "pending", and a pending baseline can never show a regression -- so the
        // ramp's stricter guard is switched off, silently, at the exact moment it is needed, and the build is
        // KEPT. "Why did the ramp keep a regressed build?" is this line, and it recorded nothing at all.
        void bumpAdminCounter(scheduler, "update-degraded-baseline-read-failed");
        return "pending";
      }
    },

    // flyNow: fly ONE real canary flight against the default destination on the now-live NEW code. This
    // proves the new build's whole write -> seal -> read -> restore -> verify path byte-for-byte. It uses
    // a throwaway verification cell (its own runId under _CANARY/) so it never disturbs the bird's own
    // scheduled state; the hourly canary continues to cover every destination. This gates on the DEFAULT
    // destination for a fast inline verdict; the hourly canary covers the rest and will alert if a
    // non-default destination breaks on the new code.
    async flyNow(): Promise<CanaryLiveness> {
      return (await flight()).status;
    },

    // G275: the same flight, reporting the fact the liveness enum cannot carry. See flight() below.
    async flyNowMeasured(): Promise<{ status: CanaryLiveness; measured: boolean }> {
      return flight();
    },

    // selfCheck: a DIAGNOSTIC signal the settle records, consulted when the canary could not complete a
    // flight. Since the optimistic rework it NO LONGER gates a rollback (decideKeep keeps on any
    // non-dead verdict regardless of this result); it shapes the reason + the confidence of a keep, and is
    // persisted so a rollback can be told apart from a keep-pending after the fact. Because settle runs on
    // the NEW code, both proofs exercise the new build: (1) ENGINE_VERSION === the recommended version (the
    // new code booted, is live and self-identifies), AND (2) a fresh preflight has ZERO FAILURES AMONG THE
    // CRITICAL ALLOWLIST ONLY (CRITICAL_PREFLIGHT_CHECK_IDS) -- the Durable-Objects round-trip. A non-critical
    // failure (an install chore: no destination, a detached source, an unproven licence) does not fail it.
    // NB the DO round-trip itself can transiently fail in the post-swap window; that is WHY it no longer
    // gates -- a health check inside its own blast radius must not decide a rollback (three live drills).
    async selfCheck(): Promise<boolean> {
      // G332: selfCheckOk was ONE boolean over TWO causes with OPPOSITE remedies. The WRONG BUILD IS LIVE
      // (version-mismatch: roll back). Or the preflight could not PROVE what is live (preflight: the engine is
      // not saying the wrong thing, it is saying nothing -- do not roll back on it). Support read one false and
      // guessed. Each cause is now its own closed counter; the returned boolean is unchanged.
      //
      // A THIRD counter, "update-degraded-selfcheck-throw", was DELETED here (R4). It claimed to mean "the
      // self-check THREW: the DO plane is down", and it had NO REACHABLE PRODUCER: runPreflight cannot throw by
      // construction (every probe it awaits guards its own I/O and the roster read is itself in a try), so the
      // catch below never fires. Worse, it asserted a fact the code never established: with the DO plane down --
      // every scheduler fetch rejecting -- this gate really does report `preflight`, because that is what the
      // preflight, having proven nothing, honestly says. A member that promises a row the product cannot write
      // tells a support engineer the evidence was looked for and not found.
      //
      // The catch stays as a backstop and now coarsens to `preflight`, whose meaning ("the preflight could not
      // complete, so the engine could not prove what is live") covers a throw exactly. It adds no vocabulary.
      if (ENGINE_VERSION !== recommendedVersion) {
        void bumpAdminCounter(scheduler, selfCheckDegradationCounter("version-mismatch") as AdminCounterName);
        return false;
      }
      try {
        const report = await runPreflight(env, scheduler);
        const critical = report.items.filter((i) => CRITICAL_PREFLIGHT_CHECK_IDS.has(i.id));
        // Fail-closed on a shape drift: every critical id must actually be PRESENT in the report (never
        // vacuously pass because an id went missing), and none of them may read failed.
        const ok = critical.length === CRITICAL_PREFLIGHT_CHECK_IDS.size && critical.every((i) => i.status !== "failed");
        if (!ok) void bumpAdminCounter(scheduler, selfCheckDegradationCounter("preflight") as AdminCounterName);
        return ok;
      } catch {
        void bumpAdminCounter(scheduler, selfCheckDegradationCounter("preflight") as AdminCounterName);
        return false;
      }
    },
  };
}

// DESTINATION_GATE_REASON is the exact, normative refusal string (design UPDATE-UX-015 §4) a LIVE apply
// with no destination configured returns verbatim, so the console can render it unmodified.
export const DESTINATION_GATE_REASON = "updates verify themselves with a canary flight to your destination; add a destination first, then apply this update";

// destinationConfigured (design §4) answers "does ANY destination resolve" -- the console-set override, or
// the deploy-time env/R2-binding configuration -- WITHOUT a live reachability probe (that stays the canary/
// self-check's job; a destination that is configured but currently broken is a wellness item, not this
// gate's concern, see CRITICAL_PREFLIGHT_CHECK_IDS above). It shares the EXACT resolution buildDestination
// already uses (console override wins, else env/R2), and the SAME configuration-shaped error classification
// preflight-probes.ts's probeDestination already applies (missing required configuration / ambiguous
// destination / a garbled DEST_KIND): those three throw shapes mean nothing is genuinely usable and this
// answers false; anything else (a transient STS/network fault while resolving an assumeRole credential)
// means a destination IS configured, just erroring right now, which is the canary/self-check's job to
// surface, not an apply-time refusal. A failed override READ (e.g. a rotated CONFIG_WRAP_KEY) does not
// itself mean unconfigured, it falls back to probing the env/binding destination, exactly like preflight.
export async function destinationConfigured(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  let override: RuntimeDestConfig | null = null;
  // overrideStoredButUnusable is the ONLY state that licenses the dest-fallback-env row below, and the name is
  // the whole point (R4): it is not "the override read failed", it is "a console-set destination is KNOWN TO
  // EXIST and could not be used". The two are different facts and the old code conflated them. See the note at
  // the bump site.
  let overrideStoredButUnusable = false;
  // G332 (R5): THE WRAP KEY IS PARSED BEFORE THE DO IS EVER READ, AND THE FAULT WAS BEING FILED AGAINST A ROW
  // THAT MAY NOT EXIST.
  //
  // loadConfigWrapKey THROWS UnwrapFaultError("key-malformed") when CONFIG_WRAP_KEY is present and is not 32
  // bytes -- an operator pasting the wrong secret, a state the engine deliberately fails loud on. Inside the
  // fetchDestConfig try, that throw was classified as "the STORED CREDENTIAL would not OPEN" (decrypt-failed) and
  // therefore set overrideStoredButUnusable, which bumps dest-fallback-env -- a row whose own vocabulary says "the
  // customer's console-set default could not be resolved". No /dest-config request had been issued. On the
  // commonest estate (env/R2 binding, no console destination) there IS no console-set default, and support was
  // being sent to a bucket the customer never configured -- on every Updates-screen poll, so it became the largest
  // number in adminCounters.
  //
  // The parse is now its OWN step, with its OWN closed counter: a FLEET-WIDE key fault (no destination credential
  // in the account can be opened) that asserts nothing about any stored row. The gate then proceeds with NO key,
  // so the DO read still happens and still speaks for itself: an estate that HAS a console destination reads its
  // wrapped credential, fails to open it, and honestly earns decrypt-failed + dest-fallback-env; an env-only
  // estate finds no row and earns neither. Those two states were byte-identical.
  let wrapKey: Uint8Array | undefined;
  try {
    wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
  } catch (e) {
    if (unwrapFaultCauseOf(e) === "key-malformed") void bumpAdminCounter(scheduler, "update-degraded-destgate-wrapkey-malformed");
    else void bumpAdminCounter(scheduler, "update-degraded-destgate-unclassified-error");
    wrapKey = undefined;
  }
  try {
    override = await fetchDestConfig(scheduler, undefined, wrapKey);
  } catch (e) {
    // G332: the customer's CONSOLE-SET default destination could not be RESOLVED. This used to be one bare
    // catch bumping one counter named "decrypt-failed", over causes with three opposite remedies: the config
    // plane is down (wait, touch nothing), a stored field is missing (the customer re-enters it), or the
    // credential genuinely will not decrypt (re-wrap / rotate the key back). The discriminator was already on
    // the thrown error and was being thrown away. Both classifiers below read the error's TYPE and its TAGGED
    // closed cause -- never its message, which can embed an endpoint or a bucket.
    const counter = destGateFailureCounter(e);
    // R4: only TWO of the four causes establish that a console-set destination EXISTS. A stored credential that
    // will not decrypt, and a stored config missing a required field, were both READ OUT OF A ROW -- so a row is
    // there. A config plane that would not answer, and a cause we could not classify, establish NOTHING about
    // whether the customer has a console-set default at all; on the commonest estate (env/R2 binding, no console
    // destination) there is none. See the bump site below.
    overrideStoredButUnusable = counter === "update-degraded-destgate-decrypt-failed" || counter === "update-degraded-destgate-config-incomplete";
    void bumpAdminCounter(scheduler, counter);
    override = null;
  }
  try {
    await buildDestination(env, undefined, override);
    // G332, NOISE, and this guard is the fix. dest-fallback-env used to be bumped on `override === null`,
    // which is TRUE for every customer who has no console-set destination and backs up to the env/R2 binding.
    // That is a state this function's own doc comment declares legitimate and buildDestination(env, _, null)
    // serves -- and GET /update/status calls this gate on every Updates-screen poll, so the counter became a
    // POLL COUNTER and, on a perfectly healthy engine, the largest number in adminCounters. A "degradation"
    // that is loudest when nothing is wrong devalues every honest row beside it.
    //
    // It now fires only where its vocabulary says it does: the gate PASSED against the ENV destination while a
    // console-set default THE ENGINE KNOWS EXISTS could not be used. That is a real and invisible state (the
    // update was verified against a destination nobody backs up to), and it is silent on the healthy env-only
    // estate.
    //
    // R4 narrowed it a second time, and the narrowing is a rule-3 fix, not a noise fix. The row asserts "the
    // customer's console-set default could not be resolved: the gate passed against a destination the customer is
    // not using". When the config plane does not ANSWER, the engine cannot know whether a console-set default
    // exists -- and on the commonest estate it does not -- so bumping this row told support to go and look at a
    // destination the customer never configured, off a transient DO blip. Only decrypt-failed and config-incomplete
    // read the fault OUT OF A STORED ROW, so only they establish the existence the row claims.
    if (overrideStoredButUnusable) void bumpAdminCounter(scheduler, "update-degraded-dest-fallback-env");
    return true;
  } catch (e) {
    const m = e instanceof Error ? e.message : "";
    const configShaped = /missing required configuration|ambiguous destination|DEST_KIND/.test(m);
    // An UNCLASSIFIED gate failure answers "configured: true" (a transient STS/network fault is the canary's
    // job, not this gate's) -- which is the right call and also means a genuinely broken destination can pass
    // the gate on a fault nobody names. Count it, so the pass is at least accompanied by its caveat.
    if (!configShaped) void bumpAdminCounter(scheduler, "update-degraded-destgate-unclassified-error");
    return !configShaped;
  }
}

/**
 * destGateFailureCounter (G332) names WHY the update gate could not resolve the customer's console-set
 * destination. The three causes have three opposite remedies and used to be one counter called "decrypt-failed",
 * which was a fact the code had not established in two of the three cases.
 *
 * It reads the error's TYPE and the CLOSED cause the throw site TAGGED it with -- destBuildFaultOf matches on the
 * DestBuildError type and never on text, and unwrapFaultCauseOf reads a tagged property. An untagged throw
 * coarsens to the residual rather than being guessed at from a message that can embed an endpoint or a bucket.
 *
 * @param e - the thrown value from fetchDestConfig.
 * @returns the closed admin-counter name.
 */
function destGateFailureCounter(e: unknown): AdminCounterName {
  const cause = destBuildFaultOf(e).cause;
  // The config plane would not answer: the destination may be perfectly healthy and we could not READ it.
  if (cause === "config-do-unreadable") return "update-degraded-destgate-config-plane-unreadable";
  // A required stored field is absent: the customer must re-enter it. Nothing is broken with the key or the DO.
  if (cause === "config-incomplete") return "update-degraded-destgate-config-incomplete";
  // The stored credential would not OPEN: a rotated/absent/malformed CONFIG_WRAP_KEY. This, and only this, is
  // what "decrypt-failed" ever meant.
  if (unwrapFaultCauseOf(e) !== null) return "update-degraded-destgate-decrypt-failed";
  return "update-degraded-destgate-unclassified-error";
}
